use crate::account::account::Account;
use crate::account::db_state::DBState;
use crate::account::node_ref::NodeRef;
use crate::account::state_node::StateNode;
use crate::common::address::Address;
use crate::consensus::tree_node::TreeNode;
use crate::consensus::worldstate::Blake2bHashResult;
use crate::database::state_db::StateDB;
use crate::database::IDB;
use crate::serialization::state::Account as ProtoAccount;
use crate::traits::{Encode, Exception, Proto};
use crate::util::hash::hash;
use protobuf::Message;
use std::sync::mpsc::{channel, Receiver, Sender};

use starling::traits::Database;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;

pub struct LegacyTrie<DBType> {
    db: StateDB<DBType, (Vec<u8>, DBState)>,
    tx: Sender<(Vec<u8>, DBState)>,
    rx: Receiver<(Vec<u8>, DBState)>,
}

impl<DBType> LegacyTrie<DBType>
where
    DBType: IDB,
{
    pub fn new(db: StateDB<DBType, (Vec<u8>, DBState)>) -> Self {
        let (tx, rx) = channel::<(Vec<u8>, DBState)>();
        Self { db, tx, rx }
    }
    pub fn get_account(&self, address: Address, root_node: &DBState) -> Option<ProtoAccount> {
        None
    }
    pub fn get(
        &self,
        root: &[u8],
        modified_accounts: Vec<Address>,
    ) -> Result<Vec<Option<ProtoAccount>>, Box<Error>> {
        let mut accounts = Vec::with_capacity(modified_accounts.len());
        let root_node = self.db.get_node(root)?;
        let mut node_map: HashMap<Vec<u8>, StateNode> = HashMap::new();
        match root_node {
            Some(node) => {
                let account_split = self.split_keys(&modified_accounts)?;
                for (index, address) in account_split {
                    accounts.push(self.traverse_nodes(&node, address, &mut node_map, index)?);
                }
            }
            None => {
                return Err(Box::new(Exception::new("Root Node not found")));
            }
        }
        Ok(accounts)
    }

    fn split_keys(&self, keys: &Vec<Address>) -> Result<Vec<(usize, Address)>, Box<Error>> {
        if keys.is_empty() {
            return Err(Box::new(Exception::new("No keys provided")));
        }
        let mut splits: Vec<(usize, Address)> = Vec::with_capacity(keys.len());
        for i in 0..keys.len() {
            if i == 0 {
                splits.push((0, keys[i].clone()))
            } else {
                for j in 0..19 {
                    if keys[i - 1][j] != keys[i][j] {
                        splits.push((j, keys[i].clone()));
                        break;
                    }
                }
            }
        }
        Ok(splits)
    }

    pub fn insert(
        &mut self,
        root: Option<&[u8]>,
        keys: Vec<Address>,
        values: &[&ProtoAccount],
    ) -> Result<Vec<u8>, Box<Error>> {
        // encode accounts and insert to db
        if keys.len() != values.len() {
            return Err(Box::new(Exception::new(
                "Keys and values have different lengths",
            )));
        }
        let split_addresses = self.split_keys(&keys)?;
        let mut node_map: BTreeMap<Vec<u8>, TreeNode> = BTreeMap::new();
        // set root - empty or existing state and create base future
        let mut root_node: TreeNode;
        match root {
            Some(root_hash) => {
                if let Some(db_state) = self.db.get_node(root_hash)? {
                    if let Some(state_node) = db_state.node {
                        root_node = TreeNode::new(state_node, Vec::new(), self.tx.clone());
                    } else {
                        return Err(Box::new(Exception::new("DB State is not a state node")));
                    }
                } else {
                    return Err(Box::new(Exception::new("DB State not found")));
                }
            }
            None => {
                let state_node = StateNode::new(Vec::new());
                root_node = TreeNode::new(state_node, Vec::new(), self.tx.clone());
            }
        }
        // iterate inserts
        for ((split, key), account) in split_addresses.iter().zip(values.iter()) {
            let mut offset = *split;
            let mut current_node: TreeNode;
            if offset > 0 {
                if let Some(node) = node_map.get(&key[0..offset]) {
                    current_node = node.clone();
                } else {
                    current_node = root_node.clone();
                }
            } else {
                current_node = root_node.clone();
            }
            // set up to traverse states
            let mut db_state: Option<DBState> = None;
            if let Some(next_node) = current_node.get_next_node_location(key[offset]) {
                let mut early_out = false;
                for i in 0..next_node.node_location.len() {
                    if &next_node.node_location[i] != &key[offset + i] {
                        // early out if key matches entirely
                        early_out = true;
                        let new_account = Account::from_proto(account);
                        let node_ref = NodeRef {
                            node_location: key[i..key.len()].to_vec(),
                            child: hash(&new_account.encode().unwrap(), 32),
                        };
                        let state_node = StateNode::new(vec![node_ref, next_node.clone()]);
                        let tree_node = TreeNode::new(
                            state_node,
                            key[offset + i..key.len()].to_vec(),
                            self.tx.clone(),
                        );
                        node_map.insert(key[0..offset + i].to_vec(), tree_node);
                        break;
                    }
                }
                if early_out {
                    continue;
                } else {
                    db_state = self.db.get_node(&next_node.child)?;
                }
            } else {
                // Early out if branch is empty
                let new_account = Account::from_proto(account);
                let node_ref = NodeRef {
                    node_location: key[offset..key.len()].to_vec(),
                    child: hash(&new_account.encode().unwrap(), 32),
                };
                let state_node = StateNode::new(vec![node_ref]);
                let tree_node =
                    TreeNode::new(state_node, key[offset..key.len()].to_vec(), self.tx.clone());
                node_map.insert(key[0..offset].to_vec(), tree_node);
                continue;
            }

            while let Some(state) = &db_state {
                if let Some(account) = &state.account {
                    return Ok(Some(account.to_proto()?));
                //we have an account
                } else if let Some(node) = &db_state.node {
                    map.insert(address[0..offset].to_vec(), node.clone());
                    if let Some(node_ref) = node.node_refs.get(&address[offset]) {
                        if let Some(next_node) = self.db.get_node(&node_ref.child)? {
                            offset += node_ref.node_location.len();
                            state = Some(next_node);
                            continue;
                        } else {
                            return Err(Box::new(Exception::new(
                                "Unable to find node, corrupted tree",
                            )));
                        }
                    } else {
                        return Err(Box::new(Exception::new(
                            "Unable to find node, corrupted tree",
                        )));
                    }
                } else {
                    return Err(Box::new(Exception::new(
                        "Unable to find node, corrupted tree",
                    )));
                    // we got nothing
                }
            }
        }

        //  - store path in node map
        //  - get next node or insert
        Ok(Vec::new())
    }

    pub fn remove(&mut self, root: &[u8]) -> Result<(), Box<Error>> {
        Ok(())
    }

    fn get_modified_nodes(
        &self,
        root: &TreeNode,
        keys: Vec<&[u8]>,
        values: &[&ProtoAccount],
    ) -> BTreeMap<Vec<u8>, TreeNode> {
        BTreeMap::new()
    }

    fn traverse_nodes(
        &self,
        root: &DBState,
        address: Address,
        map: &mut HashMap<Vec<u8>, StateNode>,
        split: usize,
    ) -> Result<Option<ProtoAccount>, Box<Error>> {
        let mut state: Option<DBState> = None;
        let mut offset = split;
        if offset > 0 {
            if let Some(node) = map.get(&address[0..offset]) {
                if let Some(node_ref) = node.node_refs.get(&address[offset]) {
                    if let Some(next_node) = self.db.get_node(&node_ref.child)? {
                        offset += node_ref.node_location.len();
                        state = Some(next_node);
                    } else {
                        return Err(Box::new(Exception::new(
                            "Unable to find node, corrupted tree",
                        )));
                    }
                }
            }
        } else {
            state = Some(root.clone());
        }
        while let Some(db_state) = &state {
            if let Some(account) = &db_state.account {
                return Ok(Some(account.to_proto()?));
            //we have an account
            } else if let Some(node) = &db_state.node {
                map.insert(address[0..offset].to_vec(), node.clone());
                if let Some(node_ref) = node.node_refs.get(&address[offset]) {
                    if let Some(next_node) = self.db.get_node(&node_ref.child)? {
                        offset += node_ref.node_location.len();
                        state = Some(next_node);
                        continue;
                    } else {
                        return Err(Box::new(Exception::new(
                            "Unable to find node, corrupted tree",
                        )));
                    }
                } else {
                    return Err(Box::new(Exception::new(
                        "Unable to find node, corrupted tree",
                    )));
                }
            } else {
                return Err(Box::new(Exception::new(
                    "Unable to find node, corrupted tree",
                )));
                // we got nothing
            }
        }
        Ok(None)
    }
}
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::account::account::Account;
    use crate::account::node_ref::NodeRef;
    use crate::common::address::ValidAddress;
    use crate::database::mock::RocksDBMock;
    use crate::traits::Encode;
    use crate::util::hash::hash;
    use std::path::PathBuf;
    #[test]
    fn it_gets_items_from_a_tree_of_depth_1() {
        let path = PathBuf::new();
        let mut state_db: StateDB<RocksDBMock> = StateDB::new(path, None).unwrap();
        let mut accounts: Vec<NodeRef> = Vec::with_capacity(256);
        for i in 0..255 {
            let db_state = DBState::new(
                Some(Account {
                    balance: i * 100,
                    nonce: i as u32,
                }),
                None,
                1,
            );
            let hash = hash(db_state.encode().unwrap().as_ref(), 32);
            let _ = state_db.insert(&hash, &db_state);
            let location = vec![
                i as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            let node_ref = NodeRef::new(&location, &hash);
            accounts.push(node_ref);
        }
        let state_node = StateNode::new(accounts);
        let state_hash = hash(state_node.encode().unwrap().as_ref(), 32);
        let db_state = DBState::new(None, Some(state_node), 1);
        let _ = state_db.insert(&state_hash, &db_state);
        let _ = state_db.batch_write();
        let legacy_trie = LegacyTrie::new(state_db);
        let returned_accounts = legacy_trie.get(
            &state_hash,
            vec![
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ],
        );
        match returned_accounts {
            Ok(vec) => {
                assert_eq!(vec.len(), 2);
                if let Some(account) = &vec[0] {
                    assert_eq!(account.balance, 0);
                    assert_eq!(account.nonce, 0);
                } else {
                    println!("Node not found");
                    unimplemented!()
                }
                if let Some(account) = &vec[1] {
                    assert_eq!(account.balance, 1200);
                    assert_eq!(account.nonce, 12);
                } else {
                    println!("Node not found");
                    unimplemented!()
                }
            }
            Err(e) => {
                println!("Error: {:?}", e);
                unimplemented!()
            }
        }
    }

    #[test]
    fn it_gets_an_item_from_a_depth_greater_than_one() {
        let path = PathBuf::new();
        let mut state_db: StateDB<RocksDBMock> = StateDB::new(path, None).unwrap();
        let first_account = DBState::new(
            Some(Account {
                balance: 100,
                nonce: 1,
            }),
            None,
            1,
        );
        let first_hash = hash(first_account.encode().unwrap().as_ref(), 32);
        let _ = state_db.insert(&first_hash, &first_account);
        let first_location = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let first_node_ref = NodeRef::new(&first_location, &first_hash);
        let second_account = DBState::new(
            Some(Account {
                balance: 200,
                nonce: 2,
            }),
            None,
            1,
        );
        let second_hash = hash(second_account.encode().unwrap().as_ref(), 32);
        let _ = state_db.insert(&second_hash, &second_account);
        let second_location = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let second_node_ref = NodeRef::new(&second_location, &second_hash);
        let third_account = DBState::new(
            Some(Account {
                balance: 300,
                nonce: 3,
            }),
            None,
            1,
        );
        let third_hash = hash(third_account.encode().unwrap().as_ref(), 32);
        let _ = state_db.insert(&third_hash, &third_account);
        let third_location = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let third_node_ref = NodeRef::new(&third_location, &third_hash);
        let second_level_refs = vec![first_node_ref, second_node_ref];
        let second_state_node = StateNode::new(second_level_refs);
        let second_state_node_state = DBState::new(None, Some(second_state_node), 1);
        let second_state_node_hash = hash(&second_state_node_state.encode().unwrap(), 32);
        let _ = state_db.insert(&second_state_node_hash, &second_state_node_state);
        let first_level_node = NodeRef::new(&vec![0], &second_state_node_hash);
        let root_node_refs = vec![first_level_node, third_node_ref];
        let root_state_node = StateNode::new(root_node_refs);
        let root_db_state = DBState::new(None, Some(root_state_node), 1);
        let root_hash = hash(&root_db_state.encode().unwrap(), 32);
        let _ = state_db.insert(&root_hash, &root_db_state);
        let _ = state_db.batch_write();
        let tree = LegacyTrie::new(state_db);
        let addresses = vec![
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        let returned_accounts = tree.get(&root_hash, addresses);
        match returned_accounts {
            Ok(vec) => {
                assert_eq!(vec.len(), 3);
                // check integrity of returned accounts
                for i in 0..vec.len() {
                    match &vec[i] {
                        Some(account) => {
                            assert_eq!(account.balance as usize, (i + 1) * 100);
                            assert_eq!(account.nonce as usize, i + 1);
                        }
                        None => unimplemented!(),
                    }
                }
            }
            Err(e) => {
                println!("Error: {:?}", e);
                unimplemented!()
            }
        }
    }
    #[test]
    fn it_gets_from_a_tree_with_compressed_branches() {
        let path = PathBuf::new();
        let mut state_db: StateDB<RocksDBMock> = StateDB::new(path, None).unwrap();
        let first_account = DBState::new(
            Some(Account {
                balance: 100,
                nonce: 1,
            }),
            None,
            1,
        );
        let first_hash = hash(first_account.encode().unwrap().as_ref(), 32);
        let _ = state_db.insert(&first_hash, &first_account);
        let first_location = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let first_node_ref = NodeRef::new(&first_location, &first_hash);
        let second_account = DBState::new(
            Some(Account {
                balance: 200,
                nonce: 2,
            }),
            None,
            1,
        );
        let second_hash = hash(second_account.encode().unwrap().as_ref(), 32);
        let _ = state_db.insert(&second_hash, &second_account);
        let second_location = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let second_node_ref = NodeRef::new(&second_location, &second_hash);
        let third_account = DBState::new(
            Some(Account {
                balance: 300,
                nonce: 3,
            }),
            None,
            1,
        );
        let third_hash = hash(third_account.encode().unwrap().as_ref(), 32);
        let _ = state_db.insert(&third_hash, &third_account);
        let third_location = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let third_node_ref = NodeRef::new(&third_location, &third_hash);
        let second_level_refs = vec![first_node_ref, second_node_ref];
        let second_state_node = StateNode::new(second_level_refs);
        let second_state_node_state = DBState::new(None, Some(second_state_node), 1);
        let second_state_node_hash = hash(&second_state_node_state.encode().unwrap(), 32);
        let _ = state_db.insert(&second_state_node_hash, &second_state_node_state);
        let first_level_node = NodeRef::new(&vec![0, 0, 0, 0, 0], &second_state_node_hash);
        let root_node_refs = vec![first_level_node, third_node_ref];
        let root_state_node = StateNode::new(root_node_refs);
        let root_db_state = DBState::new(None, Some(root_state_node), 1);
        let root_hash = hash(&root_db_state.encode().unwrap(), 32);
        let _ = state_db.insert(&root_hash, &root_db_state);
        let _ = state_db.batch_write();
        let tree = LegacyTrie::new(state_db);
        let addresses = vec![
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        let returned_accounts = tree.get(&root_hash, addresses);
        match returned_accounts {
            Ok(vec) => {
                assert_eq!(vec.len(), 3);
                println!("accounts: {:?}", vec);
                // check integrity of returned accounts
                for i in 0..vec.len() {
                    match &vec[i] {
                        Some(account) => {
                            assert_eq!(account.balance as usize, (i + 1) * 100);
                            assert_eq!(account.nonce as usize, i + 1);
                        }
                        None => unimplemented!(),
                    }
                }
            }
            Err(e) => {
                println!("Error: {:?}", e);
                unimplemented!()
            }
        }
    }
    #[test]
    fn it_calculates_the_split_points_for_keys() {
        let path = PathBuf::new();
        let state_db: StateDB<RocksDBMock> = StateDB::new(path, None).unwrap();
        let trie = LegacyTrie::new(state_db);
        let address_bytes = vec![
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        let mut addresses: Vec<Address> = Vec::new();
        for address in address_bytes {
            addresses.push(Address::from_bytes(&address));
        }
        let split_addresses = trie.split_keys(&addresses).unwrap();
        assert_eq!(split_addresses.len(), 3);
        assert_eq!(split_addresses[0].0, 0);
        assert_eq!(split_addresses[1].0, 1);
        assert_eq!(split_addresses[2].0, 0);
    }
    #[test]
    fn it_inserts_256_keys_with_different_first_bytes_into_empty_tree_and_retrieves_them() {
        unimplemented!();
    }
    #[test]
    fn it_inserts_and_retrieves_a_key_from_an_existing_tree() {
        let path = PathBuf::new();
        let mut state_db: StateDB<RocksDBMock> = StateDB::new(path, None).unwrap();
        let first_account = DBState::new(
            Some(Account {
                balance: 100,
                nonce: 1,
            }),
            None,
            1,
        );
        let first_hash = hash(first_account.encode().unwrap().as_ref(), 32);
        let _ = state_db.insert(&first_hash, &first_account);
        let first_location = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let first_node_ref = NodeRef::new(&first_location, &first_hash);
        let second_account = DBState::new(
            Some(Account {
                balance: 200,
                nonce: 2,
            }),
            None,
            1,
        );
        let second_hash = hash(second_account.encode().unwrap().as_ref(), 32);
        let _ = state_db.insert(&second_hash, &second_account);
        let second_location = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let second_node_ref = NodeRef::new(&second_location, &second_hash);
        let third_account = DBState::new(
            Some(Account {
                balance: 300,
                nonce: 3,
            }),
            None,
            1,
        );
        let third_hash = hash(third_account.encode().unwrap().as_ref(), 32);
        let _ = state_db.insert(&third_hash, &third_account);
        let third_location = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let third_node_ref = NodeRef::new(&third_location, &third_hash);
        let second_level_refs = vec![first_node_ref, second_node_ref];
        let second_state_node = StateNode::new(second_level_refs);
        let second_state_node_state = DBState::new(None, Some(second_state_node), 1);
        let second_state_node_hash = hash(&second_state_node_state.encode().unwrap(), 32);
        let _ = state_db.insert(&second_state_node_hash, &second_state_node_state);
        let first_level_node = NodeRef::new(&vec![0], &second_state_node_hash);
        let root_node_refs = vec![first_level_node, third_node_ref];
        let root_state_node = StateNode::new(root_node_refs);
        let root_db_state = DBState::new(None, Some(root_state_node), 1);
        let root_hash = hash(&root_db_state.encode().unwrap(), 32);
        let _ = state_db.insert(&root_hash, &root_db_state);
        let _ = state_db.batch_write();
        let mut tree = LegacyTrie::new(state_db);
        let account = Account {
            balance: 200,
            nonce: 2,
        };
        let account_proto = account.to_proto().unwrap();
        let address_bytes = vec![
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        let mut addresses: Vec<Address> = Vec::new();
        for address in address_bytes {
            addresses.push(Address::from_bytes(&address));
        }
        let accounts = vec![&account_proto, &account_proto, &account_proto];
        tree.insert(Some(&root_hash), addresses, &accounts.as_ref());
    }
    #[test]
    fn it_inserts_and_retrieves_two_keys_with_similar_paths() {
        unimplemented!();
    }
    #[test]
    fn it_inserts_and_retrieves_multiple_keys_from_existing_tree() {
        unimplemented!();
    }
    #[test]
    fn it_matches_typescript_world_state_for_exodus_block() {
        unimplemented!();
    }
}
