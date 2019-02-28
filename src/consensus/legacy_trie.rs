use crate::account::account::Account;
use crate::account::db_state::DBState;
use crate::account::state_node::StateNode;
use crate::common::address::Address;
use crate::consensus::tree_node::TreeNode;
use crate::consensus::worldstate::Blake2bHashResult;
use crate::database::state_db::StateDB;
use crate::database::IDB;
use crate::serialization::state::Account as ProtoAccount;
use crate::traits::{Exception, Proto};
use std::sync::mpsc::{channel, Receiver, Sender};

use starling::traits::Database;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
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
    pub fn get_multiple(
        &self,
        root: &[u8],
        modified_accounts: Vec<Address>,
    ) -> Result<Vec<Option<ProtoAccount>>, Box<Error>> {
        let mut accounts = Vec::with_capacity(modified_accounts.len());
        let root_node = self.db.get_node(root)?;
        let mut node_map: HashMap<Vec<u8>, StateNode> = HashMap::new();
        match root_node {
            Some(node) => {
                for address in modified_accounts {
                    accounts.push(self.traverse_nodes(&node, address, &mut node_map)?);
                }
            }
            None => {
                return Err(Box::new(Exception::new("Root Node not found")));
            }
        }
        Ok(accounts)
    }

    pub fn insert(
        &mut self,
        root: Option<&Blake2bHashResult>,
        keys: Vec<Address>,
        values: &[&ProtoAccount],
    ) -> Result<Vec<u8>, Box<Error>> {
        // encode accounts and insert to db
        if keys.len() != values.len() {
            return Err(Box::new(Exception::new(
                "Keys and values have different lengths",
            )));
        }
        if let Some(root_hash) = root {
            let root_node = self.db.get_node(root_hash.as_ref())?;
            let mut tree_nodes: HashMap<Vec<u8>, TreeNode> = HashMap::new();
            let mut offset = 0;
            for (key, value) in keys.iter().zip(values.iter()) {}
        } else {
            // empty tree case
        }
        Ok(Vec::new())
    }

    pub fn remove(&mut self, root: &[u8]) -> Result<(), Box<Error>> {
        Ok(())
    }

    fn traverse_nodes(
        &self,
        root: &DBState,
        address: Address,
        map: &mut HashMap<Vec<u8>, StateNode>,
    ) -> Result<Option<ProtoAccount>, Box<Error>> {
        let mut state: Option<DBState> = Some(root.clone());
        let mut offset = 0;
        while let Some(db_state) = &state {
            if let Some(account) = &db_state.account {
                return Ok(Some(account.to_proto()?));
            //we have an account
            } else if let Some(node) = &db_state.node {
                // we have a node
                //insert node into seen map
                // let entry = map.entry(address[0..offset + 1].to_vec());
                // match entry {
                //     Entry::Vacant(_entry) => {
                //         map.insert(address[0..offset + 1].to_vec(), db_state.clone());
                //     }
                //     Entry::Occupied(entry) => {
                //         // get from map
                //         let next_state = entry.get().clone();
                //         // update offset
                //         if let Some(node) = &next_state.node {
                //             if let Some(node_ref) = node.node_refs.get(&address[offset]) {
                //                 offset += node_ref.node_location.len();
                //                 state = Some(next_state);
                //                 continue;
                //             }
                //         } else {
                //             return Err(Box::new(Exception::new(
                //                 "Unable to find node, corrupted tree",
                //             )));
                //         }
                //     }
                // }
                // find next node based on index and assign to state variable
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
    use crate::account::node_ref::NodeRef;
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
        state_db.insert(&state_hash, &db_state);
        state_db.batch_write();
        let legacy_trie = LegacyTrie::new(state_db);
        let returned_accounts = legacy_trie.get_multiple(
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
        let mut accounts: Vec<NodeRef> = Vec::with_capacity(256);
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
        let returned_accounts = tree.get_multiple(&root_hash, addresses);
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
        let mut accounts: Vec<NodeRef> = Vec::with_capacity(256);
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
        let returned_accounts = tree.get_multiple(&root_hash, addresses);
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
    fn it_inserts_256_keys_with_different_first_bytes_into_empty_tree_and_retrieves_them() {
        unimplemented!();
    }
    #[test]
    fn it_inserts_and_retrieves_a_key_from_an_existing_tree() {
        unimplemented!();
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
