use crate::account::account::Account;
use crate::account::db_state::DBState;
use crate::account::state_node::StateNode;
use crate::common::address::Address;
use crate::consensus::worldstate::Blake2bHashResult;
use crate::database::state_db::StateDB;
use crate::serialization::state::Account as ProtoAccount;
use crate::traits::{Exception, Proto};

use starling::traits::Database;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error::Error;
// fn set_db_options() -> Options {
//     let mut options = Options::new();
//     options
// }
pub struct LegacyTrie {
    db: StateDB,
}

impl LegacyTrie {
    pub fn new(db: StateDB) -> Self {
        Self { db }
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
        let mut node_map: HashMap<Vec<u8>, DBState> = HashMap::new();
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
        Ok(Vec::new())
    }

    pub fn remove(&mut self, root: &[u8]) -> Result<(), Box<Error>> {
        Ok(())
    }

    fn traverse_nodes(
        &self,
        root: &DBState,
        address: Address,
        map: &mut HashMap<Vec<u8>, DBState>,
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
                let entry = map.entry(address[0..offset + 1].to_vec());
                match entry {
                    Entry::Vacant(_entry) => {
                        map.insert(address[0..offset + 1].to_vec(), db_state.clone());
                    }
                    Entry::Occupied(entry) => {
                        // get from map
                        let next_state = entry.get().clone();
                        // update offset
                        if let Some(node) = &next_state.node {
                            if let Some(node_ref) = node.node_refs.get(&vec![address[offset]]) {
                                offset += node_ref.node_location.len();
                                state = Some(next_state.clone());
                                continue;
                            }
                        } else {
                            return Err(Box::new(Exception::new(
                                "Unable to find node, corrupted tree",
                            )));
                        }
                    }
                }
                // find next node based on index and assign to state variable
                if let Some(node_ref) = node.node_refs.get(&vec![address[offset]]) {
                    if let Some(next_node) = self.db.get_node(&node_ref.child)? {
                        offset += node_ref.node_location.len();
                        state = Some(next_node.clone());
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

pub mod tests {
    use super::*;
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
