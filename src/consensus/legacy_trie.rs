use crate::account::account::Account;
use crate::account::db_state::DBState;
use crate::account::state_node::StateNode;
use crate::common::address::Address;
use crate::consensus::worldstate::Blake2bHashResult;
use crate::database::state_db::StateDB;
use crate::serialization::state::Account as ProtoAccount;

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
    pub fn get_account(&self, address: Address, root: &[u8]) -> Account {
        Account {
            balance: 0,
            nonce: 0,
        }
    }
    pub fn get_multiple(
        &self,
        root: &[u8],
        modified_accounts: Vec<Address>,
    ) -> Result<Vec<Option<ProtoAccount>>, Box<Error>> {
        let mut accounts = Vec::with_capacity(modified_accounts.len());
        // for address in modified_accounts {
        //     accounts.push(self.get_account(address, root))
        // }
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

    pub fn transition(&mut self, modified_accounts: Vec<Account>, root: &[u8]) -> Vec<u8> {
        let new_state = Vec::with_capacity(32);
        new_state
    }
}
