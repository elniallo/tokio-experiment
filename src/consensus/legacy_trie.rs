use rocksdb::{Options, WriteBatch, DB};

use crate::account::account::Account;
use crate::account::state_node::StateNode;
use crate::common::address::Address;

// fn set_db_options() -> Options {
//     let mut options = Options::new();
//     options
// }
pub struct LegacyTrie {
    db: DB,
}

impl LegacyTrie {
    pub fn new(db: DB) -> Self {
        Self { db }
    }
    pub fn get_account(&self, address: Address, root: &[u8]) -> Account {
        Account {
            balance: 0,
            nonce: 0,
        }
    }
    pub fn get_multiple(&self, modified_accounts: Vec<Address>, root: &[u8]) -> Vec<Account> {
        let mut accounts = Vec::with_capacity(modified_accounts.len());
        for address in modified_accounts {
            accounts.push(self.get_account(address, root))
        }
        accounts
    }

    pub fn transition(&mut self, modified_accounts: Vec<Account>, root: &[u8]) -> Vec<u8> {
        let new_state = Vec::with_capacity(32);
        new_state
    }
}
