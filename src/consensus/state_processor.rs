use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::{Arc, Mutex};

use crate::common::address::Address;
use crate::common::block::Block;
use crate::common::header::Header;
use crate::common::signed_tx::SignedTx;
use crate::consensus::worldstate::{Blake2bHashResult, WorldState};
use crate::database::block_db::BlockDB;
use crate::traits::{BlockHeader, Exception, Transaction};
use crate::util::strict_math::StrictU64;
use secp256k1::{RecoverableSignature, RecoveryId};

use crate::serialization::state::Account as ProtoAccount;

const MAX_STATE_CACHE_SIZE: usize = 5000;

type StateProcessorResult<T> = Result<T, Box<Error>>;

pub struct StateProcessor<
    BlockDBType = BlockDB,
    WorldStateType = WorldState,
    HashresultType = Blake2bHashResult,
> {
    worldstate: WorldStateType,
    block_db: Arc<Mutex<BlockDBType>>,
    state_cache: Vec<HashresultType>,
}

impl StateProcessor {
    pub fn new(
        block_db: Arc<Mutex<BlockDB>>,
        worldstate: WorldState,
    ) -> StateProcessor<BlockDB, WorldState> {
        let state_cache = Vec::with_capacity(MAX_STATE_CACHE_SIZE);
        StateProcessor {
            worldstate,
            block_db,
            state_cache,
        }
    }

    fn prune(&mut self) -> Result<(), Box<Error>> {
        if self.state_cache.len() <= MAX_STATE_CACHE_SIZE {
            return Ok(());
        }

        for i in (0..self.state_cache.len() - MAX_STATE_CACHE_SIZE).rev() {
            self.worldstate.remove(self.state_cache[i].as_ref())?;
            self.state_cache.remove(i);
        }

        Ok(())
    }

    fn regenerate(&mut self, height: u32) -> StateProcessorResult<()> {
        let block_tip = self
            .block_db
            .lock()
            .map_err(|_| Exception::new("Poison error"))?
            .get_block_tip_hash()?;
        let block = self
            .block_db
            .lock()
            .map_err(|_| Exception::new("Poison error"))?
            .get_block::<Block<Header, SignedTx>>(&block_tip)?;
        let tip_height;
        if let Some(m) = block.meta {
            tip_height = m.height;
        } else {
            return Err(Box::new(Exception::new("Block tip does not have height")));
        }

        if tip_height - height <= MAX_STATE_CACHE_SIZE as u32 {
            return Ok(());
        }

        return Err(Box::new(Exception::new("Not Implemented")));
    }

    fn generate_transition(
        &self,
        blocks: Vec<&Block<Header, SignedTx>>,
    ) -> StateProcessorResult<HashMap<Address, ProtoAccount>> {
        let mut address_list: Vec<Address> = Vec::with_capacity(8192);
        let mut address_set = HashSet::new();

        // Gather all affected accounts from the blocks
        for block in &blocks {
            if let Some(ref txs) = block.txs {
                for tx in txs {
                    if let Some(from) = tx.get_from() {
                        if !address_set.contains(&from) {
                            address_list.insert(0, from);
                            address_set.insert(from);
                        }
                    }

                    if let Some(to) = tx.get_to() {
                        if !address_set.contains(&to) {
                            address_list.insert(0, to);
                            address_set.insert(to);
                        }
                    }
                }
            }
        }

        // Keys must be sorted prior to retrieving accounts
        address_list.sort();

        let mut address_keys = Vec::with_capacity(address_list.len());
        for i in 0..address_list.len() {
            address_keys.push(address_list[i])
        }

        // Insert existing balances into a map
        let mut account_map = HashMap::new();

        if self.state_cache.len() > 0 {
            let mut accounts = self
                .worldstate
                .get(&self.state_cache[self.state_cache.len() - 1], &address_keys)?;
            for i in (0..accounts.len()).rev() {
                if let Some(account) = accounts.remove(i) {
                    account_map.insert(address_list[i], account.1);
                }
            }
        }

        // Process blocks in memory
        for block in &blocks {
            let mut revert = false;
            let mut processed_txs: usize = 0;

            if let Some(ref txs) = block.txs {
                let miner = block.header.get_miner();
                let genesis;
                if let Some(m) = miner {
                    genesis = false;
                } else {
                    genesis = true;
                }
                for tx in txs {
                    if let Err(e) =
                        StateProcessor::generate_tx_transition(tx, &mut account_map, miner, genesis)
                    {
                        revert = true;
                        break;
                    }
                    processed_txs += 1;
                }
            }

            if revert {
                // TODO: Revert the updates in this block and then stop
                break;
            }
        }

        return Err(Box::new(Exception::new("Not Implemented")));
    }

    fn generate_tx_transition<TxType>(
        tx: &TxType,
        account_map: &mut HashMap<Address, ProtoAccount>,
        miner: Option<&Address>,
        genesis: bool,
    ) -> StateProcessorResult<()>
    where
        TxType: Transaction<Address, RecoverableSignature, RecoveryId>,
    {
        // Handle a genesis transaction
        if genesis {
            if let Some(to) = tx.get_to() {
                let nonce;
                if let Some(n) = tx.get_nonce() {
                    nonce = n;
                } else {
                    nonce = 0;
                }

                if let Some(to_account) = account_map.get_mut(&to) {
                    // Begin committing updates to account map
                    to_account.set_balance(tx.get_amount());
                    to_account.set_nonce(nonce);
                } else {
                    return Err(Box::new(Exception::new(
                        "Invalid Tx: Tx to account does not exist",
                    )));
                }
            } else {
                return Err(Box::new(Exception::new(
                    "Invalid Tx: Tx is missing to field",
                )));
            }
            return Ok(());
        }

        let miner_address;
        if let Some(addr) = miner {
            miner_address = addr;
        } else {
            return Err(Box::new(Exception::new("No miner address was supplied")));
        }

        let prev_miner_balance;
        let prev_from_balance;
        let prev_from_nonce;
        let fee;
        let nonce;

        if let Some(a) = account_map.get(miner_address) {
            prev_miner_balance = StrictU64::new(a.get_balance());
        } else {
            return Err(Box::new(Exception::new(
                "Block miner not found in account map",
            )));
        }

        let from;
        if let Some(f) = tx.get_from() {
            from = f;
            if let Some(a) = account_map.get(&from) {
                prev_from_balance = StrictU64::new(a.get_balance());
                prev_from_nonce = a.get_nonce();
            } else {
                return Err(Box::new(Exception::new(
                    "Invalid Tx: Tx is missing from account",
                )));
            }
        } else {
            return Err(Box::new(Exception::new("Invalid Tx: Tx is missing from")));
        }

        if let Some(f) = tx.get_fee() {
            fee = StrictU64::new(f);
        } else {
            return Err(Box::new(Exception::new("Invalid Tx: Tx is missing fee")));
        }

        if let Some(n) = tx.get_nonce() {
            nonce = n;
        } else {
            return Err(Box::new(Exception::new("Invalid Tx: Tx is missing nonce")));
        }

        if nonce != prev_from_nonce {
            return Err(Box::new(Exception::new(&format!(
                "Invalid Tx:\n Expected nonce: {}\n Supplied nonce: {}",
                prev_from_nonce, nonce
            ))));
        }

        let amount = StrictU64::new(tx.get_amount());
        let total = (amount + fee)?;

        // Handle the from account and miner account
        let new_from_balance = (prev_from_balance - total)?;
        let new_miner_balance = (prev_miner_balance + fee)?;

        let new_from_nonce = prev_from_nonce + 1;

        // Handle the to account if one is supplied
        if let Some(to) = tx.get_to() {
            if let Some(to_account) = account_map.get_mut(&to) {
                let prev_to_balance = StrictU64::new(to_account.get_balance());

                let new_to_balance = (prev_to_balance + amount)?;

                // Begin committing updates to account map if the previous line succeeded
                to_account.set_balance(u64::from(new_to_balance));
            } else {
                return Err(Box::new(Exception::new(
                    "Invalid Tx: Tx to account does not exist",
                )));
            }
        }

        // Commit updates for the from address to the account map
        if let Some(from_account) = account_map.get_mut(&from) {
            from_account.set_balance(u64::from(new_from_balance));
            from_account.set_nonce(new_from_nonce);
        } else {
            return Err(Box::new(Exception::new("Corrupt account map")));
        }

        // Commit updates for the miner address to the account map
        if let Some(miner_account) = account_map.get_mut(miner_address) {
            miner_account.set_balance(u64::from(new_miner_balance));
        } else {
            return Err(Box::new(Exception::new("Corrupt account map")));
        }

        return Ok(());
    }

    fn revert_tx_transition<TxType>(
        tx: &TxType,
        account_map: &mut HashMap<Address, ProtoAccount>,
        miner: Option<&Address>,
    ) -> StateProcessorResult<()>
    where
        TxType: Transaction<Address, RecoverableSignature, RecoveryId>,
    {
        let miner_address;
        if let Some(addr) = miner {
            miner_address = addr;
        } else {
            return Err(Box::new(Exception::new("No miner address was supplied")));
        }

        let prev_miner_balance;
        let prev_from_balance;
        let prev_from_nonce;
        let fee;

        if let Some(a) = account_map.get(miner_address) {
            prev_miner_balance = StrictU64::new(a.get_balance());
        } else {
            return Err(Box::new(Exception::new(
                "Block miner not found in account map",
            )));
        }

        let from;
        if let Some(f) = tx.get_from() {
            from = f;
            if let Some(a) = account_map.get(&from) {
                prev_from_balance = StrictU64::new(a.get_balance());
                prev_from_nonce = a.get_nonce();
            } else {
                return Err(Box::new(Exception::new(
                    "Invalid Tx: Tx is missing from account",
                )));
            }
        } else {
            return Err(Box::new(Exception::new("Invalid Tx: Tx is missing from")));
        }

        if let Some(f) = tx.get_fee() {
            fee = StrictU64::new(f);
        } else {
            return Err(Box::new(Exception::new("Invalid Tx: Tx is missing fee")));
        }

        let amount = StrictU64::new(tx.get_amount());
        let total = (amount + fee)?;

        // Handle the from account and miner account
        let new_from_balance = (prev_from_balance + total)?;
        let new_miner_balance = (prev_miner_balance - fee)?;

        let new_from_nonce = prev_from_nonce - 1;

        // Handle the to account if one is supplied
        if let Some(to) = tx.get_to() {
            if let Some(to_account) = account_map.get_mut(&to) {
                let prev_to_balance = StrictU64::new(to_account.get_balance());

                let new_to_balance = (prev_to_balance - amount)?;

                // Begin committing updates to account map if the previous line succeeded
                to_account.set_balance(u64::from(new_to_balance));
            } else {
                return Err(Box::new(Exception::new(
                    "Invalid Tx: Tx to account does not exist",
                )));
            }
        }

        // Commit updates for the from address to the account map
        if let Some(from_account) = account_map.get_mut(&from) {
            from_account.set_balance(u64::from(new_from_balance));
            from_account.set_nonce(new_from_nonce);
        } else {
            return Err(Box::new(Exception::new("Corrupt account map")));
        }

        // Commit updates for the miner address to the account map
        if let Some(miner_account) = account_map.get_mut(miner_address) {
            miner_account.set_balance(u64::from(new_miner_balance));
        } else {
            return Err(Box::new(Exception::new("Corrupt account map")));
        }

        return Ok(());
    }

    fn apply_transition(
        transition: HashMap<Address, ProtoAccount>,
        root: &[u8],
    ) -> StateProcessorResult<Vec<u8>> {
        return Err(Box::new(Exception::new("Not Implemented")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::tx::Tx;

    fn it_applies_a_tx_transition() {
        let from_addr = "H27McLosW8psFMbQ8VPQwXxnUY8QAHBHr".to_string();
        //        let tx = Tx::new();
    }
}
