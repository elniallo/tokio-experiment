use std::collections::{HashMap, HashSet};
use std::error::Error;

use common::Exception;
use common::address::Address;
use common::block::Block;
use common::header::Header;
use common::signed_tx::SignedTx;
use common::transaction::Transaction;
use consensus::worldstate::{Blake2bHashResult, WorldState};
use database::block_db::BlockDB;

use serialization::state::Account as ProtoAccount;

const MAX_STATE_CACHE_SIZE: usize = 5000;

type StateProcessorResult<T> = Result<T, Box<Error>>;

pub struct StateProcessor<'a, BlockDBType = BlockDB<'a>, WorldStateType = WorldState, HashresultType = Blake2bHashResult> {
    worldstate: WorldStateType,
    block_db: &'a mut BlockDBType,
    state_cache: Vec<HashresultType>
}

impl<'a> StateProcessor<'a> {
    fn new(block_db: &'a mut BlockDB<'a>, worldstate: WorldState) -> StateProcessor<BlockDB<'a>, WorldState> {
        let state_cache = Vec::with_capacity(MAX_STATE_CACHE_SIZE);
        StateProcessor {
            worldstate,
            block_db,
            state_cache
        }
    }

    fn prune(&mut self) -> Result<(), Box<Error>> {
        if self.state_cache.len() <= MAX_STATE_CACHE_SIZE {
            return Ok(())
        }

        for i in (0..self.state_cache.len() - MAX_STATE_CACHE_SIZE).rev() {
            self.worldstate.remove(self.state_cache[i].as_ref())?;
            self.state_cache.remove(i);
        }

        Ok(())
    }

    fn regenerate(&mut self, height: u32) -> Result<(), Box<Error>> {
        let block_tip = self.block_db.get_block_tip_hash()?;
        let block = self.block_db.get_block::<Block<Header, SignedTx>>(&block_tip)?;
        let tip_height;
        if let Some(m) = block.meta {
            tip_height = m.height;
        } else {
            return Err(Box::new(Exception::new("Block tip does not have height")))
        }

        if tip_height - height <= MAX_STATE_CACHE_SIZE as u32 {
            return Ok(())
        }

        return Err(Box::new(Exception::new("Not Implemented")))
    }

    fn generate_transition(&self, blocks: Vec<&Block<Header, SignedTx>>) -> Result<HashMap<Address, ProtoAccount>, Box<Error>> {
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
            address_keys.push(address_list[i].as_ref())
        }

        // Insert existing balances into a map
        let accounts;
        let mut address_map = HashMap::new();
        if self.state_cache.len() > 0 {
            accounts = self.worldstate.get(&self.state_cache[self.state_cache.len() - 1], address_keys)?;
            for i in 0..accounts.len() {
                if let Some(ref a) = accounts[i] {
                    address_map.insert(address_list[i], a);
                }
            }
        } else {
            accounts = vec![];
        }

        // Process blocks in memory
        for block in &blocks {
            let mut revert = false;
            let mut processed_txs: usize = 0;

            if let Some(ref txs) = block.txs {
                for tx in txs {
                    let mut account;
                    if let Some(ref from) = tx.get_from() {
                        if let Some(a) = address_map.get_mut(from) {
                            account = *a;
                        } else {
                            // Account has no balance, therefore it cannot make a transaction
                            revert = true;
                            break;
                        }
                    } else {
                        // TODO: Generalize this function to handle the genesis block
                        revert = true;
                        break;
                    }

                    // Check tx nonce
                    if let Some(nonce) = tx.get_nonce() {
                        if nonce != account.get_nonce() {
                            revert = true;
                            break;
                        }
                    } else {
                        revert = true;
                        break;
                    }

                    // Check tx amount vs account balance
                    let amount = tx.get_amount();
                    if amount >= account.get_balance() {
                        revert = true;
                        break;
                    }

                    // Check tx fee vs account balance
                    if let Some(fee) = tx.get_fee() {
                        if fee >= account.get_balance() {
                            revert = true;
                            break;
                        }
                    } else {
                        revert = true;
                        break;
                    }
                }
            }

            if revert {
                // TODO: Revert the changes in this block and then stop
            }
        }

        return Err(Box::new(Exception::new("Not Implemented")))
    }

    fn generate_tx_transition<TxType>(tx: &TxType, account_map: &mut HashMap<Address, &ProtoAccount>, miner: Address, genesis: bool) -> StateProcessorResult<()>
        where TxType: Transaction {

        if let Some(from) = tx.get_from() {
            if let Some(account) = account_map.get_mut(&from) {
                if let Some(fee) = tx.get_fee() {
                    if let Some(nonce) = tx.get_nonce() {

                        if nonce != account.get_nonce() {
                            return Err(Box::new(Exception::new("Invalid Tx: Tx has an invalid 'nonce'")))
                        }

                        let amount = tx.get_amount();
                        // TODO: Safely subtract balance + fee from the from account
                        // TODO: Safely add fee to the miner account
                        if let Some(to) = tx.get_to() {
                            // Tx is a normal transaction
                            // TODO: Safely add amount to the to account
                        } else {
                            // Tx is a burn transaction, do nothing more
                        }
                        
                        // TODO: Increment sending account nonce
                    } else {
                        return Err(Box::new(Exception::new("Invalid Tx: Tx is missing the 'nonce' field")))
                    }
                } else {
                    return Err(Box::new(Exception::new("Invalid Tx: Tx is missing the 'fee' field")))
                }
            } else {
                return Err(Box::new(Exception::new("Invalid Tx: Tx account does not exist")))
            }

        } else if genesis {
            // Tx may be a genesis transaction
        } else {
            return Err(Box::new(Exception::new("Invalid Tx: Tx is missing the 'from' field")))
        }

        return Err(Box::new(Exception::new("Not Implemented")))
    }

    fn apply_transition(transition: HashMap<Address, ProtoAccount>, root: &[u8]) -> Result<Vec<u8>, Box<Error>> {
        return Err(Box::new(Exception::new("Not Implemented")))
    }
}