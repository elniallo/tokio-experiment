use common::address::{Address, ValidAddress};
use common::signed_tx::SignedTx;
use common::Encode;
use util::hash::hash;

use std::cmp::Ordering;
use std::cmp::PartialOrd;
use std::collections::{BinaryHeap, HashMap};

#[derive(Debug, Clone)]
pub struct ITxQueue {
    pub sum: u64,
    pub queue: BinaryHeap<SignedTx>,
    pub address: Address,
    pub last_nonce: u32,
}

pub struct PendingTxs {
    pub txs: Vec<SignedTx>,
    pub length: u16,
    pub total_amount: u64,
    pub total_fee: u64,
}

impl PartialOrd for ITxQueue {
    fn partial_cmp(&self, other: &ITxQueue) -> Option<Ordering> {
        Some(self.sum.cmp(&other.sum))
    }
}

impl Ord for ITxQueue {
    fn cmp(&self, other: &ITxQueue) -> Ordering {
        self.sum.cmp(&other.sum)
    }
}

impl Eq for ITxQueue {}

impl PartialEq for ITxQueue {
    fn eq(&self, other: &ITxQueue) -> bool {
        self.address == other.address
    }
}

pub struct TxPool {
    pub pool: HashMap<Vec<u8>, ITxQueue>,
    tx_seen_list: Vec<Vec<u8>>,
}

impl TxPool {
    pub fn new() -> TxPool {
        TxPool {
            pool: HashMap::new(),
            tx_seen_list: Vec::with_capacity(100000),
        }
    }

    pub fn put_txs(&mut self, mut txs: Vec<SignedTx>) -> Vec<SignedTx> {
        txs.sort();
        let mut broadcast = Vec::new();
        // Assume Txs that reach here have passed world state validation (TODO)
        // Loop through Txs
        for tx in txs {
            // Check if tx already processed
            if self.tx_seen_list.contains(&hash(&tx.encode().unwrap(), 32)) {
                continue;
            }
            // Put Tx in pool
            match self.put_tx(tx) {
                Some(put_tx) => broadcast.push(put_tx),
                None => {}
            }
        }
        // Return New Txs To Be returned for Broadcast
        broadcast
    }

    fn put_tx(&mut self, tx: SignedTx) -> Option<SignedTx> {
        // Retrieve Account ITxQueue - Slow and dirty just implementing to get done
        let tx_queue: ITxQueue;
        match self.pool.clone().get(&tx.from.to_vec()) {
            Some(account) => {}
            None => {
                tx_queue = ITxQueue {
                    sum: tx.fee,
                    queue: BinaryHeap::from(vec![tx.clone()]),
                    address: tx.from,
                    last_nonce: tx.nonce,
                };
                self.pool.insert(tx.clone().from.to_vec(), tx_queue);
                return Some(tx);
            }
        }
        None
    }

    pub fn remove_txs(&self, txs: &Vec<SignedTx>) {}

    pub fn get_txs(&self, count: u16) -> Vec<SignedTx> {
        Vec::new()
    }

    pub fn get_pending(&self, index: u16, count: u16) -> Vec<SignedTx> {
        Vec::new()
    }

    pub fn get_txs_of_address(&self, address: &Address) -> Vec<SignedTx> {
        let add = address;
        match self.pool.get(&add.to_vec()) {
            Some(queue) => queue.queue.clone().into_sorted_vec(),
            None => vec![],
        }
    }

    pub fn prepare_for_broadcast(&self) -> Vec<SignedTx> {
        Vec::new()
    }

    fn update_nonce(&self, mut queue: &ITxQueue, txs: &Vec<SignedTx>) {
        // let las
        // if last_nonce > queue.lastNonce {
        //     queue.lastNonce = last_nonce;
        // }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::address::{Address, ValidAddress};
    use common::signed_tx::SignedTx;
    use common::tx::Tx;

    use std::iter::FromIterator;

    use secp256k1::{Error as SecpError, Message, RecoverableSignature, RecoveryId, Secp256k1};
    #[test]
    fn add_tx_to_pool() {
        // Initialise Pool
        let mut tx_pool = TxPool::new();

        // Test Transaction
        let from_addr = "H27McLosW8psFMbQ8VPQwXxnUY8QAHBHr".to_string();
        let from = Address::from_string(&from_addr).unwrap();
        let to_addr = "H4JSXdLtkXVs6G7fk2xea1dB4hTgQ3ps6".to_string();
        let to = Address::from_string(&to_addr).unwrap();
        let amount = 100;
        let fee = 1;
        let nonce = 1;
        let recovery = RecoveryId::from_i32(0).unwrap();

        let signature_bytes = [
            208, 50, 197, 4, 84, 254, 196, 173, 123, 37, 234, 93, 48, 249, 247, 56, 156, 54, 7,
            211, 17, 121, 174, 74, 111, 1, 7, 184, 82, 196, 94, 176, 73, 221, 78, 105, 137, 12,
            165, 212, 15, 47, 134, 101, 221, 69, 158, 19, 237, 120, 63, 173, 92, 215, 144, 224,
            100, 78, 84, 128, 237, 25, 234, 206,
        ];
        let secp = Secp256k1::without_caps();
        let signature =
            RecoverableSignature::from_compact(&secp, &signature_bytes, recovery).unwrap();
        let signed_tx = SignedTx::new(from, to, amount, fee, nonce, signature, recovery);
        let signed_txs = vec![signed_tx];

        // Test Method
        let broadcast = tx_pool.put_txs(signed_txs);

        // Test Results
        let pool = Vec::from_iter(tx_pool.pool.iter());
        assert_eq!(pool.len(), 1);
        assert_eq!(broadcast.len(), 1);
        match tx_pool.pool.get(&from.to_vec()) {
            Some(queue) => {
                assert_eq!(queue.sum, fee);
                assert_eq!(queue.address, from);
            }
            None => {}
        }
    }
    #[test]
    fn remove_from_tx_pool() {
        // Initialise Pool
        let mut tx_pool = TxPool::new();

        // Test Transaction
        let from_addr = "H27McLosW8psFMbQ8VPQwXxnUY8QAHBHr".to_string();
        let from = Address::from_string(&from_addr).unwrap();
        let to_addr = "H4JSXdLtkXVs6G7fk2xea1dB4hTgQ3ps6".to_string();
        let to = Address::from_string(&to_addr).unwrap();
        let amount = 100;
        let fee = 1;
        let nonce = 1;
        let recovery = RecoveryId::from_i32(0).unwrap();

        let signature_bytes = [
            208, 50, 197, 4, 84, 254, 196, 173, 123, 37, 234, 93, 48, 249, 247, 56, 156, 54, 7,
            211, 17, 121, 174, 74, 111, 1, 7, 184, 82, 196, 94, 176, 73, 221, 78, 105, 137, 12,
            165, 212, 15, 47, 134, 101, 221, 69, 158, 19, 237, 120, 63, 173, 92, 215, 144, 224,
            100, 78, 84, 128, 237, 25, 234, 206,
        ];
        let secp = Secp256k1::without_caps();
        let signature =
            RecoverableSignature::from_compact(&secp, &signature_bytes, recovery).unwrap();

        let signed_tx = SignedTx::new(from, to, amount, fee, nonce, signature, recovery);
        let signed_txs = vec![signed_tx];

        // Test Method
        tx_pool.put_txs(signed_txs.clone());
        tx_pool.remove_txs(&signed_txs);
        // Test Results
        assert_eq!(tx_pool.pool.len(), 0);
    }
    #[test]
    fn should_get_txs() {}

    #[test]
    fn should_get_txs_from_address() {
        // Initialise pool
        let mut tx_pool = TxPool::new();
        //Check Empty for missing Address
        let to_addr = "H4JSXdLtkXVs6G7fk2xea1dB4hTgQ3ps6".to_string();
        let to = Address::from_string(&to_addr).unwrap();
        assert_eq!(tx_pool.get_txs_of_address(&to).len(), 0);
        let from_addr = "H27McLosW8psFMbQ8VPQwXxnUY8QAHBHr".to_string();
        let from = Address::from_string(&from_addr).unwrap();
        let amount = 100;
        let fee = 1;
        let nonce = 1;
        let recovery = RecoveryId::from_i32(0).unwrap();

        let signature_bytes = [
            208, 50, 197, 4, 84, 254, 196, 173, 123, 37, 234, 93, 48, 249, 247, 56, 156, 54, 7,
            211, 17, 121, 174, 74, 111, 1, 7, 184, 82, 196, 94, 176, 73, 221, 78, 105, 137, 12,
            165, 212, 15, 47, 134, 101, 221, 69, 158, 19, 237, 120, 63, 173, 92, 215, 144, 224,
            100, 78, 84, 128, 237, 25, 234, 206,
        ];
        let secp = Secp256k1::without_caps();
        let signature =
            RecoverableSignature::from_compact(&secp, &signature_bytes, recovery).unwrap();

        let signed_tx = SignedTx::new(from, to, amount, fee, nonce, signature, recovery);
        tx_pool.put_txs(vec![signed_tx.clone()]);
        tx_pool.put_txs(vec![signed_tx.clone()]);
        assert_eq!(tx_pool.get_txs_of_address(&from).len(), 1);
    }
}
