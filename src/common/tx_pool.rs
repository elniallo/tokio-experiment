use common::address::{Address, ValidAddress};
use common::signed_tx::SignedTx;

use std::cmp::Ordering;
use std::cmp::PartialOrd;
use std::collections::BinaryHeap;
#[derive(Debug, Clone)]
pub struct ITxQueue {
    pub sum: u64,
    pub queue: BinaryHeap<SignedTx>,
    pub address: String,
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
    pub pool: BinaryHeap<ITxQueue>,
}

impl TxPool {
    pub fn new() -> TxPool {
        TxPool {
            pool: BinaryHeap::new(),
        }
    }

    pub fn put_txs(&self, txs: &Vec<SignedTx>) {}

    pub fn remove_txs(&self, txs: &Vec<SignedTx>) {}

    pub fn get_txs(&self, count: u16) -> Vec<SignedTx> {
        Vec::new()
    }

    pub fn get_pending(&self, index: u16, count: u16) -> Vec<SignedTx> {
        Vec::new()
    }

    pub fn get_txs_of_address(&self, address: &Address) -> Vec<SignedTx> {
        let add = address.to_string();
        for account in &self.pool {
            match &account.address {
                add => return account.queue.clone().into_sorted_vec(),
            };
        }
        vec![]
    }

    pub fn prepare_for_broadcast(&self) -> Vec<SignedTx> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::address::{Address, ValidAddress};
    use common::signed_tx::SignedTx;
    use common::tx::Tx;
    use secp256k1::{Error as SecpError, Message, RecoverableSignature, RecoveryId, Secp256k1};
    #[test]
    fn add_tx_to_pool() {
        // Initialise Pool
        let tx_pool = TxPool::new();

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
        tx_pool.put_txs(&signed_txs);

        // Test Results
        let pool = tx_pool.pool.into_sorted_vec();
        assert_eq!(pool.len(), 1);
        assert_eq!(pool[0].address, from_addr);
        assert_eq!(pool[0].sum, fee);
    }
    #[test]
    fn remove_from_tx_pool() {
        // Initialise Pool
        let tx_pool = TxPool::new();

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
        tx_pool.put_txs(&signed_txs);
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
        let mut queue = ITxQueue {
            sum: fee,
            queue: BinaryHeap::new(),
            address: from_addr,
        };
        queue.queue.push(signed_tx);
        tx_pool.pool.push(queue.clone());
        let q = tx_pool.pool.peek();
        match q {
            Some(q) => assert_eq!(q, &queue),
            None => {}
        };
        assert_eq!(tx_pool.get_txs_of_address(&from).len(), 1);
    }
}
