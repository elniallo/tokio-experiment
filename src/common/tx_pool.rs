use common::address::{Address, ValidAddress};
use common::signed_tx::SignedTx;
use common::Encode;
use util::hash::hash;

use std::cmp::Ordering;
use std::cmp::PartialOrd;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
pub struct ITxQueue {
    pub sum: u64,
    pub queue: Vec<SignedTx>,
    pub address: Address,
    pub last_nonce: u32,
}

pub struct PendingTxs<'a> {
    pub txs: Vec<&'a SignedTx>,
    pub length: usize,
    pub total_amount: u64,
    pub total_fee: u64,
}

const BROADCAST_TX_NUMBER: usize = 30;
const MAX_TXS_PER_ADDRESS: usize = 64;
const MAX_ADDRESSES: usize = 36000;

impl PartialOrd for ITxQueue {
    fn partial_cmp(&self, other: &ITxQueue) -> Option<Ordering> {
        Some(self.sum.cmp(&other.sum).reverse())
    }
}

impl Ord for ITxQueue {
    fn cmp(&self, other: &ITxQueue) -> Ordering {
        self.sum.cmp(&other.sum).reverse()
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
    tx_seen_list: VecDeque<Vec<u8>>,
}

impl TxPool {
    pub fn new() -> TxPool {
        TxPool {
            pool: HashMap::new(),
            tx_seen_list: VecDeque::with_capacity(100000),
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
            if self.tx_seen_list.len() == self.tx_seen_list.capacity() - 1 {
                self.tx_seen_list.pop_front();
            }
            // Put Tx in pool
            match self.put_tx(tx) {
                Some(put_tx) => broadcast.push(put_tx),
                None => {}
            }
        }
        for ref tx in &broadcast {
            self.tx_seen_list.push_back(hash(&tx.encode().unwrap(), 32));
        }
        // Return New Txs To Be returned for Broadcast
        broadcast
    }

    fn put_tx(&mut self, tx: SignedTx) -> Option<SignedTx> {
        if self.pool.len() >= MAX_ADDRESSES {
            return None;
        }
        // Retrieve Account ITxQueue
        let mut opt: Option<ITxQueue> = None;
        let mut broadcast: bool = false;
        match self.pool.get_mut(&tx.from.to_vec()) {
            Some(account) => {
                if tx.nonce <= account.last_nonce + 1 && account.queue.len() < MAX_TXS_PER_ADDRESS {
                    account.queue.push(tx.clone());
                    account.sum += tx.fee;
                    account.last_nonce = tx.nonce;
                    account.queue.sort();
                    broadcast = true;
                }
            }
            None => {
                let tx_queue = ITxQueue {
                    sum: tx.fee,
                    queue: vec![tx.clone()],
                    address: tx.from,
                    last_nonce: tx.nonce,
                };
                broadcast = true;
                opt = Some(tx_queue);
            }
        }
        match opt {
            Some(queue) => {
                self.pool.insert(tx.clone().from.to_vec(), queue);
            }
            None => {}
        }
        if broadcast {
            Some(tx)
        } else {
            None
        }
    }

    pub fn remove_txs(&mut self, txs: &Vec<SignedTx>) {
        for tx in txs {
            self.remove_tx(tx);
        }
        self.pool.retain(|key, account| account.queue.len() > 0);
    }

    fn remove_tx(&mut self, tx: &SignedTx) {
        // Get Correct Queue
        match self.pool.get_mut(&tx.from.to_vec()) {
            Some(account) => {
                account.queue.retain(|pool_tx| pool_tx != tx);
                account.queue.sort();
            }
            None => {} // Sort
        }
    }

    pub fn get_txs(&self, count: u16) -> Vec<&SignedTx> {
        // let mut accounts: Vec<&ITxQueue> = Vec::with_capacity(self.pool.len());
        let mut txs: Vec<&SignedTx> = Vec::with_capacity(count as usize);
        let mut accounts: Vec<&ITxQueue> = self.pool
            .iter()
            .map(|(_key, queue)| queue)
            .collect::<Vec<_>>();
        accounts.sort();
        for queue in accounts {
            if txs.len() == txs.capacity() {
                break;
            }
            for tx in &queue.queue {
                if txs.len() < txs.capacity() {
                    txs.push(&tx);
                } else {
                    break;
                }
            }
        }
        txs.shrink_to_fit();
        txs
    }

    pub fn get_pending(&self, index: usize, count: usize) -> PendingTxs {
        let pool_txs: Vec<&SignedTx> = self.get_txs(4096);
        let mut sums: (u64, u64) = (0, 0);
        for tx in &pool_txs {
            sums = (sums.0 + tx.amount, sums.1 + tx.fee)
        }
        let mut last: usize = index + count;
        if &last > &pool_txs.len() {
            last = pool_txs.len();
        }
        PendingTxs {
            length: pool_txs.len(),
            txs: pool_txs[index..last].to_vec(),
            total_amount: sums.0,
            total_fee: sums.1,
        }
    }

    pub fn get_txs_of_address(&self, address: &Address) -> Vec<&SignedTx> {
        let add = address;
        let mut txs: Vec<&SignedTx> = Vec::new();
        match self.pool.get(&add.to_vec()) {
            Some(queue) => for tx in &queue.queue {
                txs.push(tx)
            },
            None => {}
        }
        txs
    }

    pub fn prepare_for_broadcast(&self) -> Vec<&SignedTx> {
        let mut broadcast: Vec<&SignedTx> = Vec::with_capacity(BROADCAST_TX_NUMBER);
        let mut accounts: Vec<&ITxQueue> = self.pool
            .iter()
            .map(|(_key, queue)| queue)
            .collect::<Vec<_>>();
        accounts.sort();
        let max_length = self.get_max_length(&accounts);
        for i in 0..max_length {
            for account in &accounts {
                if i >= account.queue.len() {
                    continue;
                }
                broadcast.push(&account.queue[i]);
                if broadcast.len() == BROADCAST_TX_NUMBER {
                    return broadcast;
                }
            }
        }
        broadcast
    }
    fn get_max_length(&self, pool: &Vec<&ITxQueue>) -> usize {
        let mut max = 0;
        for account in pool {
            if account.queue.len() > max {
                max = account.queue.len()
            }
        }
        max
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
        let signed_tx2 = SignedTx::new(from, to, amount, fee, 2, signature, recovery);
        let signed_txs = vec![signed_tx, signed_tx2];

        // Test Method
        let broadcast = tx_pool.put_txs(signed_txs);

        // Test Results
        assert_eq!(tx_pool.pool.len(), 1);
        assert_eq!(broadcast.len(), 2);
        match tx_pool.pool.get(&from.to_vec()) {
            Some(queue) => {
                assert_eq!(queue.sum, 2 * fee);
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
        assert_eq!(tx_pool.get_txs_of_address(&from).len(), 1);
        assert_eq!(tx_pool.pool.len(), 1);
        tx_pool.remove_txs(&signed_txs);
        // Test Results
        assert_eq!(tx_pool.get_txs_of_address(&from).len(), 0);
        assert_eq!(tx_pool.pool.len(), 0);
    }
    #[test]
    fn should_not_add_already_seen_tx() {
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
        let signed_txs = vec![signed_tx.clone()];

        tx_pool.put_txs(signed_txs.clone());
        assert_eq!(tx_pool.get_txs_of_address(&from).len(), 1);
        assert_eq!(tx_pool.pool.len(), 1);
        tx_pool.remove_txs(&signed_txs);
        // Test Results
        assert_eq!(tx_pool.get_txs_of_address(&from).len(), 0);
        assert_eq!(tx_pool.pool.len(), 0);
        tx_pool.put_txs(signed_txs.clone());
        assert_eq!(tx_pool.pool.len(), 0);
    }
    #[test]
    fn should_get_txs() {
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

        let stx1 = SignedTx::new(from, to, amount, fee, nonce, signature, recovery);
        let stx2 = SignedTx::new(to, from, amount, fee, nonce, signature, recovery);
        let stx3 = SignedTx::new(from, to, amount, fee, 2, signature, recovery);
        let stx4 = SignedTx::new(to, from, amount, fee, 2, signature, recovery);
        let stx5 = SignedTx::new(to, from, amount, fee, 3, signature, recovery);
        tx_pool.put_txs(vec![stx1, stx2, stx3, stx4, stx5]);
        assert_eq!(tx_pool.pool.len(), 2);
        match tx_pool.pool.get(&from.to_vec()) {
            Some(queue) => assert_eq!(queue.sum, 2),
            None => {}
        }
        match tx_pool.pool.get(&to.to_vec()) {
            Some(queue) => assert_eq!(queue.sum, 3),
            None => {}
        }
        //Test Method
        let txs = tx_pool.get_txs(100);
        assert_eq!(txs.len(), 5);
        assert_eq!(tx_pool.get_txs(4).len(), 4);
        assert_eq!(txs[0].from, to);
    }

    #[test]
    fn should_allow_for_pagination_of_pending_txs() {
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

        let stx1 = SignedTx::new(from, to, amount, fee, nonce, signature, recovery);
        let stx2 = SignedTx::new(to, from, amount, fee, nonce, signature, recovery);
        let stx3 = SignedTx::new(from, to, amount, fee, 2, signature, recovery);
        let stx4 = SignedTx::new(to, from, amount, fee, 2, signature, recovery);
        let stx5 = SignedTx::new(to, from, amount, fee, 3, signature, recovery);
        tx_pool.put_txs(vec![stx1, stx2, stx3, stx4, stx5]);

        //Test Function
        let pending = tx_pool.get_pending(0, 3);
        assert_eq!(pending.txs.len(), 3);
        assert_eq!(pending.length, 5);
        assert_eq!(pending.total_amount, 500);
        let page2 = tx_pool.get_pending(3, 3);
        assert_eq!(page2.txs.len(), 2);
        assert_eq!(page2.length, 5);
        assert_eq!(page2.total_amount, 500);
    }

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

    #[test]
    fn it_should_return_priority_transactions_to_be_broadcast() {
        let mut tx_pool = TxPool::new();
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

        let stx1 = SignedTx::new(from, to, amount, fee, nonce, signature, recovery);
        let stx2 = SignedTx::new(to, from, amount, fee, nonce, signature, recovery);
        let stx3 = SignedTx::new(from, to, amount, fee, 2, signature, recovery);
        let stx4 = SignedTx::new(to, from, amount, fee, 2, signature, recovery);
        let stx5 = SignedTx::new(to, from, amount, fee, 3, signature, recovery);
        tx_pool.put_txs(vec![stx1, stx2, stx3, stx4, stx5]);

        // Test
        let broadcast = tx_pool.prepare_for_broadcast();
        assert_eq!(broadcast.len(), 5);
    }
}
