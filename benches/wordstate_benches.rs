#[macro_use]
extern crate criterion;

use criterion::Criterion;
use hycon_rust::account::account::Account;
use hycon_rust::account::db_state::DBState;
use hycon_rust::account::node_ref::NodeRef;
use hycon_rust::account::state_node::StateNode;
use hycon_rust::common::address::Address;
use hycon_rust::common::exodus_block::ExodusBlock;
use hycon_rust::common::transaction::Transaction;
use hycon_rust::consensus::legacy_trie::LegacyTrie;
use hycon_rust::database::mock::RocksDBMock;
use hycon_rust::database::state_db::StateDB;
use hycon_rust::serialization::state::Account as ProtoAccount;
use hycon_rust::traits::{Decode, Encode, Proto};
use hycon_rust::util::hash::hash;
use starling::traits::Database;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

fn get_from_trie_best_case(c: &mut Criterion) {
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
    c.bench_function("Get from Trie: Best Case", move |b| {
        b.iter(|| {
            legacy_trie.get(
                &state_hash,
                &vec![[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
            )
        })
    });
}

fn exodus(c: &mut Criterion) {
    let mut path = env::current_dir().unwrap();
    path.push("data/exodusBlock.dat");
    let mut exodus_file = File::open(path).unwrap();
    let mut exodus_buf = Vec::new();
    exodus_file.read_to_end(&mut exodus_buf).unwrap();
    let exodus = ExodusBlock::decode(&exodus_buf).unwrap();
    let mut keypairs: Vec<(Address, ProtoAccount)> = Vec::with_capacity(12000);
    let mut addresses: Vec<Address> = Vec::with_capacity(12000);
    let mut accounts: Vec<ProtoAccount> = Vec::with_capacity(12000);
    match &exodus.txs {
        Some(tx_vec) => {
            for tx in tx_vec {
                let amount: u64 = tx.get_amount();
                let nonce: u32;
                if let Some(tx_nonce) = tx.get_nonce() {
                    nonce = tx_nonce;
                } else {
                    break;
                }
                if let Some(add) = tx.get_to() {
                    keypairs.push((add, Account::new(amount, nonce).to_proto().unwrap()));
                } else {
                    break;
                }
            }
        }
        None => {}
    }
    keypairs.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, value) in keypairs.clone() {
        addresses.push(key);
        accounts.push(value);
    }
    let db_path = PathBuf::new();
    c.bench_function("Exodus Block", move |b| {
        let add = addresses.clone();
        let acc = accounts.clone();
        b.iter(|| {
            let state_db: StateDB<RocksDBMock> = StateDB::new(db_path.clone(), None).unwrap();
            let mut tree = LegacyTrie::new(state_db);
            let _root = tree.insert(None, add.clone(), &acc).unwrap();
        });
    });
}

fn get_from_exodus_state(c: &mut Criterion) {
    let mut path = env::current_dir().unwrap();
    path.push("data/exodusBlock.dat");
    let mut exodus_file = File::open(path).unwrap();
    let mut exodus_buf = Vec::new();
    exodus_file.read_to_end(&mut exodus_buf).unwrap();
    let exodus = ExodusBlock::decode(&exodus_buf).unwrap();
    let mut keypairs: Vec<(Address, ProtoAccount)> = Vec::with_capacity(12000);
    let mut addresses: Vec<Address> = Vec::with_capacity(12000);
    let mut accounts: Vec<ProtoAccount> = Vec::with_capacity(12000);
    match &exodus.txs {
        Some(tx_vec) => {
            for tx in tx_vec {
                let amount: u64 = tx.get_amount();
                let nonce: u32;
                if let Some(tx_nonce) = tx.get_nonce() {
                    nonce = tx_nonce;
                } else {
                    break;
                }
                if let Some(add) = tx.get_to() {
                    keypairs.push((add, Account::new(amount, nonce).to_proto().unwrap()));
                } else {
                    break;
                }
            }
        }
        None => {}
    }
    keypairs.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, value) in keypairs.clone() {
        addresses.push(key);
        accounts.push(value);
    }
    let db_path = PathBuf::new();
    let state_db: StateDB<RocksDBMock> = StateDB::new(db_path.clone(), None).unwrap();
    let mut tree = LegacyTrie::new(state_db);
    let root = tree.insert(None, addresses.clone(), &accounts).unwrap();
    c.bench_function("Get After Exodus", move |b| {
        b.iter(|| {
            let _retrieved = &tree.get(&root, &addresses);
        });
    });
}
criterion_group!(
    benches,
    get_from_trie_best_case,
    exodus,
    get_from_exodus_state
);
criterion_main!(benches);
