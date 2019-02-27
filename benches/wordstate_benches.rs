#[macro_use]
extern crate criterion;

use criterion::Criterion;
use hycon_rust::account::account::Account;
use hycon_rust::account::db_state::DBState;
use hycon_rust::account::node_ref::NodeRef;
use hycon_rust::account::state_node::StateNode;
use hycon_rust::consensus::legacy_trie::LegacyTrie;
use hycon_rust::database::mock::RocksDBMock;
use hycon_rust::database::state_db::StateDB;
use hycon_rust::traits::Encode;
use hycon_rust::util::hash::hash;
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
        let _ = state_db.set(&hash, &db_state);
        let location = vec![
            i as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let node_ref = NodeRef::new(&location, &hash);
        accounts.push(node_ref);
    }
    let state_node = StateNode::new(accounts);
    let state_hash = hash(state_node.encode().unwrap().as_ref(), 32);
    let db_state = DBState::new(None, Some(state_node), 1);
    state_db.set(&state_hash, &db_state);
    let legacy_trie = LegacyTrie::new(state_db);
    let returned_accounts = legacy_trie.get_multiple(
        &state_hash,
        vec![[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
    );
    c.bench_function("Get from Trie: Best Case", move |b| {
        b.iter(|| {
            legacy_trie.get_multiple(
                &state_hash,
                vec![[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
            )
        })
    });
}
criterion_group!(benches, get_from_trie_best_case);
criterion_main!(benches);
