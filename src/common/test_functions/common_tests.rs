use crate::common::address::{Address, ValidAddress};
use crate::common::block::Block;
use crate::common::genesis_block::GenesisBlock;
use crate::common::genesis_tx::GenesisTx;
use crate::common::header::Header;
use crate::common::signed_tx::SignedTx;
use crate::common::tx::Tx;
use crate::common::wallet::Wallet;

use rand::Rng;

pub fn assert_block(block: Block<Header, SignedTx>, compare_block: Block<Header, SignedTx>) {
    assert_eq!(
        block.header.previous_hash,
        compare_block.header.previous_hash
    );
    assert_eq!(block.header.merkle_root, compare_block.header.merkle_root);
    assert_eq!(block.header.state_root, compare_block.header.state_root);
    assert_eq!(block.header.difficulty, compare_block.header.difficulty);
    assert_eq!(block.header.nonce, compare_block.header.nonce);
    assert_eq!(block.header.miner, compare_block.header.miner);
    assert_eq!(block.header.time_stamp, compare_block.header.time_stamp);
    match block.txs {
        Some(ref txs) => assert_eq!(txs.len(), compare_block.txs.unwrap().len()),
        None => panic!("txs fail"),
    };
}

pub fn assert_genesis_block(block: GenesisBlock, compare_block: GenesisBlock) {
    assert_eq!(block.header.merkle_root, compare_block.header.merkle_root);
    assert_eq!(block.header.state_root, compare_block.header.state_root);
    assert_eq!(block.header.difficulty, compare_block.header.difficulty);
    assert_eq!(block.header.time_stamp, compare_block.header.time_stamp);
    match block.txs {
        Some(ref txs) => assert_eq!(txs.len(), compare_block.txs.clone().unwrap().len()),
        None => panic!("txs fail"),
    };
}

pub fn create_random_tx<RngType>(from: Address, nonce: u32, rng: &mut RngType) -> Tx
where
    RngType: Rng,
{
    let mut to = create_random_address(rng);

    let amount = rng.gen();
    let fee = rng.gen();

    Tx::new(from, to, amount, fee, nonce)
}

pub fn create_random_genesis_tx<RngType>(rng: &mut RngType) -> GenesisTx
where
    RngType: Rng,
{
    let mut to = [0u8; 20];
    rng.fill(&mut to);

    let amount = rng.gen();

    GenesisTx::new(to, amount)
}

pub fn create_random_signed_tx<RngType>(wallet: &Wallet, nonce: u32, rng: &mut RngType) -> SignedTx
where
    RngType: Rng,
{
    let tx = create_random_tx(Address::from_pubkey(wallet.public_key), nonce, rng);
    wallet.sign_tx(&tx).unwrap()
}

pub fn create_random_wallet<RngType>(rng: &mut RngType) -> Wallet
where
    RngType: Rng,
{
    let private_key = Wallet::generate_private_key(rng);
    Wallet::from_private_key(private_key)
}

pub fn create_random_address<RngType>(rng: &mut RngType) -> Address
where
    RngType: Rng,
{
    let wallet = create_random_wallet(rng);
    Address::from_pubkey(wallet.public_key)
}

// pub fn create_random_block<RngType>(
//     previous_block: Vec<u8>,
//     num_txs: u64,
//     wallet_pool: &mut Vec<Wallet>,
//     rng: &mut RngType,
// ) -> Block<Header, SignedTx>
// where
//     RngType: Rng,
// {
//     let mut txs = Vec::with_capacity(num_txs as usize);
//     let mut remaining_txs = num_txs;

//     for i in 0..wallet_pool.len() {
//         let wallet = &wallet_pool[i];
//         let wallet_txs = rng.gen_range(1, remaining_txs);
//         let mut nonce = 0;
//         for j in 0..wallet_txs {
//             let tx = create_random_signed_tx(&wallet, nonce, rng);
//             txs.push(tx);
//             nonce += 1;
//         }
//         remaining_txs -= wallet_txs;

//         if remaining_txs == 0 {
//             break;
//         }
//     }

//     Block::new(header, Some(txs), None)
// }
