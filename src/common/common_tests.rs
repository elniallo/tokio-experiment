#[cfg(test)]
pub mod common_tests{
    use crate::common::header::Header;
    use crate::common::signed_tx::SignedTx;
    use crate::common::block::Block;
    use crate::common::genesis_block::GenesisBlock;
    
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
}