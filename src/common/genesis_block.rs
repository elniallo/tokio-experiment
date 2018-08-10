use common::block::{Block, Embodied, Headed, Meta};
use common::genesis_signed_tx::GenesisSignedTx;
use common::tx::{Quantifiable, Sendable, Signed, Tx};
use common::header::{Header, Rooted};
use common::genesis_header::GenesisHeader;
use common::meta_info::MetaInfo;

type GenesisBlockHeader = GenesisHeader<Header>;
type GenesisBlockTx = GenesisSignedTx<Tx>;

struct GenesisBlock<T>(T);

impl Headed<GenesisBlockHeader> for GenesisBlock<Block<GenesisBlockHeader, GenesisBlockTx>> 
    where GenesisBlockHeader: Rooted {
    fn get_header(&self) -> &GenesisBlockHeader {
        &self.0.header
    }
}

impl Embodied<GenesisBlockTx> for GenesisBlock<Block<GenesisBlockHeader, GenesisBlockTx>> 
    where GenesisBlockTx: Quantifiable + Sendable + Signed,
          GenesisBlockHeader: Rooted {
    fn get_txs(&self) -> Result<Vec<GenesisBlockTx>, String> {
        match self.0.txs.clone() {
            Some(data) => Ok(data),
            None => Err("Block has no record of transactions".to_string())
        }
    }
}

impl Meta for GenesisBlock<Block<GenesisBlockHeader, GenesisBlockTx>> 
    where GenesisBlockHeader: Rooted,
          GenesisBlockTx: Quantifiable + Sendable + Signed {
    fn get_meta(&self) -> Result<MetaInfo, String> {
        match self.0.meta.clone() {
            Some(data) => Ok(data),
            None => Err("Block has no meta information".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_makes_a_genesis_block_with_no_txs() {
        // Set up header
        let merkle_root = vec![218,175,98,56,136,59,157,43,178,250,66,
            194,50,129,87,37,147,54,157,79,238,83,118,209,92,202,25,32,246,230,153,39];
        let state_root = vec![121,132,139,154,165,229,182,152,126,204,
            58,142,150,220,236,119,144,1,181,107,19,130,67,220,241,192,46,94,69,215,134,11];
        let time_stamp = 1515003305000;
        let difficulty: f64 = 0 as f64;

        let header = Header::new(merkle_root.clone(), time_stamp, difficulty, state_root.clone(), None, None, None);
        let genesis_header = GenesisHeader(header);
        let block = Block::new(genesis_header.clone(), None, None);
        let genesis_block = GenesisBlock(block);

        match genesis_block.get_txs() {
            Ok(_) => panic!("No transactions were given, but the genesis block has transactions!"),
            Err(_) => {}
        }

        match genesis_block.get_meta() {
            Ok(_) => panic!("No meta information was given, but the genesis block has meta information!"),
            Err(_) => {}
        }

        assert_eq!(genesis_block.get_header(), &genesis_header);
    }

    #[test]
    fn it_makes_a_genesis_block_with_txs() {
        panic!();
    }

    #[test]
    fn it_encodes_a_genesis_block_with_no_txs() {
        panic!();
    }

    #[test]
    fn it_encodes_a_genesis_block_with_txs() {
        panic!();
    }
}