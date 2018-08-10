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