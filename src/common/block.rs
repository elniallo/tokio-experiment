use common::meta_info::MetaInfo;
use common::signed_tx::SignedTx;
use common::tx::{Quantifiable, Countable, Signed, Tx};
use common::header::{Rooted, Header, Mined, Raw};
use common::Encode;

use serialization::block::Block as ProtoBlock;
use serialization::tx::SignedTx as ProtoTx;

use protobuf::{Message, RepeatedField};

pub struct Block<T, U>
    where T: Rooted,
          U: Quantifiable + Signed {
    pub header: T,
    pub txs: Option<Vec<U>>,
    pub meta: Option<MetaInfo>,
}

pub trait Headed<T> {
    fn get_header(&self) -> &T;
}

pub trait Embodied<T> {
    fn get_txs(&self) -> Result<Vec<T>, String>;
}

pub trait Meta {
    fn get_meta(&self) -> Result<MetaInfo, String>;
}

impl Block<Header, SignedTx<Tx>>
    where Header: Rooted + Raw + Mined,
          SignedTx<Tx>: Quantifiable + Countable + Signed {
    fn from_header(header: Header)-> Block<Header, SignedTx<Tx>> {
        Block {
            header,
            txs: None,
            meta: None
        }
    }
}

impl Encode for Block<Header, SignedTx<Tx>> 
    where Block<Header, SignedTx<Tx>>: Headed<Header> + Embodied<SignedTx<Tx>> + Meta{
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut proto_block = ProtoBlock::new();
        proto_block.set_header(self.get_header().to_proto_header());
        let txs = self.get_txs();
        match txs {
            Ok(tx_vec) => {
                let proto_txs: Vec<ProtoTx> = tx_vec.into_iter().map(|x| -> ProtoTx {x.to_proto_signed_tx()}).collect();
                proto_block.set_txs(RepeatedField::from(proto_txs));
            },
            Err(e) => return Err(e)
        }
        let block_bytes = proto_block.write_to_bytes();
        match block_bytes {
            Ok(data) => Ok(data),
            Err(e) => Err(e.to_string())
        }

    }
}



impl Headed<Header> for Block<Header, SignedTx<Tx>>
    where Header: Rooted + Raw + Mined,
          SignedTx<Tx>: Quantifiable + Countable + Signed {
    fn get_header(&self) -> &Header {
        &self.header
    }
}

impl Embodied<SignedTx<Tx>> for Block<Header, SignedTx<Tx>>
    where Header: Rooted + Raw + Mined,
          SignedTx<Tx>: Quantifiable + Countable + Signed {
    
    fn get_txs(&self) -> Result<Vec<SignedTx<Tx>>, String> {
        match self.txs.clone() {
            Some(data) => Ok(data),
            None => Err("Block has no record of transactions".to_string())
        }
    }
}

impl Meta for Block<Header, SignedTx<Tx>>
    where Header: Rooted + Raw + Mined,
          SignedTx<Tx>: Quantifiable + Countable + Signed {
    fn get_meta(&self) -> Result<MetaInfo, String> {
        match self.meta.clone() {
            Some(data) => Ok(data),
            None => Err("Block has no meta info".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::address::{Address, ValidAddress};
    use rust_base58::FromBase58;

    #[test]
    fn it_makes_a_block_from_header() {
        let merkle_root = vec![218,175,98,56,136,59,157,43,178,250,66,194,50,129,
            87,37,147,54,157,79,238,83,118,209,92,202,25,32,246,230,153,39];
        let state_root = vec![121,132,139,154,165,229,182,152,126,204,58,142,150,
            220,236,119,144,1,181,107,19,130,67,220,241,192,46,94,69,215,134,11];
        let time_stamp = 1515003305000;
        let difficulty = 0 as f64;
        let nonce = 0;
        let miner = Address::from_string(&"H3yGUaF38TxQxoFrqCqPdB2pN9jyBHnaj".to_string()).unwrap();
        let previous_hash = vec!["G4qXusbRyXmf62c8Tsha7iZoyLsVGfka7ynkvb3Esd1d".from_base58().unwrap()];
        let header = Header::new(merkle_root.clone(), time_stamp, difficulty, state_root.clone(), Some(previous_hash.clone()), Some(nonce), Some(miner));
        let block = Block::from_header(header.clone());
        let txs = block.get_txs();
        match txs {
            Ok(_) => panic!("Only a header was provided, but the block has transactions!"),
            Err(_) => {}
        }
        let meta = block.get_meta();
        match meta {
            Ok(_) => panic!("Only a header was provided, but the block has meta data!"),
            Err(_) => {}
        }
        assert_eq!(block.get_header(), &header);
    }

    fn it_makes_a_block_with_txs() {
        
    }
}