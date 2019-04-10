use std::error::Error;
use std::ops::Deref;

use crate::common::block::Block;
use crate::common::exodus_tx::ExodusTx;
use crate::common::genesis_header::GenesisHeader;
use crate::traits::{Decode, Encode, Exception, Proto};

use crate::serialization::block::ExodusBlock as ProtoBlock;
use crate::serialization::tx::ExodusTx as ProtoTx;

use protobuf::{Message as ProtoMessage, RepeatedField};

#[derive(Debug)]
pub struct ExodusBlock(pub Block<GenesisHeader, ExodusTx>);

impl Deref for ExodusBlock {
    type Target = Block<GenesisHeader, ExodusTx>;
    fn deref(&self) -> &Block<GenesisHeader, ExodusTx> {
        &self.0
    }
}

impl Decode for ExodusBlock {
    fn decode(bytes: &[u8]) -> Result<Self, Box<Error>> {
        Ok(ExodusBlock(Block::decode(bytes)?))
    }
}

impl Proto for ExodusBlock {
    type ProtoType = ProtoBlock;
    fn to_proto(&self) -> Result<Self::ProtoType, Box<Error>> {
        let mut proto_block = Self::ProtoType::new();
        let proto_header = self.header.to_proto()?;
        proto_block.set_header(proto_header);
        match self.txs.clone() {
            Some(tx_vec) => {
                let mut proto_txs: Vec<ProtoTx> = vec![];
                for tx in tx_vec.into_iter() {
                    match tx.to_proto() {
                        Ok(proto_tx) => proto_txs.push(proto_tx),
                        Err(_) => {}
                    }
                }
                proto_block.set_txs(RepeatedField::from(proto_txs));
            }
            None => {}
        }
        Ok(proto_block)
    }
    fn from_proto(_block: &ProtoBlock) -> Result<Self, Box<Error>> {
        Err(Box::new(Exception::new("Not Implemented")))
    }
}

impl Encode for ExodusBlock {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        let proto_block = self.to_proto()?;
        Ok(proto_block.write_to_bytes()?)
    }
}
