use protobuf::ProtobufError;
use secp256k1::Error as SecpError;

pub mod address;
pub mod genesis_tx;
pub mod genesis_signed_tx;
pub mod signed_tx;
pub mod tx;
pub mod header;
pub mod genesis_header;
// pub mod block;
// pub mod genesis_block;
// pub mod meta_info;

pub trait Encode<ErrorType> {
    fn encode(&self) -> Result<Vec<u8>, ErrorType>;
}

pub trait Proto<ErrorType> {
    type ProtoType;
    fn to_proto(&self) -> Result<Self::ProtoType, ErrorType>;
}

#[derive(Debug)]
pub enum EncodingError {
    Proto(ProtobufError),
    Secp(SecpError),
    Integrity(String)
}

