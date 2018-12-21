use std::error::Error;

use common::{Decode, Encode};
use database::database::Database;
use serialization::state::{ProtoMerkleNode, Branch as ProtoBranch, Leaf as ProtoLeaf, Data as ProtoData};

use protobuf::Message as ProtoMessage;
use starling::traits;
use starling::merkle_bit::{BinaryMerkleTreeResult, MerkleBIT, NodeVariant};

impl Encode for ProtoMerkleNode {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        Ok(self.write_to_bytes()?)
    }
}

impl Decode for ProtoMerkleNode {
    fn decode(buffer: &Vec<u8>) -> Result<ProtoMerkleNode, Box<Error>> {
        let mut proto_merkle_node = ProtoMerkleNode::new();
        proto_merkle_node.merge_from_bytes(buffer)?;
        Ok(proto_merkle_node)
    }
}