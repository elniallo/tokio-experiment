use std::error::Error;
use std::cmp::Ordering;

use common::{Decode, Encode, Exception};
use database::database::Database;
use serialization::state::{ProtoMerkleNode, Branch as ProtoBranch, Leaf as ProtoLeaf, Data as ProtoData, Account as ProtoAccount, ProtoMerkleNode_oneof_node as ProtoVariant};

use blake2_rfc::blake2b::{Blake2b, Blake2bResult};
use protobuf::Message as ProtoMessage;
use starling::traits::{Branch, Leaf, Data, Node, Encode as TreeEncode, Decode as TreeDecode, Hasher};
use starling::merkle_bit::{BinaryMerkleTreeResult, MerkleBIT, NodeVariant};

impl Branch for ProtoBranch {
    fn new() -> ProtoBranch {
        ProtoBranch::new()
    }

    fn get_count(&self) -> u64 {
        ProtoBranch::get_count(&self)
    }

    fn get_zero(&self) -> &[u8] {
        ProtoBranch::get_zero(&self)
    }

    fn get_one(&self) -> &[u8] {
        ProtoBranch::get_one(&self)
    }

    fn get_split_index(&self) -> u32 {
        ProtoBranch::get_split_index(&self)
    }

    fn set_count(&mut self, count: u64) {
        ProtoBranch::set_count(self, count)
    }

    fn set_zero(&mut self, zero: &[u8]) {
        ProtoBranch::set_zero(self, zero.to_vec())
    }

    fn set_one(&mut self, one: &[u8]) {
        ProtoBranch::set_one(self, one.to_vec())
    }

    fn set_split_index(&mut self, split_index: u32) {
        ProtoBranch::set_split_index(self, split_index)
    }
}

impl Leaf for ProtoLeaf {
    fn new() -> ProtoLeaf {
        ProtoLeaf::new()
    }

    fn get_key(&self) -> &[u8] {
        ProtoLeaf::get_key(&self)
    }

    fn get_data(&self) -> &[u8] {
        ProtoLeaf::get_data(&self)
    }

    fn set_key(&mut self, key: &[u8]) {
        ProtoLeaf::set_key(self, key.to_vec())
    }

    fn set_data(&mut self, data: &[u8]) {
        ProtoLeaf::set_data(self, data.to_vec())
    }
}

impl Data for ProtoData {
    fn new() -> ProtoData {
        ProtoData::new()
    }

    fn get_value(&self) -> &[u8] {
        ProtoData::get_value(&self)
    }

    fn set_value(&mut self, value: &[u8]) {
        ProtoData::set_value(self, value.to_vec())
    }
}

impl Node<ProtoBranch, ProtoLeaf, ProtoData, ProtoAccount> for ProtoMerkleNode {
    fn new() -> ProtoMerkleNode {
        ProtoMerkleNode::new()
    }

    fn get_references(&self) -> u64 {
        ProtoMerkleNode::get_references(&self) as u64
    }

    fn get_variant(&self) -> BinaryMerkleTreeResult<NodeVariant<ProtoBranch, ProtoLeaf, ProtoData>> {
        if let Some(ref n) = self.node {
            match n {
                ProtoVariant::branch(b) => return Ok(NodeVariant::Branch(b.clone())),
                ProtoVariant::leaf(l) => return Ok(NodeVariant::Leaf(l.clone())),
                ProtoVariant::data(d) => return Ok(NodeVariant::Data(d.clone()))
            }
        } else {
            return Err(Box::new(Exception::new("Unable to get node variant")))
        }
    }

    fn set_references(&mut self, references: u64) {
        // Caution, values greater than u32::MAX may have unintended behavior
        ProtoMerkleNode::set_references(self, references as u32);
    }

    fn set_branch(&mut self, branch: ProtoBranch) {
        ProtoMerkleNode::set_branch(self, branch);
    }

    fn set_leaf(&mut self, leaf: ProtoLeaf) {
        ProtoMerkleNode::set_leaf(self, leaf);
    }

    fn set_data(&mut self, data: ProtoData) {
        ProtoMerkleNode::set_data(self, data);
    }
}

impl Encode for ProtoMerkleNode {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        Ok(self.write_to_bytes()?)
    }
}

impl TreeEncode for ProtoMerkleNode {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        Ok(self.write_to_bytes()?)
    }
}

impl Decode for ProtoMerkleNode {
    fn decode(buffer: &[u8]) -> Result<ProtoMerkleNode, Box<Error>> {
        let mut proto_merkle_node = ProtoMerkleNode::new();
        proto_merkle_node.merge_from_bytes(buffer)?;
        Ok(proto_merkle_node)
    }
}

impl TreeDecode for ProtoMerkleNode {
    fn decode(buffer: &[u8]) -> Result<ProtoMerkleNode, Box<Error>> {
        let mut proto_merkle_node = ProtoMerkleNode::new();
        proto_merkle_node.merge_from_bytes(buffer)?;
        Ok(proto_merkle_node)
    }
}

impl Encode for ProtoAccount {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        Ok(self.write_to_bytes()?)
    }
}

impl TreeEncode for ProtoAccount {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        Ok(self.write_to_bytes()?)
    }
}

impl Decode for ProtoAccount {
    fn decode(buffer: &[u8]) -> Result<ProtoAccount, Box<Error>> {
        let mut proto_account = ProtoAccount::new();
        proto_account.merge_from_bytes(buffer)?;
        Ok(proto_account)
    }
}

impl TreeDecode for ProtoAccount {
    fn decode(buffer: &[u8]) -> Result<ProtoAccount, Box<Error>> {
        let mut proto_account = ProtoAccount::new();
        proto_account.merge_from_bytes(buffer)?;
        Ok(proto_account)
    }
}

pub struct Blake2bHasher {
    hasher: Blake2b
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Blake2bHashResult {
    hash: Blake2bResult
}

impl PartialOrd for Blake2bHashResult {
    fn partial_cmp(&self, other: &Blake2bHashResult) -> Option<Ordering> {
        Some(self.as_ref().cmp(other.as_ref()))
    }
}

impl Blake2bHashResult {
    pub fn new(hash: Blake2bResult) -> Blake2bHashResult {
        Blake2bHashResult {
            hash
        }
    }
}

impl AsRef<[u8]> for Blake2bHashResult {
    fn as_ref(&self) -> &[u8]{
        self.hash.as_bytes()
    }
}

impl Blake2bHasher {
    pub fn new() -> Blake2bHasher {
        Blake2bHasher {
            hasher: Blake2b::new(32)
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data)
    }

    pub fn finalize(self) -> Blake2bResult {
        self.hasher.finalize()
    }
}

impl Hasher for Blake2bHasher {
    type HashType = Blake2bHasher;
    type HashResultType = Blake2bHashResult;

    fn new(size: usize) -> Self::HashType {
        Blake2bHasher::new()
    }
    fn update(&mut self, data: &[u8]) {
        Blake2bHasher::update(self, data)
    }
    fn finalize(self) -> Self::HashResultType {
        Blake2bHashResult::new(Blake2bHasher::finalize(self))
    }
}

struct WorldState<'a> {
    tree: MerkleBIT<Database<'a>, ProtoBranch, ProtoLeaf, ProtoData, ProtoMerkleNode, Blake2bHasher, Blake2bHashResult, ProtoAccount>
}