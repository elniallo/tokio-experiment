use common::address::Address;
use common::Encode;

use serialization::blockHeader::BlockHeader;

use protobuf::{Message, RepeatedField};

pub struct Header {
    pub merkle_root: Vec<u8>,
    pub time_stamp: u64,
    pub difficulty: f64,
    pub state_root: Vec<u8>,
    pub previous_hash: Option<Vec<Vec<u8>>>,
    pub nonce: Option<u64>,
    pub miner: Option<Address>,
}

pub trait Base {
    fn get_merkle_root(&self) -> Vec<u8>;
    fn get_time_stamp(&self) -> u64;
    fn get_difficulty(&self) -> f64;
    fn get_state_root(&self) -> Vec<u8>;
}

pub trait Raw {
    fn get_previous_hash(&self) -> Vec<Vec<u8>>;
    fn get_miner(&self) -> Address;
}

pub trait Mined {
    fn get_nonce(&self) -> u64;
}

impl Header {
    pub fn new(merkle_root: Vec<u8>, 
               time_stamp: u64, 
               difficulty: f64, 
               state_root: Vec<u8>, 
               previous_hash: Option<Vec<Vec<u8>>>, 
               nonce: Option<u64>, 
               miner: Option<Address>) -> Header {
                   Header {
                       merkle_root,
                       time_stamp,
                       difficulty,
                       state_root,
                       previous_hash,
                       nonce,
                       miner
                   }
    }
}

impl Encode for Header 
    where Header: Base + Raw + Mined {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut proto_block_header = BlockHeader::new();
        let merkle_root = self.merkle_root.clone();
        proto_block_header.set_merkleRoot(merkle_root);
        proto_block_header.set_timeStamp(self.time_stamp);
        proto_block_header.set_difficulty(self.difficulty);
        let state_root = self.state_root.clone();
        proto_block_header.set_stateRoot(state_root);

        let previous_hash_option = Option::as_ref(&self.previous_hash);
        let previous_hash_ref = previous_hash_option.unwrap();
        let previous_hash = previous_hash_ref.clone();
        proto_block_header.set_previousHash(RepeatedField::from(previous_hash));
        proto_block_header.set_nonce(self.nonce.unwrap());
        proto_block_header.set_miner(self.miner.unwrap().to_vec());
        match proto_block_header.write_to_bytes() {
            Ok(data) => return Ok(data),
            Err(e) => return Err(e.to_string())
        }
    }
}

impl Base for Header {
    fn get_merkle_root(&self) -> Vec<u8> {
        self.merkle_root.clone()
    }
    fn get_time_stamp(&self) -> u64 {
        self.time_stamp
    }
    fn get_difficulty(&self) -> f64 {
        self.difficulty
    }
    fn get_state_root(&self) -> Vec<u8> {
        self.state_root.clone()
    }
}

impl Raw for Header {
    fn get_previous_hash(&self) -> Vec<Vec<u8>> {
        let previous_hash_option = Option::as_ref(&self.previous_hash);
        let previous_hash_ref = previous_hash_option.unwrap();
        previous_hash_ref.clone()
    }
    fn get_miner(&self) -> Address {
        self.miner.unwrap()
    }
}

impl Mined for Header {
    fn get_nonce(&self) -> u64 {
        self.nonce.unwrap()
    }
}

