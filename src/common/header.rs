use common::address::Address;
use common::Encode;
use util::hash::hash;

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

    pub fn prehash<Header: Base + Raw>(header: Header) -> Result<Vec<u8>, String> {
        let mut proto_header = BlockHeader::new();
        proto_header.set_merkleRoot(header.get_merkle_root());
        proto_header.set_timeStamp(header.get_time_stamp());
        proto_header.set_difficulty(header.get_difficulty());
        proto_header.set_stateRoot(header.get_state_root());
        proto_header.set_previousHash(RepeatedField::from(header.get_previous_hash()));
        proto_header.set_miner(header.get_miner().to_vec());
        let encoding: Vec<u8>;
        match proto_header.write_to_bytes() {
            Ok(data) => encoding = data,
            Err(e) => return Err(e.to_string())
        }
        Ok(hash(&encoding, 64))
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

#[cfg(test)]
mod tests {
    use super::*;
    use common::address::ValidAddress;
    use rust_base58::{FromBase58, ToBase58};

    #[test]
    fn it_makes_a_raw_header() {
        let merkle_root = vec![218,175,98,56,136,59,157,43,178,250,66,194,50,129,87,37,147,54,157,79,238,83,118,209,92,202,25,32,246,230,153,39];
        let state_root = vec![121,132,139,154,165,229,182,152,126,204,58,142,150,220,236,119,144,1,181,107,19,130,67,220,241,192,46,94,69,215,134,11];
        let time_stamp = 1515003305000;
        let difficulty = 0 as f64;
        let miner = Address::from_string(&"H3yGUaF38TxQxoFrqCqPdB2pN9jyBHnaj".to_string());
    }

}