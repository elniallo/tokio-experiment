use common::address::Address;
use common::{Encode, EncodingError, Proto};
use util::hash::hash;

use serialization::blockHeader::{HeaderPrehash, BlockHeader};

use protobuf::{Message as ProtoMessage, RepeatedField};

#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    merkle_root: Vec<u8>,
    time_stamp: u64,
    difficulty: f64,
    state_root: Vec<u8>,
    previous_hash: Option<Vec<Vec<u8>>>,
    nonce: Option<u64>,
    miner: Option<Address>,
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

    pub fn get_merkle_root(&self) -> Vec<u8> {
        self.merkle_root.clone()
    }
    pub fn get_time_stamp(&self) -> u64 {
        self.time_stamp
    }
    pub fn get_difficulty(&self) -> f64 {
        self.difficulty
    }
    pub fn get_state_root(&self) -> Vec<u8> {
        self.state_root.clone()
    }
    pub fn get_previous_hash(&self) -> Option<Vec<Vec<u8>>> {
        self.previous_hash.clone()
    }
    pub fn get_nonce(&self) -> Option<u64> {
        self.nonce
    }
    pub fn get_miner(&self) -> Option<Address> {
        self.miner
    }

    pub fn prehash(&self) -> Result<Vec<u8>, EncodingError> {
        let mut proto_header = HeaderPrehash::new();
        proto_header.set_merkleRoot(self.get_merkle_root());
        proto_header.set_timeStamp(self.get_time_stamp());
        proto_header.set_difficulty(self.get_difficulty());
        proto_header.set_stateRoot(self.get_state_root());
        match self.get_previous_hash() {
            Some(previous_hash) => proto_header.set_previousHash(RepeatedField::from(previous_hash)),
            None => return Err(EncodingError::Integrity("Header is missing a previous hash".to_string()))
        }
        match self.get_miner() {
            Some(miner) => proto_header.set_miner(miner.to_vec()),
            None => return Err(EncodingError::Integrity("Header is missing a miner".to_string()))
        }
        let encoding: Vec<u8>;
        match proto_header.write_to_bytes() {
            Ok(data) => encoding = data,
            Err(e) => return Err(EncodingError::Proto(e))
        }
        Ok(hash(&encoding, 64))
    }
}

impl Encode<EncodingError> for Header {
    fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        let proto_block_header = self.to_proto()?;
        match proto_block_header.write_to_bytes() {
            Ok(data) => return Ok(data),
            Err(e) => return Err(EncodingError::Proto(e))
        }
    }
}

impl Proto<EncodingError> for Header {
    type ProtoType = BlockHeader;
    fn to_proto(&self) -> Result<Self::ProtoType, EncodingError> {
        let mut proto_header = Self::ProtoType::new();
        proto_header.set_merkleRoot(self.get_merkle_root());
        proto_header.set_timeStamp(self.get_time_stamp());
        proto_header.set_difficulty(self.difficulty);
        proto_header.set_stateRoot(self.get_state_root());
        match self.get_previous_hash() {
            Some(previous_hash) => proto_header.set_previousHash(RepeatedField::from(previous_hash)),
            None => {}
        }
        match self.get_nonce() {
            Some(nonce) => proto_header.set_nonce(nonce),
            None => {}
        }
        match self.get_miner() {
            Some(miner) => proto_header.set_miner(miner.to_vec()),
            None => {}
        }        
        Ok(proto_header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::address::ValidAddress;
    use rust_base58::FromBase58;

    #[test]
    fn it_makes_a_header() {
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
        assert_eq!(header.get_merkle_root(), merkle_root);
        assert_eq!(header.get_state_root(), state_root);
        assert_eq!(header.get_time_stamp(), time_stamp);
        assert_eq!(header.get_difficulty(), difficulty);
        assert_eq!(header.get_nonce().unwrap(), nonce);
        assert_eq!(header.get_miner().unwrap(), miner);
        assert_eq!(header.get_previous_hash().unwrap(), previous_hash);
    }

    #[test]
    fn it_makes_a_raw_header() {
        let merkle_root = vec![218,175,98,56,136,59,157,43,178,250,66,194,50,129,
            87,37,147,54,157,79,238,83,118,209,92,202,25,32,246,230,153,39];
        let state_root = vec![121,132,139,154,165,229,182,152,126,204,58,142,150,
            220,236,119,144,1,181,107,19,130,67,220,241,192,46,94,69,215,134,11];
        let time_stamp = 1515003305000;
        let difficulty = 0 as f64;
        let miner = Address::from_string(&"H3yGUaF38TxQxoFrqCqPdB2pN9jyBHnaj".to_string()).unwrap();
        let previous_hash = vec!["G4qXusbRyXmf62c8Tsha7iZoyLsVGfka7ynkvb3Esd1d".from_base58().unwrap()];
        let nonce = 0;
        let header = Header::new(merkle_root.clone(), time_stamp, difficulty, state_root.clone(), Some(previous_hash.clone()), Some(nonce), Some(miner));
        let encoding = header.encode().unwrap();
        let expected_encoding = vec![10,32,223,218,236,54,245,118,35,75,80,237,
            79,63,61,46,46,228,77,128,114,163,92,252,73,201,159,108,48,48,86,
            233,136,20,18,32,218,175,98,56,136,59,157,43,178,250,66,194,50,129,
            87,37,147,54,157,79,238,83,118,209,92,202,25,32,246,230,153,39,26,
            32,121,132,139,154,165,229,182,152,126,204,58,142,150,220,236,119,
            144,1,181,107,19,130,67,220,241,192,46,94,69,215,134,11,33,
            0,0,0,0,0,0,0,0,40,168,184,239,233,139,44,48,0,58,20,213,49,13,190,
            194,137,35,119,16,249,57,125,207,78,117,246,36,136,151,210];
        let prehash = header.prehash().unwrap();
        let expected_prehash = vec![213,155,184,6,160,192,238,37,190,172,89,224,
            41,36,132,38,46,5,70,193,159,49,130,25,220,56,238,148,167,135,240,
            158,162,189,223,13,85,156,251,105,34,21,90,14,21,248,16,183,136,77,
            231,102,80,183,192,177,184,19,75,226,188,134,38,218];

        assert_eq!(encoding, expected_encoding);
        assert_eq!(prehash, expected_prehash);
    }
}