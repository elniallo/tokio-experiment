use common::header::{Base, Header};
use common::Encode;
use serialization::blockHeader::BlockHeader;
use protobuf::Message;

pub struct GenesisHeader<T>(T);

impl Encode for GenesisHeader<Header> 
    where Header: Base {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut proto_genesis_block_header = BlockHeader::new();
        proto_genesis_block_header.set_merkleRoot(self.0.get_merkle_root());
        proto_genesis_block_header.set_stateRoot(self.0.get_state_root());
        proto_genesis_block_header.set_timeStamp(self.0.get_time_stamp());
        proto_genesis_block_header.set_difficulty(self.0.get_difficulty());
        match proto_genesis_block_header.write_to_bytes() {
            Ok(data) => {
                // The typescript protobufs for some reason elides the nonce on the encoding of the genesis block header
                // The following deletes the nonce after it has been written to maintain compatibility with typescript
                let mut elided_nonce = vec![0; data.len() - 2];
                elided_nonce.clone_from_slice(&data[0..data.len() - 2]);
                return Ok(elided_nonce);
            },
            Err(e) => return Err(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_base58::ToBase58;
    use util::hash::hash;

    #[test]
    fn it_makes_the_genesis_header() {
        let merkle_root = vec![218,175,98,56,136,59,157,43,178,250,66,
            194,50,129,87,37,147,54,157,79,238,83,118,209,92,202,25,32,246,230,153,39];
        let state_root = vec![121,132,139,154,165,229,182,152,126,204,
            58,142,150,220,236,119,144,1,181,107,19,130,67,220,241,192,46,94,69,215,134,11];
        let time_stamp = 1515003305000;
        let difficulty: f64 = 0 as f64;

        let header = Header::new(merkle_root.clone(), time_stamp, difficulty, state_root.clone(), None, None, None);
        let genesis_header = GenesisHeader(header);
        let encoding = genesis_header.encode().unwrap();
        let expected_encoding = vec![18,32,218,175,98,56,136,59,157,
            43,178,250,66,194,50,129,87,37,147,54,157,79,238,83,118,
            209,92,202,25,32,246,230,153,39,26,32,121,132,139,154,165,
            229,182,152,126,204,58,142,150,220,236,119,144,1,181,107,19,
            130,67,220,241,192,46,94,69,215,134,11,33,0,0,0,0,0,0,0,0,40,168,184,239,233,139,44];
        let genesis_header_hash = hash(&encoding, 32).to_base58();
        assert_eq!(genesis_header.0.get_merkle_root(), merkle_root);
        assert_eq!(genesis_header.0.get_state_root(), state_root);
        assert_eq!(genesis_header.0.get_time_stamp(), time_stamp);
        assert_eq!(genesis_header.0.get_difficulty(), difficulty);
        assert_eq!(encoding, expected_encoding);
        assert_eq!(genesis_header_hash, "G4qXusbRyXmf62c8Tsha7iZoyLsVGfka7ynkvb3Esd1d".to_string())
    }
}
