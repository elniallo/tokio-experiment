use common::header::{Base, Header};
use common::Encode;
use serialization::blockHeader::GenesisBlockHeader;
use protobuf::Message;

pub struct GenesisHeader<T>(T);

impl Encode for GenesisHeader<Header> 
    where Header: Base {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut proto_genesis_block_header = GenesisBlockHeader::new();
        proto_genesis_block_header.set_merkleRoot(self.0.get_merkle_root());
        proto_genesis_block_header.set_timeStamp(self.0.get_time_stamp());
        proto_genesis_block_header.set_difficulty(self.0.get_difficulty() as u32);
        proto_genesis_block_header.set_stateRoot(self.0.get_state_root());
        match proto_genesis_block_header.write_to_bytes() {
            Ok(data) => return Ok(data),
            Err(e) => return Err(e.to_string())
        }
    }
}
