use account::Account;
use common::address::Address;
use common::{Decode, DecodingError, Encode, EncodingError, Proto};
use protobuf::{Message as ProtoMessage, RepeatedField};
use serialization::state::DBState as ProtoDBState;
use util::hash::hash;

pub struct DBState {
    pub account: Option<Account>,
    pub node: Option<String>,
    pub ref_count: u32,
}

impl DBState {
    pub fn new() -> DBState {
        return DBState {
            account: None,
            node: None,
            ref_count: 0,
        };
    }

    pub fn set_account(&mut self, account: Account) {
        self.account = Some(account);
    }
    pub fn set_node(&mut self, node: String) {
        self.node = Some(node);
    }
}

impl Encode<EncodingError> for DBState {
    fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        let mut data = ProtoDBState::new();

        match data.write_to_bytes() {
            Ok(data) => return Ok(data),
            Err(e) => return Err(EncodingError::Proto(e)),
        }
    }
}

impl Decode<DBState, DecodingError> for DBState {
    type ProtoType = DBState;
    fn decode(&self, buffer: &Vec<u8>) -> Result<Self::ProtoType, DecodingError> {
        let mut data = ProtoDBState::new();
        data.merge_from_bytes(buffer);
        let ret = DBState {
            account: None,
            node: None,
            ref_count: data.refCount,
        };
        return Ok(ret);
    }
}
