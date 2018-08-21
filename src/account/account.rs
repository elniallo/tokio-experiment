use common::address::Address;
use common::{Decode, DecodingError, Encode, EncodingError, Proto};
use protobuf::{Message as ProtoMessage, RepeatedField};
use serialization::state::Account as ProtoAccount;
use util::hash::hash;
pub struct Account {
    pub balance: u64,
    pub nonce: u32,
}

impl Encode<EncodingError> for Account {
    fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        let serialized = self.to_proto()?;
        match serialized.write_to_bytes() {
            Ok(data) => return Ok(data),
            Err(e) => return Err(EncodingError::Proto(e)),
        }
    }
}
impl Decode<Account, DecodingError> for Account {
    type ProtoType = ProtoAccount;
    fn decode(&self, buffer: &Vec<u8>) -> Result<Account, DecodingError> {
        let mut data = Self::ProtoType::new();
        data.merge_from_bytes(buffer);
        let ret = Account {
            balance: data.balance,
            nonce: data.nonce,
        };
        return Ok(ret);
    }
}
impl Proto<EncodingError> for Account {
    type ProtoType = ProtoAccount;
    fn to_proto(&self) -> Result<Self::ProtoType, EncodingError> {
        let mut data = Self::ProtoType::new();
        data.balance = self.balance;
        data.nonce = self.nonce;
        return Ok(data);
    }
}
