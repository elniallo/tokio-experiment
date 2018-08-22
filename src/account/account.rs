use common::address::Address;
use common::{Decode, DecodingError, Encode, EncodingError, Proto};
use protobuf::{Message as ProtoMessage, RepeatedField};
use serialization::state::Account as ProtoAccount;
use util::hash::hash;
pub struct Account {
    pub balance: u64,
    pub nonce: u32,
}

impl Account {
    pub fn new(balance: u64, nonce: u32) -> Account {
        return Account { balance, nonce };
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use common::address::ValidAddress;
    use rust_base58::FromBase58;
    #[test]
    fn it_makes_a_account() {
        let balance: u64 = 1000;
        let nonce: u32 = 20;
        let account = Account::new(balance, nonce);
        assert_eq!(account.balance, balance);
        assert_eq!(account.nonce, nonce);
    }

    #[test]
    fn it_makes_a_rew_account() {
        let balance: u64 = 1000;
        let nonce: u32 = 20;
        let account = Account::new(balance, nonce);
        let encoded = account.encode().unwrap();
        let javascriptEncoded = vec![8, 232, 7, 16, 20];
        let decoded = account.decode(&encoded).unwrap();
        assert_eq!(encoded, javascriptEncoded);
        assert_eq!(decoded.balance, account.balance);
        assert_eq!(decoded.nonce, account.nonce);
    }
}
