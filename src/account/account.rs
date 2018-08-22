use std::error::Error;

use common::{Decode, Encode, Proto};
use protobuf::Message as ProtoMessage;
use serialization::state::Account as ProtoAccount;

#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub balance: u64,
    pub nonce: u32,
}

impl Account {
    pub fn new(balance: u64, nonce: u32) -> Account {
        Account { balance, nonce }
    }
}

impl Decode for Account {
    type ProtoType = ProtoAccount;
    fn decode(buffer: &Vec<u8>) -> Result<Account, Box<Error>> {
        let mut proto_account = Self::ProtoType::new();
        proto_account.merge_from_bytes(buffer)?;

        Ok(Account::new(proto_account.balance, proto_account.nonce))
    }
}

impl Proto for Account {
    type ProtoType = ProtoAccount;
    fn to_proto(&self) -> Result<Self::ProtoType, Box<Error>> {
        let mut proto_account = Self::ProtoType::new();
        proto_account.balance = self.balance;
        proto_account.nonce = self.nonce;

        Ok(proto_account)
    }
}

impl Encode for Account {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        let proto_account = self.to_proto()?;

        Ok(proto_account.write_to_bytes()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_makes_a_account() {
        let balance: u64 = 1000;
        let nonce: u32 = 20;
        let account = Account::new(balance, nonce);
        assert_eq!(account.balance, balance);
        assert_eq!(account.nonce, nonce);
    }

    #[test]
    fn it_encodes_like_javascript_for_non_zero() {
        let balance: u64 = 1000;
        let nonce: u32 = 20;
        let account = Account::new(balance, nonce);
        let encoded = account.encode().unwrap();
        let javascript_encoded = vec![8, 232, 7, 16, 20];
        let decoded = Account::decode(&encoded).unwrap();
        assert_eq!(encoded, javascript_encoded);
        assert_eq!(decoded.balance, account.balance);
        assert_eq!(decoded.nonce, account.nonce);
    }

    #[test]
    fn it_encodes_like_javascript_for_zero() {
        let balance: u64 = 1000;
        let nonce: u32 = 0;
        let account = Account::new(balance, nonce);
        let encoded = account.encode().unwrap();
        let javascript_encoded = vec![8, 232, 7, 16, 0];
        let decoded = Account::decode(&encoded).unwrap();
        assert_eq!(encoded, javascript_encoded);
        assert_eq!(decoded.balance, account.balance);
        assert_eq!(decoded.nonce, account.nonce);
    }
}
