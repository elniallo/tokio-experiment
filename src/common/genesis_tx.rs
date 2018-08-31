use std::ops::Deref;
use std::error::Error;
use common::{Encode, Exception, Proto};
use common::address::Address;
use common::transaction::Transaction;
use serialization::tx::GenesisTx as ProtoGenesisTx;

use secp256k1::{RecoverableSignature, RecoveryId};
use protobuf::Message as ProtoMessage;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisTx {
    pub to: Address,
    pub amount: u64,
}

impl Transaction for GenesisTx {
    fn get_from(&self) -> Option<Address> {None}
    fn get_to(&self) -> Option<Address> {Some(self.to)}
    fn get_amount(&self) -> u64 {self.amount}
    fn get_fee(&self) -> Option<u64> {None}
    fn get_nonce(&self) -> Option<u32> {None}
    fn get_signature(&self) -> Option<RecoverableSignature> {None}
    fn get_recovery(&self) -> Option<RecoveryId> {None}
}

impl GenesisTx {
    pub fn new(to: Address, amount: u64) -> GenesisTx {
        GenesisTx {
            to,
            amount
        }
    }

    pub fn decode(itx: ProtoGenesisTx) -> GenesisTx {
        let mut to: Address = [0; 20];
        to.clone_from_slice(&itx.to);
        let amount = itx.amount;
        GenesisTx::new(to, amount)
    }
}

impl Proto for GenesisTx {
    type ProtoType = ProtoGenesisTx;
    fn to_proto(&self) -> Result<Self::ProtoType, Box<Error>> {
        let mut proto_genesis_tx = Self::ProtoType::new();
        proto_genesis_tx.set_to(self.to.to_vec());
        proto_genesis_tx.set_amount(self.amount);
        Ok(proto_genesis_tx)
    }
}

impl Encode for GenesisTx {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        let proto_tx = self.to_proto()?;
        Ok(proto_tx.write_to_bytes()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_makes_a_genesis_transaction() {
        let to = [
            87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149, 135, 84, 9, 224, 232,
            102,
        ];
        let amount = 123456789;
        let genesis_tx = GenesisTx::new(to, amount);
        assert_eq!(genesis_tx.to, to);
        assert_eq!(genesis_tx.amount, amount);
    }

    #[test]
    fn it_makes_a_genesis_transaction_from_itx() {
        let to = [
            87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149, 135, 84, 9, 224, 232,
            102,
        ];
        let amount = 123456789;
        let mut itx = ProtoGenesisTx::new();
        itx.set_to(to.to_vec());
        itx.set_amount(amount);

        let genesis_tx = GenesisTx::decode(itx);
        assert_eq!(genesis_tx.to, to);
        assert_eq!(genesis_tx.amount, amount);
    }

    #[test]
    fn it_encodes_like_javascript_for_non_zero() {
        let to = [
            87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149, 135, 84, 9, 224, 232,
            102,
        ];
        let amount = 123456789;
        let genesis_tx = GenesisTx::new(to, amount);
        let encoding = genesis_tx.encode().unwrap();
        let expected_encoding = vec![
            18, 20, 87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149, 135, 84, 9,
            224, 232, 102, 24, 149, 154, 239, 58,
        ];
        assert_eq!(encoding, expected_encoding);
    }

    #[test]
    fn it_encodes_like_javascript_for_zero() {
        let to = [
            87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149, 135, 84, 9, 224, 232,
            102,
        ];
        let amount = 0;
        let genesis_tx = GenesisTx::new(to, amount);
        let encoding = genesis_tx.encode().unwrap();
        let expected_encoding = vec![
            18, 20, 87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149, 135, 84, 9,
            224, 232, 102, 24, 0,
        ];
        assert_eq!(encoding, expected_encoding);
    }
}
