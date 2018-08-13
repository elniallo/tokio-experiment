use secp256k1::{RecoverableSignature, RecoveryId};
use common::{Encode, Proto};
use common::address::Address;
use common::tx::{Tx, ITx};
use serialization::tx::GenesisTx as ProtoGenesisTx;

use protobuf::{Message, ProtobufError};

pub struct GenesisTx<T>(pub T);

impl GenesisTx<Tx> {
    pub fn decode(itx: ProtoGenesisTx) -> GenesisTx<Tx> {
        let mut to: Address = [0; 20];
        to.clone_from_slice(&itx.to[..]);
        let amount = itx.amount;
        let tx = Tx::new(None, Some(to), amount, None, None, None, None);
        GenesisTx(tx)
    }
}

impl Proto<ProtoGenesisTx, ProtobufError> for GenesisTx<Tx> {
    fn to_proto(&self) -> Result<ProtoGenesisTx, ProtobufError> {
        let mut proto_genesis_tx = ProtoGenesisTx::new();
        proto_genesis_tx.set_amount(self.get_amount());
        match self.get_to() {
            Some(addr) => proto_genesis_tx.set_to(addr.to_vec()),
            None => {}
        }
        Ok(proto_genesis_tx)
    }
}

impl ITx for GenesisTx<Tx> {
    fn get_amount(&self) -> u64 {
        self.0.get_amount()
    }
    fn get_from(&self) -> Option<Address> {
        self.0.get_from()
    }
    fn get_to(&self) -> Option<Address> {
        self.0.get_to()
    }
    fn get_fee(&self) -> Option<u64> {
        self.0.get_fee()
    }
    fn get_nonce(&self) -> Option<u32> {
        self.0.get_nonce()
    }
    fn get_signature(&self) -> Option<RecoverableSignature> {
        self.0.get_signature()
    }
    fn get_recovery(&self) -> Option<RecoveryId> {
        self.0.get_recovery()
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
        let tx = Tx::new(None, Some(to), amount, None, None, None, None);
        let genesis_tx = GenesisTx(tx);
        assert_eq!(genesis_tx.get_to().unwrap(), to);
        assert_eq!(genesis_tx.get_amount(), amount);
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
        assert_eq!(genesis_tx.get_to().unwrap(), to);
        assert_eq!(genesis_tx.get_amount(), amount);
    }

    #[test]
    fn it_encodes_like_javascript_for_non_zero() {
        let to = [
            87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149, 135, 84, 9, 224, 232,
            102,
        ];
        let amount = 123456789;
        let genesis_tx = GenesisTx(Tx::new(None, Some(to), amount, None, None, None, None));
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
        let genesis_tx = GenesisTx(Tx::new(None, Some(to), amount, None, None, None, None));
        let encoding = genesis_tx.encode().unwrap();
        let expected_encoding = vec![
            18, 20, 87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149, 135, 84, 9,
            224, 232, 102, 24, 0,
        ];
        assert_eq!(encoding, expected_encoding);
    }
}
