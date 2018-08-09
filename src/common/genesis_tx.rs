use common::Encode;
use common::address::Address;
use common::tx::{Tx, Base, Sendable};
use serialization::tx::GenesisTx as ProtoGenesisTx;

use protobuf::Message;

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

impl Encode for GenesisTx<Tx>
    where Tx: Base + Sendable {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut itx = ProtoGenesisTx::new();
        itx.set_to(self.0.get_to().to_vec());
        itx.set_amount(self.0.get_amount());
        let encoding = itx.write_to_bytes();
        match encoding {
            Ok(data) => return Ok(data),
            Err(e) => return Err(e.to_string())
        }
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
        assert_eq!(genesis_tx.0.to.unwrap(), to);
        assert_eq!(genesis_tx.0.amount, amount);
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
        assert_eq!(genesis_tx.0.to.unwrap(), to);
        assert_eq!(genesis_tx.0.amount, amount);
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
