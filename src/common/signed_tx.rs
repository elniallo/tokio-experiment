use common::address::Address;
use common::tx::{Tx, Quantifiable, Sendable, Countable, Signed, Valid};
use common::Encode;

use serialization::tx::SignedTx as ProtoTx;

use protobuf::Message as ProtoMessage;
use secp256k1::{Error, RecoverableSignature, RecoveryId, Secp256k1};

#[derive(Clone, Debug, PartialEq)]
pub struct SignedTx<T>(T);

impl SignedTx<Tx> 
    where Tx: Quantifiable + Sendable + Countable + Signed + Valid {
    pub fn decode(proto_tx: ProtoTx) -> Result<SignedTx<Tx>, Error> {
        let mut from: Address = [0; 20];
        from.clone_from_slice(&proto_tx.from[..]);
        let mut to: Address = [0; 20];
        to.clone_from_slice(&proto_tx.to[..]);
        let amount = proto_tx.amount;
        let fee = proto_tx.fee;
        let nonce = proto_tx.nonce;

        let secp = Secp256k1::without_caps();
        let recovery = RecoveryId::from_i32(proto_tx.recovery as i32)?;
        let signature = RecoverableSignature::from_compact(&secp, &proto_tx.signature[..], recovery)?;
        let tx = Tx::new(Some(from), Some(to), amount, Some(fee), Some(nonce), Some(signature), Some(recovery));
        Ok(SignedTx(tx))
    }

    pub fn verify(&self) -> Result<bool, Error> {
        let encoding = self.0.encode().unwrap();
        let sender = self.0.get_from();
        let signature = self.0.get_signature();
        Tx::verify(encoding, sender, signature)
    }

    pub fn to_proto_signed_tx(&self) -> ProtoTx {
        let mut proto_tx = ProtoTx::new();
        let secp = Secp256k1::without_caps();
        proto_tx.set_from(self.0.get_from().to_vec());
        proto_tx.set_to(self.0.get_to().to_vec());
        proto_tx.set_amount(self.0.get_amount());
        proto_tx.set_fee(self.0.get_fee());
        proto_tx.set_nonce(self.0.get_nonce());
        proto_tx.set_signature(self.0.get_signature().serialize_compact(&secp).1.to_vec());
        proto_tx.set_recovery(self.0.get_recovery().to_i32() as u32);
        proto_tx
    }
}

impl Encode for SignedTx<Tx>
    where Tx: Quantifiable + Sendable + Countable + Signed {
        fn encode(&self) -> Result<Vec<u8>, String> {
            let proto_tx = self.to_proto_signed_tx();
            let encoding = proto_tx.write_to_bytes();
            match encoding {
                Ok(data) => return Ok(data),
                Err(e) => return Err(e.to_string())
            }
        }
    }

impl Quantifiable for SignedTx<Tx>
    where Tx: Quantifiable {
    fn get_amount(&self) -> u64 {
        self.0.get_amount()
    }
}

impl Sendable for SignedTx<Tx>
    where Tx: Sendable {
        fn get_to(&self) -> Address {
            self.0.get_to()
        }
    }

impl Countable for SignedTx<Tx>
    where Tx: Countable {
        fn get_from(&self) -> Address {
            self.0.get_from()
        }
        fn get_fee(&self) -> u64 {
            self.0.get_fee()
        }
        fn get_nonce(&self) -> u32 {
            self.0.get_nonce()
        }
    }

impl Signed for SignedTx<Tx>
    where Tx: Signed {
        fn get_signature(&self) -> RecoverableSignature {
            self.0.get_signature()
        }
        fn get_recovery(&self) -> RecoveryId {
            self.0.get_recovery()
        }
    }

#[cfg(test)]
mod tests {
    use super::*;
    use common::address::ValidAddress;

    #[test]
    fn it_verifies_a_signed_tx() {
        let from_addr_string = "H27McLosW8psFMbQ8VPQwXxnUY8QAHBHr".to_string();
        let from_addr = Address::from_string(&from_addr_string).unwrap();
        let to_addr_str = "H4JSXdLtkXVs6G7fk2xea1dB4hTgQ3ps6".to_string();
        let to_addr = Address::from_string(&to_addr_str).unwrap();
        let amount = 100;
        let fee = 1;
        let nonce = 1;
        let recovery = RecoveryId::from_i32(0).unwrap();

        let signature_bytes = [
            208, 50, 197, 4, 84, 254, 196, 173, 123, 37, 234, 93, 48, 249, 247, 56, 156, 54, 7,
            211, 17, 121, 174, 74, 111, 1, 7, 184, 82, 196, 94, 176, 73, 221, 78, 105, 137, 12,
            165, 212, 15, 47, 134, 101, 221, 69, 158, 19, 237, 120, 63, 173, 92, 215, 144, 224,
            100, 78, 84, 128, 237, 25, 234, 206,
        ];
        let secp = Secp256k1::without_caps();
        let signature =
            RecoverableSignature::from_compact(&secp, &signature_bytes, recovery).unwrap();

        let tx = Tx::new(Some(from_addr), Some(to_addr), amount, Some(fee), Some(nonce), Some(signature), Some(recovery));
        let signed_tx = SignedTx(tx);
        assert_eq!(true, signed_tx.verify().unwrap());
    }

    #[test]
    fn it_rejects_a_forged_tx() {
        let from_addr_string = "H27McLosW8psFMbQ8VPQwXxnUY8QAHBHr".to_string();
        let from_addr = Address::from_string(&from_addr_string).unwrap();
        let to_addr_str = "H4JSXdLtkXVs6G7fk2xea1dB4hTgQ3ps6".to_string();
        let to_addr = Address::from_string(&to_addr_str).unwrap();
        let amount = 200;
        let fee = 1;
        let nonce = 1;
        let recovery = RecoveryId::from_i32(0).unwrap();

        let signature_bytes = [
            208, 50, 197, 4, 84, 254, 196, 173, 123, 37, 234, 93, 48, 249, 247, 56, 156, 54, 7,
            211, 17, 121, 174, 74, 111, 1, 7, 184, 82, 196, 94, 176, 73, 221, 78, 105, 137, 12,
            165, 212, 15, 47, 134, 101, 221, 69, 158, 19, 237, 120, 63, 173, 92, 215, 144, 224,
            100, 78, 84, 128, 237, 25, 234, 206,
        ];
        let secp = Secp256k1::without_caps();
        let signature =
            RecoverableSignature::from_compact(&secp, &signature_bytes, recovery).unwrap();

        let tx = Tx::new(Some(from_addr), Some(to_addr), amount, Some(fee), Some(nonce), Some(signature), Some(recovery));
        let signed_tx = SignedTx(tx);

        match signed_tx.verify() {
            Ok(_) => panic!("Invalid signature was reported as verified"),
            Err(_) => {}
        }
    }
}