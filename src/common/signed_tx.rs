use common::address::Address;
use common::tx::{ITx, Tx, Valid};
use common::{Encode, Proto};

use serialization::tx::{SignedTx as ProtoSignedTx, Tx as ProtoTx};

use protobuf::{Message as ProtoMessage, ProtobufError};
use secp256k1::{Error as SecpError, RecoverableSignature, RecoveryId, Secp256k1};

#[derive(Debug)]
pub enum VerifyError {
    Proto(ProtobufError),
    Secp(SecpError),
    Integrity(String)
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignedTx<T>(pub T);

impl SignedTx<Tx> {
    pub fn decode(proto_tx: ProtoSignedTx) -> Result<SignedTx<Tx>, SecpError> {
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
}

impl Proto<ProtoSignedTx, ProtobufError> for SignedTx<Tx> 
    where Tx: Proto<ProtoTx, ProtobufError> {
    fn to_proto(&self) -> Result<ProtoSignedTx, ProtobufError> {
        let proto_tx: ProtoTx = self.0.to_proto()?;
        let mut proto_signed_tx = ProtoSignedTx::new();
        let encoding = proto_tx.write_to_bytes()?;
        proto_signed_tx.merge_from_bytes(&encoding[..])?;
        let secp = Secp256k1::without_caps();
        match self.get_signature() {
            Some(sig) => proto_signed_tx.set_signature(sig.serialize_compact(&secp).1.to_vec()),
            None => {}
        }
        match self.get_recovery() {
            Some(recovery) => proto_signed_tx.set_recovery(recovery.to_i32() as u32),
            None => {}
        }
        Ok(proto_signed_tx)
    }
}

impl ITx for SignedTx<Tx> {
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

impl Valid<VerifyError> for SignedTx<Tx> {
    fn verify(&self) -> Result<bool, VerifyError> {
        let encoding: Vec<u8>;
        match self.encode() {
            Ok(data) => encoding = data,
            Err(e) => return Err(VerifyError::Proto(e))
        }
        let sender: Address;
        match self.get_from() {
            Some(addr) => sender = addr,
            None => return Err(VerifyError::Integrity("Tx has no sender".to_string()))
        }
        let signature: RecoverableSignature;
        match self.get_signature() {
            Some(sig) => signature = sig,
            None => return Err(VerifyError::Integrity("Tx has no signature".to_string()))
        }
        match Tx::verify(encoding, sender, signature) {
            Ok(result) => return Ok(result),
            Err(e) => return Err(VerifyError::Secp(e))
        }
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