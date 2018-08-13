use common::signed_tx::VerifyError;
use common::address::Address;
use common::tx::{Tx, ITx, Valid};
use common::genesis_tx;
use common::{Encode, Proto};
use serialization::tx::GenesisSignedTx as ProtoGenesisSignedTx;


use protobuf::{Message as ProtoMessage, ProtobufError};
use secp256k1::{Error, RecoverableSignature, RecoveryId, Secp256k1};

#[derive(Clone, Debug, PartialEq)]
pub struct GenesisSignedTx<T>(pub T);

impl GenesisSignedTx<Tx> {
    pub fn decode(proto_tx: ProtoGenesisSignedTx) -> Result<GenesisSignedTx<Tx>, Error> {
        let mut to: Address = [0; 20];
        to.clone_from_slice(&proto_tx.to[..]);
        let amount = proto_tx.amount;

        let secp = Secp256k1::without_caps();
        let recovery = RecoveryId::from_i32(proto_tx.recovery as i32)?;
        let signature = RecoverableSignature::from_compact(&secp, &proto_tx.signature[..], recovery)?;
        let tx = Tx::new(None, Some(to), amount, None, None, Some(signature), Some(recovery));
        Ok(GenesisSignedTx(tx))
    }
}

impl Proto<ProtoGenesisSignedTx, VerifyError> for GenesisSignedTx<Tx> {
    fn to_proto(&self) -> Result<ProtoGenesisSignedTx, VerifyError> {
        let mut proto_genesis_signed_tx = ProtoGenesisSignedTx::new();
        let secp = Secp256k1::without_caps();
        match self.get_to() {
            Some(addr) => proto_genesis_signed_tx.set_to(addr.to_vec()),
            None => {}
        }
        proto_genesis_signed_tx.set_amount(self.get_amount());
        match self.get_signature() {
            Some(sig) => proto_genesis_signed_tx.set_signature(sig.serialize_compact(&secp).1.to_vec()),
            None => {}
        }
        match self.get_recovery() {
            Some(recovery) => proto_genesis_signed_tx.set_recovery(recovery.to_i32() as u32),
            None => {}
        }
        Ok(proto_genesis_signed_tx)
    }
}

impl Valid<VerifyError> for GenesisSignedTx<Tx> {
    fn verify(&self) -> Result<bool, VerifyError> {
        let to: Address;
        match self.get_to() {
            Some(addr) => to = addr,
            None => return Err(VerifyError::Integrity("Genesis tx has no recipient".to_string()))
        }
        let tx = Tx::new(None, Some(to), self.get_amount(), None, None, None, None);
        let genesis_tx = genesis_tx::GenesisTx(tx);
        let encoding: Vec<u8>;
        match genesis_tx.encode() {
            Ok(data) => encoding = data,
            Err(e) => return Err(VerifyError::Proto(e))
        }
        let signature: RecoverableSignature;
        match self.get_signature() {
            Some(sig) => signature = sig,
            None => return Err(VerifyError::Integrity("Genesis tx has no signature".to_string()))
        }
        match Tx::verify(encoding, to, signature) {
            Ok(result) => return Ok(result),
            Err(e) => return Err(VerifyError::Secp(e))
        }
    }
}

impl ITx for GenesisSignedTx<Tx> {
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
    use common::address::ValidAddress;

    #[test]
    fn it_creates_a_signed_genesis_transaction() {
        let to: Address = Address::from_string(&"HLjHZYkjRNkjH3zPmXoU8FDEJ3ALDkuA".to_string()).unwrap();
        let amount = 100;
        let signature_bytes = [155,15,206,7,232,20,132,186,33,220,220,31,36,100,48,103,61,198,40,
        155,48,189,196,64,162,132,254,252,160,242,136,253,42,105,138,104,227,162,198,254,59,114,252,
        62,3,211,77,93,196,72,221,18,128,112,143,185,199,178,56,0,141,232,12,201];
        let secp = Secp256k1::without_caps();
        let recovery = RecoveryId::from_i32(0).unwrap();
        let signature =
            RecoverableSignature::from_compact(&secp, &signature_bytes, recovery).unwrap();
        let tx = Tx::new(None, Some(to), amount, None, None, Some(signature), Some(recovery));
        let gen_sign_tx = GenesisSignedTx(tx);
        assert_eq!(to, gen_sign_tx.get_to().unwrap());
        assert_eq!(amount, gen_sign_tx.get_amount());
        assert_eq!(signature, gen_sign_tx.get_signature().unwrap());
        assert_eq!(recovery, gen_sign_tx.get_recovery().unwrap());
    }

    #[test]
    fn it_verifies_a_signed_genesis_transaction() {
        let to: Address = Address::from_string(&"HLjHZYkjRNkjH3zPmXoU8FDEJ3ALDkuA".to_string()).unwrap();
        let amount = 100;
        let signature_bytes = [155,15,206,7,232,20,132,186,33,220,220,31,36,100,48,103,61,198,40,
        155,48,189,196,64,162,132,254,252,160,242,136,253,42,105,138,104,227,162,198,254,59,114,252,
        62,3,211,77,93,196,72,221,18,128,112,143,185,199,178,56,0,141,232,12,201];
        let secp = Secp256k1::without_caps();
        let recovery = RecoveryId::from_i32(0).unwrap();
        let signature =
            RecoverableSignature::from_compact(&secp, &signature_bytes, recovery).unwrap();
        let tx = Tx::new(None, Some(to), amount, None, None, Some(signature), Some(recovery));
        let gen_sign_tx = GenesisSignedTx(tx);
        assert_eq!(true, gen_sign_tx.verify().unwrap());
    }
    
    #[test]
    fn it_rejects_a_forged_genesis_transaction() {
        let to: Address = Address::from_string(&"HLjHZYkjRNkjH3zPmXoU8FDEJ3ALDkuA".to_string()).unwrap();
        let amount = 200;
        let signature_bytes = [155,15,206,7,232,20,132,186,33,220,220,31,36,100,48,103,61,198,40,
        155,48,189,196,64,162,132,254,252,160,242,136,253,42,105,138,104,227,162,198,254,59,114,252,
        62,3,211,77,93,196,72,221,18,128,112,143,185,199,178,56,0,141,232,12,201];
        let secp = Secp256k1::without_caps();
        let recovery = RecoveryId::from_i32(0).unwrap();
        let signature =
            RecoverableSignature::from_compact(&secp, &signature_bytes, recovery).unwrap();
        let tx = Tx::new(None, Some(to), amount, None, None, Some(signature), Some(recovery));
        let gen_sign_tx = GenesisSignedTx(tx);
        match gen_sign_tx.verify() {
            Ok(_) => panic!("Invalid signature was reported as verified"),
            Err(_) => {}
        }
    }
}