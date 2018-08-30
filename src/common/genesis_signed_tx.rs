use std::ops::Deref;
use std::error::Error;

use common::address::Address;
use common::tx::{Tx, Valid};
use common::genesis_tx::GenesisTx;
use common::{Encode, Exception, Proto};
use serialization::tx::GenesisSignedTx as ProtoGenesisSignedTx;

use secp256k1::{RecoverableSignature, RecoveryId, Secp256k1};
use protobuf::Message as ProtoMessage;

#[derive(Clone, Debug, PartialEq)]
pub struct GenesisSignedTx(pub GenesisTx);

impl GenesisSignedTx {
    pub fn decode(proto_tx: ProtoGenesisSignedTx) -> Result<GenesisSignedTx, Box<Error>> {
        let mut to: Address = [0; 20];
        to.clone_from_slice(&proto_tx.to[..]);
        let amount = proto_tx.amount;

        let secp = Secp256k1::without_caps();
        let recovery = RecoveryId::from_i32(proto_tx.recovery as i32)?;
        let signature = RecoverableSignature::from_compact(&secp, &proto_tx.signature, recovery)?;
        let tx = Tx::new(None, Some(to), amount, None, None, Some(signature), Some(recovery));
        let genesis_tx = GenesisTx(tx);
        Ok(GenesisSignedTx(genesis_tx))
    }
}

impl Deref for GenesisSignedTx {
    type Target = GenesisTx;
    fn deref(&self) -> &GenesisTx {
        &self.0
    }
}

impl Proto for GenesisSignedTx {
    type ProtoType = ProtoGenesisSignedTx;
    fn to_proto(&self) -> Result<ProtoGenesisSignedTx, Box<Error>> {
        let mut proto_genesis_signed_tx = ProtoGenesisSignedTx::new();
        let encoding = self.0.encode()?;
        proto_genesis_signed_tx.merge_from_bytes(&encoding)?;
        match self.recovery {
            Some(recovery) => proto_genesis_signed_tx.set_recovery(recovery.to_i32() as u32),
            None => return Err(Box::new(Exception::new("Signed tx is missing a recovery id")))
        }
        let secp = Secp256k1::without_caps();
        match self.signature {
            Some(signature) => proto_genesis_signed_tx.set_signature(signature.serialize_compact(&secp).1.to_vec()),
            None => return Err(Box::new(Exception::new("Signed tx is missing a signature")))
        }
        Ok(proto_genesis_signed_tx)
    }
}

impl Encode for GenesisSignedTx {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        let proto_genesis_signed_tx = self.to_proto()?;
        Ok(proto_genesis_signed_tx.write_to_bytes()?)
    }
}

impl Valid for GenesisSignedTx {
    fn verify(&self) -> Result<(), Box<Error>> {
        let to: Address;
        match self.to {
            Some(addr) => to = addr,
            None => return Err(Box::new(Exception::new("Genesis tx has no recipient")))
        }
        let tx = Tx::new(None, Some(to), self.amount, None, None, None, None);
        let genesis_tx = GenesisTx(tx);
        let encoding = genesis_tx.encode()?;
        let signature: RecoverableSignature;
        match self.signature {
            Some(sig) => signature = sig,
            None => return Err(Box::new(Exception::new("Genesis tx has no signature")))
        }
        Tx::verify(encoding, to, signature)
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
        let genesis_tx = GenesisTx(tx);
        let gen_sign_tx = GenesisSignedTx(genesis_tx);
        assert_eq!(to, gen_sign_tx.to.unwrap());
        assert_eq!(amount, gen_sign_tx.amount);
        assert_eq!(signature, gen_sign_tx.signature.unwrap());
        assert_eq!(recovery, gen_sign_tx.recovery.unwrap());
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
        let genesis_tx = GenesisTx(tx);
        let gen_sign_tx = GenesisSignedTx(genesis_tx);
        gen_sign_tx.verify().unwrap();
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
        let genesis_tx = GenesisTx(tx);
        let gen_sign_tx = GenesisSignedTx(genesis_tx);
        match gen_sign_tx.verify() {
            Ok(_) => panic!("Invalid signature was reported as verified"),
            Err(_) => {}
        }
    }
}