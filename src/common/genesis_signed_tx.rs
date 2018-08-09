use common::address::Address;
use common::tx::{Tx, Base, Sendable, Signed, Valid};
use common::genesis_tx;
use common::Encode;
use serialization;


use protobuf::Message as ProtoMessage;
use secp256k1::{Error, RecoverableSignature, RecoveryId, Secp256k1};

pub struct GenesisSignedTx<T>(T);

impl GenesisSignedTx<Tx> {
    pub fn decode(proto_tx: serialization::tx::GenesisSignedTx) -> Result<GenesisSignedTx<Tx>, Error> {
        let mut to: Address = [0; 20];
        to.clone_from_slice(&proto_tx.to[..]);
        let amount = proto_tx.amount;

        let secp = Secp256k1::without_caps();
        let recovery = RecoveryId::from_i32(proto_tx.recovery as i32)?;
        let signature = RecoverableSignature::from_compact(&secp, &proto_tx.signature[..], recovery)?;
        let tx = Tx::new(None, Some(to), amount, None, None, Some(signature), Some(recovery));
        Ok(GenesisSignedTx(tx))
    }
    
    pub fn verify(&self) -> Result<bool, Error> {
        let sender = self.0.to.unwrap();
        let tx = Tx::new(None, Some(sender), self.0.amount, None, None, None, None);
        let genesis_tx = genesis_tx::GenesisTx(tx);
        let encoding = genesis_tx.encode().unwrap();
        let signature = self.0.signature.unwrap();

        Tx::verify(encoding, sender, signature)
    }
}

impl Encode for GenesisSignedTx<Tx> 
where Tx: Base + Sendable + Signed {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut itx = serialization::tx::GenesisSignedTx::new();
        let secp = Secp256k1::without_caps();
        itx.set_to(self.0.get_to().to_vec());
        itx.set_amount(self.0.get_amount());
        itx.set_signature(self.0.get_signature().serialize_compact(&secp).1.to_vec());
        itx.set_recovery(self.0.get_recovery().to_i32() as u32);
        let encoding = itx.write_to_bytes(); {
            match encoding {
                Ok(data) => return Ok(data),
                Err(e) => return Err(e.to_string())
            }
        }
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
        assert_eq!(to, gen_sign_tx.0.to.unwrap());
        assert_eq!(amount, gen_sign_tx.0.amount);
        assert_eq!(signature, gen_sign_tx.0.signature.unwrap());
        assert_eq!(recovery, gen_sign_tx.0.recovery.unwrap());
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