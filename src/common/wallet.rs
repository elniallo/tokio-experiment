use common::tx::Tx;
use common::signed_tx::SignedTx;
use common::{Encode, EncodingError};

use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::{Error, Message, RecoverableSignature, Secp256k1};
use rand::{thread_rng, Rng};

pub struct Wallet {
    private_key: SecretKey,
    public_key: PublicKey
}

impl Wallet {
    pub fn new() -> Wallet {
        let secp = Secp256k1::without_caps();
        let mut secret_key = [0u8; 32];
        loop {
            thread_rng().fill(&mut secret_key);
            let priv_key = SecretKey::from_slice(&secp, &secret_key[..]);
            match priv_key {
                Ok(private_key) => {
                    let wallet = Wallet::from_private_key(private_key);
                    return wallet
                }
                Err(_) => {}
            }
        }
    }

    pub fn from_private_key(private_key: SecretKey) -> Wallet {
        let secp = Secp256k1::signing_only();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        Wallet {
            private_key,
            public_key
        }
    }

    pub fn sign(&self, message: &Vec<u8>) -> Result<RecoverableSignature, Error> {
        let msg = Message::from_slice(&message[..])?;
        let secp = Secp256k1::signing_only();
        Ok(secp.sign_recoverable(&msg, &self.private_key))
    }

    pub fn sign_tx(&self, tx: &Tx) -> Result<SignedTx, EncodingError> {
        let encoded_tx = tx.encode()?;
        let signature: RecoverableSignature;
        match self.sign(&encoded_tx) {
            Ok(sig) => signature = sig,
            Err(e) => return Err(EncodingError::Secp(e))
        }
        let secp = Secp256k1::without_caps();
        let recovery = signature.serialize_compact(&secp).0;
        let mut new_tx = tx.clone();
        new_tx.signature = Some(signature);
        new_tx.recovery = Some(recovery);
        Ok(SignedTx(new_tx))
    }
}