use std::error::Error;

use crate::common::signed_tx::SignedTx;
use crate::common::tx::Tx;
use crate::traits::Encode;
use crate::util::hash::hash;

use rand::rngs::EntropyRng;
use rand::Rng;
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::{Message, RecoverableSignature, Secp256k1};

type WalletResult<T> = Result<T, Box<Error>>;

pub struct Wallet {
    private_key: SecretKey,
    pub public_key: PublicKey,
}

impl Wallet {
    pub fn new() -> Wallet {
        let mut rng = EntropyRng::new();
        let private_key = Wallet::generate_private_key(&mut rng);
        Wallet::from_private_key(private_key)
    }

    pub fn from_private_key(private_key: SecretKey) -> Wallet {
        let secp = Secp256k1::signing_only();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        Wallet {
            private_key,
            public_key,
        }
    }

    pub fn sign(&self, message: &Vec<u8>) -> WalletResult<RecoverableSignature> {
        let msg = Message::from_slice(&message)?;
        let secp = Secp256k1::signing_only();
        Ok(secp.sign_recoverable(&msg, &self.private_key))
    }

    pub fn sign_tx(&self, tx: &Tx) -> WalletResult<SignedTx> {
        let encoded_tx = hash(&tx.encode()?, 32);
        let signature = self.sign(&encoded_tx)?;
        let secp = Secp256k1::without_caps();
        let recovery = signature.serialize_compact(&secp).0;

        Ok(SignedTx::from_tx(tx, signature, recovery))
    }

    pub fn generate_private_key<RngType>(rng: &mut RngType) -> SecretKey
    where
        RngType: Rng,
    {
        let secp = Secp256k1::without_caps();
        let mut secret_key = [0u8; 32];
        loop {
            rng.fill(&mut secret_key);
            let priv_key = SecretKey::from_slice(&secp, &secret_key[..]);
            if let Ok(key) = priv_key {
                return key;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::address::{Address, ValidAddress};
    use crate::util::hash::hash;

    use rand::{thread_rng, Rng};
    use secp256k1::{Message, Secp256k1};

    #[test]
    fn it_makes_a_wallet() {
        Wallet::new();
    }

    #[test]
    fn it_signs_data() {
        let wallet = Wallet::new();
        let message = hash("This is a test message to be signed".as_bytes(), 32);
        let secp_message = Message::from_slice(&message[..]).unwrap();
        let recoverable_signature = wallet.sign(&message.to_vec()).unwrap();
        let secp = Secp256k1::verification_only();
        let signature = recoverable_signature.to_standard(&secp);
        let pubkey = secp.recover(&secp_message, &recoverable_signature).unwrap();
        assert_eq!(pubkey, wallet.public_key);
        secp.verify(&secp_message, &signature, &wallet.public_key)
            .unwrap();
    }

    #[test]
    fn it_signs_a_tx() {
        let wallet = Wallet::new();
        let to_wallet = Wallet::new();
        let secp = Secp256k1::verification_only();
        let from = Address::from_pubkey(wallet.public_key);
        let to = Address::from_pubkey(to_wallet.public_key);
        let amount = thread_rng().gen_range(123456, 12345566789);
        let fee = thread_rng().gen_range(1, 12345293847);
        let nonce = thread_rng().gen_range(0, 123456789);
        let tx = Tx::new(from, to, amount, fee, nonce);
        let encoding = tx.encode().unwrap();
        let secp_message = Message::from_slice(&hash(&encoding[..], 32)[..]).unwrap();
        let signed_tx = wallet.sign_tx(&tx).unwrap();

        assert_eq!(signed_tx.from, from);
        assert_eq!(signed_tx.to, to);
        assert_eq!(signed_tx.amount, amount);
        assert_eq!(signed_tx.fee, fee);
        assert_eq!(signed_tx.nonce, nonce);

        let recoverable_signature = signed_tx.signature;
        let signature = recoverable_signature.to_standard(&secp);
        let pubkey = secp.recover(&secp_message, &recoverable_signature).unwrap();
        assert_eq!(pubkey, wallet.public_key);
        secp.verify(&secp_message, &signature, &wallet.public_key)
            .unwrap();
    }
}
