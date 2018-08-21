use std::fs::File;
use std::io::{Error as FSError, Read, Write};
use std::string::FromUtf8Error;
use rustc_serialize::hex::{ToHex, FromHex, FromHexError};

use common::tx::Tx;
use common::signed_tx::SignedTx;
use common::{Encode, EncodingError};
use util::hash::hash;
use util::aes::{decrypt_aes, encrypt_aes};

use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::{Error, Message, RecoverableSignature, Secp256k1};
use rand::{thread_rng, Rng};
use crypto::symmetriccipher::SymmetricCipherError;

static WALLET_PATH: &str = "./wallet/";

pub enum WalletError {
    Fs(FSError),
    Encrypt(SymmetricCipherError),
    Load(FromUtf8Error),
    Hex(FromHexError),
    Key(Error)
}

pub struct Wallet {
    private_key: SecretKey,
    pub public_key: PublicKey
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

    pub fn load(name: String, password: String) -> Result<Wallet, WalletError> {
        let mut file: File;
        match File::open(WALLET_PATH.to_owned() + &"/rootkey/".to_owned() + &name) {
            Ok(f) => file = f,
            Err(e) => return Err(WalletError::Fs(e))
        }
        let mut buffer: Vec<u8> = vec![];
        match file.read(&mut buffer) {
            Ok(_) => {},
            Err(e) => return Err(WalletError::Fs(e)),
        }
        let loaded_data: String;
        match String::from_utf8(buffer) {
            Ok(data) => loaded_data = data,
            Err(e) => return Err(WalletError::Load(e))
        }
        let string_data: Vec<&str> = loaded_data.split(":").collect();
        let key = hash(password.as_bytes(), 32);
        let iv: Vec<u8>;
        match string_data[1].to_owned().from_hex() {
            Ok(data) => iv = data,
            Err(e) => return Err(WalletError::Hex(e))
        }
        let encrypted_data: Vec<u8>;
        match string_data[2].from_hex() {
            Ok(data) => encrypted_data = data,
            Err(e) => return Err(WalletError::Hex(e)),
        }

        let decrypted_data: Vec<u8>;
        match decrypt_aes(&encrypted_data, &key, &iv, 32) {
            Ok(data) => decrypted_data = data,
            Err(e) => return Err(WalletError::Encrypt(e))
        }

        let secp = Secp256k1::without_caps();
        let private_key: SecretKey;
        match SecretKey::from_slice(&secp, &decrypted_data) {
            Ok(s_key) => private_key = s_key,
            Err(e) => return Err(WalletError::Key(e))
        }
        Ok(Wallet::from_private_key(private_key))
    }

    pub fn sign(&self, message: &Vec<u8>) -> Result<RecoverableSignature, Error> {
        let msg = Message::from_slice(&message)?;
        let secp = Secp256k1::signing_only();
        Ok(secp.sign_recoverable(&msg, &self.private_key))
    }

    pub fn sign_tx(&self, tx: &Tx) -> Result<SignedTx, EncodingError> {
        let encoded_tx = hash(&tx.encode()?, 32);
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

    pub fn save(&self, name: String, password: String, hint: Option<String>) -> Result <(), WalletError> {
        match File::open(WALLET_PATH.to_owned()  + &"/rootkey/".to_owned() + &name) {
            Ok(_) => return Ok(()),
            Err(_) => {}
        }

        let mut file: File;
        match File::create(WALLET_PATH.to_owned() + &name) {
            Ok(f) => file = f,
            Err(e) => return Err(WalletError::Fs(e))
        }
        let key = hash(password.as_bytes(), 32);
        let mut iv = [0u8; 16];
        thread_rng().fill(&mut iv);
        let encrypted_key: Vec<u8>;
        match encrypt_aes(&self.private_key[..], &key, &iv) {
            Ok(data) => encrypted_key = data,
            Err(e) => return Err(WalletError::Encrypt(e))
        }

        let mut encrypted_data = ":".to_owned() + &iv.to_hex().to_owned() + &":".to_owned() + &encrypted_key.to_hex();
        match hint {
            Some(h) => encrypted_data = h + &encrypted_data,
            None => {}
        }
        match file.write(encrypted_data.as_bytes()) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(WalletError::Fs(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::address::{Address, ValidAddress};

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
        let signature= recoverable_signature.to_standard(&secp);
        let pubkey = secp.recover(&secp_message, &recoverable_signature).unwrap();
        assert_eq!(pubkey, wallet.public_key);
        secp.verify(&secp_message, &signature, &wallet.public_key).unwrap();
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
        let tx = Tx::new(Some(from), Some(to), amount, Some(fee), Some(nonce), None, None);
        let encoding = tx.encode().unwrap();
        let secp_message = Message::from_slice(&hash(&encoding[..], 32)[..]).unwrap();
        let signed_tx = wallet.sign_tx(&tx).unwrap();

        assert_eq!(signed_tx.from.unwrap(), from);
        assert_eq!(signed_tx.to.unwrap(), to);
        assert_eq!(signed_tx.amount, amount);
        assert_eq!(signed_tx.fee.unwrap(), fee);
        assert_eq!(signed_tx.nonce.unwrap(), nonce);

        let recoverable_signature = signed_tx.signature.unwrap();
        let signature = recoverable_signature.to_standard(&secp);
        let pubkey = secp.recover(&secp_message, &recoverable_signature).unwrap();
        assert_eq!(pubkey, wallet.public_key);
        secp.verify(&secp_message, &signature, &wallet.public_key).unwrap();
    }
}