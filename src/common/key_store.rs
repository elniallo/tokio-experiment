use common::address::{Address, ValidAddress};
use common::{Encode, EncodingError};
use util::aes::encrypt_aes;
use util::hash::hash;
use secp256k1::{Secp256k1, PublicKey, SecretKey};
use uuid::Uuid;
use rand::{thread_rng, Rng};
use crypto::scrypt::{scrypt, ScryptParams};
use crypto::sha3::Sha3::sha_256;
use crypto::symmetriccipher::SymmetricCipherError;
use serde_json::to_vec;
use rustc_serialize::hex::ToHex;

#[derive(Serialize, Deserialize)]
pub struct CipherParams {
    iv: String
}

#[derive(Serialize, Deserialize)]
pub struct KdfParams {
    dklen: usize,
    salt: String,
    n: u32,
    r: u32,
    p: u32
}

#[derive(Serialize, Deserialize)]
pub struct Crypto {
    cipher_text: String,
    cipher_params: CipherParams,
    cipher: String,
    kdf: String,
    kdf_params: KdfParams,
    mac: String
}

#[derive(Serialize, Deserialize)]
pub struct KeyStore {
    pub version: usize,
    pub id: String,
    pub address: String,
    pub crypto: Crypto
}

impl KeyStore {
    pub fn new(password: String, private_key: SecretKey) -> Result<KeyStore, SymmetricCipherError> {
        let version = 1;
        let id = Uuid::new_v4().to_string();
        let secp = Secp256k1::signing_only();
        let address = Address::from_pubkey(PublicKey::from_secret_key(&secp, &private_key)).to_string();
        let kdf = "scrypt".to_string();
        let dklen = 32;
        let mut salt_bytes = [0u8; 32];
        thread_rng().fill(&mut salt_bytes);
        let salt = salt_bytes.to_vec();
        let n = 8192;
        let r = 8;
        let p = 1;
        let kdf_params = KdfParams::new(dklen, salt.to_hex(), n, r, p);
        // log2(8192) = 13
        let scrypt_params = ScryptParams::new(13, r, p);
        let mut decryption_key = [0u8; 32];
        scrypt(password.as_bytes(), &salt_bytes, &scrypt_params, &mut decryption_key[0..16]);
        let mut iv = [0u8; 16];
        thread_rng().fill(&mut iv);
        let cipher_params = CipherParams::new(iv.to_hex());
        let cipher = "aes-256-cbc".to_string();
        panic!("{:?}", &private_key[..].to_hex());
        let cipher_text = encrypt_aes(&private_key[..], &decryption_key, &iv, false)?;
        let mut mac = vec![0u8; 16];
        mac.clone_from_slice(&decryption_key[16..32]);
        mac.append(&mut cipher_text.clone());
        mac = sha_256(&mac);
        let crypto = Crypto::new(cipher_text.to_hex(), cipher_params, cipher, kdf, kdf_params, mac.to_hex());
        Ok(KeyStore {
            version,
            id,
            address,
            crypto
        })
    }

    pub fn from_params(version: usize, id: String, address: String, crypto: Crypto) -> Result<KeyStore, SymmetricCipherError> {
        Ok(KeyStore {
            version,
            id,
            address,
            crypto
        })
    }
}

impl Encode<EncodingError> for KeyStore {
    fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        match to_vec(&self) {
            Ok(vec) => Ok(vec),
            Err(e) => Err(EncodingError::Json(e))
        }
    }
}

impl Crypto {
    pub fn new(cipher_text: String, cipher_params: CipherParams, cipher: String, kdf: String, kdf_params: KdfParams, mac: String) -> Crypto {
        Crypto {
            cipher_text,
            cipher_params,
            cipher,
            kdf,
            kdf_params,
            mac
        }
    }
}

impl KdfParams {
    pub fn new(dklen: usize, salt: String, n: u32, r: u32, p: u32) -> KdfParams {
        KdfParams {
            dklen,
            salt,
            n,
            r,
            p
        }
    }
}

impl CipherParams {
    pub fn new(iv: String) -> CipherParams {
        CipherParams {
            iv
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wallet::Wallet;

    #[test]
    fn it_makes_a_keystore() {
        let mut secret_key = [0u8; 32];
        let secp = Secp256k1::without_caps();
        let private_key: SecretKey;
        loop {
            thread_rng().fill(&mut secret_key);
            let priv_key = SecretKey::from_slice(&secp, &secret_key[..]);
            match priv_key {
                Ok(sk) => {
                    private_key = sk;
                    break;
                }
                Err(_) => {}
            }
        }
        let password = "password".to_string();

        KeyStore::new(password, private_key).unwrap();
    }

    #[test]
    fn it_encodes_a_keystore() {
        let secp = Secp256k1::signing_only();
        let secret_key = [
            89, 93, 215, 179, 88, 214, 191, 205,
            71, 18, 68, 185, 7, 173, 139, 43, 57,
            169, 198, 89, 105, 244, 77, 14, 200,
            198, 139, 124, 84, 119, 244, 131];
        let private_key = SecretKey::from_slice(&secp, &secret_key).unwrap();
        let salt_bytes = [
            151, 182, 137, 124, 150, 214, 220, 53,
            68, 86, 23, 212, 253, 237, 96, 146,
            14, 217, 43, 21, 226, 129, 214, 195,
            203, 79, 111, 65, 213, 96, 239, 21];

        let kdf_params = KdfParams::new(32, salt_bytes.to_hex(), 8192, 8, 1);
        let scrypt_params = ScryptParams::new(13, 8, 1);
        let mut decryption_key = [0u8; 32];
        let password = "password".to_string();
        panic!("{:?}", password.as_bytes().to_hex());
        scrypt(password.as_bytes(), &salt_bytes, &scrypt_params, &mut decryption_key);
        panic!("{:?}", decryption_key.to_hex());
        let iv = [
            185, 241, 200, 172, 170, 213, 21, 117,
            32, 89, 71, 130, 253, 101, 113, 139];
        let cipher_text = encrypt_aes(&secret_key, &decryption_key, &iv, false).unwrap();
        let mut mac = vec![0u8; 16];
        mac.clone_from_slice(&decryption_key[0..16]);
        mac.append(&mut cipher_text.clone());
        mac = hash(&mac, 32);
        let cipher_params = CipherParams::new(iv.to_hex());
        let cipher = "aes-256-cbc".to_string();
        let kdf = "scrypt".to_string();
        let crypto = Crypto::new(cipher_text.to_hex(), cipher_params, cipher, kdf, kdf_params, mac.to_hex());
        let version = 1;
        let id = Uuid::new_v4().to_string();
        let address = Address::from_pubkey(PublicKey::from_secret_key(&secp, &private_key)).to_string();
        let key_store = KeyStore::from_params(version, id, address, crypto).unwrap();
        let encoding = key_store.encode().unwrap();
        panic!("{}", String::from_utf8(encoding).unwrap());

        let expected_decryption_key = [
            0x14, 0x9d, 0x34, 0xb7, 0x02, 0x28, 0x8a, 0x8f,
            0x2c, 0x37, 0x95, 0x7f, 0xf4, 0xfd, 0x61, 0xf7,
            0x32, 0x04, 0x9b, 0x38, 0xff, 0xdb, 0x62, 0x37,
            0x0c, 0xee, 0xb7, 0x12, 0x59, 0x4d, 0x7d, 0x30];
        let expected_cipher_text = [
            0x7d, 0xed, 0x35, 0x5c, 0xc6, 0xc4, 0xda, 0x4c,
            0xc6, 0xa5, 0x6e, 0x49, 0x08, 0x87, 0x11, 0xe0];
    }
}