use std::string::FromUtf8Error;

use common::address::{Address, ValidAddress};
use common::{Encode, EncodingError};
use util::aes::{AESError, encrypt_aes, decrypt_aes};
use util::hash::hash;
use secp256k1::{Error as SecpError, Secp256k1, PublicKey, SecretKey};
use uuid::Uuid;
use rand::{thread_rng, Rng};
use crypto::scrypt::{scrypt, ScryptParams};
use crypto::sha3::Sha3;
use crypto::symmetriccipher::SymmetricCipherError;
use crypto::digest::Digest;
use serde_json::{to_vec, Error as JSONError};
use serde_json::de;
use rustc_serialize::hex::{ToHex, FromHex, FromHexError};

const DEFAULT_N: u32 = 16384;
const DEFAULT_R: u32 = 8;
const DEFAULT_P: u32 = 1;
const DEFAULT_V3_KEYSIZE: usize = 16;
const DEFAULT_V4_KEYSIZE: usize = 32;
const MAC_KEY_SIZE: usize = 16;
const MAC_SIZE: usize = 32;
const PRIVATE_KEY_SIZE: usize = 32;

#[derive(Debug)]
pub enum KeyStoreError {
    Crypto(SymmetricCipherError),
    Serial(JSONError),
    Hex(FromHexError),
    Access(String),
    Key(SecpError),
    Aes(AESError),
    String(FromUtf8Error)
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CipherParams {
    iv: String,
    keysize: Option<usize>
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct KdfParams {
    dklen: usize,
    salt: String,
    n: u32,
    r: u32,
    p: u32
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Crypto {
    ciphertext: String,
    cipherparams: CipherParams,
    cipher: String,
    kdf: String,
    kdfparams: KdfParams,
    mac: String
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct KeyStore {
    pub network: Option<String>,
    pub version: usize,
    pub id: String,
    pub crypto: Crypto
}

impl KeyStore {
    fn gen_derived_key(password: String,
                       salt: &[u8],
                       iv: &[u8],
                       given_n: Option<u32>,
                       given_r: Option<u32>,
                       given_p: Option<u32>,
                       given_keysize: Option<usize>) -> (KdfParams, CipherParams, usize, Vec<u8>) {
        let n: u32;
        let r: u32;
        let p: u32;
        let keysize: usize;

        match given_n {
            Some(num) => n = num,
            None => n = DEFAULT_N
        }
        match given_r {
            Some(num) => r = num,
            None => r = DEFAULT_R
        }
        match given_p {
            Some(num) => p = num,
            None => p = DEFAULT_P
        }
        match given_keysize {
            Some(num) => keysize = num as usize,
            None => keysize = DEFAULT_V3_KEYSIZE
        }
        let dklen: usize = keysize + MAC_KEY_SIZE;
        let log_n = ((n as f64).log2()) as u8;
        let scrypt_params = ScryptParams::new(log_n, r, p);
        let kdf_params = KdfParams::new(dklen, salt.to_hex(), n, r, p);
        let cipher_params = CipherParams::new(iv.to_hex(), Some(keysize));
        let mut derived_key = vec![0u8; dklen];
        let max_mem = 128 * n * r + 1024 * 3;
        scrypt(password.as_bytes(), &salt, n, r, p, max_mem, &mut derived_key);
        (kdf_params, cipher_params, keysize, derived_key)
    }

    fn gen_mac(keysize: usize, derived_key: &[u8], cipher_text: &Vec<u8>) -> Vec<u8>{
        let mut mac_input = vec![0u8; MAC_KEY_SIZE];
        mac_input.clone_from_slice(&derived_key[keysize..keysize + MAC_KEY_SIZE]);
        mac_input.append(&mut cipher_text.clone());
        let mut mac_hash = Sha3::keccak256();
        mac_hash.input(&mac_input);
        let mut mac = vec![0u8; MAC_SIZE];
        mac_hash.result(&mut mac);
        mac
    }

    fn generate_keystore(password: String,
                 private_key: SecretKey,
                 version: usize,
                 given_n: Option<u32>,
                 given_r: Option<u32>,
                 given_p: Option<u32>,
                 given_keysize: Option<usize>) -> Result<KeyStore, AESError> {
        let network = "hycon".to_string();
        let id = Uuid::new_v4().to_string();
        let kdf = "scrypt".to_string();

        let mut salt = [0u8; 32];
        thread_rng().fill(&mut salt);
        let mut iv = [0u8; 16];
        thread_rng().fill(&mut iv);

        let (kdf_params,
             cipher_params,
             keysize,
             derived_key) = KeyStore::gen_derived_key(password, &salt, &iv, given_n, given_r, given_p, given_keysize);

        let cipher: String;
        if keysize == 16 {
            cipher = "aes-128-cbc".to_string();
        } else if keysize == 24 {
            cipher = "aes-192-cbc".to_string();
        } else if keysize == 32 {
            cipher = "aes-256-cbc".to_string();
        } else {
            return Err(AESError::Cipher(SymmetricCipherError::InvalidLength))
        }

        let cipher_text;
        match encrypt_aes(&private_key[..], &derived_key[0..keysize], &iv, true, cipher.clone()) {
            Ok(c) => cipher_text = c,
            Err(e) => return Err(e)
        }
        let mac = KeyStore::gen_mac(keysize, &derived_key, &cipher_text);

        let crypto = Crypto::new(cipher_text.to_hex(), cipher_params, cipher, kdf, kdf_params, mac.to_hex());
        Ok(KeyStore {
            network: Some(network),
            version,
            id,
            crypto
        })
    }

    pub fn unlock_keystore(keystore: KeyStore, password: String) -> Result<SecretKey, KeyStoreError> {
        let version = keystore.version;
        if version < 3 || version > 4 {
            return Err(KeyStoreError::Access("Unsupported Version".to_string()))
        }
        let cipher = keystore.crypto.cipher;

        let salt: Vec<u8>;
        match keystore.crypto.kdfparams.salt.from_hex() {
            Ok(s) => salt = s,
            Err(e) => return Err(KeyStoreError::Hex(e))
        }
        let iv: Vec<u8>;
        match keystore.crypto.cipherparams.iv.from_hex() {
            Ok(i) => iv = i,
            Err(e) => return Err(KeyStoreError::Hex(e))
        }
        let mac: Vec<u8>;
        match keystore.crypto.mac.from_hex() {
            Ok(m) => mac = m,
            Err(e) => return Err(KeyStoreError::Hex(e))
        }
        let keysize: usize;
        match keystore.crypto.cipherparams.keysize {
            Some(k) => keysize = k,
            None => keysize = DEFAULT_V3_KEYSIZE
        }
        let cipher_text: Vec<u8>;
        match keystore.crypto.ciphertext.from_hex() {
            Ok(c) => cipher_text = c,
            Err(e) => return Err(KeyStoreError::Hex(e))
        }
        let n = keystore.crypto.kdfparams.n;
        let r = keystore.crypto.kdfparams.r;
        let p = keystore.crypto.kdfparams.p;

        let derived_key =
            KeyStore::gen_derived_key(password, &salt, &iv, Some(n), Some(r), Some(p), Some(keysize)).3;

        let derived_mac = KeyStore::gen_mac(keysize, &derived_key, &cipher_text);
        if derived_mac != mac {
            return Err(KeyStoreError::Access("Invalid Password".to_string()))
        }

        let private_key: Vec<u8>;
        match decrypt_aes(&cipher_text, &derived_key[0..keysize], &iv, cipher, PRIVATE_KEY_SIZE) {
            Ok(pk) => private_key = pk,
            Err(e) => return Err(KeyStoreError::Aes(e))
        }

        let secp = Secp256k1::without_caps();
        match SecretKey::from_slice(&secp, &private_key) {
            Ok(sk) => return Ok(sk),
            Err(e) => return Err(KeyStoreError::Key(e))
        }
    }

    pub fn load_keystore(encoded_keystore: Vec<u8>) -> Result<KeyStore, JSONError> {
        de::from_slice(&encoded_keystore)
    }

    pub fn load_legacy_keystore(encoded_keystore: Vec<u8>, password: String) -> Result<SecretKey, KeyStoreError> {
        let loaded_data: String;
        match String::from_utf8(encoded_keystore) {
            Ok(data) => loaded_data = data,
            Err(e) => return Err(KeyStoreError::String(e))
        }
        let string_data: Vec<&str> = loaded_data.split(":").collect();

        let key = hash(password.as_bytes(), 32);
        let iv: Vec<u8>;
        match string_data[1].to_owned().from_hex() {
            Ok(data) => iv = data,
            Err(e) => return Err(KeyStoreError::Hex(e))
        }
        // The legacy versions encrypted the string representation of the private key.
        // It must be converted from that to bytes which the string represents
        let encrypted_hex_data = string_data[2].to_string();
        let encrypted_data: Vec<u8>;
        match encrypted_hex_data.from_hex() {
            Ok(data) => encrypted_data = data.to_vec(),
            Err(e) => return Err(KeyStoreError::Hex(e))
        }

        let decrypted_string_data_bytes;
        match decrypt_aes(&encrypted_data, &key, &iv, "aes-256-cbc".to_string(), 64) {
            Ok(data) => decrypted_string_data_bytes = data,
            Err(e) => return Err(KeyStoreError::Aes(e))
        }

        let decrypted_string_data;
        match String::from_utf8(decrypted_string_data_bytes) {
            Ok(data) => decrypted_string_data = data,
            Err(e) => return Err(KeyStoreError::String(e))
        }

        let decrypted_data;
        match decrypted_string_data.from_hex() {
            Ok(data) => decrypted_data = data,
            Err(e) => return Err(KeyStoreError::Hex(e))
        }

        let secp = Secp256k1::without_caps();
        match SecretKey::from_slice(&secp, &decrypted_data) {
            Ok(s_key) => return Ok(s_key),
            Err(e) => return Err(KeyStoreError::Key(e))
        }
    }

    pub fn to_v3(password: String, private_key: SecretKey) -> Result<KeyStore, AESError> {
        KeyStore::generate_keystore(password, private_key, 3, None, None, None, Some(DEFAULT_V3_KEYSIZE))
    }

    pub fn to_v4(password: String, private_key: SecretKey) -> Result<KeyStore, AESError> {
        KeyStore::generate_keystore(password, private_key, 4, None, None, None, Some(DEFAULT_V4_KEYSIZE))
    }

    pub fn from_params(network: String, version: usize, id: String, crypto: Crypto) -> Result<KeyStore, SymmetricCipherError> {
        Ok(KeyStore {
            network: Some(network),
            version,
            id,
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
    pub fn new(ciphertext: String, cipherparams: CipherParams, cipher: String, kdf: String, kdfparams: KdfParams, mac: String) -> Crypto {
        Crypto {
            ciphertext,
            cipherparams,
            cipher,
            kdf,
            kdfparams,
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
    pub fn new(iv: String, keysize: Option<usize>) -> CipherParams {
        CipherParams {
            iv,
            keysize
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wallet::Wallet;

    #[test]
    fn it_makes_a_v4_keystore() {
        let private_key = generate_private_key();
        KeyStore::generate_keystore("password".to_string(), private_key, 4, None, None, None, Some(DEFAULT_V4_KEYSIZE)).unwrap().encode().unwrap();
    }

    #[test]
    fn it_makes_a_v3_keystore() {
        let private_key = generate_private_key();
        KeyStore::generate_keystore("password".to_string(), private_key, 3, Some(8192), None, None, None).unwrap().encode().unwrap();
    }

    #[test]
    fn it_encodes_a_v3_keystore() {
        let password = "testpassword".to_string();
        let secp = Secp256k1::without_caps();
        let secret_key = [
            0x75, 0xca, 0x59, 0x3e, 0xcb, 0x74, 0x06, 0x79,
            0x19, 0x10, 0xff, 0x87, 0x0d, 0x0f, 0x8d, 0xd0,
            0x4d, 0x13, 0x00, 0xf2, 0xc0, 0xfd, 0x17, 0xaf,
            0xa6, 0xff, 0xbb, 0x60, 0x51, 0xbf, 0x4a, 0xc2];
        let private_key = SecretKey::from_slice(&secp, &secret_key).unwrap();
        let network = "hycon".to_string();
        let version = 3;
        let id = "3198bc9c-6672-5ab3-d995-4942343ae5b6".to_string();
        let kdf = "scrypt".to_string();
        let dklen = 32;
        let salt = vec![
            0xae, 0x3c, 0xd4, 0xe7, 0x01, 0x38, 0x36, 0xa3,
            0xdf, 0x6b, 0xd7, 0x24, 0x1b, 0x12, 0xdb, 0x06,
            0x1d, 0xbe, 0x2c, 0x67, 0x85, 0x85, 0x3c, 0xce,
            0x42, 0x2d, 0x14, 0x8a, 0x62, 0x4c, 0xe0, 0xbd];
        let n = 8192;
        let r = 8;
        let p = 1;
        let kdf_params = KdfParams::new(dklen, salt.to_hex(), n, r, p);
        let scrypt_params = ScryptParams::new(13, r, p);
        let mut derived_key = vec![0u8; dklen];
        let max_mem = 128 * n * r + 1024 * 3;
        scrypt(password.as_bytes(), &salt, n, r, p, max_mem, &mut derived_key);
        let iv = [
            0x60, 0x87, 0xda, 0xb2, 0xf9, 0xfd, 0xbb, 0xfa,
            0xdd, 0xc3, 0x1a, 0x90, 0x97, 0x35, 0xc1, 0xe6];
        let cipher_params = CipherParams::new(iv.to_hex(), Some(DEFAULT_V3_KEYSIZE));
        let cipher = "aes-128-cbc".to_string();
        let cipher_text = encrypt_aes(&private_key[..], &derived_key[0..DEFAULT_V3_KEYSIZE], &iv, true, cipher.clone()).unwrap();
        assert_eq!("e44f58dc0de4183814970d2cd0f72385de469285c07caaad4eda5ab0b579d911419f40fe4412b63b8a50a787cc9403e4".to_string(), cipher_text.to_hex());
        let mut mac_input = vec![0u8; MAC_KEY_SIZE];
        mac_input.clone_from_slice(&derived_key[DEFAULT_V3_KEYSIZE..DEFAULT_V3_KEYSIZE + MAC_KEY_SIZE]);
        mac_input.append(&mut cipher_text.clone());
        let mut mac_hash = Sha3::keccak256();
        mac_hash.input(&mac_input);
        let mut mac = [0u8; MAC_SIZE];
        mac_hash.result(&mut mac);
        assert_eq!("f9413c4b594522b2e73e3afb0f475c5013c9954de34bd6ca9ea39042e69f9e58".to_string(), mac.to_hex());
        let crypto = Crypto::new(cipher_text.to_hex(), cipher_params, cipher.clone(), kdf, kdf_params, mac.to_hex());
        let key_store = KeyStore::from_params(network, version, id, crypto).unwrap();
        let encoding = key_store.encode().unwrap();
        let encoding_string = String::from_utf8(encoding).unwrap();
        assert_eq!(encoding_string, expected_v3_encoding());
    }

    #[test]
    fn it_encodes_a_v4_keystore() {
        let password = "testpassword".to_string();
        let secp = Secp256k1::without_caps();
        let secret_key = [
            0x75, 0xca, 0x59, 0x3e, 0xcb, 0x74, 0x06, 0x79,
            0x19, 0x10, 0xff, 0x87, 0x0d, 0x0f, 0x8d, 0xd0,
            0x4d, 0x13, 0x00, 0xf2, 0xc0, 0xfd, 0x17, 0xaf,
            0xa6, 0xff, 0xbb, 0x60, 0x51, 0xbf, 0x4a, 0xc2];
        let private_key = SecretKey::from_slice(&secp, &secret_key).unwrap();
        let network = "hycon".to_string();
        let version = 4;
        let id = "3198bc9c-6672-5ab3-d995-4942343ae5b6".to_string();
        let kdf = "scrypt".to_string();
        let dklen = 48;
        let salt = vec![
            0xae, 0x3c, 0xd4, 0xe7, 0x01, 0x38, 0x36, 0xa3,
            0xdf, 0x6b, 0xd7, 0x24, 0x1b, 0x12, 0xdb, 0x06,
            0x1d, 0xbe, 0x2c, 0x67, 0x85, 0x85, 0x3c, 0xce,
            0x42, 0x2d, 0x14, 0x8a, 0x62, 0x4c, 0xe0, 0xbd];
        let n = 8192;
        let r = 8;
        let p = 1;
        let kdf_params = KdfParams::new(dklen, salt.to_hex(), n, r, p);
        let scrypt_params = ScryptParams::new(13, r, p);
        let mut derived_key = vec![0u8; dklen];
        let max_mem = 128 * n * r + 1024 * 3;
        scrypt(password.as_bytes(), &salt, n, r, p, max_mem, &mut derived_key).unwrap();
        let iv = [
            0x60, 0x87, 0xda, 0xb2, 0xf9, 0xfd, 0xbb, 0xfa,
            0xdd, 0xc3, 0x1a, 0x90, 0x97, 0x35, 0xc1, 0xe6];
        let cipher_params = CipherParams::new(iv.to_hex(), Some(DEFAULT_V4_KEYSIZE));
        let cipher = "aes-256-cbc".to_string();
        let cipher_text = encrypt_aes(&private_key[..], &derived_key[0..DEFAULT_V4_KEYSIZE], &iv, true, cipher.clone()).unwrap();
        assert_eq!("73bd75ef1556bfd51b647e3860db8109b6f850f8d7598671c54b9727403576d1e3207b6ee10c15f5a0e2d7fb530ec673".to_string(), cipher_text.to_hex());
        let mut mac_input = vec![0u8; MAC_KEY_SIZE];
        mac_input.clone_from_slice(&derived_key[DEFAULT_V4_KEYSIZE..DEFAULT_V4_KEYSIZE + MAC_KEY_SIZE]);
        mac_input.append(&mut cipher_text.clone());
        let mut mac_hash = Sha3::keccak256();
        mac_hash.input(&mac_input);
        let mut mac = [0u8; MAC_SIZE];
        mac_hash.result(&mut mac);
        assert_eq!("7e4de3e41191fde8156f5677de34a9330f775741145615d5e72ac8e6fb528506".to_string(), mac.to_hex());
        let crypto = Crypto::new(cipher_text.to_hex(), cipher_params, cipher.clone(), kdf, kdf_params, mac.to_hex());
        let key_store = KeyStore::from_params(network, version, id, crypto).unwrap();
        let encoding = key_store.encode().unwrap();
        let encoding_string = String::from_utf8(encoding).unwrap();
        assert_eq!(encoding_string, expected_v4_encoding());
    }

    #[test]
    fn it_loads_a_v3_keystore() {
        let keystore = KeyStore::load_keystore(expected_v3_encoding().as_bytes().to_vec()).unwrap();
        let expected_cipher_params = CipherParams::new("6087dab2f9fdbbfaddc31a909735c1e6".to_string(), Some(16));
        let expected_kdf_params = KdfParams::new(32, "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd".to_string(), 8192, 8, 1);
        let expected_mac = "f9413c4b594522b2e73e3afb0f475c5013c9954de34bd6ca9ea39042e69f9e58".to_string();
        let expected_crypto = Crypto::new("e44f58dc0de4183814970d2cd0f72385de469285c07caaad4eda5ab0b579d911419f40fe4412b63b8a50a787cc9403e4".to_string(),
            expected_cipher_params, "aes-128-cbc".to_string(), "scrypt".to_string(), expected_kdf_params, expected_mac);
        assert_eq!(keystore.network, Some("hycon".to_string()));
        assert_eq!(keystore.version, 3);
        assert_eq!(keystore.id, "3198bc9c-6672-5ab3-d995-4942343ae5b6".to_string());
        assert_eq!(keystore.crypto, expected_crypto);
    }

    #[test]
    fn it_loads_a_v4_keystore() {
        let keystore = KeyStore::load_keystore(expected_v4_encoding().as_bytes().to_vec()).unwrap();
        let expected_cipher_params = CipherParams::new("6087dab2f9fdbbfaddc31a909735c1e6".to_string(), Some(32));
        let expected_kdf_params = KdfParams::new(48, "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd".to_string(), 8192, 8, 1);
        let expected_mac = "7e4de3e41191fde8156f5677de34a9330f775741145615d5e72ac8e6fb528506".to_string();
        let expected_crypto = Crypto::new("73bd75ef1556bfd51b647e3860db8109b6f850f8d7598671c54b9727403576d1e3207b6ee10c15f5a0e2d7fb530ec673".to_string(),
            expected_cipher_params, "aes-256-cbc".to_string(), "scrypt".to_string(), expected_kdf_params, expected_mac);
        assert_eq!(keystore.network, Some("hycon".to_string()));
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.id, "3198bc9c-6672-5ab3-d995-4942343ae5b6".to_string());
        assert_eq!(keystore.crypto, expected_crypto);
    }

    #[test]
    fn it_loads_a_v3_keystore_with_extra_zeros() {
        let mut frame = [0u8; 1024];

    }

    #[test]
    fn it_unlocks_a_v3_keystore() {
        let private_key = generate_private_key();
        let keystore = KeyStore::generate_keystore("password".to_string(), private_key, 3, Some(8192), None, None, None).unwrap();
        let decrypted_key = KeyStore::unlock_keystore(keystore, "password".to_string()).unwrap();
        assert_eq!(private_key, decrypted_key);
    }

    #[test]
    fn it_unlocks_a_v4_keystore() {
        let private_key = generate_private_key();
        let keystore = KeyStore::generate_keystore("password".to_string(), private_key, 4, Some(8192), None, None, Some(32)).unwrap();
        let decrypted_key = KeyStore::unlock_keystore(keystore, "password".to_string()).unwrap();
        assert_eq!(private_key, decrypted_key);
    }

    // You can ignore this test for the most part since it takes a long time to complete.
    // However, you should run this test if you are changing the wallet/keystore/crypto functions
    #[test]
    #[ignore]
    fn it_unlocks_a_ctr_v3_keystore() {
        let secp = Secp256k1::without_caps();
        let private_key = [
            0x7a, 0x28, 0xb5, 0xba, 0x57, 0xc5, 0x36, 0x03,
            0xb0, 0xb0, 0x7b, 0x56, 0xbb, 0xa7, 0x52, 0xf7,
            0x78, 0x4b, 0xf5, 0x06, 0xfa, 0x95, 0xed, 0xc3,
            0x95, 0xf5, 0xcf, 0x6c, 0x75, 0x14, 0xfe, 0x9d];
        let secret_key = SecretKey::from_slice(&secp, &private_key).unwrap();
        let keystore = KeyStore::load_keystore(ctr_encrypted_keystore().as_bytes().to_vec()).unwrap();
        let decrypted_key = KeyStore::unlock_keystore(keystore, "testpassword".to_string()).unwrap();
        assert_eq!(secret_key, decrypted_key);
    }

    #[test]
    fn it_unlocks_a_legacy_keystore() {
        let secp = Secp256k1::without_caps();
        let expected_secret_key = [
            124, 214, 250, 144, 150, 223, 109, 129,
            174, 64,  89,  150, 99,  184, 82,  202,
            35,  114, 240, 250, 76,  57,  129, 250,
            43,  168, 112, 23,  225, 186, 120, 222];
        let password = "password".to_string();
        let expected_private_key = SecretKey::from_slice(&secp, &expected_secret_key).unwrap();
        let private_key = KeyStore::load_legacy_keystore(legacy_keystore().as_bytes().to_vec(), password).unwrap();
        assert_eq!(private_key, expected_private_key);
    }

    fn generate_private_key() -> SecretKey {
        let mut secret_key = [0u8; PRIVATE_KEY_SIZE];
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
        private_key
    }

    fn expected_v3_encoding() -> String {
        "{\
            \"network\":\"hycon\",\
            \"version\":3,\
            \"id\":\"3198bc9c-6672-5ab3-d995-4942343ae5b6\",\
            \"crypto\":{\
                \"ciphertext\":\"e44f58dc0de4183814970d2cd0f72385de469285c07caaad4eda5ab0b579d911419f40fe4412b63b8a50a787cc9403e4\",\
                \"cipherparams\":{\
                    \"iv\":\"6087dab2f9fdbbfaddc31a909735c1e6\",\
                    \"keysize\":16\
                },\
                \"cipher\":\"aes-128-cbc\",\
                \"kdf\":\"scrypt\",\
                \"kdfparams\":{\
                    \"dklen\":32,\
                    \"salt\":\"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd\",\
                    \"n\":8192,\
                    \"r\":8,\
                    \"p\":1\
                },\
                \"mac\":\"f9413c4b594522b2e73e3afb0f475c5013c9954de34bd6ca9ea39042e69f9e58\"}\
         }".to_string()
    }

    fn expected_v4_encoding() -> String {
        "{\
            \"network\":\"hycon\",\
            \"version\":4,\
            \"id\":\"3198bc9c-6672-5ab3-d995-4942343ae5b6\",\
            \"crypto\":{\
                \"ciphertext\":\"73bd75ef1556bfd51b647e3860db8109b6f850f8d7598671c54b9727403576d1e3207b6ee10c15f5a0e2d7fb530ec673\",\
                \"cipherparams\":{\
                    \"iv\":\"6087dab2f9fdbbfaddc31a909735c1e6\",\
                    \"keysize\":32\
                },\
                \"cipher\":\"aes-256-cbc\",\
                \"kdf\":\"scrypt\",\
                \"kdfparams\":{\
                    \"dklen\":48,\
                    \"salt\":\"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd\",\
                    \"n\":8192,\
                    \"r\":8,\
                    \"p\":1\
                },\
            \"mac\":\"7e4de3e41191fde8156f5677de34a9330f775741145615d5e72ac8e6fb528506\"}\
        }".to_string()
    }

    fn ctr_encrypted_keystore() -> String {
        "{\
            \"version\": 3,\
            \"id\":\"1bfe00fa-3a0f-4758-936b-c0816c84d57b\",\
            \"address\":\"008aeeda4d805471df9b2a5b0f38a0c3bcba786b\",\
            \"crypto\":{\
                \"ciphertext\":\"0262b75a41568c31e3b248ae6051f3fc8037a50d99d043813c17df315e67c5f2\",\
                \"cipherparams\":{\
                    \"iv\":\"b043656cc25861128a501acbdce1e8af\"},\
                \"cipher\":\"aes-128-ctr\",\
                \"kdf\":\"scrypt\",\
                \"kdfparams\":{\
                    \"dklen\":32,\
                    \"salt\":\"fb7b556a8150c2ec985cf572bc9ba5c31dc909d5cc1135f1d5e28a4eb9dc7055\",\
                    \"n\":262144,\
                    \"r\":8,\
                    \"p\":1\
                },\
                \"mac\":\"b7e4a5938a298802e449db084b7f591b5a161a304ef9b0f234a229ce554f915d\"}\
        }".to_string()
    }

    fn legacy_keystore() -> String {
        ":d5421c02ecbc77a07ce6e46e7c156a70\
        :89644ab4749644de227f292f36208da9\
        b0fb1a47a70b5bdec78097957616b128\
        694cc3436e3cec6e63cbbdd501cf1cca\
        a6adfa4277cfcce6656635a795abc2fc\
        7e32e48342db345f0b928cdb7ecf463d".to_string()
    }
}