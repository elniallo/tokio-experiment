use common::address::{Address, ValidAddress};
use common::{Encode, EncodingError};
use util::aes::encrypt_aes_cbc;
use util::hash::hash;
use secp256k1::{Secp256k1, PublicKey, SecretKey};
use uuid::Uuid;
use rand::{thread_rng, Rng};
use crypto::scrypt::{scrypt, ScryptParams};
use crypto::sha3::Sha3;
use crypto::symmetriccipher::SymmetricCipherError;
use crypto::digest::Digest;
use serde_json::to_vec;
use rustc_serialize::hex::ToHex;

#[derive(Serialize, Deserialize)]
pub struct CipherParams {
    iv: String,
    keysize: usize
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
    ciphertext: String,
    cipherparams: CipherParams,
    cipher: String,
    kdf: String,
    kdfparams: KdfParams,
    mac: String
}

#[derive(Serialize, Deserialize)]
pub struct KeyStore {
    pub network: String,
    pub version: usize,
    pub id: String,
    pub crypto: Crypto
}

impl KeyStore {
    pub fn to_v4(password: String, private_key: SecretKey) -> Result<KeyStore, SymmetricCipherError> {
        let network = "hycon".to_string();
        let version = 4;
        let id = Uuid::new_v4().to_string();
        let secp = Secp256k1::signing_only();
        let kdf = "scrypt".to_string();
        let dklen = 48;
        let keysize = 32;
        let mut salt_bytes = [0u8; 32];
        thread_rng().fill(&mut salt_bytes);
        let salt = salt_bytes.to_vec();
        let n = 262144;
        let r = 8;
        let p = 1;
        let kdf_params = KdfParams::new(dklen, salt.to_hex(), n, r, p);
        // log2(8192) = 13
        let scrypt_params = ScryptParams::new(18, r, p);
        let mut derived_key = [0u8; 48];
        scrypt(password.as_bytes(), &salt_bytes, &scrypt_params, &mut derived_key);
        let mut iv = [0u8; 16];
        thread_rng().fill(&mut iv);
        let cipher_params = CipherParams::new(iv.to_hex(), keysize);
        let cipher = "aes-256-cbc".to_string();
        let cipher_text = encrypt_aes_cbc(&private_key[..], &derived_key[0..32], &iv, false)?;
        let mut mac_input = vec![0u8; 16];
        mac_input.clone_from_slice(&derived_key[32..48]);
        mac_input.append(&mut cipher_text.clone());
        let mut mac_hash = Sha3::keccak256();
        mac_hash.input(&mac_input);
        let mut mac = [0u8; 32];
        mac_hash.result(&mut mac);
        let crypto = Crypto::new(cipher_text.to_hex(), cipher_params, cipher, kdf, kdf_params, mac.to_hex());
        Ok(KeyStore {
            network,
            version,
            id,
            crypto
        })
    }

    pub fn to_v3(password: String, private_key: SecretKey) -> Result<KeyStore, SymmetricCipherError> {
        let network = "ethereum".to_string();
        let version = 3;
        let id = Uuid::new_v4().to_string();
        let secp = Secp256k1::signing_only();
        let kdf = "scrypt".to_string();
        let dklen = 32;
        let keysize = 16;
        let mut salt_bytes = [0u8; 32];
        thread_rng().fill(&mut salt_bytes);
        let salt = salt_bytes.to_vec();
        let n = 262144;
        let r = 8;
        let p = 1;
        let kdf_params = KdfParams::new(dklen, salt.to_hex(), n, r, p);
        let scrypt_params = ScryptParams::new(18, r, p);
        let mut derived_key = [0u8; 32];
        scrypt(password.as_bytes(), &salt_bytes, &scrypt_params, &mut derived_key);
        let mut iv = [0u8; 16];
        thread_rng().fill(&mut iv);
        let cipher_params = CipherParams::new(iv.to_hex(), keysize);
        let cipher = "aes-128-cbc".to_string();
        let cipher_text = encrypt_aes_cbc(&private_key[..], &derived_key[0..16], &iv, true)?;
        let mut mac_input = vec![0u8; 16];
        mac_input.clone_from_slice(&derived_key[16..32]);
        mac_input.append(&mut cipher_text.clone());
        let mut mac_hash = Sha3::keccak256();
        mac_hash.input(&mac_input);
        let mut mac = [0u8; 32];
        mac_hash.result(&mut mac);
        let crypto = Crypto::new(cipher_text.to_hex(), cipher_params, cipher, kdf, kdf_params, mac.to_hex());
        Ok(KeyStore {
            network,
            version,
            id,
            crypto
        })
    }

    pub fn from_params(network: String, version: usize, id: String, crypto: Crypto) -> Result<KeyStore, SymmetricCipherError> {
        Ok(KeyStore {
            network,
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
    pub fn new(iv: String, keysize: usize) -> CipherParams {
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

        KeyStore::to_v4(password, private_key).unwrap();
    }

    #[test]
    fn it_makes_a_v3_keystore() {
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
        KeyStore::to_v3("password".to_string(), private_key).unwrap().encode().unwrap();
    }

    #[test]
    fn it_encodes_a_v3_keystore() {
        let password = "testpassword".to_string();
        let secp = Secp256k1::without_caps();
        let mut secret_key = [
            0x75, 0xca, 0x59, 0x3e, 0xcb, 0x74, 0x06, 0x79,
            0x19, 0x10, 0xff, 0x87, 0x0d, 0x0f, 0x8d, 0xd0,
            0x4d, 0x13, 0x00, 0xf2, 0xc0, 0xfd, 0x17, 0xaf,
            0xa6, 0xff, 0xbb, 0x60, 0x51, 0xbf, 0x4a, 0xc2];
        let private_key = SecretKey::from_slice(&secp, &secret_key).unwrap();
        let network = "ethereum".to_string();
        let version = 3;
        let id = "3198bc9c-6672-5ab3-d995-4942343ae5b6".to_string();
        let secp = Secp256k1::signing_only();
        let kdf = "scrypt".to_string();
        let dklen = 32;
        let salt = vec![
            0xae, 0x3c, 0xd4, 0xe7, 0x01, 0x38, 0x36, 0xa3,
            0xdf, 0x6b, 0xd7, 0x24, 0x1b, 0x12, 0xdb, 0x06,
            0x1d, 0xbe, 0x2c, 0x67, 0x85, 0x85, 0x3c, 0xce,
            0x42, 0x2d, 0x14, 0x8a, 0x62, 0x4c, 0xe0, 0xbd];
        let n = 262144;
        let r = 8;
        let p = 1;
        let kdf_params = KdfParams::new(dklen, salt.to_hex(), n, r, p);
        let scrypt_params = ScryptParams::new(18, r, p);
        let mut derived_key = [0u8; 32];
        scrypt(password.as_bytes(), &salt, &scrypt_params, &mut derived_key);
        let iv = [
            0x60, 0x87, 0xda, 0xb2, 0xf9, 0xfd, 0xbb, 0xfa,
            0xdd, 0xc3, 0x1a, 0x90, 0x97, 0x35, 0xc1, 0xe6];
        let cipher_params = CipherParams::new(iv.to_hex(), 16);
        let cipher = "aes-128-cbc".to_string();
        let cipher_text = encrypt_aes_cbc(&private_key[..], &derived_key[0..16], &iv, true).unwrap();
        assert_eq!("052643cd39cd9e2e0f045ebcfec424d33a9fa6135f363d94a95cb09abc4d086a1c7eecc132c966e2a6691c6640605615".to_string(), cipher_text.to_hex());
        let mut mac_input = vec![0u8; 16];
        mac_input.clone_from_slice(&derived_key[16..32]);
        mac_input.append(&mut cipher_text.clone());
        let mut mac_hash = Sha3::keccak256();
        mac_hash.input(&mac_input);
        let mut mac = [0u8; 32];
        mac_hash.result(&mut mac);
        assert_eq!("44c8b015c8702b9a315644725ca2c780605d62f56583ec43c140c14860ef807a".to_string(), mac.to_hex());
        let crypto = Crypto::new(cipher_text.to_hex(), cipher_params, cipher, kdf, kdf_params, mac.to_hex());
        let key_store = KeyStore::from_params(network, version, id, crypto).unwrap();
        let encoding = key_store.encode().unwrap();
        let encoding_string = String::from_utf8(encoding).unwrap();
        assert_eq!(encoding_string, expected_v3_encoding());
    }

    #[test]
    #[ignore]
    fn it_encodes_a_keystore() {
        let network = "hycon".to_string();
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
        let cipher_text = encrypt_aes_cbc(&secret_key, &decryption_key, &iv, false).unwrap();
        let mut mac = vec![0u8; 16];
        mac.clone_from_slice(&decryption_key[0..16]);
        mac.append(&mut cipher_text.clone());
        mac = hash(&mac, 32);
        let cipher_params = CipherParams::new(iv.to_hex(), 32);
        let cipher = "aes-256-cbc".to_string();
        let kdf = "scrypt".to_string();
        let crypto = Crypto::new(cipher_text.to_hex(), cipher_params, cipher, kdf, kdf_params, mac.to_hex());
        let version = 1;
        let id = Uuid::new_v4().to_string();
        let address = Address::from_pubkey(PublicKey::from_secret_key(&secp, &private_key)).to_string();
        let key_store = KeyStore::from_params(network, version, id, crypto).unwrap();
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

    fn expected_v3_encoding() -> String {
        "{\"network\":\"ethereum\",\"version\":3,\"id\":\"3198bc9c-6672-5ab3-d995-4942343ae5b6\",\"crypto\":{\"ciphertext\":\"052643cd39cd9e2e0f045ebcfec424d33a9fa6135f363d94a95cb09abc4d086a1c7eecc132c966e2a6691c6640605615\",\"cipherparams\":{\"iv\":\"6087dab2f9fdbbfaddc31a909735c1e6\",\"keysize\":16},\"cipher\":\"aes-128-cbc\",\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"salt\":\"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd\",\"n\":262144,\"r\":8,\"p\":1},\"mac\":\"44c8b015c8702b9a315644725ca2c780605d62f56583ec43c140c14860ef807a\"}}".to_string()
    }
}