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
    fn gen_derived_key(password: String,
                       salt: &[u8],
                       iv: &[u8],
                       given_n: Option<u32>,
                       given_r: Option<u32>,
                       given_p: Option<u32>,
                       given_keysize: Option<u32>) -> (ScryptParams, KdfParams, CipherParams, usize, Vec<u8>) {
        let n: u32;
        let r: u32;
        let p: u32;
        let keysize: usize;

        match given_n {
            Some(num) => n = num,
            None => n = 262144
        }
        match given_r {
            Some(num) => r = num,
            None => r = 8
        }
        match given_p {
            Some(num) => p = num,
            None => p = 1
        }
        match given_keysize {
            Some(num) => keysize = num as usize,
            None => keysize = 32
        }
        let dklen: usize = keysize + 16;
        let log_n = ((n as f64).log2()) as u8;
        let scrypt_params = ScryptParams::new(log_n, r, p);
        let kdf_params = KdfParams::new(dklen, salt.to_hex(), n, r, p);
        let cipher_params = CipherParams::new(iv.to_hex(), keysize);
        let mut derived_key = vec![0u8; dklen];
        scrypt(password.as_bytes(), &salt, &scrypt_params, &mut derived_key);
        (scrypt_params, kdf_params, cipher_params, keysize, derived_key)
    }

    fn gen_mac(keysize: usize, derived_key: &[u8], cipher_text: &Vec<u8>) -> Vec<u8>{
        let mut mac_input = vec![0u8; 16];
        mac_input.clone_from_slice(&derived_key[keysize..keysize + 16]);
        mac_input.append(&mut cipher_text.clone());
        let mut mac_hash = Sha3::keccak256();
        mac_hash.input(&mac_input);
        let mut mac = vec![0u8; 32];
        mac_hash.result(&mut mac);
        mac
    }

    fn generate_keystore(password: String,
                 private_key: SecretKey,
                 version: usize,
                 given_n: Option<u32>,
                 given_r: Option<u32>,
                 given_p: Option<u32>,
                 given_keysize: Option<u32>) -> Result<KeyStore, SymmetricCipherError> {
        let network = "hycon".to_string();
        let id = Uuid::new_v4().to_string();
        let kdf = "scrypt".to_string();

        let mut salt = [0u8; 32];
        thread_rng().fill(&mut salt);
        let mut iv = [0u8; 16];
        thread_rng().fill(&mut iv);

        let (scrypt_params,
             kdf_params,
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
            return Err(SymmetricCipherError::InvalidLength)
        }

        let cipher_text = encrypt_aes_cbc(&private_key[..], &derived_key[0..keysize], &iv, true)?;
        let mac = KeyStore::gen_mac(keysize, &derived_key, &cipher_text);

        let crypto = Crypto::new(cipher_text.to_hex(), cipher_params, cipher, kdf, kdf_params, mac.to_hex());
        Ok(KeyStore {
            network,
            version,
            id,
            crypto
        })
    }

    pub fn to_v4(password: String, private_key: SecretKey) -> Result<KeyStore, SymmetricCipherError> {
        KeyStore::generate_keystore(password, private_key, 4, None, None, None, None)
    }

    pub fn to_v3(password: String, private_key: SecretKey) -> Result<KeyStore, SymmetricCipherError> {
        KeyStore::generate_keystore(password, private_key, 3, None, None, None, Some(16))
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

        KeyStore::generate_keystore(password, private_key, 4, Some(8192), None, None, None).unwrap().encode().unwrap();
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
        KeyStore::generate_keystore("password".to_string(), private_key, 3, Some(8192), None, None, Some(16)).unwrap().encode().unwrap();
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
        let network = "ethereum".to_string();
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
    fn it_encodes_a_v4_keystore() {
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
        scrypt(password.as_bytes(), &salt_bytes, &scrypt_params, &mut decryption_key);
        let iv = [
            185, 241, 200, 172, 170, 213, 21, 117,
            32, 89, 71, 130, 253, 101, 113, 139];
        let cipher_text = encrypt_aes_cbc(&secret_key, &decryption_key, &iv, true).unwrap();
        let mut mac = vec![0u8; 16];
        mac.clone_from_slice(&decryption_key[0..16]);
        mac.append(&mut cipher_text.clone());
        mac = hash(&mac, 32);
        let cipher_params = CipherParams::new(iv.to_hex(), 32);
        let cipher = "aes-256-cbc".to_string();
        let kdf = "scrypt".to_string();
        let crypto = Crypto::new(cipher_text.to_hex(), cipher_params, cipher, kdf, kdf_params, mac.to_hex());
        let version = 4;
        let id = Uuid::new_v4().to_string();
        let address = Address::from_pubkey(PublicKey::from_secret_key(&secp, &private_key)).to_string();
        let key_store = KeyStore::from_params(network, version, id, crypto).unwrap();
        let encoding = key_store.encode().unwrap();
        panic!(String::from_utf8(encoding).unwrap())
    }

    fn expected_v3_encoding() -> String {
        "{\"network\":\"ethereum\",\
          \"version\":3,\
          \"id\":\"3198bc9c-6672-5ab3-d995-4942343ae5b6\",\
          \"crypto\":\
            {\"ciphertext\":\"052643cd39cd9e2e0f045ebcfec424d33a9fa6135f363d94a95cb09abc4d086a1c7eecc132c966e2a6691c6640605615\",\
             \"cipherparams\":\
                {\"iv\":\"6087dab2f9fdbbfaddc31a909735c1e6\",\
                 \"keysize\":16},\
                 \"cipher\":\"aes-128-cbc\",\
                 \"kdf\":\"scrypt\",\
                 \"kdfparams\":\
                    {\"dklen\":32,\
                     \"salt\":\"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd\",\
                     \"n\":262144,\
                     \"r\":8,\
                     \"p\":1},\
                 \"mac\":\"44c8b015c8702b9a315644725ca2c780605d62f56583ec43c140c14860ef807a\"}}".to_string()
    }

    fn expected_v4_encoding() -> String {
        "{
            \"network\": \"hycon\",
            \"version\": 4,
            \"id\": \"ddeb9f92-e95b-4261-b6d1-f7467389ae57\",
            \"crypto\": {
            \"ciphertext\": \"7ad1265e0d5f6fbdfa55fcf190f4a762d1b1484f2be628f28e94c7af22a2cb2d9991b6b876a920712ee26b48e362419e\",
            \"cipherparams\": {
                \"iv\": \"d8c87d0f26499ab7c99edd9f9cbcc731\",
                \"keysize\": 32
            },
            \"cipher\": \"aes-256-cbc\",
            \"kdf\": \"scrypt\",
            \"kdfparams\": {
                \"dklen\": 48,
                \"salt\": \"ad9db25d82e7235a271c1b8a5c288199023693bb4105ec26e48eb167affa8545\",
                \"n\": 262144,
                \"r\": 8,
                \"p\": 1
            },
            \"mac\": \"dacacb8ded75e02f52590a9d0be964ab74e1e26e96894610e6579e46eee706c9\"
        }".to_string()
    }
}