use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::traits::{Encode, Exception};
use crate::util::aes::{decrypt_aes, encrypt_aes};
use crate::util::hash::hash;

use hex;
use openssl::pkcs5::scrypt;
use rand::{thread_rng, Rng};
use secp256k1::{Secp256k1, SecretKey};
use tiny_keccak::keccak256;
use uuid::Uuid;

use serde_json::de;
use serde_json::to_vec;

const DEFAULT_N: u64 = 262144;
const DEFAULT_R: u64 = 8;
const DEFAULT_P: u64 = 1;
const DEFAULT_V3_KEYSIZE: usize = 16;
const DEFAULT_V4_KEYSIZE: usize = 32;
const MAC_KEY_SIZE: usize = 16;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CipherParams {
    iv: String,
    keysize: Option<usize>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct KdfParams {
    dklen: usize,
    salt: String,
    n: u64,
    r: u64,
    p: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Crypto {
    ciphertext: String,
    cipherparams: CipherParams,
    cipher: String,
    kdf: String,
    kdfparams: KdfParams,
    mac: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct KeyStore {
    pub network: Option<String>,
    pub version: usize,
    pub id: String,
    pub crypto: Crypto,
}

impl KeyStore {
    fn gen_derived_key(
        password: String,
        salt: &[u8],
        iv: &[u8],
        given_n: Option<u64>,
        given_r: Option<u64>,
        given_p: Option<u64>,
        given_keysize: Option<usize>,
    ) -> Result<(KdfParams, CipherParams, usize, Vec<u8>), Box<Error>> {
        let n: u64;
        let r: u64;
        let p: u64;
        let keysize: usize;

        match given_n {
            Some(num) => n = num,
            None => n = DEFAULT_N,
        }
        match given_r {
            Some(num) => r = num,
            None => r = DEFAULT_R,
        }
        match given_p {
            Some(num) => p = num,
            None => p = DEFAULT_P,
        }
        match given_keysize {
            Some(num) => keysize = num as usize,
            None => keysize = DEFAULT_V3_KEYSIZE,
        }
        let dklen: usize = keysize + MAC_KEY_SIZE;
        let kdf_params = KdfParams::new(dklen, hex::encode(salt), n, r, p);
        let cipher_params = CipherParams::new(hex::encode(iv), Some(keysize));
        let mut derived_key = vec![0u8; dklen];
        let max_mem = 128 * n * r + 1024 * 3;
        scrypt(
            password.as_bytes(),
            &salt,
            n,
            r,
            p,
            max_mem,
            &mut derived_key,
        )?;
        Ok((kdf_params, cipher_params, keysize, derived_key))
    }

    fn gen_mac(keysize: usize, derived_key: &[u8], cipher_text: &Vec<u8>) -> Vec<u8> {
        let mut mac_input = vec![0u8; MAC_KEY_SIZE];
        mac_input.clone_from_slice(&derived_key[keysize..keysize + MAC_KEY_SIZE]);
        mac_input.append(&mut cipher_text.clone());
        keccak256(&mac_input).to_vec()
    }

    fn generate_keystore(
        password: String,
        private_key: SecretKey,
        version: usize,
        given_n: Option<u64>,
        given_r: Option<u64>,
        given_p: Option<u64>,
        given_keysize: Option<usize>,
    ) -> Result<KeyStore, Box<Error>> {
        let network = "hycon".to_string();
        let id = Uuid::new_v4().to_string();
        let kdf = "scrypt".to_string();

        let mut salt = [0u8; 32];
        thread_rng().fill(&mut salt);
        let mut iv = [0u8; 16];
        thread_rng().fill(&mut iv);

        let (kdf_params, cipher_params, keysize, derived_key) = KeyStore::gen_derived_key(
            password,
            &salt,
            &iv,
            given_n,
            given_r,
            given_p,
            given_keysize,
        )?;

        let cipher: String;
        if keysize == 16 {
            cipher = "aes-128-cbc".to_string();
        } else if keysize == 32 {
            cipher = "aes-256-cbc".to_string();
        } else {
            return Err(Box::new(Exception::new("Unsupported cipher")));
        }

        let cipher_text = encrypt_aes(
            &private_key[..],
            &derived_key[0..keysize],
            &iv,
            cipher.clone(),
        )?;
        let mac = KeyStore::gen_mac(keysize, &derived_key, &cipher_text);

        let crypto = Crypto::new(
            hex::encode(cipher_text),
            cipher_params,
            cipher,
            kdf,
            kdf_params,
            hex::encode(mac),
        );
        Ok(KeyStore {
            network: Some(network),
            version,
            id,
            crypto,
        })
    }

    pub fn unlock_keystore(keystore: KeyStore, password: String) -> Result<SecretKey, Box<Error>> {
        let version = keystore.version;
        if version < 3 || version > 4 {
            return Err(Box::new(Exception::new("Unsupported Version")));
        }
        let cipher = keystore.crypto.cipher;

        let salt = hex::decode(keystore.crypto.kdfparams.salt)?;
        let iv = hex::decode(keystore.crypto.cipherparams.iv)?;
        let mac = hex::decode(keystore.crypto.mac)?;
        let keysize: usize;
        match keystore.crypto.cipherparams.keysize {
            Some(k) => keysize = k,
            None => keysize = DEFAULT_V3_KEYSIZE,
        }
        let cipher_text = hex::decode(keystore.crypto.ciphertext)?;
        let n = keystore.crypto.kdfparams.n;
        let r = keystore.crypto.kdfparams.r;
        let p = keystore.crypto.kdfparams.p;

        let derived_key = KeyStore::gen_derived_key(
            password,
            &salt,
            &iv,
            Some(n),
            Some(r),
            Some(p),
            Some(keysize),
        )?
        .3;

        let derived_mac = KeyStore::gen_mac(keysize, &derived_key, &cipher_text);
        if derived_mac != mac {
            return Err(Box::new(Exception::new("Invalid Password")));
        }

        let private_key = decrypt_aes(&cipher_text, &derived_key[0..keysize], &iv, cipher)?;

        let secp = Secp256k1::without_caps();
        Ok(SecretKey::from_slice(&secp, &private_key)?)
    }

    pub fn load_keystore(path: PathBuf) -> Result<KeyStore, Box<Error>> {
        let file = File::open(path)?;
        Ok(de::from_reader(file)?)
    }

    pub fn load_legacy_keystore(path: PathBuf, password: String) -> Result<SecretKey, Box<Error>> {
        let mut file = File::open(path)?;
        let mut loaded_data = String::new();
        file.read_to_string(&mut loaded_data)?;
        Ok(KeyStore::unlock_legacy_keystore(loaded_data, password)?)
    }

    pub fn unlock_legacy_keystore(
        encoded_string: String,
        password: String,
    ) -> Result<SecretKey, Box<Error>> {
        let string_data: Vec<&str> = encoded_string.split(":").collect();

        let key = hash(password.as_bytes(), 32);
        let iv = hex::decode(string_data[1].to_owned())?;

        // The legacy versions encrypted the string representation of the private key.
        // It must be converted from that to bytes which the string represents
        let encrypted_hex_data = string_data[2].to_string();
        let encrypted_data = hex::decode(encrypted_hex_data)?.to_vec();

        let decrypted_string_data_bytes =
            decrypt_aes(&encrypted_data, &key, &iv, "aes-256-cbc".to_string())?;
        let decrypted_string_data = String::from_utf8(decrypted_string_data_bytes)?;

        let decrypted_data = hex::decode(decrypted_string_data)?;

        let secp = Secp256k1::without_caps();
        Ok(SecretKey::from_slice(&secp, &decrypted_data)?)
    }

    pub fn generate_v3(password: String, private_key: SecretKey) -> Result<KeyStore, Box<Error>> {
        KeyStore::generate_keystore(
            password,
            private_key,
            3,
            None,
            None,
            None,
            Some(DEFAULT_V3_KEYSIZE),
        )
    }

    pub fn generate_v4(password: String, private_key: SecretKey) -> Result<KeyStore, Box<Error>> {
        KeyStore::generate_keystore(
            password,
            private_key,
            4,
            None,
            None,
            None,
            Some(DEFAULT_V4_KEYSIZE),
        )
    }

    pub fn save(path: PathBuf, keystore: KeyStore) -> Result<(), Box<Error>> {
        if path.exists() {
            return Err(Box::new(Exception::new("File already exists")));
        }
        let mut file = File::create(path)?;
        let encoded_keystore = keystore.encode()?;
        file.write(&encoded_keystore)?;
        Ok(())
    }

    pub fn from_params(
        network: String,
        version: usize,
        id: String,
        crypto: Crypto,
    ) -> Result<KeyStore, Box<Error>> {
        Ok(KeyStore {
            network: Some(network),
            version,
            id,
            crypto,
        })
    }
}

impl Encode for KeyStore {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        Ok(to_vec(&self)?)
    }
}

impl Crypto {
    pub fn new(
        ciphertext: String,
        cipherparams: CipherParams,
        cipher: String,
        kdf: String,
        kdfparams: KdfParams,
        mac: String,
    ) -> Crypto {
        Crypto {
            ciphertext,
            cipherparams,
            cipher,
            kdf,
            kdfparams,
            mac,
        }
    }
}

impl KdfParams {
    pub fn new(dklen: usize, salt: String, n: u64, r: u64, p: u64) -> KdfParams {
        KdfParams {
            dklen,
            salt,
            n,
            r,
            p,
        }
    }
}

impl CipherParams {
    pub fn new(iv: String, keysize: Option<usize>) -> CipherParams {
        CipherParams { iv, keysize }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIVATE_KEY_SIZE: usize = 32;

    #[test]
    fn it_makes_a_v4_keystore() {
        let private_key = generate_private_key();
        KeyStore::generate_keystore(
            "password".to_string(),
            private_key,
            4,
            None,
            None,
            None,
            Some(DEFAULT_V4_KEYSIZE),
        )
        .unwrap()
        .encode()
        .unwrap();
    }

    #[test]
    fn it_makes_a_v3_keystore() {
        let private_key = generate_private_key();
        KeyStore::generate_keystore(
            "password".to_string(),
            private_key,
            3,
            Some(8192),
            None,
            None,
            None,
        )
        .unwrap()
        .encode()
        .unwrap();
    }

    #[test]
    fn it_encodes_a_v3_keystore() {
        let password = "testpassword".to_string();
        let secp = Secp256k1::without_caps();
        let secret_key = [
            0x75, 0xca, 0x59, 0x3e, 0xcb, 0x74, 0x06, 0x79, 0x19, 0x10, 0xff, 0x87, 0x0d, 0x0f,
            0x8d, 0xd0, 0x4d, 0x13, 0x00, 0xf2, 0xc0, 0xfd, 0x17, 0xaf, 0xa6, 0xff, 0xbb, 0x60,
            0x51, 0xbf, 0x4a, 0xc2,
        ];
        let private_key = SecretKey::from_slice(&secp, &secret_key).unwrap();
        let network = "hycon".to_string();
        let version = 3;
        let id = "3198bc9c-6672-5ab3-d995-4942343ae5b6".to_string();
        let kdf = "scrypt".to_string();
        let dklen = 32;
        let salt = vec![
            0xae, 0x3c, 0xd4, 0xe7, 0x01, 0x38, 0x36, 0xa3, 0xdf, 0x6b, 0xd7, 0x24, 0x1b, 0x12,
            0xdb, 0x06, 0x1d, 0xbe, 0x2c, 0x67, 0x85, 0x85, 0x3c, 0xce, 0x42, 0x2d, 0x14, 0x8a,
            0x62, 0x4c, 0xe0, 0xbd,
        ];
        let n = 8192;
        let r = 8;
        let p = 1;
        let kdf_params = KdfParams::new(dklen, hex::encode(salt.clone()), n, r, p);
        let mut derived_key = vec![0u8; dklen];
        let max_mem = 128 * n * r + 1024 * 3;
        scrypt(
            password.as_bytes(),
            &salt,
            n,
            r,
            p,
            max_mem,
            &mut derived_key,
        )
        .unwrap();
        let iv = [
            0x60, 0x87, 0xda, 0xb2, 0xf9, 0xfd, 0xbb, 0xfa, 0xdd, 0xc3, 0x1a, 0x90, 0x97, 0x35,
            0xc1, 0xe6,
        ];
        let cipher_params = CipherParams::new(hex::encode(iv), Some(DEFAULT_V3_KEYSIZE));
        let cipher = "aes-128-cbc".to_string();
        let cipher_text = encrypt_aes(
            &private_key[..],
            &derived_key[0..DEFAULT_V3_KEYSIZE],
            &iv,
            cipher.clone(),
        )
        .unwrap();
        let mac = KeyStore::gen_mac(16, &derived_key, &cipher_text);
        let crypto = Crypto::new(
            hex::encode(cipher_text.clone()),
            cipher_params,
            cipher.clone(),
            kdf,
            kdf_params,
            hex::encode(mac.clone()),
        );
        let key_store = KeyStore::from_params(network, version, id, crypto).unwrap();
        let encoding = key_store.encode().unwrap();
        let encoding_string = String::from_utf8(encoding).unwrap();

        assert_eq!("e44f58dc0de4183814970d2cd0f72385de469285c07caaad4eda5ab0b579d911419f40fe4412b63b8a50a787cc9403e4".to_string(), hex::encode(cipher_text.clone()));
        assert_eq!(
            "f9413c4b594522b2e73e3afb0f475c5013c9954de34bd6ca9ea39042e69f9e58".to_string(),
            hex::encode(mac.clone())
        );
        assert_eq!(encoding_string, expected_v3_encoding());
    }

    #[test]
    fn it_encodes_a_v4_keystore() {
        let password = "testpassword".to_string();
        let secp = Secp256k1::without_caps();
        let secret_key = [
            0x75, 0xca, 0x59, 0x3e, 0xcb, 0x74, 0x06, 0x79, 0x19, 0x10, 0xff, 0x87, 0x0d, 0x0f,
            0x8d, 0xd0, 0x4d, 0x13, 0x00, 0xf2, 0xc0, 0xfd, 0x17, 0xaf, 0xa6, 0xff, 0xbb, 0x60,
            0x51, 0xbf, 0x4a, 0xc2,
        ];
        let private_key = SecretKey::from_slice(&secp, &secret_key).unwrap();
        let network = "hycon".to_string();
        let version = 4;
        let id = "3198bc9c-6672-5ab3-d995-4942343ae5b6".to_string();
        let kdf = "scrypt".to_string();
        let dklen = 48;
        let salt = vec![
            0xae, 0x3c, 0xd4, 0xe7, 0x01, 0x38, 0x36, 0xa3, 0xdf, 0x6b, 0xd7, 0x24, 0x1b, 0x12,
            0xdb, 0x06, 0x1d, 0xbe, 0x2c, 0x67, 0x85, 0x85, 0x3c, 0xce, 0x42, 0x2d, 0x14, 0x8a,
            0x62, 0x4c, 0xe0, 0xbd,
        ];
        let n = 8192;
        let r = 8;
        let p = 1;
        let kdf_params = KdfParams::new(dklen, hex::encode(salt.clone()), n, r, p);
        let mut derived_key = vec![0u8; dklen];
        let max_mem = 128 * n * r + 1024 * 3;
        scrypt(
            password.as_bytes(),
            &salt,
            n,
            r,
            p,
            max_mem,
            &mut derived_key,
        )
        .unwrap();
        let iv = [
            0x60, 0x87, 0xda, 0xb2, 0xf9, 0xfd, 0xbb, 0xfa, 0xdd, 0xc3, 0x1a, 0x90, 0x97, 0x35,
            0xc1, 0xe6,
        ];
        let cipher_params = CipherParams::new(hex::encode(iv), Some(DEFAULT_V4_KEYSIZE));
        let cipher = "aes-256-cbc".to_string();
        let cipher_text = encrypt_aes(
            &private_key[..],
            &derived_key[0..DEFAULT_V4_KEYSIZE],
            &iv,
            cipher.clone(),
        )
        .unwrap();

        let mac = KeyStore::gen_mac(32, &derived_key, &cipher_text);

        let crypto = Crypto::new(
            hex::encode(cipher_text.clone()),
            cipher_params,
            cipher.clone(),
            kdf,
            kdf_params,
            hex::encode(mac.clone()),
        );
        let key_store = KeyStore::from_params(network, version, id, crypto).unwrap();
        let encoding = key_store.encode().unwrap();
        let encoding_string = String::from_utf8(encoding).unwrap();

        assert_eq!("73bd75ef1556bfd51b647e3860db8109b6f850f8d7598671c54b9727403576d1e3207b6ee10c15f5a0e2d7fb530ec673".to_string(), hex::encode(cipher_text.clone()));
        assert_eq!(
            "7e4de3e41191fde8156f5677de34a9330f775741145615d5e72ac8e6fb528506".to_string(),
            hex::encode(mac.clone())
        );
        assert_eq!(encoding_string, expected_v4_encoding());
    }

    #[test]
    fn it_unlocks_a_v3_keystore() {
        let private_key = generate_private_key();
        let keystore = KeyStore::generate_keystore(
            "password".to_string(),
            private_key,
            3,
            Some(8192),
            None,
            None,
            None,
        )
        .unwrap();
        let decrypted_key = KeyStore::unlock_keystore(keystore, "password".to_string()).unwrap();
        assert_eq!(private_key, decrypted_key);
    }

    #[test]
    fn it_unlocks_a_v4_keystore() {
        let private_key = generate_private_key();
        let keystore = KeyStore::generate_keystore(
            "password".to_string(),
            private_key,
            4,
            Some(8192),
            None,
            None,
            Some(32),
        )
        .unwrap();
        let decrypted_key = KeyStore::unlock_keystore(keystore, "password".to_string()).unwrap();
        assert_eq!(private_key, decrypted_key);
    }

    #[test]
    fn it_unlocks_a_ctr_v3_keystore() {
        let secp = Secp256k1::without_caps();
        let private_key = [
            0x7a, 0x28, 0xb5, 0xba, 0x57, 0xc5, 0x36, 0x03, 0xb0, 0xb0, 0x7b, 0x56, 0xbb, 0xa7,
            0x52, 0xf7, 0x78, 0x4b, 0xf5, 0x06, 0xfa, 0x95, 0xed, 0xc3, 0x95, 0xf5, 0xcf, 0x6c,
            0x75, 0x14, 0xfe, 0x9d,
        ];
        let secret_key = SecretKey::from_slice(&secp, &private_key).unwrap();
        let keystore = de::from_str(&ctr_encrypted_keystore()).unwrap();
        let decrypted_key =
            KeyStore::unlock_keystore(keystore, "testpassword".to_string()).unwrap();
        assert_eq!(secret_key, decrypted_key);
    }

    #[test]
    fn it_unlocks_a_legacy_keystore() {
        let secp = Secp256k1::without_caps();
        let expected_secret_key = [
            124, 214, 250, 144, 150, 223, 109, 129, 174, 64, 89, 150, 99, 184, 82, 202, 35, 114,
            240, 250, 76, 57, 129, 250, 43, 168, 112, 23, 225, 186, 120, 222,
        ];
        let password = "password".to_string();
        let expected_private_key = SecretKey::from_slice(&secp, &expected_secret_key).unwrap();
        let private_key = KeyStore::unlock_legacy_keystore(legacy_keystore(), password).unwrap();
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
         }"
        .to_string()
    }

    fn legacy_keystore() -> String {
        ":d5421c02ecbc77a07ce6e46e7c156a70\
         :89644ab4749644de227f292f36208da9\
         b0fb1a47a70b5bdec78097957616b128\
         694cc3436e3cec6e63cbbdd501cf1cca\
         a6adfa4277cfcce6656635a795abc2fc\
         7e32e48342db345f0b928cdb7ecf463d"
            .to_string()
    }
}
