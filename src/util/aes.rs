use std::error::Error;

use crate::traits::Exception;

use openssl::nid::Nid;
use openssl::symm::{decrypt, encrypt, Cipher};

const AES_128_CBC: &str = "aes-128-cbc";
const AES_256_CBC: &str = "aes-256-cbc";
const AES_128_CTR: &str = "aes-128-ctr";
const AES_256_CTR: &str = "aes-256-ctr";
const AES_128_ECB: &str = "aes-128-ecb";
const AES_256_ECB: &str = "aes-256-ecb";
const AES_128_XTS: &str = "aes-128-xts";
const AES_256_XTS: &str = "aes-256-xts";
const AES_128_CFB1: &str = "aes-128-cfb1";
const AES_256_CFB1: &str = "aes-256-cfb1";
const AES_128_CFB8: &str = "aes-128-cfb8";
const AES_256_CFB8: &str = "aes-256-cfb8";
const AES_128_CFB128: &str = "aes-128-cfb128";
const AES_256_CFB128: &str = "aes-256-cfb128";
const AES_128_GCM: &str = "aes-128-gcm";
const AES_256_GCM: &str = "aes-256-gcm";
const AES_128_CCM: &str = "aes-128-ccm";
const AES_256_CCM: &str = "aes-256-ccm";

fn get_nid(name: String) -> Result<Nid, Exception> {
    match name.to_lowercase().as_ref() {
        AES_128_CBC => Ok(Nid::AES_128_CBC),
        AES_256_CBC => Ok(Nid::AES_256_CBC),
        AES_128_CTR => Ok(Nid::AES_128_CTR),
        AES_256_CTR => Ok(Nid::AES_256_CTR),
        AES_128_ECB => Ok(Nid::AES_128_ECB),
        AES_256_ECB => Ok(Nid::AES_256_ECB),
        AES_128_XTS => Ok(Nid::AES_128_XTS),
        AES_256_XTS => Ok(Nid::AES_256_XTS),
        AES_128_CFB1 => Ok(Nid::AES_128_CFB1),
        AES_256_CFB1 => Ok(Nid::AES_256_CFB1),
        AES_128_CFB8 => Ok(Nid::AES_128_CFB8),
        AES_256_CFB8 => Ok(Nid::AES_256_CFB8),
        AES_128_CFB128 => Ok(Nid::AES_128_CFB128),
        AES_256_CFB128 => Ok(Nid::AES_256_CFB128),
        AES_128_GCM => Ok(Nid::AES_128_GCM),
        AES_256_GCM => Ok(Nid::AES_256_GCM),
        AES_128_CCM => Ok(Nid::AES_128_CCM),
        AES_256_CCM => Ok(Nid::AES_256_CCM),
        _ => Err(Exception::new("Unsupported AES cipher")),
    }
}

pub fn encrypt_aes(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
    cipher: String,
) -> Result<Vec<u8>, Box<Error>> {
    let nid = get_nid(cipher)?;
    let algo = Cipher::from_nid(nid);
    let encryptor = algo.ok_or_else(|| Exception::new("my_key not defined"))?;
    Ok(encrypt(encryptor, key, Some(iv), data)?)
}

pub fn decrypt_aes(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
    cipher: String,
) -> Result<Vec<u8>, Box<Error>> {
    let nid = get_nid(cipher)?;
    let algo = Cipher::from_nid(nid);
    let decryptor = algo.ok_or_else(|| Exception::new("my_key not defined"))?;
    Ok(decrypt(decryptor, key, Some(iv), data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hash::hash;
    use rand::{thread_rng, Rng};

    #[test]
    fn it_cbc_encrypts_data_less_than_32_bytes() {
        let key = hash("password".as_bytes(), 32);
        let iv = [
            0xed, 0xe2, 0xa8, 0x5d, 0x3a, 0x82, 0x4d, 0x08, 0xc7, 0xd6, 0xcf, 0xc5, 0xe9, 0x3e,
            0x1d, 0x21,
        ];
        let data = "Data to be encrypted".as_bytes();
        let encryption = encrypt_aes(data, &key, &iv, "aes-256-cbc".to_string()).unwrap();
        let expected_encryption = vec![
            0xe1, 0x47, 0xa9, 0x39, 0x0c, 0xe6, 0x4b, 0x55, 0x93, 0x46, 0xc1, 0x7a, 0xde, 0xff,
            0x03, 0xd6, 0xd7, 0xd6, 0x24, 0x8f, 0xed, 0x98, 0x65, 0x59, 0xe4, 0x45, 0x62, 0xc8,
            0xfa, 0xc3, 0x70, 0xec,
        ];
        assert_eq!(encryption, expected_encryption);
    }

    #[test]
    fn it_cbc_encrypts_data_exactly_32_bytes_long() {
        let key = hash("password".as_bytes(), 32);
        let iv = [
            0x25, 0x52, 0x1f, 0xc0, 0x00, 0x69, 0x10, 0xa5, 0x3f, 0x81, 0x9e, 0x24, 0xe5, 0xaa,
            0x70, 0x09,
        ];
        let data = "aaaaaaaabbbbbbbbccccccccdddddddd".as_bytes();
        let encryption = encrypt_aes(data, &key, &iv, "aes-256-cbc".to_string()).unwrap();
        let expected_encryption = vec![
            0x5d, 0x5f, 0xaf, 0xfd, 0x02, 0x45, 0xae, 0x91, 0x4b, 0x6f, 0x24, 0x6e, 0x62, 0x5a,
            0x93, 0xda, 0x40, 0x34, 0xb1, 0x1f, 0xbc, 0xd8, 0x20, 0x05, 0x55, 0x06, 0x77, 0x93,
            0x0e, 0x88, 0x34, 0x86, 0xcb, 0xb4, 0x56, 0x38, 0x09, 0xca, 0x80, 0x5a, 0x30, 0x24,
            0x3b, 0x02, 0x8f, 0x6e, 0x8e, 0x97,
        ];
        assert_eq!(encryption, expected_encryption);
    }

    #[test]
    fn it_cbc_encrypts_data_longer_than_32_bytes() {
        let key = hash("password".as_bytes(), 32);
        let iv = [
            0xad, 0xec, 0x18, 0x8e, 0xab, 0xc7, 0xcc, 0x8b, 0xe1, 0x20, 0xa7, 0x41, 0x9f, 0xdb,
            0xa9, 0x07,
        ];
        let data = "Really long data to be encrypted.  This data is so long it exceeds 32 bytes!"
            .as_bytes();
        let encryption = encrypt_aes(data, &key, &iv, "aes-256-cbc".to_string()).unwrap();
        let expected_encryption = vec![
            0xdd, 0xb3, 0xd2, 0xfb, 0xd0, 0x20, 0xa5, 0xd2, 0x8d, 0x82, 0x91, 0xe2, 0x74, 0x50,
            0xbc, 0x5d, 0xbf, 0x0d, 0x28, 0x6a, 0x57, 0xfa, 0xcd, 0xcb, 0xdb, 0xbe, 0xcf, 0x85,
            0x5e, 0x29, 0x9c, 0xf8, 0xce, 0x57, 0x79, 0x02, 0x12, 0xba, 0x8e, 0x48, 0xdf, 0x12,
            0xa6, 0x6b, 0xf0, 0xfb, 0xd0, 0xbc, 0xb0, 0x8e, 0xb3, 0x2c, 0x7f, 0xb3, 0x37, 0x14,
            0x0f, 0x81, 0xb5, 0x8f, 0x56, 0x39, 0x25, 0x27, 0x22, 0xe2, 0x2e, 0xb1, 0xd8, 0x60,
            0x46, 0x92, 0xd5, 0xd5, 0x43, 0x0d, 0xa7, 0xf0, 0x44, 0x91,
        ];
        assert_eq!(encryption, expected_encryption);
    }

    #[test]
    fn it_decrypts_cbc_encrypted_data() {
        let mut password = [0u8; 32];
        thread_rng().fill(&mut password);
        let key = hash(&password, 32);
        let mut iv = [0u8; 16];
        thread_rng().fill(&mut iv);
        let mut data = [0u8; 256];
        thread_rng().fill(&mut data);
        let encryption = encrypt_aes(&data, &key[..], &iv, "aes-256-cbc".to_string()).unwrap();
        let decryption = decrypt_aes(&encryption, &key, &iv, "aes-256-cbc".to_string()).unwrap();
        assert_eq!(data.to_vec(), &decryption[..]);
    }

    #[test]
    fn it_ctr_encrypts_data() {
        let key = [
            0xfa, 0xc1, 0x92, 0xce, 0xb5, 0xfd, 0x77, 0x29, 0x06, 0xbe, 0xa3, 0xe1, 0x18, 0xa6,
            0x9e, 0x8b,
        ];
        let iv = [
            0x83, 0xdb, 0xcc, 0x02, 0xd8, 0xcc, 0xb4, 0x0e, 0x46, 0x61, 0x91, 0xa1, 0x23, 0x79,
            0x1e, 0x0e,
        ];
        let data = [
            0x7a, 0x28, 0xb5, 0xba, 0x57, 0xc5, 0x36, 0x03, 0xb0, 0xb0, 0x7b, 0x56, 0xbb, 0xa7,
            0x52, 0xf7, 0x78, 0x4b, 0xf5, 0x06, 0xfa, 0x95, 0xed, 0xc3, 0x95, 0xf5, 0xcf, 0x6c,
            0x75, 0x14, 0xfe, 0x9d,
        ];
        let encryption = encrypt_aes(&data, &key, &iv, "aes-128-ctr".to_string()).unwrap();
        let expected_encryption = vec![
            0xd1, 0x72, 0xbf, 0x74, 0x3a, 0x67, 0x4d, 0xa9, 0xcd, 0xad, 0x04, 0x53, 0x4d, 0x56,
            0x92, 0x6e, 0xf8, 0x35, 0x85, 0x34, 0xd4, 0x58, 0xff, 0xfc, 0xcd, 0x4e, 0x6a, 0xd2,
            0xfb, 0xde, 0x47, 0x9c,
        ];
        assert_eq!(encryption, expected_encryption);
    }

    #[test]
    fn it_ctr_decrypts_data() {
        let key = [
            0xfa, 0xc1, 0x92, 0xce, 0xb5, 0xfd, 0x77, 0x29, 0x06, 0xbe, 0xa3, 0xe1, 0x18, 0xa6,
            0x9e, 0x8b,
        ];
        let iv = [
            0x83, 0xdb, 0xcc, 0x02, 0xd8, 0xcc, 0xb4, 0x0e, 0x46, 0x61, 0x91, 0xa1, 0x23, 0x79,
            0x1e, 0x0e,
        ];
        let data = [
            0x7a, 0x28, 0xb5, 0xba, 0x57, 0xc5, 0x36, 0x03, 0xb0, 0xb0, 0x7b, 0x56, 0xbb, 0xa7,
            0x52, 0xf7, 0x78, 0x4b, 0xf5, 0x06, 0xfa, 0x95, 0xed, 0xc3, 0x95, 0xf5, 0xcf, 0x6c,
            0x75, 0x14, 0xfe, 0x9d,
        ];
        let encryption = encrypt_aes(&data, &key, &iv, "aes-128-ctr".to_string()).unwrap();
        let decryption = decrypt_aes(&encryption, &key, &iv, "aes-128-ctr".to_string()).unwrap();
        assert_eq!(data.to_vec(), decryption);
    }
}
