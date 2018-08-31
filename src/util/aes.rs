use std::error::Error;

use crypto::aes::{cbc_decryptor, cbc_encryptor, ctr};
use crypto::aes::KeySize::{KeySize128, KeySize192, KeySize256};
use crypto::aes::KeySize;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{BufferResult, RefReadBuffer, RefWriteBuffer};
use crypto::symmetriccipher::{Decryptor, Encryptor, SymmetricCipherError, SynchronousStreamCipher};

#[derive(Debug)]
pub enum AESError {
    Cipher(SymmetricCipherError),
    Support(String)
}

struct AESCTR{
    b: Box<SynchronousStreamCipher>
}

impl AESCTR {
    pub fn new(b: Box<SynchronousStreamCipher>) -> AESCTR {
        AESCTR {
            b
        }
    }
}

impl Deref for AESCTR {
    type Target = SynchronousStreamCipher;
    fn deref(&self) -> &Self::Target {&self.b}
}

impl Encryptor for AESCTR {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool) -> Result<BufferResult, SymmetricCipherError> {
        self.b.encrypt(input, output, eof)
    }
}

impl Decryptor for AESCTR {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool) -> Result<BufferResult, SymmetricCipherError> {
        self.b.decrypt(input, output, eof)
    }
}

pub fn encrypt_aes(data: &[u8], key: &[u8], iv: &[u8], extra: bool, cipher: String) -> Result<Vec<u8>, AESError> {
    let key_size;
    if key.len() == 16 {
        key_size = KeySize128;
    } else if key.len() == 24 {
        key_size = KeySize192;
    } else if key.len() == 32 {
        key_size = KeySize256;
    } else {
        return Err(AESError::Cipher(SymmetricCipherError::InvalidLength));
    }

    let mut length = data.len();
    let mut encryptor;

    if cipher.contains("cbc") {
        encryptor = cbc_encryptor(key_size, &key, &iv, PkcsPadding);
        if length % 16 == 0 && extra {
            length += 16;
        } else if length % 16 != 0 {
            length += 16 - length % 16;
        }
    } else if cipher.contains("ctr") {
        encryptor = Box::new(AESCTR::new(ctr(key_size, &key, &iv)));
    } else {
        return Err(AESError::Support("Unsupported AES mode".to_string()));
    }
    let mut ref_input = RefReadBuffer::new(&data);

    let mut out = vec![0u8; length];
    match encryptor.encrypt(&mut ref_input, &mut RefWriteBuffer::new(&mut out), true) {
        Ok(_) => {},
        Err(e) => return Err(AESError::Cipher(e))
    }
    Ok(out)
}

pub fn decrypt_aes(data: &[u8], key: &[u8], iv: &[u8], cipher: String, size: usize) -> Result<Vec<u8>, AESError> {
    let key_size;
    if key.len() == 16 {
        key_size = KeySize128;
    } else if key.len() == 24 {
        key_size = KeySize192;
    } else if key.len() == 32 {
        key_size = KeySize256;
    } else {
        return Err(AESError::Cipher(SymmetricCipherError::InvalidLength));
    }

    let mut decryptor;
    if cipher.contains("cbc") {
        decryptor = cbc_decryptor(key_size, &key, &iv, PkcsPadding);
    } else if cipher.contains("ctr") {
        decryptor = Box::new(AESCTR::new(ctr(key_size, &key, &iv)));
    } else {
        return Err(AESError::Support("Unsupported AES mode".to_string()));
    }
    let mut out = vec![0u8; size];
    let mut ref_input = RefReadBuffer::new(&data);
    match decryptor.decrypt(&mut ref_input, &mut RefWriteBuffer::new(&mut out), true) {
        Ok(_) => {},
        Err(e) => return Err(AESError::Cipher(e))
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use util::hash::hash;
    use rustc_serialize::hex::ToHex;

    #[test]
    fn it_cbc_encrypts_data_less_than_32_bytes() {
        let key = hash("password".as_bytes(), 32);
        let iv = [
            0xed, 0xe2, 0xa8, 0x5d, 0x3a, 0x82, 0x4d, 0x08,
            0xc7, 0xd6, 0xcf, 0xc5, 0xe9, 0x3e, 0x1d, 0x21];
        let data = "Data to be encrypted".as_bytes();
        let encryption = encrypt_aes(data, &key, &iv, true, "cbc".to_string()).unwrap();
        let expected_encryption = vec![
            0xe1, 0x47, 0xa9, 0x39, 0x0c, 0xe6, 0x4b, 0x55,
            0x93, 0x46, 0xc1, 0x7a, 0xde, 0xff, 0x03, 0xd6,
            0xd7, 0xd6, 0x24, 0x8f, 0xed, 0x98, 0x65, 0x59,
            0xe4, 0x45, 0x62, 0xc8, 0xfa, 0xc3, 0x70, 0xec];
        assert_eq!(encryption, expected_encryption);
    }

    #[test]
    fn it_cbc_encrypts_data_exactly_32_bytes_long() {
        let key = hash("password".as_bytes(), 32);
        let iv = [
            0x25, 0x52, 0x1f, 0xc0, 0x00, 0x69, 0x10, 0xa5,
            0x3f, 0x81, 0x9e, 0x24, 0xe5, 0xaa, 0x70, 0x09];
        let data = "aaaaaaaabbbbbbbbccccccccdddddddd".as_bytes();
        let encryption = encrypt_aes(data, &key, &iv, true, "cbc".to_string()).unwrap();
        let expected_encryption = vec![
            0x5d, 0x5f, 0xaf, 0xfd, 0x02, 0x45, 0xae, 0x91,
            0x4b, 0x6f, 0x24, 0x6e, 0x62, 0x5a, 0x93, 0xda,
            0x40, 0x34, 0xb1, 0x1f, 0xbc, 0xd8, 0x20, 0x05,
            0x55, 0x06, 0x77, 0x93, 0x0e, 0x88, 0x34, 0x86,
            0xcb, 0xb4, 0x56, 0x38, 0x09, 0xca, 0x80, 0x5a,
            0x30, 0x24, 0x3b, 0x02, 0x8f, 0x6e, 0x8e, 0x97];
        assert_eq!(encryption, expected_encryption);
    }

    #[test]
    fn it_cbc_encrypts_data_longer_than_32_bytes() {
        let key = hash("password".as_bytes(), 32);
        let iv = [0xad, 0xec, 0x18, 0x8e, 0xab, 0xc7, 0xcc, 0x8b,
            0xe1, 0x20, 0xa7, 0x41, 0x9f, 0xdb, 0xa9, 0x07];
        let data = "Really long data to be encrypted.  This data is so long it exceeds 32 bytes!".as_bytes();
        let encryption = encrypt_aes(data, &key, &iv, true, "cbc".to_string()).unwrap();
        let expected_encryption = vec![
            0xdd, 0xb3, 0xd2, 0xfb, 0xd0, 0x20, 0xa5, 0xd2,
            0x8d, 0x82, 0x91, 0xe2, 0x74, 0x50, 0xbc, 0x5d,
            0xbf, 0x0d, 0x28, 0x6a, 0x57, 0xfa, 0xcd, 0xcb,
            0xdb, 0xbe, 0xcf, 0x85, 0x5e, 0x29, 0x9c, 0xf8,
            0xce, 0x57, 0x79, 0x02, 0x12, 0xba, 0x8e, 0x48,
            0xdf, 0x12, 0xa6, 0x6b, 0xf0, 0xfb, 0xd0, 0xbc,
            0xb0, 0x8e, 0xb3, 0x2c, 0x7f, 0xb3, 0x37, 0x14,
            0x0f, 0x81, 0xb5, 0x8f, 0x56, 0x39, 0x25, 0x27,
            0x22, 0xe2, 0x2e, 0xb1, 0xd8, 0x60, 0x46, 0x92,
            0xd5, 0xd5, 0x43, 0x0d, 0xa7, 0xf0, 0x44, 0x91];
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
        let encryption = encrypt_aes(&data, &key[..], &iv, true, "cbc".to_string()).unwrap();
        let decryption = decrypt_aes(&encryption, &key, &iv, "cbc".to_string(), data.len()).unwrap();
        assert_eq!(data.to_vec(), &decryption[..]);
    }

    #[test]
    fn it_ctr_encrypts_data() {
        let key = [
            0xfa, 0xc1, 0x92, 0xce, 0xb5, 0xfd, 0x77, 0x29,
            0x06, 0xbe, 0xa3, 0xe1, 0x18, 0xa6, 0x9e, 0x8b];
        let iv = [
            0x83, 0xdb, 0xcc, 0x02, 0xd8, 0xcc, 0xb4, 0x0e,
            0x46, 0x61, 0x91, 0xa1, 0x23, 0x79, 0x1e, 0x0e];
        let data = [
            0x7a, 0x28, 0xb5, 0xba, 0x57, 0xc5, 0x36, 0x03,
            0xb0, 0xb0, 0x7b, 0x56, 0xbb, 0xa7, 0x52, 0xf7,
            0x78, 0x4b, 0xf5, 0x06, 0xfa, 0x95, 0xed, 0xc3,
            0x95, 0xf5, 0xcf, 0x6c, 0x75, 0x14, 0xfe, 0x9d];
        let encryption = encrypt_aes(&data, &key, &iv, true, "ctr".to_string()).unwrap();
        let expected_encryption = vec![
            0xd1, 0x72, 0xbf, 0x74, 0x3a, 0x67, 0x4d, 0xa9,
            0xcd, 0xad, 0x04, 0x53, 0x4d, 0x56, 0x92, 0x6e,
            0xf8, 0x35, 0x85, 0x34, 0xd4, 0x58, 0xff, 0xfc,
            0xcd, 0x4e, 0x6a, 0xd2, 0xfb, 0xde, 0x47, 0x9c];
        assert_eq!(encryption, expected_encryption);
    }

    #[test]
    fn it_ctr_decrypts_data() {
        let key = [
            0xfa, 0xc1, 0x92, 0xce, 0xb5, 0xfd, 0x77, 0x29,
            0x06, 0xbe, 0xa3, 0xe1, 0x18, 0xa6, 0x9e, 0x8b];
        let iv = [
            0x83, 0xdb, 0xcc, 0x02, 0xd8, 0xcc, 0xb4, 0x0e,
            0x46, 0x61, 0x91, 0xa1, 0x23, 0x79, 0x1e, 0x0e];
        let data = [
            0x7a, 0x28, 0xb5, 0xba, 0x57, 0xc5, 0x36, 0x03,
            0xb0, 0xb0, 0x7b, 0x56, 0xbb, 0xa7, 0x52, 0xf7,
            0x78, 0x4b, 0xf5, 0x06, 0xfa, 0x95, 0xed, 0xc3,
            0x95, 0xf5, 0xcf, 0x6c, 0x75, 0x14, 0xfe, 0x9d];
        let encryption = encrypt_aes(&data, &key, &iv, true, "ctr".to_string()).unwrap();
        let decryption = decrypt_aes(&encryption, &key, &iv, "ctr".to_string(), 32).unwrap();
        assert_eq!(data.to_vec(), decryption);
    }
}