use crypto::aes::{cbc_decryptor, cbc_encryptor};
use crypto::aes::KeySize::{KeySize256, KeySize128, KeySize192};
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::symmetriccipher::SymmetricCipherError;

pub fn encrypt_aes_cbc(data: &[u8], key: &[u8], iv: &[u8], extra: bool) -> Result<Vec<u8>, SymmetricCipherError> {
    let key_size;
    if key.len() == 32 {
        key_size = KeySize256;
    } else if key.len() == 16 {
        key_size = KeySize128;
    } else if key.len() == 24 {
        key_size = KeySize192;
    } else {
        return Err(SymmetricCipherError::InvalidLength)
    }
    let mut encryptor = cbc_encryptor(key_size, &key, &iv, PkcsPadding);
    let mut ref_input = RefReadBuffer::new(&data);
    let mut length = data.len();
    if length % 16 == 0 && extra {
        length += 16;
    } else if length % 16 != 0 {
        length += 16 - length % 16;
    }
    let mut out = vec![0u8; length];
    encryptor.encrypt(&mut ref_input, &mut RefWriteBuffer::new(&mut out), true)?;
    Ok(out)
}

pub fn decrypt_aes_cbc(data: &[u8], key: &[u8], iv: &[u8], size: usize, extra: bool) -> Result<Vec<u8>, SymmetricCipherError> {
    let key_size;
    if key.len() == 32 {
        key_size = KeySize256;
    } else if key.len() == 16 {
        key_size = KeySize128;
    } else if key.len() == 24 {
        key_size = KeySize192;
    } else {
        return Err(SymmetricCipherError::InvalidLength)
    }

    let mut decryptor = cbc_decryptor(key_size, &key, &iv, PkcsPadding);
    let mut out = vec![0u8; size];
    let mut ref_input = RefReadBuffer::new(&data);
    decryptor.decrypt(&mut ref_input, &mut RefWriteBuffer::new(&mut out), true)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use util::hash::hash;

    #[test]
    fn it_encrypts_data_less_than_32_bytes() {
        let key = hash("password".as_bytes(), 32);
        let iv = [0xed, 0xe2, 0xa8, 0x5d, 0x3a, 0x82, 0x4d, 0x08,
            0xc7, 0xd6, 0xcf, 0xc5, 0xe9, 0x3e, 0x1d, 0x21];
        let data = "Data to be encrypted".as_bytes();
        let encryption = encrypt_aes_cbc(data, &key[..], &iv, true).unwrap();
        let expected_encryption = vec![
            0xe1, 0x47, 0xa9, 0x39, 0x0c, 0xe6, 0x4b, 0x55,
            0x93, 0x46, 0xc1, 0x7a, 0xde, 0xff, 0x03, 0xd6,
            0xd7, 0xd6, 0x24, 0x8f, 0xed, 0x98, 0x65, 0x59,
            0xe4, 0x45, 0x62, 0xc8, 0xfa, 0xc3, 0x70, 0xec];
        assert_eq!(encryption, expected_encryption);
    }

    #[test]
    fn it_encrypts_data_exactly_32_bytes_long() {
        let key = hash("password".as_bytes(), 32);
        let iv = [0x25, 0x52, 0x1f, 0xc0, 0x00, 0x69, 0x10, 0xa5,
            0x3f, 0x81, 0x9e, 0x24, 0xe5, 0xaa, 0x70, 0x09];
        let data = "aaaaaaaabbbbbbbbccccccccdddddddd".as_bytes();
        let encryption = encrypt_aes_cbc(data, &key[..], &iv, true).unwrap();
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
    fn it_encrypts_data_longer_than_32_bytes() {
        let key = hash("password".as_bytes(), 32);
        let iv = [0xad, 0xec, 0x18, 0x8e, 0xab, 0xc7, 0xcc, 0x8b,
            0xe1, 0x20, 0xa7, 0x41, 0x9f, 0xdb, 0xa9, 0x07];
        let data = "Really long data to be encrypted.  This data is so long it exceeds 32 bytes!".as_bytes();
        let encryption = encrypt_aes_cbc(data, &key[..], &iv, true).unwrap();
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
    fn it_decrypts_encrypted_data() {
        let mut password = [0u8; 32];
        thread_rng().fill(&mut password);
        let key = hash(&password, 32);
        let mut iv = [0u8; 16];
        thread_rng().fill(&mut iv);
        let mut data = [0u8; 256];
        thread_rng().fill(&mut data);
        let encryption = encrypt_aes_cbc(&data, &key[..], &iv, true).unwrap();
        let decryption = decrypt_aes_cbc(&encryption, &key[..], &iv, data.len(), true).unwrap();
        assert_eq!(data.to_vec(), &decryption[..]);
    }
}