use crate::util::hash::hash;
use std::error::Error;
use std::result::Result;

use crate::traits::{Exception, ValidAddress};

use rust_base58::{FromBase58, ToBase58};
use secp256k1::PublicKey;

fn check_sum(arr: &[u8; 20]) -> String {
    let arr_hash = hash(arr, 32);
    let string = arr_hash.to_base58();
    string[0..4].to_string()
}

pub type AddressResult<T> = Result<T, Box<Error>>;

pub type Address = [u8; 20];

impl ValidAddress<PublicKey, Address> for Address {
    fn to_string(&self) -> String {
        let base58_address = self.to_base58();
        "H".to_string() + &base58_address + &check_sum(&self)
    }

    fn from_string(string: &String) -> AddressResult<Address> {
        if string.len() < 5 {
            return Err(Box::new(Exception::new("Address is too short")));
        }
        if !string.starts_with("H") {
            return Err(Box::new(Exception::new("Address must begin with an H")));
        }
        // let mut string_iter = string.chars();
        // let first_char = string_iter.next();
        // match first_char {
        //     Some(letter) => {
        //         if letter != 'H' {
        //             return Err(Box::new(Exception::new("Address must begin with an H")));
        //         }
        //     }
        //     None => return Err(Box::new(Exception::new("No data was supplied"))),
        // }

        //let address_and_checksum = &string[1..string.len()];
        let (address, checksum) = string.split_at(string.len() - 4);

        let decoded_bytes;
        if let Ok(b) = address[1..address.len()].from_base58() {
            decoded_bytes = b;
        } else {
            return Err(Box::new(Exception::new("Failed to decode address string")));
        }
        if decoded_bytes.len() != 20 {
            return Err(Box::new(Exception::new(&format!(
                "{} is {} bytes long",
                address,
                decoded_bytes.len()
            ))));
        }

        let mut address_bytes: [u8; 20] = [0; 20];
        address_bytes.copy_from_slice(&decoded_bytes[0..20]);

        let checksum_bytes = check_sum(&address_bytes);
        if &checksum_bytes != checksum {
            return Err(Box::new(Exception::new(&format!(
                "{} did not match {}",
                checksum,
                checksum_bytes.to_string()
            ))));
        }

        Ok(address_bytes)
    }

    fn from_pubkey(pubkey: PublicKey) -> Address {
        let pub_key_hash = hash(&pubkey.serialize(), 32);
        let mut addr = [0; 20];
        for i in 12..32 {
            addr[i - 12] = pub_key_hash[i];
        }
        addr
    }
    fn from_bytes(bytes: &[u8; 20]) -> Address {
        let mut addr = [0; 20];
        for i in 0..20 {
            addr[i] = bytes[i]
        }
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;
    #[test]
    fn it_makes_an_address_string() {
        let address: Address = [
            11, 216, 55, 107, 140, 247, 121, 126, 90, 115, 233, 197, 108, 128, 64, 46, 135, 184,
            87, 180,
        ];
        let expected_address_string = "HAa7S1QqVRMw13VdUnrSkn5w6oNK891W";
        assert_eq!(expected_address_string, address.to_string());
    }

    #[test]
    fn it_makes_an_address_from_string() {
        let address_string = "HAa7S1QqVRMw13VdUnrSkn5w6oNK891W".to_string();
        let address: Address = Address::from_string(&address_string).unwrap();
        assert_eq!(address.to_string(), address_string);
    }

    #[test]
    fn it_makes_an_address_from_pubkey() {
        let pubkey_bytes = [
            2, 170, 74, 64, 253, 208, 212, 90, 203, 135, 144, 142, 65, 16, 248, 16, 212, 186, 252,
            206, 57, 137, 163, 162, 40, 81, 138, 12, 183, 237, 70, 48, 136,
        ];
        let secp = Secp256k1::without_caps();
        let pubkey = PublicKey::from_slice(&secp, &pubkey_bytes).unwrap();
        let address_string = "HM8NwBmP6FKyhiBaxQMWcZiAoZqQFk8a".to_string();
        let address_from_string = Address::from_string(&address_string).unwrap();
        let address_from_pubkey = Address::from_pubkey(pubkey);
        assert_eq!(address_from_string, address_from_pubkey);
    }

    #[test]
    fn it_checks_checksum() {
        let address_string = "HAa7S1QqVRMw13VdUnrSkn5w6oNK36MM".to_string();
        let address = Address::from_string(&address_string);
        match address {
            Ok(_addr) => panic!("{} is not a valid address string!", address_string),
            Err(_) => {}
        }
    }

    #[test]
    fn it_checks_equality() {
        let address_string = "HAa7S1QqVRMw13VdUnrSkn5w6oNK891W".to_string();
        let address: Address = Address::from_string(&address_string).unwrap();

        let other_address: [u8; 20] = [
            11, 216, 55, 107, 140, 247, 121, 126, 90, 115, 233, 197, 108, 128, 64, 46, 135, 184,
            87, 180,
        ];
        assert_eq!(address, other_address);
    }

    #[test]
    fn it_fails_on_malformed_addresses() {
        let empty_string = "".to_string();
        let empty_address = Address::from_string(&empty_string);
        assert!(empty_address.is_err());
        let h_string = "H".to_string();
        let h_address = Address::from_string(&h_string);
        assert!(h_address.is_err());
        let h_plus_checksum = "H1234".to_string();
        let h_plus_checksum_address = Address::from_string(&h_plus_checksum);
        assert!(h_plus_checksum_address.is_err());
        let short_address = "H1223425fjsf".to_string();
        let short_address_address = Address::from_string(&short_address);
        assert!(short_address_address.is_err());
        let address_string = "Not a valid address string".to_string();
        let address = Address::from_string(&address_string);
        assert!(address.is_err());
    }
}
