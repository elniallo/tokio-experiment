use common::Encode;
use common::address::{Address, ValidAddress};
use util::hash::hash;
use serialization;

use protobuf::{Message as ProtoMessage};
use secp256k1::{Message, RecoverableSignature, RecoveryId, Secp256k1, Error};

pub struct Tx {
    from: Option<Address>,
    to: Option<Address>,
    amount: u64,
    fee: Option<u64>,
    nonce: Option<u32>,
    signature: Option<RecoverableSignature>,
    recovery: Option<RecoveryId>,
}

pub trait Quantifiable {
    fn get_amount(&self) -> u64;
}

pub trait Countable {
    fn get_from(&self) -> Address;
    fn get_fee(&self) -> u64;
    fn get_nonce(&self) -> u32;
}

pub trait Sendable {
    fn get_to(&self) -> Address;
}

pub trait Signed {
    fn get_signature(&self) -> RecoverableSignature;
    fn get_recovery(&self) -> RecoveryId;
}
pub trait Valid {
    fn verify(&self) -> Result<bool, Error>;
}

impl Tx {
    pub fn new(from: Option<Address>, 
        to: Option<Address>, 
        amount: u64, 
        fee: Option<u64>, 
        nonce: Option<u32>, 
        signature: Option<RecoverableSignature>, 
        recovery: Option<RecoveryId>) -> Tx {
        Tx {
            from,
            to,
            amount,
            fee,
            nonce,
            signature,
            recovery
        }
    }

    pub fn decode(proto_tx: serialization::tx::Tx) -> Tx {
        let mut from: Address = [0; 20];
        from.clone_from_slice(&proto_tx.from);
        let mut to: Address = [0; 20];
        to.clone_from_slice(&proto_tx.to);
        let amount = proto_tx.amount;
        let fee = proto_tx.fee;
        let nonce = proto_tx.nonce;
        Tx::new(Some(from), Some(to), amount, Some(fee), Some(nonce), None, None)
    }

    pub fn verify(encoding: Vec<u8>, sender: Address, signature: RecoverableSignature) -> Result<bool, Error> {
            let message = Message::from_slice(&hash(&encoding[..], 32))?;
            let secp = Secp256k1::verification_only();
            let pubkey = secp.recover(&message, &signature)?;
            let address = Address::from_pubkey(pubkey);
            if address != sender {
                return Err(Error::InvalidSignature);
            }
            let standard_signature = signature.to_standard(&secp);
            match secp.verify(&message, &standard_signature, &pubkey) {
                Ok(_) => return Ok(true),
                Err(e) => return Err(e)
            }
        }

    pub fn equals(&self, other_tx: Tx) -> bool {
        if self.from != other_tx.from {
            false
        } else if self.to != other_tx.to {
            false
        } else if self.amount != other_tx.amount {
            false
        } else if self.fee != other_tx.fee {
            false
        } else if self.nonce != other_tx.nonce {
            false
        } else {
            true
        }
    }
}

impl Encode for Tx {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let from: Address;
        match self.from {
            Some(addr) => from = addr,
            None => return Err("Tried to encode a Tx without a from address".to_string())
        }
        let to: Address;
        match self.to {
            Some(addr) => to = addr,
            None => return Err("Tried to encode a Tx without a to address".to_string())
        }

        let fee: u64;
        match self.fee {
            Some(txfee) => fee = txfee,
            None => return Err("Tried to encode a Tx without a tx fee".to_string())
        }

        let nonce: u32;
        match self.nonce {
            Some(txnonce) => nonce = txnonce,
            None => return Err("Tried to encode a Tx without a nonce".to_string())
        }


        let mut itx = serialization::tx::Tx::new();
        itx.set_from(from.to_vec());
        itx.set_to(to.to_vec());
        itx.set_amount(self.amount);
        itx.set_fee(fee);
        itx.set_nonce(nonce);
        let encoding = itx.write_to_bytes();
        match encoding {
            Ok(data) => return Ok(data),
            Err(e) => return Err(e.to_string())
        }
    }
}

impl Quantifiable for Tx {
    fn get_amount(&self) -> u64 {
        self.amount
    }
}

impl Sendable for Tx {
    fn get_to(&self) -> Address {
        self.to.unwrap()
    }
}

impl Countable for Tx {
    fn get_from(&self) -> Address {
        self.from.unwrap()
    }

    fn get_fee(&self) -> u64 {
        self.fee.unwrap()
    }

    fn get_nonce(&self) -> u32 {
        self.nonce.unwrap()
    }
}

impl Signed for Tx {
    fn get_signature(&self) -> RecoverableSignature {
        self.signature.unwrap()
    }
    fn get_recovery(&self) -> RecoveryId {
        self.recovery.unwrap()
    }
}

impl Valid for Tx 
    where Tx: Encode + Countable {
    fn verify(&self) -> Result<bool, Error> {
        let encoding = self.encode().unwrap();
        let sender = self.get_from();
        let signature = self.get_signature();
        Tx::verify(encoding, sender, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_makes_a_transaction() {
        let from = [
            230, 104, 95, 253, 219, 134, 92, 215, 230, 126, 105, 213, 18, 95, 30, 166, 128, 229,
            233, 114,
        ];
        let to = [
            87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149, 135, 84, 9, 224, 232,
            102,
        ];
        let amount = 123456789;
        let fee = 1;
        let nonce = 3;
        let tx = Tx::new(Some(from), Some(to), amount, Some(fee), Some(nonce), None, None);
        assert_eq!(tx.from.unwrap(), from);
        assert_eq!(tx.to.unwrap(), to);
        assert_eq!(tx.amount, amount);
        assert_eq!(tx.fee.unwrap(), fee);
        assert_eq!(tx.nonce.unwrap(), nonce);
        assert_eq!(tx.signature, None);
        assert_eq!(tx.recovery, None);
    }

    #[test]
    fn it_makes_a_transaction_from_itx() {
        let from = [
            230, 104, 95, 253, 219, 134, 92, 215, 230, 126, 105, 213, 18, 95, 30, 166, 128, 229,
            233, 114,
        ];
        let to = [
            87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149, 135, 84, 9, 224, 232,
            102,
        ];
        let amount = 123456789;
        let fee = 1;
        let nonce = 3;
        let mut itx = serialization::tx::Tx::new();
        itx.set_from(from.to_vec());
        itx.set_to(to.to_vec());
        itx.set_amount(amount);
        itx.set_fee(fee);
        itx.set_nonce(nonce);

        let tx = Tx::decode(itx);
        assert_eq!(tx.from.unwrap(), from);
        assert_eq!(tx.to.unwrap(), to);
        assert_eq!(tx.amount, amount);
        assert_eq!(tx.fee.unwrap(), fee);
        assert_eq!(tx.nonce.unwrap(), nonce);
    }

    #[test]
    fn it_encodes_like_javascript_for_non_zero() {
        let from = [
            230, 104, 95, 253, 219, 134, 92, 215, 230, 126, 105, 213, 18, 95, 30, 166, 128, 229,
            233, 114,
        ];
        let to = [
            87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149, 135, 84, 9, 224, 232,
            102,
        ];
        let amount = 123456789;
        let fee = 1;
        let nonce = 3;
        let tx = Tx::new(Some(from), Some(to), amount, Some(fee), Some(nonce), None, None);
        let encoding = tx.encode().unwrap();
        let expected_encoding = vec![
            10, 20, 230, 104, 95, 253, 219, 134, 92, 215, 230, 126, 105, 213, 18, 95, 30, 166, 128,
            229, 233, 114, 18, 20, 87, 217, 90, 40, 10, 141, 125, 74, 177, 128, 155, 18, 148, 149,
            135, 84, 9, 224, 232, 102, 24, 149, 154, 239, 58, 32, 1, 40, 3,
        ];
        assert_eq!(encoding, expected_encoding);
    }

    #[test]
    fn it_encodes_like_javascript_for_zero() {
        let from: Address =
            Address::from_string(&"H2rCdhQ4fhGk5qX9AwzxA61zhoUKCDVQC".to_string()).unwrap();
        let to: Address =
            Address::from_string(&"Hj3eZJpesfCjrMZfmKXpep6rVWS56Qaz".to_string()).unwrap();
        let amount = 0;
        let fee = 0;
        let nonce = 0;
        let tx = Tx::new(Some(from), Some(to), amount, Some(fee), Some(nonce), None, None);
        let encoding = tx.encode().unwrap();
        let expected_encoding = vec![
            10, 20, 132, 170, 245, 157, 55, 19, 7, 190, 193, 159, 54, 150, 44, 139, 78, 36, 165,
            149, 140, 187, 18, 20, 52, 8, 198, 113, 205, 252, 248, 236, 75, 130, 108, 209, 4, 214,
            46, 51, 111, 17, 216, 146, 24, 0, 32, 0, 40, 0,
        ];
        assert_eq!(encoding, expected_encoding);
    }
}
