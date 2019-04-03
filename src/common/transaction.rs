use std::error::Error;

use crate::common::address::Address;
use crate::traits::ValidAddress;
use crate::util::hash::hash;

use secp256k1::{Error as SecpError, Message, RecoverableSignature, RecoveryId, Secp256k1};

pub fn verify_tx(
    encoding: Vec<u8>,
    signer: Address,
    signature: RecoverableSignature,
) -> Result<(), Box<Error>> {
    let message = Message::from_slice(&hash(&encoding, 32))?;
    let secp = Secp256k1::verification_only();
    let pubkey = secp.recover(&message, &signature)?;
    let address = Address::from_pubkey(pubkey);
    if address != signer {
        return Err(Box::new(SecpError::IncorrectSignature));
    }
    let standard_signature = signature.to_standard(&secp);
    Ok(secp.verify(&message, &standard_signature, &pubkey)?)
}
