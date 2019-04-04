use std::error::Error;

use crate::common::address::Address;
use crate::serialization::tx::ExodusTx as ProtoExodusTx;
use crate::traits::{Decode, Encode, Proto, Transaction, VerifiableTransaction};

use protobuf::Message as ProtoMessage;
use secp256k1::{RecoverableSignature, RecoveryId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExodusTx {
    to: Address,
    amount: u64,
    nonce: u32,
}

impl Transaction<Address, RecoverableSignature, RecoveryId> for ExodusTx {
    fn get_from(&self) -> Option<Address> {
        None
    }
    fn get_to(&self) -> Option<Address> {
        Some(self.to)
    }
    fn get_amount(&self) -> u64 {
        self.amount
    }
    fn get_fee(&self) -> Option<u64> {
        None
    }
    fn get_nonce(&self) -> Option<u32> {
        Some(self.nonce)
    }
    fn get_signature(&self) -> Option<RecoverableSignature> {
        None
    }
    fn get_recovery(&self) -> Option<RecoveryId> {
        None
    }
}

impl ExodusTx {
    pub fn new(to: Address, amount: u64, nonce: u32) -> Self {
        ExodusTx { to, amount, nonce }
    }
}

impl Proto for ExodusTx {
    type ProtoType = ProtoExodusTx;
    fn to_proto(&self) -> Result<Self::ProtoType, Box<Error>> {
        let mut proto_exodus_tx = ProtoExodusTx::new();
        proto_exodus_tx.set_to(self.to.to_vec());
        proto_exodus_tx.set_amount(self.amount);
        proto_exodus_tx.set_nonce(self.nonce);
        Ok(proto_exodus_tx)
    }

    fn from_proto(_prototype: &Self::ProtoType) -> Result<Self, Box<Error>> {
        unimplemented!()
    }
}

impl Encode for ExodusTx {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        let proto_exodus_tx = self.to_proto()?;
        Ok(proto_exodus_tx.write_to_bytes()?)
    }
}

impl Decode for ExodusTx {
    fn decode(buffer: &[u8]) -> Result<Self, Box<Error>> {
        let mut proto_exodus_tx = ProtoExodusTx::new();
        proto_exodus_tx.merge_from_bytes(&buffer)?;
        let mut to = [0u8; 20];
        to.clone_from_slice(&proto_exodus_tx.to);
        Ok(Self::new(to, proto_exodus_tx.amount, proto_exodus_tx.nonce))
    }
}

impl VerifiableTransaction for ExodusTx {
    fn verify(&self) -> Result<(), Box<Error>> {
        Ok(())
    }
}
