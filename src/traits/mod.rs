use crate::common::address::Address;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

/// Defines methods for a Valid Address Type
pub trait ValidAddress<KeyType, AddressType> {
    /// Returns a String representation of the AddressType
    fn to_string(&self) -> String;
    /// Converts a string into an AddressType, wrapped in a `Result`
    fn from_string(string: &String) -> Result<AddressType, Box<Error>>;
    /// Converts a KeyType into an AddressType
    fn from_pubkey(pubkey: KeyType) -> AddressType;
    /// Converts a raw byte array into an Address Type
    fn from_bytes(bytes: &[u8; 20]) -> AddressType;
}

/// Performs a conversion on an enum
pub trait EnumConverter<OutputType> {
    /// Returns a representation of the Enum in the form of the OutputType
    fn to_output(&self) -> OutputType;
    /// Returns an Enum from an input of the Specified Type
    fn from_input(number: OutputType) -> Result<Self, Box<Error>>
    where
        Self: Sized;
}
/// Defines a BlockHeader
pub trait BlockHeader {
    /// Retrieves the Merkle Root from the Header
    fn get_merkle_root(&self) -> &Vec<u8>;
    /// Retrieves the TimeStamp from the Header
    fn get_time_stamp(&self) -> u64;
    /// Retrieves the Difficulty parameter from the Header
    fn get_difficulty(&self) -> f64;
    /// Retrieves the State Root from the Header
    fn get_state_root(&self) -> &Vec<u8>;
    /// Retrieves the previous hashes from the Header
    fn get_previous_hash(&self) -> Option<&Vec<Vec<u8>>>;
    /// Retrieves the nonce from the Header
    fn get_nonce(&self) -> Option<u64>;
    /// Retrieves the address of the miner
    fn get_miner(&self) -> Option<&Address>;
}
/// Defines behaviour for Transactions
pub trait Transaction<AddressType, SignatureType, RecoveryType> {
    /// Returns an `Option` containing the From Address
    fn get_from(&self) -> Option<AddressType>;
    /// Returns an `Option` containing the To Address
    fn get_to(&self) -> Option<AddressType>;
    /// Returns the Transaction amount
    fn get_amount(&self) -> u64;
    /// Returns an `Option` containing he transaction fee
    fn get_fee(&self) -> Option<u64>;
    /// Returns an `Option` containing the transaction nonce
    fn get_nonce(&self) -> Option<u32>;
    /// Returns an `Option` containing the transaction signature
    fn get_signature(&self) -> Option<SignatureType>;
    /// Returns an `Option` containing the secp256k1 recovery parameter
    fn get_recovery(&self) -> Option<RecoveryType>;
}
/// Transaction can be verified
pub trait VerifiableTransaction {
    /// Verifies a transaction
    fn verify(&self) -> Result<(), Box<Error>>;
}

/// Defines methods required for a peer database implementation
pub trait PeerDB<KeyType, PeerType> {
    /// An `Option` containing the Peer corresponding to the given key, `None` if not found
    fn get(&self, key: &KeyType) -> Option<PeerType>;
    /// Gets all peers from the DB
    fn get_all(&self) -> Option<Vec<PeerType>>;
    /// Gets multiple peers from the DB
    fn get_multiple(&self, limit: usize) -> Option<Vec<PeerType>>;
    /// Handler for an inbound peer connection
    fn inbound_connection(&mut self, key: KeyType, value: PeerType) -> Result<(), Box<Error>>;
    /// Handler for an outbound peer connection
    fn outbound_connection(&mut self, key: KeyType, value: PeerType) -> Result<(), Box<Error>>;
    /// Handler for a connection failure
    fn connection_failure(&mut self, key: &KeyType) -> Result<(), Box<Error>>;
    /// Handler for a disconnect event
    fn disconnect(&mut self, key: &KeyType);
    /// Puts multiple peers into the DB
    fn put_multiple(&mut self, values: Vec<(KeyType, PeerType)>) -> Result<(), Box<Error>>;
    /// Get peers that have been seen recently
    fn get_recent(&self, limit: usize) -> Option<Vec<PeerType>>;
    /// Gets list of seen peers
    fn get_seen(&self, limit: usize) -> Option<Vec<PeerType>>;
    /// Gets peer that is the oldest
    fn get_oldest(&self, limit: usize) -> Option<Vec<PeerType>>;
    /// Gets a random peer
    fn get_random(&self, limit: usize) -> Option<Vec<PeerType>>;
}
/// Converts an in memory representation to a type for insertion into a database
pub trait ToDBType<T> {
    /// Converts self to database type
    fn to_db_type(&self) -> T;
}
/// Encodes for network transmission or storage in a DB
pub trait Encode {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>>;
}
/// Decodes a serialized buffer into the desired type
pub trait Decode {
    fn decode(buffer: &[u8]) -> Result<Self, Box<Error>>
    where
        Self: Sized;
}
/// Converts items to/from the protobuf version
pub trait Proto {
    type ProtoType;
    fn to_proto(&self) -> Result<Self::ProtoType, Box<Error>>;
    fn from_proto(prototype: &Self::ProtoType) -> Result<Self, Box<Error>>
    where
        Self: Sized;
}
// Error wrapper
#[derive(Debug)]
pub struct Exception {
    details: String,
}

impl Exception {
    pub fn new(details: &str) -> Exception {
        Exception {
            details: details.to_string(),
        }
    }
}

impl Display for Exception {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.details)
    }
}

impl Error for Exception {
    fn description(&self) -> &str {
        &self.details
    }
}
