pub mod address;
pub mod genesis_tx;
pub mod genesis_signed_tx;
pub mod signed_tx;
pub mod tx;
pub mod header;
pub mod genesis_header;

pub trait Encode {
    fn encode(&self) -> Result<Vec<u8>, String>;
}