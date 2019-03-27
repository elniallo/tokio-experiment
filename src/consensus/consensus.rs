use crate::common::header::{BlockHeader, Header};
use crate::consensus::difficulty_adjuster;
use crate::consensus::state_processor::StateProcessor;
use crate::traits::Exception;
use crate::util::hash::hash_cryptonight;
use std::error::Error;
use std::path::PathBuf;
pub struct Consensus<'a> {
    state_processor: StateProcessor<'a>,
}

impl<'a> Consensus<'a> {
    fn new(state_processor: StateProcessor<'a>) -> Result<Self, Box<Error>> {
        Ok(Self { state_processor })
    }
}

impl<'a> HeaderProcessor<Header> for Consensus<'a> {
    fn process_header(&self, header: &Header) -> Result<(), Box<Error>> {
        let mut prehash = header.prehash()?;
        prehash.append(&mut header.nonce.to_le_bytes().to_vec());
        if difficulty_adjuster::acceptable(
            hash_cryptonight(&prehash, 32),
            difficulty_adjuster::get_target(header.difficulty, 32)?,
        )? {
            Ok(())
        } else {
            Err(Box::new(Exception::new(
                "Block rejected, hash does not match difficulty",
            )))
        }
    }
}

pub trait ForkChoice<BlockType> {
    fn fork_choice(&self, tip: &BlockType, new_block_work: &BlockType) -> bool;
}

pub trait HeaderProcessor<HeaderType>
where
    HeaderType: BlockHeader,
{
    fn process_header(&self, header: &HeaderType) -> Result<(), Box<Error>>;
}

pub trait StateProcessorTrait<TxType> {
    fn process_txs(&self, txs: &[TxType]) -> Result<(), Box<Error>>;
}

pub trait TxProcessor<TxType> {
    fn check_signatures(&self, txs: &[TxType]) -> Result<(), Box<Error>>;
}
