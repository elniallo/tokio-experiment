use crate::common::header::{BlockHeader, Header};
use crate::common::meta::Meta;
use crate::consensus::difficulty_adjuster;
use crate::consensus::state_processor::StateProcessor;
use crate::consensus::BlockForkChoice;
use crate::traits::Exception;
use crate::util::hash::hash_cryptonight;
use std::cmp::Ordering;
use std::error::Error;

impl BlockForkChoice for Meta {
    fn fork_choice(&self, other: &Meta) -> Ordering {
        self.total_work.partial_cmp(&other.total_work).unwrap()
    }
}
pub struct Consensus<'a> {
    state_processor: StateProcessor<'a>,
}

impl<'a> Consensus<'a> {
    pub fn new(state_processor: StateProcessor<'a>) -> Result<Self, Box<Error>> {
        Ok(Self { state_processor })
    }
}

impl<'a> HeaderProcessor<Header> for Consensus<'a> {
    fn process_header(&self, header: &Header) -> Result<(), Box<Error>> {
        let mut prehash = header.prehash()?;
        prehash.append(&mut header.nonce.to_le_bytes().to_vec());
        if difficulty_adjuster::acceptable(
            hash_cryptonight(&prehash, prehash.len()),
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

impl<'a> ForkChoice<Meta> for Consensus<'a> {
    fn fork_choice(&self, tip: &Meta, new_block: &Meta) -> bool {
        match new_block.fork_choice(tip) {
            Ordering::Greater => true,
            _ => false,
        }
    }
}

pub trait ForkChoice<BlockType>
where
    BlockType: BlockForkChoice,
{
    fn fork_choice(&self, tip: &BlockType, new_block: &BlockType) -> bool;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::address::{Address, ValidAddress};
    use crate::consensus::worldstate::WorldState;
    use crate::database::block_db::BlockDB;
    use crate::database::dbkeys::DBKeys;
    use crate::database::state_db::StateDB;
    use crate::traits::Encode;
    use crate::util::hash::hash;

    use rust_base58::{FromBase58, ToBase58};
    use std::path::PathBuf;
    #[test]
    fn it_assigns_nonce_bytes_correctly() {
        let nonce: u64 = 9991999136134178034;
        let le_nonce = nonce.to_le_bytes();
        let expected_bytes = [242, 164, 73, 65, 70, 182, 170, 138];
        assert_eq!(le_nonce, expected_bytes);
    }

    #[test]
    fn it_correctly_checks_cn_hash_of_header() {
        //Set up consensus
        let state_path = PathBuf::from("state");
        let block_path = PathBuf::from("blocks");
        let file_path = PathBuf::from("blockfile");
        let keys = DBKeys::default();
        let mut block_db = BlockDB::new(block_path, file_path, &keys, None).unwrap();
        let state_db = StateDB::new(state_path, None).unwrap();
        let world_state = WorldState::new(state_db, 20).unwrap();
        let state_processor = StateProcessor::new(&mut block_db, world_state);
        let consensus = Consensus::new(state_processor).unwrap();

        // Set up header - Block Number 864589
        let merkle_root = "xyw95Bsby3s4mt6f4FmFDnFVpQBAeJxBFNGzu2cX4dM"
            .from_base58()
            .unwrap();
        let state_root = "2TQHHSG8daQxYMCisMywUppz7a3YXb83VKzpMsZwQgLi"
            .from_base58()
            .unwrap();
        let time_stamp = 1553674416492;
        let difficulty = 0.00000004430078803796533 as f64;
        let nonce = 12610086967913974370;
        let miner = Address::from_string(&"H2zF9ZrneniGejpGSs7dpafiU7vJACFTW".to_string()).unwrap();
        let previous_hash = vec!["3u3jNwUbeMPiRBMCy2hHLRtGmiYQJmxMwyv1aUGV7AMN"
            .from_base58()
            .unwrap()];

        let header = Header::new(
            merkle_root.clone(),
            time_stamp,
            difficulty,
            state_root.clone(),
            previous_hash.clone(),
            nonce,
            miner,
        );
        let header_hash = hash(&header.encode().unwrap(), 32);
        let res = consensus.process_header(&header);
        assert!(res.is_ok());
    }
}
