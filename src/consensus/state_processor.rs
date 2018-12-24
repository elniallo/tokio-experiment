use std::collections::HashMap;
use std::error::Error;

use common::Exception;
use common::address::Address;
use common::block::Block;
use common::header::Header;
use common::signed_tx::SignedTx;
use consensus::worldstate::WorldState;
use database::block_db::BlockDB;

use serialization::state::Account as ProtoAccount;

pub struct StateProcessor<'a, BlockDBType = BlockDB<'a>, WorldStateType = WorldState> {
    worldstate: WorldStateType,
    block_db: &'a BlockDBType
}

impl<'a> StateProcessor<'a> {
    fn new(block_db: &'a BlockDB<'a>, worldstate: WorldState) -> StateProcessor<BlockDB<'a>, WorldState> {
        StateProcessor {
            worldstate,
            block_db
        }
    }

    fn prune(&mut self) -> Result<(), Box<Error>> {
        return Err(Box::new(Exception::new("Not Implemented")))
    }

    fn regenerate(&mut self, height: u64) -> Result<(), Box<Error>> {
        return Err(Box::new(Exception::new("Not Implemented")))
    }

    fn generate_transition(blocks: Vec<&Block<SignedTx, Header>>) -> Result<HashMap<Address, ProtoAccount>, Box<Error>> {
        return Err(Box::new(Exception::new("Not Implemented")))
    }

    fn apply_transition(transition: HashMap<Address, ProtoAccount>, root: &[u8]) -> Result<(), Box<Error>> {
        return Err(Box::new(Exception::new("Not Implemented")))
    }
}