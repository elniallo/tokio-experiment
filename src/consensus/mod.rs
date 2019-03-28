pub mod consensus;
pub mod difficulty_adjuster;
pub mod legacy_trie;
pub mod state_processor;
pub mod tree_node;
pub mod worldstate;

use std::cmp::Ordering;
pub trait BlockForkChoice {
    fn fork_choice(&self, other: &Self) -> Ordering;
}
