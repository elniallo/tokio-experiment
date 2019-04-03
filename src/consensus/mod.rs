pub mod consensus;
pub mod difficulty_adjuster;
pub mod legacy_trie;
pub mod state_processor;
pub mod tree_node;
pub mod worldstate;

use std::cmp::Ordering;
/// # BlockForkChoice Trait
/// Acts as a comparator between two blocks to give precedence to one over the other in the event of a forking event
/// ___
/// ## Required Methods
/// ### Fork Choice
/// ```
/// fn fork_choice(&self, other: &Self) -> std::cmp::Ordering
/// ```
/// #### Arguments
/// - `other` - some other block to compare to
///
/// #### Returns
///  An ordering between self and other
/// ___
pub trait BlockForkChoice {
    fn fork_choice(&self, other: &Self) -> Ordering;
}
