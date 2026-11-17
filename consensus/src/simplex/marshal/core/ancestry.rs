//! Round bounds for parent fetches made through simplex marshal.

use crate::{Block, ancestry::BlockProvider, types::Round};

/// A simplex marshal source of parent fetches whose requests consensus can retire.
///
/// A parent request is bounded by a round. Once a block finalized at that round or a later one is
/// processed, the parent is either processed or its child can never be finalized, so the provider
/// may stop fetching it.
pub trait RoundBounded: Clone + Send + Sync + 'static {
    /// The block type the providers walk.
    type Block: Block;

    /// The provider that serves parent requests under a chosen bound.
    type Provider: BlockProvider<Block = Self::Block> + Clone;

    /// Returns a provider whose parent requests `bound` retires.
    ///
    /// `bound` is the round consensus assigned to the starting block or to a descendant of it,
    /// or the round of the consensus request the caller serves.
    fn bounded(&self, bound: Round) -> Self::Provider;

    /// Returns a provider whose parent requests nothing retires.
    ///
    /// Use only when every block the caller walks from was checked against its own parent, as in
    /// certified or finalized ancestry. An unchecked child can name any height, so an unbounded
    /// request for its parent may never end.
    fn unbounded(&self) -> Self::Provider;
}
