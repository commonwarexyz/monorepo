//! Ordered delivery of finalized blocks.
//!
//! # Architecture
//!
//! The core of the module is the unified [`core::Actor`]. It marshals finalized blocks into order by:
//!
//! - Receiving uncertified blocks from a broadcast mechanism
//! - Receiving notarizations and finalizations from consensus
//! - Reconstructing a total order of finalized blocks
//! - Providing a backfill mechanism for missing blocks
//!
//! The actor interacts with several main components:
//! - [`crate::Reporter`]: Receives ordered, finalized blocks at-least-once
//! - [`crate::simplex`]: Provides consensus messages
//! - Application: Provides verified blocks
//! - [`commonware_broadcast::buffered`]: Provides uncertified blocks (standard mode)
//! - [`coding::shards::Engine`]: Provides erasure-coded shards (coding mode)
//! - [`resolver`]: Provides a backfill mechanism for missing blocks
//!
//! # Design
//!
//! ## Delivery
//!
//! The actor will deliver a block to the reporter at-least-once. The reporter should be prepared to
//! handle duplicate deliveries. However the blocks will be in order.
//!
//! ## Finalization
//!
//! The actor uses a view-based model to track the state of the chain. Each view corresponds
//! to a potential block in the chain. The actor will only finalize a block (and its ancestors)
//! if it has a corresponding finalization from consensus.
//!
//! _It is possible that there may exist multiple finalizations for the same block in different views. Marshal
//! only concerns itself with verifying a valid finalization exists for a block, not that a specific finalization
//! exists. This means different Marshals may have different finalizations for the same block persisted to disk._
//!
//! ## Backfill
//!
//! The actor provides a backfill mechanism for missing blocks. If the actor notices a gap in its
//! knowledge of finalized blocks, it will request the missing blocks from its peers. This ensures
//! that the actor can catch up to the rest of the network if it falls behind.
//!
//! ## Storage
//!
//! The actor uses a combination of internal and external ([`store::Certificates`], [`store::Blocks`]) storage
//! to store blocks and finalizations. Internal storage (in-memory caches) is used for data that is only
//! needed for a short period of time, such as unverified blocks or notarizations. External storage
//! (archive backends) is used to persist finalized blocks and certificates indefinitely.
//!
//! Marshal will store all blocks after a configurable starting height (or, floor) onward.
//! This allows for state sync from a specific height rather than from genesis. When
//! updating the starting height, marshal will attempt to prune blocks in external storage
//! that are no longer needed, if the backing [`store::Blocks`] supports pruning.
//!
//! _Setting a configurable starting height will prevent others from backfilling blocks below said height. This
//! feature is only recommended for applications that support state sync (i.e., those that don't require full
//! block history to participate in consensus)._
//!
//! ## Limitations and Future Work
//!
//! - Only works with [crate::simplex] rather than general consensus.
//! - Assumes at-most one notarization per view, incompatible with some consensus protocols.
//! - Uses [`broadcast::buffered`](`commonware_broadcast::buffered`) for broadcasting and receiving
//!   uncertified blocks from the network.

use crate::{
    types::{Height, Round},
    Block,
};
use commonware_cryptography::Digest;
use commonware_macros::stability_mod;
use commonware_storage::archive;
use commonware_utils::{acknowledgement::Exact, Acknowledgement};

mod config;
pub use config::Config;

pub mod ancestry;
pub mod resolver;
pub mod standard;
pub mod store;

pub mod core;

stability_mod!(ALPHA, pub mod coding);

#[cfg(test)]
pub mod mocks;

#[cfg(test)]
mod tests {
    use super::mocks::harness::{self, CodingHarness, StandardHarness, LINK, UNRELIABLE_LINK};
    use commonware_macros::test_traced;

    // =============================================================================
    // Standard Variant Tests
    // =============================================================================

    #[test_traced("WARN")]
    fn test_standard_finalize_good_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<StandardHarness>(seed, LINK, false);
            let r2 = harness::finalize::<StandardHarness>(seed, LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_standard_finalize_bad_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<StandardHarness>(seed, UNRELIABLE_LINK, false);
            let r2 = harness::finalize::<StandardHarness>(seed, UNRELIABLE_LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_standard_finalize_good_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<StandardHarness>(seed, LINK, true);
            let r2 = harness::finalize::<StandardHarness>(seed, LINK, true);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_standard_finalize_bad_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<StandardHarness>(seed, UNRELIABLE_LINK, true);
            let r2 = harness::finalize::<StandardHarness>(seed, UNRELIABLE_LINK, true);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_standard_sync_height_floor() {
        harness::sync_height_floor::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_prune_finalized_archives() {
        harness::prune_finalized_archives::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_basic_block_delivery() {
        harness::subscribe_basic_block_delivery::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_multiple_subscriptions() {
        harness::subscribe_multiple_subscriptions::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_canceled_subscriptions() {
        harness::subscribe_canceled_subscriptions::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_blocks_from_different_sources() {
        harness::subscribe_blocks_from_different_sources::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_info_basic_queries_present_and_missing() {
        harness::get_info_basic_queries_present_and_missing::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_info_latest_progression_multiple_finalizations() {
        harness::get_info_latest_progression_multiple_finalizations::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_block_by_height_and_latest() {
        harness::get_block_by_height_and_latest::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_block_by_commitment_from_sources_and_missing() {
        harness::get_block_by_commitment_from_sources_and_missing::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_finalization_by_height() {
        harness::get_finalization_by_height::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_hint_finalized_triggers_fetch() {
        harness::hint_finalized_triggers_fetch::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_ancestry_stream() {
        harness::ancestry_stream::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_finalize_same_height_different_views() {
        harness::finalize_same_height_different_views::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_init_processed_height() {
        harness::init_processed_height::<StandardHarness>();
    }

    #[test_traced("INFO")]
    fn test_standard_broadcast_caches_block() {
        harness::broadcast_caches_block::<StandardHarness>();
    }

    // =============================================================================
    // Coding Variant Tests
    // =============================================================================

    #[test_traced("WARN")]
    fn test_coding_finalize_good_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, LINK, false);
            let r2 = harness::finalize::<CodingHarness>(seed, LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_coding_finalize_bad_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, false);
            let r2 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_coding_finalize_good_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, LINK, true);
            let r2 = harness::finalize::<CodingHarness>(seed, LINK, true);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_coding_finalize_bad_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, true);
            let r2 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, true);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_coding_sync_height_floor() {
        harness::sync_height_floor::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_prune_finalized_archives() {
        harness::prune_finalized_archives::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_basic_block_delivery() {
        harness::subscribe_basic_block_delivery::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_multiple_subscriptions() {
        harness::subscribe_multiple_subscriptions::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_canceled_subscriptions() {
        harness::subscribe_canceled_subscriptions::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_blocks_from_different_sources() {
        harness::subscribe_blocks_from_different_sources::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_info_basic_queries_present_and_missing() {
        harness::get_info_basic_queries_present_and_missing::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_info_latest_progression_multiple_finalizations() {
        harness::get_info_latest_progression_multiple_finalizations::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_block_by_height_and_latest() {
        harness::get_block_by_height_and_latest::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_block_by_commitment_from_sources_and_missing() {
        harness::get_block_by_commitment_from_sources_and_missing::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_finalization_by_height() {
        harness::get_finalization_by_height::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_hint_finalized_triggers_fetch() {
        harness::hint_finalized_triggers_fetch::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_ancestry_stream() {
        harness::ancestry_stream::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_finalize_same_height_different_views() {
        harness::finalize_same_height_different_views::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_init_processed_height() {
        harness::init_processed_height::<CodingHarness>();
    }

    #[test_traced("INFO")]
    fn test_coding_broadcast_caches_block() {
        harness::broadcast_caches_block::<CodingHarness>();
    }
}

/// An identifier for a block request.
pub enum Identifier<D: Digest> {
    /// The height of the block to retrieve.
    Height(Height),
    /// The digest of the block to retrieve.
    Digest(D),
    /// The highest finalized block. It may be the case that marshal does not have some of the
    /// blocks below this height.
    Latest,
}

// Allows using u64 directly for convenience.
impl<D: Digest> From<Height> for Identifier<D> {
    fn from(src: Height) -> Self {
        Self::Height(src)
    }
}

// Allows using &Digest directly for convenience.
impl<D: Digest> From<&D> for Identifier<D> {
    fn from(src: &D) -> Self {
        Self::Digest(*src)
    }
}

// Allows using archive identifiers directly for convenience.
impl<D: Digest> From<archive::Identifier<'_, D>> for Identifier<D> {
    fn from(src: archive::Identifier<'_, D>) -> Self {
        match src {
            archive::Identifier::Index(index) => Self::Height(Height::new(index)),
            archive::Identifier::Key(key) => Self::Digest(*key),
        }
    }
}

/// An update reported to the application, either a new finalized tip or a finalized block.
///
/// Finalized tips are reported as soon as known, whether or not we hold all blocks up to that height.
/// Finalized blocks are reported to the application in monotonically increasing order (no gaps permitted).
#[derive(Clone, Debug)]
pub enum Update<B: Block, A: Acknowledgement = Exact> {
    /// A new finalized tip and the finalization round.
    Tip(Round, Height, B::Digest),
    /// A new finalized block and an [Acknowledgement] for the application to signal once processed.
    ///
    /// To ensure all blocks are delivered at least once, marshal waits to mark a block as delivered
    /// until the application explicitly acknowledges the update. If the [Acknowledgement] is dropped before
    /// handling, marshal will exit (assuming the application is shutting down).
    ///
    /// Because the [Acknowledgement] is clonable, the application can pass [Update] to multiple consumers
    /// (and marshal will only consider the block delivered once all consumers have acknowledged it).
    Block(B, A),
}
