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
//! The actor interacts with several components:
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
//! The actor delivers each finalized block from its starting height onward, in height order and
//! at least once. Installing a floor can skip ahead. A restart or a floor installation can
//! redeliver already reported blocks with fresh acknowledgements, so reporters must handle
//! duplicates.
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
//! ## Message Sizes
//!
//! Recovery sends a complete block in one resolver response, with a certificate when the request
//! names a round or height. The receiver returned by [`resolver::p2p::init`] carries values up to
//! the backfill sender's [`max_message_size`](commonware_p2p::LimitedSender::max_message_size)
//! minus [`MAX_MESSAGE_OVERHEAD`](commonware_resolver::p2p::MAX_MESSAGE_OVERHEAD). When the actor
//! starts, it fixes its bound to the largest encoded [`core::Variant::Block`] that meets every
//! condition below:
//!
//! - The block and the widest notarization for [`Config::max_participants`] fit one such value.
//! - The block's buffer payload for every committee of at most `max_participants`, plus a
//!   [`Muxer`](commonware_p2p::utils::mux::Muxer) subchannel prefix, fits the backfill sender.
//! - The buffer's own limit, if [`core::Buffer::max_block_size`] reports one, admits the block
//!   ([`coding::shards::Config::max_block_size`] for coding).
//!
//! The actor panics at start when an application block of zero bytes fails these conditions, so
//! the bound always admits one.
//!
//! To admit blocks up to a target size, fold the [`Limits`] for that size and `max_participants`
//! into the P2P `max_message_size` with [`commonware_p2p::max_message_size`], wrapped in
//! [`Prefixed`](commonware_p2p::utils::mux::Prefixed) when backfill runs on a subchannel, and set
//! the buffer's own limit, if it has one, to at least that size. The bound follows the backfill
//! sender's limit, so when another component's [`Footprint`](commonware_p2p::Footprint) raises that
//! limit, marshal can admit blocks above the target, up to the buffer's own limit.
//!
//! The buffer must send on the backfill network, directly or on one subchannel, so that the bound
//! keeps what it sends within its sender's limit:
//!
//! - [`commonware_broadcast::buffered`] sends each block whole.
//! - [`coding::shards::Engine`] sends the shards of a block it proposes or forwards only when the
//!   block fits its [`max_block_size`](coding::shards::Config::max_block_size) and is coded for its
//!   committee. It also relays the shards it receives, and p2p delivers none larger than the
//!   sender's limit.
//!
//! Marshal never admits a block above the bound:
//!
//! - [`standard::Inline`], [`standard::Deferred`], and [`coding::Marshaled`] decline to propose a
//!   built block above the bound and answer [`Handoff::Wait`](crate::Handoff::Wait) for a prepared
//!   term-start candidate above it.
//! - The actor treats a block above the bound from the buffer, a buffer subscription, or the
//!   resolver as unavailable. It acknowledges an otherwise valid resolver delivery of such a block,
//!   so the peer is not blocked.
//! - The actor panics on a block above the bound passed to [`core::Mailbox`] or given as the
//!   genesis anchor.
//!
//! As a result, a [`standard`] validator never votes for such a block. A [`coding`] validator can
//! cast a notarize vote for one, since that vote needs only its assigned shard, but it never
//! certifies the block and so never votes to finalize it.
//!
//! The bound is the same in every epoch, and [`core::Mailbox::max_block_size`] returns it. Every
//! node that runs marshal on a network must configure the same `max_message_size`,
//! `max_participants`, and buffer limit, so that all nodes admit the same blocks. A node with a
//! smaller bound cannot admit a block its peers finalize. It makes no progress past that height,
//! keeps fetching and refusing the block, and behaves like a crashed node until it restarts with a
//! bound that admits the block.
//!
//! Marshal serves and reuses the blocks and certificates it stores without checking their sizes
//! again. Across restarts, the backfill sender's `max_message_size` must not decrease, or a
//! response carrying a stored block may exceed it and panic in p2p. The bound must not decrease
//! either, and raising `max_participants` or lowering the buffer's own limit can lower it.
//! Subscriptions also return stored blocks. A wrapper that verifies, certifies, or re-proposes such
//! a block hands it back to the actor, and the actor panics if the block exceeds a lowered bound.
//!
//! ## Storage
//!
//! The actor uses a combination of internal and external ([`store::Certificates`], [`store::Blocks`]) storage
//! to store blocks and finalizations. Internal storage (in-memory caches) is used for data that is only
//! needed for a short period of time, such as unverified blocks or notarizations. External storage
//! (archive backends) is used to persist finalized blocks and certificates.
//!
//! Marshal stores finalized blocks from a configurable starting height (or, floor) onward.
//! This allows for state sync from a specific height rather than from genesis. The floor
//! is supplied as a finalization. Marshal obtains the corresponding block asynchronously,
//! from local storage, the buffer, or peers, before dispatching application blocks starting
//! at that height. Installing a floor may prune older history if [`store::Blocks`] supports
//! pruning, but keeps the stored block preceding the floor.
//!
//! _History below the starting height may be unavailable to peers. This feature is only
//! recommended for applications that support state sync and do not require full block history to
//! participate in consensus._
//!
//! ## Limitations and Future Work
//!
//! - Only works with [crate::simplex] rather than general consensus.
//! - Assumes at-most one notarization per view, incompatible with some consensus protocols.
//! - Uses [`broadcast::buffered`](`commonware_broadcast::buffered`) for broadcasting and receiving
//!   uncertified blocks from the network.

use crate::{
    Block,
    types::{Height, Round},
};
use commonware_cryptography::{Digest, Digested};
use commonware_storage::archive;
use commonware_utils::{Acknowledgement, acknowledgement::Exact};

mod config;
pub use config::{Config, Start};
mod sizing;
pub use sizing::Limits;

pub mod ancestry;
pub mod core;
pub mod resolver;
pub mod standard;
pub mod store;

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;

commonware_macros::stability_scope!(ALPHA {
    pub(crate) mod application;
    pub mod coding;
});

#[cfg(test)]
pub mod mocks;

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
/// Finalized blocks are reported from the starting height onward, in height order without gaps.
/// Installing a floor can skip ahead. A restart or a floor installation can redeliver already
/// reported blocks with fresh acknowledgements.
#[derive(Clone, Debug)]
pub enum Update<B: Block, A: Acknowledgement = Exact> {
    /// A new finalized tip and the finalization round.
    ///
    /// This update can be reported before the finalized block and finalization archives complete
    /// a durable sync. Applications must not use this update as a storage durability signal.
    /// [`Update::Block`] provides that guarantee.
    Tip(Round, Height, B::Digest),
    /// A new finalized block and an [Acknowledgement] for the application to signal once processed.
    ///
    /// Marshal waits to mark a block as delivered until the application explicitly acknowledges the
    /// update. Dropping an [Acknowledgement] while marshal still waits for it stops marshal.
    ///
    /// Cloning the update shares the immutable block, so applications can fan it out without requiring
    /// block clones. Marshal only considers the block delivered once every acknowledgement is handled.
    ///
    /// Marshal only emits a block after durably persisting it, so applications that keep state
    /// derived from a block can read the same block after a restart. See [core::Processed] for
    /// the block that backs the processed height.
    Block(Digested<B>, A),
}
