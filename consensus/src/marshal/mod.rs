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
//! Marshal sends requests, responses, and errors through its resolver on the backfill network, and
//! its buffer ([`commonware_broadcast::buffered`] or [`coding::shards::Engine`]) disseminates
//! blocks or their shards. `V` and `S` are the variant and certificate scheme given to
//! [`Limits::new`]:
//!
//! ```text
//! Any payload on a muxer subchannel:
//!
//! +---------------------------+---------+
//! | subchannel (varint, 1-10) | payload |
//! +---------------------------+---------+
//!
//! Request for Key::Block (tag 0, subject 0):
//!
//! +--------+---------+-------------+----------------------------------+
//! | id (8) | tag (1) | subject (1) | commitment (V::Commitment::SIZE) |
//! +--------+---------+-------------+----------------------------------+
//!
//! Request for Key::Finalized (tag 0, subject 1):
//!
//! +--------+---------+-------------+-----------------------+
//! | id (8) | tag (1) | subject (1) | height (varint, 1-10) |
//! +--------+---------+-------------+-----------------------+
//!
//! Request for Key::Notarized (tag 0, subject 2):
//!
//! +--------+---------+-------------+----------------------+---------------------+
//! | id (8) | tag (1) | subject (1) | epoch (varint, 1-10) | view (varint, 1-10) |
//! +--------+---------+-------------+----------------------+---------------------+
//!
//! Response for Key::Block (tag 1):
//!
//! +--------+---------+----------------------+----------------+
//! | id (8) | tag (1) | length (varint, 1-5) | backfill block |
//! +--------+---------+----------------------+----------------+
//!
//! Response for Key::Finalized (tag 1):
//!
//! +--------+---------+----------------------+--------------+-------------------+
//! | id (8) | tag (1) | length (varint, 1-5) | finalization | application block |
//! +--------+---------+----------------------+--------------+-------------------+
//!
//! Response for Key::Notarized (tag 1):
//!
//! +--------+---------+----------------------+--------------+----------------+
//! | id (8) | tag (1) | length (varint, 1-5) | notarization | backfill block |
//! +--------+---------+----------------------+--------------+----------------+
//!
//! Error (tag 2):
//!
//! +--------+---------+
//! | id (8) | tag (1) |
//! +--------+---------+
//!
//! Notarization or finalization:
//!
//! +----------------------+---------------------+-----------------------------------+
//! | epoch (varint, 1-10) | view (varint, 1-10) | parent (varint, 1-10)             |
//! +----------------------+-----------+---------+-----------------------------------+
//! | commitment (V::Commitment::SIZE) | certificate (up to S::max_certificate_size) |
//! +----------------------------------+---------------------------------------------+
//!
//! Backfill block under standard, and each buffered broadcast message:
//!
//! +---------------------------------------------------------+
//! | application block (up to the largest application block) |
//! +---------------------------------------------------------+
//!
//! Backfill block under coding:
//!
//! +---------------------------------------------------------+-------------------+
//! | application block (up to the largest application block) | coding config (4) |
//! +---------------------------------------------------------+-------------------+
//!
//! Shard:
//!
//! +------------------+-----------+-------+
//! | commitment (100) | index (2) | chunk |
//! +------------------+-----------+-------+
//!
//! Chunk (Reed-Solomon):
//!
//! +----------------------------+---------------------+-----------------------+
//! | shard length (varint, 1-5) | shard (shard width) | index (2)             |
//! +----------------+-----------+---------------------+-----------------------+
//! | leaf count (4) | sibling count (varint, 1-5)     | siblings (n x digest) |
//! +----------------+---------------------------------+-----------------------+
//! ```
//!
//! [`Limits`] takes every varint at its widest, every certificate at `S::max_certificate_size` for
//! committees of at most the given size, and every backfill block at its largest. Its footprint is
//! the larger of the widest backfill message and the widest buffer payload.
//!
//! The widest buffer payload is the largest application block under [`standard`]. Under
//! [`coding`], it is the widest shard that any committee of 4 to the given size codes from the
//! largest backfill block.
//!
//! [`Limits::new`] takes [`Config::block_codec_config`] and sizes the largest application block
//! with [`BoundedBlock::max_encode_size`](crate::BoundedBlock::max_encode_size). Every
//! application block marshal holds must fit it: the blocks
//! [`Application::prepare`](crate::Application::prepare) and
//! [`Application::propose`](crate::Application::propose) return, the genesis anchor, and every
//! block passed to [`core::Mailbox`].
//!
//! [`Limits`] bounds a network that carries both backfill and the buffer. When they send on
//! different networks, [`Limits::backfill`] bounds the one that carries backfill and
//! [`Limits::buffer`] the one that carries the buffer, each wrapped in [`Prefixed`] when it sends
//! on a subchannel. [`coding::shards::Engine`] also relays the shards it receives, so its receiver
//! must yield no payload larger than its sender's network admits.
//!
//! Every node that runs marshal on one network must give marshal and its buffer the same block
//! codec configuration and limits. Across restarts, neither the largest application block nor the
//! `max_message_size` of a network that carries backfill or the buffer may decrease while stored
//! blocks remain.
//!
//! [`Prefixed`]: commonware_p2p::utils::mux::Prefixed
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
mod limits;
pub use limits::Limits;

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
