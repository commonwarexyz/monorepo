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
//! knowledge of finalized blocks, it will request the missing blocks from its peers. This lets
//! the actor catch up to the rest of the network if it falls behind.
//!
//! ## Message Sizes
//!
//! Marshal sends requests, responses, and errors through its resolver on the backfill network, and
//! its buffer ([`commonware_broadcast::buffered`] or [`coding::shards::Engine`]) disseminates
//! blocks or their shards. `V` and `S` are the variant and certificate scheme given to
//! [`max_payload_size`]:
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
//! | application block (up to the application block bound)   |
//! +---------------------------------------------------------+
//!
//! Backfill block under coding:
//!
//! +---------------------------------------------------------+-------------------+
//! | application block (up to the application block bound)   | coding config (4) |
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
//! [`max_payload_size`] sizes every varint at its widest, every certificate at
//! `S::max_certificate_size` for committees of at most the given size, and every backfill block at
//! its bound. It returns the larger of the backfill and buffer bounds.
//!
//! The buffer bound is the application block bound under [`standard`]. Under [`coding`], it is
//! the largest shard bound for the backfill block bound across committees of 4 to the given size.
//!
//! The application block bound is what
//! [`BoundedBlock::max_encode_size`](crate::BoundedBlock::max_encode_size) reports for
//! [`Config::block_codec_config`]. Every application block marshal holds must fit within it: the
//! blocks [`Application::prepare`](crate::Application::prepare) and
//! [`Application::propose`](crate::Application::propose) return, the genesis anchor, and every
//! block passed to [`core::Mailbox`].
//!
//! Every network that carries backfill or the buffer must admit [`max_payload_size`], or its
//! [`prefixed`] size when marshal runs on a muxer subchannel. [`coding::shards::Engine`] also
//! relays the shards it receives, so its receiver must yield no payload larger than its sender's
//! network admits.
//!
//! Every node that runs marshal on one network must give marshal and its buffer the same block
//! codec configuration and limits. Across restarts, neither the application block bound nor the
//! `max_message_size` of a network that carries backfill or the buffer may decrease while stored
//! blocks remain.
//!
//! [`prefixed`]: commonware_p2p::utils::mux::prefixed
//!
//! ## Storage
//!
//! The actor uses a combination of internal and external ([`store::Certificates`],
//! [`store::Blocks`]) storage to store blocks and finalizations. Internal storage (prunable
//! on-disk caches) is used for data that is only needed for a short period of time, such as
//! unverified blocks or notarizations. External storage (archive backends) is used to persist
//! finalized blocks and certificates.
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
//! ## Durability
//!
//! Marshal stores finalized blocks in [`store::Blocks`] and their finalizations in
//! [`store::Certificates`]. After it writes a block and its finalization, it syncs both stores
//! before it delivers the block in an [`Update::Block`]. When consensus reports a finalization,
//! marshal first syncs it into its cache.
//!
//! ```text
//!                                 marshal waits    both syncs in flight
//!                                 |<-------->|     |<------>|
//!  consensus              report--.
//!  cache                          w==========#-----.
//!  store::Blocks                                   w========#
//!  store::Certificates                             w================#
//!  application                                                        > Update::Block(H)
//!
//!  a stop in              <------- 1 --------|----- 2 ------|-- 3 --|--- 4 --->
//!  is sure to leave
//!    in the cache                                   f           f        f
//!    in Blocks                                                  B        B
//!    in Certificates                                                     f
//!
//!  w buffered write    = sync in flight    # durable    --. then    > delivery
//!  f finalization of H    B block H
//! ```
//!
//! Marshal delivers a block only when [`store::Certificates`] durably holds a finalization at or
//! above the block's height, so acknowledging a delivered block never moves the
//! [processed height](core::Processed) above the highest stored finalization. Every stored block
//! below a finalized block is one of its ancestors, so that finalization also covers a block that
//! has none of its own. The block at height zero is delivered without one. The rule applies to
//! every block [`store::Blocks`] serves, including a block that marshal did not write.
//!
//! The two syncs run concurrently, so a process that stops between them (span 3) can leave one
//! store holding a height that the other lacks. The figure draws [`store::Blocks`] finishing
//! first. A restart can then find either of two states:
//!
//! - A finalization without its block. Marshal tries to recover the block from local data or
//!   peers, and it does not deliver that height until it has the block.
//! - A block above every stored finalization. Marshal does not deliver it until a finalization
//!   at or above its height is durable. A finalization that consensus reported is cached before
//!   its block is written, so at startup marshal restores the cached finalization of the highest
//!   such block that has one. A finalization delivered by the resolver is not cached, and marshal
//!   does not request one. Its block waits until its height is hinted again with
//!   [`core::Mailbox::hint_finalized`] or a finalization at or above its height is stored.
//!
//! After a restart that follows an interrupted sync:
//!
//! | Height | [`store::Blocks`] | [`store::Certificates`] |
//! |--------|-------------------|-------------------------|
//! | H-2    | stored            | stored                  |
//! | H-1    | stored            | stored                  |
//! | H      | stored            | missing                 |
//!
//! If the cache lacks the finalization of H, [`Identifier::Latest`] is the block at H-1 and marshal
//! delivers through H-1. It delivers H once a finalization for H or a later height is durable.
//!
//! A block can also be stored without a finalization while marshal fills a gap. Marshal can reach
//! an ancestor of a finalized block by following parent links, and a block stored this way may
//! never receive a finalization of its own. [`core::Mailbox::get_finalization`] can return `None`
//! for such a block even after marshal delivers it.
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
pub use limits::max_payload_size;

pub mod ancestry;
pub(crate) mod application;
pub mod coding;
pub mod core;
pub mod resolver;
pub mod standard;
pub mod store;

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;

#[cfg(test)]
pub mod mocks;

/// An identifier for a block request.
pub enum Identifier<D: Digest> {
    /// The height of the block to retrieve.
    Height(Height),
    /// The digest of the block to retrieve.
    Digest(D),
    /// The block named by the highest finalization in [`store::Certificates`]. Marshal may lack
    /// this block and some of the blocks below it, and it delivers no block above this block's
    /// height. The Durability section of the [module docs](self) explains both.
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
    /// [`Update::Block`] signals that its block is durable.
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
