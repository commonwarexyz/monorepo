//! TBD
//!
//! Makes some assumptions about the consensus construction:
//! * Cryptographic proof of participation

pub mod fixed;
pub mod mocks;

use bytes::Bytes;
use commonware_cryptography::PublicKey;
use std::collections::HashMap;
use std::future::Future;

// TODO: add simulated dialect for applications to test their execution environments under (with arbitary orphans, etc.)

// TODO: add a view limit (where no further blocks can be produced) but still respond to sync requests (would need to periodically gossip
// last finalization to all peers to allow new syncers to catch up)

// TODO: tests
// - sync from scratch
// - halt (50% shutdown) and recover
// - 33% shutdown and recover
// - full shutdown and recover (no safety failure from voting incorrectly)
// - 33% double-voting
// - block sent to one honest party different than block sent to all others, does it drop at notarization and fetch actual?

type View = u64;
type Height = u64;
type Hash = Bytes; // use fixed size bytes
const HASH_LENGTH: usize = 32;
type Payload = Bytes;
/// Faults are specified by the underlying primitive and can be interpreted if desired (not
/// interpreting just means all faults would be treated equally).
type Fault = u32;

/// Context is a collection of information about the context in which a block is built.
pub struct Context {
    pub parent: Hash,
    pub view: View,
    pub height: Height,
}

/// Participation is a collection of information about consensus performance
/// included in the block wrapper.
pub struct Participation {
    pub proposer: PublicKey,

    /// Votes for a canonical block at a given height.
    ///
    /// Height is exposed such that rewards can be scaled by
    /// timeliness.
    // TODO: ensure a validator can only support if active at a given
    // view
    pub support: HashMap<Height, Vec<PublicKey>>,
    pub faults: HashMap<PublicKey, Fault>,
}

pub trait Parser: Clone + Send + 'static {
    /// Parse the payload and return the hash of the payload. We don't just hash
    /// the payload because it may be more efficient to prove against a hash
    /// that is specifically formatted (like a trie root).
    ///
    /// Parse is a stateless operation and may be called out-of-order.
    fn parse(&mut self, payload: Payload) -> impl Future<Output = Option<Hash>> + Send;
}

/// TODO: call verify after voting (before finalization votes) or before voting? Can include
/// outputs of block in next block?
/// TODO: perform verification async so can keep responding to messages?
/// TODO: change name
pub trait Processor: Send + 'static {
    /// Initialize the application with the genesis block at view=0, height=0.
    fn genesis(&mut self) -> (Hash, Payload);

    /// Generate a new payload for the given parent hash.
    ///
    /// If state is not yet ready, this will return None.
    ///
    /// TODO: provide uptime/fault info here?
    fn propose(
        &mut self,
        context: Context,
        participation: Participation,
    ) -> impl Future<Output = Option<Payload>> + Send;

    /// Verify the payload is valid.
    ///
    /// Verify is a stateful operation and must be called in-order.
    fn verify(
        &mut self,
        context: Context,
        participation: Participation,
        payload: Payload,
        block: Hash,
    ) -> impl Future<Output = bool> + Send;

    /// Event that the payload has been notarized.
    ///
    /// No guarantee will send notarized event for all heights.
    fn notarized(&mut self, block: Hash) -> impl Future<Output = ()> + Send;

    /// Event that the payload has been finalized.
    fn finalized(&mut self, block: Hash) -> impl Future<Output = ()> + Send;
}

/// Oracle is a trait that allows the application to update the participants
/// in consensus at a given view.
pub trait Oracle {
    /// It is up to the developer to ensure that any updates cannot cause a halt (if some validators
    /// apply the change and others do not, often as a result of delayed finality at a previous view).
    fn participants(&mut self, view: View, validators: Vec<PublicKey>);
}

// TODO: break apart into smaller traits?
// TODO: how to layer traits (want to call propose different ways depending
// on whether we are including uptime info/faults)?

// Example Payload (Transfers):
// - Vec<Tx> => hashed as balanced binary trie by hash
//
// Context:
// -> Builder, View (gauge of time elapsed), Height, Timestamp, Parent_Payload (used to track inner trie)
// .   -> If previously proposed block at a height that is not yet canonicalized, should re-propose?
// -> (Optional) Signers in previous round (reward uptime)
// -> (Optional) Faults (at any round)
//
// Expectations:
// * Application tracks a trie of pending blocks (with pending state diffs to that trie)
//   * If we only execute committed blocks, this isn't required? Still need to build proposals on a tree of blocks (can't wait for finality
// .   to build). Also would mean data proveable from a block may not be correct (would need to rely on child block to indicate what was successful).
