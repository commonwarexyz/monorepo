//! TBD
//!
//! Makes some assumptions about the consensus construction:
//! * Cryptographic proof of participation

pub mod fixed;
pub mod mocks;
pub mod sha256;

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

type Hash = Bytes; // use fixed size bytes

/// Hasher is provided by the application for hashing.
///
/// This is configurable because some hash functions are better suited for
/// SNARK/STARK proofs than others.
pub trait Hasher: Clone + Send + 'static {
    /// Validate the hash.
    fn validate(hash: &Hash) -> bool;

    /// Hash the given digest.
    fn hash(&mut self, digest: &[u8]) -> Hash;
}

type View = u64;
type Height = u64;

/// Context is a collection of information about the context in which a block is built.
#[derive(Clone)]
pub struct Context {
    pub view: View,
    pub parent: Hash,
    pub height: Height,
}

/// Faults are specified by the underlying primitive and can be interpreted if desired (not
/// interpreting just means all faults would be treated equally).
type FaultType = u16;
type Fault = (PublicKey, FaultType);

/// Various consensus implementations may want to reward participation in different ways. For example,
/// validators could be required to send multiple types of messages (i.e. vote and finalize) and rewarding
/// both equally may better align incentives with desired behavior.
type ContributionType = u16;
type Contribution = (PublicKey, ContributionType);

/// Activity is a collection of information about consensus performance
/// included in the block wrapper (handled externally).
///
/// It is up to the application to determine how to act on this information (attributing
/// rewards, removing validators, etc.).
#[derive(Clone)]
pub struct Activity {
    pub proposer: PublicKey,

    /// Contributions at a given height.
    ///
    ///
    /// Height is exposed such that rewards can be scaled by
    /// timeliness.
    ///
    /// Inactivity (no posted support) can be inferred from the
    /// contents of `support`.
    pub contributions: HashMap<Height, Vec<Contribution>>,

    /// Faults are not gossiped through the network and are only
    /// posted once locally observed (as this would create a DoS vector).
    pub faults: HashMap<View, Vec<Fault>>,
}

type Payload = Bytes;

/// Application is the interface for the consensus engine to inform of progress.
///
/// While an application may be logically instantiated as a single entity, it may be
/// cloned by multiple sub-components of a consensus engine.
pub trait Application: Clone + Send + 'static {
    /// Initialize the application with the genesis block at view=0, height=0.
    fn genesis(&mut self) -> (Hash, Payload);

    /// Get the **sorted** participants for the given view. This is called when entering a new view before
    /// listening for proposals or votes. If nothing is returned, the view will not be entered.
    ///
    /// It is up to the developer to ensure changes to this list are synchronized across nodes in the network
    /// at a given view. If care is not taken to do this, the chain could fork/halt. If using an underlying
    /// consensus implementation that does not require finalization of a height before producing a block
    /// at the next height (asynchronous finalization), a synchrony bound should be enforced around
    /// changes to the set (i.e. participant joining in view 10 should only become active in view 20, where
    /// we assume all other participants have finalized view 10).
    fn participants(&self, view: View) -> Option<&Vec<PublicKey>>;

    // Indicate whether a PublicKey is a participant at the given view.
    fn is_participant(&self, view: View, candidate: &PublicKey) -> Option<bool>;

    /// Generate a new payload for the given parent hash.
    ///
    /// If state is not yet ready, this will return None.
    fn propose(
        &mut self,
        context: Context,
        activity: Activity,
    ) -> impl Future<Output = Option<Payload>> + Send;

    /// Parse the payload and return the hash of the payload. We don't just hash
    /// the payload because it may be more efficient to prove against a hash
    /// that is specifically formatted (like a trie root).
    ///
    /// Parse is a stateless operation and may be called out-of-order.
    fn parse(&mut self, payload: Payload) -> impl Future<Output = Option<Hash>> + Send;

    /// Verify the payload is valid.
    ///
    /// Verify is a stateful operation and must be called in-order.
    fn verify(
        &mut self,
        context: Context,
        activity: Activity,
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

type Epoch = u64;

#[derive(Clone)]
pub struct EpochContext {
    pub epoch: Epoch,
    pub context: Context,
}

pub trait EpochApplication: Application {
    fn participants(&self, epoch: Epoch, view: View) -> Option<Vec<PublicKey>>;

    fn propose(
        &mut self,
        context: EpochContext,
        activity: Activity,
    ) -> impl Future<Output = Option<Payload>> + Send;

    fn verify(
        &mut self,
        context: EpochContext,
        activity: Activity,
        payload: Payload,
        block: Hash,
    ) -> impl Future<Output = bool> + Send;

    fn start_epoch(&mut self, epoch: Epoch, view: View) -> impl Future<Output = ()> + Send;

    fn end_epoch(&mut self, epoch: Epoch, view: View) -> impl Future<Output = ()> + Send;
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
