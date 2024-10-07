//! TBD

pub mod simplex;

use bytes::Bytes;

// TODO: add simulated dialect for applications to test their execution environments under (with arbitary orphans, etc.)

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
type Payload = Bytes;

/// TODO: call verify after voting (before finalization votes) or before voting? Can include
/// outputs of block in next block?
/// TODO: perform verification async so can keep responding to messages?
pub trait Application: Clone + Send + Sync {
    /// Generate a new payload for the given parent hash.
    ///
    /// If state is not yet ready, this will return None.
    fn propose(&mut self, parent: Hash) -> Option<Payload>;

    /// Parse the payload and return the hash of the payload.
    ///
    /// Parse is a stateless operation and may be called out-of-order.
    fn parse(&self, payload: Payload) -> Option<Hash>;

    /// Verify the payload is valid.
    ///
    /// Verify is a stateful operation and must be called in-order.
    fn verify(&self, payload: Payload) -> bool;

    /// Event that the payload has been notarized.
    ///
    /// No guarantee will send notarized event for all heights.
    fn notarized(&mut self, payload: Payload);

    /// Event that the payload has been finalized.
    fn finalized(&mut self, payload: Payload);
}

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
