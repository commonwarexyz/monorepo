//! TBD

pub mod simplex;

use bytes::Bytes;

// TODO: add simulated dialect for applications to test their execution environments under

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

pub trait Application: Clone {
    /// Generate a new payload for the given parent hash.
    fn propose(&mut self, parent: Hash) -> (Hash, Payload); // (hash, payload)

    /// Parse the payload and return the hash of the payload.
    fn parse(&self, payload: Payload) -> Option<Hash>;

    /// Verify the payload is valid.
    fn verify(&self, payload: Payload) -> bool;

    /// Event that the payload has been notarized.
    ///
    /// No guarantee will send notarized event for all heights.
    fn notarized(&mut self, payload: Payload);

    /// Event that the payload has been finalized.
    fn finalized(&mut self, payload: Payload);
}
