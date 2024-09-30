//! TBD

pub mod simplex;
pub mod tbd;

use bytes::Bytes;

// TODO: add simulated dialect for applications to test their execution environments under

// TODO: tests
// - sync from scratch
// - halt (50% shutdown) and recover
// - 33% shutdown and recover
// - full shutdown and recover (no safety failure from voting incorrectly)
// - 33% double-voting
// - block sent to one honest party different than block sent to all others, does it drop at notarization and fetch actual?

pub trait Application {
    fn propose(&mut self) -> Bytes;
    fn verify(&self, block: Bytes) -> Option<Bytes>;
    fn notarized(&mut self, block: Bytes);
    fn finalized(&mut self, block: Bytes);
}
