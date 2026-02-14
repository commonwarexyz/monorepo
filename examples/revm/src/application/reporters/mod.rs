//! Reporters used by the REVM chain example.
//!
//! The example maintains two reporter contexts:
//! - `seed`: watches simplex activity and caches `prevrandao` seeds via `LedgerEvent::SeedUpdated`.
//! - `finalized`: replays finalized blocks and persists their snapshots through `LedgerService`.

mod finalized;
mod seed;

pub(crate) use finalized::FinalizedReporter;
pub(crate) use seed::SeedReporter;
