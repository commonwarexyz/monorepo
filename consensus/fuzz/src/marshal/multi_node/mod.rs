//! Multi-node marshal liveness fuzzing model.
//!
//! This fuzzing harness runs three honest validators plus one byzantine `Disrupter`,
//! reusing the shared fuzz infrastructure. The honest validators are parametrized by
//! the *marshal sink* instead of the reporter sink: marshal is the consensus
//! engine's reporter and delivers ordered finalized blocks to a downstream
//! application.
//!
//! The liveness check injects byzantine faults, then asserts that honest nodes keep making progress:
//! every honest marshal delivers a target number of ordered finalized blocks
//! (sampled within a single-epoch bound).
//!
//! # Layout
//!
//! - `app` is the block-building automaton bridging the engine to marshal.
//! - `engine` wires the per-variant live simplex engine (standard `Deferred`,
//!   coding `Marshaled`) reporting to marshal.
//! - `runner` sets up the cluster, drives the liveness window, and checks
//!   invariants.
//! - `twins` runs the standard marshal stack under sampled Simplex Twins
//!   scenarios and checks post-prefix recovery.
//! - `invariants` holds the end-of-run and live automaton assertions.

use commonware_consensus::marshal::mocks::harness::BLOCKS_PER_EPOCH;

mod app;
mod engine;
mod input;
mod invariants;
mod runner;
mod twins;

pub use engine::LiveMarshal;
pub use input::{MarshalLivenessInput, MarshalTwinsInput};
pub use runner::fuzz_marshal_liveness;
pub use twins::{
    fuzz_marshal_twins, fuzz_marshal_twins_id_split_header,
    fuzz_marshal_twins_id_split_header_inline,
};

/// Engine p2p channel ids, shared by the honest engines and Byzantine twins.
/// Marshal hardcodes backfill=1 and broadcast=2 in `setup_validator_with`, so
/// these sit above.
const ENGINE_VOTE: u64 = 3;
const ENGINE_CERTIFICATE: u64 = 4;
const ENGINE_RESOLVER: u64 = 5;

/// Highest fresh block height this single-epoch harness can require. With
/// `FixedEpocher::new(BLOCKS_PER_EPOCH)`, height `BLOCKS_PER_EPOCH - 1` is the
/// epoch-0 boundary block; after that the wrappers re-propose the boundary block
/// instead of producing height `BLOCKS_PER_EPOCH`.
const MAX_REQUIRED: u64 = BLOCKS_PER_EPOCH.get() - 1;
