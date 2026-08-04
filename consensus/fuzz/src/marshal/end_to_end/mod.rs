//! Multi-node end-to-end marshal fuzzing model.
//!
//! This fuzzing harness runs three honest validators plus one byzantine validator,
//! reusing the shared fuzz infrastructure. The honest validators are parametrized by
//! the *marshal sink* instead of the reporter sink: marshal is the consensus
//! engine's reporter and delivers ordered finalized blocks to a downstream
//! application.
//!
//! Safety invariants are checked during execution and after the run completes.
//!
//! The liveness check injects byzantine faults, then asserts that honest nodes keep making progress:
//! every honest marshal delivers a target number of ordered finalized blocks
//! (sampled within a single-epoch bound).
//!
//! The certificate-poison target adds one byzantine backfill answer: the
//! covering nullification one honest node fetches is replaced by a valid
//! notarization whose block no node holds. Marshal cannot certify that
//! proposal, so the node must re-fetch the view it is still missing or it can
//! never vote again.

//!
//! # Layout
//!
//! - `app` is the block-building automaton bridging the engine to marshal.
//! - `runner` sets up the cluster, drives the liveness window, and checks
//!   invariants.
//! - `twins` runs the standard marshal stack under sampled Simplex Twins
//!   scenarios and checks post-prefix recovery.
//! - `invariants` holds the safety invariants and automaton assertions.

use commonware_consensus::marshal::mocks::harness::BLOCKS_PER_EPOCH;

mod app;
pub(crate) mod coding_stack;
mod input;
pub(super) mod invariants;
mod runner;
pub(crate) mod twins;

pub use input::{MarshalDisrupterInput, MarshalTwinsInput};
pub use runner::{
    fuzz_marshal_coding_disrupter, fuzz_marshal_standard_certificate_poison,
    fuzz_marshal_standard_disrupter, wedge::fuzz_split_notarization,
};
pub use twins::{
    fuzz_marshal_standard_deferred_id_twins_split_header,
    fuzz_marshal_standard_inline_id_twins_split_header, fuzz_marshal_standard_twins,
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
