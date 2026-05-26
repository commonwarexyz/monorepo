//! Multi-node marshal liveness fuzzing model.
//!
//! This fuzzing harness runs three honest validators plus one byzantine `Disrupter`,
//! reusing the shared fuzz infrastructure. The honest validators are parametrized by
//! the *marshal sink* instead of the reporter sink: marshal is the consensus
//! engine's reporter and delivers ordered finalized blocks to a downstream
//! application.
//!
//! The liveness check injects byzantine faults, then assert that honest nodes keep making progress:
//! every honest marshal delivers `required_containers` ordered finalized blocks.
//!
//! # Layout
//!
//! - `app` is the block-building automaton bridging the engine to marshal.
//! - `engine` wires the per-variant live simplex engine (standard `Deferred`,
//!   coding `Marshaled`) reporting to marshal.
//! - `runner` sets up the cluster, drives the liveness window, and checks
//!   invariants.
//! - `invariant` holds the end-of-run assertions.

mod app;
mod engine;
mod invariant;
mod runner;

pub use engine::LiveMarshal;
pub use runner::fuzz_marshal_liveness;

/// Engine p2p channel ids, shared by the honest engines and the byzantine
/// `Disrupter` so they talk on the same consensus channels. Marshal hardcodes
/// backfill=1 and broadcast=2 in `setup_validator_with`, so these sit above.
const ENGINE_VOTE: u64 = 3;
const ENGINE_CERTIFICATE: u64 = 4;
const ENGINE_RESOLVER: u64 = 5;
