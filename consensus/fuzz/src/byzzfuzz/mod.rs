//! ByzzFuzz fault injection for the Simplex fuzz harness.
//!
//! This module implements the network interception model from "ByzzFuzz:
//! Foundations and Applications of Random Testing for BFT Protocols" on top of
//! the simulated p2p network.
//!
//! The harness runs honest Simplex validators while the network layer injects:
//! - network faults, which drop messages crossing sampled partitions; and
//! - process faults, which mutate or omit messages sent by the Byzantine sender.
//!
//! Fault decisions are made using the sender's current protocol round `rnd(m)`,
//! tracked as the maximum view the sender has sent or received. Vote,
//! certificate, and resolver traffic all participate in this tracking.
//!
//! Public surface used from `lib.rs`:
//! - [`run`] is the `Mode::Byzzfuzz` (safety) entry point;
//! - [`run_liveness`] is the `Mode::ByzzfuzzLiveness` entry point: applies
//!   faults during a bounded fault phase, reaches GST on the shared fault gate,
//!   then requires every non-byzantine reporter to make at least one new
//!   finalization within a fixed post-GST window;
//! - [`log`] stores the bounded decision trace drained on panic.

mod fault;
mod forwarder;
mod injector;
mod intercept;
pub mod log;
mod mutator;
mod observed;
mod runner;
mod sampling;
mod scope;

pub use runner::{run, run_liveness};
pub(crate) use sampling::ByzzFuzz;

/// Byzantine index in `participants`. Single source of truth for the
/// sampler and the runner (sender selection, injector key, invariant exclusion).
pub(crate) const BYZANTINE_IDX: usize = 0;
