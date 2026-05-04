//! ByzzFuzz fault injection for the Simplex fuzz harness.
//!
//! This module implements the network interception model from "ByzzFuzz:
//! Foundations and Applications of Random Testing for BFT Protocols" on top of
//! the simulated p2p network".
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
//! - [`run`] is the `Mode::Byzzfuzz` entry point;
//! - [`log`] stores the bounded decision trace drained on panic.

mod fault;
mod forwarder;
mod injector;
mod intercept;
pub mod log;
mod runner;

pub use runner::run;

/// Index of the byzantine identity in `participants`. Fixed at the lowest
/// position so every consumer (process-fault sampling in
/// [`fault::sample`]; sender selection / interception / injector key /
/// invariant exclusion in [`runner::run`]) reads from a single source of
/// truth. Several call sites encode this assumption (notably the sampler,
/// which builds its candidate receiver set as `participants[1..]`);
/// changing this value requires auditing them.
pub(crate) const BYZANTINE_IDX: usize = 0;
