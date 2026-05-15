//! ByzzFuzz fault injection for the Simplex fuzz harness.
//!
//! This module implements ByzzFuzz-style network interception on top of the
//! simulated p2p network.
//!
//! The harness runs honest Simplex validators while the network layer injects:
//! - network faults, which drop messages crossing sampled partitions; and
//! - process faults, which mutate or omit messages sent by the Byzantine sender.
//!
//! Network faults are attributed using the sender's current protocol round
//! `rnd(m)`, tracked as the maximum view the sender has sent or received.
//! Process faults are matched against the decoded view carried by the
//! byzantine sender's outgoing message. Vote, certificate, and resolver
//! traffic all participate in round tracking.
//!
//! Public surface used from `lib.rs`:
//! - [`run`] is the `Mode::Byzzfuzz` entry point:
//!   applies network faults during a bounded fault phase, skips GST if every
//!   non-byzantine reporter reaches `required_containers`, otherwise reaches
//!   GST and waits for each non-byzantine reporter's post-GST target while
//!   Byzantine process faults remain active;
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

pub use runner::run;
pub(crate) use sampling::ByzzFuzz;

/// Byzantine index in `participants`. Single source of truth for the
/// sampler and the runner (sender selection, injector key, invariant exclusion).
pub(crate) const BYZANTINE_IDX: usize = 0;
