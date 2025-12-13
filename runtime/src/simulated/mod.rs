//! Simulated network infrastructure for deterministic testing.
//!
//! This module provides building blocks for simulating network conditions
//! in a deterministic way, useful for testing distributed systems:
//!
//! - [`Link`]: Configures latency, jitter, and packet loss between endpoints
//! - [`bandwidth`]: Max-min fair bandwidth allocation algorithm
//! - [`transmitter`]: Deterministic scheduler for message delivery with bandwidth limits
//!
//! # Design
//!
//! The simulation is generic over the peer identifier type `P`, which must implement
//! `Clone + Ord`. In the `p2p` crate, this is typically a `PublicKey`, while in the
//! `runtime` crate's multihead module, it's an `Ipv4Addr`.
//!
//! # Example
//!
//! ```ignore
//! use commonware_runtime::simulated::{Link, transmitter::State};
//! use std::time::Duration;
//!
//! // Configure link conditions
//! let link = Link::new(
//!     Duration::from_millis(50),  // 50ms latency
//!     Duration::from_millis(10),  // 10ms jitter
//!     0.01,                        // 1% drop rate
//! );
//!
//! // Create a transmitter for scheduling message delivery
//! let mut transmitter: State<u64> = State::new();
//! ```

pub mod bandwidth;
mod link;
mod transmitter;

pub use bandwidth::{allocate, duration, transfer, Flow, Rate};
pub use link::Link;
pub use transmitter::{Completion, State};
