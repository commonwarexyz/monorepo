//! Simulated network infrastructure for deterministic testing.
//!
//! This module provides building blocks for simulating network conditions
//! in a deterministic way, useful for testing distributed systems:
//!
//! - [`Link`]: Configures latency, jitter, and packet loss between endpoints
//! - [`bandwidth`]: Max-min fair bandwidth allocation algorithm
//! - [`Completion`]/[`State`]: Deterministic scheduler for message delivery with bandwidth limits
//! - [`Router`]: High-level message router that manages links and delivery
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
//! use commonware_runtime::simulated::{Link, Router};
//! use std::time::Duration;
//!
//! // Create a router for message delivery
//! let mut router: Router<u64, u32> = Router::new();
//!
//! // Configure link conditions between peers
//! let link = Link::new(
//!     Duration::from_millis(50),  // 50ms latency
//!     Duration::from_millis(10),  // 10ms jitter
//!     0.99,                        // 99% success rate
//! );
//! router.add_link(peer1, peer2, link);
//!
//! // Set bandwidth limits
//! router.limit_bandwidth(now, &peer1, Some(1_000_000), None); // 1MB/s egress
//!
//! // Send messages through the router
//! let deliveries = router.send(now, &mut rng, peer1, peer2, channel, message);
//! ```

pub mod bandwidth;
mod link;
mod router;
mod transmitter;

pub use bandwidth::{allocate, duration, transfer, Flow, Rate};
pub use link::Link;
pub use router::{Delivery, Router};
pub use transmitter::{Completion, State};
