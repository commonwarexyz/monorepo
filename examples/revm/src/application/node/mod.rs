//! Node wiring for the tokio runtime simulation.
//!
//! Each node runs:
//! - a marshal instance (block dissemination, backfill, and finalized block delivery), and
//! - a threshold-simplex engine instance that orders opaque digests.

mod channels;
mod config;
mod env;
mod marshal;
mod start;

pub(crate) use config::{threshold_schemes, ThresholdScheme};
pub(crate) use env::{NodeEnvironment, TransportControl};
pub(crate) use start::start_node;
