//! Utilities for running benchmarks.

use commonware_macros::ready_mod;

pub mod context;
ready_mod!(WIRE_STABLE, pub mod tokio);
