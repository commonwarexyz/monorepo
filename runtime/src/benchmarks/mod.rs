//! Utilities for running benchmarks.

use commonware_macros::ready_mod;

pub mod context;
ready_mod!(2, pub mod tokio);
