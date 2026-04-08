//! Benchmark entry point for QMDB merkleize benchmarks.
//!
//! This is a separate binary from the other QMDB benchmarks so they don't block waiting on the
//! time-consuming setup of the QMDB init benchmarks.

use criterion::criterion_main;

#[path = "common.rs"]
#[allow(unused_imports, unused_macros, dead_code)]
mod common;
mod merkleize;

criterion_main!(merkleize::benches);
