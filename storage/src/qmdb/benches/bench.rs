//! Benchmark entry point for all QMDB benchmarks.
//!
//! Run with: `cargo bench --bench qmdb`

use criterion::criterion_main;

mod common;
mod generate;
mod init;

criterion_main!(generate::benches, init::benches);
