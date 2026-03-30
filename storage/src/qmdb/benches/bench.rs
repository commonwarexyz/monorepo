//! Benchmark entry point for all QMDB benchmarks.
//!
//! Run with: `cargo bench --bench qmdb`

use criterion::criterion_main;

mod apply_batch;
mod common;
mod generate;
mod get;
mod init;
mod merkleize;
mod proof;

criterion_main!(
    generate::benches,
    merkleize::benches,
    apply_batch::benches,
    get::benches,
    proof::benches,
    init::benches,
);
