//! Benchmark entry point for all QMDB benchmarks.

use criterion::criterion_main;

mod apply_batch;
mod chained_growth;
mod common;
mod generate;
mod init;
#[macro_use]
mod merkleize_workload;
mod merkleize;

criterion_main!(
    apply_batch::benches,
    chained_growth::benches,
    generate::benches,
    init::benches,
    merkleize::benches
);
