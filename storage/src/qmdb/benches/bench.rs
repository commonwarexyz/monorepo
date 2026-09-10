//! Benchmark entry point for all QMDB benchmarks.

use criterion::criterion_main;

mod ancestor_candidates;
mod apply_batch;
mod chained_growth;
mod common;
mod generate;
mod init;
mod merkleize;

criterion_main!(
    ancestor_candidates::benches,
    apply_batch::benches,
    chained_growth::benches,
    generate::benches,
    init::benches,
    merkleize::benches
);
