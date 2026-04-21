//! Benchmark entry point for all QMDB benchmarks.

use criterion::criterion_main;

mod chained_growth;
mod common;
mod generate;
mod init;
mod merkleize;

criterion_main!(
    chained_growth::benches,
    generate::benches,
    init::benches,
    merkleize::benches
);
