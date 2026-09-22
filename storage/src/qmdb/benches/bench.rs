//! Benchmark entry point for all QMDB benchmarks.

use criterion::criterion_main;

mod apply_batch;
mod chained_growth;
mod common;
mod digest_reads;
mod generate;
mod init;
mod merkleize;

criterion_main!(
    apply_batch::benches,
    chained_growth::benches,
    digest_reads::benches,
    generate::benches,
    init::benches,
    merkleize::benches
);
