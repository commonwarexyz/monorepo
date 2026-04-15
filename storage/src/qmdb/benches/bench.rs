//! Benchmark entry point for all QMDB benchmarks.

use criterion::criterion_main;

mod common;
mod generate;
mod init;
mod merkleize;

criterion_main!(generate::benches, init::benches, merkleize::benches);
