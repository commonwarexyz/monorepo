//! Benchmark entry point for the generate & init QMDB benchmarks.

use criterion::criterion_main;

mod common;
mod generate;
mod init;

criterion_main!(generate::benches, init::benches);
