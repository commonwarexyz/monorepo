//! Benchmark entry point for QMDB generation benchmarks.
//!
//! Run with: `cargo bench --bench qmdb_generate`

use criterion::criterion_main;

#[allow(dead_code)]
mod fixed;
mod keyless;
#[allow(dead_code)]
mod variable;

criterion_main!(
    fixed::generate::benches,
    keyless::generate::benches,
    variable::generate::benches,
);
