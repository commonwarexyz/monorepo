//! Benchmark entry point for QMDB generation benchmarks.
//!
//! Run with: `cargo bench --bench qmdb_generate`

use criterion::criterion_main;

mod fixed;
mod keyless_generate;
mod variable;

criterion_main!(
    fixed::generate::benches,
    keyless_generate::benches,
    variable::generate::benches,
);
