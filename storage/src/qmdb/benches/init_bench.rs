//! Benchmark entry point for QMDB initialization benchmarks.
//!
//! These benchmarks have expensive setup (generating large random databases) and are separated
//! into their own binary so they can be skipped when running other benchmarks.
//!
//! Run with: `cargo bench --bench qmdb_init`

use criterion::criterion_main;

#[allow(dead_code)]
mod fixed;
#[allow(dead_code)]
mod variable;

criterion_main!(fixed::init::benches, variable::init::benches);
