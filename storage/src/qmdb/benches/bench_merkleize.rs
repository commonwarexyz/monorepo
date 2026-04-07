//! Standalone benchmark entry point for QMDB merkleize benchmarks.
//!
//! Run with: `cargo bench --bench qmdb-merkleize`

use criterion::criterion_main;

#[path = "common.rs"]
#[allow(unused_imports, unused_macros, dead_code)]
mod common;
mod merkleize;

criterion_main!(merkleize::benches);
