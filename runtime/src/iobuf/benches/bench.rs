//! Benchmarks for `runtime::iobuf`.
//!
//! Run with: `cargo bench --bench iobuf -p commonware-runtime`

use criterion::{criterion_group, criterion_main};

mod iobuf;

criterion_group!(benches, iobuf::bench);

criterion_main!(benches);
