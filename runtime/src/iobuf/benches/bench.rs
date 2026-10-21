//! Benchmarks for `runtime::iobuf`.

use criterion::{criterion_group, criterion_main};

mod iobuf;

criterion_group!(benches, iobuf::bench);

criterion_main!(benches);
