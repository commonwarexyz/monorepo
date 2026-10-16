//! Benchmarks for `runtime::iobuf`.
//!
//! [`iobuf`]: fixed-size decode benchmarks comparing `Bytes` with `IoBuf`
//! backed by external `Bytes` or native heap storage. `Vec<u8>` modes
//! provide the deep-clone baseline.
//!
//! Run with: `cargo bench --bench iobuf -p commonware-runtime --features bench`

use criterion::{criterion_group, criterion_main};

mod iobuf;

criterion_group!(benches, iobuf::bench);

criterion_main!(benches);
