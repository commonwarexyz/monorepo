//! Criterion benchmarks for durable storage writes.

use criterion::criterion_main;

mod write_at_sync;

criterion_main!(write_at_sync::benches);
