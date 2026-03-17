//! Benchmarks for steady-state buffer allocation and reuse.
//!
//! Compares [`BufferPool`] against bare aligned allocation for the hot path we
//! care about here: allocate, touch the requested bytes at page granularity,
//! and drop.
//!
//! Run with: `cargo bench --bench buffer_pool -p commonware-runtime`

use criterion::{criterion_group, criterion_main};

mod pool;

criterion_group!(benches, pool::bench);

criterion_main!(benches);
