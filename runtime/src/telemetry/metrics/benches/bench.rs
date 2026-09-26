//! Benchmarks for `runtime::telemetry::metrics`.
//!
//! - [`histogram`]: observing samples into a bucketed histogram.
//!
//! Run with: `cargo bench --bench telemetry -p commonware-runtime`

use criterion::{criterion_group, criterion_main};

mod histogram;

criterion_group!(benches, histogram::bench);

criterion_main!(benches);
