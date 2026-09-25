//! Benchmarks for `runtime::telemetry::metrics`.
//!
//! - [`histogram`]: observing samples into a bucketed histogram.
//!
//! Run with: `cargo bench --bench telemetry -p commonware-runtime`

use commonware_allocator::mimalloc;
use criterion::{criterion_group, criterion_main};

mod histogram;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_group!(benches, histogram::bench);

criterion_main!(benches);
