//! Benchmarks for `runtime::iobuf`.

use commonware_allocator::mimalloc;
use criterion::{criterion_group, criterion_main};

mod iobuf;

criterion_group!(benches, iobuf::bench);

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(benches);
