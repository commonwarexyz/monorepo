//! Benchmarks for `runtime::iobuf`.

use commonware_allocator::mimalloc;
use criterion::{criterion_group, criterion_main};

mod iobuf;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_group!(benches, iobuf::bench);

criterion_main!(benches);
