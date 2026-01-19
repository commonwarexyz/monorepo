//! Benchmarks for the buffer pool page cache via the Append blob wrapper.
//!
//! Uses memory-based storage (deterministic runtime) to isolate buffer pool
//! performance from disk I/O.
//!
//! Run with: `cargo bench --bench buffer_pool -p commonware-runtime`

use commonware_runtime::{
    buffer::{pool::Append, PoolRef},
    deterministic::Context,
    Storage as _,
};
use commonware_utils::NZU16;
use criterion::{criterion_group, criterion_main};
use std::num::NonZeroU16;

mod append;
mod read;

const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
const PAGE_SIZE_USIZE: usize = PAGE_SIZE.get() as usize;
const WRITE_BUFFER_SIZE: usize = PAGE_SIZE_USIZE * 4;
const CACHE_SIZE: usize = 10_000;

type MemBlob = <Context as commonware_runtime::Storage>::Blob;

/// Create a new Append wrapper for benchmarking.
async fn create_append(ctx: &Context, name: &[u8], pool_ref: PoolRef) -> Append<MemBlob> {
    let (blob, size) = ctx.open("bench_partition", name).await.unwrap();
    Append::new(blob, size, WRITE_BUFFER_SIZE, pool_ref)
        .await
        .unwrap()
}

async fn destroy_append(ctx: &Context, append: Append<MemBlob>, name: &[u8]) {
    drop(append);
    ctx.remove("bench_partition", Some(name)).await.unwrap();
}

criterion_group!(benches, append::bench, read::bench);

criterion_main!(benches);
