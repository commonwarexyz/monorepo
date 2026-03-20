//! Benchmarks for the page cache via the Append blob wrapper.
//!
//! Includes both deterministic in-memory runs to isolate buffer/page-cache work
//! and Tokio-backed runs to exercise real storage I/O paths.
//!
//! Run with: `cargo bench --bench buffer_paged -p commonware-runtime`

use commonware_runtime::{
    buffer::paged::{Append, CacheRef},
    Storage,
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

/// Create a new Append wrapper for benchmarking.
async fn create_append<C: Storage>(ctx: &C, name: &[u8], cache_ref: CacheRef) -> Append<C::Blob> {
    let (blob, size) = ctx.open("bench_partition", name).await.unwrap();
    Append::new(blob, size, WRITE_BUFFER_SIZE, cache_ref)
        .await
        .unwrap()
}

async fn destroy_append<C: Storage>(ctx: &C, append: Append<C::Blob>, name: &[u8]) {
    drop(append);
    ctx.remove("bench_partition", Some(name)).await.unwrap();
}

criterion_group!(benches, append::bench, read::bench);

criterion_main!(benches);
