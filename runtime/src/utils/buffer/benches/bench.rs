//! Benchmarks for the page cache via the Append blob wrapper.
//!
//! Includes both deterministic in-memory runs to isolate buffer/page-cache work
//! and Tokio-backed runs to exercise real storage I/O paths.

use commonware_allocator::mimalloc;
use commonware_runtime::{
    BLOB_PAGE_SIZE, Storage,
    buffer::paged::{CacheRef, Writer, page_size},
};
use criterion::{criterion_group, criterion_main};
use std::num::NonZeroU16;

mod append;
mod evict;
mod read;
mod sync;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

const PAGE_SIZE: NonZeroU16 = page_size(BLOB_PAGE_SIZE);
const PAGE_SIZE_USIZE: usize = PAGE_SIZE.get() as usize;
const WRITE_BUFFER_SIZE: usize = PAGE_SIZE_USIZE * 4;
const CACHE_SIZE: usize = 10_000;

/// Create a new Writer for benchmarking.
async fn create_append<C: Storage>(ctx: &C, name: &[u8], cache_ref: CacheRef) -> Writer<C::Blob> {
    let (blob, size) = ctx.open("bench_partition", name).await.unwrap();
    Writer::new(blob, size, WRITE_BUFFER_SIZE, cache_ref)
        .await
        .unwrap()
}

async fn destroy_append<C: Storage>(ctx: &C, append: Writer<C::Blob>, name: &[u8]) {
    drop(append);
    ctx.remove("bench_partition", Some(name)).await.unwrap();
}

criterion_group!(
    benches,
    append::bench,
    evict::bench,
    read::bench,
    sync::bench
);

criterion_main!(benches);
