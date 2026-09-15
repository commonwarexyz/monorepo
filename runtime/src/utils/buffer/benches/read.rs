//! Benchmark read performance at random offsets.

use super::{CACHE_SIZE, PAGE_SIZE, PAGE_SIZE_USIZE, create_append, destroy_append};
use commonware_runtime::{
    BufferPooler, Runner, Storage, buffer::paged::CacheRef, deterministic, tokio,
};
use commonware_utils::{NZUsize, TestRng};
use criterion::Criterion;
use rand::RngExt as _;
use std::time::Instant;

// Use cache size pages so all data fits in cache (testing buffer performance, not disk).
const TOTAL_PAGES: usize = CACHE_SIZE;
const TOTAL_SIZE: usize = PAGE_SIZE_USIZE * TOTAL_PAGES;

fn bench_backend<R>(c: &mut Criterion, backend: &str, read_size: usize)
where
    R: Runner + Default,
    R::Context: Storage + BufferPooler,
{
    c.bench_function(
        &format!("{}/backend={backend} size={read_size}", module_path!()),
        |b| {
            b.iter_custom(|iters| {
                let name = format!("read_{backend}_{read_size}").into_bytes();

                let executor = R::default();
                executor.start(|ctx| async move {
                    let cache_ref = CacheRef::from_pooler(&ctx, PAGE_SIZE, NZUsize!(CACHE_SIZE));

                    // Setup: populate the blob
                    let mut append = create_append(&ctx, &name, cache_ref.clone()).await;
                    let data = vec![0xABu8; TOTAL_SIZE];
                    append.append(&data).await.unwrap();
                    append.sync().await.unwrap();
                    drop(append);

                    // Benchmark: random reads
                    let append = create_append(&ctx, &name, cache_ref).await;
                    let mut buf = vec![0u8; read_size];
                    let max_offset = TOTAL_SIZE - read_size;
                    let mut rng = TestRng::new(42);

                    let start = Instant::now();
                    for _ in 0..iters {
                        // Ensure ~1/100 reads are going to be cache misses.
                        for _ in 0..TOTAL_PAGES * 100 {
                            let offset = rng.random_range(0..=max_offset) as u64;
                            append.read_into(&mut buf, offset).await.unwrap();
                        }
                    }
                    let elapsed = start.elapsed();

                    // Cleanup
                    destroy_append(&ctx, append, &name).await;

                    elapsed
                })
            });
        },
    );
}

pub fn bench(c: &mut Criterion) {
    for read_size in [64, 256, 1024, 4096] {
        bench_backend::<deterministic::Runner>(c, "deterministic", read_size);
        bench_backend::<tokio::Runner>(c, "tokio", read_size);
    }
    #[cfg(feature = "test-utils")]
    for pages in [1, 16, 256] {
        for cold in [false, true] {
            bench_range::<deterministic::Runner>(c, "deterministic", pages, cold);
            bench_range::<tokio::Runner>(c, "tokio", pages, cold);
        }
    }
}

/// Compare contiguous range reads with a cold application cache and with all pages resident.
/// Run with `--features test-utils` to enable explicit cache eviction between samples.
#[cfg(feature = "test-utils")]
fn bench_range<R>(c: &mut Criterion, backend: &str, pages: usize, cold: bool)
where
    R: Runner + Default,
    R::Context: Storage + BufferPooler,
{
    let cache = if cold { "cold" } else { "warm" };
    c.bench_function(
        &format!(
            "{}/backend={backend} pages={pages} cache={cache}",
            module_path!()
        ),
        |b| {
            b.iter_custom(|iters| {
                R::default().start(|ctx| async move {
                    let name = b"read_range";
                    let cache_ref = CacheRef::from_pooler(&ctx, PAGE_SIZE, NZUsize!(512));
                    let mut append = create_append(&ctx, name, cache_ref.clone()).await;
                    let len = pages * PAGE_SIZE_USIZE;
                    append.append(&vec![0xAB; len]).await.unwrap();
                    append.sync().await.unwrap();
                    let mut elapsed = std::time::Duration::ZERO;
                    for _ in 0..iters {
                        if cold {
                            cache_ref.clear();
                        }
                        let start = Instant::now();
                        std::hint::black_box(append.read_at(0, len).await.unwrap());
                        elapsed += start.elapsed();
                    }
                    destroy_append(&ctx, append, name).await;
                    elapsed
                })
            });
        },
    );
}
