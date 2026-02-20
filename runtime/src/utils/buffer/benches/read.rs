//! Benchmark read performance at random offsets.

use super::{create_append, destroy_append, CACHE_SIZE, PAGE_SIZE};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner as _};
use commonware_utils::NZUsize;
use criterion::Criterion;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::Instant;

// Use cache size logical pages so all data fits in cache (testing buffer performance, not disk).
const TOTAL_PAGES: usize = CACHE_SIZE;

pub fn bench(c: &mut Criterion) {
    for read_size in [64, 256, 1024, 4096] {
        let name = format!("read_{read_size}").into_bytes();

        c.bench_function(&format!("{}/size={}", module_path!(), read_size), |b| {
            b.iter_custom(|iters| {
                let name = name.clone();

                let executor = deterministic::Runner::default();
                executor.start(|ctx| async move {
                    let cache_ref = CacheRef::from_pooler(&ctx, PAGE_SIZE, NZUsize!(CACHE_SIZE));
                    let logical_page_size = cache_ref.page_size() as usize;
                    let total_size = logical_page_size * TOTAL_PAGES;
                    // Setup: populate the blob
                    let append = create_append(&ctx, &name, cache_ref.clone()).await;
                    let data = vec![0xABu8; total_size];
                    append.append(&data).await.unwrap();
                    append.sync().await.unwrap();
                    drop(append);

                    // Benchmark: random reads
                    let append = create_append(&ctx, &name, cache_ref.clone()).await;
                    let max_offset = total_size.saturating_sub(read_size);
                    let mut rng = StdRng::seed_from_u64(42);

                    let start = Instant::now();
                    for _ in 0..iters {
                        // Exercise many random offsets; after warmup these should be cache hits.
                        for _ in 0..TOTAL_PAGES * 100 {
                            let offset = rng.gen_range(0..=max_offset) as u64;
                            let _ = append.read_at(offset, read_size).await.unwrap();
                        }
                    }
                    let elapsed = start.elapsed();

                    // Cleanup
                    destroy_append(&ctx, append, &name).await;

                    elapsed
                })
            });
        });
    }
}
