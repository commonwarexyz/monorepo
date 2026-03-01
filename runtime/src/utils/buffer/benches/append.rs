//! Benchmark sequential append performance.

use super::{create_append, destroy_append, CACHE_SIZE, PAGE_SIZE};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner as _};
use commonware_utils::NZUsize;
use criterion::Criterion;
use std::time::Instant;

pub fn bench(c: &mut Criterion) {
    for chunk_size in [64, 256, 1024, 4096] {
        c.bench_function(&format!("{}/chunk={}", module_path!(), chunk_size), |b| {
            b.iter_custom(|iters| {
                let name = format!("append_seq_{chunk_size}").into_bytes();
                let data = vec![0xABu8; chunk_size];

                let executor = deterministic::Runner::default();
                executor.start(|ctx| async move {
                    let cache_ref =
                        CacheRef::from_pooler_physical(&ctx, PAGE_SIZE, NZUsize!(CACHE_SIZE));
                    let logical_page_size = cache_ref.logical_page_size() as usize;
                    let append = create_append(&ctx, &name, cache_ref).await;

                    let start = Instant::now();
                    for _ in 0..iters {
                        // Write double the bytes that can be held by the cache.
                        for _ in 0..(CACHE_SIZE * logical_page_size / chunk_size) * 2 {
                            append.append(&data).await.unwrap();
                        }
                    }
                    let elapsed = start.elapsed();

                    destroy_append(&ctx, append, &name).await;

                    elapsed
                })
            });
        });
    }
}
