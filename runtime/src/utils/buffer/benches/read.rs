//! Benchmark read performance at random offsets.

use super::{create_append, destroy_append, CACHE_SIZE, PAGE_SIZE, PAGE_SIZE_USIZE};
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, tokio, BufferPooler, Metrics, Runner, Storage,
    Supervisor,
};
use commonware_utils::NZUsize;
use criterion::Criterion;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::Instant;

// Use cache size pages so all data fits in cache (testing buffer performance, not disk).
const TOTAL_PAGES: usize = CACHE_SIZE;
const TOTAL_SIZE: usize = PAGE_SIZE_USIZE * TOTAL_PAGES;

fn bench_backend<R>(c: &mut Criterion, backend: &str, read_size: usize)
where
    R: Runner + Default,
    R::Context: Storage + BufferPooler + Metrics,
{
    c.bench_function(
        &format!("{}/backend={backend} size={read_size}", module_path!()),
        |b| {
            b.iter_custom(|iters| {
                let name = format!("read_{backend}_{read_size}").into_bytes();

                let executor = R::default();
                executor.start(|ctx| async move {
                    let cache_ref =
                        CacheRef::from_pooler(ctx.child("cache"), PAGE_SIZE, NZUsize!(CACHE_SIZE));

                    // Setup: populate the blob
                    let append = create_append(ctx.child("setup"), &name, cache_ref.clone()).await;
                    let data = vec![0xABu8; TOTAL_SIZE];
                    append.append(&data).await.unwrap();
                    append.sync().await.unwrap();
                    drop(append);

                    // Benchmark: random reads
                    let append = create_append(ctx.child("bench"), &name, cache_ref).await;
                    let mut buf = vec![0u8; read_size];
                    let max_offset = TOTAL_SIZE - read_size;
                    let mut rng = StdRng::seed_from_u64(42);

                    let start = Instant::now();
                    for _ in 0..iters {
                        // Ensure ~1/100 reads are going to be cache misses.
                        for _ in 0..TOTAL_PAGES * 100 {
                            let offset = rng.gen_range(0..=max_offset) as u64;
                            append.read_into(&mut buf, offset).await.unwrap();
                        }
                    }
                    let elapsed = start.elapsed();

                    // Cleanup
                    destroy_append(ctx.child("destroy"), append, &name).await;

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
}
