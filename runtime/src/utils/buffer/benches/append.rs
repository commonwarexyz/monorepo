//! Benchmark sequential append performance.

use super::{create_append, destroy_append, CACHE_SIZE, PAGE_SIZE};
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, tokio, BufferPooler, Metrics, Runner, Storage,
};
use commonware_utils::NZUsize;
use criterion::Criterion;
use std::time::Instant;

fn bench_backend<R>(c: &mut Criterion, backend: &str, chunk_size: usize)
where
    R: Runner + Default,
    R::Context: Storage + BufferPooler + Metrics,
{
    c.bench_function(
        &format!("{}/backend={backend} chunk={chunk_size}", module_path!()),
        |b| {
            b.iter_custom(|iters| {
                let name = format!("append_seq_{backend}_{chunk_size}").into_bytes();
                let data = vec![0xABu8; chunk_size];

                let executor = R::default();
                executor.start(|ctx| async move {
                    let cache_ref = CacheRef::from_pooler(
                        ctx.with_label("cache"),
                        PAGE_SIZE,
                        NZUsize!(CACHE_SIZE),
                    );
                    let append = create_append(&ctx, &name, cache_ref).await;

                    let start = Instant::now();
                    for _ in 0..iters {
                        // Write double the bytes that can be held by the cache.
                        for _ in 0..(CACHE_SIZE * PAGE_SIZE.get() as usize / chunk_size) * 2 {
                            append.append(&data).await.unwrap();
                        }
                    }
                    let elapsed = start.elapsed();

                    destroy_append(&ctx, append, &name).await;

                    elapsed
                })
            });
        },
    );
}

pub fn bench(c: &mut Criterion) {
    for chunk_size in [64, 256, 1024, 4096] {
        bench_backend::<deterministic::Runner>(c, "deterministic", chunk_size);
        bench_backend::<tokio::Runner>(c, "tokio", chunk_size);
    }
}
