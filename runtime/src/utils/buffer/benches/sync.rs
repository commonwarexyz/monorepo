//! Benchmark end-to-end append and sync cadence.

use super::{CACHE_SIZE, PAGE_SIZE, WRITE_BUFFER_SIZE, create_append, destroy_append};
use commonware_runtime::{
    BufferPooler, Runner, Storage, buffer::paged::CacheRef, deterministic, tokio,
};
use commonware_utils::NZUsize;
use criterion::Criterion;
use std::time::Instant;

const RECORD_SIZE: usize = 256;

fn bench_runner<R>(c: &mut Criterion, runner: &str, per_sync: usize)
where
    R: Runner + Default,
    R::Context: Storage + BufferPooler,
{
    c.bench_function(
        &format!(
            "{}/runner={runner} per_sync={per_sync} record_size={RECORD_SIZE} write_buffer={WRITE_BUFFER_SIZE}",
            module_path!()
        ),
        |b| {
            b.iter_custom(|iters| {
                let name = format!("sync_{runner}_{per_sync}").into_bytes();
                let data = vec![0xABu8; RECORD_SIZE];

                R::default().start(|ctx| async move {
                    let cache_ref = CacheRef::from_pooler(&ctx, PAGE_SIZE, NZUsize!(CACHE_SIZE));
                    let mut writer = create_append(&ctx, &name, cache_ref).await;

                    let start = Instant::now();
                    for _ in 0..iters {
                        for _ in 0..per_sync {
                            writer.append(&data).await.unwrap();
                        }
                        writer.sync().await.unwrap();
                    }
                    let elapsed = start.elapsed();

                    destroy_append(&ctx, writer, &name).await;
                    elapsed
                })
            });
        },
    );
}

pub fn bench(c: &mut Criterion) {
    for per_sync in [1, 16] {
        bench_runner::<deterministic::Runner>(c, "deterministic", per_sync);
        bench_runner::<tokio::Runner>(c, "tokio", per_sync);
    }
}
