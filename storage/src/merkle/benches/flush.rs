//! Benchmark for flushing the journaled Merkle structure's in-memory nodes to the journal.
//!
//! Each iteration applies a batch of `n` leaves to the in-memory structure (untimed setup), then
//! times [`full::Merkle::flush`], which encodes the un-journaled nodes and appends them to the
//! journal before pruning them from memory. `flush` does not fsync, so the timed region is the
//! encode/append/prune CPU work (the cost this benchmark is meant to surface), not disk latency.

use commonware_cryptography::{sha256, Sha256};
use commonware_math::algebra::Random as _;
use commonware_parallel::Sequential;
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
    BufferPooler, Supervisor as _,
};
use commonware_storage::merkle::{self, full, Bagging::ForwardFold, Family};
use commonware_utils::{NZUsize, NZU16, NZU64};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::{
    num::{NonZeroU16, NonZeroUsize},
    time::{Duration, Instant},
};

type StandardHasher<H> = merkle::hasher::Standard<H>;

const ITEMS_PER_BLOB: std::num::NonZeroU64 = NZU64!(10_000_000);
const PAGE_SIZE: NonZeroU16 = NZU16!(16384);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(512);
const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(2 * 1024 * 1024);

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 2] = [10_000, 100_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 3] = [10_000, 100_000, 1_000_000];

fn merkle_cfg(ctx: &impl BufferPooler, family: &str) -> full::Config<Sequential> {
    full::Config {
        journal_partition: format!("journal-bench-flush-{family}"),
        metadata_partition: format!("metadata-bench-flush-{family}"),
        items_per_blob: ITEMS_PER_BLOB,
        write_buffer: WRITE_BUFFER_SIZE,
        strategy: Sequential,
        page_cache: CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

fn bench_flush_family<F: Family>(c: &mut Criterion, family: &str) {
    let runner = tokio::Runner::new(Config::default());
    for n in N_LEAVES {
        c.bench_function(
            &format!("{}/n={n} family={family}", module_path!()),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<Context>();
                    let hasher = StandardHasher::<Sha256>::new(ForwardFold);
                    let mmr = full::Merkle::<F, _, sha256::Digest, _>::init(
                        ctx.child("mmr"),
                        &hasher,
                        merkle_cfg(&ctx, family),
                    )
                    .await
                    .unwrap();

                    let mut rng = StdRng::seed_from_u64(0);
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // Untimed: apply a batch of `n` leaves to the in-memory structure.
                        let mut batch = mmr.new_batch();
                        for _ in 0..n {
                            batch = batch.add(&hasher, &sha256::Digest::random(&mut rng));
                        }
                        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
                        mmr.apply_batch(&batch).unwrap();

                        // Timed: flush the freshly applied nodes to the journal.
                        let start = Instant::now();
                        mmr.flush().await.unwrap();
                        total += start.elapsed();
                    }
                    mmr.destroy().await.unwrap();
                    total
                });
            },
        );
    }
}

fn bench_flush(c: &mut Criterion) {
    bench_flush_family::<commonware_storage::mmr::Family>(c, "mmr");
    bench_flush_family::<commonware_storage::mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_flush
}
