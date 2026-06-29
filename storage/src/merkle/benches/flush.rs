//! Benchmark for flushing the journaled Merkle structure's in-memory nodes to the journal.
//!
//! Each measured flush applies a batch of `n` leaves to the in-memory structure (untimed setup),
//! then times [`full::Merkle::flush`], which encodes the un-journaled nodes and appends them to
//! the journal before pruning them from memory. `flush` does not fsync, so the timed region is the
//! encode/append/prune CPU work (the cost this benchmark is meant to surface), not disk latency.
//!
//! Following the `qmdb::chained_growth` model, the structure is rebuilt (and its journal
//! destroyed) every `cycles` flushes so the backing journal doesn't grow without bound over a run.
//! `cycles` scales down as `n` grows so the peak on-disk size stays roughly constant.

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
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

type StandardHasher<H> = merkle::hasher::Standard<H>;

const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000_000);
const PAGE_SIZE: NonZeroU16 = NZU16!(16384);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(512);
const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(2 * 1024 * 1024);

/// Rebuild the structure after roughly this many flushed nodes so the journal stays bounded on
/// disk over a run (~32 bytes/node, so the live journal stays around 64 MiB).
const REBUILD_NODE_BUDGET: usize = 2_000_000;

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

fn bench_flush_family<F: Family>(c: &mut Criterion, family: &'static str) {
    let runner = tokio::Runner::new(Config::default());
    for n in N_LEAVES {
        // Flush moves ~2n nodes; rebuild every `cycles` flushes to cap the journal's on-disk size.
        let cycles = (REBUILD_NODE_BUDGET / (2 * n)).max(1);
        c.bench_function(&format!("{}/n={n} family={family}", module_path!()), |b| {
            b.to_async(&runner).iter_custom(move |iters| async move {
                let ctx = context::get::<Context>();
                let hasher = StandardHasher::<Sha256>::new(ForwardFold);
                let mut rng = StdRng::seed_from_u64(0);
                let mut total = Duration::ZERO;

                // `iters` is the number of flushes to time. Rebuild a fresh structure every
                // `cycles` flushes so the journal it appends to never grows without bound.
                let mut remaining = iters;
                while remaining > 0 {
                    let mut merkle = full::Merkle::<F, _, sha256::Digest, _>::init(
                        ctx.child(family),
                        &hasher,
                        merkle_cfg(&ctx, family),
                    )
                    .await
                    .unwrap();

                    let flushes = (cycles as u64).min(remaining);
                    for _ in 0..flushes {
                        // Untimed: apply a batch of `n` leaves to the in-memory structure.
                        let mut batch = merkle.new_batch();
                        for _ in 0..n {
                            batch = batch.add(&hasher, &sha256::Digest::random(&mut rng));
                        }
                        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
                        merkle.apply_batch(&batch).unwrap();

                        // Timed: flush the freshly applied nodes to the journal.
                        let start = Instant::now();
                        merkle.flush().await.unwrap();
                        total += start.elapsed();
                    }

                    merkle.destroy().await.unwrap();
                    remaining -= flushes;
                }
                total
            });
        });
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
