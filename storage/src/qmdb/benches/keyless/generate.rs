//! Benchmark the generation of a large randomly generated keyless database.

use commonware_cryptography::Sha256;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::PoolRef,
    tokio::{Config, Context},
    RayonPoolSpawner,
};
use commonware_storage::qmdb::{
    keyless::{Config as KConfig, Keyless},
    Durable, Merkleized, NonDurable, Unmerkleized,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

const NUM_OPERATIONS: u64 = 10_000;
const COMMIT_FREQUENCY: u32 = 25;
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(50_000);
const PARTITION_SUFFIX: &str = "keyless_bench_partition";

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroU16 = NZU16!(16384);

/// The number of pages to cache in the buffer pool.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores.
const THREADS: NonZeroUsize = NZUsize!(8);

fn keyless_cfg<S: Strategy>(strategy: S) -> KConfig<(commonware_codec::RangeCfg<usize>, ()), S> {
    KConfig::<(commonware_codec::RangeCfg<usize>, ()), S> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: NZUsize!(1024),
        log_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_section: ITEMS_PER_BLOB,
        log_write_buffer: NZUsize!(1024),
        log_compression: None,
        strategy,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

#[derive(Debug, Clone, Copy)]
enum Parallelism {
    Sequential,
    Parallel,
}

impl Parallelism {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Sequential => "sequential",
            Self::Parallel => "parallel",
        }
    }
}

const PARALLELISMS: [Parallelism; 2] = [Parallelism::Sequential, Parallelism::Parallel];

/// Clean (Merkleized, Durable) db type alias for Keyless (Sequential).
type KeylessDbSeq = Keyless<Context, Vec<u8>, Sha256, Merkleized<Sha256>, Durable, Sequential>;

/// Mutable (Unmerkleized, NonDurable) type alias for Keyless (Sequential).
type KeylessMutableSeq = Keyless<Context, Vec<u8>, Sha256, Unmerkleized, NonDurable, Sequential>;

/// Clean (Merkleized, Durable) db type alias for Keyless (Parallel).
type KeylessDbPar = Keyless<Context, Vec<u8>, Sha256, Merkleized<Sha256>, Durable, Rayon>;

/// Mutable (Unmerkleized, NonDurable) type alias for Keyless (Parallel).
type KeylessMutablePar = Keyless<Context, Vec<u8>, Sha256, Unmerkleized, NonDurable, Rayon>;

/// Generate a keyless db by appending `num_operations` random values in total. The database is
/// committed after every `COMMIT_FREQUENCY` operations.
async fn gen_random_keyless_seq(ctx: Context, num_operations: u64) -> KeylessDbSeq {
    let keyless_cfg = keyless_cfg(Sequential);
    let clean = KeylessDbSeq::init(ctx, keyless_cfg).await.unwrap();

    // Convert to mutable state for operations.
    let mut db: KeylessMutableSeq = clean.into_mutable();

    // Randomly append.
    let mut rng = StdRng::seed_from_u64(42);
    for _ in 0u64..num_operations {
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 300) + 10) as usize];
        db.append(v).await.unwrap();
        if rng.next_u32() % COMMIT_FREQUENCY == 0 {
            let (durable, _) = db.commit(None).await.unwrap();
            db = durable.into_mutable();
        }
    }
    let (durable, _) = db.commit(None).await.unwrap();
    let mut clean = durable.into_merkleized();
    clean.sync().await.unwrap();

    clean
}

/// Generate a keyless db by appending `num_operations` random values in total. The database is
/// committed after every `COMMIT_FREQUENCY` operations.
async fn gen_random_keyless_par(ctx: Context, num_operations: u64) -> KeylessDbPar {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    let keyless_cfg = keyless_cfg(Rayon::with_pool(pool));
    let clean = KeylessDbPar::init(ctx, keyless_cfg).await.unwrap();

    // Convert to mutable state for operations.
    let mut db: KeylessMutablePar = clean.into_mutable();

    // Randomly append.
    let mut rng = StdRng::seed_from_u64(42);
    for _ in 0u64..num_operations {
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 300) + 10) as usize];
        db.append(v).await.unwrap();
        if rng.next_u32() % COMMIT_FREQUENCY == 0 {
            let (durable, _) = db.commit(None).await.unwrap();
            db = durable.into_mutable();
        }
    }
    let (durable, _) = db.commit(None).await.unwrap();
    let mut clean = durable.into_merkleized();
    clean.sync().await.unwrap();

    clean
}

/// Benchmark the generation of a large randomly generated keyless db.
fn bench_keyless_generate(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg);
    for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 2] {
        for parallelism in PARALLELISMS {
            c.bench_function(
                &format!(
                    "{}/parallelism={} operations={}",
                    module_path!(),
                    parallelism.name(),
                    operations,
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        let mut total_elapsed = Duration::ZERO;
                        for _ in 0..iters {
                            let start = Instant::now();
                            match parallelism {
                                Parallelism::Sequential => {
                                    let mut db =
                                        gen_random_keyless_seq(ctx.clone(), operations).await;
                                    db.sync().await.unwrap();
                                    total_elapsed += start.elapsed();
                                    db.destroy().await.unwrap();
                                }
                                Parallelism::Parallel => {
                                    let mut db =
                                        gen_random_keyless_par(ctx.clone(), operations).await;
                                    db.sync().await.unwrap();
                                    total_elapsed += start.elapsed();
                                    db.destroy().await.unwrap();
                                }
                            }
                        }

                        total_elapsed
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_keyless_generate
}
