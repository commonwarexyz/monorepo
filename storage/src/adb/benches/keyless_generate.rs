use commonware_cryptography::Sha256;
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::PoolRef,
    create_pool,
    tokio::{Config, Context},
    ThreadPool,
};
use commonware_storage::adb::keyless::{Config as KConfig, Keyless};
use commonware_utils::{NZUsize, NZU64};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

const NUM_OPERATIONS: u64 = 10_000;
const COMMIT_FREQUENCY: u32 = 25;
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(50_000);
const PARTITION_SUFFIX: &str = "keyless_bench_partition";

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroUsize = NZUsize!(16384);

/// The number of pages to cache in the buffer pool.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores.
const THREADS: usize = 8;

fn keyless_cfg(pool: ThreadPool) -> KConfig<(commonware_codec::RangeCfg, ())> {
    KConfig::<(commonware_codec::RangeCfg, ())> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: NZUsize!(1024),
        log_journal_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_section: ITEMS_PER_BLOB,
        log_write_buffer: NZUsize!(1024),
        log_compression: None,
        locations_journal_partition: format!("locations_journal_{PARTITION_SUFFIX}"),
        locations_items_per_blob: ITEMS_PER_BLOB,
        locations_write_buffer: NZUsize!(1024),
        thread_pool: Some(pool),
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

/// Generate a keyless db by appending `num_operations` random values in total. The database is
/// committed after every `COMMIT_FREQUENCY` operations.
async fn gen_random_keyless(ctx: Context, num_operations: u64) -> KeylessDb {
    let pool = create_pool(ctx.clone(), THREADS).unwrap();
    let keyless_cfg = keyless_cfg(pool);
    let mut db = Keyless::<_, Vec<u8>, Sha256>::init(ctx, keyless_cfg)
        .await
        .unwrap();

    // Randomly append.
    let mut rng = StdRng::seed_from_u64(42);
    for _ in 0u64..num_operations {
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 300) + 10) as usize];
        db.append(v).await.unwrap();
        if rng.next_u32() % COMMIT_FREQUENCY == 0 {
            db.commit(None).await.unwrap();
        }
    }
    db.commit(None).await.unwrap();
    db.sync().await.unwrap();

    db
}

type KeylessDb = Keyless<Context, Vec<u8>, Sha256>;

/// Benchmark the generation of a large randomly generated keyless db.
fn bench_keyless_generate(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg.clone());
    for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 2] {
        c.bench_function(
            &format!("{}/operations={}", module_path!(), operations,),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<Context>();
                    let mut total_elapsed = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        let mut db = gen_random_keyless(ctx.clone(), operations).await;
                        db.sync().await.unwrap();
                        total_elapsed += start.elapsed();

                        db.destroy().await.unwrap(); // don't time destroy
                    }

                    total_elapsed
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_keyless_generate
}
