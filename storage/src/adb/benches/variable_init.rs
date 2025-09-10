use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::PoolRef,
    create_pool,
    tokio::{Config, Context, Runner},
    Runner as _, ThreadPool,
};
use commonware_storage::{
    adb::any::variable::{Any, Config as AConfig},
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU64};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Instant,
};
use tracing::info;

const NUM_ELEMENTS: u64 = 100_000;
const NUM_OPERATIONS: u64 = 1_000_000;
const COMMIT_FREQUENCY: u32 = 10_000;
const DELETE_FREQUENCY: u32 = 10; // 1/10th of the updates will be deletes.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(500_000);
const PARTITION_SUFFIX: &str = "any_bench_partition";

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroUsize = NZUsize!(16384);

/// The number of pages to cache in the buffer pool.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores. This speeds up benchmark setup, but doesn't affect the benchmark
/// timing itself since any::init is single threaded.
const THREADS: usize = 8;

fn any_cfg(pool: ThreadPool) -> AConfig<EightCap, (commonware_codec::RangeCfg, ())> {
    AConfig::<EightCap, (commonware_codec::RangeCfg, ())> {
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
        translator: EightCap,
        thread_pool: Some(pool),
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

/// Generate a large any db with random data. The function seeds the db with exactly `num_elements`
/// elements by inserting them in order, each with a new random value. Then, it performs
/// `num_operations` over these elements, each selected uniformly at random for each operation. The
/// ratio of updates to deletes is configured with `DELETE_FREQUENCY`. The database is committed
/// after every `COMMIT_FREQUENCY` operations.
fn gen_random_any(cfg: Config, num_elements: u64, num_operations: u64) {
    let runner = Runner::new(cfg.clone());
    runner.start(|ctx| async move {
        info!("starting DB generation...");
        let pool = create_pool(ctx.clone(), THREADS).unwrap();
        let any_cfg = any_cfg(pool);
        let mut db = AnyDb::init(ctx, any_cfg).await.unwrap();

        // Insert a random value for every possible element into the db.
        let mut rng = StdRng::seed_from_u64(42);
        for i in 0u64..num_elements {
            let k = Sha256::hash(&i.to_be_bytes());
            // Generate a random value with a length between 24 and 40 bytes (avg = 32).
            let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 16) + 24) as usize];
            db.update(k, v).await.unwrap();
        }

        // Randomly update / delete them.
        for _ in 0u64..num_operations {
            let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
            if rng.next_u32() % DELETE_FREQUENCY == 0 {
                db.delete(rand_key).await.unwrap();
                continue;
            }
            // Generate a random value with a length between 20 and 44 bytes (avg = 32).
            let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 24) + 20) as usize];
            db.update(rand_key, v).await.unwrap();
            if rng.next_u32() % COMMIT_FREQUENCY == 0 {
                db.commit(None).await.unwrap();
            }
        }
        db.commit(None).await.unwrap();
        info!(
            op_count = db.op_count(),
            oldest_retained_loc = db.oldest_retained_loc().unwrap(),
            "DB generated.",
        );
        db.prune(db.inactivity_floor_loc()).await.unwrap();
        db.close().await.unwrap();
    });
}

type AnyDb = Any<Context, <Sha256 as Hasher>::Digest, Vec<u8>, Sha256, EightCap>;

/// Benchmark the initialization of a large randomly generated any db.
fn bench_variable_init(c: &mut Criterion) {
    tracing_subscriber::fmt().try_init().ok();
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg.clone());
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 2] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 2] {
            info!(elements, operations, "benchmarking variable::Any init");
            gen_random_any(cfg.clone(), elements, operations);

            c.bench_function(
                &format!(
                    "{}/elements={} operations={}",
                    module_path!(),
                    elements,
                    operations,
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<commonware_runtime::tokio::Context>();
                        let pool = commonware_runtime::create_pool(ctx.clone(), THREADS).unwrap();
                        let any_cfg = any_cfg(pool);
                        let start = Instant::now();
                        for _ in 0..iters {
                            let db = AnyDb::init(ctx.clone(), any_cfg.clone()).await.unwrap();
                            assert_ne!(db.op_count(), 0);
                            db.close().await.unwrap();
                        }

                        start.elapsed()
                    });
                },
            );

            let runner = Runner::new(cfg.clone());
            runner.start(|ctx| async move {
                info!("cleaning up db...");
                let pool = commonware_runtime::create_pool(ctx.clone(), THREADS).unwrap();
                let any_cfg = any_cfg(pool);
                // Clean up the database after the benchmark.
                let db = AnyDb::init(ctx.clone(), any_cfg.clone()).await.unwrap();
                db.destroy().await.unwrap();
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_init
}
