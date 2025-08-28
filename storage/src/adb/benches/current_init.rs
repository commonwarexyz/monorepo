use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::PoolRef,
    create_pool,
    tokio::{Config, Context, Runner},
    Runner as _, ThreadPool,
};
use commonware_storage::{
    adb::current::{Config as CConfig, Current},
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
const PARTITION_SUFFIX: &str = "current_bench_partition";

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroUsize = NZUsize!(16384);

/// The number of pages to cache in the buffer pool.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// current_init is multi-threaded, and will have different performance for different number of
/// threads. So we benchmark with no thread pool and 8 threads to compare single-threaded and
/// multi-threaded performance.
const SINGLE_THREADED: usize = 1;
const MULTI_THREADED: usize = 8;

/// Chunk size for the current ADB bitmap - must be a power of 2 (as assumed in
/// current::grafting_height()) and a multiple of digest size.
const CHUNK_SIZE: usize = 32;

fn current_cfg(pool: Option<ThreadPool>) -> CConfig<EightCap> {
    CConfig::<EightCap> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: NZUsize!(1024),
        log_journal_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: NZUsize!(1024),
        bitmap_metadata_partition: format!("bitmap_metadata_{PARTITION_SUFFIX}"),
        translator: EightCap,
        thread_pool: pool,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        pruning_delay: 10,
    }
}

/// Generate a large current db with random data. The function seeds the db with exactly
/// `num_elements` elements by inserting them in order, each with a new random value. Then, it
/// performs `num_operations` over these elements, each selected uniformly at random for each
/// operation. The ratio of updates to deletes is configured with `DELETE_FREQUENCY`. The database
/// is committed after every `COMMIT_FREQUENCY` operations.
fn gen_random_current(cfg: Config, num_elements: u64, num_operations: u64, threads: usize) {
    let runner = Runner::new(cfg.clone());
    runner.start(|ctx| async move {
        info!("starting DB generation...");
        let pool = if threads == 1 {
            None
        } else {
            Some(create_pool(ctx.clone(), threads).unwrap())
        };
        let current_cfg = current_cfg(pool);
        let mut db = Current::<_, _, _, Sha256, EightCap, CHUNK_SIZE>::init(ctx, current_cfg)
            .await
            .unwrap();

        // Insert a random value for every possible element into the db.
        let mut rng = StdRng::seed_from_u64(42);
        for i in 0u64..num_elements {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = Sha256::hash(&rng.next_u32().to_be_bytes());
            db.update(k, v).await.unwrap();
        }

        // Randomly update / delete them.
        for _ in 0u64..num_operations {
            let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
            if rng.next_u32() % DELETE_FREQUENCY == 0 {
                db.delete(rand_key).await.unwrap();
                continue;
            }
            let v = Sha256::hash(&rng.next_u32().to_be_bytes());
            db.update(rand_key, v).await.unwrap();
            if rng.next_u32() % COMMIT_FREQUENCY == 0 {
                db.commit().await.unwrap();
            }
        }
        db.commit().await.unwrap();
        info!(
            op_count = db.op_count(),
            oldest_retained_loc = db.oldest_retained_loc().unwrap(),
            "DB generated.",
        );
        db.close().await.unwrap();
    });
}

type CurrentDb = Current<
    Context,
    <Sha256 as Hasher>::Digest,
    <Sha256 as Hasher>::Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;

/// Benchmark the initialization of a large randomly generated current db.
fn bench_current_init(c: &mut Criterion) {
    tracing_subscriber::fmt().try_init().ok();
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg.clone());

    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 2] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 2] {
            for (multithreaded_name, threads) in [("off", SINGLE_THREADED), ("on", MULTI_THREADED)]
            {
                info!(elements, operations, threads, "benchmarking current init");
                gen_random_current(cfg.clone(), elements, operations, threads);

                c.bench_function(
                    &format!(
                        "{}/elements={} operations={} multithreaded={}",
                        module_path!(),
                        elements,
                        operations,
                        multithreaded_name,
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let pool = if threads == 1 {
                                None
                            } else {
                                Some(commonware_runtime::create_pool(ctx.clone(), threads).unwrap())
                            };
                            let current_cfg = current_cfg(pool);
                            let start = Instant::now();
                            for _ in 0..iters {
                                let db = CurrentDb::init(ctx.clone(), current_cfg.clone())
                                    .await
                                    .unwrap();
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
                    let pool = if threads == 1 {
                        None
                    } else {
                        Some(commonware_runtime::create_pool(ctx.clone(), threads).unwrap())
                    };
                    let current_cfg = current_cfg(pool);
                    // Clean up the database after the benchmark.
                    let db = CurrentDb::init(ctx.clone(), current_cfg.clone())
                        .await
                        .unwrap();
                    db.destroy().await.unwrap();
                });
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_current_init
}
