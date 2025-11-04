use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::PoolRef,
    create_pool,
    tokio::{Config, Context, Runner},
    Runner as _, ThreadPool,
};
use commonware_storage::{
    adb::{
        any::variable::{Any, Config as AConfig},
        store::{Config as SConfig, Db, Store},
    },
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU64};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Instant,
};

const NUM_ELEMENTS: u64 = 100_000;
const NUM_OPERATIONS: u64 = 1_000_000;
const COMMIT_FREQUENCY: u32 = 10_000;
const DELETE_FREQUENCY: u32 = 10; // 1/10th of the updates will be deletes.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(500_000);
const PARTITION_SUFFIX: &str = "variable_init_bench_partition";

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroUsize = NZUsize!(16384);

/// The number of pages to cache in the buffer pool.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores. This speeds up benchmark setup, but doesn't affect the benchmark
/// timing itself since any::init is single threaded.
const THREADS: usize = 8;

cfg_if::cfg_if! {
    if #[cfg(not(full_bench))] {
        const ELEMENTS: [u64; 1] = [NUM_ELEMENTS];
        const OPERATIONS: [u64; 1] = [NUM_OPERATIONS];
    } else {
        const ELEMENTS: [u64; 2] = [NUM_ELEMENTS, NUM_ELEMENTS * 10];
        const OPERATIONS: [u64; 2] = [NUM_OPERATIONS, NUM_OPERATIONS * 10];
    }
}

fn any_cfg(pool: ThreadPool) -> AConfig<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
    AConfig::<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
        mmr_journal_partition: format!("journal_any_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_any_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log_any_{PARTITION_SUFFIX}"),
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_section: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        translator: EightCap,
        thread_pool: Some(pool),
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

fn store_cfg() -> SConfig<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
    SConfig::<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
        log_partition: format!("log_store_{PARTITION_SUFFIX}"),
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_section: ITEMS_PER_BLOB,
        translator: EightCap,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

fn gen_random_any(cfg: Config, num_elements: u64, num_operations: u64) {
    let runner = Runner::new(cfg.clone());
    runner.start(|ctx| async move {
        let pool = create_pool(ctx.clone(), THREADS).unwrap();
        let any_cfg = any_cfg(pool);
        let db = AnyDb::init(ctx, any_cfg).await.unwrap();
        gen_random_kv(db, num_elements, num_operations).await;
    });
}

fn gen_random_store(cfg: Config, num_elements: u64, num_operations: u64) {
    let runner = Runner::new(cfg.clone());
    runner.start(|ctx| async move {
        let store_cfg = store_cfg();
        let db = Store::init(ctx, store_cfg).await.unwrap();
        gen_random_kv(db, num_elements, num_operations).await;
    });
}

/// Generate a large key-value db with random data. The function seeds the db with exactly
/// `num_elements` elements by inserting them in order, each with a new random value. Then, it
/// performs `num_operations` over these elements, each selected uniformly at random for each
/// operation. The ratio of updates to deletes is configured with `DELETE_FREQUENCY`. The database
/// is committed after every `COMMIT_FREQUENCY` operations.
async fn gen_random_kv<A: Db<Context, <Sha256 as Hasher>::Digest, Vec<u8>, EightCap>>(
    mut db: A,
    num_elements: u64,
    num_operations: u64,
) {
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
            db.commit().await.unwrap();
        }
    }
    db.commit().await.unwrap();
    db.prune(db.inactivity_floor_loc()).await.unwrap();
    db.close().await.unwrap();
}

type AnyDb = Any<Context, <Sha256 as Hasher>::Digest, Vec<u8>, Sha256, EightCap>;

type StoreDb = Store<Context, <Sha256 as Hasher>::Digest, Vec<u8>, EightCap>;

#[derive(Debug, Clone, Copy)]
enum Variant {
    Store,
    Any,
}

impl Variant {
    pub fn name(&self) -> &'static str {
        match self {
            Variant::Store => "store",
            Variant::Any => "any",
        }
    }
}

const VARIANTS: [Variant; 2] = [Variant::Store, Variant::Any];

/// Benchmark the initialization of a large randomly generated any db.
fn bench_variable_init(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg.clone());
    for elements in ELEMENTS {
        for operations in OPERATIONS {
            for variant in VARIANTS {
                match variant {
                    Variant::Any => gen_random_any(cfg.clone(), elements, operations),
                    Variant::Store => gen_random_store(cfg.clone(), elements, operations),
                }
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={} operations={}",
                        module_path!(),
                        variant.name(),
                        elements,
                        operations,
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let pool =
                                commonware_runtime::create_pool(ctx.clone(), THREADS).unwrap();
                            let any_cfg = any_cfg(pool);
                            let store_cfg = store_cfg();
                            let start = Instant::now();
                            for _ in 0..iters {
                                match variant {
                                    Variant::Store => {
                                        let db = StoreDb::init(ctx.clone(), store_cfg.clone())
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                        db.close().await.unwrap();
                                    }
                                    Variant::Any => {
                                        let db = AnyDb::init(ctx.clone(), any_cfg.clone())
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                        db.close().await.unwrap();
                                    }
                                }
                            }

                            start.elapsed()
                        });
                    },
                );

                let runner = Runner::new(cfg.clone());
                runner.start(|ctx| async move {
                    // Clean up the databases after the benchmark.
                    let pool = commonware_runtime::create_pool(ctx.clone(), THREADS).unwrap();
                    let store_cfg = store_cfg();
                    let db = StoreDb::init(ctx.clone(), store_cfg).await.unwrap();
                    db.destroy().await.unwrap();
                    let any_cfg = any_cfg(pool);
                    let db = AnyDb::init(ctx.clone(), any_cfg).await.unwrap();
                    db.destroy().await.unwrap();
                });
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_init
}
