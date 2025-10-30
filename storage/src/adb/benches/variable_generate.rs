//! Benchmark the generation of a large database with values of varying sizes for each (a)db variant
//! that supports variable-size values.
//!
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::PoolRef,
    create_pool,
    tokio::{Config, Context},
    ThreadPool,
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
    time::{Duration, Instant},
};

const NUM_ELEMENTS: u64 = 1_000;
const NUM_OPERATIONS: u64 = 10_000;
const COMMITS_PER_ITERATION: u64 = 100;
const DELETE_FREQUENCY: u32 = 10; // 1/10th of the updates will be deletes.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(50_000);
const PARTITION_SUFFIX: &str = "any_variable_bench_partition";
const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroUsize = NZUsize!(16384);

/// The number of pages to cache in the buffer pool.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores.
const THREADS: usize = 8;

fn unauth_cfg() -> SConfig<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
    SConfig::<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
        log_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_section: ITEMS_PER_BLOB,
        locations_journal_partition: format!("locations_journal_{PARTITION_SUFFIX}"),
        locations_items_per_blob: ITEMS_PER_BLOB,
        translator: EightCap,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

fn any_cfg(pool: ThreadPool) -> AConfig<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
    AConfig::<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_section: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        translator: EightCap,
        thread_pool: Some(pool),
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

async fn get_unauthenticated(ctx: Context) -> UnauthDb {
    let store_cfg = unauth_cfg();
    Store::init(ctx, store_cfg).await.unwrap()
}

async fn get_any(ctx: Context) -> AnyDb {
    let pool = create_pool(ctx.clone(), THREADS).unwrap();
    let any_cfg = any_cfg(pool);
    Any::init(ctx, any_cfg).await.unwrap()
}

/// Generate a large any db with random data. The function seeds the db with exactly `num_elements`
/// elements by inserting them in order, each with a new random value. Then, it performs
/// `num_operations` over these elements, each selected uniformly at random for each operation. The
/// ratio of updates to deletes is configured with `DELETE_FREQUENCY`. The database is committed
/// after every `commit_frequency` operations.
async fn gen_random_kv<A: Db<Context, <Sha256 as Hasher>::Digest, Vec<u8>, EightCap>>(
    mut db: A,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: u32,
) -> A {
    // Insert a random value for every possible element into the db.
    let mut rng = StdRng::seed_from_u64(42);
    for i in 0u64..num_elements {
        let k = Sha256::hash(&i.to_be_bytes());
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 16) + 24) as usize];
        db.update(k, v).await.unwrap();
    }

    // Randomly update / delete them + randomly commit.
    for _ in 0u64..num_operations {
        let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
        if rng.next_u32() % DELETE_FREQUENCY == 0 {
            db.delete(rand_key).await.unwrap();
            continue;
        }
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 24) + 20) as usize];
        db.update(rand_key, v).await.unwrap();
        if rng.next_u32() % commit_frequency == 0 {
            db.commit().await.unwrap();
        }
    }
    db.commit().await.unwrap();
    db.sync().await.unwrap();
    db.prune(db.inactivity_floor_loc()).await.unwrap();

    db
}

type AnyDb = Any<Context, <Sha256 as Hasher>::Digest, Vec<u8>, Sha256, EightCap>;
type UnauthDb = Store<Context, <Sha256 as Hasher>::Digest, Vec<u8>, EightCap>;

#[derive(Debug, Clone, Copy)]
enum Variant {
    Unauthenticated,
    VariableAny, // unordered
}

impl Variant {
    pub fn name(&self) -> &'static str {
        match self {
            Variant::Unauthenticated => "adb::store",
            Variant::VariableAny => "any::variable",
        }
    }
}

const VARIANTS: [Variant; 2] = [Variant::Unauthenticated, Variant::VariableAny];

/// Benchmark the generation of a large randomly generated any db.
fn bench_variable_generate(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg.clone());
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 10] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 10] {
            for variant in VARIANTS {
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
                            let ctx = context::get::<Context>();
                            let mut total_elapsed = Duration::ZERO;
                            for _ in 0..iters {
                                let start = Instant::now();
                                let commit_frequency = (operations / COMMITS_PER_ITERATION) as u32;
                                match variant {
                                    Variant::Unauthenticated => {
                                        let db = get_unauthenticated(ctx.clone()).await;
                                        let db = gen_random_kv(
                                            db,
                                            elements,
                                            operations,
                                            commit_frequency,
                                        )
                                        .await;
                                        total_elapsed += start.elapsed();
                                        db.destroy().await.unwrap(); // don't time destroy
                                    }
                                    Variant::VariableAny => {
                                        let db = get_any(ctx.clone()).await;
                                        let db = gen_random_kv(
                                            db,
                                            elements,
                                            operations,
                                            commit_frequency,
                                        )
                                        .await;
                                        total_elapsed += start.elapsed();
                                        db.destroy().await.unwrap(); // don't time destroy
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
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_generate
}
