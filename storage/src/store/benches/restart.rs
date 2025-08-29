use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::PoolRef,
    tokio::{Config, Context, Runner},
    Runner as _,
};
use commonware_storage::{
    store::{Config as SConfig, Store},
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
const PARTITION_SUFFIX: &str = "store_bench_partition";

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroUsize = NZUsize!(16_384);

/// The number of pages to cache in the buffer pool.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

fn store_cfg() -> SConfig<EightCap, ()> {
    SConfig::<EightCap, ()> {
        log_journal_partition: format!("log_{PARTITION_SUFFIX}"),
        log_write_buffer: NZUsize!(64 * 1024),
        log_compression: None,
        log_codec_config: (),
        log_items_per_section: ITEMS_PER_BLOB,
        locations_journal_partition: format!("locations_{PARTITION_SUFFIX}"),
        locations_items_per_blob: ITEMS_PER_BLOB,
        translator: EightCap,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

/// Generate a large store db with random data. The function seeds the db with exactly `num_elements`
/// elements by inserting them in order, each with a new random value. Then, it performs
/// `num_operations` over these elements, each selected uniformly at random for each operation. The
/// ratio of updates to deletes is configured with `DELETE_FREQUENCY`. The database is committed
/// after every `COMMIT_FREQUENCY` operations.
fn gen_random_store(cfg: Config, num_elements: u64, num_operations: u64) {
    let runner = Runner::new(cfg.clone());
    runner.start(|ctx| async move {
        let store_cfg = store_cfg();
        let mut db = Store::<_, _, _, EightCap>::init(ctx, store_cfg)
            .await
            .unwrap();
        let metadata = Sha256::fill(0);

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
                db.commit(Some(metadata)).await.unwrap();
            }
        }
        db.commit(Some(metadata)).await.unwrap();
        db.close().await.unwrap();
    });
}

type StoreDb = Store<Context, <Sha256 as Hasher>::Digest, <Sha256 as Hasher>::Digest, EightCap>;

/// Benchmark the initialization of a large randomly generated store db.
fn bench_restart(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg.clone());
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 2] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 2] {
            // Create a large store db.
            gen_random_store(cfg.clone(), elements, operations);

            // Restart the db.
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
                        let store_cfg = store_cfg();
                        let start = Instant::now();
                        for _ in 0..iters {
                            let db = StoreDb::init(ctx.clone(), store_cfg.clone()).await.unwrap();
                            db.close().await.unwrap();
                        }

                        start.elapsed()
                    });
                },
            );

            let runner = Runner::new(cfg.clone());
            runner.start(|ctx| async move {
                let db = StoreDb::init(ctx, store_cfg()).await.unwrap();
                db.destroy().await.unwrap();
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_restart
}
