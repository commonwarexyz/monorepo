use commonware_cryptography::{hash, Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    create_pool,
    tokio::{Config, Context, Runner},
    Runner as _, ThreadPool,
};
use commonware_storage::{
    adb::any::{Any, Config as AConfig},
    index::translator::EightCap,
};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::Instant;
use tracing::info;

const NUM_ELEMENTS: u64 = 100_000;
const NUM_OPERATIONS: u64 = 1_000_000;
const COMMIT_FREQUENCY: u32 = 10_000;
const DELETE_FREQUENCY: u32 = 10; // 1/10th of the updates will be deletes.
const ITEMS_PER_BLOB: u64 = 500_000;
const PARTITION_SUFFIX: &str = "any_bench_partition";

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores. This speeds up benchmark setup, but doesn't affect the benchmark
/// timing itself since any::init is single threaded.
const THREADS: usize = 8;

fn any_cfg(pool: ThreadPool) -> AConfig<EightCap> {
    AConfig::<EightCap> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: 1024,
        log_journal_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: 1024,
        translator: EightCap,
        pool: Some(pool),
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
        info!("Starting DB generation...");
        let pool = create_pool(ctx.clone(), THREADS).unwrap();
        let any_cfg = any_cfg(pool);
        let mut db = Any::<_, _, _, Sha256, EightCap>::init(ctx, any_cfg)
            .await
            .unwrap();

        // Insert a random value for every possible element into the db.
        let mut rng = StdRng::seed_from_u64(42);
        for i in 0u64..num_elements {
            let k = hash(&i.to_be_bytes());
            let v = hash(&rng.next_u32().to_be_bytes());
            db.update(k, v).await.unwrap();
        }

        // Randomly update / delete them.
        for _ in 0u64..num_operations {
            let rand_key = hash(&(rng.next_u64() % num_elements).to_be_bytes());
            if rng.next_u32() % DELETE_FREQUENCY == 0 {
                db.delete(rand_key).await.unwrap();
                continue;
            }
            let v = hash(&rng.next_u32().to_be_bytes());
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

/// Benchmark the initialization of a large randomly generated any db.
fn bench_any_init(c: &mut Criterion) {
    tracing_subscriber::fmt().try_init().ok();
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg.clone());
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 2] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 2] {
            info!(elements, operations, "Benchmarking any init.",);
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
                            let db = Any::<
                                Context,
                                <Sha256 as Hasher>::Digest,
                                <Sha256 as Hasher>::Digest,
                                Sha256,
                                EightCap,
                            >::init(
                                ctx.clone(), any_cfg.clone()
                            )
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
                info!("Cleaning up db...");
                let pool = commonware_runtime::create_pool(ctx.clone(), THREADS).unwrap();
                let any_cfg = any_cfg(pool);
                // Clean up the database after the benchmark.
                let db = Any::<
                    Context,
                    <Sha256 as Hasher>::Digest,
                    <Sha256 as Hasher>::Digest,
                    Sha256,
                    EightCap,
                >::init(ctx.clone(), any_cfg.clone())
                .await
                .unwrap();
                db.destroy().await.unwrap();
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_any_init
}
