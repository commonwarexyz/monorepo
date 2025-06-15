use std::time::Instant;

use commonware_cryptography::{hash, Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context, Runner},
    Runner as _, ThreadPool,
};
use commonware_storage::{
    adb::any::{Any, Config as AConfig},
    index::translator::EightCap,
};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};

const NUM_ELEMENTS: u64 = 100_000;
const NUM_OPERATIONS: u64 = 1_000_000;
const COMMIT_FREQUENCY: u32 = 10_000;
const DELETE_FREQUENCY: u32 = 10; // 1/10th of the updates will be deletes.
const PARTITION_SUFFIX: &str = "anydb_bench_partition";

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores. This speeds up benchmark setup, but doesn't affect the benchmark
/// timing itself since any::init is single threaded.
const THREADS: usize = 8;

fn any_cfg(pool: ThreadPool) -> AConfig<EightCap> {
    AConfig::<EightCap> {
        mmr_journal_partition: format!("journal_{}", PARTITION_SUFFIX),
        mmr_metadata_partition: format!("metadata_{}", PARTITION_SUFFIX),
        mmr_items_per_blob: 10_000,
        mmr_write_buffer: 1024,
        log_journal_partition: format!("log_journal_{}", PARTITION_SUFFIX),
        log_items_per_blob: 10_000,
        log_write_buffer: 1024,
        translator: EightCap,
        pool: Some(pool),
    }
}

// Generate a large any db with random data.
fn gen_random_any(cfg: Config) {
    let runner = Runner::new(cfg.clone());
    runner.start(|ctx| async move {
        let pool = commonware_runtime::create_pool(ctx.clone(), THREADS).unwrap();
        let any_cfg = any_cfg(pool);
        let mut anydb = Any::<_, _, _, Sha256, EightCap>::init(ctx, any_cfg)
            .await
            .unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        for i in 0u64..NUM_ELEMENTS {
            let k = hash(&i.to_be_bytes());
            let v = hash(&rng.next_u32().to_be_bytes());
            anydb.update(k, v).await.unwrap();
        }

        // Randomly update / delete them.
        for _ in 0u64..NUM_OPERATIONS {
            let rand_key = hash(&(rng.next_u64() % NUM_ELEMENTS).to_be_bytes());
            if rng.next_u32() % DELETE_FREQUENCY == 0 {
                anydb.delete(rand_key).await.unwrap();
                continue;
            }
            let v = hash(&rng.next_u32().to_be_bytes());
            anydb.update(rand_key, v).await.unwrap();
            if rng.next_u32() % COMMIT_FREQUENCY == 0 {
                anydb.commit().await.unwrap();
            }
        }
        anydb.commit().await.unwrap();
        anydb.close().await.unwrap();
    });
}

/// Benchmark the initialization of a large randomly generated any db.
fn bench_anydb_init(c: &mut Criterion) {
    let cfg = Config::default();
    gen_random_any(cfg.clone());
    let runner = tokio::Runner::new(cfg);
    c.bench_function(
        &format!(
            "{}/elements={} operations={}",
            module_path!(),
            NUM_ELEMENTS,
            NUM_OPERATIONS,
        ),
        |b| {
            b.to_async(&runner).iter_custom(|_| async move {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let pool = commonware_runtime::create_pool(ctx.clone(), THREADS).unwrap();
                let any_cfg = any_cfg(pool);
                let start = Instant::now();
                let anydb = Any::<
                    Context,
                    <Sha256 as Hasher>::Digest,
                    <Sha256 as Hasher>::Digest,
                    Sha256,
                    EightCap,
                >::init(ctx, any_cfg)
                .await
                .unwrap();
                assert_ne!(anydb.op_count(), 0);
                anydb.close().await.unwrap();

                start.elapsed()
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_anydb_init
}
