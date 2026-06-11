use crate::{append_fixed_random_data, get_fixed_journal, ITEMS_PER_BLOB, ITEM_SIZE};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
    Handle, Spawner as _, Supervisor as _,
};
use commonware_storage::journal::contiguous::Reader as _;
use commonware_utils::sequence::FixedBytes;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use std::{
    hint::black_box,
    sync::Arc,
    time::{Duration, Instant},
};

/// Partition name to use in the journal config.
const PARTITION: &str = "test-partition-mixed";

/// Number of items pre-populated for readers to read: ~800 pages against the 10,000-page
/// cache, so reads are cache hits and the benchmark measures reader/writer interference,
/// not I/O.
const INITIAL_ITEMS: u64 = 200_000;

/// Number of items appended (then synced) per measured iteration.
const APPENDS: u64 = 10_000;

/// Number of random reads performed through one reader before taking a fresh one.
const READS_PER_BATCH: usize = 100;

/// Benchmark append throughput while concurrent reader tasks repeatedly take a reader, perform a
/// batch of random reads over the pre-populated range, and drop it.
fn bench_fixed_mixed(c: &mut Criterion) {
    let cfg = Config::default();
    for readers in [0usize, 1, 4] {
        let runner = tokio::Runner::new(cfg.clone());
        c.bench_function(
            &format!(
                "{}/readers={} appends={} size={}",
                module_path!(),
                readers,
                APPENDS,
                ITEM_SIZE
            ),
            |b| {
                b.to_async(&runner).iter_custom(move |iters| async move {
                    let ctx = context::get::<Context>();
                    let mut journal = get_fixed_journal::<ITEM_SIZE>(
                        ctx.child("journal"),
                        PARTITION,
                        ITEMS_PER_BLOB,
                    )
                    .await;
                    append_fixed_random_data(&mut journal, INITIAL_ITEMS).await;
                    let journal = Arc::new(journal);

                    // Spawn the readers.
                    let mut handles = Vec::<Handle<()>>::with_capacity(readers);
                    for seed in 0..readers {
                        let journal = journal.clone();
                        handles.push(ctx.child("reader").spawn(move |_| async move {
                            let mut rng = StdRng::seed_from_u64(seed as u64);
                            loop {
                                let reader = journal.reader().await;
                                for _ in 0..READS_PER_BATCH {
                                    let pos = rng.gen_range(0..INITIAL_ITEMS);
                                    black_box(reader.read(pos).await.expect("failed to read"));
                                }
                            }
                        }));
                    }

                    // Measure append+sync throughput while the readers run.
                    let mut rng = StdRng::seed_from_u64(u64::MAX);
                    let mut arr = [0u8; ITEM_SIZE];
                    let mut duration = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        for _ in 0..APPENDS {
                            rng.fill_bytes(&mut arr);
                            journal
                                .append(&FixedBytes::new(arr))
                                .await
                                .expect("failed to append");
                        }
                        journal.sync().await.expect("failed to sync");
                        duration += start.elapsed();
                    }

                    // Stop the readers and clean up.
                    for handle in handles {
                        handle.abort();
                        let _ = handle.await;
                    }
                    Arc::try_unwrap(journal)
                        .map_err(|_| ())
                        .expect("readers still hold the journal")
                        .destroy()
                        .await
                        .expect("failed to destroy journal");

                    duration
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_mixed,
}
