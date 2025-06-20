use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config as TokioConfig,
};
use commonware_storage::diskmap::{Config, DiskMap};
use commonware_utils::array::FixedBytes;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::time::{Duration, Instant};

type TestKey = FixedBytes<8>;
type TestValue = FixedBytes<16>;

fn bench_insert(c: &mut Criterion) {
    let cfg = TokioConfig::default();
    let runner = tokio::Runner::new(cfg);

    for items in [10_000, 50_000, 100_000, 500_000, 1_000_000] {
        let label = format!("{}/items={}", module_path!(), items);
        c.bench_function(&label, |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                // Setup items
                let mut rng = StdRng::seed_from_u64(0);
                let mut kvs = Vec::with_capacity(items);
                for i in 0..items {
                    // Create simple key and value using byte arrays
                    let key_bytes = (i as u64).to_be_bytes();
                    let key = TestKey::new(key_bytes);
                    let value = TestValue::new([i as u8; 16]);
                    kvs.push((key, value));
                }

                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let mut total = Duration::ZERO;
                for iter_count in 0..iters {
                    // Shuffle items and setup DiskMap
                    kvs.shuffle(&mut rng);

                    let config = Config {
                        partition: format!("diskmap_bench_{}", iter_count),
                        directory_size: 1024,
                        codec_config: (),
                        write_buffer: 1024,
                        target_journal_size: 64 * 1024 * 1024, // 64MB
                    };

                    let mut diskmap = DiskMap::<_, TestKey, TestValue>::init(ctx.clone(), config)
                        .await
                        .unwrap();

                    // Run benchmark
                    let start = Instant::now();
                    for (k, v) in &kvs {
                        diskmap.put(k.clone(), v.clone()).await.unwrap();
                    }
                    total += start.elapsed();

                    // Clean up - destroy to remove all data
                    diskmap.destroy().await.unwrap();
                }
                total
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert
}
