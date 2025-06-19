use commonware_cryptography::{hash, sha256::Digest};
use commonware_runtime::benchmarks::{context, tokio};
use commonware_storage::bmap::{BMap, Config};
use commonware_utils::array::FixedBytes;
use criterion::{criterion_group, Criterion};
use std::{
    marker::PhantomData,
    time::{Duration, Instant},
};

type TestKey = Digest;
type TestValue = FixedBytes<64>;

fn test_config(num_buckets: usize) -> Config<TestKey, TestValue> {
    Config {
        partition: "bmap_bench".into(),
        num_buckets,
        journal_write_buffer: 1024 * 1024, // 1MB
        codec_config: (),
        _key: PhantomData,
    }
}

fn bench_insert(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for items in [10_000, 100_000] {
        for buckets in [1, 16, 256] {
            let label = format!("{}/items={} buckets={}", module_path!(), items, buckets);
            c.bench_function(&label, |b| {
                b.to_async(&runner).iter_custom(move |iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();

                    let mut kvs = Vec::with_capacity(items);
                    for i in 0..items {
                        kvs.push((hash(&i.to_be_bytes()), FixedBytes::new([i as u8; 64])));
                    }

                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut bmap = BMap::init(ctx.clone(), test_config(buckets)).await.unwrap();
                        let start = Instant::now();
                        for (k, v) in &kvs {
                            bmap.insert(*k, *v).await.unwrap();
                        }
                        total += start.elapsed();
                        bmap.destroy().await.unwrap();
                    }
                    total
                });
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert
}
