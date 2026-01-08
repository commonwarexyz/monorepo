use commonware_cryptography::{sha256::Sha256, BloomFilter};
use commonware_utils::{NZUsize, NZU8};
use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::HashSet;

fn benchmark_contains(c: &mut Criterion, name: &str, query_inserted: bool) {
    let mut group = c.benchmark_group(format!("bloomfilter/{name}"));

    let filter_bits = [1 << 10, 1 << 14, 1 << 17, 1 << 20]; // 1024, 16384, 131072, 1048576
    let hashers = [3, 7, 10];
    let item_size = 32;
    let num_items = 1_000;

    let mut rng = StdRng::seed_from_u64(42);

    for &bits in &filter_bits {
        for &k in &hashers {
            let mut bf = BloomFilter::<Sha256>::new(NZU8!(k), NZUsize!(bits));
            let mut set = HashSet::new();

            // Insert items
            let inserted: Vec<_> = (0..num_items)
                .map(|_| {
                    let mut item = vec![0u8; item_size];
                    rng.fill_bytes(&mut item);
                    bf.insert(&item);
                    set.insert(item.clone());
                    item
                })
                .collect();

            // Items to query: inserted ones or guaranteed non-inserted ones
            let items = if query_inserted {
                inserted
            } else {
                let mut items = Vec::with_capacity(num_items);
                while items.len() < num_items {
                    let mut item = vec![0u8; item_size];
                    rng.fill_bytes(&mut item);
                    if !set.contains(&item) {
                        items.push(item);
                    }
                }
                items
            };

            group.throughput(Throughput::Elements(1));
            group.bench_with_input(
                BenchmarkId::new(format!("bits={bits}"), format!("k={k}")),
                &items,
                |b, items| {
                    let mut idx = 0;
                    b.iter(|| {
                        let result = bf.contains(&items[idx]);
                        idx = (idx + 1) % items.len();
                        result
                    });
                },
            );
        }
    }

    group.finish();
}

fn benchmark_contains_positive(c: &mut Criterion) {
    benchmark_contains(c, "contains_positive", true);
}

fn benchmark_contains_negative(c: &mut Criterion) {
    benchmark_contains(c, "contains_negative", false);
}

criterion_group!(
    benches,
    benchmark_contains_positive,
    benchmark_contains_negative
);
