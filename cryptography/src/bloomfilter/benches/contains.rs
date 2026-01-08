use commonware_cryptography::{blake3::Blake3, sha256::Sha256, BloomFilter, Hasher};
use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::HashSet;

const ITEM_SIZES: [usize; 4] = [32, 256, 2048, 4096];
const NUM_ITEMS: [usize; 3] = [1000, 10000, 100000];
const FP_RATES: [f64; 3] = [0.1, 0.01, 0.001];

fn benchmark_contains_with_hasher<H: Hasher>(
    c: &mut Criterion,
    hasher_name: &str,
    query_inserted: bool,
) {
    let bench_type = if query_inserted {
        "positive"
    } else {
        "negative"
    };
    let mut group = c.benchmark_group(format!("bloomfilter/contains_{bench_type}/{hasher_name}"));

    for &num_items in &NUM_ITEMS {
        for &item_size in &ITEM_SIZES {
            for &fp_rate in &FP_RATES {
                let mut rng = StdRng::seed_from_u64(42);

                // Create and populate the bloom filter
                let mut bf = BloomFilter::<H>::with_rate(num_items, fp_rate);
                let mut inserted_set = HashSet::new();

                let inserted: Vec<Vec<u8>> = (0..num_items)
                    .map(|_| {
                        let mut item = vec![0u8; item_size];
                        rng.fill_bytes(&mut item);
                        bf.insert(&item);
                        inserted_set.insert(item.clone());
                        item
                    })
                    .collect();

                // Items to query: inserted ones or guaranteed non-inserted ones
                let query_items = if query_inserted {
                    inserted
                } else {
                    let mut items = Vec::with_capacity(num_items);
                    while items.len() < num_items {
                        let mut item = vec![0u8; item_size];
                        rng.fill_bytes(&mut item);
                        if !inserted_set.contains(&item) {
                            items.push(item);
                        }
                    }
                    items
                };

                group.throughput(Throughput::Elements(1));
                group.bench_with_input(
                    BenchmarkId::new(
                        format!("items={num_items}/size={item_size}"),
                        format!("fp={fp_rate}"),
                    ),
                    &query_items,
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
    }

    group.finish();
}

fn benchmark_contains_positive_sha256(c: &mut Criterion) {
    benchmark_contains_with_hasher::<Sha256>(c, "sha256", true);
}

fn benchmark_contains_positive_blake3(c: &mut Criterion) {
    benchmark_contains_with_hasher::<Blake3>(c, "blake3", true);
}

fn benchmark_contains_negative_sha256(c: &mut Criterion) {
    benchmark_contains_with_hasher::<Sha256>(c, "sha256", false);
}

fn benchmark_contains_negative_blake3(c: &mut Criterion) {
    benchmark_contains_with_hasher::<Blake3>(c, "blake3", false);
}

criterion_group!(
    benches,
    benchmark_contains_positive_sha256,
    benchmark_contains_positive_blake3,
    benchmark_contains_negative_sha256,
    benchmark_contains_negative_blake3
);
