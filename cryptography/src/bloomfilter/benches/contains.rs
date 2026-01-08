use commonware_cryptography::{blake3::Blake3, sha256::Sha256, BloomFilter, Hasher};
use criterion::{criterion_group, measurement::Measurement, Criterion, Throughput};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{collections::HashSet, hint::black_box, num::NonZeroUsize};

const ITEM_SIZES: [usize; 3] = [32, 2048, 4096];
const NUM_ITEMS: usize = 10000;
const FP_RATES: [f64; 2] = [0.1, 0.001];

fn run_contains_bench<H: Hasher>(
    group: &mut criterion::BenchmarkGroup<'_, impl Measurement>,
    hasher_name: &str,
    query_inserted: bool,
) {
    for &item_size in &ITEM_SIZES {
        for &fp_rate in &FP_RATES {
            let mut rng = StdRng::seed_from_u64(42);

            // Create and populate the bloom filter
            let mut bf =
                BloomFilter::<H>::with_rate(NonZeroUsize::new(NUM_ITEMS).unwrap(), fp_rate);
            let mut inserted_set = HashSet::new();

            let inserted: Vec<Vec<u8>> = (0..NUM_ITEMS)
                .map(|_| {
                    let mut item = vec![0u8; item_size];
                    rng.fill_bytes(&mut item);
                    bf.insert(&item);
                    inserted_set.insert(item.clone());
                    item
                })
                .collect();

            // Items to query: inserted ones or guaranteed non-inserted ones
            let items = if query_inserted {
                inserted
            } else {
                let mut items = Vec::with_capacity(NUM_ITEMS);
                while items.len() < NUM_ITEMS {
                    let mut item = vec![0u8; item_size];
                    rng.fill_bytes(&mut item);
                    if !inserted_set.contains(&item) {
                        items.push(item);
                    }
                }
                items
            };

            group.throughput(Throughput::Elements(1));
            group.bench_function(
                format!("{hasher_name}/size={item_size} fp={fp_rate}"),
                |b| {
                    let mut idx = 0;
                    b.iter(|| {
                        let result = bf.contains(black_box(&items[idx]));
                        idx = (idx + 1) % items.len();
                        result
                    });
                },
            );
        }
    }
}

fn benchmark_contains_positive(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}/positive", module_path!()));
    run_contains_bench::<Sha256>(&mut group, "sha256", true);
    run_contains_bench::<Blake3>(&mut group, "blake3", true);
    group.finish();
}

fn benchmark_contains_negative(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}/negative", module_path!()));
    run_contains_bench::<Sha256>(&mut group, "sha256", false);
    run_contains_bench::<Blake3>(&mut group, "blake3", false);
    group.finish();
}

criterion_group!(
    benches,
    benchmark_contains_positive,
    benchmark_contains_negative
);
