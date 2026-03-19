use commonware_cryptography::{blake3::Blake3, sha256::Sha256, BloomFilter, Hasher};
use commonware_utils::rational::BigRationalExt;
use criterion::{criterion_group, Criterion};
use num_rational::BigRational;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{collections::HashSet, hint::black_box, num::NonZeroUsize};

const ITEM_SIZES: [usize; 3] = [32, 2048, 4096];
const NUM_ITEMS: usize = 10000;

fn fp_rates() -> [(BigRational, &'static str); 2] {
    [
        (BigRational::from_frac_u64(1, 10), "10%"),
        (BigRational::from_frac_u64(1, 1000), "0.1%"),
    ]
}

fn run_contains_bench<H: Hasher>(c: &mut Criterion, hasher: &str, query_inserted: bool) {
    let query_type = if query_inserted {
        "positive"
    } else {
        "negative"
    };
    for item_size in ITEM_SIZES {
        for (fp_rate, fp_label) in fp_rates() {
            // Create and populate the bloom filter
            let mut rng = StdRng::seed_from_u64(42);
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

            c.bench_function(
                &format!(
                    "{}/hasher={} item_size={} fp_rate={} query={}",
                    module_path!(),
                    hasher,
                    item_size,
                    fp_label,
                    query_type
                ),
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

fn benchmark_contains(c: &mut Criterion) {
    run_contains_bench::<Sha256>(c, "sha256", true);
    run_contains_bench::<Sha256>(c, "sha256", false);
    run_contains_bench::<Blake3>(c, "blake3", true);
    run_contains_bench::<Blake3>(c, "blake3", false);
}

criterion_group!(benches, benchmark_contains);
