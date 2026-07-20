use commonware_cryptography::{BloomFilter, Hasher, blake3::Blake3, sha256::Sha256};
use commonware_utils::{TestRng, rational::BigRationalExt};
use criterion::{BatchSize, Criterion, criterion_group};
use num_rational::BigRational;
use rand::Rng;
use std::num::NonZeroUsize;

const ITEM_SIZES: [usize; 3] = [32, 2048, 4096];
const NUM_ITEMS: usize = 10000;

fn fp_rates() -> [(BigRational, &'static str); 2] {
    [
        (BigRational::from_frac_u64(1, 10), "10%"),
        (BigRational::from_frac_u64(1, 1000), "0.1%"),
    ]
}

fn run_insert_bench<H: Hasher>(c: &mut Criterion, hasher: &str) {
    for item_size in ITEM_SIZES {
        for (fp_rate, fp_label) in fp_rates() {
            // Pre-generate items to insert
            let mut rng = TestRng::new(42);
            let items: Vec<Vec<u8>> = (0..NUM_ITEMS)
                .map(|_| {
                    let mut item = vec![0u8; item_size];
                    rng.fill_bytes(&mut item);
                    item
                })
                .collect();

            c.bench_function(
                &format!(
                    "{}/hasher={} item_size={} fp_rate={}",
                    module_path!(),
                    hasher,
                    item_size,
                    fp_label
                ),
                |b| {
                    let mut idx = 0;
                    b.iter_batched(
                        || {
                            BloomFilter::<H>::with_rate(
                                NonZeroUsize::new(NUM_ITEMS).unwrap(),
                                fp_rate.clone(),
                            )
                        },
                        |mut bf| {
                            bf.insert(&items[idx]);
                            idx = (idx + 1) % items.len();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

fn benchmark_insert(c: &mut Criterion) {
    run_insert_bench::<Sha256>(c, "sha256");
    run_insert_bench::<Blake3>(c, "blake3");
}

criterion_group!(benches, benchmark_insert);
