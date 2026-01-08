use commonware_cryptography::{blake3::Blake3, sha256::Sha256, BloomFilter, Hasher};
use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use rand::{rngs::StdRng, RngCore, SeedableRng};

const ITEM_SIZES: [usize; 4] = [32, 256, 2048, 4096];
const NUM_ITEMS: [usize; 3] = [1000, 10000, 100000];
const FP_RATES: [f64; 3] = [0.1, 0.01, 0.001];

fn benchmark_insert_with_hasher<H: Hasher>(c: &mut Criterion, hasher_name: &str) {
    let mut group = c.benchmark_group(format!("bloomfilter/insert/{hasher_name}"));

    for &num_items in &NUM_ITEMS {
        for &item_size in &ITEM_SIZES {
            for &fp_rate in &FP_RATES {
                let mut rng = StdRng::seed_from_u64(42);

                // Pre-generate items
                let items: Vec<Vec<u8>> = (0..num_items)
                    .map(|_| {
                        let mut item = vec![0u8; item_size];
                        rng.fill_bytes(&mut item);
                        item
                    })
                    .collect();

                group.throughput(Throughput::Elements(1));
                group.bench_with_input(
                    BenchmarkId::new(
                        format!("items={num_items}/size={item_size}"),
                        format!("fp={fp_rate}"),
                    ),
                    &items,
                    |b, items| {
                        let mut bf = BloomFilter::<H>::with_rate(num_items, fp_rate);
                        let mut idx = 0;
                        b.iter(|| {
                            bf.insert(&items[idx]);
                            idx = (idx + 1) % items.len();
                        });
                    },
                );
            }
        }
    }

    group.finish();
}

fn benchmark_insert_sha256(c: &mut Criterion) {
    benchmark_insert_with_hasher::<Sha256>(c, "sha256");
}

fn benchmark_insert_blake3(c: &mut Criterion) {
    benchmark_insert_with_hasher::<Blake3>(c, "blake3");
}

criterion_group!(benches, benchmark_insert_sha256, benchmark_insert_blake3);
