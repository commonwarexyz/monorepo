use commonware_cryptography::{blake3::Blake3, sha256::Sha256, BloomFilter, Hasher};
use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use rand::{rngs::StdRng, RngCore, SeedableRng};

const ITEM_SIZES: [usize; 3] = [32, 2048, 4096];
const NUM_ITEMS: usize = 10000;
const FP_RATES: [f64; 2] = [0.1, 0.001];

fn run_insert_bench<H: Hasher>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    hasher_name: &str,
) {
    for &item_size in &ITEM_SIZES {
        for &fp_rate in &FP_RATES {
            let mut rng = StdRng::seed_from_u64(42);

            // Pre-generate items
            let items: Vec<Vec<u8>> = (0..NUM_ITEMS)
                .map(|_| {
                    let mut item = vec![0u8; item_size];
                    rng.fill_bytes(&mut item);
                    item
                })
                .collect();

            group.throughput(Throughput::Elements(1));
            group.bench_with_input(
                BenchmarkId::new(format!("{hasher_name}/size={item_size}"), format!("fp={fp_rate}")),
                &items,
                |b, items| {
                    let mut bf = BloomFilter::<H>::with_rate(NUM_ITEMS, fp_rate);
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

fn benchmark_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloomfilter/insert");
    run_insert_bench::<Sha256>(&mut group, "sha256");
    run_insert_bench::<Blake3>(&mut group, "blake3");
    group.finish();
}

criterion_group!(benches, benchmark_insert);
