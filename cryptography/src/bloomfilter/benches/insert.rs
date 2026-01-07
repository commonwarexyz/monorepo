use commonware_cryptography::BloomFilter;
use commonware_utils::{NZUsize, NZU8};
use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn benchmark_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloomfilter/insert");

    let filter_bits = [1_000, 10_000, 100_000, 1_000_000];
    let hashers = [3, 7, 10];
    let item_size = 32;

    let mut rng = StdRng::seed_from_u64(42);

    for &bits in &filter_bits {
        for &k in &hashers {
            let mut bf = BloomFilter::new(NZU8!(k), NZUsize!(bits));

            let mut item = vec![0u8; item_size];
            rng.fill_bytes(&mut item);

            group.throughput(Throughput::Elements(1));
            group.bench_with_input(
                BenchmarkId::new(format!("bits={bits}"), format!("k={k}")),
                &item,
                |b, item| {
                    b.iter(|| {
                        bf.insert(item);
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, benchmark_insert);
