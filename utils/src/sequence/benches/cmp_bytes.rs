use commonware_utils::{TestRng, sequence::FixedBytes};
use criterion::{BatchSize, Criterion, criterion_group};
use rand::RngExt as _;
use std::hint::black_box;

fn bench_cmp_bytes<const N: usize>(c: &mut Criterion) {
    for n in [100u64, 10_000, 100_000] {
        let mut rng = TestRng::new(n);
        let keys: Vec<FixedBytes<N>> = (0..n).map(|_| FixedBytes::new(rng.random())).collect();
        c.bench_function(&format!("{}/op=sort size={N} n={n}", module_path!()), |b| {
            b.iter_batched(
                || keys.clone(),
                |mut v| {
                    v.sort_unstable();
                    v
                },
                BatchSize::LargeInput,
            );
        });
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        // A hit ends on an equal compare, which reads every byte; a miss usually stops early.
        let misses: Vec<FixedBytes<N>> = (0..n).map(|_| FixedBytes::new(rng.random())).collect();
        for (op, queries) in [("hit", &keys), ("miss", &misses)] {
            c.bench_function(&format!("{}/op={op} size={N} n={n}", module_path!()), |b| {
                b.iter(|| {
                    for k in queries {
                        black_box(sorted.binary_search(black_box(k)).is_ok());
                    }
                });
            });
        }
    }
}

fn benchmark_cmp_bytes(c: &mut Criterion) {
    // 16 and 65 keep the derived compare; the rest cover whole words with and without leftovers.
    bench_cmp_bytes::<16>(c);
    bench_cmp_bytes::<20>(c);
    bench_cmp_bytes::<23>(c);
    bench_cmp_bytes::<32>(c);
    bench_cmp_bytes::<33>(c);
    bench_cmp_bytes::<64>(c);
    bench_cmp_bytes::<65>(c);
}

criterion_group!(benches, benchmark_cmp_bytes);
