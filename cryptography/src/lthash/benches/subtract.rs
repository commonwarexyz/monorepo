use commonware_cryptography::lthash::LtHash;
use criterion::{criterion_group, BatchSize, Criterion};

fn benchmark_subtract(c: &mut Criterion) {
    for size in [32, 256, 1024] {
        let data = vec![0u8; size];
        c.bench_function(&format!("{}/bytes={}", module_path!(), size), |b| {
            b.iter_batched(
                || {
                    let mut lthash = LtHash::new();
                    lthash.add(&data);
                    lthash
                },
                |mut lthash| {
                    lthash.subtract(&data);
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_subtract);
