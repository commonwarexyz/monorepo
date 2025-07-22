use commonware_cryptography::lthash::LtHash;
use criterion::{criterion_group, BatchSize, Criterion};

fn benchmark_add(c: &mut Criterion) {
    for size in [32, 256, 1024, 4096] {
        let data = vec![0u8; size];
        c.bench_function(&format!("{}/bytes={}", module_path!(), size), |b| {
            b.iter_batched(
                LtHash::new,
                |mut lthash| {
                    lthash.add(&data);
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_add);
