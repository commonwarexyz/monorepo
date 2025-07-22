use commonware_cryptography::lthash::LtHash;
use commonware_cryptography::{Blake3, Sha256};
use criterion::{criterion_group, BatchSize, Criterion};

fn benchmark_add(c: &mut Criterion) {
    // Benchmark with different data sizes
    for size in [32, 256, 1024, 4096] {
        let data = vec![0u8; size];
        
        c.bench_function(&format!("{}/blake3_{}bytes", module_path!(), size), |b| {
            b.iter_batched(
                LtHash::<Blake3>::new,
                |mut lthash| {
                    lthash.add(&data);
                },
                BatchSize::SmallInput,
            );
        });

        c.bench_function(&format!("{}/sha256_{}bytes", module_path!(), size), |b| {
            b.iter_batched(
                LtHash::<Sha256>::new,
                |mut lthash| {
                    lthash.add(&data);
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_add);