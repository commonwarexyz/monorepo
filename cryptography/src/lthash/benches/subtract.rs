use commonware_cryptography::lthash::LtHash;
use commonware_cryptography::Blake3;
use criterion::{criterion_group, BatchSize, Criterion};

fn benchmark_subtract(c: &mut Criterion) {
    // Benchmark with different data sizes
    for size in [32, 256, 1024] {
        let data = vec![0u8; size];
        
        c.bench_function(&format!("{}/blake3_{}bytes", module_path!(), size), |b| {
            b.iter_batched(
                || {
                    let mut lthash = LtHash::<Blake3>::new();
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