use commonware_cryptography::lthash::LtHash;
use commonware_cryptography::Blake3;
use criterion::{criterion_group, BatchSize, Criterion};

fn benchmark_combine(c: &mut Criterion) {
    c.bench_function(&format!("{}/blake3", module_path!()), |b| {
        b.iter_batched(
            || {
                let mut lthash1 = LtHash::<Blake3>::new();
                let mut lthash2 = LtHash::<Blake3>::new();
                lthash1.add(b"data1");
                lthash2.add(b"data2");
                (lthash1, lthash2)
            },
            |(mut lthash1, lthash2)| {
                lthash1.combine(&lthash2);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, benchmark_combine);