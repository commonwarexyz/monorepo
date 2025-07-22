use commonware_cryptography::lthash::LtHash;
use commonware_cryptography::{Blake3, Sha256};
use criterion::{criterion_group, Criterion};

fn benchmark_finalize(c: &mut Criterion) {
    c.bench_function(&format!("{}/blake3", module_path!()), |b| {
        let mut lthash = LtHash::<Blake3>::new();
        for i in 0..100u32 {
            lthash.add(&i.to_le_bytes());
        }
        b.iter(|| {
            lthash.finalize()
        });
    });

    c.bench_function(&format!("{}/sha256", module_path!()), |b| {
        let mut lthash = LtHash::<Sha256>::new();
        for i in 0..100u32 {
            lthash.add(&i.to_le_bytes());
        }
        b.iter(|| {
            lthash.finalize()
        });
    });
}

criterion_group!(benches, benchmark_finalize);