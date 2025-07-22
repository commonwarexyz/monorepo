use commonware_cryptography::lthash::LtHash;
use criterion::{criterion_group, Criterion};

fn benchmark_checksum(c: &mut Criterion) {
    c.bench_function(module_path!(), |b| {
        let mut lthash = LtHash::new();
        for i in 0..100u32 {
            lthash.add(&i.to_le_bytes());
        }
        b.iter(|| lthash.checksum());
    });
}

criterion_group!(benches, benchmark_checksum);
