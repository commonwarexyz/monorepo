use commonware_cryptography::Sha512;
use criterion::{Criterion, criterion_group};

fn bench_hash_many(c: &mut Criterion) {
    crate::workload::bench::<Sha512>(
        c,
        module_path!(),
        &[96, 1024, 16_384, 65_536, 262_144],
        &[1, 2, 7, 8, 9, 16, 32, 128],
    );
}

criterion_group!(benches, bench_hash_many);
