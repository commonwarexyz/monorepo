use commonware_cryptography::{Hasher as _, Sha256};
use criterion::{criterion_group, Criterion};
use std::hint::black_box;

fn bench_fixed(c: &mut Criterion) {
    let left = Sha256::hash(b"left");
    let right = Sha256::hash(b"right");
    let bytes = [7u8; 32];
    let mut hasher = Sha256::new();

    c.bench_function(&format!("{}/shape=pair", module_path!()), |b| {
        b.iter(|| black_box(hasher.hash_encoded((black_box(left), black_box(right)))));
    });

    c.bench_function(&format!("{}/shape=u32_digest", module_path!()), |b| {
        b.iter(|| black_box(hasher.hash_encoded((black_box(7u32), black_box(left)))));
    });

    c.bench_function(&format!("{}/shape=u64_bytes32", module_path!()), |b| {
        b.iter(|| black_box(hasher.hash_encoded((black_box(7u64), black_box(bytes.as_slice())))));
    });

    c.bench_function(&format!("{}/shape=u64_pair", module_path!()), |b| {
        b.iter(|| {
            black_box(hasher.hash_encoded((black_box(7u64), black_box(left), black_box(right))))
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_fixed
}
