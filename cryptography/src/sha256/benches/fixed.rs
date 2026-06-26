use commonware_cryptography::{Hasher as _, Sha256};
use criterion::{criterion_group, Criterion};
use std::hint::black_box;

fn bench_fixed(c: &mut Criterion) {
    let left = Sha256::hash(b"left");
    let right = Sha256::hash(b"right");
    let bytes = [7u8; 32];

    c.bench_function(&format!("{}/shape=pair mode=static", module_path!()), |b| {
        b.iter(|| black_box(Sha256::hash_pair(black_box(&left), black_box(&right))));
    });
    c.bench_function(
        &format!("{}/shape=pair mode=mutable", module_path!()),
        |b| {
            let mut hasher = Sha256::default();
            b.iter(|| black_box(hasher.hash_pair_mut(black_box(&left), black_box(&right))));
        },
    );

    c.bench_function(
        &format!("{}/shape=u32_digest mode=static", module_path!()),
        |b| {
            b.iter(|| black_box(Sha256::hash_u32_with_digest(black_box(7), black_box(&left))));
        },
    );
    c.bench_function(
        &format!("{}/shape=u32_digest mode=mutable", module_path!()),
        |b| {
            let mut hasher = Sha256::default();
            b.iter(|| black_box(hasher.hash_u32_with_digest_mut(black_box(7), black_box(&left))));
        },
    );

    c.bench_function(
        &format!("{}/shape=u64_bytes32 mode=static", module_path!()),
        |b| {
            b.iter(|| {
                black_box(Sha256::hash_u64_with_bytes(
                    black_box(7),
                    black_box(bytes.as_slice()),
                ))
            });
        },
    );
    c.bench_function(
        &format!("{}/shape=u64_bytes32 mode=mutable", module_path!()),
        |b| {
            let mut hasher = Sha256::default();
            b.iter(|| {
                black_box(hasher.hash_u64_with_bytes_mut(black_box(7), black_box(bytes.as_slice())))
            });
        },
    );

    c.bench_function(
        &format!("{}/shape=u64_pair mode=static", module_path!()),
        |b| {
            b.iter(|| {
                black_box(Sha256::hash_u64_with_pair(
                    black_box(7),
                    black_box(&left),
                    black_box(&right),
                ))
            });
        },
    );
    c.bench_function(
        &format!("{}/shape=u64_pair mode=mutable", module_path!()),
        |b| {
            let mut hasher = Sha256::default();
            b.iter(|| {
                black_box(hasher.hash_u64_with_pair_mut(
                    black_box(7),
                    black_box(&left),
                    black_box(&right),
                ))
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_fixed
}
