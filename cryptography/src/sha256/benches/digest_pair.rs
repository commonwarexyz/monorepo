use commonware_cryptography::{Hasher, Sha256};
use criterion::{criterion_group, Criterion};
use std::hint::black_box;

/// Compares the per-call cost of the digest-pair primitives. `merge_digest_pair` (the Merkle node
/// hash) is a single compression block, whereas `hash_digest_pair` (a full hash of `left || right`)
/// spans two.
fn bench_digest_pair(c: &mut Criterion) {
    let left = Sha256::hash(b"left");
    let right = Sha256::hash(b"right");

    c.bench_function(&format!("{}/op=merge_digest_pair", module_path!()), |b| {
        let mut hasher = Sha256::new();
        b.iter(|| black_box(hasher.merge_digest_pair(black_box(&left), black_box(&right))));
    });

    c.bench_function(&format!("{}/op=hash_digest_pair", module_path!()), |b| {
        let mut hasher = Sha256::new();
        b.iter(|| black_box(hasher.hash_digest_pair(black_box(&left), black_box(&right))));
    });
}

criterion_group!(benches, bench_digest_pair);
