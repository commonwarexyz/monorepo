use bytes::BufMut;
use commonware_codec::Write;
use commonware_cryptography::{Hasher as _, Sha256};
use criterion::{criterion_group, Criterion};
use std::hint::black_box;

fn bench_fixed(c: &mut Criterion) {
    let left = Sha256::hash(b"left");
    let right = Sha256::hash(b"right");
    let bytes = [7u8; 32];
    let mut hasher = Sha256::default();

    c.bench_function(&format!("{}/shape=pair", module_path!()), |b| {
        b.iter(|| black_box(hasher.hash_pair(black_box(&left), black_box(&right))));
    });

    // Same 64-byte preimage as `shape=pair`, but routed through the generic (runtime-length)
    // `hash_parts` path so its overhead can be compared against the constant-length fast paths.
    c.bench_function(&format!("{}/shape=pair_parts", module_path!()), |b| {
        b.iter(|| {
            black_box(hasher.hash_parts([black_box(&left).as_ref(), black_box(&right).as_ref()]))
        });
    });

    c.bench_function(&format!("{}/shape=u32_digest", module_path!()), |b| {
        b.iter(|| {
            black_box(hasher.hash_codec(|buf| {
                black_box(7u32).write(buf);
                black_box(&left).write(buf);
            }))
        });
    });

    // Fixed prefix followed by a raw, variable-length suffix (the Merkle leaf shape).
    c.bench_function(&format!("{}/shape=u64_bytes32", module_path!()), |b| {
        b.iter(|| {
            black_box(hasher.hash_codec(|buf| {
                black_box(7u64).write(buf);
                buf.put_slice(black_box(bytes.as_slice()));
            }))
        });
    });

    c.bench_function(&format!("{}/shape=u64_pair", module_path!()), |b| {
        b.iter(|| {
            black_box(hasher.hash_codec(|buf| {
                black_box(7u64).write(buf);
                black_box(&left).write(buf);
                black_box(&right).write(buf);
            }))
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_fixed
}
