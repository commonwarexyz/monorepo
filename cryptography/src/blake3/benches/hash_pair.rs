use commonware_cryptography::{Hasher, blake3::Blake3};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::Rng;
use std::hint::black_box;

fn bench_hash_pair(c: &mut Criterion) {
    let mut sampler = test_rng();
    let mut messages = [[0u8; 72]; 2];
    for message in &mut messages {
        sampler.fill_bytes(message);
    }
    for (shape, parts) in [
        (
            "bmt",
            messages
                .each_ref()
                .map(|message| vec![&message[..32], &message[32..64]]),
        ),
        (
            "mmr",
            messages
                .each_ref()
                .map(|message| vec![&message[..8], &message[8..40], &message[40..]]),
        ),
        (
            "leaf",
            messages
                .each_ref()
                .map(|message| vec![&message[..8], &message[8..40]]),
        ),
    ] {
        c.bench_function(&format!("{}/shape={shape}", module_path!()), |b| {
            b.iter(|| Blake3::hash_pair(black_box(&parts[0]), black_box(&parts[1])));
        });
    }
}

criterion_group!(benches, bench_hash_pair);
