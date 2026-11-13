use commonware_cryptography::{Hasher, Sha256};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::Rng;
use std::hint::black_box;

fn bench_hash_parts(c: &mut Criterion) {
    let mut sampler = test_rng();
    let mut message = [0u8; 72];
    sampler.fill_bytes(&mut message);
    for (shape, parts) in [
        (
            "mmr_node",
            vec![&message[..8], &message[8..40], &message[40..]],
        ),
        ("bmt_node", vec![&message[..32], &message[32..64]]),
        ("mmr_leaf", vec![&message[..8], &message[8..40]]),
        ("bmt_leaf", vec![&message[..4], &message[4..36]]),
    ] {
        c.bench_function(&format!("{}/shape={shape}", module_path!()), |b| {
            b.iter(|| Sha256::hash(black_box(&parts)));
        });
    }
}

criterion_group!(benches, bench_hash_parts);
