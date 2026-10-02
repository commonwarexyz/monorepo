use commonware_cryptography::{Hasher, blake3::Blake3};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::Rng;
use std::hint::black_box;

fn bench_hash_message(c: &mut Criterion) {
    let mut sampler = test_rng();
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for message_length in [40, 64, 72, 1024].into_iter().chain(cases) {
        let mut msg = vec![0u8; message_length];
        sampler.fill_bytes(msg.as_mut_slice());
        let msg = msg.as_slice();
        c.bench_function(&format!("{}/msg_len={}", module_path!(), msg.len()), |b| {
            b.iter(|| Blake3::hash(&[msg]));
        });
    }

    // Merkle leaf (position and element), BMT node, and MMR node shapes.
    let mut msg = [0u8; 72];
    sampler.fill_bytes(&mut msg);
    for ends in [&[8, 40][..], &[32, 64], &[8, 40, 72]] {
        let mut start = 0;
        let parts: Vec<&[u8]> = ends
            .iter()
            .map(|&end| {
                let part = &msg[start..end];
                start = end;
                part
            })
            .collect();
        c.bench_function(
            &format!("{}/msg_len={start} parts={}", module_path!(), parts.len()),
            |b| b.iter(|| Blake3::hash(black_box(&parts))),
        );
    }
}

criterion_group!(benches, bench_hash_message);
