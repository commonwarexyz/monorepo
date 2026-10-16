use commonware_cryptography::{ChaCha20Poly1305, Cipher};
use commonware_math::algebra::Random;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};

fn bench_seal_open(c: &mut Criterion) {
    // test_rng() has a fixed seed, so both ciphers get the same key.
    let (send, recv) = (
        ChaCha20Poly1305::random(test_rng()),
        ChaCha20Poly1305::random(test_rng()),
    );

    // Sealing and opening consume each cipher and return the next one.
    let (mut send, mut recv) = (Some(send), Some(recv));
    for n in [1 << 12, 1 << 16, 1 << 20] {
        let data = vec![0; n];
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter(|| {
                // Copy the plaintext because sealing encrypts it in place.
                let mut buf = data.clone();
                let (next, tag) = send.take().unwrap().seal(&[], &mut buf).unwrap();
                send = Some(next);
                recv = Some(recv.take().unwrap().open(&[], &mut buf, &tag).unwrap());
                buf
            })
        });
    }
}

criterion_group!(benches, bench_seal_open);
