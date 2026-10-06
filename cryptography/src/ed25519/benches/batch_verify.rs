use commonware_cryptography::{
    BatchEntry, BatchVerifier, Signer as _,
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, TestRng, test_rng};
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;
use std::hint::black_box;

const NAMESPACE: &[u8] = b"constantinople-tx";

/// Signs `n` random `msg_len`-byte messages, each with a distinct signer.
fn signed(rng: &mut TestRng, n: usize, msg_len: usize) -> Vec<(PublicKey, Vec<u8>, Signature)> {
    (0..n)
        .map(|_| {
            let signer = PrivateKey::random(&mut *rng);
            let mut msg = vec![0u8; msg_len];
            rng.fill(&mut msg[..]);
            let sig = signer.sign(NAMESPACE, &msg);
            (signer.public_key(), msg, sig)
        })
        .collect()
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut rng = test_rng();
    let mut verify_rng = TestRng::new(1);
    let rayon = Rayon::new(NZUsize!(8)).unwrap();
    for (n, msg_len, concurrency) in [
        (10_000, 32, 8),
        (100_000, 32, 8),
        (10_000, 96, 8),
        (10, 32, 1),
        (100, 32, 1),
    ] {
        let items = signed(&mut rng, n, msg_len);
        c.bench_function(
            &format!(
                "{}/sigs={n} msg={msg_len} conc={concurrency}",
                module_path!()
            ),
            |b| {
                b.iter(|| {
                    if concurrency == 1 {
                        black_box(PublicKey::verify_batch(
                            &mut verify_rng,
                            &items,
                            |_, (public_key, message, signature)| BatchEntry {
                                namespace: NAMESPACE,
                                message,
                                public_key,
                                signature,
                            },
                            &Sequential,
                        ))
                    } else {
                        black_box(PublicKey::verify_batch(
                            &mut verify_rng,
                            &items,
                            |_, (public_key, message, signature)| BatchEntry {
                                namespace: NAMESPACE,
                                message,
                                public_key,
                                signature,
                            },
                            &rayon,
                        ))
                    }
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_batch_verify
}
