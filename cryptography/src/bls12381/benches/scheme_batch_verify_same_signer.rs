use commonware_cryptography::{
    BatchEntry, BatchVerifier as _, Signer as _,
    bls12381::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, TestRng, test_rng};
use criterion::{BatchSize, Criterion, criterion_group};
use rand::RngExt as _;
use std::hint::black_box;

fn bench_scheme_batch_verify_same_signer(c: &mut Criterion) {
    let mut rng = test_rng();
    let mut verify_rng = TestRng::new(1);
    let namespace = b"namespace";
    for n_messages in [1, 10, 100, 1000, 10000].into_iter() {
        for concurrency in [1, 8] {
            let rayon = (concurrency > 1).then(|| Rayon::new(NZUsize!(concurrency)).unwrap());
            let mut msgs = Vec::with_capacity(n_messages);
            for _ in 0..n_messages {
                let mut msg = [0u8; 32];
                rng.fill(&mut msg);
                msgs.push(msg);
            }
            c.bench_function(
                &format!(
                    "{}/msgs={} conc={}",
                    module_path!(),
                    n_messages,
                    concurrency
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let signer = PrivateKey::random(&mut rng);
                            let public_key = signer.public_key();
                            let signatures = msgs
                                .iter()
                                .map(|msg| (msg, signer.sign(namespace, msg)))
                                .collect::<Vec<_>>();
                            (public_key, signatures)
                        },
                        |(public_key, signatures)| {
                            #[allow(clippy::option_if_let_else)]
                            if let Some(rayon) = rayon.as_ref() {
                                black_box(PublicKey::verify_batch(
                                    &mut verify_rng,
                                    &signatures,
                                    |_, (msg, signature)| BatchEntry {
                                        namespace,
                                        message: msg.as_slice(),
                                        public_key: &public_key,
                                        signature,
                                    },
                                    rayon,
                                ))
                            } else {
                                black_box(PublicKey::verify_batch(
                                    &mut verify_rng,
                                    &signatures,
                                    |_, (msg, signature)| BatchEntry {
                                        namespace,
                                        message: msg.as_slice(),
                                        public_key: &public_key,
                                        signature,
                                    },
                                    &Sequential,
                                ))
                            }
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_scheme_batch_verify_same_signer
);
