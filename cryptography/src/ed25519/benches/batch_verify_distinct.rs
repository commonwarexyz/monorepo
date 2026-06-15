use commonware_cryptography::{ed25519, BatchVerifier, Signer};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::NZUsize;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

/// Times batch verification only (the batch is assembled in the untimed setup),
/// for distinct keys and distinct messages.
fn bench_variant<S, B>(c: &mut Criterion, variant: &str)
where
    S: Signer,
    B: BatchVerifier<PublicKey = S::PublicKey>,
{
    let namespace = b"namespace";
    for n_signatures in [1, 10, 100, 1000, 10000].into_iter() {
        for concurrency in [1, 8] {
            let rayon = (concurrency > 1).then(|| Rayon::new(NZUsize!(concurrency)).unwrap());
            let mut msgs = Vec::with_capacity(n_signatures);
            for _ in 0..n_signatures {
                let mut msg = [0u8; 32];
                thread_rng().fill(&mut msg);
                msgs.push(msg);
            }
            c.bench_function(
                &format!(
                    "{}/variant={variant} sigs={n_signatures} conc={concurrency}",
                    module_path!()
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let mut batch = B::new();
                            for msg in msgs.iter() {
                                let signer = S::random(&mut thread_rng());
                                let sig = signer.sign(namespace, msg);
                                assert!(batch.add(namespace, msg, &signer.public_key(), &sig));
                            }
                            batch
                        },
                        |batch| {
                            #[allow(clippy::option_if_let_else)]
                            if let Some(rayon) = rayon.as_ref() {
                                black_box(batch.verify(&mut thread_rng(), rayon))
                            } else {
                                black_box(batch.verify(&mut thread_rng(), &Sequential))
                            }
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

fn bench_batch_verify_distinct(c: &mut Criterion) {
    bench_variant::<ed25519::standard::PrivateKey, ed25519::standard::Batch>(c, "standard");
    bench_variant::<ed25519::hinted::PrivateKey, ed25519::hinted::Batch>(c, "hinted");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_batch_verify_distinct
}
