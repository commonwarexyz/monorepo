use commonware_cryptography::{ed25519, BatchVerifier, Signer};
use commonware_codec::{DecodeExt, Encode};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::NZUsize;
use criterion::{criterion_group, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

/// Times the full from-wire pipeline for distinct keys and distinct messages:
/// decoding each received public key and signature from bytes (where `standard`
/// pays a point decompression per key and per `R`, while `hinted` pays only an
/// on-curve check), assembling the batch, and verifying.
fn bench_variant<S, B>(c: &mut Criterion, variant: &str)
where
    S: Signer,
    B: BatchVerifier<PublicKey = S::PublicKey>,
    S::PublicKey: DecodeExt<()>,
    S::Signature: DecodeExt<()>,
{
    let namespace = b"namespace";
    for n_signatures in [1, 10, 100, 1000, 10000].into_iter() {
        for concurrency in [1, 8] {
            let rayon = (concurrency > 1).then(|| Rayon::new(NZUsize!(concurrency)).unwrap());
            let mut inputs = Vec::with_capacity(n_signatures);
            for _ in 0..n_signatures {
                let signer = S::random(&mut thread_rng());
                let mut msg = [0u8; 32];
                thread_rng().fill(&mut msg);
                let public_key = signer.public_key().encode().to_vec();
                let signature = signer.sign(namespace, &msg).encode().to_vec();
                inputs.push((public_key, signature, msg));
            }
            c.bench_function(
                &format!(
                    "{}/variant={variant} sigs={n_signatures} conc={concurrency}",
                    module_path!()
                ),
                |b| {
                    b.iter(|| {
                        let mut batch = B::new();
                        for (public_key, signature, msg) in inputs.iter() {
                            let public_key = S::PublicKey::decode(public_key.as_ref()).unwrap();
                            let signature = S::Signature::decode(signature.as_ref()).unwrap();
                            assert!(batch.add(namespace, msg, &public_key, &signature));
                        }

                        #[allow(clippy::option_if_let_else)]
                        if let Some(rayon) = rayon.as_ref() {
                            black_box(batch.verify(&mut thread_rng(), rayon))
                        } else {
                            black_box(batch.verify(&mut thread_rng(), &Sequential))
                        }
                    });
                },
            );
        }
    }
}

fn bench_batch_verify_distinct_full(c: &mut Criterion) {
    bench_variant::<ed25519::standard::PrivateKey, ed25519::standard::Batch>(c, "standard");
    bench_variant::<ed25519::hinted::PrivateKey, ed25519::hinted::Batch>(c, "hinted");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_batch_verify_distinct_full
}
