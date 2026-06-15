use commonware_cryptography::{ed25519, BatchVerifier, Signer};
use commonware_codec::{DecodeExt, Encode};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::NZUsize;
use criterion::{criterion_group, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

/// Batch-verifies distinct-key, distinct-message signatures over the full
/// from-wire block path, mirroring how `constantinople` verifies a block:
/// public keys and signatures are decoded (decompressing points) in parallel
/// across the strategy, as `preload_transaction_chunks` does, then batch
/// signature verification runs over the already-decoded inputs. `standard`
/// decompresses each public key and each `R`; `hinted` only on-curve-checks them.
fn bench_variant<S, B>(c: &mut Criterion, variant: &str)
where
    S: Signer,
    B: BatchVerifier<PublicKey = S::PublicKey>,
    S::PublicKey: DecodeExt<()> + Send,
    S::Signature: DecodeExt<()> + Send,
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
            let decode = |input: &(Vec<u8>, Vec<u8>, [u8; 32])| {
                (
                    S::PublicKey::decode(input.0.as_ref()).unwrap(),
                    S::Signature::decode(input.1.as_ref()).unwrap(),
                )
            };
            c.bench_function(
                &format!(
                    "{}/variant={variant} sigs={n_signatures} conc={concurrency}",
                    module_path!()
                ),
                |b| {
                    b.iter(|| {
                        // Decode public keys and signatures (decompressing points)
                        // in parallel, as the block path does before batch verify.
                        let decoded: Vec<(S::PublicKey, S::Signature)> = rayon.as_ref().map_or_else(
                            || Sequential.map_collect_vec(&inputs, decode),
                            |rayon| rayon.map_collect_vec(&inputs, decode),
                        );

                        let mut batch = B::new();
                        for ((public_key, signature), input) in decoded.iter().zip(&inputs) {
                            assert!(batch.add(namespace, &input.2, public_key, signature));
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

fn bench_batch_verify_distinct(c: &mut Criterion) {
    bench_variant::<ed25519::standard::PrivateKey, ed25519::standard::Batch>(c, "standard");
    bench_variant::<ed25519::hinted::PrivateKey, ed25519::hinted::Batch>(c, "hinted");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_batch_verify_distinct
}
