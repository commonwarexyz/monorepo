//! Throughput of the public batch-verification API across batch sizes and signing-key counts.
//! Regular batches use independent keys and exclude verifier construction from timing. Lazy
//! batches measure queueing and verification with either deferred or already decoded keys.
//! Fixture generation and constructing or dropping retained lazy wrappers are not timed. Messages
//! are distinct 32-byte values in every workload.

use commonware_codec::types::lazy::Lazy;
use commonware_cryptography_curve25519::signing::{
    BatchVerifier, Signature, SigningKey, VerifyingKey,
};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, TestRng, test_rng};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_BATCH_VERIFY_BENCH";
const MESSAGE_SIZE: usize = 32;

/// Generates `n` valid `(verifying key, signature, message)` triples using `key_count` signing keys
/// and distinct 32-byte messages.
fn generate_batch(n: usize, key_count: usize) -> Vec<(VerifyingKey, Signature, Vec<u8>)> {
    let mut rng = test_rng();
    let keys = (0..key_count)
        .map(|_| SigningKey::random(&mut rng))
        .collect::<Vec<_>>();
    (0..n)
        .map(|i| {
            let signing_key = &keys[i % key_count];

            let mut message = vec![0u8; MESSAGE_SIZE];
            message[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let signature = signing_key.sign(NAMESPACE, &message);

            (signing_key.verifying_key(), signature, message)
        })
        .collect()
}

fn batch_verifier(batch: &[(VerifyingKey, Signature, Vec<u8>)]) -> BatchVerifier<'static> {
    let mut verifier = BatchVerifier::new(batch.len());
    for (verifying_key, signature, message) in batch {
        verifier.add(NAMESPACE, message, verifying_key, signature);
    }
    verifier
}

/// Nested so `module_path!()` includes the crate::module separator the benchmark-name lint (and
/// the benchmark-tracking dashboard) expect.
mod verify_batch_bytes_bench {
    use super::{
        BatchSize, Criterion, NZUsize, Rayon, Sequential, TestRng, Throughput, batch_verifier,
        black_box, generate_batch,
    };

    pub fn bench(c: &mut Criterion) {
        let mut group = c.benchmark_group(module_path!());
        for n in [1, 10, 100, 1_000, 10_000, 16_384] {
            let batch = generate_batch(n, n);
            for concurrency in [1, 8, 16, 32] {
                let rayon = (concurrency > 1).then(|| Rayon::new(NZUsize!(concurrency)).unwrap());
                group.throughput(Throughput::Elements(n as u64));
                group.bench_function(format!("sigs={n} conc={concurrency}"), |b| {
                    b.iter_batched(
                        || (TestRng::new(1), batch_verifier(&batch)),
                        |(mut rng, verifier)| {
                            #[allow(clippy::option_if_let_else)]
                            if let Some(rayon) = rayon.as_ref() {
                                black_box(verifier.verify(&mut rng, rayon))
                            } else {
                                black_box(verifier.verify(&mut rng, &Sequential))
                            }
                        },
                        BatchSize::SmallInput,
                    );
                });
            }
        }
    }
}

mod verify_lazy_batch_bench {
    use super::{
        BatchSize, BatchVerifier, Criterion, Lazy, NAMESPACE, NZUsize, Rayon, Sequential, TestRng,
        Throughput, black_box, generate_batch,
    };

    pub fn bench(c: &mut Criterion) {
        let mut group = c.benchmark_group(module_path!());
        for n in [1_024, 16_384] {
            group.throughput(Throughput::Elements(n as u64));
            for key_count in [n, 64, 1] {
                let batch = generate_batch(n, key_count);
                for concurrency in [1, 8] {
                    let rayon =
                        (concurrency > 1).then(|| Rayon::new(NZUsize!(concurrency)).unwrap());
                    for cache in ["cold", "warm"] {
                        group.bench_function(
                            format!("sigs={n} keys={key_count} conc={concurrency} cache={cache}"),
                            |b| {
                                b.iter_batched(
                                    || {
                                        let keys = batch
                                            .iter()
                                            .map(|(key, _, _)| {
                                                if cache == "warm" {
                                                    Lazy::new(key.clone())
                                                } else {
                                                    Lazy::deferred(&mut key.as_ref(), ())
                                                }
                                            })
                                            .collect::<Vec<_>>();
                                        (TestRng::new(1), keys)
                                    },
                                    |(mut rng, keys)| {
                                        let mut verifier = BatchVerifier::new(batch.len());
                                        for ((_, signature, message), key) in
                                            batch.iter().zip(&keys)
                                        {
                                            verifier.add_lazy(NAMESPACE, message, key, signature);
                                        }
                                        #[allow(clippy::option_if_let_else)]
                                        let verified = if let Some(rayon) = rayon.as_ref() {
                                            black_box(verifier.verify(&mut rng, rayon))
                                        } else {
                                            black_box(verifier.verify(&mut rng, &Sequential))
                                        };
                                        (verified, keys)
                                    },
                                    BatchSize::SmallInput,
                                );
                            },
                        );
                    }
                }
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = verify_batch_bytes_bench::bench, verify_lazy_batch_bench::bench
}
criterion_main!(benches);
