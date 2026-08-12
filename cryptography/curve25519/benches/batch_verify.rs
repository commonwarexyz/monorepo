//! Throughput of the public batch-verification API across batch sizes. Each signature is from an
//! independent key over an independent message (no key/message reuse to amortize), the harder case
//! for the underlying MSM. Fixture generation and verifier construction are not timed.
use commonware_cryptography_curve25519::signing::{
    BatchVerifier, Signature, SigningKey, VerifyingKey,
};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, TestRng, test_rng};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_BATCH_VERIFY_BENCH";

/// Generates `n` valid `(verifying key, signature, message)` triples, signed by independent keys
/// over independent messages using the public API.
fn generate_batch(n: usize) -> Vec<(VerifyingKey, Signature, Vec<u8>)> {
    generate_batch_with_message_size(n, 0)
}

/// Like [`generate_batch`], but with `message_size`-byte messages (unique per signature) when
/// `message_size > 0` -- for cross-library comparisons that fix a wire-realistic message size.
fn generate_batch_with_message_size(
    n: usize,
    message_size: usize,
) -> Vec<(VerifyingKey, Signature, Vec<u8>)> {
    let mut rng = test_rng();
    (0..n)
        .map(|i| {
            let signing_key = SigningKey::random(&mut rng);

            let message = if message_size == 0 {
                format!("message {i}").into_bytes()
            } else {
                let mut message = vec![0u8; message_size];
                message[..8].copy_from_slice(&(i as u64).to_le_bytes());
                message
            };
            let signature = signing_key.sign(NAMESPACE, &message);

            (signing_key.verifying_key(), signature, message)
        })
        .collect()
}

fn batch_verifier(batch: &[(VerifyingKey, Signature, Vec<u8>)]) -> BatchVerifier {
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
        // Temporary cross-library comparison points (narya-ed25519 uses 1232-byte messages, the
        // Solana packet size, and tops out at 64-signature groups): distinct bench names so the
        // standard sweep's baselines stay comparable run over run.
        for n in [64, 256, 1_024, 4_096, 16_384, 65_536] {
            let batch = super::generate_batch_with_message_size(n, 1232);
            for concurrency in [1usize, 32] {
                let rayon = (concurrency > 1).then(|| Rayon::new(NZUsize!(concurrency)).unwrap());
                group.throughput(Throughput::Elements(n as u64));
                group.bench_function(format!("msg1232/sigs={n} conc={concurrency}"), |b| {
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
        for n in [1, 10, 100, 1_000, 10_000, 16_384] {
            let batch = generate_batch(n);
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = verify_batch_bytes_bench::bench
}
criterion_main!(benches);
