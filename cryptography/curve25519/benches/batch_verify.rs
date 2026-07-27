//! Throughput of [`verify_batch_bytes`] across batch sizes, up to the ~16k-signature scale a busy
//! validator sees per block, starting from raw wire bytes for everything (public key, signature,
//! message) -- so this measures decompressing both `A` and `R` plus the MSM, not just the MSM.
//! Each signature is from an independent key over an independent message (no key/message reuse to
//! amortize), the harder case for the underlying MSM.
use commonware_cryptography_curve25519::signing::{Signature, verify_batch_bytes};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, TestRng, test_rng};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use ed25519_consensus::SigningKey as RefSigningKey;
use rand_core::Rng;
use std::hint::black_box;

/// Generates `n` valid `(pubkey_bytes, Signature, message)` triples, signed by independent keys
/// over independent messages using the `ed25519-consensus` reference implementation (this crate
/// does not yet implement signing). Nothing here is decompressed: that is the point being
/// measured.
fn generate_batch(n: usize) -> Vec<([u8; 32], Signature, Vec<u8>)> {
    generate_batch_with_message_size(n, 0)
}

/// Like [`generate_batch`], but with `message_size`-byte messages (unique per signature) when
/// `message_size > 0` -- for cross-library comparisons that fix a wire-realistic message size.
fn generate_batch_with_message_size(
    n: usize,
    message_size: usize,
) -> Vec<([u8; 32], Signature, Vec<u8>)> {
    let mut rng = test_rng();
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let signing_key = RefSigningKey::from(seed);
            let pubkey_bytes = signing_key.verification_key().to_bytes();

            let message = if message_size == 0 {
                format!("message {i}").into_bytes()
            } else {
                let mut message = vec![0u8; message_size];
                message[..8].copy_from_slice(&(i as u64).to_le_bytes());
                message
            };
            let signature = Signature::from_bytes(signing_key.sign(&message).to_bytes());

            (pubkey_bytes, signature, message)
        })
        .collect()
}

/// Nested so `module_path!()` includes the crate::module separator the benchmark-name lint (and
/// the benchmark-tracking dashboard) expect.
mod verify_batch_bytes_bench {
    use super::{
        BatchSize, Criterion, NZUsize, Rayon, Sequential, TestRng, Throughput, black_box,
        generate_batch, verify_batch_bytes,
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
                        || TestRng::new(1),
                        |mut rng| {
                            let items =
                                batch.iter().map(|(pk, sig, msg)| (pk, sig, msg.as_slice()));
                            #[allow(clippy::option_if_let_else)]
                            if let Some(rayon) = rayon.as_ref() {
                                black_box(verify_batch_bytes(&mut rng, items, rayon))
                            } else {
                                black_box(verify_batch_bytes(&mut rng, items, &Sequential))
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
                        || TestRng::new(1),
                        |mut rng| {
                            let items =
                                batch.iter().map(|(pk, sig, msg)| (pk, sig, msg.as_slice()));
                            #[allow(clippy::option_if_let_else)]
                            if let Some(rayon) = rayon.as_ref() {
                                black_box(verify_batch_bytes(&mut rng, items, rayon))
                            } else {
                                black_box(verify_batch_bytes(&mut rng, items, &Sequential))
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
