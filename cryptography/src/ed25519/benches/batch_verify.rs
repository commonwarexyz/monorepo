//! Compare dalek, the in-tree backend, and public dispatch on identical fixtures.
//! `verify` excludes queuing, `queued` includes it with cached keys, and `decoded` also
//! includes public-key decoding. Signing is never timed.

use super::dalek;
use commonware_codec::{Copying, DecodeExt as _};
use commonware_cryptography::{BatchVerifier as _, Signer as _, ed25519};
use commonware_cryptography_curve25519::batch;
use commonware_math::algebra::Random as _;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::{NZUsize, TestRng, test_rng, union_unique};
use criterion::{BatchSize, Criterion, Throughput, criterion_group};
use std::hint::black_box;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ED25519_BATCH_COMPARE_BENCH";

struct Item {
    key: ed25519::PublicKey,
    dalek_key: dalek::VerificationKey,
    key_bytes: [u8; 32],
    signature: ed25519::Signature,
    signature_bytes: [u8; 64],
    message: Vec<u8>,
}

enum Verifier {
    Dalek(dalek::batch::Verifier<Vec<u8>>),
    Curve(batch::Verifier<Vec<u8>>),
    Dispatch(ed25519::Batch),
}

impl Verifier {
    fn queued(items: &[Item], backend: &str, decode: bool) -> Self {
        let mut verifier = match backend {
            "dalek" => Self::Dalek(dalek::batch::Verifier::new(items.len())),
            "curve25519" => Self::Curve(batch::Verifier::new(items.len())),
            "dispatch" => Self::Dispatch(ed25519::Batch::new(items.len())),
            _ => unreachable!(),
        };
        for item in items {
            match &mut verifier {
                Self::Dalek(verifier) => {
                    let key = if decode {
                        dalek::VerificationKey::try_from(black_box(item.key_bytes)).unwrap()
                    } else {
                        item.dalek_key
                    };
                    verifier.queue(
                        key,
                        dalek::Signature::from(item.signature_bytes),
                        union_unique(NAMESPACE, &item.message),
                    );
                }
                Self::Curve(verifier) => {
                    // The integration preserves eager public-key validation even though the
                    // low-level in-tree verifier itself accepts unvalidated encodings.
                    if decode {
                        black_box(
                            ed25519::PublicKey::decode(Copying(black_box(
                                item.key_bytes.as_slice(),
                            )))
                            .unwrap(),
                        );
                    }
                    verifier.queue(
                        item.key_bytes,
                        item.signature_bytes,
                        union_unique(NAMESPACE, &item.message),
                    );
                }
                Self::Dispatch(verifier) => {
                    let decoded;
                    let key = if decode {
                        decoded = ed25519::PublicKey::decode(Copying(black_box(
                            item.key_bytes.as_slice(),
                        )))
                        .unwrap();
                        &decoded
                    } else {
                        &item.key
                    };
                    assert!(verifier.add(NAMESPACE, &item.message, key, &item.signature));
                }
            }
        }
        verifier
    }

    fn verify(self, strategy: &impl Strategy) -> bool {
        let mut rng = TestRng::new(1);
        match self {
            Self::Dalek(verifier) => verifier.verify(&mut rng, strategy).is_ok(),
            Self::Curve(verifier) => verifier.verify(&mut rng, strategy),
            Self::Dispatch(verifier) => verifier.verify(&mut rng, strategy),
        }
    }
}

fn measure(
    c: &mut Criterion,
    items: &[Item],
    signers: usize,
    conc: usize,
    strategy: &impl Strategy,
) {
    let n = items.len();
    let bytes = items[0].message.len();
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(n as u64));
    for backend in ["dalek", "curve25519", "dispatch"] {
        assert!(Verifier::queued(items, backend, false).verify(strategy));
        for mode in ["verify", "queued", "decoded"] {
            group.bench_function(
                format!("sigs={n} signers={signers} bytes={bytes} conc={conc} backend={backend} mode={mode}"),
                |b| {
                    if mode == "verify" {
                        b.iter_batched(
                            || Verifier::queued(items, backend, false),
                            |verifier| black_box(verifier.verify(strategy)),
                            BatchSize::LargeInput,
                        );
                    } else {
                        b.iter(|| {
                            black_box(Verifier::queued(black_box(items), backend, mode == "decoded").verify(strategy))
                        });
                    }
                },
            );
        }
    }
}

fn bench(c: &mut Criterion) {
    let parallel = Rayon::new(NZUsize!(8)).unwrap();
    for n in [1, 32, 1_000, 16_384, 100_000] {
        let mut signer_counts = vec![1, n.min(32), n];
        signer_counts.dedup();
        for signers in signer_counts {
            for bytes in [32, 256] {
                let mut rng = test_rng();
                let keys: Vec<_> = (0..signers)
                    .map(|_| ed25519::PrivateKey::random(&mut rng))
                    .collect();
                let items: Vec<_> = (0..n)
                    .map(|i| {
                        let signer = &keys[i % signers];
                        let key = signer.public_key();
                        let key_bytes = key.as_ref().try_into().unwrap();
                        let mut message = vec![0; bytes];
                        message[..8].copy_from_slice(&(i as u64).to_le_bytes());
                        let signature = signer.sign(NAMESPACE, &message);
                        let signature_bytes = signature.as_ref().try_into().unwrap();
                        Item {
                            key,
                            dalek_key: dalek::VerificationKey::try_from(key_bytes).unwrap(),
                            key_bytes,
                            signature,
                            signature_bytes,
                            message,
                        }
                    })
                    .collect();
                measure(c, &items, signers, 1, &Sequential);
                measure(c, &items, signers, 8, &parallel);
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}
