#![no_main]
// The `impl_certificate_bls12381_threshold!` expansion contains a `#[cfg(feature = "mocks")]`
// gated fixture helper; this crate does not define that feature.
#![allow(unexpected_cfgs)]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    bls12381::{
        certificate::threshold::Certificate,
        dkg::feldman_desmedt as dkg,
        primitives::variant::{MinPk, MinSig, Variant},
    },
    certificate::{Scheme as _, Subject},
    ed25519::{self, PrivateKey as Ed25519PrivateKey},
    impl_certificate_bls12381_threshold,
    sha256::Digest as Sha256Digest,
    Signer as _,
};
use commonware_math::algebra::{Additive, Random};
use commonware_parallel::Sequential;
use commonware_utils::{ordered::Set, Faults, N3f1, Participant, TryCollect};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};
use std::{collections::BTreeSet, num::NonZeroU32};

const NAMESPACE: &[u8] = b"fuzz-bls12381-threshold-certificate";

/// Subject type for the generated scheme. Mirrors the test fixture in the module.
#[derive(Clone, Debug)]
pub struct TestSubject {
    message: Bytes,
}

impl Subject for TestSubject {
    type Namespace = Vec<u8>;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        derived
    }

    fn message(&self) -> Bytes {
        self.message.clone()
    }
}

impl_certificate_bls12381_threshold!(TestSubject, Vec<u8>);

#[derive(Arbitrary, Debug)]
enum Op {
    Sign {
        signer: u8,
        message: Vec<u8>,
    },
    VerifyAttestation {
        signer: u8,
        message: Vec<u8>,
        corrupt: bool,
    },
    VerifyAttestations {
        signers: Vec<u8>,
        message: Vec<u8>,
        corrupt: bool,
    },
    Assemble {
        signers: Vec<u8>,
        message: Vec<u8>,
    },
    VerifyStoredCertificate {
        which: u16,
        corrupt: bool,
    },
    VerifyStoredCertificates,
    ArbitraryCertificate(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    n: u8,
    seed: u64,
    ops: Vec<Op>,
}

const MAX_OPERATIONS: usize = 64;

/// Distinct participant indices (0-based) selected by the fuzzer.
fn distinct_indices(selection: &[u8], n: usize) -> Vec<usize> {
    selection
        .iter()
        .map(|&s| (s as usize) % n)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn run<V: Variant>(seed: u64, n: u32, ops: &[Op])
where
    V::Signature: for<'a> Arbitrary<'a> + Additive,
{
    let mut rng = StdRng::seed_from_u64(seed);

    // Build a valid committee: ed25519 identities plus a threshold polynomial.
    let identity_keys: Vec<_> = (0..n)
        .map(|_| Ed25519PrivateKey::random(&mut rng))
        .collect();
    let Ok(participants): Result<Set<ed25519::PublicKey>, _> =
        identity_keys.iter().map(|sk| sk.public_key()).try_collect()
    else {
        return;
    };
    let total = NonZeroU32::new(n).unwrap();
    let (polynomial, shares) = dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), total);

    let signers: Vec<Scheme<ed25519::PublicKey, V>> = shares
        .into_iter()
        .map(|share| {
            Scheme::signer(NAMESPACE, participants.clone(), polynomial.clone(), share).unwrap()
        })
        .collect();
    let verifier = Scheme::verifier(NAMESPACE, participants.clone(), polynomial.clone());
    let cert_verifier =
        Scheme::<ed25519::PublicKey, V>::certificate_verifier(NAMESPACE, *polynomial.public());
    let quorum = N3f1::quorum(n) as usize;
    let n = n as usize;

    // Accessors and constants.
    assert!(!Scheme::<ed25519::PublicKey, V>::is_attributable());
    assert!(Scheme::<ed25519::PublicKey, V>::is_batchable());
    verifier.certificate_codec_config();
    Scheme::<ed25519::PublicKey, V>::certificate_codec_config_unbounded();
    assert!(signers[0].share().is_some());
    assert!(signers[0].me().is_some());
    let _ = signers[0].identity();
    let _ = signers[0].participants();
    assert!(verifier.share().is_none());
    assert!(verifier.me().is_none());
    let _ = verifier.participants();
    let _ = verifier.identity();
    let _ = cert_verifier.identity();

    let mut certs: Vec<(Vec<u8>, Certificate<V>)> = Vec::new();

    for op in ops {
        match op {
            Op::Sign { signer, message } => {
                let subject = TestSubject {
                    message: Bytes::copy_from_slice(message),
                };
                assert!(signers[*signer as usize % n]
                    .sign::<Sha256Digest>(subject)
                    .is_some());
            }
            Op::VerifyAttestation {
                signer,
                message,
                corrupt,
            } => {
                let subject = TestSubject {
                    message: Bytes::copy_from_slice(message),
                };
                let Some(attestation) =
                    signers[*signer as usize % n].sign::<Sha256Digest>(subject.clone())
                else {
                    continue;
                };
                if *corrupt {
                    let mut bad = attestation;
                    bad.signer = Participant::new(u32::MAX);
                    let _ = verifier.verify_attestation::<_, Sha256Digest>(
                        &mut rng,
                        subject,
                        &bad,
                        &Sequential,
                    );
                } else {
                    assert!(verifier.verify_attestation::<_, Sha256Digest>(
                        &mut rng,
                        subject,
                        &attestation,
                        &Sequential,
                    ));
                }
            }
            Op::VerifyAttestations {
                signers: selection,
                message,
                corrupt,
            } => {
                let subject = TestSubject {
                    message: Bytes::copy_from_slice(message),
                };
                let mut attestations: Vec<_> = distinct_indices(selection, n)
                    .into_iter()
                    .filter_map(|i| signers[i].sign::<Sha256Digest>(subject.clone()))
                    .collect();
                if attestations.is_empty() {
                    continue;
                }
                if *corrupt {
                    attestations[0].signer = Participant::new(u32::MAX);
                }
                let result = verifier.verify_attestations::<_, Sha256Digest, _>(
                    &mut rng,
                    subject,
                    attestations.clone(),
                    &Sequential,
                );
                if !corrupt {
                    assert!(result.invalid.is_empty());
                    assert_eq!(result.verified.len(), attestations.len());
                }
            }
            Op::Assemble {
                signers: selection,
                message,
            } => {
                let subject = TestSubject {
                    message: Bytes::copy_from_slice(message),
                };
                let mut attestations: Vec<_> = distinct_indices(selection, n)
                    .into_iter()
                    .filter_map(|i| signers[i].sign::<Sha256Digest>(subject.clone()))
                    .collect();
                if attestations.len() < quorum {
                    assert!(signers[0]
                        .assemble::<_, N3f1>(attestations, &Sequential)
                        .is_none());
                } else {
                    // Exactly a quorum of valid, distinct partials must assemble.
                    attestations.truncate(quorum);
                    let certificate = signers[0]
                        .assemble::<_, N3f1>(attestations, &Sequential)
                        .expect("quorum-valid attestations assemble");
                    assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        subject,
                        &certificate,
                        &Sequential,
                    ));
                    let encoded = certificate.encode();
                    let decoded = Certificate::<V>::decode(encoded).expect("certificate decodes");
                    assert_eq!(decoded, certificate);
                    certs.push((message.clone(), certificate));
                }
            }
            Op::VerifyStoredCertificate { which, corrupt } => {
                if certs.is_empty() {
                    continue;
                }
                let (message, certificate) = &certs[*which as usize % certs.len()];
                let subject = TestSubject {
                    message: Bytes::copy_from_slice(message),
                };
                if *corrupt {
                    let bad = Certificate::<V>::new(V::Signature::zero());
                    let _ = cert_verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        subject,
                        &bad,
                        &Sequential,
                    );
                } else {
                    assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        subject.clone(),
                        certificate,
                        &Sequential,
                    ));
                    assert!(cert_verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        subject,
                        certificate,
                        &Sequential,
                    ));
                }
            }
            Op::VerifyStoredCertificates => {
                let items: Vec<(TestSubject, &Certificate<V>)> = certs
                    .iter()
                    .map(|(message, certificate)| {
                        (
                            TestSubject {
                                message: Bytes::copy_from_slice(message),
                            },
                            certificate,
                        )
                    })
                    .collect();
                assert!(verifier.verify_certificates::<_, Sha256Digest, _, N3f1>(
                    &mut rng,
                    items.into_iter(),
                    &Sequential,
                ));
            }
            Op::ArbitraryCertificate(data) => {
                let mut u = Unstructured::new(data);
                if let Ok(certificate) = Certificate::<V>::arbitrary(&mut u) {
                    let _ = certificate.get();
                    let encoded = certificate.encode();
                    let decoded =
                        Certificate::<V>::decode(encoded).expect("certificate roundtrips");
                    assert_eq!(decoded, certificate);
                    let subject = TestSubject {
                        message: Bytes::from_static(b"arbitrary"),
                    };
                    let _ = cert_verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        subject,
                        &certificate,
                        &Sequential,
                    );
                }
            }
        }
    }
}

fuzz_target!(|input: Input| {
    let n = 4 + (input.n % 4) as u32;
    let ops = &input.ops[..input.ops.len().min(MAX_OPERATIONS)];
    run::<MinPk>(input.seed, n, ops);
    run::<MinSig>(input.seed, n, ops);
});
