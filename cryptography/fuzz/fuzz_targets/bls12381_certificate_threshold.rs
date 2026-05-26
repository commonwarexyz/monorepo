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
    certificate::{Attestation, ConstantProvider, Provider, Scheme as CertScheme, Signers, Subject},
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
use std::{collections::BTreeSet, num::NonZeroU32, sync::Arc};

const NAMESPACE: &[u8] = b"fuzz-bls12381-threshold-certificate";

/// Subject type for the generated scheme. Borrows its message so it can be `Copy`
/// (required by `verify_certificates_bisect`).
#[derive(Clone, Copy, Debug)]
pub struct TestSubject<'a> {
    message: &'a [u8],
}

impl Subject for TestSubject<'_> {
    type Namespace = Vec<u8>;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        derived
    }

    fn message(&self) -> Bytes {
        Bytes::copy_from_slice(self.message)
    }
}

impl_certificate_bls12381_threshold!(TestSubject<'a>, Vec<u8>);

fn subject(message: &[u8]) -> TestSubject<'_> {
    TestSubject { message }
}

/// A [`Provider`] that only implements `scoped`, exercising the default `all` (returns `None`).
#[derive(Clone)]
struct DefaultAllProvider<S: CertScheme>(Arc<S>);

impl<S: CertScheme> Provider for DefaultAllProvider<S> {
    type Scope = ();
    type Scheme = S;

    fn scoped(&self, _: ()) -> Option<Arc<S>> {
        Some(self.0.clone())
    }
}

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
    BisectStoredCertificates,
    ArbitraryCertificate(Vec<u8>),
    CertificateHelpers(Vec<u8>),
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
                assert!(signers[*signer as usize % n]
                    .sign::<Sha256Digest>(subject(message))
                    .is_some());
            }
            Op::VerifyAttestation {
                signer,
                message,
                corrupt,
            } => {
                let Some(attestation) =
                    signers[*signer as usize % n].sign::<Sha256Digest>(subject(message))
                else {
                    continue;
                };
                if *corrupt {
                    let mut bad = attestation;
                    bad.signer = Participant::new(u32::MAX);
                    let _ = verifier.verify_attestation::<_, Sha256Digest>(
                        &mut rng,
                        subject(message),
                        &bad,
                        &Sequential,
                    );
                } else {
                    assert!(verifier.verify_attestation::<_, Sha256Digest>(
                        &mut rng,
                        subject(message),
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
                let mut attestations: Vec<_> = distinct_indices(selection, n)
                    .into_iter()
                    .filter_map(|i| signers[i].sign::<Sha256Digest>(subject(message)))
                    .collect();
                if attestations.is_empty() {
                    continue;
                }
                if *corrupt {
                    attestations[0].signer = Participant::new(u32::MAX);
                }
                let result = verifier.verify_attestations::<_, Sha256Digest, _>(
                    &mut rng,
                    subject(message),
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
                let mut attestations: Vec<_> = distinct_indices(selection, n)
                    .into_iter()
                    .filter_map(|i| signers[i].sign::<Sha256Digest>(subject(message)))
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
                        subject(message),
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
                if *corrupt {
                    let bad = Certificate::<V>::new(V::Signature::zero());
                    let _ = cert_verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        subject(message),
                        &bad,
                        &Sequential,
                    );
                } else {
                    assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        subject(message),
                        certificate,
                        &Sequential,
                    ));
                    assert!(cert_verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        subject(message),
                        certificate,
                        &Sequential,
                    ));
                }
            }
            Op::VerifyStoredCertificates => {
                let items: Vec<(TestSubject<'_>, &Certificate<V>)> = certs
                    .iter()
                    .map(|(message, certificate)| (subject(message), certificate))
                    .collect();
                assert!(verifier.verify_certificates::<_, Sha256Digest, _, N3f1>(
                    &mut rng,
                    items.into_iter(),
                    &Sequential,
                ));
            }
            Op::BisectStoredCertificates => {
                // Empty input exercises the length-zero early return.
                let none: Vec<(TestSubject<'_>, &Certificate<V>)> = Vec::new();
                assert!(verifier
                    .verify_certificates_bisect::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        &none,
                        &Sequential
                    )
                    .is_empty());

                // Valid stored certificates plus one corrupt entry drive both the
                // batch-pass fill and the bisection split/singleton-fail paths.
                let bad = Certificate::<V>::new(V::Signature::zero());
                let mut items: Vec<(TestSubject<'_>, &Certificate<V>)> = certs
                    .iter()
                    .map(|(message, certificate)| (subject(message), certificate))
                    .collect();
                items.push((subject(b"corrupt"), &bad));
                let verified = verifier.verify_certificates_bisect::<_, Sha256Digest, N3f1>(
                    &mut rng,
                    &items,
                    &Sequential,
                );
                assert_eq!(verified.len(), certs.len() + 1);
                assert!(verified[..certs.len()].iter().all(|&v| v));
                assert!(!verified[certs.len()]);
            }
            Op::ArbitraryCertificate(data) => {
                let mut u = Unstructured::new(data);
                if let Ok(certificate) = Certificate::<V>::arbitrary(&mut u) {
                    let _ = certificate.get();
                    let encoded = certificate.encode();
                    let decoded =
                        Certificate::<V>::decode(encoded).expect("certificate roundtrips");
                    assert_eq!(decoded, certificate);
                    let _ = cert_verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        subject(b"arbitrary"),
                        &certificate,
                        &Sequential,
                    );
                }
            }
            Op::CertificateHelpers(data) => {
                let mut u = Unstructured::new(data);

                // `Attestation::arbitrary`.
                if let Ok(attestation) =
                    u.arbitrary::<Attestation<Scheme<ed25519::PublicKey, V>>>()
                {
                    let _ = (attestation.signer, attestation.signature.get().is_some());
                }

                // `Signers::arbitrary` and its accessors.
                if let Ok(signers) = u.arbitrary::<Signers>() {
                    assert_eq!(signers.iter().count(), signers.count());
                    assert!(signers.count() <= signers.len());
                }

                // `Provider` implementations: `ConstantProvider` overrides `all`,
                // `DefaultAllProvider` uses the default `all` (returns `None`).
                let constant =
                    ConstantProvider::<Scheme<ed25519::PublicKey, V>>::new(verifier.clone());
                assert!(constant.scoped(()).is_some());
                assert!(constant.all().is_some());
                let default_all = DefaultAllProvider(Arc::new(verifier.clone()));
                assert!(default_all.scoped(()).is_some());
                assert!(default_all.all().is_none());
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
