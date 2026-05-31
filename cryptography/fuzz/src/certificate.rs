//! Generic fuzz driver for `commonware-cryptography` certificate schemes.
//!
//! A single [`fuzz`] driver exercises the full attestation/certificate surface of the
//! [`commonware_cryptography::certificate::Scheme`] trait. Cryptographic settings (ed25519,
//! secp256r1, BLS12-381 multisig over each variant) are selected by the [`Fixture`] type
//! parameter, mirroring the parametrization in `coding/fuzz`.
// The `impl_certificate_*!` expansions contain `#[cfg(feature = "mocks")]` gated fixture
// helpers; this crate does not define that feature.
#![allow(unexpected_cfgs)]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_codec::{types::lazy::Lazy, Decode, Encode};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Private,
        ops::{aggregate, compute_public},
        variant::Variant,
    },
    certificate::{Scheme as CertScheme, Subject},
    ed25519::{self, PrivateKey as Ed25519PrivateKey},
    secp256r1::standard::PrivateKey as SecpPrivateKey,
    sha256::Digest as Sha256Digest,
    Signer as _,
};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use commonware_utils::{
    ordered::{BiMap, Set},
    Faults, FuzzRng, N3f1, Participant, TryCollect,
};
use core::marker::PhantomData;
use std::collections::BTreeSet;

const NAMESPACE: &[u8] = b"fuzz-certificate";
const MAX_OPERATIONS: usize = 64;
const MAX_MESSAGE: usize = 256;
const MAX_SELECTION: usize = 20;
/// Upper bound on the byte tape fed to [`FuzzRng`] (committee keys + verification randomness).
const MAX_RNG_BYTES: usize = 4096;
/// Upper bound on raw `DecodeCertificate` bytes; large enough to frame a full-size
/// attributable certificate for the largest committee (one signature per signer).
const MAX_CERTIFICATE_BYTES: usize = 2048;
/// Cap on stored certificates so repeated verify-all/bisect ops stay linear, not quadratic.
const MAX_STORED_CERTIFICATES: usize = 16;
/// Committee sizes that straddle the 1-byte signer-bitmap boundaries (8/9, 16/17).
const COMMITTEE_SIZES: [u32; 8] = [4, 5, 7, 8, 9, 15, 16, 17];

/// Borrowed-message subject shared by every scheme; `Copy` for `verify_certificates_bisect`.
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

fn subject(message: &[u8]) -> TestSubject<'_> {
    TestSubject { message }
}

mod ed25519_scheme {
    use super::TestSubject;
    use commonware_cryptography::impl_certificate_ed25519;

    impl_certificate_ed25519!(TestSubject<'a>, Vec<u8>);
}

mod secp256r1_scheme {
    use super::TestSubject;
    use commonware_cryptography::impl_certificate_secp256r1;

    impl_certificate_secp256r1!(TestSubject<'a>, Vec<u8>);
}

mod multisig_scheme {
    use super::TestSubject;
    use commonware_cryptography::impl_certificate_bls12381_multisig;

    impl_certificate_bls12381_multisig!(TestSubject<'a>, Vec<u8>);
}

/// A cryptographic setting: how to build a committee, derive subjects, and corrupt a certificate.
pub trait Fixture {
    /// Concrete certificate scheme exercised by this setting.
    type Scheme: CertScheme;

    /// Whether the scheme benefits from batch verification (cross-checked against the trait).
    const BATCHABLE: bool;

    /// Builds a committee of `n` signers plus a verifier. Returns `None` on key collision.
    fn setup(rng: &mut FuzzRng, n: u32) -> Option<(Vec<Self::Scheme>, Self::Scheme)>;

    /// Builds a subject for the given message.
    fn subject(message: &[u8]) -> <Self::Scheme as CertScheme>::Subject<'_, Sha256Digest>;

    /// Returns a deterministically-invalid clone of `certificate`.
    fn corrupt(
        certificate: &<Self::Scheme as CertScheme>::Certificate,
    ) -> <Self::Scheme as CertScheme>::Certificate;
}

/// Ed25519: same key for identity and signing, individual signatures, batchable.
pub struct Ed25519;

impl Fixture for Ed25519 {
    type Scheme = ed25519_scheme::Scheme;
    const BATCHABLE: bool = true;

    fn setup(rng: &mut FuzzRng, n: u32) -> Option<(Vec<Self::Scheme>, Self::Scheme)> {
        let keys: Vec<Ed25519PrivateKey> = (0..n)
            .map(|_| Ed25519PrivateKey::random(&mut *rng))
            .collect();
        let participants: Set<ed25519::PublicKey> =
            keys.iter().map(|k| k.public_key()).try_collect().ok()?;
        let signers = keys
            .into_iter()
            .map(|k| ed25519_scheme::Scheme::signer(NAMESPACE, participants.clone(), k).unwrap())
            .collect();
        let verifier = ed25519_scheme::Scheme::verifier(NAMESPACE, participants);
        Some((signers, verifier))
    }

    fn subject(message: &[u8]) -> <Self::Scheme as CertScheme>::Subject<'_, Sha256Digest> {
        subject(message)
    }

    fn corrupt(
        certificate: &<Self::Scheme as CertScheme>::Certificate,
    ) -> <Self::Scheme as CertScheme>::Certificate {
        let mut bad = certificate.clone();
        bad.signatures.swap(0, 1);
        bad
    }
}

/// Secp256r1: ed25519 identities, secp256r1 signing keys, individual signatures, not batchable.
pub struct Secp256r1;

impl Fixture for Secp256r1 {
    type Scheme = secp256r1_scheme::Scheme<ed25519::PublicKey>;
    const BATCHABLE: bool = false;

    fn setup(rng: &mut FuzzRng, n: u32) -> Option<(Vec<Self::Scheme>, Self::Scheme)> {
        let identity_keys: Vec<Ed25519PrivateKey> = (0..n)
            .map(|_| Ed25519PrivateKey::random(&mut *rng))
            .collect();
        let signing_keys: Vec<SecpPrivateKey> =
            (0..n).map(|_| SecpPrivateKey::random(&mut *rng)).collect();
        let participants: BiMap<ed25519::PublicKey, _> = identity_keys
            .iter()
            .zip(signing_keys.iter())
            .map(|(id, sk)| (id.public_key(), sk.public_key()))
            .try_collect()
            .ok()?;
        let signers = signing_keys
            .into_iter()
            .map(|sk| {
                secp256r1_scheme::Scheme::signer(NAMESPACE, participants.clone(), sk).unwrap()
            })
            .collect();
        let verifier = secp256r1_scheme::Scheme::verifier(NAMESPACE, participants);
        Some((signers, verifier))
    }

    fn subject(message: &[u8]) -> <Self::Scheme as CertScheme>::Subject<'_, Sha256Digest> {
        subject(message)
    }

    fn corrupt(
        certificate: &<Self::Scheme as CertScheme>::Certificate,
    ) -> <Self::Scheme as CertScheme>::Certificate {
        let mut bad = certificate.clone();
        bad.signatures.swap(0, 1);
        bad
    }
}

/// BLS12-381 multisig over variant `V`: ed25519 identities, BLS signing keys, aggregated.
pub struct Multisig<V>(PhantomData<V>);

impl<V: Variant> Fixture for Multisig<V> {
    type Scheme = multisig_scheme::Scheme<ed25519::PublicKey, V>;
    const BATCHABLE: bool = true;

    fn setup(rng: &mut FuzzRng, n: u32) -> Option<(Vec<Self::Scheme>, Self::Scheme)> {
        let identity_keys: Vec<Ed25519PrivateKey> = (0..n)
            .map(|_| Ed25519PrivateKey::random(&mut *rng))
            .collect();
        let signing_keys: Vec<Private> = (0..n).map(|_| Private::random(&mut *rng)).collect();
        let participants: BiMap<ed25519::PublicKey, V::Public> = identity_keys
            .iter()
            .zip(signing_keys.iter())
            .map(|(id, sk)| (id.public_key(), compute_public::<V>(sk)))
            .try_collect()
            .ok()?;
        let signers = signing_keys
            .into_iter()
            .map(|sk| multisig_scheme::Scheme::signer(NAMESPACE, participants.clone(), sk).unwrap())
            .collect();
        let verifier = multisig_scheme::Scheme::verifier(NAMESPACE, participants);
        Some((signers, verifier))
    }

    fn subject(message: &[u8]) -> <Self::Scheme as CertScheme>::Subject<'_, Sha256Digest> {
        subject(message)
    }

    fn corrupt(
        certificate: &<Self::Scheme as CertScheme>::Certificate,
    ) -> <Self::Scheme as CertScheme>::Certificate {
        let mut bad = certificate.clone();
        bad.signature = Lazy::from(aggregate::Signature::<V>::zero());
        bad
    }
}

#[derive(Debug)]
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
    DecodeCertificate(Vec<u8>),
}

/// Generates a length-bounded byte vector so mutation budget is not spent on size.
///
/// The length is clamped to the bytes actually remaining (after `int_in_range`'s own
/// consumption) so no input is discarded and no zero-padding dilutes the content.
fn bounded_bytes(u: &mut Unstructured, max: usize) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=max)?.min(u.len());
    Ok(u.bytes(len)?.to_vec())
}

fn gen_ops(u: &mut Unstructured) -> arbitrary::Result<Vec<Op>> {
    let count = u.int_in_range(1..=MAX_OPERATIONS)?;
    let mut ops = Vec::with_capacity(count);
    for _ in 0..count {
        let op = match u.int_in_range(0u8..=7)? {
            0 => Op::Sign {
                signer: u.arbitrary()?,
                message: bounded_bytes(u, MAX_MESSAGE)?,
            },
            1 => Op::VerifyAttestation {
                signer: u.arbitrary()?,
                message: bounded_bytes(u, MAX_MESSAGE)?,
                corrupt: u.arbitrary()?,
            },
            2 => Op::VerifyAttestations {
                signers: bounded_bytes(u, MAX_SELECTION)?,
                message: bounded_bytes(u, MAX_MESSAGE)?,
                corrupt: u.arbitrary()?,
            },
            3 => Op::Assemble {
                signers: bounded_bytes(u, MAX_SELECTION)?,
                message: bounded_bytes(u, MAX_MESSAGE)?,
            },
            4 => Op::VerifyStoredCertificate {
                which: u.arbitrary()?,
                corrupt: u.arbitrary()?,
            },
            5 => Op::VerifyStoredCertificates,
            6 => Op::BisectStoredCertificates,
            _ => Op::DecodeCertificate(bounded_bytes(u, MAX_CERTIFICATE_BYTES)?),
        };
        ops.push(op);
    }
    Ok(ops)
}

/// Fuzz input: a seed, a committee-size selector, and a bounded operation sequence.
#[derive(Debug)]
pub struct FuzzInput {
    size_index: u8,
    ops: Vec<Op>,
    rng_bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let size_index = u.arbitrary()?;
        let ops = gen_ops(u)?;
        // Remaining bytes become the FuzzRng tape so libfuzzer mutations map locally
        // to committee key material and verification randomness.
        let remaining = u.len().min(MAX_RNG_BYTES);
        let rng_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };
        Ok(FuzzInput {
            size_index,
            ops,
            rng_bytes,
        })
    }
}

/// Certificate type produced by fixture `F`.
type CertOf<F> = <<F as Fixture>::Scheme as CertScheme>::Certificate;

/// A `(subject, &certificate)` pair as consumed by batch certificate verification.
type Item<'a, F> = (
    <<F as Fixture>::Scheme as CertScheme>::Subject<'a, Sha256Digest>,
    &'a CertOf<F>,
);

/// Distinct participant indices (0-based) selected by the fuzzer.
fn distinct_indices(selection: &[u8], n: usize) -> Vec<usize> {
    selection
        .iter()
        .map(|&s| (s as usize) % n)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Drives the certificate scheme selected by `F` through a sequence of operations.
pub fn fuzz<F: Fixture>(input: FuzzInput)
where
    for<'a> <F::Scheme as CertScheme>::Subject<'a, Sha256Digest>: Copy,
{
    let FuzzInput {
        size_index,
        ops,
        rng_bytes,
    } = input;
    let n = COMMITTEE_SIZES[size_index as usize % COMMITTEE_SIZES.len()];
    let mut rng = FuzzRng::new(rng_bytes);
    let Some((signers, verifier)) = F::setup(&mut rng, n) else {
        return;
    };
    let n = n as usize;
    let quorum = N3f1::quorum(n) as usize;
    let cfg = verifier.certificate_codec_config();

    assert!(<F::Scheme as CertScheme>::is_attributable());
    assert_eq!(<F::Scheme as CertScheme>::is_batchable(), F::BATCHABLE);
    let _ = <F::Scheme as CertScheme>::certificate_codec_config_unbounded();
    assert!(verifier.me().is_none());
    assert!(signers[0].me().is_some());
    let _ = verifier.participants();

    let mut certs: Vec<(Vec<u8>, CertOf<F>)> = Vec::new();

    for op in &ops {
        match op {
            Op::Sign { signer, message } => {
                assert!(signers[*signer as usize % n]
                    .sign::<Sha256Digest>(F::subject(message))
                    .is_some());
            }
            Op::VerifyAttestation {
                signer,
                message,
                corrupt,
            } => {
                let Some(attestation) =
                    signers[*signer as usize % n].sign::<Sha256Digest>(F::subject(message))
                else {
                    continue;
                };
                if *corrupt {
                    let mut bad = attestation;
                    bad.signer = Participant::new(u32::MAX);
                    // An out-of-range signer index must be rejected.
                    assert!(!verifier.verify_attestation::<_, Sha256Digest>(
                        &mut rng,
                        F::subject(message),
                        &bad,
                        &Sequential,
                    ));
                } else {
                    assert!(verifier.verify_attestation::<_, Sha256Digest>(
                        &mut rng,
                        F::subject(message),
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
                    .filter_map(|i| signers[i].sign::<Sha256Digest>(F::subject(message)))
                    .collect();
                if attestations.is_empty() {
                    continue;
                }
                if *corrupt {
                    attestations[0].signer = Participant::new(u32::MAX);
                }
                let result = verifier.verify_attestations::<_, Sha256Digest, _>(
                    &mut rng,
                    F::subject(message),
                    attestations.clone(),
                    &Sequential,
                );
                if *corrupt {
                    // The out-of-range signer must be the only rejected attestation.
                    assert!(result.invalid.contains(&Participant::new(u32::MAX)));
                    assert_eq!(result.verified.len(), attestations.len() - 1);
                } else {
                    assert!(result.invalid.is_empty());
                    assert_eq!(result.verified.len(), attestations.len());
                }
            }
            Op::Assemble {
                signers: selection,
                message,
            } => {
                let attestations: Vec<_> = distinct_indices(selection, n)
                    .into_iter()
                    .filter_map(|i| signers[i].sign::<Sha256Digest>(F::subject(message)))
                    .collect();
                if attestations.len() < quorum {
                    assert!(signers[0]
                        .assemble::<_, N3f1>(attestations, &Sequential)
                        .is_none());
                } else {
                    let certificate = signers[0]
                        .assemble::<_, N3f1>(attestations, &Sequential)
                        .expect("quorum-valid attestations assemble");
                    assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        F::subject(message),
                        &certificate,
                        &Sequential,
                    ));
                    let encoded = certificate.encode();
                    let decoded =
                        CertOf::<F>::decode_cfg(encoded, &cfg).expect("certificate roundtrips");
                    assert_eq!(decoded, certificate);
                    if certs.len() < MAX_STORED_CERTIFICATES {
                        certs.push((message.clone(), certificate));
                    }
                }
            }
            Op::VerifyStoredCertificate { which, corrupt } => {
                if certs.is_empty() {
                    continue;
                }
                let (message, certificate) = &certs[*which as usize % certs.len()];
                if *corrupt {
                    let bad = F::corrupt(certificate);
                    // A deterministically-invalid certificate must be rejected.
                    assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        F::subject(message),
                        &bad,
                        &Sequential,
                    ));
                } else {
                    assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        F::subject(message),
                        certificate,
                        &Sequential,
                    ));
                }
            }
            Op::VerifyStoredCertificates => {
                let items = certs
                    .iter()
                    .map(|(message, certificate)| (F::subject(message), certificate));
                assert!(verifier.verify_certificates::<_, Sha256Digest, _, N3f1>(
                    &mut rng,
                    items,
                    &Sequential,
                ));
            }
            Op::BisectStoredCertificates => {
                let none: Vec<Item<'_, F>> = Vec::new();
                assert!(verifier
                    .verify_certificates_bisect::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        &none,
                        &Sequential
                    )
                    .is_empty());
                if certs.is_empty() {
                    continue;
                }

                // A deterministically-invalid clone must fail, exercising the bisection split path.
                let bad = F::corrupt(&certs[0].1);
                let mut items: Vec<Item<'_, F>> = certs
                    .iter()
                    .map(|(message, certificate)| (F::subject(message), certificate))
                    .collect();
                items.push((F::subject(&certs[0].0), &bad));
                let verified = verifier.verify_certificates_bisect::<_, Sha256Digest, N3f1>(
                    &mut rng,
                    &items,
                    &Sequential,
                );
                assert_eq!(verified.len(), items.len());
                assert!(verified[..certs.len()].iter().all(|&v| v));
                assert!(!verified[certs.len()]);
            }
            Op::DecodeCertificate(data) => {
                if let Ok(certificate) = CertOf::<F>::decode_cfg(Bytes::copy_from_slice(data), &cfg)
                {
                    let _ = verifier.verify_certificate::<_, Sha256Digest, N3f1>(
                        &mut rng,
                        F::subject(b"decoded"),
                        &certificate,
                        &Sequential,
                    );
                    let re = CertOf::<F>::decode_cfg(certificate.encode(), &cfg)
                        .expect("re-encode roundtrips");
                    assert_eq!(re, certificate);
                }
            }
        }
    }
}
