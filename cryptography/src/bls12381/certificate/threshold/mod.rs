//! BLS12-381 threshold signature scheme implementation.
//!
//! This module provides both the generic BLS12-381 threshold implementation and a macro to generate
//! protocol-specific wrappers.
//!
//! Unlike multi-signature schemes, threshold signatures:
//! - Use partial signatures that can be combined to form a threshold signature
//! - Require a quorum of signatures to recover the full signature
//! - Are **non-attributable**: partial signatures can be forged by holders of enough other partials

#[cfg(feature = "mocks")]
pub mod mocks;

use crate::{
    bls12381::primitives::{
        group::Share,
        ops::{
            aggregate_signatures, aggregate_verify_multiple_messages, partial_sign_message,
            partial_verify_multiple_public_keys, threshold_signature_recover, verify_message,
        },
        sharing::Sharing,
        variant::{PartialSignature, Variant},
    },
    certificate::{Attestation, Scheme, Subject, Verification},
    Digest, PublicKey,
};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, vec::Vec};
use commonware_utils::ordered::Set;
use core::fmt::Debug;
use rand::{CryptoRng, Rng};
#[cfg(feature = "std")]
use std::collections::BTreeSet;

/// Generic BLS12-381 threshold signature implementation.
///
/// This enum contains the core cryptographic operations without protocol-specific
/// context types. It can be reused across different protocols (simplex, aggregation, etc.)
/// by wrapping it with protocol-specific trait implementations via the macro.
///
/// A node can play one of the following roles: a signer (with its share),
/// a verifier (with evaluated public polynomial), or an external verifier that
/// only checks recovered certificates.
#[derive(Clone, Debug)]
pub enum Generic<P: PublicKey, V: Variant> {
    Signer {
        /// Participants in the committee.
        participants: Set<P>,
        /// The public polynomial, used for the group identity, and partial signatures.
        polynomial: Sharing<V>,
        /// Local share used to generate partial signatures.
        share: Share,
    },
    Verifier {
        /// Participants in the committee.
        participants: Set<P>,
        /// The public polynomial, used for the group identity, and partial signatures.
        polynomial: Sharing<V>,
    },
    CertificateVerifier {
        /// Public identity of the committee (constant across reshares).
        identity: V::Public,
    },
}

impl<P: PublicKey, V: Variant> Generic<P, V> {
    /// Constructs a signer instance with a private share and evaluated public polynomial.
    ///
    /// The participant identity keys are used for committee ordering and indexing.
    /// The polynomial can be evaluated to obtain public verification keys for partial
    /// signatures produced by committee members.
    ///
    /// Returns `None` if the share's public key does not match any participant.
    ///
    /// * `participants` - ordered set of participant identity keys
    /// * `polynomial` - public polynomial for threshold verification
    /// * `share` - local threshold share for signing
    pub fn signer(participants: Set<P>, polynomial: Sharing<V>, share: Share) -> Option<Self> {
        assert_eq!(
            polynomial.total().get() as usize,
            participants.len(),
            "polynomial total must equal participant len"
        );
        #[cfg(feature = "std")]
        polynomial.precompute_partial_publics();
        let partial_public = polynomial
            .partial_public(share.index)
            .expect("share index must match participant indices");
        if partial_public == share.public::<V>() {
            Some(Self::Signer {
                participants,
                polynomial,
                share,
            })
        } else {
            None
        }
    }

    /// Produces a verifier that can authenticate signatures but does not hold signing state.
    ///
    /// The participant identity keys are used for committee ordering and indexing.
    /// The polynomial can be evaluated to obtain public verification keys for partial
    /// signatures produced by committee members.
    ///
    /// * `participants` - ordered set of participant identity keys
    /// * `polynomial` - public polynomial for threshold verification
    pub fn verifier(participants: Set<P>, polynomial: Sharing<V>) -> Self {
        assert_eq!(
            polynomial.total().get() as usize,
            participants.len(),
            "polynomial total must equal participant len"
        );
        #[cfg(feature = "std")]
        polynomial.precompute_partial_publics();

        Self::Verifier {
            participants,
            polynomial,
        }
    }

    /// Creates a verifier that only checks recovered certificates.
    ///
    /// This lightweight verifier can authenticate recovered threshold certificates but cannot
    /// verify individual signatures or partial signatures.
    ///
    /// * `identity` - public identity of the committee (constant across reshares)
    pub const fn certificate_verifier(identity: V::Public) -> Self {
        Self::CertificateVerifier { identity }
    }

    /// Returns the ordered set of participant public identity keys in the committee.
    pub fn participants(&self) -> &Set<P> {
        match self {
            Self::Signer { participants, .. } => participants,
            Self::Verifier { participants, .. } => participants,
            _ => panic!("can only be called for signer and verifier"),
        }
    }

    /// Returns the public identity of the committee (constant across reshares).
    pub fn identity(&self) -> &V::Public {
        match self {
            Self::Signer { polynomial, .. } => polynomial.public(),
            Self::Verifier { polynomial, .. } => polynomial.public(),
            Self::CertificateVerifier { identity, .. } => identity,
        }
    }

    /// Returns the local share if this instance can generate partial signatures.
    pub const fn share(&self) -> Option<&Share> {
        match self {
            Self::Signer { share, .. } => Some(share),
            _ => None,
        }
    }

    /// Returns the evaluated public polynomial for validating partial signatures produced by committee members.
    fn polynomial(&self) -> &Sharing<V> {
        match self {
            Self::Signer { polynomial, .. } => polynomial,
            Self::Verifier { polynomial, .. } => polynomial,
            _ => panic!("can only be called for signer and verifier"),
        }
    }

    /// Returns the index of "self" in the participant set, if available.
    pub const fn me(&self) -> Option<u32> {
        match self {
            Self::Signer { share, .. } => Some(share.index),
            _ => None,
        }
    }

    /// Signs a subject and returns the attestation.
    pub fn sign<S, D>(&self, namespace: &[u8], subject: S::Subject<'_, D>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = V::Signature>,
        D: Digest,
    {
        let share = self.share()?;

        let (namespace, message) = subject.namespace_and_message(namespace);
        let signature =
            partial_sign_message::<V>(share, Some(namespace.as_ref()), message.as_ref()).value;

        Some(Attestation {
            signer: share.index,
            signature,
        })
    }

    /// Verifies a single attestation from a signer.
    pub fn verify_attestation<S, D>(
        &self,
        namespace: &[u8],
        subject: S::Subject<'_, D>,
        attestation: &Attestation<S>,
    ) -> bool
    where
        S: Scheme<Signature = V::Signature>,
        D: Digest,
    {
        let Ok(evaluated) = self.polynomial().partial_public(attestation.signer) else {
            return false;
        };

        let (namespace, message) = subject.namespace_and_message(namespace);
        verify_message::<V>(
            &evaluated,
            Some(namespace.as_ref()),
            message.as_ref(),
            &attestation.signature,
        )
        .is_ok()
    }

    /// Batch-verifies attestations and returns verified attestations and invalid signers.
    pub fn verify_attestations<S, R, D, I>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        subject: S::Subject<'_, D>,
        attestations: I,
    ) -> Verification<S>
    where
        S: Scheme<Signature = V::Signature>,
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<S>>,
    {
        let mut invalid = BTreeSet::new();
        let partials: Vec<_> = attestations
            .into_iter()
            .map(|attestation| PartialSignature::<V> {
                index: attestation.signer,
                value: attestation.signature,
            })
            .collect();

        let polynomial = self.polynomial();
        let (namespace, message) = subject.namespace_and_message(namespace);
        if let Err(errs) = partial_verify_multiple_public_keys::<V, _>(
            polynomial,
            Some(namespace.as_ref()),
            message.as_ref(),
            partials.iter(),
        ) {
            for partial in errs {
                invalid.insert(partial.index);
            }
        }

        let verified = partials
            .into_iter()
            .filter(|partial| !invalid.contains(&partial.index))
            .map(|partial| Attestation {
                signer: partial.index,
                signature: partial.value,
            })
            .collect();

        Verification::new(verified, invalid.into_iter().collect())
    }

    /// Assembles a certificate from a collection of attestations.
    pub fn assemble<S, I>(&self, attestations: I) -> Option<V::Signature>
    where
        S: Scheme<Signature = V::Signature>,
        I: IntoIterator<Item = Attestation<S>>,
    {
        let partials: Vec<_> = attestations
            .into_iter()
            .map(|attestation| PartialSignature::<V> {
                index: attestation.signer,
                value: attestation.signature,
            })
            .collect();

        let quorum = self.polynomial();
        if partials.len() < quorum.required() as usize {
            return None;
        }

        threshold_signature_recover::<V, _>(quorum, partials.iter()).ok()
    }

    /// Verifies a certificate.
    pub fn verify_certificate<S, R, D>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        subject: S::Subject<'_, D>,
        certificate: &V::Signature,
    ) -> bool
    where
        S: Scheme,
        R: Rng + CryptoRng,
        D: Digest,
    {
        let identity = self.identity();
        let (namespace, message) = subject.namespace_and_message(namespace);
        verify_message::<V>(
            identity,
            Some(namespace.as_ref()),
            message.as_ref(),
            certificate,
        )
        .is_ok()
    }

    /// Verifies multiple certificates in a batch.
    pub fn verify_certificates<'a, S, R, D, I>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        certificates: I,
    ) -> bool
    where
        S: Scheme,
        R: Rng + CryptoRng,
        D: Digest,
        I: Iterator<Item = (S::Subject<'a, D>, &'a V::Signature)>,
    {
        let identity = self.identity();

        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        for (subject, certificate) in certificates {
            let (namespace, message) = subject.namespace_and_message(namespace);
            messages.push((Some(namespace), message));
            signatures.push(*certificate);
        }

        if messages.is_empty() {
            return true;
        }

        let signature = aggregate_signatures::<V, _>(signatures.iter());
        aggregate_verify_multiple_messages::<V, _>(
            identity,
            &messages
                .iter()
                .map(|(namespace, message)| (namespace.as_deref(), message.as_ref()))
                .collect::<Vec<_>>(),
            &signature,
            1,
        )
        .is_ok()
    }

    pub const fn is_attributable(&self) -> bool {
        false
    }

    pub const fn certificate_codec_config(&self) {}

    pub const fn certificate_codec_config_unbounded() {}
}

mod macros {
    /// Generates a BLS12-381 threshold signing scheme wrapper for a specific protocol.
    ///
    /// This macro creates a complete wrapper struct with constructors, `Scheme` trait
    /// implementation, and a `fixture` function for testing.
    /// The only required parameter is the `Subject` type, which varies per protocol.
    ///
    /// # Example
    /// ```ignore
    /// impl_certificate_bls12381_threshold!(VoteSubject<'a, D>);
    /// ```
    #[macro_export]
    macro_rules! impl_certificate_bls12381_threshold {
        ($subject:ty) => {
            /// Generates a test fixture with Ed25519 identities and BLS12-381 threshold schemes.
            ///
            /// Returns a [`commonware_cryptography::certificate::mocks::Fixture`] whose keys and
            /// scheme instances share a consistent ordering.
            #[cfg(feature = "mocks")]
            #[allow(dead_code)]
            pub fn fixture<V, R>(
                rng: &mut R,
                n: u32,
            ) -> $crate::certificate::mocks::Fixture<Scheme<$crate::ed25519::PublicKey, V>>
            where
                V: $crate::bls12381::primitives::variant::Variant,
                R: rand::RngCore + rand::CryptoRng,
            {
                $crate::bls12381::certificate::threshold::mocks::fixture::<_, V, _>(
                    rng,
                    n,
                    Scheme::signer,
                    Scheme::verifier,
                )
            }

            /// BLS12-381 threshold signature scheme wrapper.
            #[derive(Clone, Debug)]
            pub struct Scheme<
                P: $crate::PublicKey,
                V: $crate::bls12381::primitives::variant::Variant,
            > {
                generic: $crate::bls12381::certificate::threshold::Generic<P, V>,
            }

            impl<
                P: $crate::PublicKey,
                V: $crate::bls12381::primitives::variant::Variant,
            > Scheme<P, V> {
                /// Creates a new signer instance with a private share and evaluated public polynomial.
                pub fn signer(
                    participants: commonware_utils::ordered::Set<P>,
                    polynomial: $crate::bls12381::primitives::sharing::Sharing<V>,
                    share: $crate::bls12381::primitives::group::Share,
                ) -> Option<Self> {
                    Some(Self {
                        generic: $crate::bls12381::certificate::threshold::Generic::signer(
                            participants,
                            polynomial,
                            share,
                        )?,
                    })
                }

                /// Creates a verifier that can authenticate partial signatures.
                pub fn verifier(
                    participants: commonware_utils::ordered::Set<P>,
                    polynomial: $crate::bls12381::primitives::sharing::Sharing<V>,
                ) -> Self {
                    Self {
                        generic: $crate::bls12381::certificate::threshold::Generic::verifier(
                            participants,
                            polynomial,
                        ),
                    }
                }

                /// Creates a lightweight verifier that only checks recovered certificates.
                pub const fn certificate_verifier(identity: V::Public) -> Self {
                    Self {
                        generic: $crate::bls12381::certificate::threshold::Generic::certificate_verifier(
                            identity,
                        ),
                    }
                }

                /// Returns the public identity of the committee (constant across reshares).
                pub fn identity(&self) -> &V::Public {
                    self.generic.identity()
                }

                /// Returns the local share if this instance can generate partial signatures.
                pub const fn share(&self) -> Option<&$crate::bls12381::primitives::group::Share> {
                    self.generic.share()
                }
            }

            impl<
                P: $crate::PublicKey,
                V: $crate::bls12381::primitives::variant::Variant + Send + Sync,
            > $crate::certificate::Scheme for Scheme<P, V> {
                type Subject<'a, D: $crate::Digest> = $subject;
                type PublicKey = P;
                type Signature = V::Signature;
                type Certificate = V::Signature;

                fn me(&self) -> Option<u32> {
                    self.generic.me()
                }

                fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
                    self.generic.participants()
                }

                fn sign<D: $crate::Digest>(
                    &self,
                    namespace: &[u8],
                    subject: Self::Subject<'_, D>,
                ) -> Option<$crate::certificate::Attestation<Self>> {
                    self.generic.sign::<_, D>(namespace, subject)
                }

                fn verify_attestation<D: $crate::Digest>(
                    &self,
                    namespace: &[u8],
                    subject: Self::Subject<'_, D>,
                    attestation: &$crate::certificate::Attestation<Self>,
                ) -> bool {
                    self.generic.verify_attestation::<_, D>(namespace, subject, attestation)
                }

                fn verify_attestations<R, D, I>(
                    &self,
                    rng: &mut R,
                    namespace: &[u8],
                    subject: Self::Subject<'_, D>,
                    attestations: I,
                ) -> $crate::certificate::Verification<Self>
                where
                    R: rand::Rng + rand::CryptoRng,
                    D: $crate::Digest,
                    I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                {
                    self.generic.verify_attestations::<_, _, D, _>(rng, namespace, subject, attestations)
                }

                fn assemble<I>(&self, attestations: I) -> Option<Self::Certificate>
                where
                    I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                {
                    self.generic.assemble(attestations)
                }

                fn verify_certificate<
                    R: rand::Rng + rand::CryptoRng,
                    D: $crate::Digest,
                >(
                    &self,
                    rng: &mut R,
                    namespace: &[u8],
                    subject: Self::Subject<'_, D>,
                    certificate: &Self::Certificate,
                ) -> bool {
                    self.generic.verify_certificate::<Self, _, D>(rng, namespace, subject, certificate)
                }

                fn verify_certificates<'a, R, D, I>(
                    &self,
                    rng: &mut R,
                    namespace: &[u8],
                    certificates: I,
                ) -> bool
                where
                    R: rand::Rng + rand::CryptoRng,
                    D: $crate::Digest,
                    I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
                {
                    self.generic.verify_certificates::<Self, _, D, _>(rng, namespace, certificates)
                }

                fn is_attributable(&self) -> bool {
                    self.generic.is_attributable()
                }

                fn certificate_codec_config(
                    &self,
                ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    self.generic.certificate_codec_config()
                }

                fn certificate_codec_config_unbounded(
                ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    $crate::bls12381::certificate::threshold::Generic::<P, V>::certificate_codec_config_unbounded()
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bls12381::{
            dkg,
            primitives::{
                ops::partial_sign_message,
                variant::{MinPk, MinSig, Variant},
            },
        },
        certificate::Scheme as _,
        ed25519::{self, PrivateKey as Ed25519PrivateKey},
        impl_certificate_bls12381_threshold,
        sha256::Digest as Sha256Digest,
        Signer as _,
    };
    use bytes::Bytes;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_math::algebra::{Additive, Random};
    use commonware_utils::{ordered::Set, quorum, TryCollect, NZU32};
    use rand::{rngs::StdRng, thread_rng, SeedableRng};

    const NAMESPACE: &[u8] = b"test-bls12381-threshold";
    const MESSAGE: &[u8] = b"test message";

    /// Test context type for generic scheme tests.
    #[derive(Clone, Debug)]
    pub struct TestSubject<'a> {
        pub message: &'a [u8],
    }

    impl<'a> Subject for TestSubject<'a> {
        fn namespace_and_message(&self, namespace: &[u8]) -> (Bytes, Bytes) {
            (namespace.to_vec().into(), self.message.to_vec().into())
        }
    }

    // Use the macro to generate the test scheme
    impl_certificate_bls12381_threshold!(TestSubject<'a>);

    #[allow(clippy::type_complexity)]
    fn setup_signers<V: Variant>(
        n: u32,
        seed: u64,
    ) -> (
        Vec<Scheme<ed25519::PublicKey, V>>,
        Scheme<ed25519::PublicKey, V>,
        Sharing<V>,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);

        // Generate identity keys (ed25519)
        let identity_keys: Vec<_> = (0..n)
            .map(|_| Ed25519PrivateKey::random(&mut rng))
            .collect();
        let participants: Set<ed25519::PublicKey> = identity_keys
            .iter()
            .map(|sk| sk.public_key())
            .try_collect()
            .unwrap();

        // Generate threshold polynomial and shares using DKG
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(n));

        let signers = shares
            .into_iter()
            .map(|share| Scheme::signer(participants.clone(), polynomial.clone(), share).unwrap())
            .collect();

        let verifier = Scheme::verifier(participants, polynomial.clone());

        (signers, verifier, polynomial)
    }

    fn test_sign_vote_roundtrip<V: Variant + Send + Sync>() {
        let (schemes, _, _) = setup_signers::<V>(4, 42);
        let scheme = &schemes[0];

        let attestation = scheme
            .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
            .unwrap();
        assert!(scheme.verify_attestation::<Sha256Digest>(
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &attestation
        ));
    }

    #[test]
    fn test_sign_vote_roundtrip_variants() {
        test_sign_vote_roundtrip::<MinPk>();
        test_sign_vote_roundtrip::<MinSig>();
    }

    fn test_verifier_cannot_sign<V: Variant + Send + Sync>() {
        let (_, verifier, _) = setup_signers::<V>(4, 43);
        assert!(verifier
            .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
            .is_none());
    }

    #[test]
    fn test_verifier_cannot_sign_variants() {
        test_verifier_cannot_sign::<MinPk>();
        test_verifier_cannot_sign::<MinSig>();
    }

    fn test_verify_attestations_filters_invalid<V: Variant + Send + Sync>() {
        let (schemes, _, _) = setup_signers::<V>(5, 44);
        let quorum = quorum(schemes.len() as u32) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut rng = StdRng::seed_from_u64(45);
        let result = schemes[0].verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            NAMESPACE,
            TestSubject { message: MESSAGE },
            attestations.clone(),
        );
        assert!(result.invalid.is_empty());
        assert_eq!(result.verified.len(), quorum);

        // Test: Corrupt one attestation - invalid signer index
        let mut attestations_corrupted = attestations.clone();
        attestations_corrupted[0].signer = 999;
        let result = schemes[0].verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            NAMESPACE,
            TestSubject { message: MESSAGE },
            attestations_corrupted,
        );
        assert_eq!(result.invalid, vec![999]);
        assert_eq!(result.verified.len(), quorum - 1);

        // Test: Corrupt one attestation - invalid signature
        let mut attestations_corrupted = attestations;
        attestations_corrupted[0].signature = attestations_corrupted[1].signature;
        let result = schemes[0].verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            NAMESPACE,
            TestSubject { message: MESSAGE },
            attestations_corrupted,
        );
        assert_eq!(result.invalid.len(), 1);
        assert_eq!(result.verified.len(), quorum - 1);
    }

    #[test]
    fn test_verify_attestations_filters_invalid_variants() {
        test_verify_attestations_filters_invalid::<MinPk>();
        test_verify_attestations_filters_invalid::<MinSig>();
    }

    fn test_assemble_certificate<V: Variant + Send + Sync>() {
        let (schemes, verifier, _) = setup_signers::<V>(4, 46);
        let quorum = quorum(schemes.len() as u32) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble(attestations).unwrap();

        // Verify the assembled certificate
        assert!(verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate
        ));
    }

    #[test]
    fn test_assemble_certificate_variants() {
        test_assemble_certificate::<MinPk>();
        test_assemble_certificate::<MinSig>();
    }

    fn test_verify_certificate<V: Variant + Send + Sync>() {
        let (schemes, verifier, _) = setup_signers::<V>(4, 48);
        let quorum = quorum(schemes.len() as u32) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble(attestations).unwrap();

        let mut rng = StdRng::seed_from_u64(49);
        assert!(verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate
        ));
    }

    #[test]
    fn test_verify_certificate_variants() {
        test_verify_certificate::<MinPk>();
        test_verify_certificate::<MinSig>();
    }

    fn test_verify_certificate_detects_corruption<V: Variant + Send + Sync>() {
        let (schemes, verifier, _) = setup_signers::<V>(4, 50);
        let quorum = quorum(schemes.len() as u32) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble(attestations).unwrap();

        // Valid certificate passes
        assert!(verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate
        ));

        // Corrupted certificate fails
        let corrupted = V::Signature::zero();
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &corrupted
        ));
    }

    #[test]
    fn test_verify_certificate_detects_corruption_variants() {
        test_verify_certificate_detects_corruption::<MinPk>();
        test_verify_certificate_detects_corruption::<MinSig>();
    }

    fn test_certificate_codec_roundtrip<V: Variant + Send + Sync>() {
        let (schemes, _, _) = setup_signers::<V>(4, 51);
        let quorum = quorum(schemes.len() as u32) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble(attestations).unwrap();
        let encoded = certificate.encode();
        let decoded = V::Signature::decode(encoded).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_codec_roundtrip_variants() {
        test_certificate_codec_roundtrip::<MinPk>();
        test_certificate_codec_roundtrip::<MinSig>();
    }

    fn test_certificate_rejects_sub_quorum<V: Variant + Send + Sync>() {
        let (schemes, _, _) = setup_signers::<V>(4, 52);
        let sub_quorum = 2; // Less than quorum (3)

        let attestations: Vec<_> = schemes
            .iter()
            .take(sub_quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        assert!(schemes[0].assemble(attestations).is_none());
    }

    #[test]
    fn test_certificate_rejects_sub_quorum_variants() {
        test_certificate_rejects_sub_quorum::<MinPk>();
        test_certificate_rejects_sub_quorum::<MinSig>();
    }

    fn test_verify_certificates_batch<V: Variant + Send + Sync>() {
        let (schemes, verifier, _) = setup_signers::<V>(4, 56);
        let quorum = quorum(schemes.len() as u32) as usize;

        let messages = [b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];
        let mut certificates = Vec::new();

        for msg in &messages {
            let attestations: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| {
                    s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: msg })
                        .unwrap()
                })
                .collect();
            certificates.push(schemes[0].assemble(attestations).unwrap());
        }

        let certs_iter = messages
            .iter()
            .zip(&certificates)
            .map(|(msg, cert)| (TestSubject { message: msg }, cert));

        let mut rng = StdRng::seed_from_u64(57);
        assert!(verifier.verify_certificates::<_, Sha256Digest, _>(&mut rng, NAMESPACE, certs_iter));
    }

    #[test]
    fn test_verify_certificates_batch_variants() {
        test_verify_certificates_batch::<MinPk>();
        test_verify_certificates_batch::<MinSig>();
    }

    fn test_verify_certificates_batch_detects_failure<V: Variant + Send + Sync>() {
        let (schemes, verifier, _) = setup_signers::<V>(4, 58);
        let quorum = quorum(schemes.len() as u32) as usize;

        let messages = [b"msg1".as_slice(), b"msg2".as_slice()];
        let mut certificates = Vec::new();

        for msg in &messages {
            let attestations: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| {
                    s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: msg })
                        .unwrap()
                })
                .collect();
            certificates.push(schemes[0].assemble(attestations).unwrap());
        }

        // Corrupt second certificate
        certificates[1] = V::Signature::zero();

        let certs_iter = messages
            .iter()
            .zip(&certificates)
            .map(|(msg, cert)| (TestSubject { message: msg }, cert));

        let mut rng = StdRng::seed_from_u64(59);
        assert!(
            !verifier.verify_certificates::<_, Sha256Digest, _>(&mut rng, NAMESPACE, certs_iter)
        );
    }

    #[test]
    fn test_verify_certificates_batch_detects_failure_variants() {
        test_verify_certificates_batch_detects_failure::<MinPk>();
        test_verify_certificates_batch_detects_failure::<MinSig>();
    }

    fn test_certificate_verifier<V: Variant + Send + Sync>() {
        let (schemes, _, polynomial) = setup_signers::<V>(4, 60);
        let quorum = quorum(schemes.len() as u32) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble(attestations).unwrap();

        // Create a certificate-only verifier using the identity from the polynomial
        let identity = polynomial.public();
        let cert_verifier = Scheme::<ed25519::PublicKey, V>::certificate_verifier(*identity);

        // Should be able to verify certificates
        assert!(cert_verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate
        ));

        // Should not be able to sign
        assert!(cert_verifier
            .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
            .is_none());
    }

    #[test]
    fn test_certificate_verifier_variants() {
        test_certificate_verifier::<MinPk>();
        test_certificate_verifier::<MinSig>();
    }

    fn test_is_not_attributable<V: Variant + Send + Sync>() {
        let (schemes, verifier, _) = setup_signers::<V>(4, 61);

        // Threshold signatures are non-attributable
        assert!(!schemes[0].is_attributable());
        assert!(!verifier.is_attributable());
    }

    #[test]
    fn test_is_not_attributable_variants() {
        test_is_not_attributable::<MinPk>();
        test_is_not_attributable::<MinSig>();
    }

    fn test_verifier_accepts_votes<V: Variant + Send + Sync>() {
        let (schemes, verifier, _) = setup_signers::<V>(4, 62);

        let vote = schemes[1]
            .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
            .unwrap();
        assert!(verifier.verify_attestation::<Sha256Digest>(
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &vote
        ));
    }

    #[test]
    fn test_verifier_accepts_votes_variants() {
        test_verifier_accepts_votes::<MinPk>();
        test_verifier_accepts_votes::<MinSig>();
    }

    fn test_scheme_clone_and_verifier<V: Variant + Send + Sync>() {
        let (schemes, verifier, _) = setup_signers::<V>(4, 63);

        // Clone a signer
        let signer = schemes[0].clone();
        assert!(
            signer
                .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                .is_some(),
            "signer should produce votes"
        );

        // A verifier cannot produce votes
        assert!(
            verifier
                .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                .is_none(),
            "verifier should not produce votes"
        );
    }

    #[test]
    fn test_scheme_clone_and_verifier_variants() {
        test_scheme_clone_and_verifier::<MinPk>();
        test_scheme_clone_and_verifier::<MinSig>();
    }

    fn certificate_verifier_panics_on_vote<V: Variant + Send + Sync>() {
        let (schemes, _, _) = setup_signers::<V>(4, 37);
        let certificate_verifier =
            Scheme::<ed25519::PublicKey, V>::certificate_verifier(*schemes[0].identity());

        let vote = schemes[1]
            .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
            .unwrap();

        // CertificateVerifier should panic when trying to verify a vote
        certificate_verifier.verify_attestation::<Sha256Digest>(
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &vote,
        );
    }

    #[test]
    #[should_panic(expected = "can only be called for signer and verifier")]
    fn test_certificate_verifier_panics_on_vote_min_pk() {
        certificate_verifier_panics_on_vote::<MinPk>();
    }

    #[test]
    #[should_panic(expected = "can only be called for signer and verifier")]
    fn test_certificate_verifier_panics_on_vote_min_sig() {
        certificate_verifier_panics_on_vote::<MinSig>();
    }

    fn signer_shares_must_match_participant_indices<V: Variant + Send + Sync>() {
        let mut rng = StdRng::seed_from_u64(64);

        // Generate identity keys (ed25519)
        let identity_keys: Vec<_> = (0..4)
            .map(|_| Ed25519PrivateKey::random(&mut rng))
            .collect();
        let participants: Set<ed25519::PublicKey> = identity_keys
            .iter()
            .map(|sk| sk.public_key())
            .try_collect()
            .unwrap();

        let (polynomial, mut shares) =
            dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(4));
        shares[0].index = 999;
        Scheme::<ed25519::PublicKey, V>::signer(participants, polynomial, shares[0].clone());
    }

    #[test]
    #[should_panic(expected = "share index must match participant indices")]
    fn test_signer_shares_must_match_participant_indices_min_pk() {
        signer_shares_must_match_participant_indices::<MinPk>();
    }

    #[test]
    #[should_panic(expected = "share index must match participant indices")]
    fn test_signer_shares_must_match_participant_indices_min_sig() {
        signer_shares_must_match_participant_indices::<MinSig>();
    }

    fn make_participants<R: rand::RngCore + rand::CryptoRng + Clone>(
        rng: &mut R,
        n: u32,
    ) -> Set<ed25519::PublicKey> {
        (0..n)
            .map(|_| Ed25519PrivateKey::random(&mut *rng).public_key())
            .try_collect()
            .expect("participants are unique")
    }

    fn signer_polynomial_threshold_must_equal_quorum<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(7);
        let participants = make_participants(&mut rng, 5);
        // Create a polynomial with threshold 4, but quorum of 5 participants is 4
        // so this should succeed. Let's use threshold 2 to make it fail.
        // quorum(5) = 4, but polynomial.required() = 2, so this should panic
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(2));
        Scheme::<ed25519::PublicKey, V>::signer(participants, polynomial, shares[0].clone());
    }

    #[test]
    #[should_panic(expected = "polynomial total must equal participant len")]
    fn test_signer_polynomial_threshold_must_equal_quorum_min_pk() {
        signer_polynomial_threshold_must_equal_quorum::<MinPk>();
    }

    #[test]
    #[should_panic(expected = "polynomial total must equal participant len")]
    fn test_signer_polynomial_threshold_must_equal_quorum_min_sig() {
        signer_polynomial_threshold_must_equal_quorum::<MinSig>();
    }

    fn verifier_polynomial_threshold_must_equal_quorum<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(7);
        let participants = make_participants(&mut rng, 5);
        // Create a polynomial with threshold 2, but quorum of 5 participants is 4
        // quorum(5) = 4, but polynomial.required() = 2, so this should panic
        let (polynomial, _) = dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(2));
        Scheme::<ed25519::PublicKey, V>::verifier(participants, polynomial);
    }

    #[test]
    #[should_panic(expected = "polynomial total must equal participant len")]
    fn test_verifier_polynomial_threshold_must_equal_quorum_min_pk() {
        verifier_polynomial_threshold_must_equal_quorum::<MinPk>();
    }

    #[test]
    #[should_panic(expected = "polynomial total must equal participant len")]
    fn test_verifier_polynomial_threshold_must_equal_quorum_min_sig() {
        verifier_polynomial_threshold_must_equal_quorum::<MinSig>();
    }

    fn certificate_decode_rejects_length_mismatch<V: Variant + Send + Sync>() {
        let (schemes, _, _) = setup_signers::<V>(4, 65);
        let quorum = quorum(schemes.len() as u32) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble(attestations).unwrap();
        let mut encoded = certificate.encode();
        encoded.truncate(encoded.len() - 1);
        assert!(V::Signature::decode(encoded).is_err());
    }

    #[test]
    fn test_certificate_decode_rejects_length_mismatch_variants() {
        certificate_decode_rejects_length_mismatch::<MinPk>();
        certificate_decode_rejects_length_mismatch::<MinSig>();
    }

    fn sign_vote_partial_matches_share<V: Variant + Send + Sync>() {
        let (schemes, _, _) = setup_signers::<V>(4, 66);
        let scheme = &schemes[0];

        let signature = scheme
            .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
            .unwrap();

        // Verify the partial signature matches what we'd get from direct signing
        let share = scheme.share().expect("expected signer");

        let expected = partial_sign_message::<V>(share, Some(NAMESPACE), MESSAGE);

        assert_eq!(signature.signer, share.index);
        assert_eq!(signature.signature, expected.value);
    }

    #[test]
    fn test_sign_vote_partial_matches_share_variants() {
        sign_vote_partial_matches_share::<MinPk>();
        sign_vote_partial_matches_share::<MinSig>();
    }
}
