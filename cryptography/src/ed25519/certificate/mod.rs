//! Ed25519 signing scheme implementation.
//!
//! This module provides both the generic Ed25519 implementation and a macro to generate
//! protocol-specific wrappers.

#[cfg(feature = "mocks")]
pub mod mocks;

#[cfg(feature = "std")]
use super::Batch;
use super::{PrivateKey, PublicKey, Signature as Ed25519Signature};
#[cfg(feature = "std")]
use crate::{certificate::Verification, BatchVerifier};
use crate::{
    certificate::{Attestation, Namespace, Scheme, Signers, Subject},
    Digest, Signer as _, Verifier as _,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{types::lazy::Lazy, EncodeSize, Error, Read, ReadRangeExt, Write};
use commonware_utils::{
    ordered::{Quorum, Set},
    Faults, Participant,
};
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

/// Generic Ed25519 signing scheme implementation.
///
/// This struct contains the core cryptographic operations without protocol-specific
/// context types. It can be reused across different protocols (simplex, aggregation, etc.)
/// by wrapping it with protocol-specific trait implementations via the macro.
#[derive(Clone, Debug)]
pub struct Generic<N: Namespace> {
    /// Participants in the committee.
    pub participants: Set<PublicKey>,
    /// Key used for generating signatures.
    pub signer: Option<(Participant, PrivateKey)>,
    /// Pre-computed namespace(s) for this subject type.
    pub namespace: N,
}

impl<N: Namespace> Generic<N> {
    /// Creates a new generic Ed25519 scheme instance.
    pub fn signer(
        namespace: &[u8],
        participants: Set<PublicKey>,
        private_key: PrivateKey,
    ) -> Option<Self> {
        let signer = participants
            .index(&private_key.public_key())
            .map(|index| (index, private_key))?;

        Some(Self {
            participants,
            signer: Some(signer),
            namespace: N::derive(namespace),
        })
    }

    /// Builds a verifier that can authenticate signatures without generating them.
    pub fn verifier(namespace: &[u8], participants: Set<PublicKey>) -> Self {
        Self {
            participants,
            signer: None,
            namespace: N::derive(namespace),
        }
    }

    /// Returns the index of "self" in the participant set, if available.
    pub fn me(&self) -> Option<Participant> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    /// Signs a subject and returns the signer index and signature.
    pub fn sign<'a, S, D>(&self, subject: S::Subject<'a, D>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = Ed25519Signature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let (index, private_key) = self.signer.as_ref()?;

        let signature = private_key.sign(subject.namespace(&self.namespace), &subject.message());

        Some(Attestation {
            signer: *index,
            signature: signature.into(),
        })
    }

    /// Verifies a single attestation from a signer.
    pub fn verify_attestation<'a, S, D>(
        &self,
        subject: S::Subject<'a, D>,
        attestation: &Attestation<S>,
    ) -> bool
    where
        S: Scheme<Signature = Ed25519Signature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let Some(public_key) = self.participants.key(attestation.signer) else {
            return false;
        };
        let Some(signature) = attestation.signature.get() else {
            return false;
        };

        public_key.verify(
            subject.namespace(&self.namespace),
            &subject.message(),
            signature,
        )
    }

    /// Batch-verifies attestations and returns verified attestations and invalid signers.
    #[cfg(feature = "std")]
    pub fn verify_attestations<'a, S, R, D, I>(
        &self,
        rng: &mut R,
        subject: S::Subject<'a, D>,
        attestations: I,
    ) -> Verification<S>
    where
        S: Scheme<Signature = Ed25519Signature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        I: IntoIterator<Item = Attestation<S>>,
    {
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();

        let mut invalid = BTreeSet::new();
        let mut candidates = Vec::new();
        let mut batch = Batch::new();

        for attestation in attestations.into_iter() {
            let Some(public_key) = self.participants.key(attestation.signer) else {
                invalid.insert(attestation.signer);
                continue;
            };
            let Some(signature) = attestation.signature.get() else {
                invalid.insert(attestation.signer);
                continue;
            };

            batch.add(namespace, &message, public_key, signature);
            candidates.push((attestation, public_key));
        }

        if !candidates.is_empty() && !batch.verify(rng) {
            // Batch failed: fall back to per-signer verification to isolate faulty attestations.
            for (attestation, public_key) in &candidates {
                let Some(signature) = attestation.signature.get() else {
                    invalid.insert(attestation.signer);
                    continue;
                };
                if !public_key.verify(namespace, &message, signature) {
                    invalid.insert(attestation.signer);
                }
            }
        }

        let verified = candidates
            .into_iter()
            .filter_map(|(attestation, _)| {
                if invalid.contains(&attestation.signer) {
                    None
                } else {
                    Some(attestation)
                }
            })
            .collect();

        Verification::new(verified, invalid.into_iter().collect())
    }

    /// Verifies attestations one-by-one and returns verified attestations and invalid signers.
    #[cfg(not(feature = "std"))]
    pub fn verify_attestations<'a, S, R, D, I>(
        &self,
        _rng: &mut R,
        subject: S::Subject<'a, D>,
        attestations: I,
    ) -> crate::certificate::Verification<S>
    where
        S: Scheme<Signature = Ed25519Signature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        I: IntoIterator<Item = Attestation<S>>,
    {
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();

        let mut invalid = alloc::collections::BTreeSet::new();
        let mut verified = Vec::new();

        for attestation in attestations.into_iter() {
            let Some(public_key) = self.participants.key(attestation.signer) else {
                invalid.insert(attestation.signer);
                continue;
            };
            let Some(signature) = attestation.signature.get() else {
                invalid.insert(attestation.signer);
                continue;
            };

            if public_key.verify(namespace, &message, signature) {
                verified.push(attestation);
            } else {
                invalid.insert(attestation.signer);
            }
        }

        crate::certificate::Verification::new(verified, invalid.into_iter().collect())
    }

    /// Assembles a certificate from a collection of attestations.
    pub fn assemble<S, I, M>(&self, attestations: I) -> Option<Certificate>
    where
        S: Scheme<Signature = Ed25519Signature>,
        I: IntoIterator<Item = Attestation<S>>,
        M: Faults,
    {
        // Collect the signers and signatures.
        let mut entries = Vec::new();
        for Attestation { signer, signature } in attestations {
            if usize::from(signer) >= self.participants.len() {
                return None;
            }
            let signature = signature.get().cloned()?;
            entries.push((signer, signature));
        }
        if entries.len() < self.participants.quorum::<M>() as usize {
            return None;
        }

        // Sort the signatures by signer index.
        entries.sort_by_key(|(signer, _)| *signer);
        let (signer, signatures): (Vec<Participant>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::from(self.participants.len(), signer);
        let signatures = signatures.into_iter().map(Lazy::from).collect();

        Some(Certificate {
            signers,
            signatures,
        })
    }

    /// Stages a certificate for batch verification.
    ///
    /// Returns false if the certificate structure is invalid.
    #[cfg(feature = "std")]
    fn batch_verify_certificate<'a, S, D, M>(
        &self,
        batch: &mut Batch,
        subject: S::Subject<'a, D>,
        certificate: &Certificate,
    ) -> bool
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
        M: Faults,
    {
        // If the certificate signers length does not match the participant set, return false.
        if certificate.signers.len() != self.participants.len() {
            return false;
        }

        // If the certificate signers and signatures counts differ, return false.
        if certificate.signers.count() != certificate.signatures.len() {
            return false;
        }

        // If the certificate does not meet the quorum, return false.
        if certificate.signers.count() < self.participants.quorum::<M>() as usize {
            return false;
        }

        // Add the certificate to the batch.
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();
        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            let Some(public_key) = self.participants.key(signer) else {
                return false;
            };
            let Some(signature) = signature.get() else {
                return false;
            };

            batch.add(namespace, &message, public_key, signature);
        }

        true
    }

    /// Verifies a certificate using batch verification.
    #[cfg(feature = "std")]
    pub fn verify_certificate<'a, S, R, D, M>(
        &self,
        rng: &mut R,
        subject: S::Subject<'a, D>,
        certificate: &Certificate,
    ) -> bool
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        M: Faults,
    {
        let mut batch = Batch::new();
        if !self.batch_verify_certificate::<S, D, M>(&mut batch, subject, certificate) {
            return false;
        }

        batch.verify(rng)
    }

    /// Verifies a certificate by checking each signature individually.
    #[cfg(not(feature = "std"))]
    pub fn verify_certificate<'a, S, R, D, M>(
        &self,
        _rng: &mut R,
        subject: S::Subject<'a, D>,
        certificate: &Certificate,
    ) -> bool
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        M: Faults,
    {
        if certificate.signers.len() != self.participants.len() {
            return false;
        }
        if certificate.signers.count() != certificate.signatures.len() {
            return false;
        }
        if certificate.signers.count() < self.participants.quorum::<M>() as usize {
            return false;
        }

        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();
        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            let Some(public_key) = self.participants.key(signer) else {
                return false;
            };
            let Some(signature) = signature.get() else {
                return false;
            };
            if !public_key.verify(namespace, &message, signature) {
                return false;
            }
        }

        true
    }

    /// Verifies multiple certificates in a batch.
    #[cfg(feature = "std")]
    pub fn verify_certificates<'a, S, R, D, I, M>(&self, rng: &mut R, certificates: I) -> bool
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        I: Iterator<Item = (S::Subject<'a, D>, &'a Certificate)>,
        M: Faults,
    {
        let mut batch = Batch::new();
        for (subject, certificate) in certificates {
            if !self.batch_verify_certificate::<S, D, M>(&mut batch, subject, certificate) {
                return false;
            }
        }

        batch.verify(rng)
    }

    /// Verifies multiple certificates one-by-one.
    #[cfg(not(feature = "std"))]
    pub fn verify_certificates<'a, S, R, D, I, M>(&self, rng: &mut R, certificates: I) -> bool
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        I: Iterator<Item = (S::Subject<'a, D>, &'a Certificate)>,
        M: Faults,
    {
        for (subject, certificate) in certificates {
            if !self.verify_certificate::<S, _, D, M>(rng, subject, certificate) {
                return false;
            }
        }

        true
    }

    pub const fn is_attributable() -> bool {
        true
    }

    pub const fn is_batchable() -> bool {
        // Batch verification requires the `std` feature because it depends on
        // `ed25519_consensus::batch::Verifier`.
        cfg!(feature = "std")
    }

    pub const fn certificate_codec_config(&self) -> <Certificate as commonware_codec::Read>::Cfg {
        self.participants.len()
    }

    pub const fn certificate_codec_config_unbounded() -> <Certificate as commonware_codec::Read>::Cfg
    {
        u32::MAX as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    /// Bitmap of participant indices that contributed signatures.
    pub signers: Signers,
    /// Ed25519 signatures emitted by the respective participants ordered by signer index.
    pub signatures: Vec<Lazy<Ed25519Signature>>,
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Certificate {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let signers = Signers::arbitrary(u)?;
        let signatures = (0..signers.count())
            .map(|_| u.arbitrary::<Ed25519Signature>().map(Lazy::from))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        Ok(Self {
            signers,
            signatures,
        })
    }
}

impl Write for Certificate {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.signatures.write(writer);
    }
}

impl EncodeSize for Certificate {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.signatures.encode_size()
    }
}

impl Read for Certificate {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, Error> {
        let signers = Signers::read_cfg(reader, participants)?;
        if signers.count() == 0 {
            return Err(Error::Invalid(
                "cryptography::ed25519::certificate::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signatures = Vec::<Lazy<Ed25519Signature>>::read_range(reader, ..=*participants)?;
        if signers.count() != signatures.len() {
            return Err(Error::Invalid(
                "cryptography::ed25519::certificate::Certificate",
                "Signers and signatures counts differ",
            ));
        }

        Ok(Self {
            signers,
            signatures,
        })
    }
}

mod macros {
    /// Generates an Ed25519 signing scheme wrapper for a specific protocol.
    ///
    /// This macro creates a complete wrapper struct with constructors, `Scheme` trait
    /// implementation, and a `fixture` function for testing.
    ///
    /// # Parameters
    ///
    /// - `$subject`: The subject type used as `Scheme::Subject<'a, D>`. Use `'a` and `D`
    ///   in the subject type to bind to the GAT lifetime and digest type parameters.
    ///
    /// - `$namespace`: The namespace type that implements [`Namespace`](crate::certificate::Namespace).
    ///   This type pre-computes and stores any protocol-specific namespace bytes derived from
    ///   a base namespace. The scheme calls `$namespace::derive(base)` at construction time
    ///   to create the namespace, then passes it to `Subject::namespace()` during signing
    ///   and verification. For simple protocols with only a base namespace, `Vec<u8>` can be used directly.
    ///   For protocols with multiple message types, a custom struct can pre-compute all variants.
    ///
    /// # Example
    /// ```ignore
    /// // For non-generic subject types with a single namespace:
    /// impl_certificate_ed25519!(MySubject, Vec<u8>);
    ///
    /// // For protocols with generic subject types:
    /// impl_certificate_ed25519!(Subject<'a, D>, Namespace);
    /// ```
    #[macro_export]
    macro_rules! impl_certificate_ed25519 {
        ($subject:ty, $namespace:ty) => {
            /// Generates a test fixture with Ed25519 identities and signing schemes.
            ///
            /// Returns a [`commonware_cryptography::certificate::mocks::Fixture`] whose keys and
            /// scheme instances share a consistent ordering.
            #[cfg(feature = "mocks")]
            #[allow(dead_code)]
            pub fn fixture<R>(
                rng: &mut R,
                namespace: &[u8],
                n: u32,
            ) -> $crate::certificate::mocks::Fixture<Scheme>
            where
                R: rand::RngCore + rand::CryptoRng,
            {
                $crate::ed25519::certificate::mocks::fixture(
                    rng,
                    namespace,
                    n,
                    Scheme::signer,
                    Scheme::verifier,
                )
            }

            /// Ed25519 signing scheme wrapper.
            #[derive(Clone, Debug)]
            pub struct Scheme {
                generic: $crate::ed25519::certificate::Generic<$namespace>,
            }

            impl Scheme {
                /// Creates a new scheme instance with the provided key material.
                ///
                /// Participants use the same key for both identity and signing.
                ///
                /// If the provided private key does not match any signing key in the participant set,
                /// the instance will act as a verifier (unable to generate signatures).
                ///
                /// Returns `None` if the provided private key does not match any participant
                /// in the participant set.
                pub fn signer(
                    namespace: &[u8],
                    participants: commonware_utils::ordered::Set<$crate::ed25519::PublicKey>,
                    private_key: $crate::ed25519::PrivateKey,
                ) -> Option<Self> {
                    Some(Self {
                        generic: $crate::ed25519::certificate::Generic::signer(
                            namespace,
                            participants,
                            private_key,
                        )?,
                    })
                }

                /// Builds a verifier that can authenticate signatures without generating them.
                ///
                /// Participants use the same key for both identity and signing.
                pub fn verifier(
                    namespace: &[u8],
                    participants: commonware_utils::ordered::Set<$crate::ed25519::PublicKey>,
                ) -> Self {
                    Self {
                        generic: $crate::ed25519::certificate::Generic::verifier(
                            namespace,
                            participants,
                        ),
                    }
                }
            }

            impl $crate::certificate::Scheme for Scheme {
                type Subject<'a, D: $crate::Digest> = $subject;
                type PublicKey = $crate::ed25519::PublicKey;
                type Signature = $crate::ed25519::Signature;
                type Certificate = $crate::ed25519::certificate::Certificate;

                fn me(&self) -> Option<commonware_utils::Participant> {
                    self.generic.me()
                }

                fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
                    &self.generic.participants
                }

                fn sign<D: $crate::Digest>(
                    &self,
                    subject: Self::Subject<'_, D>,
                ) -> Option<$crate::certificate::Attestation<Self>> {
                    self.generic.sign::<_, D>(subject)
                }

                fn verify_attestation<R, D>(
                    &self,
                    _rng: &mut R,
                    subject: Self::Subject<'_, D>,
                    attestation: &$crate::certificate::Attestation<Self>,
                    _strategy: &impl commonware_parallel::Strategy,
                ) -> bool
                where
                    R: rand_core::CryptoRngCore,
                    D: $crate::Digest,
                {
                    self.generic
                        .verify_attestation::<_, D>(subject, attestation)
                }

                fn verify_attestations<R, D, I>(
                    &self,
                    rng: &mut R,
                    subject: Self::Subject<'_, D>,
                    attestations: I,
                    _strategy: &impl commonware_parallel::Strategy,
                ) -> $crate::certificate::Verification<Self>
                where
                    R: rand_core::CryptoRngCore,
                    D: $crate::Digest,
                    I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                {
                    self.generic
                        .verify_attestations::<_, _, D, _>(rng, subject, attestations)
                }

                fn assemble<I, M>(
                    &self,
                    attestations: I,
                    _strategy: &impl commonware_parallel::Strategy,
                ) -> Option<Self::Certificate>
                where
                    I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                    M: commonware_utils::Faults,
                {
                    self.generic.assemble::<Self, _, M>(attestations)
                }

                fn verify_certificate<R, D, M>(
                    &self,
                    rng: &mut R,
                    subject: Self::Subject<'_, D>,
                    certificate: &Self::Certificate,
                    _strategy: &impl commonware_parallel::Strategy,
                ) -> bool
                where
                    R: rand_core::CryptoRngCore,
                    D: $crate::Digest,
                    M: commonware_utils::Faults,
                {
                    self.generic
                        .verify_certificate::<Self, _, D, M>(rng, subject, certificate)
                }

                fn verify_certificates<'a, R, D, I, M>(
                    &self,
                    rng: &mut R,
                    certificates: I,
                    _strategy: &impl commonware_parallel::Strategy,
                ) -> bool
                where
                    R: rand::Rng + rand::CryptoRng,
                    D: $crate::Digest,
                    I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
                    M: commonware_utils::Faults,
                {
                    self.generic
                        .verify_certificates::<Self, _, D, _, M>(rng, certificates)
                }

                fn is_attributable() -> bool {
                    $crate::ed25519::certificate::Generic::<$namespace>::is_attributable()
                }

                fn is_batchable() -> bool {
                    $crate::ed25519::certificate::Generic::<$namespace>::is_batchable()
                }

                fn certificate_codec_config(
                    &self,
                ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    self.generic.certificate_codec_config()
                }

                fn certificate_codec_config_unbounded(
                ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    $crate::ed25519::certificate::Generic::<$namespace>::certificate_codec_config_unbounded()
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        certificate::Scheme as _, impl_certificate_ed25519, sha256::Digest as Sha256Digest,
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode};
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::{ordered::Set, test_rng, Faults, N3f1, Participant, TryCollect};

    const NAMESPACE: &[u8] = b"test-ed25519";
    const MESSAGE: &[u8] = b"test message";

    /// Test context type for generic scheme tests.
    #[derive(Clone, Debug)]
    pub struct TestSubject {
        pub message: Bytes,
    }

    impl Subject for TestSubject {
        type Namespace = Vec<u8>;

        fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
            derived.as_ref()
        }

        fn message(&self) -> Bytes {
            self.message.clone()
        }
    }

    // Use the macro to generate the test scheme
    impl_certificate_ed25519!(TestSubject, Vec<u8>);

    fn setup_signers(rng: &mut impl CryptoRngCore, n: u32) -> (Vec<Scheme>, Scheme) {
        let private_keys: Vec<_> = (0..n).map(|_| PrivateKey::random(&mut *rng)).collect();
        let participants: Set<PublicKey> = private_keys
            .iter()
            .map(|sk| sk.public_key())
            .try_collect()
            .unwrap();

        let signers = private_keys
            .into_iter()
            .map(|sk| Scheme::signer(NAMESPACE, participants.clone(), sk).unwrap())
            .collect();

        let verifier = Scheme::verifier(NAMESPACE, participants);

        (signers, verifier)
    }

    #[test]
    fn test_is_attributable() {
        assert!(Generic::<Vec<u8>>::is_attributable());
        assert!(Scheme::is_attributable());
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_is_batchable() {
        assert!(Generic::<Vec<u8>>::is_batchable());
        assert!(Scheme::is_batchable());
    }

    #[test]
    #[cfg(not(feature = "std"))]
    fn test_is_not_batchable() {
        assert!(!Generic::is_batchable());
        assert!(!Scheme::is_batchable());
    }

    #[test]
    fn test_sign_vote_roundtrip() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers(&mut rng, 4);
        let scheme = &schemes[0];

        let attestation = scheme
            .sign::<Sha256Digest>(TestSubject {
                message: Bytes::from_static(MESSAGE),
            })
            .unwrap();
        assert!(scheme.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &attestation,
            &Sequential,
        ));
    }

    #[test]
    fn test_verifier_cannot_sign() {
        let mut rng = test_rng();
        let (_, verifier) = setup_signers(&mut rng, 4);
        assert!(verifier
            .sign::<Sha256Digest>(TestSubject {
                message: Bytes::from_static(MESSAGE)
            })
            .is_none());
    }

    #[test]
    fn test_verify_attestations_filters_invalid() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers(&mut rng, 5);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        let result = schemes[0].verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            attestations.clone(),
            &Sequential,
        );
        assert!(result.invalid.is_empty());
        assert_eq!(result.verified.len(), quorum);

        // Test 1: Corrupt one attestation - invalid signer index
        let mut attestations_corrupted = attestations.clone();
        attestations_corrupted[0].signer = Participant::new(999);
        let result = schemes[0].verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            attestations_corrupted,
            &Sequential,
        );
        assert_eq!(result.invalid, vec![Participant::new(999)]);
        assert_eq!(result.verified.len(), quorum - 1);

        // Test 2: Corrupt one attestation - invalid signature
        let mut attestations_corrupted = attestations;
        attestations_corrupted[0].signature = attestations_corrupted[1].signature.clone();
        let result = schemes[0].verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            attestations_corrupted,
            &Sequential,
        );
        // Batch verification may detect either signer 0 (wrong sig) or signer 1 (duplicate sig)
        assert_eq!(result.invalid.len(), 1);
        assert_eq!(result.verified.len(), quorum - 1);
    }

    #[test]
    fn test_assemble_certificate() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        // Verify certificate has correct number of signers
        assert_eq!(certificate.signers.count(), quorum);
        assert_eq!(certificate.signatures.len(), quorum);
    }

    #[test]
    fn test_assemble_certificate_sorts_signers() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers(&mut rng, 4);

        // Get indices and sort them to create attestations in guaranteed reverse order
        let mut indexed: Vec<_> = (0..3).map(|i| (schemes[i].me().unwrap(), i)).collect();
        indexed.sort_by_key(|(idx, _)| *idx);

        // Create attestations in reverse sorted order (guaranteed non-sorted)
        let attestations = vec![
            schemes[indexed[2].1]
                .sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap(),
            schemes[indexed[1].1]
                .sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap(),
            schemes[indexed[0].1]
                .sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap(),
        ];

        let certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        // Verify signers are sorted by signer index
        let expected: Vec<_> = indexed.iter().map(|(idx, _)| *idx).collect();
        assert_eq!(certificate.signers.iter().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn test_verify_certificate() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE)
            },
            &certificate,
            &Sequential,
        ));
    }

    #[test]
    fn test_verify_certificate_detects_corruption() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        // Valid certificate passes
        assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &certificate,
            &Sequential,
        ));

        // Corrupted certificate fails
        let mut corrupted = certificate;
        corrupted.signatures[0] = corrupted.signatures[1].clone();
        assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &corrupted,
            &Sequential,
        ));
    }

    #[test]
    fn test_certificate_codec_roundtrip() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();
        let encoded = certificate.encode();
        let decoded = Certificate::decode_cfg(encoded, &schemes.len()).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_rejects_sub_quorum() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers(&mut rng, 4);
        let sub_quorum = 2; // Less than quorum (3)

        let attestations: Vec<_> = schemes
            .iter()
            .take(sub_quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        assert!(schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .is_none());
    }

    #[test]
    fn test_certificate_rejects_invalid_signer() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        let mut attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        // Corrupt signer index to be out of range
        attestations[0].signer = Participant::new(999);

        assert!(schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .is_none());
    }

    #[test]
    fn test_verify_certificate_rejects_sub_quorum() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers(&mut rng, 4);
        let participants_len = schemes.len();

        let attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        let mut certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        // Artificially truncate to below quorum
        let mut signers: Vec<Participant> = certificate.signers.iter().collect();
        signers.pop();
        certificate.signers = Signers::from(participants_len, signers);
        certificate.signatures.pop();

        assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &certificate,
            &Sequential,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_mismatched_signature_count() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers(&mut rng, 4);

        let attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        let mut certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        // Remove one signature but keep signers bitmap unchanged
        certificate.signatures.pop();

        assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &certificate,
            &Sequential,
        ));
    }

    #[test]
    fn test_verify_certificates_batch() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        let messages: Vec<Bytes> = [b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()]
            .into_iter()
            .map(Bytes::copy_from_slice)
            .collect();
        let mut certificates = Vec::new();

        for msg in &messages {
            let attestations: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| {
                    s.sign::<Sha256Digest>(TestSubject {
                        message: msg.clone(),
                    })
                    .unwrap()
                })
                .collect();
            certificates.push(
                schemes[0]
                    .assemble::<_, N3f1>(attestations, &Sequential)
                    .unwrap(),
            );
        }

        let certs_iter = messages.iter().zip(&certificates).map(|(msg, cert)| {
            (
                TestSubject {
                    message: msg.clone(),
                },
                cert,
            )
        });

        assert!(verifier.verify_certificates::<_, Sha256Digest, _, N3f1>(
            &mut rng,
            certs_iter,
            &Sequential
        ));
    }

    #[test]
    fn test_verify_certificates_batch_detects_failure() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        let messages: Vec<Bytes> = [b"msg1".as_slice(), b"msg2".as_slice()]
            .into_iter()
            .map(Bytes::copy_from_slice)
            .collect();
        let mut certificates = Vec::new();

        for msg in &messages {
            let attestations: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| {
                    s.sign::<Sha256Digest>(TestSubject {
                        message: msg.clone(),
                    })
                    .unwrap()
                })
                .collect();
            certificates.push(
                schemes[0]
                    .assemble::<_, N3f1>(attestations, &Sequential)
                    .unwrap(),
            );
        }

        // Corrupt second certificate
        certificates[1].signatures[0] = certificates[1].signatures[1].clone();

        let certs_iter = messages.iter().zip(&certificates).map(|(msg, cert)| {
            (
                TestSubject {
                    message: msg.clone(),
                },
                cert,
            )
        });

        assert!(!verifier.verify_certificates::<_, Sha256Digest, _, N3f1>(
            &mut rng,
            certs_iter,
            &Sequential
        ));
    }

    #[test]
    #[should_panic(expected = "duplicate signer index")]
    fn test_assemble_certificate_rejects_duplicate_signers() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers(&mut rng, 4);

        let mut attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        // Add a duplicate of the last vote
        attestations.push(attestations.last().unwrap().clone());

        // This should panic due to duplicate signer
        schemes[0].assemble::<_, N3f1>(attestations, &Sequential);
    }

    #[test]
    fn test_scheme_clone_and_verifier() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers(&mut rng, 4);
        let participants = schemes[0].participants().clone();

        // Clone a signer
        let signer = schemes[0].clone();
        assert!(
            signer
                .sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .is_some(),
            "signer should produce votes"
        );

        // A verifier cannot produce votes
        let verifier = Scheme::verifier(NAMESPACE, participants);
        assert!(
            verifier
                .sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .is_none(),
            "verifier should not produce votes"
        );
    }

    #[test]
    fn test_certificate_decode_validation() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers(&mut rng, 4);
        let participants_len = schemes.len();

        let attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        // Well-formed certificate decodes successfully
        let encoded = certificate.encode();
        let decoded =
            Certificate::decode_cfg(encoded, &participants_len).expect("decode certificate");
        assert_eq!(decoded, certificate);

        // Certificate with no signers is rejected
        let empty = Certificate {
            signers: Signers::from(participants_len, std::iter::empty::<Participant>()),
            signatures: Vec::new(),
        };
        assert!(Certificate::decode_cfg(empty.encode(), &participants_len).is_err());

        // Certificate with mismatched signature count is rejected
        let mismatched = Certificate {
            signers: Signers::from(participants_len, [0u32, 1].map(Participant::new)),
            signatures: vec![certificate.signatures[0].clone()],
        };
        assert!(Certificate::decode_cfg(mismatched.encode(), &participants_len).is_err());

        // Certificate containing more signers than the participant set is rejected
        let mut signers = certificate.signers.iter().collect::<Vec<_>>();
        signers.push(Participant::from_usize(participants_len));
        let mut sigs = certificate.signatures.clone();
        sigs.push(certificate.signatures[0].clone());
        let extended = Certificate {
            signers: Signers::from(participants_len + 1, signers),
            signatures: sigs,
        };
        assert!(Certificate::decode_cfg(extended.encode(), &participants_len).is_err());
    }

    #[test]
    fn test_verify_certificate_rejects_unknown_signer() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers(&mut rng, 4);
        let participants_len = schemes.len();

        let attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        let mut certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        // Add an unknown signer (out of range)
        let mut signers: Vec<Participant> = certificate.signers.iter().collect();
        signers.push(Participant::from_usize(participants_len));
        certificate.signers = Signers::from(participants_len + 1, signers);
        certificate
            .signatures
            .push(certificate.signatures[0].clone());

        assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &certificate,
            &Sequential,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_invalid_certificate_signers_size() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers(&mut rng, 4);
        let participants_len = schemes.len();

        let attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        let mut certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        // Valid certificate passes
        assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &certificate,
            &Sequential,
        ));

        // Make the signers bitmap size larger (mismatched with participants)
        let signers: Vec<Participant> = certificate.signers.iter().collect();
        certificate.signers = Signers::from(participants_len + 1, signers);

        // Certificate verification should fail due to size mismatch
        assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &certificate,
            &Sequential,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_signers_size_mismatch() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers(&mut rng, 4);
        let participants_len = schemes.len();

        let attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        let mut certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        // Make the signers bitmap size larger than participants
        let signers: Vec<Participant> = certificate.signers.iter().collect();
        certificate.signers = Signers::from(participants_len + 1, signers);
        certificate
            .signatures
            .push(certificate.signatures[0].clone());

        assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &certificate,
            &Sequential,
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Certificate>,
        }
    }
}
