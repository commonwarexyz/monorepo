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
    certificate::{Attestation, Scheme, Signers, Subject},
    Digest, Signer as _, Verifier as _,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadRangeExt, Write};
use commonware_utils::ordered::{Quorum, Set};
use rand::{CryptoRng, Rng};
#[cfg(feature = "std")]
use std::collections::BTreeSet;

/// Generic Ed25519 signing scheme implementation.
///
/// This struct contains the core cryptographic operations without protocol-specific
/// context types. It can be reused across different protocols (simplex, aggregation, etc.)
/// by wrapping it with protocol-specific trait implementations via the macro.
#[derive(Clone, Debug)]
pub struct Generic {
    /// Participants in the committee.
    pub participants: Set<PublicKey>,
    /// Key used for generating signatures.
    pub signer: Option<(u32, PrivateKey)>,
}

impl Generic {
    /// Creates a new generic Ed25519 scheme instance.
    pub fn signer(participants: Set<PublicKey>, private_key: PrivateKey) -> Option<Self> {
        let signer = participants
            .index(&private_key.public_key())
            .map(|index| (index, private_key))?;

        Some(Self {
            participants,
            signer: Some(signer),
        })
    }

    /// Builds a verifier that can authenticate signatures without generating them.
    pub const fn verifier(participants: Set<PublicKey>) -> Self {
        Self {
            participants,
            signer: None,
        }
    }

    /// Returns the index of "self" in the participant set, if available.
    pub fn me(&self) -> Option<u32> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    /// Signs a subject and returns the signer index and signature.
    pub fn sign<S, D>(&self, namespace: &[u8], subject: S::Subject<'_, D>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = Ed25519Signature>,
        D: Digest,
    {
        let (index, private_key) = self.signer.as_ref()?;

        let (namespace, message) = subject.namespace_and_message(namespace);
        let signature = private_key.sign(namespace.as_ref(), message.as_ref());

        Some(Attestation {
            signer: *index,
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
        S: Scheme<Signature = Ed25519Signature>,
        D: Digest,
    {
        let Some(public_key) = self.participants.key(attestation.signer) else {
            return false;
        };

        let (namespace, message) = subject.namespace_and_message(namespace);
        public_key.verify(namespace.as_ref(), message.as_ref(), &attestation.signature)
    }

    /// Batch-verifies attestations and returns verified attestations and invalid signers.
    #[cfg(feature = "std")]
    pub fn verify_attestations<S, R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        subject: S::Subject<'_, D>,
        attestations: I,
    ) -> Verification<S>
    where
        S: Scheme<Signature = Ed25519Signature>,
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<S>>,
    {
        let (namespace, message) = subject.namespace_and_message(namespace);

        let mut invalid = BTreeSet::new();
        let mut candidates = Vec::new();
        let mut batch = Batch::new();

        for attestation in attestations.into_iter() {
            let Some(public_key) = self.participants.key(attestation.signer) else {
                invalid.insert(attestation.signer);
                continue;
            };

            batch.add(
                namespace.as_ref(),
                message.as_ref(),
                public_key,
                &attestation.signature,
            );

            candidates.push((attestation, public_key));
        }

        if !candidates.is_empty() && !batch.verify(rng) {
            // Batch failed: fall back to per-signer verification to isolate faulty attestations.
            for (attestation, public_key) in &candidates {
                if !public_key.verify(namespace.as_ref(), message.as_ref(), &attestation.signature)
                {
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
    pub fn verify_attestations<S, R, D, I>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        subject: S::Subject<'_, D>,
        attestations: I,
    ) -> crate::certificate::Verification<S>
    where
        S: Scheme<Signature = Ed25519Signature>,
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<S>>,
    {
        let (namespace, message) = subject.namespace_and_message(namespace);

        let mut invalid = alloc::collections::BTreeSet::new();
        let mut verified = Vec::new();

        for attestation in attestations.into_iter() {
            let Some(public_key) = self.participants.key(attestation.signer) else {
                invalid.insert(attestation.signer);
                continue;
            };

            if public_key.verify(namespace.as_ref(), message.as_ref(), &attestation.signature) {
                verified.push(attestation);
            } else {
                invalid.insert(attestation.signer);
            }
        }

        crate::certificate::Verification::new(verified, invalid.into_iter().collect())
    }

    /// Assembles a certificate from a collection of attestations.
    pub fn assemble<S, I>(&self, attestations: I) -> Option<Certificate>
    where
        S: Scheme<Signature = Ed25519Signature>,
        I: IntoIterator<Item = Attestation<S>>,
    {
        // Collect the signers and signatures.
        let mut entries = Vec::new();
        for Attestation { signer, signature } in attestations {
            if signer as usize >= self.participants.len() {
                return None;
            }

            entries.push((signer, signature));
        }
        if entries.len() < self.participants.quorum() as usize {
            return None;
        }

        // Sort the signatures by signer index.
        entries.sort_by_key(|(signer, _)| *signer);
        let (signer, signatures): (Vec<u32>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::from(self.participants.len(), signer);

        Some(Certificate {
            signers,
            signatures,
        })
    }

    /// Stages a certificate for batch verification.
    ///
    /// Returns false if the certificate structure is invalid.
    #[cfg(feature = "std")]
    fn batch_verify_certificate<S, D>(
        &self,
        batch: &mut Batch,
        namespace: &[u8],
        subject: S::Subject<'_, D>,
        certificate: &Certificate,
    ) -> bool
    where
        S: Scheme,
        D: Digest,
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
        if certificate.signers.count() < self.participants.quorum() as usize {
            return false;
        }

        // Add the certificate to the batch.
        let (namespace, message) = subject.namespace_and_message(namespace);
        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            let Some(public_key) = self.participants.key(signer) else {
                return false;
            };

            batch.add(namespace.as_ref(), message.as_ref(), public_key, signature);
        }

        true
    }

    /// Verifies a certificate using batch verification.
    #[cfg(feature = "std")]
    pub fn verify_certificate<S, R, D>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        subject: S::Subject<'_, D>,
        certificate: &Certificate,
    ) -> bool
    where
        S: Scheme,
        R: Rng + CryptoRng,
        D: Digest,
    {
        let mut batch = Batch::new();
        if !self.batch_verify_certificate::<S, D>(&mut batch, namespace, subject, certificate) {
            return false;
        }

        batch.verify(rng)
    }

    /// Verifies a certificate by checking each signature individually.
    #[cfg(not(feature = "std"))]
    pub fn verify_certificate<S, R, D>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        subject: S::Subject<'_, D>,
        certificate: &Certificate,
    ) -> bool
    where
        S: Scheme,
        R: Rng + CryptoRng,
        D: Digest,
    {
        if certificate.signers.len() != self.participants.len() {
            return false;
        }
        if certificate.signers.count() != certificate.signatures.len() {
            return false;
        }
        if certificate.signers.count() < self.participants.quorum() as usize {
            return false;
        }

        let (namespace, message) = subject.namespace_and_message(namespace);
        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            let Some(public_key) = self.participants.key(signer) else {
                return false;
            };
            if !public_key.verify(namespace.as_ref(), message.as_ref(), signature) {
                return false;
            }
        }

        true
    }

    /// Verifies multiple certificates in a batch.
    #[cfg(feature = "std")]
    pub fn verify_certificates<'a, S, R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        certificates: I,
    ) -> bool
    where
        S: Scheme,
        R: Rng + CryptoRng,
        D: Digest,
        I: Iterator<Item = (S::Subject<'a, D>, &'a Certificate)>,
    {
        let mut batch = Batch::new();
        for (subject, certificate) in certificates {
            if !self.batch_verify_certificate::<S, D>(&mut batch, namespace, subject, certificate) {
                return false;
            }
        }

        batch.verify(rng)
    }

    /// Verifies multiple certificates one-by-one.
    #[cfg(not(feature = "std"))]
    pub fn verify_certificates<'a, S, R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        certificates: I,
    ) -> bool
    where
        S: Scheme,
        R: Rng + CryptoRng,
        D: Digest,
        I: Iterator<Item = (S::Subject<'a, D>, &'a Certificate)>,
    {
        for (subject, certificate) in certificates {
            if !self.verify_certificate::<S, _, D>(rng, namespace, subject, certificate) {
                return false;
            }
        }

        true
    }

    pub const fn is_attributable(&self) -> bool {
        true
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
    pub signatures: Vec<Ed25519Signature>,
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Certificate {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let signers = Signers::arbitrary(u)?;
        let signatures = (0..signers.count())
            .map(|_| u.arbitrary::<Ed25519Signature>())
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

        let signatures = Vec::<Ed25519Signature>::read_range(reader, ..=*participants)?;
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
    /// The only required parameter is the `Subject` type, which varies per protocol.
    ///
    /// # Example
    /// ```ignore
    /// impl_certificate_ed25519!(VoteSubject<'a, D>);
    /// ```
    #[macro_export]
    macro_rules! impl_certificate_ed25519 {
        ($subject:ty) => {
            /// Generates a test fixture with Ed25519 identities and signing schemes.
            ///
            /// Returns a [`commonware_cryptography::certificate::mocks::Fixture`] whose keys and
            /// scheme instances share a consistent ordering.
            #[cfg(feature = "mocks")]
            #[allow(dead_code)]
            pub fn fixture<R>(rng: &mut R, n: u32) -> $crate::certificate::mocks::Fixture<Scheme>
            where
                R: rand::RngCore + rand::CryptoRng,
            {
                $crate::ed25519::certificate::mocks::fixture(
                    rng,
                    n,
                    Scheme::signer,
                    Scheme::verifier,
                )
            }

            /// Ed25519 signing scheme wrapper.
            #[derive(Clone, Debug)]
            pub struct Scheme {
                generic: $crate::ed25519::certificate::Generic,
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
                    participants: commonware_utils::ordered::Set<$crate::ed25519::PublicKey>,
                    private_key: $crate::ed25519::PrivateKey,
                ) -> Option<Self> {
                    Some(Self {
                        generic: $crate::ed25519::certificate::Generic::signer(
                            participants,
                            private_key,
                        )?,
                    })
                }

                /// Builds a verifier that can authenticate signatures without generating them.
                ///
                /// Participants use the same key for both identity and signing.
                pub const fn verifier(
                    participants: commonware_utils::ordered::Set<$crate::ed25519::PublicKey>,
                ) -> Self {
                    Self {
                        generic: $crate::ed25519::certificate::Generic::verifier(participants),
                    }
                }
            }

            impl $crate::certificate::Scheme for Scheme {
                type Subject<'a, D: $crate::Digest> = $subject;
                type PublicKey = $crate::ed25519::PublicKey;
                type Signature = $crate::ed25519::Signature;
                type Certificate = $crate::ed25519::certificate::Certificate;

                fn me(&self) -> Option<u32> {
                    self.generic.me()
                }

                fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
                    &self.generic.participants
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
                    self.generic
                        .verify_attestation::<_, D>(namespace, subject, attestation)
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
                    self.generic.verify_attestations::<_, _, D, _>(
                        rng,
                        namespace,
                        subject,
                        attestations,
                    )
                }

                fn assemble<I>(&self, attestations: I) -> Option<Self::Certificate>
                where
                    I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                {
                    self.generic.assemble(attestations)
                }

                fn verify_certificate<R: rand::Rng + rand::CryptoRng, D: $crate::Digest>(
                    &self,
                    rng: &mut R,
                    namespace: &[u8],
                    subject: Self::Subject<'_, D>,
                    certificate: &Self::Certificate,
                ) -> bool {
                    self.generic.verify_certificate::<Self, _, D>(
                        rng,
                        namespace,
                        subject,
                        certificate,
                    )
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
                    self.generic
                        .verify_certificates::<Self, _, D, _>(rng, namespace, certificates)
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
                    $crate::ed25519::certificate::Generic::certificate_codec_config_unbounded()
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
    use commonware_utils::{ordered::Set, quorum, TryCollect};
    use rand::{rngs::StdRng, thread_rng, SeedableRng};

    const NAMESPACE: &[u8] = b"test-ed25519";
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
    impl_certificate_ed25519!(TestSubject<'a>);

    fn setup_signers(n: u32, seed: u64) -> (Vec<Scheme>, Scheme) {
        let mut rng = StdRng::seed_from_u64(seed);
        let private_keys: Vec<_> = (0..n).map(|_| PrivateKey::random(&mut rng)).collect();
        let participants: Set<PublicKey> = private_keys
            .iter()
            .map(|sk| sk.public_key())
            .try_collect()
            .unwrap();

        let signers = private_keys
            .into_iter()
            .map(|sk| Scheme::signer(participants.clone(), sk).unwrap())
            .collect();

        let verifier = Scheme::verifier(participants);

        (signers, verifier)
    }

    #[test]
    fn test_sign_vote_roundtrip() {
        let (schemes, _) = setup_signers(4, 42);
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
    fn test_verifier_cannot_sign() {
        let (_, verifier) = setup_signers(4, 43);
        assert!(verifier
            .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
            .is_none());
    }

    #[test]
    fn test_verify_attestations_filters_invalid() {
        let (schemes, _) = setup_signers(5, 44);
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

        // Test 1: Corrupt one attestation - invalid signer index
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

        // Test 2: Corrupt one attestation - invalid signature
        let mut attestations_corrupted = attestations;
        attestations_corrupted[0].signature = attestations_corrupted[1].signature.clone();
        let result = schemes[0].verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            NAMESPACE,
            TestSubject { message: MESSAGE },
            attestations_corrupted,
        );
        // Batch verification may detect either signer 0 (wrong sig) or signer 1 (duplicate sig)
        assert_eq!(result.invalid.len(), 1);
        assert_eq!(result.verified.len(), quorum - 1);
    }

    #[test]
    fn test_assemble_certificate() {
        let (schemes, _) = setup_signers(4, 46);
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

        // Verify certificate has correct number of signers
        assert_eq!(certificate.signers.count(), quorum);
        assert_eq!(certificate.signatures.len(), quorum);
    }

    #[test]
    fn test_assemble_certificate_sorts_signers() {
        let (schemes, _) = setup_signers(4, 47);

        // Create votes in non-sorted order (indices 2, 0, 1)
        let attestations = vec![
            schemes[2]
                .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                .unwrap(),
            schemes[0]
                .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                .unwrap(),
            schemes[1]
                .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                .unwrap(),
        ];

        let certificate = schemes[0].assemble(attestations).unwrap();

        // Verify signers are sorted
        assert_eq!(
            certificate.signers.iter().collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn test_verify_certificate() {
        let (schemes, verifier) = setup_signers(4, 48);
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
    fn test_verify_certificate_detects_corruption() {
        let (schemes, verifier) = setup_signers(4, 50);
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
        let mut corrupted = certificate;
        corrupted.signatures[0] = corrupted.signatures[1].clone();
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &corrupted
        ));
    }

    #[test]
    fn test_certificate_codec_roundtrip() {
        let (schemes, _) = setup_signers(4, 51);
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
        let decoded = Certificate::decode_cfg(encoded, &schemes.len()).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_rejects_sub_quorum() {
        let (schemes, _) = setup_signers(4, 52);
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
    fn test_certificate_rejects_invalid_signer() {
        let (schemes, _) = setup_signers(4, 53);
        let quorum = quorum(schemes.len() as u32) as usize;

        let mut attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        // Corrupt signer index to be out of range
        attestations[0].signer = 999;

        assert!(schemes[0].assemble(attestations).is_none());
    }

    #[test]
    fn test_verify_certificate_rejects_sub_quorum() {
        let (schemes, verifier) = setup_signers(4, 54);
        let participants_len = schemes.len();

        let attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0].assemble(attestations).unwrap();

        // Artificially truncate to below quorum
        let mut signers: Vec<u32> = certificate.signers.iter().collect();
        signers.pop();
        certificate.signers = Signers::from(participants_len, signers);
        certificate.signatures.pop();

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_mismatched_signature_count() {
        let (schemes, verifier) = setup_signers(4, 55);

        let attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0].assemble(attestations).unwrap();

        // Remove one signature but keep signers bitmap unchanged
        certificate.signatures.pop();

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate
        ));
    }

    #[test]
    fn test_verify_certificates_batch() {
        let (schemes, verifier) = setup_signers(4, 56);
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
    fn test_verify_certificates_batch_detects_failure() {
        let (schemes, verifier) = setup_signers(4, 58);
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
        certificates[1].signatures[0] = certificates[1].signatures[1].clone();

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
    #[should_panic(expected = "duplicate signer index")]
    fn test_assemble_certificate_rejects_duplicate_signers() {
        let (schemes, _) = setup_signers(4, 60);

        let mut attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        // Add a duplicate of the last vote
        attestations.push(attestations.last().unwrap().clone());

        // This should panic due to duplicate signer
        schemes[0].assemble(attestations);
    }

    #[test]
    fn test_scheme_clone_and_verifier() {
        let (schemes, _) = setup_signers(4, 61);
        let participants = schemes[0].participants().clone();

        // Clone a signer
        let signer = schemes[0].clone();
        assert!(
            signer
                .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                .is_some(),
            "signer should produce votes"
        );

        // A verifier cannot produce votes
        let verifier = Scheme::verifier(participants);
        assert!(
            verifier
                .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                .is_none(),
            "verifier should not produce votes"
        );
    }

    #[test]
    fn test_certificate_decode_validation() {
        let (schemes, _) = setup_signers(4, 62);
        let participants_len = schemes.len();

        let attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble(attestations).unwrap();

        // Well-formed certificate decodes successfully
        let encoded = certificate.encode();
        let decoded =
            Certificate::decode_cfg(encoded, &participants_len).expect("decode certificate");
        assert_eq!(decoded, certificate);

        // Certificate with no signers is rejected
        let empty = Certificate {
            signers: Signers::from(participants_len, std::iter::empty::<u32>()),
            signatures: Vec::new(),
        };
        assert!(Certificate::decode_cfg(empty.encode(), &participants_len).is_err());

        // Certificate with mismatched signature count is rejected
        let mismatched = Certificate {
            signers: Signers::from(participants_len, [0u32, 1]),
            signatures: vec![certificate.signatures[0].clone()],
        };
        assert!(Certificate::decode_cfg(mismatched.encode(), &participants_len).is_err());

        // Certificate containing more signers than the participant set is rejected
        let mut signers = certificate.signers.iter().collect::<Vec<_>>();
        signers.push(participants_len as u32);
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
        let (schemes, verifier) = setup_signers(4, 63);
        let participants_len = schemes.len();

        let attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0].assemble(attestations).unwrap();

        // Add an unknown signer (out of range)
        let mut signers: Vec<u32> = certificate.signers.iter().collect();
        signers.push(participants_len as u32);
        certificate.signers = Signers::from(participants_len + 1, signers);
        certificate
            .signatures
            .push(certificate.signatures[0].clone());

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_invalid_certificate_signers_size() {
        let (schemes, verifier) = setup_signers(4, 64);
        let participants_len = schemes.len();

        let attestations: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0].assemble(attestations).unwrap();

        // Valid certificate passes
        assert!(verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate,
        ));

        // Make the signers bitmap size larger (mismatched with participants)
        let signers: Vec<u32> = certificate.signers.iter().collect();
        certificate.signers = Signers::from(participants_len + 1, signers);

        // Certificate verification should fail due to size mismatch
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate,
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
