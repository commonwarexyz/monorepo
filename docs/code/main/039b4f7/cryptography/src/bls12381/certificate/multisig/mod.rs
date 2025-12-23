//! BLS12-381 multi-signature signing scheme implementation.
//!
//! This module provides both the generic BLS12-381 multisig implementation and a macro to generate
//! protocol-specific wrappers.

#[cfg(feature = "mocks")]
pub mod mocks;

use crate::{
    bls12381::primitives::{
        group::Private,
        ops::{
            aggregate_signatures, aggregate_verify_multiple_public_keys, compute_public,
            sign_message, verify_message,
        },
        variant::Variant,
    },
    certificate::{Attestation, Scheme, Signers, Subject, Verification},
    Digest, PublicKey,
};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_utils::ordered::{BiMap, Quorum, Set};
use rand::{CryptoRng, Rng};
#[cfg(feature = "std")]
use std::collections::BTreeSet;

/// Generic BLS12-381 multi-signature implementation.
///
/// This struct contains the core cryptographic operations without protocol-specific
/// context types. It can be reused across different protocols (simplex, aggregation, etc.)
/// by wrapping it with protocol-specific trait implementations via the macro.
#[derive(Clone, Debug)]
pub struct Generic<P: PublicKey, V: Variant> {
    /// Participants in the committee.
    pub participants: BiMap<P, V::Public>,
    /// Key used for generating signatures.
    pub signer: Option<(u32, Private)>,
}

impl<P: PublicKey, V: Variant> Generic<P, V> {
    /// Creates a new scheme instance with the provided key material.
    ///
    /// Participants have both an identity key and a signing key. The identity key
    /// is used for participant set ordering and indexing, while the signing key is used for
    /// signing and verification.
    ///
    /// Returns `None` if the provided private key does not match any signing key
    /// in the participant set.
    pub fn signer(participants: BiMap<P, V::Public>, private_key: Private) -> Option<Self> {
        let public_key = compute_public::<V>(&private_key);
        let signer = participants
            .values()
            .iter()
            .position(|p| p == &public_key)
            .map(|index| (index as u32, private_key))?;

        Some(Self {
            participants,
            signer: Some(signer),
        })
    }

    /// Builds a verifier that can authenticate signatures and certificates.
    ///
    /// Participants have both an identity key and a signing key. The identity key
    /// is used for participant set ordering and indexing, while the signing key is used for
    /// verification.
    pub const fn verifier(participants: BiMap<P, V::Public>) -> Self {
        Self {
            participants,
            signer: None,
        }
    }

    /// Returns the ordered set of identity keys.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns the index of "self" in the participant set, if available.
    pub fn me(&self) -> Option<u32> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    /// Signs a subject and returns the attestation.
    pub fn sign<S, D>(&self, namespace: &[u8], subject: S::Subject<'_, D>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = V::Signature>,
        D: Digest,
    {
        let (index, private_key) = self.signer.as_ref()?;

        let (namespace, message) = subject.namespace_and_message(namespace);
        let signature = sign_message::<V>(private_key, Some(namespace.as_ref()), message.as_ref());

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
        S: Scheme<Signature = V::Signature>,
        D: Digest,
    {
        let Some(public_key) = self.participants.value(attestation.signer as usize) else {
            return false;
        };

        let (namespace, message) = subject.namespace_and_message(namespace);
        verify_message::<V>(
            public_key,
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
        let mut candidates = Vec::new();
        let mut publics = Vec::new();
        let mut sigs = Vec::new();
        for attestation in attestations.into_iter() {
            let Some(public_key) = self.participants.value(attestation.signer as usize) else {
                invalid.insert(attestation.signer);
                continue;
            };

            publics.push(*public_key);
            sigs.push(attestation.signature);
            candidates.push(attestation);
        }

        // If there are no candidates to verify, return before doing any work.
        if candidates.is_empty() {
            return Verification::new(candidates, invalid.into_iter().collect());
        }

        // Verify the aggregate signature.
        let (namespace, message) = subject.namespace_and_message(namespace);
        if aggregate_verify_multiple_public_keys::<V, _>(
            publics.iter(),
            Some(namespace.as_ref()),
            message.as_ref(),
            &aggregate_signatures::<V, _>(sigs.iter()),
        )
        .is_err()
        {
            for (attestation, public_key) in candidates.iter().zip(publics.iter()) {
                if verify_message::<V>(
                    public_key,
                    Some(namespace.as_ref()),
                    message.as_ref(),
                    &attestation.signature,
                )
                .is_err()
                {
                    invalid.insert(attestation.signer);
                }
            }
        }

        // Collect the verified attestations.
        let verified = candidates
            .into_iter()
            .filter(|attestation| !invalid.contains(&attestation.signer))
            .collect();

        Verification::new(verified, invalid.into_iter().collect())
    }

    /// Assembles a certificate from a collection of attestations.
    pub fn assemble<S, I>(&self, attestations: I) -> Option<Certificate<V>>
    where
        S: Scheme<Signature = V::Signature>,
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

        // Produce signers and aggregate signature.
        let (signers, signatures): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::from(self.participants.len(), signers);
        let signature = aggregate_signatures::<V, _>(signatures.iter());

        Some(Certificate { signers, signature })
    }

    /// Verifies a certificate.
    pub fn verify_certificate<S, R, D>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        subject: S::Subject<'_, D>,
        certificate: &Certificate<V>,
    ) -> bool
    where
        S: Scheme,
        R: Rng + CryptoRng,
        D: Digest,
    {
        // If the certificate signers length does not match the participant set, return false.
        if certificate.signers.len() != self.participants.len() {
            return false;
        }

        // If the certificate does not meet the quorum, return false.
        if certificate.signers.count() < self.participants.quorum() as usize {
            return false;
        }

        // Collect the public keys.
        let mut publics = Vec::with_capacity(certificate.signers.count());
        for signer in certificate.signers.iter() {
            let Some(public_key) = self.participants.value(signer as usize) else {
                return false;
            };

            publics.push(*public_key);
        }

        // Verify the aggregate signature.
        let (namespace, message) = subject.namespace_and_message(namespace);
        aggregate_verify_multiple_public_keys::<V, _>(
            publics.iter(),
            Some(namespace.as_ref()),
            message.as_ref(),
            &certificate.signature,
        )
        .is_ok()
    }

    /// Verifies multiple certificates (no batch optimization for BLS multisig).
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
        I: Iterator<Item = (S::Subject<'a, D>, &'a Certificate<V>)>,
    {
        for (subject, certificate) in certificates {
            if !self.verify_certificate::<S, R, D>(rng, namespace, subject, certificate) {
                return false;
            }
        }
        true
    }

    pub const fn is_attributable(&self) -> bool {
        true
    }

    pub const fn certificate_codec_config(&self) -> <Certificate<V> as Read>::Cfg {
        self.participants.len()
    }

    pub const fn certificate_codec_config_unbounded() -> <Certificate<V> as Read>::Cfg {
        u32::MAX as usize
    }
}

/// Certificate formed by an aggregated BLS12-381 signature plus the signers that
/// contributed to it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<V: Variant> {
    /// Bitmap of participant indices that contributed signatures.
    pub signers: Signers,
    /// Aggregated BLS signature covering all signatures in this certificate.
    pub signature: V::Signature,
}

impl<V: Variant> Write for Certificate<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant> EncodeSize for Certificate<V> {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.signature.encode_size()
    }
}

impl<V: Variant> Read for Certificate<V> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, Error> {
        let signers = Signers::read_cfg(reader, participants)?;
        if signers.count() == 0 {
            return Err(Error::Invalid(
                "cryptography::bls12381::certificate::multisig::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signature = V::Signature::read(reader)?;

        Ok(Self { signers, signature })
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for Certificate<V>
where
    V::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let signers = Signers::arbitrary(u)?;
        let signature = V::Signature::arbitrary(u)?;
        Ok(Self { signers, signature })
    }
}

mod macros {
    /// Generates a BLS12-381 multisig signing scheme wrapper for a specific protocol.
    ///
    /// This macro creates a complete wrapper struct with constructors, `Scheme` trait
    /// implementation, and a `fixture` function for testing.
    /// The only required parameter is the `Subject` type, which varies per protocol.
    ///
    /// # Example
    /// ```ignore
    /// impl_certificate_bls12381_multisig!(VoteSubject<'a, D>);
    /// ```
    #[macro_export]
    macro_rules! impl_certificate_bls12381_multisig {
        ($subject:ty) => {
            /// Generates a test fixture with Ed25519 identities and BLS12-381 multisig schemes.
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
                $crate::bls12381::certificate::multisig::mocks::fixture::<_, V, _>(
                    rng,
                    n,
                    Scheme::signer,
                    Scheme::verifier,
                )
            }

            /// BLS12-381 multi-signature signing scheme wrapper.
            #[derive(Clone, Debug)]
            pub struct Scheme<
                P: $crate::PublicKey,
                V: $crate::bls12381::primitives::variant::Variant,
            > {
                generic: $crate::bls12381::certificate::multisig::Generic<P, V>,
            }

            impl<
                P: $crate::PublicKey,
                V: $crate::bls12381::primitives::variant::Variant,
            > Scheme<P, V> {
                /// Creates a new scheme instance with the provided key material.
                pub fn signer(
                    participants: commonware_utils::ordered::BiMap<P, V::Public>,
                    private_key: $crate::bls12381::primitives::group::Private,
                ) -> Option<Self> {
                    Some(Self {
                        generic: $crate::bls12381::certificate::multisig::Generic::signer(
                            participants,
                            private_key,
                        )?,
                    })
                }

                /// Builds a verifier that can authenticate signatures and certificates.
                pub const fn verifier(
                    participants: commonware_utils::ordered::BiMap<P, V::Public>,
                ) -> Self {
                    Self {
                        generic: $crate::bls12381::certificate::multisig::Generic::verifier(
                            participants,
                        ),
                    }
                }
            }

            impl<
                P: $crate::PublicKey,
                V: $crate::bls12381::primitives::variant::Variant + Send + Sync,
            > $crate::certificate::Scheme for Scheme<P, V> {
                type Subject<'a, D: $crate::Digest> = $subject;
                type PublicKey = P;
                type Signature = V::Signature;
                type Certificate = $crate::bls12381::certificate::multisig::Certificate<V>;

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

                fn certificate_codec_config_unbounded() -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    $crate::bls12381::certificate::multisig::Generic::<P, V>::certificate_codec_config_unbounded()
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bls12381::primitives::{
            group::Private,
            ops::compute_public,
            variant::{MinPk, MinSig, Variant},
        },
        certificate::Scheme as _,
        ed25519::{self, PrivateKey as Ed25519PrivateKey},
        impl_certificate_bls12381_multisig,
        sha256::Digest as Sha256Digest,
        Signer as _,
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode};
    use commonware_math::algebra::{Additive, Random};
    use commonware_utils::{ordered::BiMap, quorum, TryCollect};
    use rand::{rngs::StdRng, thread_rng, SeedableRng};

    const NAMESPACE: &[u8] = b"test-bls12381-multisig";
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
    impl_certificate_bls12381_multisig!(TestSubject<'a>);

    fn setup_signers<V: Variant>(
        n: u32,
        seed: u64,
    ) -> (
        Vec<Scheme<ed25519::PublicKey, V>>,
        Scheme<ed25519::PublicKey, V>,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);

        // Generate identity keys (ed25519) and consensus keys (BLS)
        let identity_keys: Vec<_> = (0..n)
            .map(|_| Ed25519PrivateKey::random(&mut rng))
            .collect();
        let consensus_keys: Vec<Private> = (0..n).map(|_| Private::random(&mut rng)).collect();

        // Build BiMap of identity public keys -> consensus public keys
        let participants: BiMap<ed25519::PublicKey, V::Public> = identity_keys
            .iter()
            .zip(consensus_keys.iter())
            .map(|(id_sk, cons_sk)| (id_sk.public_key(), compute_public::<V>(cons_sk)))
            .try_collect()
            .unwrap();

        let signers = consensus_keys
            .into_iter()
            .map(|sk| Scheme::signer(participants.clone(), sk).unwrap())
            .collect();

        let verifier = Scheme::verifier(participants);

        (signers, verifier)
    }

    fn test_sign_vote_roundtrip<V: Variant + Send + Sync>() {
        let (schemes, _) = setup_signers::<V>(4, 42);
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
        let (_, verifier) = setup_signers::<V>(4, 43);
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
        let (schemes, _) = setup_signers::<V>(5, 44);
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
        let (schemes, _) = setup_signers::<V>(4, 46);
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
        assert_eq!(certificate.signers.count(), quorum);
    }

    #[test]
    fn test_assemble_certificate_variants() {
        test_assemble_certificate::<MinPk>();
        test_assemble_certificate::<MinSig>();
    }

    fn test_assemble_certificate_sorts_signers<V: Variant + Send + Sync>() {
        let (schemes, _) = setup_signers::<V>(4, 47);

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
        assert_eq!(
            certificate.signers.iter().collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn test_assemble_certificate_sorts_signers_variants() {
        test_assemble_certificate_sorts_signers::<MinPk>();
        test_assemble_certificate_sorts_signers::<MinSig>();
    }

    fn test_verify_certificate<V: Variant + Send + Sync>() {
        let (schemes, verifier) = setup_signers::<V>(4, 48);
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
        let (schemes, verifier) = setup_signers::<V>(4, 50);
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
        corrupted.signature = V::Signature::zero();
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
        let (schemes, _) = setup_signers::<V>(4, 51);
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
        let decoded =
            Certificate::<V>::decode_cfg(encoded, &schemes.len()).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_codec_roundtrip_variants() {
        test_certificate_codec_roundtrip::<MinPk>();
        test_certificate_codec_roundtrip::<MinSig>();
    }

    fn test_certificate_rejects_sub_quorum<V: Variant + Send + Sync>() {
        let (schemes, _) = setup_signers::<V>(4, 52);
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

    fn test_certificate_rejects_invalid_signer<V: Variant + Send + Sync>() {
        let (schemes, _) = setup_signers::<V>(4, 53);
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
    fn test_certificate_rejects_invalid_signer_variants() {
        test_certificate_rejects_invalid_signer::<MinPk>();
        test_certificate_rejects_invalid_signer::<MinSig>();
    }

    fn test_verify_certificate_rejects_sub_quorum<V: Variant + Send + Sync>() {
        let (schemes, verifier) = setup_signers::<V>(4, 54);
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

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_sub_quorum_variants() {
        test_verify_certificate_rejects_sub_quorum::<MinPk>();
        test_verify_certificate_rejects_sub_quorum::<MinSig>();
    }

    fn test_verify_certificate_rejects_signers_size_mismatch<V: Variant + Send + Sync>() {
        let (schemes, verifier) = setup_signers::<V>(4, 55);
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

        // Make the signers bitmap size larger than participants
        let signers: Vec<u32> = certificate.signers.iter().collect();
        certificate.signers = Signers::from(participants_len + 1, signers);

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_signers_size_mismatch_variants() {
        test_verify_certificate_rejects_signers_size_mismatch::<MinPk>();
        test_verify_certificate_rejects_signers_size_mismatch::<MinSig>();
    }

    fn test_verify_certificates_batch<V: Variant + Send + Sync>() {
        let (schemes, verifier) = setup_signers::<V>(4, 56);
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
        let (schemes, verifier) = setup_signers::<V>(4, 58);
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
        certificates[1].signature = V::Signature::zero();

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

    fn test_scheme_clone_and_verifier<V: Variant + Send + Sync>() {
        let (schemes, verifier) = setup_signers::<V>(4, 60);

        // Clone a signer
        let signer = schemes[0].clone();
        assert!(
            signer
                .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                .is_some(),
            "cloned signer should retain signing capability"
        );

        // A verifier cannot produce votes
        assert!(
            verifier
                .sign::<Sha256Digest>(NAMESPACE, TestSubject { message: MESSAGE })
                .is_none(),
            "verifier must not sign votes"
        );
    }

    #[test]
    fn test_scheme_clone_and_verifier_variants() {
        test_scheme_clone_and_verifier::<MinPk>();
        test_scheme_clone_and_verifier::<MinSig>();
    }

    fn test_certificate_decode_validation<V: Variant + Send + Sync>() {
        let (schemes, _) = setup_signers::<V>(4, 61);
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
            Certificate::<V>::decode_cfg(encoded, &participants_len).expect("decode certificate");
        assert_eq!(decoded, certificate);

        // Certificate with no signers is rejected
        let empty = Certificate::<V> {
            signers: Signers::from(participants_len, std::iter::empty::<u32>()),
            signature: certificate.signature,
        };
        assert!(Certificate::<V>::decode_cfg(empty.encode(), &participants_len).is_err());

        // Certificate containing more signers than the participant set is rejected
        let mut signers = certificate.signers.iter().collect::<Vec<_>>();
        signers.push(participants_len as u32);
        let extended = Certificate::<V> {
            signers: Signers::from(participants_len + 1, signers),
            signature: certificate.signature,
        };
        assert!(Certificate::<V>::decode_cfg(extended.encode(), &participants_len).is_err());
    }

    #[test]
    fn test_certificate_decode_validation_variants() {
        test_certificate_decode_validation::<MinPk>();
        test_certificate_decode_validation::<MinSig>();
    }

    fn test_verify_certificate_rejects_unknown_signer<V: Variant + Send + Sync>() {
        let (schemes, verifier) = setup_signers::<V>(4, 62);
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

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestSubject { message: MESSAGE },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_unknown_signer_variants() {
        test_verify_certificate_rejects_unknown_signer::<MinPk>();
        test_verify_certificate_rejects_unknown_signer::<MinSig>();
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::bls12381::primitives::variant::MinSig;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Certificate<MinSig>>,
        }
    }
}
