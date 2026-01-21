//! BLS12-381 multi-signature signing scheme implementation.
//!
//! This module provides both the generic BLS12-381 multisig implementation and a macro to generate
//! protocol-specific wrappers.

#[cfg(feature = "mocks")]
pub mod mocks;

use crate::{
    bls12381::primitives::{
        group::Private,
        ops::{self, aggregate, batch},
        variant::Variant,
    },
    certificate::{Attestation, Namespace, Scheme, Signers, Subject, Verification},
    Digest, PublicKey,
};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{types::lazy::Lazy, EncodeSize, Error, Read, ReadExt, Write};
use commonware_parallel::Strategy;
use commonware_utils::{
    ordered::{BiMap, Quorum, Set},
    Faults, Participant,
};
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

/// Generic BLS12-381 multi-signature implementation.
///
/// This struct contains the core cryptographic operations without protocol-specific
/// context types. It can be reused across different protocols (simplex, aggregation, etc.)
/// by wrapping it with protocol-specific trait implementations via the macro.
#[derive(Clone, Debug)]
pub struct Generic<P: PublicKey, V: Variant, N: Namespace> {
    /// Participants in the committee.
    pub participants: BiMap<P, V::Public>,
    /// Key used for generating signatures.
    pub signer: Option<(Participant, Private)>,
    /// Pre-computed namespace(s) for this subject type.
    pub namespace: N,
}

impl<P: PublicKey, V: Variant, N: Namespace> Generic<P, V, N> {
    /// Creates a new scheme instance with the provided key material.
    ///
    /// Participants have both an identity key and a signing key. The identity key
    /// is used for participant set ordering and indexing, while the signing key is used for
    /// signing and verification.
    ///
    /// Returns `None` if the provided private key does not match any signing key
    /// in the participant set.
    pub fn signer(
        namespace: &[u8],
        participants: BiMap<P, V::Public>,
        private_key: Private,
    ) -> Option<Self> {
        let public_key = ops::compute_public::<V>(&private_key);
        let signer = participants
            .values()
            .iter()
            .position(|p| p == &public_key)
            .map(|index| (Participant::from_usize(index), private_key))?;

        Some(Self {
            participants,
            signer: Some(signer),
            namespace: N::derive(namespace),
        })
    }

    /// Builds a verifier that can authenticate signatures and certificates.
    ///
    /// Participants have both an identity key and a signing key. The identity key
    /// is used for participant set ordering and indexing, while the signing key is used for
    /// verification.
    pub fn verifier(namespace: &[u8], participants: BiMap<P, V::Public>) -> Self {
        Self {
            participants,
            signer: None,
            namespace: N::derive(namespace),
        }
    }

    /// Returns the ordered set of identity keys.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns the index of "self" in the participant set, if available.
    pub fn me(&self) -> Option<Participant> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    /// Signs a subject and returns the attestation.
    pub fn sign<'a, S, D>(&self, subject: S::Subject<'a, D>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = V::Signature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let (index, private_key) = self.signer.as_ref()?;

        let signature = ops::sign_message::<V>(
            private_key,
            subject.namespace(&self.namespace),
            &subject.message(),
        );

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
        S: Scheme<Signature = V::Signature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let Some(public_key) = self.participants.value(attestation.signer.into()) else {
            return false;
        };
        let Some(sig) = attestation.signature.get() else {
            return false;
        };

        ops::verify_message::<V>(
            public_key,
            subject.namespace(&self.namespace),
            &subject.message(),
            sig,
        )
        .is_ok()
    }

    /// Batch-verifies attestations and returns verified attestations and invalid signers.
    pub fn verify_attestations<'a, S, R, D, I, T>(
        &self,
        rng: &mut R,
        subject: S::Subject<'a, D>,
        attestations: I,
        strategy: &T,
    ) -> Verification<S>
    where
        S: Scheme<Signature = V::Signature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        I: IntoIterator<Item = Attestation<S>>,
        I::IntoIter: Send,
        T: Strategy,
    {
        let (filtered, decode_failures) =
            strategy.map_collect_vec_filter(attestations.into_iter(), |attestation| {
                let signer = attestation.signer;
                let value = self
                    .participants
                    .value(signer.into())
                    .and_then(|public_key| {
                        attestation
                            .signature
                            .get()
                            .cloned()
                            .map(|signature| (attestation, (*public_key, signature)))
                    });
                (signer, value)
            });

        let mut invalid: BTreeSet<_> = decode_failures.into_iter().collect();
        let (candidates, entries): (Vec<_>, Vec<_>) = filtered.into_iter().unzip();

        // If there are no candidates to verify, return before doing any work.
        if candidates.is_empty() {
            return Verification::new(candidates, invalid.into_iter().collect());
        }

        // Verify attestations and return any invalid ones.
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();
        let invalid_indices = batch::verify_same_message::<_, V>(
            rng,
            namespace,
            message.as_ref(),
            &entries,
            strategy,
        );

        // Mark invalid attestations.
        for idx in invalid_indices {
            invalid.insert(candidates[idx].signer);
        }

        // Collect the verified attestations.
        let verified = candidates
            .into_iter()
            .filter(|attestation| !invalid.contains(&attestation.signer))
            .collect();

        Verification::new(verified, invalid.into_iter().collect())
    }

    /// Assembles a certificate from a collection of attestations.
    pub fn assemble<S, I, M>(&self, attestations: I) -> Option<Certificate<V>>
    where
        S: Scheme<Signature = V::Signature>,
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

        // Produce signers and aggregate signature.
        let (signers, signatures): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::from(self.participants.len(), signers);
        let signature = aggregate::combine_signatures::<V, _>(signatures.iter());

        Some(Certificate {
            signers,
            signature: Lazy::from(signature),
        })
    }

    /// Verifies a certificate.
    pub fn verify_certificate<'a, S, R, D, M>(
        &self,
        _rng: &mut R,
        subject: S::Subject<'a, D>,
        certificate: &Certificate<V>,
    ) -> bool
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        M: Faults,
    {
        // If the certificate signers length does not match the participant set, return false.
        if certificate.signers.len() != self.participants.len() {
            return false;
        }

        // If the certificate does not meet the quorum, return false.
        if certificate.signers.count() < self.participants.quorum::<M>() as usize {
            return false;
        }

        // Collect the public keys.
        let mut publics = Vec::with_capacity(certificate.signers.count());
        for signer in certificate.signers.iter() {
            let Some(public_key) = self.participants.value(signer.into()) else {
                return false;
            };

            publics.push(*public_key);
        }

        // Verify the aggregate signature.
        let Some(signature) = certificate.signature.get() else {
            return false;
        };
        let agg_public = aggregate::combine_public_keys::<V, _>(&publics);
        aggregate::verify_same_message::<V>(
            &agg_public,
            subject.namespace(&self.namespace),
            &subject.message(),
            signature,
        )
        .is_ok()
    }

    /// Verifies multiple certificates (no batch optimization for BLS multisig).
    pub fn verify_certificates<'a, S, R, D, I, M>(&self, rng: &mut R, certificates: I) -> bool
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        I: Iterator<Item = (S::Subject<'a, D>, &'a Certificate<V>)>,
        M: Faults,
    {
        for (subject, certificate) in certificates {
            if !self.verify_certificate::<S, _, _, M>(rng, subject, certificate) {
                return false;
            }
        }
        true
    }

    pub const fn is_attributable() -> bool {
        true
    }

    pub const fn is_batchable() -> bool {
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
    pub signature: Lazy<aggregate::Signature<V>>,
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

        let signature = Lazy::<aggregate::Signature<V>>::read(reader)?;

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
        let signature = aggregate::Signature::arbitrary(u)?;
        Ok(Self {
            signers,
            signature: Lazy::from(signature),
        })
    }
}

mod macros {
    /// Generates a BLS12-381 multisig signing scheme wrapper for a specific protocol.
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
    /// impl_certificate_bls12381_multisig!(MySubject, Vec<u8>);
    ///
    /// // For protocols with generic subject types:
    /// impl_certificate_bls12381_multisig!(Subject<'a, D>, Namespace);
    /// ```
    #[macro_export]
    macro_rules! impl_certificate_bls12381_multisig {
        ($subject:ty, $namespace:ty) => {
            /// Generates a test fixture with Ed25519 identities and BLS12-381 multisig schemes.
            ///
            /// Returns a [`commonware_cryptography::certificate::mocks::Fixture`] whose keys and
            /// scheme instances share a consistent ordering.
            #[cfg(feature = "mocks")]
            #[allow(dead_code)]
            pub fn fixture<V, R>(
                rng: &mut R,
                namespace: &[u8],
                n: u32,
            ) -> $crate::certificate::mocks::Fixture<Scheme<$crate::ed25519::PublicKey, V>>
            where
                V: $crate::bls12381::primitives::variant::Variant,
                R: rand::RngCore + rand::CryptoRng,
            {
                $crate::bls12381::certificate::multisig::mocks::fixture::<_, V, _>(
                    rng,
                    namespace,
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
                generic: $crate::bls12381::certificate::multisig::Generic<P, V, $namespace>,
            }

            impl<
                P: $crate::PublicKey,
                V: $crate::bls12381::primitives::variant::Variant,
            > Scheme<P, V> {
                /// Creates a new scheme instance with the provided key material.
                pub fn signer(
                    namespace: &[u8],
                    participants: commonware_utils::ordered::BiMap<P, V::Public>,
                    private_key: $crate::bls12381::primitives::group::Private,
                ) -> Option<Self> {
                    Some(Self {
                        generic: $crate::bls12381::certificate::multisig::Generic::signer(
                            namespace,
                            participants,
                            private_key,
                        )?,
                    })
                }

                /// Builds a verifier that can authenticate signatures and certificates.
                pub fn verifier(
                    namespace: &[u8],
                    participants: commonware_utils::ordered::BiMap<P, V::Public>,
                ) -> Self {
                    Self {
                        generic: $crate::bls12381::certificate::multisig::Generic::verifier(
                            namespace,
                            participants,
                        ),
                    }
                }
            }

            impl<
                P: $crate::PublicKey,
                V: $crate::bls12381::primitives::variant::Variant,
            > $crate::certificate::Scheme for Scheme<P, V> {
                type Subject<'a, D: $crate::Digest> = $subject;
                type PublicKey = P;
                type Signature = V::Signature;
                type Certificate = $crate::bls12381::certificate::multisig::Certificate<V>;

                fn me(&self) -> Option<commonware_utils::Participant> {
                    self.generic.me()
                }

                fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
                    self.generic.participants()
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
                    strategy: &impl commonware_parallel::Strategy,
                ) -> $crate::certificate::Verification<Self>
                where
                    R: rand_core::CryptoRngCore,
                    D: $crate::Digest,
                    I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                    I::IntoIter: Send
                {
                    self.generic
                        .verify_attestations::<_, _, D, _, _>(rng, subject, attestations, strategy)
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
                    R: rand_core::CryptoRngCore,
                    D: $crate::Digest,
                    I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
                    M: commonware_utils::Faults,
                {
                    self.generic
                        .verify_certificates::<Self, _, D, _, M>(rng, certificates)
                }

                fn is_attributable() -> bool {
                    $crate::bls12381::certificate::multisig::Generic::<P, V, $namespace>::is_attributable()
                }

                fn is_batchable() -> bool {
                    $crate::bls12381::certificate::multisig::Generic::<P, V, $namespace>::is_batchable()
                }

                fn certificate_codec_config(
                    &self,
                ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    self.generic.certificate_codec_config()
                }

                fn certificate_codec_config_unbounded() -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    $crate::bls12381::certificate::multisig::Generic::<P, V, $namespace>::certificate_codec_config_unbounded()
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
            group::{Private, Scalar},
            ops::compute_public,
            variant::{MinPk, MinSig, Variant},
        },
        certificate::{Attestation, Scheme as _},
        ed25519::{self, PrivateKey as Ed25519PrivateKey},
        impl_certificate_bls12381_multisig,
        sha256::Digest as Sha256Digest,
        Signer as _,
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode};
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_parallel::Sequential;
    use commonware_utils::{ordered::BiMap, test_rng, Faults, N3f1, Participant, TryCollect};

    const NAMESPACE: &[u8] = b"test-bls12381-multisig";
    const MESSAGE: &[u8] = b"test message";

    /// Test context type for generic scheme tests.
    #[derive(Clone, Debug)]
    pub struct TestSubject {
        pub message: Bytes,
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

    // Use the macro to generate the test scheme
    impl_certificate_bls12381_multisig!(TestSubject, Vec<u8>);

    fn setup_signers<V: Variant>(
        rng: &mut impl CryptoRngCore,
        n: u32,
    ) -> (
        Vec<Scheme<ed25519::PublicKey, V>>,
        Scheme<ed25519::PublicKey, V>,
    ) {
        // Generate identity keys (ed25519) and consensus keys (BLS)
        let identity_keys: Vec<_> = (0..n)
            .map(|_| Ed25519PrivateKey::random(&mut *rng))
            .collect();
        let consensus_keys: Vec<Private> = (0..n).map(|_| Private::random(&mut *rng)).collect();

        // Build BiMap of identity public keys -> consensus public keys
        let participants: BiMap<ed25519::PublicKey, V::Public> = identity_keys
            .iter()
            .zip(consensus_keys.iter())
            .map(|(id_sk, cons_sk)| (id_sk.public_key(), compute_public::<V>(cons_sk)))
            .try_collect()
            .unwrap();

        let signers = consensus_keys
            .into_iter()
            .map(|sk| Scheme::signer(NAMESPACE, participants.clone(), sk).unwrap())
            .collect();

        let verifier = Scheme::verifier(NAMESPACE, participants);

        (signers, verifier)
    }

    #[test]
    fn test_is_attributable() {
        assert!(Generic::<ed25519::PublicKey, MinPk, Vec<u8>>::is_attributable());
        assert!(Scheme::<ed25519::PublicKey, MinPk>::is_attributable());
        assert!(Generic::<ed25519::PublicKey, MinSig, Vec<u8>>::is_attributable());
        assert!(Scheme::<ed25519::PublicKey, MinSig>::is_attributable());
    }

    #[test]
    fn test_is_batchable() {
        assert!(Generic::<ed25519::PublicKey, MinPk, Vec<u8>>::is_batchable());
        assert!(Scheme::<ed25519::PublicKey, MinPk>::is_batchable());
        assert!(Generic::<ed25519::PublicKey, MinSig, Vec<u8>>::is_batchable());
        assert!(Scheme::<ed25519::PublicKey, MinSig>::is_batchable());
    }

    fn test_sign_vote_roundtrip<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);
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
    fn test_sign_vote_roundtrip_variants() {
        test_sign_vote_roundtrip::<MinPk>();
        test_sign_vote_roundtrip::<MinSig>();
    }

    fn test_verifier_cannot_sign<V: Variant>() {
        let mut rng = test_rng();
        let (_, verifier) = setup_signers::<V>(&mut rng, 4);
        assert!(verifier
            .sign::<Sha256Digest>(TestSubject {
                message: Bytes::from_static(MESSAGE)
            })
            .is_none());
    }

    #[test]
    fn test_verifier_cannot_sign_variants() {
        test_verifier_cannot_sign::<MinPk>();
        test_verifier_cannot_sign::<MinSig>();
    }

    fn test_verify_attestations_filters_invalid<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 5);
        let quorum = N3f1::quorum(schemes.len() as u32) as usize;

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

        // Test: Corrupt one attestation - invalid signer index
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

        // Test: Corrupt one attestation - invalid signature
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
        assert_eq!(result.invalid.len(), 1);
        assert_eq!(result.verified.len(), quorum - 1);
    }

    #[test]
    fn test_verify_attestations_filters_invalid_variants() {
        test_verify_attestations_filters_invalid::<MinPk>();
        test_verify_attestations_filters_invalid::<MinSig>();
    }

    fn test_assemble_certificate<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len() as u32) as usize;

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
        assert_eq!(certificate.signers.count(), quorum);
    }

    #[test]
    fn test_assemble_certificate_variants() {
        test_assemble_certificate::<MinPk>();
        test_assemble_certificate::<MinSig>();
    }

    fn test_assemble_certificate_sorts_signers<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);

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
    fn test_assemble_certificate_sorts_signers_variants() {
        test_assemble_certificate_sorts_signers::<MinPk>();
        test_assemble_certificate_sorts_signers::<MinSig>();
    }

    fn test_verify_certificate<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len() as u32) as usize;

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
    fn test_verify_certificate_variants() {
        test_verify_certificate::<MinPk>();
        test_verify_certificate::<MinSig>();
    }

    fn test_verify_certificate_detects_corruption<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len() as u32) as usize;

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
        corrupted.signature = Lazy::from(aggregate::Signature::zero());
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
    fn test_verify_certificate_detects_corruption_variants() {
        test_verify_certificate_detects_corruption::<MinPk>();
        test_verify_certificate_detects_corruption::<MinSig>();
    }

    fn test_certificate_codec_roundtrip<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len() as u32) as usize;

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
        let decoded =
            Certificate::<V>::decode_cfg(encoded, &schemes.len()).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_codec_roundtrip_variants() {
        test_certificate_codec_roundtrip::<MinPk>();
        test_certificate_codec_roundtrip::<MinSig>();
    }

    fn test_certificate_rejects_sub_quorum<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);
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
    fn test_certificate_rejects_sub_quorum_variants() {
        test_certificate_rejects_sub_quorum::<MinPk>();
        test_certificate_rejects_sub_quorum::<MinSig>();
    }

    fn test_certificate_rejects_invalid_signer<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len() as u32) as usize;

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
    fn test_certificate_rejects_invalid_signer_variants() {
        test_certificate_rejects_invalid_signer::<MinPk>();
        test_certificate_rejects_invalid_signer::<MinSig>();
    }

    fn test_verify_certificate_rejects_sub_quorum<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
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
    fn test_verify_certificate_rejects_sub_quorum_variants() {
        test_verify_certificate_rejects_sub_quorum::<MinPk>();
        test_verify_certificate_rejects_sub_quorum::<MinSig>();
    }

    fn test_verify_certificate_rejects_signers_size_mismatch<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
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
    fn test_verify_certificate_rejects_signers_size_mismatch_variants() {
        test_verify_certificate_rejects_signers_size_mismatch::<MinPk>();
        test_verify_certificate_rejects_signers_size_mismatch::<MinSig>();
    }

    fn test_verify_certificates_batch<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len() as u32) as usize;

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
    fn test_verify_certificates_batch_variants() {
        test_verify_certificates_batch::<MinPk>();
        test_verify_certificates_batch::<MinSig>();
    }

    fn test_verify_certificates_batch_detects_failure<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len() as u32) as usize;

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
        certificates[1].signature = Lazy::from(aggregate::Signature::zero());

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
    fn test_verify_certificates_batch_detects_failure_variants() {
        test_verify_certificates_batch_detects_failure::<MinPk>();
        test_verify_certificates_batch_detects_failure::<MinSig>();
    }

    fn test_assemble_certificate_rejects_duplicate_signers<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);

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

        // Add a duplicate of the last attestation
        attestations.push(attestations.last().unwrap().clone());

        // This should panic due to duplicate signer
        schemes[0].assemble::<_, N3f1>(attestations, &Sequential);
    }

    #[test]
    #[should_panic(expected = "duplicate signer")]
    fn test_assemble_certificate_rejects_duplicate_signers_min_pk() {
        test_assemble_certificate_rejects_duplicate_signers::<MinPk>();
    }

    #[test]
    #[should_panic(expected = "duplicate signer")]
    fn test_assemble_certificate_rejects_duplicate_signers_min_sig() {
        test_assemble_certificate_rejects_duplicate_signers::<MinSig>();
    }

    fn test_scheme_clone_and_verifier<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);

        // Clone a signer
        let signer = schemes[0].clone();
        assert!(
            signer
                .sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE)
                })
                .is_some(),
            "cloned signer should retain signing capability"
        );

        // A verifier cannot produce votes
        assert!(
            verifier
                .sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE)
                })
                .is_none(),
            "verifier must not sign votes"
        );
    }

    #[test]
    fn test_scheme_clone_and_verifier_variants() {
        test_scheme_clone_and_verifier::<MinPk>();
        test_scheme_clone_and_verifier::<MinSig>();
    }

    fn test_certificate_decode_validation<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);
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
            Certificate::<V>::decode_cfg(encoded, &participants_len).expect("decode certificate");
        assert_eq!(decoded, certificate);

        // Certificate with no signers is rejected
        let empty = Certificate::<V> {
            signers: Signers::from(participants_len, std::iter::empty::<Participant>()),
            signature: certificate.signature.clone(),
        };
        assert!(Certificate::<V>::decode_cfg(empty.encode(), &participants_len).is_err());

        // Certificate containing more signers than the participant set is rejected
        let mut signers = certificate.signers.iter().collect::<Vec<_>>();
        signers.push(Participant::from_usize(participants_len));
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

    fn test_verify_certificate_rejects_unknown_signer<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
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
    fn test_verify_certificate_rejects_unknown_signer_variants() {
        test_verify_certificate_rejects_unknown_signer::<MinPk>();
        test_verify_certificate_rejects_unknown_signer::<MinSig>();
    }

    fn test_verify_attestations_rejects_malleability<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);

        let attestation1 = schemes[0]
            .sign::<Sha256Digest>(TestSubject {
                message: Bytes::from_static(MESSAGE),
            })
            .unwrap();
        let attestation2 = schemes[1]
            .sign::<Sha256Digest>(TestSubject {
                message: Bytes::from_static(MESSAGE),
            })
            .unwrap();

        let verification = schemes[0].verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            vec![attestation1.clone(), attestation2.clone()],
            &Sequential,
        );
        assert!(verification.invalid.is_empty());
        assert_eq!(verification.verified.len(), 2);

        let random_scalar = Scalar::random(&mut rng);
        let delta = V::Signature::generator() * &random_scalar;
        let forged_attestation1: Attestation<Scheme<ed25519::PublicKey, V>> = Attestation {
            signer: attestation1.signer,
            signature: (*attestation1.signature.get().unwrap() - &delta).into(),
        };
        let forged_attestation2: Attestation<Scheme<ed25519::PublicKey, V>> = Attestation {
            signer: attestation2.signer,
            signature: (*attestation2.signature.get().unwrap() + &delta).into(),
        };

        let forged_sum = *forged_attestation1.signature.get().unwrap()
            + forged_attestation2.signature.get().unwrap();
        let valid_sum =
            *attestation1.signature.get().unwrap() + attestation2.signature.get().unwrap();
        assert_eq!(forged_sum, valid_sum, "signature sums should be equal");

        let verification = schemes[0].verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            vec![forged_attestation1, forged_attestation2],
            &Sequential,
        );
        assert!(
            !verification.invalid.is_empty(),
            "forged attestations should be detected"
        );
    }

    #[test]
    fn test_verify_attestations_rejects_malleability_variants() {
        test_verify_attestations_rejects_malleability::<MinPk>();
        test_verify_attestations_rejects_malleability::<MinSig>();
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
