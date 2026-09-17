//! BLS12-381 multi-signature signing scheme implementation.
//!
//! This module provides both the generic BLS12-381 multisig implementation and a macro to generate
//! protocol-specific wrappers.
//!
//! # Proof of Possession
//!
//! Before constructing a scheme, callers must verify a proof of possession (PoP) for every BLS
//! public key in the participant map. Without it, aggregate certificate verification is vulnerable
//! to rogue-key attacks. Verify each PoP during participant registration with
//! [`verify_proof_of_possession`](crate::bls12381::primitives::ops::verify_proof_of_possession),
//! then construct schemes only from the validated participant set.

#[cfg(feature = "mocks")]
pub mod mocks;

use crate::{
    Digest, PublicKey,
    bls12381::primitives::{
        group::Private,
        ops::{self, aggregate, batch},
        variant::Variant,
    },
    certificate::{AssemblyError, Attestation, Namespace, Scheme, Signers, Subject, Verification},
};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, vec::Vec};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, Read, ReadExt, Write, types::lazy::Lazy};
use commonware_parallel::Strategy;
use commonware_utils::{
    Participant,
    iter::NonEmpty,
    non_empty,
    ordered::{BiMap, Quorum, Set},
};
use rand_core::CryptoRng;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

/// Generic BLS12-381 multi-signature implementation.
///
/// This struct contains the core cryptographic operations without protocol-specific
/// context types. It can be reused across different protocols (simplex, aggregation, etc.)
/// by wrapping it with protocol-specific trait implementations via the macro.
#[derive(Clone, Debug)]
pub struct Generic<P: PublicKey, V: Variant, N: Namespace> {
    /// Participants' identity keys and BLS signing keys.
    ///
    /// Every signing key must have a verified proof of possession.
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
    ///
    /// # Security
    ///
    /// This function does not verify proofs of possession. The caller must verify a PoP for every
    /// BLS public key in `participants` before constructing the scheme. See the [module-level
    /// documentation](crate::bls12381::certificate::multisig) for details.
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
    ///
    /// # Security
    ///
    /// This function does not verify proofs of possession. The caller must verify a PoP for every
    /// BLS public key in `participants` before constructing the scheme. See the [module-level
    /// documentation](crate::bls12381::certificate::multisig) for details.
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
        R: CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<S>>,
        I::IntoIter: Send,
        T: Strategy,
    {
        let (filtered, failures) =
            strategy.map_partition_collect_vec(attestations.into_iter(), |attestation| {
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
        let mut invalid: BTreeSet<_> = failures.into_iter().collect();
        let (candidates, entries): (Vec<_>, Vec<_>) = filtered.into_iter().unzip();

        // If there are no candidates to verify, return before doing any work.
        if candidates.is_empty() {
            return Verification::new(candidates, invalid.into_iter().collect());
        }

        // Verify attestations and return any invalid ones.
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();
        let entries = non_empty![@entries];
        let invalid_indices = batch::verify_same_message::<_, V, _>(
            rng,
            namespace,
            message.as_ref(),
            entries,
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

    /// Assembles a certificate from a non-empty collection of attestations.
    pub fn assemble<S, I>(&self, attestations: NonEmpty<I>) -> Result<Certificate<V>, AssemblyError>
    where
        S: Scheme<Signature = V::Signature>,
        I: Iterator<Item = Attestation<S>>,
    {
        // Collect the signers and signatures.
        let mut entries = Vec::new();
        for Attestation { signer, signature } in attestations {
            self.participants
                .value(signer.into())
                .ok_or(AssemblyError::UnknownSigner(signer))?;
            let signature = signature
                .get()
                .cloned()
                .ok_or(AssemblyError::MalformedSignature(signer))?;
            entries.push((signer, signature));
        }

        // Produce signers and aggregate signature.
        let (signers, signatures): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::try_from((self.participants.keys(), signers))?
            .require(self.participants.quorum::<S::Faults>())?;
        let signatures = non_empty![@signatures.iter()];
        let signature = aggregate::combine_signatures::<V, _>(signatures);

        Ok(Certificate {
            signers,
            signature: Lazy::from(signature),
        })
    }

    /// Verifies a certificate.
    pub fn verify_certificate<'a, S, R, D>(
        &self,
        _rng: &mut R,
        subject: S::Subject<'a, D>,
        certificate: &Certificate<V>,
    ) -> bool
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRng,
        D: Digest,
    {
        let Some((public, message, signature)) =
            self.prepare_certificate::<S, D>(subject, certificate)
        else {
            return false;
        };
        V::verify(&public, &message, &signature).is_ok()
    }

    /// Checks the signer set and decodes a certificate into a BLS verification equation.
    fn prepare_certificate<'a, S, D>(
        &self,
        subject: S::Subject<'a, D>,
        certificate: &Certificate<V>,
    ) -> Option<(V::Public, V::Signature, V::Signature)>
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        // Require the signer bitmap to match the participant set.
        if certificate.signers.len() != self.participants.len() {
            return None;
        }

        // Require a quorum of signers.
        if certificate.signers.count() < self.participants.quorum::<S::Faults>() as usize {
            return None;
        }

        // Malformed signatures can skip per-signer group operations.
        let signature = certificate.signature.get()?;

        // Aggregate the public keys.
        let mut agg_public = aggregate::PublicKey::<V>::zero();
        for signer in certificate.signers.iter() {
            let public_key = self.participants.value(signer.into())?;
            agg_public.add(public_key);
        }

        let message = ops::hash_with_namespace::<V>(
            V::MESSAGE,
            subject.namespace(&self.namespace),
            &subject.message(),
        );
        Some((*agg_public.inner(), message, *signature.inner()))
    }

    /// Verifies multiple certificates with fresh random weights for each batch.
    /// Singletons use individual verification.
    pub fn verify_certificates<'a, S, R, D, I, T>(
        &self,
        rng: &mut R,
        certificates: NonEmpty<I>,
        strategy: &T,
    ) -> bool
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRng,
        D: Digest,
        I: Iterator<Item = (S::Subject<'a, D>, &'a Certificate<V>)>,
        T: Strategy,
    {
        let (first, rest) = certificates.into_parts();
        let mut rest = rest.peekable();
        if rest.peek().is_none() {
            return self.verify_certificate::<S, _, D>(rng, first.0, first.1);
        }

        let capacity = rest.size_hint().0.saturating_add(1);
        let mut publics = Vec::with_capacity(capacity);
        let mut messages = Vec::with_capacity(capacity);
        let mut signatures = Vec::with_capacity(capacity);
        for (subject, certificate) in NonEmpty::new(first, rest) {
            let Some((public, message, signature)) =
                self.prepare_certificate::<S, D>(subject, certificate)
            else {
                return false;
            };
            publics.push(public);
            messages.push(message);
            signatures.push(signature);
        }

        // Independent random weights prevent invalid certificates from cancelling each other.
        V::batch_verify(rng, &publics, &messages, &signatures, strategy).is_ok()
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
/// - `$namespace`: The namespace type that implements [`Namespace`].
///   This type pre-computes and stores any protocol-specific namespace bytes derived from
///   a base namespace. The scheme calls `$namespace::derive(base)` at construction time
///   to create the namespace, then passes it to `Subject::namespace()` during signing
///   and verification. For simple protocols with only a base namespace, `Vec<u8>` can be used directly.
///   For protocols with multiple message types, a custom struct can pre-compute all variants.
///
/// - `$faults`: The [`Faults`](commonware_utils::Faults) implementation used to compute certificate
///   quorums.
///
/// # Security
///
/// The generated constructors do not verify proofs of possession. Before constructing a scheme,
/// callers must verify a PoP for every BLS public key in the participant map. Otherwise, aggregate
/// certificate verification is vulnerable to rogue-key attacks.
///
/// # Example
/// ```ignore
/// // For non-generic subject types with a single namespace:
/// impl_certificate_bls12381_multisig!(MySubject, Vec<u8>, commonware_utils::N3f1);
///
/// // For protocols with generic subject types:
/// impl_certificate_bls12381_multisig!(
///     Subject<'a, D>,
///     Namespace,
///     commonware_utils::N3f1,
/// );
/// ```
#[macro_export]
macro_rules! impl_certificate_bls12381_multisig {
    ($subject:ty, $namespace:ty, $faults:ty) => {
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
            R: rand_core::CryptoRng,
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
        ///
        /// Every participant BLS public key must have a verified proof of possession before this
        /// scheme is constructed.
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
            ///
            /// # Security
            ///
            /// This function does not verify proofs of possession. The caller must verify a PoP
            /// for every BLS public key in `participants` before constructing the scheme.
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
            ///
            /// # Security
            ///
            /// This function does not verify proofs of possession. The caller must verify a PoP
            /// for every BLS public key in `participants` before constructing the scheme.
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
        > $crate::certificate::Verifier for Scheme<P, V> {
            type Subject<'a, D: $crate::Digest> = $subject;
            type Faults = $faults;
            type PublicKey = P;
            type Certificate = $crate::bls12381::certificate::multisig::Certificate<V>;

            fn verify_certificate<R, D>(
                &self,
                rng: &mut R,
                subject: Self::Subject<'_, D>,
                certificate: &Self::Certificate,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> bool
            where
                R: rand_core::CryptoRng,
                D: $crate::Digest,
            {
                self.generic
                    .verify_certificate::<Self, _, D>(rng, subject, certificate)
            }

            fn verify_certificates<'a, R, D, I>(
                &self,
                rng: &mut R,
                certificates: commonware_utils::iter::NonEmpty<I>,
                strategy: &impl commonware_parallel::Strategy,
            ) -> bool
            where
                R: rand_core::CryptoRng,
                D: $crate::Digest,
                I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
            {
                self.generic
                    .verify_certificates::<Self, _, D, _, _>(rng, certificates, strategy)
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

        impl<
            P: $crate::PublicKey,
            V: $crate::bls12381::primitives::variant::Variant,
        > $crate::certificate::Scheme for Scheme<P, V> {
            type Signature = V::Signature;

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
                R: rand_core::CryptoRng,
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
                R: rand_core::CryptoRng,
                D: $crate::Digest,
                I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                I::IntoIter: Send
            {
                self.generic
                    .verify_attestations::<_, _, D, _, _>(rng, subject, attestations, strategy)
            }

            fn assemble<I>(
                &self,
                attestations: commonware_utils::iter::NonEmpty<I>,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> Result<Self::Certificate, $crate::certificate::AssemblyError>
            where
                I: Iterator<Item = $crate::certificate::Attestation<Self>> + Send,
            {
                self.generic.assemble::<Self, _>(attestations)
            }

            fn is_attributable() -> bool {
                $crate::bls12381::certificate::multisig::Generic::<P, V, $namespace>::is_attributable()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Signer as _,
        bls12381::primitives::{
            group::{Private, Scalar},
            ops::compute_public,
            variant::{MinPk, MinSig, Variant},
        },
        certificate::{Attestation, Scheme as _, Verifier as _},
        ed25519::{self, PrivateKey as Ed25519PrivateKey},
        sha256::Digest as Sha256Digest,
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode};
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{
        Faults, N3f1, NZUsize, Participant, TestRng, TryCollect, ordered::BiMap, test_rng,
    };
    use rand_core::Rng as _;

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
    impl_certificate_bls12381_multisig!(TestSubject, Vec<u8>, N3f1);

    fn setup_signers<V: Variant>(
        rng: &mut impl CryptoRng,
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
        assert!(
            verifier
                .sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE)
                })
                .is_none()
        );
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
            .assemble(non_empty![@attestations], &Sequential)
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
            .assemble(non_empty![@attestations], &Sequential)
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
            .assemble(non_empty![@attestations], &Sequential)
            .unwrap();

        assert!(verifier.verify_certificate::<_, Sha256Digest>(
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
            .assemble(non_empty![@attestations], &Sequential)
            .unwrap();

        // Valid certificate passes
        assert!(verifier.verify_certificate::<_, Sha256Digest>(
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
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
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
            .assemble(non_empty![@attestations], &Sequential)
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
        let expected = N3f1::quorum(schemes.len());
        let found = expected - 1;
        let found_count = usize::try_from(found).expect("quorum exceeds usize::MAX");

        let attestations: Vec<_> = schemes
            .iter()
            .take(found_count)
            .map(|s| {
                s.sign::<Sha256Digest>(TestSubject {
                    message: Bytes::from_static(MESSAGE),
                })
                .unwrap()
            })
            .collect();

        assert_eq!(
            schemes[0].assemble(non_empty![@attestations], &Sequential),
            Err(AssemblyError::InsufficientAttestations(expected, found))
        );
    }

    #[test]
    fn test_certificate_rejects_sub_quorum_variants() {
        test_certificate_rejects_sub_quorum::<MinPk>();
        test_certificate_rejects_sub_quorum::<MinSig>();
    }

    fn test_certificate_rejects_invalid_signer<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);
        let quorum =
            usize::try_from(N3f1::quorum(schemes.len())).expect("quorum exceeds usize::MAX");

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

        assert_eq!(
            schemes[0].assemble(non_empty![@attestations], &Sequential),
            Err(AssemblyError::UnknownSigner(Participant::new(999)))
        );
    }

    #[test]
    fn test_certificate_rejects_invalid_signer_variants() {
        test_certificate_rejects_invalid_signer::<MinPk>();
        test_certificate_rejects_invalid_signer::<MinSig>();
    }

    fn test_certificate_rejects_malformed_signature<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);
        let quorum =
            usize::try_from(N3f1::quorum(schemes.len())).expect("quorum exceeds usize::MAX");

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

        let signer = attestations[0].signer;
        let mut malformed = Bytes::from_static(&[0u8]);
        attestations[0].signature = Lazy::deferred(&mut malformed, ());

        assert_eq!(
            schemes[0].assemble(non_empty![@attestations], &Sequential),
            Err(AssemblyError::MalformedSignature(signer))
        );
    }

    #[test]
    fn test_certificate_rejects_malformed_signature_variants() {
        test_certificate_rejects_malformed_signature::<MinPk>();
        test_certificate_rejects_malformed_signature::<MinSig>();
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
            .assemble(non_empty![@attestations], &Sequential)
            .unwrap();

        // Artificially truncate to below quorum
        let mut signers: Vec<Participant> = certificate.signers.iter().collect();
        signers.pop();
        certificate.signers = Signers::new(participants_len.try_into().unwrap(), signers).unwrap();

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
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
            .assemble(non_empty![@attestations], &Sequential)
            .unwrap();

        // Make the signers bitmap size larger than participants
        let signers: Vec<Participant> = certificate.signers.iter().collect();
        certificate.signers =
            Signers::new((participants_len + 1).try_into().unwrap(), signers).unwrap();

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
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

    fn certificates<V: Variant>(
        schemes: &[Scheme<ed25519::PublicKey, V>],
        messages: &[Bytes],
    ) -> Vec<Certificate<V>> {
        let quorum = N3f1::quorum(schemes.len() as u32) as usize;
        messages
            .iter()
            .enumerate()
            .map(|(i, message)| {
                // Vary both the signer set and its size, including super-quorums.
                let attestations = schemes
                    .iter()
                    .cycle()
                    .skip(i % schemes.len())
                    .take(quorum + i % 2)
                    .map(|s| {
                        s.sign::<Sha256Digest>(TestSubject {
                            message: message.clone(),
                        })
                        .unwrap()
                    });
                schemes[0]
                    .assemble(non_empty![@attestations], &Sequential)
                    .unwrap()
            })
            .collect()
    }

    fn verify_batch<V: Variant>(
        verifier: &Scheme<ed25519::PublicKey, V>,
        rng: &mut impl CryptoRng,
        messages: &[Bytes],
        certificates: &[Certificate<V>],
        strategy: &impl Strategy,
    ) -> bool {
        verifier.verify_certificates::<_, Sha256Digest, _>(
            rng,
            non_empty![@messages.iter().zip(certificates).map(|(message, cert)| {
                (TestSubject { message: message.clone() }, cert)
            })],
            strategy,
        )
    }

    fn test_verify_certificates_batch<V: Variant>(strategy: &impl Strategy) {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        // Repeated messages must work even when the signer sets differ.
        let messages: Vec<_> = (0..33).map(|i| Bytes::from(vec![i / 2])).collect();
        let certificates: Vec<_> = certificates(&schemes, &messages)
            .into_iter()
            .map(|cert| Certificate::decode_cfg(cert.encode(), &schemes.len()).unwrap())
            .collect();

        for n in [1, 2, 8, 33] {
            let mut verify_rng = TestRng::new(1);
            let mut untouched_rng = TestRng::new(1);
            assert!(verify_batch(
                &verifier,
                &mut verify_rng,
                &messages[..n],
                &certificates[..n],
                strategy
            ));
            // Singletons use individual verification; batches must consume fresh randomness.
            assert_eq!(verify_rng.next_u64() == untouched_rng.next_u64(), n == 1);
            assert!(verify_batch(
                &verifier,
                &mut verify_rng,
                &messages[..n],
                &certificates[..n],
                strategy
            ));
        }

        let wrong_namespace = Scheme::verifier(b"wrong namespace", verifier.generic.participants);
        assert!(!verify_batch(
            &wrong_namespace,
            &mut rng,
            &messages,
            &certificates,
            strategy
        ));
    }

    #[test]
    fn test_verify_certificates_batch_variants() {
        let parallel = Rayon::new(NZUsize!(2)).unwrap();
        test_verify_certificates_batch::<MinPk>(&Sequential);
        test_verify_certificates_batch::<MinSig>(&Sequential);
        test_verify_certificates_batch::<MinPk>(&parallel);
        test_verify_certificates_batch::<MinSig>(&parallel);
    }

    fn test_verify_certificates_batch_rejects_invalid<V: Variant>(strategy: &impl Strategy) {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let messages: Vec<_> = (0..3).map(|i| Bytes::from(vec![i])).collect();
        let valid = certificates(&schemes, &messages);

        for index in 0..valid.len() {
            for invalid in 0..6 {
                let mut certificates = valid.clone();
                let certificate = &mut certificates[index];
                match invalid {
                    0 => certificate.signature = valid[(index + 1) % valid.len()].signature.clone(),
                    1 => certificate.signature = Lazy::from(aggregate::Signature::zero()),
                    2 => {
                        certificate.signature = Lazy::deferred(&mut Bytes::from_static(&[0u8]), ())
                    }
                    3 => {
                        certificate.signers =
                            Signers::new(4, [Participant::new(0), Participant::new(1)]).unwrap()
                    }
                    4 => certificate.signers = Signers::new(5, certificate.signers.iter()).unwrap(),
                    5 => certificate.signers = Signers::new(4, core::iter::empty()).unwrap(),
                    _ => unreachable!(),
                }
                assert!(
                    !verify_batch(&verifier, &mut rng, &messages, &certificates, strategy),
                    "index={index} invalid={invalid}"
                );
                // Exercise the singleton fast path with the same invalid certificate.
                assert!(!verify_batch(
                    &verifier,
                    &mut rng,
                    &messages[index..=index],
                    &certificates[index..=index],
                    strategy
                ));
            }
        }
    }

    #[test]
    fn test_verify_certificates_batch_rejects_invalid_variants() {
        let parallel = Rayon::new(NZUsize!(2)).unwrap();
        test_verify_certificates_batch_rejects_invalid::<MinPk>(&Sequential);
        test_verify_certificates_batch_rejects_invalid::<MinSig>(&Sequential);
        test_verify_certificates_batch_rejects_invalid::<MinPk>(&parallel);
        test_verify_certificates_batch_rejects_invalid::<MinSig>(&parallel);
    }

    fn test_verify_certificates_batch_rejects_cancellation<V: Variant>(strategy: &impl Strategy) {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let messages = [Bytes::from_static(b"first"), Bytes::from_static(b"second")];
        let mut certificates = certificates(&schemes, &messages);
        let original_sum = *certificates[0].signature.get().unwrap().inner()
            + certificates[1].signature.get().unwrap().inner();

        // Opposite errors preserve the unweighted signature sum, despite each being invalid.
        let error = V::Signature::generator();
        let mut first = certificates[0].signature.get().unwrap().clone();
        first.add(&error);
        certificates[0].signature = Lazy::from(first);
        let mut second = certificates[1].signature.get().unwrap().clone();
        second.add(&-error);
        certificates[1].signature = Lazy::from(second);
        assert_eq!(
            original_sum,
            *certificates[0].signature.get().unwrap().inner()
                + certificates[1].signature.get().unwrap().inner()
        );

        for (message, certificate) in messages.iter().zip(&certificates) {
            assert!(!verifier.verify_certificate::<_, Sha256Digest>(
                &mut rng,
                TestSubject {
                    message: message.clone()
                },
                certificate,
                strategy,
            ));
        }
        for seed in 0..8 {
            assert!(!verify_batch(
                &verifier,
                &mut TestRng::new(seed),
                &messages,
                &certificates,
                strategy
            ));
        }
    }

    #[test]
    fn test_verify_certificates_batch_rejects_cancellation_variants() {
        let parallel = Rayon::new(NZUsize!(2)).unwrap();
        test_verify_certificates_batch_rejects_cancellation::<MinPk>(&Sequential);
        test_verify_certificates_batch_rejects_cancellation::<MinSig>(&Sequential);
        test_verify_certificates_batch_rejects_cancellation::<MinPk>(&parallel);
        test_verify_certificates_batch_rejects_cancellation::<MinSig>(&parallel);
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
        let duplicate = attestations.last().unwrap().clone();
        let signer = duplicate.signer;
        attestations.push(duplicate);

        assert_eq!(
            schemes[0].assemble(non_empty![@attestations], &Sequential),
            Err(AssemblyError::DuplicateSigner(signer))
        );
    }

    #[test]
    fn test_assemble_certificate_rejects_duplicate_signers_min_pk() {
        test_assemble_certificate_rejects_duplicate_signers::<MinPk>();
    }

    #[test]
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
        let participant_count =
            u32::try_from(participants_len).expect("participant count exceeds u32::MAX");

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
            .assemble(non_empty![@attestations], &Sequential)
            .unwrap();

        // Well-formed certificate decodes successfully
        let encoded = certificate.encode();
        let decoded =
            Certificate::<V>::decode_cfg(encoded, &participants_len).expect("decode certificate");
        assert_eq!(decoded, certificate);

        // Certificate with no signers is rejected
        let empty = Certificate::<V> {
            signers: Signers::new(participant_count, std::iter::empty::<Participant>()).unwrap(),
            signature: certificate.signature.clone(),
        };
        assert!(Certificate::<V>::decode_cfg(empty.encode(), &participants_len).is_err());

        // Certificate containing more signers than the participant set is rejected
        let mut signers = certificate.signers.iter().collect::<Vec<_>>();
        signers.push(Participant::from_usize(participants_len));
        let extended = Certificate::<V> {
            signers: Signers::new(participant_count + 1, signers).unwrap(),
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
            .assemble(non_empty![@attestations], &Sequential)
            .unwrap();

        // Add an unknown signer (out of range)
        let mut signers: Vec<Participant> = certificate.signers.iter().collect();
        signers.push(Participant::from_usize(participants_len));
        certificate.signers =
            Signers::new((participants_len + 1).try_into().unwrap(), signers).unwrap();

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
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
