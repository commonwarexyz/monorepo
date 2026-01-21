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
        ops::{self, batch, threshold},
        sharing::Sharing,
        variant::{PartialSignature, Variant},
    },
    certificate::{Attestation, Namespace, Scheme, Subject, Verification},
    Digest, PublicKey,
};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{types::lazy::Lazy, Error, FixedSize, Read, ReadExt, Write};
use commonware_parallel::Strategy;
use commonware_utils::{ordered::Set, Faults, Participant};
use core::fmt::Debug;
use rand_core::CryptoRngCore;
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
pub enum Generic<P: PublicKey, V: Variant, N: Namespace> {
    Signer {
        /// Participants in the committee.
        participants: Set<P>,
        /// The public polynomial, used for the group identity, and partial signatures.
        polynomial: Sharing<V>,
        /// Local share used to generate partial signatures.
        share: Share,
        /// Pre-computed namespace(s) for this subject type.
        namespace: N,
    },
    Verifier {
        /// Participants in the committee.
        participants: Set<P>,
        /// The public polynomial, used for the group identity, and partial signatures.
        polynomial: Sharing<V>,
        /// Pre-computed namespace(s) for this subject type.
        namespace: N,
    },
    CertificateVerifier {
        /// Public identity of the committee (constant across reshares).
        identity: V::Public,
        /// Pre-computed namespace(s) for this subject type.
        namespace: N,
    },
}

impl<P: PublicKey, V: Variant, N: Namespace> Generic<P, V, N> {
    /// Constructs a signer instance with a private share and evaluated public polynomial.
    ///
    /// The participant identity keys are used for committee ordering and indexing.
    /// The polynomial can be evaluated to obtain public verification keys for partial
    /// signatures produced by committee members.
    ///
    /// Returns `None` if the share's public key does not match any participant.
    ///
    /// * `namespace` - base namespace for domain separation
    /// * `participants` - ordered set of participant identity keys
    /// * `polynomial` - public polynomial for threshold verification
    /// * `share` - local threshold share for signing
    pub fn signer(
        namespace: &[u8],
        participants: Set<P>,
        polynomial: Sharing<V>,
        share: Share,
    ) -> Option<Self> {
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
                namespace: N::derive(namespace),
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
    /// * `namespace` - base namespace for domain separation
    /// * `participants` - ordered set of participant identity keys
    /// * `polynomial` - public polynomial for threshold verification
    pub fn verifier(namespace: &[u8], participants: Set<P>, polynomial: Sharing<V>) -> Self {
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
            namespace: N::derive(namespace),
        }
    }

    /// Creates a verifier that only checks recovered certificates.
    ///
    /// This lightweight verifier can authenticate recovered threshold certificates but cannot
    /// verify individual signatures or partial signatures.
    ///
    /// * `namespace` - base namespace for domain separation
    /// * `identity` - public identity of the committee (constant across reshares)
    pub fn certificate_verifier(namespace: &[u8], identity: V::Public) -> Self {
        Self::CertificateVerifier {
            identity,
            namespace: N::derive(namespace),
        }
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

    /// Returns the pre-computed namespace.
    const fn namespace(&self) -> &N {
        match self {
            Self::Signer { namespace, .. } => namespace,
            Self::Verifier { namespace, .. } => namespace,
            Self::CertificateVerifier { namespace, .. } => namespace,
        }
    }

    /// Returns the index of "self" in the participant set, if available.
    pub const fn me(&self) -> Option<Participant> {
        match self {
            Self::Signer { share, .. } => Some(share.index),
            _ => None,
        }
    }

    /// Signs a subject and returns the attestation.
    pub fn sign<'a, S, D>(&self, subject: S::Subject<'a, D>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = V::Signature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let share = self.share()?;

        let signature = threshold::sign_message::<V>(
            share,
            subject.namespace(self.namespace()),
            &subject.message(),
        )
        .value;

        Some(Attestation {
            signer: share.index,
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
        let Ok(evaluated) = self.polynomial().partial_public(attestation.signer) else {
            return false;
        };
        let Some(signature) = attestation.signature.get() else {
            return false;
        };

        ops::verify_message::<V>(
            &evaluated,
            subject.namespace(self.namespace()),
            &subject.message(),
            signature,
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
        let mut invalid = BTreeSet::new();
        let partials = strategy.map_collect_vec(attestations.into_iter(), |attestation| {
            let index = attestation.signer;
            let partial = attestation
                .signature
                .get()
                .map(|&value| PartialSignature::<V> { index, value });
            (index, partial)
        });
        let partials: Vec<_> = partials
            .into_iter()
            .filter_map(|(index, partial)| {
                if partial.is_none() {
                    invalid.insert(index);
                }
                partial
            })
            .collect();
        let polynomial = self.polynomial();
        if let Err(errs) = threshold::batch_verify_same_message::<_, V, _>(
            rng,
            polynomial,
            subject.namespace(self.namespace()),
            &subject.message(),
            partials.iter(),
            strategy,
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
                signature: partial.value.into(),
            })
            .collect();

        Verification::new(verified, invalid.into_iter().collect())
    }

    /// Assembles a certificate from a collection of attestations.
    pub fn assemble<S, I, T, M>(&self, attestations: I, strategy: &T) -> Option<Certificate<V>>
    where
        S: Scheme<Signature = V::Signature>,
        I: IntoIterator<Item = Attestation<S>>,
        I::IntoIter: Send,
        T: Strategy,
        M: Faults,
    {
        let partials = strategy.map_collect_vec(attestations.into_iter(), |attestation| {
            attestation
                .signature
                .get()
                .map(|&value| PartialSignature::<V> {
                    index: attestation.signer,
                    value,
                })
        });
        let partials: Vec<_> = partials.into_iter().collect::<Option<_>>()?;

        let quorum = self.polynomial();
        if partials.len() < quorum.required::<M>() as usize {
            return None;
        }

        threshold::recover::<V, _, M>(quorum, partials.iter(), strategy)
            .ok()
            .map(Certificate::new)
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
        let Some(signature) = certificate.get() else {
            return false;
        };
        ops::verify_message::<V>(
            self.identity(),
            subject.namespace(self.namespace()),
            &subject.message(),
            signature,
        )
        .is_ok()
    }

    /// Verifies multiple certificates in a batch.
    pub fn verify_certificates<'a, S, R, D, I, T, M>(
        &self,
        rng: &mut R,
        certificates: I,
        strategy: &T,
    ) -> bool
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        I: Iterator<Item = (S::Subject<'a, D>, &'a Certificate<V>)>,
        T: Strategy,
        M: Faults,
    {
        let mut entries: Vec<_> = Vec::new();

        for (subject, certificate) in certificates {
            let Some(signature) = certificate.get() else {
                return false;
            };
            let namespace = subject.namespace(self.namespace());
            let message = subject.message();
            entries.push((namespace.to_vec(), message.to_vec(), *signature));
        }

        if entries.is_empty() {
            return true;
        }

        let entries_refs: Vec<_> = entries
            .iter()
            .map(|(ns, msg, sig)| (ns.as_ref(), msg.as_ref(), *sig))
            .collect();

        batch::verify_same_signer::<_, V, _>(rng, self.identity(), &entries_refs, strategy).is_ok()
    }

    pub const fn is_attributable() -> bool {
        false
    }

    pub const fn is_batchable() -> bool {
        true
    }

    pub const fn certificate_codec_config(&self) {}

    pub const fn certificate_codec_config_unbounded() {}
}

/// Certificate for BLS12-381 threshold signatures.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<V: Variant> {
    /// The recovered threshold signature.
    pub signature: Lazy<V::Signature>,
}

impl<V: Variant> Certificate<V> {
    /// Creates a new certificate from a recovered signature.
    pub fn new(signature: V::Signature) -> Self {
        Self {
            signature: Lazy::from(signature),
        }
    }

    /// Attempts to get the decoded signature.
    ///
    /// Returns `None` if the signature fails to decode.
    pub fn get(&self) -> Option<&V::Signature> {
        self.signature.get()
    }
}

impl<V: Variant> Write for Certificate<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signature.write(writer);
    }
}

impl<V: Variant> Read for Certificate<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let signature = Lazy::<V::Signature>::read(reader)?;
        Ok(Self { signature })
    }
}

impl<V: Variant> FixedSize for Certificate<V> {
    const SIZE: usize = V::Signature::SIZE;
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for Certificate<V>
where
    V::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            signature: Lazy::from(u.arbitrary::<V::Signature>()?),
        })
    }
}

mod macros {
    /// Generates a BLS12-381 threshold signing scheme wrapper for a specific protocol.
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
    /// impl_certificate_bls12381_threshold!(MySubject, Vec<u8>);
    ///
    /// // For protocols with generic subject types:
    /// impl_certificate_bls12381_threshold!(Subject<'a, D>, Namespace);
    /// ```
    #[macro_export]
    macro_rules! impl_certificate_bls12381_threshold {
        ($subject:ty, $namespace:ty) => {
            /// Generates a test fixture with Ed25519 identities and BLS12-381 threshold schemes.
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
                $crate::bls12381::certificate::threshold::mocks::fixture::<_, V, _>(
                    rng,
                    namespace,
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
                generic: $crate::bls12381::certificate::threshold::Generic<P, V, $namespace>,
            }

            impl<
                P: $crate::PublicKey,
                V: $crate::bls12381::primitives::variant::Variant,
            > Scheme<P, V> {
                /// Creates a new signer instance with a private share and evaluated public polynomial.
                pub fn signer(
                    namespace: &[u8],
                    participants: commonware_utils::ordered::Set<P>,
                    polynomial: $crate::bls12381::primitives::sharing::Sharing<V>,
                    share: $crate::bls12381::primitives::group::Share,
                ) -> Option<Self> {
                    Some(Self {
                        generic: $crate::bls12381::certificate::threshold::Generic::signer(
                            namespace,
                            participants,
                            polynomial,
                            share,
                        )?,
                    })
                }

                /// Creates a verifier that can authenticate partial signatures.
                pub fn verifier(
                    namespace: &[u8],
                    participants: commonware_utils::ordered::Set<P>,
                    polynomial: $crate::bls12381::primitives::sharing::Sharing<V>,
                ) -> Self {
                    Self {
                        generic: $crate::bls12381::certificate::threshold::Generic::verifier(
                            namespace,
                            participants,
                            polynomial,
                        ),
                    }
                }

                /// Creates a lightweight verifier that only checks recovered certificates.
                pub fn certificate_verifier(namespace: &[u8], identity: V::Public) -> Self {
                    Self {
                        generic: $crate::bls12381::certificate::threshold::Generic::certificate_verifier(
                            namespace,
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
                V: $crate::bls12381::primitives::variant::Variant,
            > $crate::certificate::Scheme for Scheme<P, V> {
                type Subject<'a, D: $crate::Digest> = $subject;
                type PublicKey = P;
                type Signature = V::Signature;
                type Certificate = $crate::bls12381::certificate::threshold::Certificate<V>;

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
                    strategy: &impl commonware_parallel::Strategy,
                ) -> Option<Self::Certificate>
                where
                    I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                    I::IntoIter: Send,
                    M: commonware_utils::Faults,
                {
                    self.generic.assemble::<Self, _, _, M>(attestations, strategy)
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
                    strategy: &impl commonware_parallel::Strategy,
                ) -> bool
                where
                    R: rand_core::CryptoRngCore,
                    D: $crate::Digest,
                    I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
                    M: commonware_utils::Faults,
                {
                    self.generic
                        .verify_certificates::<Self, _, D, _, _, M>(rng, certificates, strategy)
                }

                fn is_attributable() -> bool {
                    $crate::bls12381::certificate::threshold::Generic::<P, V, $namespace>::is_attributable()
                }

                fn is_batchable() -> bool {
                    $crate::bls12381::certificate::threshold::Generic::<P, V, $namespace>::is_batchable()
                }

                fn certificate_codec_config(
                    &self,
                ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    self.generic.certificate_codec_config()
                }

                fn certificate_codec_config_unbounded(
                ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    $crate::bls12381::certificate::threshold::Generic::<P, V, $namespace>::certificate_codec_config_unbounded()
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
                ops::threshold::sign_message,
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
    use commonware_parallel::Sequential;
    use commonware_utils::{ordered::Set, test_rng, Faults, N3f1, TryCollect, NZU32};

    const NAMESPACE: &[u8] = b"test-bls12381-threshold";
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
    impl_certificate_bls12381_threshold!(TestSubject, Vec<u8>);

    #[allow(clippy::type_complexity)]
    fn setup_signers<V: Variant>(
        rng: &mut impl CryptoRngCore,
        n: u32,
    ) -> (
        Vec<Scheme<ed25519::PublicKey, V>>,
        Scheme<ed25519::PublicKey, V>,
        Sharing<V>,
    ) {
        // Generate identity keys (ed25519)
        let identity_keys: Vec<_> = (0..n)
            .map(|_| Ed25519PrivateKey::random(&mut *rng))
            .collect();
        let participants: Set<ed25519::PublicKey> = identity_keys
            .iter()
            .map(|sk| sk.public_key())
            .try_collect()
            .unwrap();

        // Generate threshold polynomial and shares using DKG
        let (polynomial, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut *rng, Default::default(), NZU32!(n));

        let signers = shares
            .into_iter()
            .map(|share| {
                Scheme::signer(NAMESPACE, participants.clone(), polynomial.clone(), share).unwrap()
            })
            .collect();

        let verifier = Scheme::verifier(NAMESPACE, participants, polynomial.clone());

        (signers, verifier, polynomial)
    }

    fn test_sign_vote_roundtrip<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _, _) = setup_signers::<V>(&mut rng, 4);
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
        let (_, verifier, _) = setup_signers::<V>(&mut rng, 4);
        assert!(verifier
            .sign::<Sha256Digest>(TestSubject {
                message: Bytes::from_static(MESSAGE),
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
        let (schemes, _, _) = setup_signers::<V>(&mut rng, 5);
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
        let (schemes, verifier, _) = setup_signers::<V>(&mut rng, 4);
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

        // Verify the assembled certificate
        assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &certificate,
            &Sequential,
        ));
    }

    #[test]
    fn test_assemble_certificate_variants() {
        test_assemble_certificate::<MinPk>();
        test_assemble_certificate::<MinSig>();
    }

    fn test_verify_certificate<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier, _) = setup_signers::<V>(&mut rng, 4);
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
                message: Bytes::from_static(MESSAGE),
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
        let (schemes, verifier, _) = setup_signers::<V>(&mut rng, 4);
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
        let corrupted = Certificate::new(V::Signature::zero());
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
        let (schemes, _, _) = setup_signers::<V>(&mut rng, 4);
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
        let decoded = Certificate::<V>::decode(encoded).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_codec_roundtrip_variants() {
        test_certificate_codec_roundtrip::<MinPk>();
        test_certificate_codec_roundtrip::<MinSig>();
    }

    fn test_certificate_rejects_sub_quorum<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _, _) = setup_signers::<V>(&mut rng, 4);
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

    fn test_verify_certificates_batch<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier, _) = setup_signers::<V>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len() as u32) as usize;

        let messages: [Bytes; 3] = [
            Bytes::from_static(b"msg1"),
            Bytes::from_static(b"msg2"),
            Bytes::from_static(b"msg3"),
        ];
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
        let (schemes, verifier, _) = setup_signers::<V>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len() as u32) as usize;

        let messages: [Bytes; 2] = [Bytes::from_static(b"msg1"), Bytes::from_static(b"msg2")];
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
        certificates[1] = Certificate::new(V::Signature::zero());

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

    fn test_certificate_verifier<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _, polynomial) = setup_signers::<V>(&mut rng, 4);
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

        // Create a certificate-only verifier using the identity from the polynomial
        let identity = polynomial.public();
        let cert_verifier =
            Scheme::<ed25519::PublicKey, V>::certificate_verifier(NAMESPACE, *identity);

        // Should be able to verify certificates
        assert!(cert_verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &certificate,
            &Sequential,
        ));

        // Should not be able to sign
        assert!(cert_verifier
            .sign::<Sha256Digest>(TestSubject {
                message: Bytes::from_static(MESSAGE),
            })
            .is_none());
    }

    #[test]
    fn test_certificate_verifier_variants() {
        test_certificate_verifier::<MinPk>();
        test_certificate_verifier::<MinSig>();
    }

    #[test]
    fn test_is_not_attributable() {
        assert!(!Generic::<ed25519::PublicKey, MinPk, Vec<u8>>::is_attributable());
        assert!(!Scheme::<ed25519::PublicKey, MinPk>::is_attributable());
        assert!(!Generic::<ed25519::PublicKey, MinSig, Vec<u8>>::is_attributable());
        assert!(!Scheme::<ed25519::PublicKey, MinSig>::is_attributable());
    }

    #[test]
    fn test_is_batchable() {
        assert!(Generic::<ed25519::PublicKey, MinPk, Vec<u8>>::is_batchable());
        assert!(Scheme::<ed25519::PublicKey, MinPk>::is_batchable());
        assert!(Generic::<ed25519::PublicKey, MinSig, Vec<u8>>::is_batchable());
        assert!(Scheme::<ed25519::PublicKey, MinSig>::is_batchable());
    }

    fn test_verifier_accepts_votes<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier, _) = setup_signers::<V>(&mut rng, 4);

        let vote = schemes[1]
            .sign::<Sha256Digest>(TestSubject {
                message: Bytes::from_static(MESSAGE),
            })
            .unwrap();
        assert!(verifier.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &vote,
            &Sequential,
        ));
    }

    #[test]
    fn test_verifier_accepts_votes_variants() {
        test_verifier_accepts_votes::<MinPk>();
        test_verifier_accepts_votes::<MinSig>();
    }

    fn test_scheme_clone_and_verifier<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier, _) = setup_signers::<V>(&mut rng, 4);

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
    fn test_scheme_clone_and_verifier_variants() {
        test_scheme_clone_and_verifier::<MinPk>();
        test_scheme_clone_and_verifier::<MinSig>();
    }

    fn certificate_verifier_panics_on_vote<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _, _) = setup_signers::<V>(&mut rng, 4);
        let certificate_verifier = Scheme::<ed25519::PublicKey, V>::certificate_verifier(
            NAMESPACE,
            *schemes[0].identity(),
        );

        let vote = schemes[1]
            .sign::<Sha256Digest>(TestSubject {
                message: Bytes::from_static(MESSAGE),
            })
            .unwrap();

        // CertificateVerifier should panic when trying to verify a vote
        certificate_verifier.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &vote,
            &Sequential,
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

    fn signer_shares_must_match_participant_indices<V: Variant>() {
        let mut rng = test_rng();

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
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(4));
        shares[0].index = Participant::new(999);
        Scheme::<ed25519::PublicKey, V>::signer(
            NAMESPACE,
            participants,
            polynomial,
            shares[0].clone(),
        );
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
        let mut rng = test_rng();
        let participants = make_participants(&mut rng, 5);
        // Create a polynomial with threshold 4, but quorum of 5 participants is 4
        // so this should succeed. Let's use threshold 2 to make it fail.
        // quorum(5) = 4, but polynomial.required() = 2, so this should panic
        let (polynomial, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(2));
        Scheme::<ed25519::PublicKey, V>::signer(
            NAMESPACE,
            participants,
            polynomial,
            shares[0].clone(),
        );
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
        let mut rng = test_rng();
        let participants = make_participants(&mut rng, 5);
        // Create a polynomial with threshold 2, but quorum of 5 participants is 4
        // quorum(5) = 4, but polynomial.required() = 2, so this should panic
        let (polynomial, _) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(2));
        Scheme::<ed25519::PublicKey, V>::verifier(NAMESPACE, participants, polynomial);
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

    fn certificate_decode_rejects_length_mismatch<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _, _) = setup_signers::<V>(&mut rng, 4);
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
        let mut encoded = certificate.encode();
        encoded.truncate(encoded.len() - 1);
        assert!(V::Signature::decode(encoded).is_err());
    }

    #[test]
    fn test_certificate_decode_rejects_length_mismatch_variants() {
        certificate_decode_rejects_length_mismatch::<MinPk>();
        certificate_decode_rejects_length_mismatch::<MinSig>();
    }

    fn sign_vote_partial_matches_share<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _, _) = setup_signers::<V>(&mut rng, 4);
        let scheme = &schemes[0];

        let signature = scheme
            .sign::<Sha256Digest>(TestSubject {
                message: Bytes::from_static(MESSAGE),
            })
            .unwrap();

        // Verify the partial signature matches what we'd get from direct signing
        let share = scheme.share().expect("expected signer");

        let expected = sign_message::<V>(share, NAMESPACE, MESSAGE);

        assert_eq!(signature.signer, share.index);
        assert_eq!(signature.signature.get().unwrap(), &expected.value);
    }

    #[test]
    fn test_sign_vote_partial_matches_share_variants() {
        sign_vote_partial_matches_share::<MinPk>();
        sign_vote_partial_matches_share::<MinSig>();
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Certificate<MinSig>>,
        }
    }
}
