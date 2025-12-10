//! BLS12-381 threshold signature scheme implementation.
//!
//! This module provides both the raw BLS12-381 threshold implementation and a macro to generate
//! protocol-specific wrappers.
//!
//! Unlike multi-signature schemes, threshold signatures:
//! - Use partial signatures that can be combined to form a threshold signature
//! - Require a quorum of signatures to recover the full signature
//! - Are **non-attributable**: partial signatures can be forged by holders of enough other partials

use crate::signing_scheme::{Context, Scheme, Signature, SignatureVerification};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        ops::{
            aggregate_signatures, aggregate_verify_multiple_messages, partial_sign_message,
            partial_verify_multiple_public_keys_precomputed, threshold_signature_recover,
            verify_message,
        },
        poly::{self, PartialSignature, Public},
        variant::Variant,
    },
    Digest, PublicKey,
};
use commonware_utils::{
    ordered::{BiMap, Quorum, Set},
    TryCollect,
};
use rand::{CryptoRng, Rng};
use std::collections::BTreeSet;

/// BLS12-381 threshold implementation of the [`Scheme`] trait.
///
/// It is possible for a node to play one of the following roles: a signer (with its share),
/// a verifier (with evaluated public polynomial), or an external verifier that
/// only checks recovered certificates.
#[derive(Clone, Debug)]
pub enum Bls12381Threshold<P: PublicKey, V: Variant> {
    Signer {
        /// Participants in the committee.
        participants: BiMap<P, V::Public>,
        /// Public identity of the committee (constant across reshares).
        identity: V::Public,
        /// Local share used to generate partial signatures.
        share: Share,
    },
    Verifier {
        /// Participants in the committee.
        participants: BiMap<P, V::Public>,
        /// Public identity of the committee (constant across reshares).
        identity: V::Public,
    },
    CertificateVerifier {
        /// Public identity of the committee (constant across reshares).
        identity: V::Public,
    },
}

impl<P: PublicKey, V: Variant> Bls12381Threshold<P, V> {
    /// Constructs a signer instance with a private share and evaluated public polynomial.
    ///
    /// The participant identity keys are used for committee ordering and indexing.
    /// The polynomial can be evaluated to obtain public verification keys for partial
    /// signatures produced by committee members.
    ///
    /// If the provided share does not match the polynomial evaluation at its index,
    /// the instance will act as a verifier (unable to sign votes).
    ///
    /// * `participants` - ordered set of participant identity keys
    /// * `polynomial` - public polynomial for threshold verification
    /// * `share` - local threshold share for signing
    pub fn new(participants: Set<P>, polynomial: &Public<V>, share: Share) -> Self {
        let identity = *poly::public::<V>(polynomial);
        let polynomial = polynomial.evaluate_all(participants.len() as u32);
        let participants = participants
            .into_iter()
            .zip(polynomial)
            .try_collect::<BiMap<_, _>>()
            .expect("participants are unique");

        let public_key = share.public::<V>();
        if let Some(index) = participants.values().iter().position(|p| p == &public_key) {
            assert_eq!(
                index as u32, share.index,
                "share index must match participant index"
            );
            Self::Signer {
                participants,
                identity,
                share,
            }
        } else {
            Self::Verifier {
                participants,
                identity,
            }
        }
    }

    /// Produces a verifier that can authenticate votes but does not hold signing state.
    ///
    /// The participant identity keys are used for committee ordering and indexing.
    /// The polynomial can be evaluated to obtain public verification keys for partial
    /// signatures produced by committee members.
    ///
    /// * `participants` - ordered set of participant identity keys
    /// * `polynomial` - public polynomial for threshold verification
    pub fn verifier(participants: Set<P>, polynomial: &Public<V>) -> Self {
        let identity = *poly::public::<V>(polynomial);
        let polynomial = polynomial.evaluate_all(participants.len() as u32);
        let participants = participants
            .into_iter()
            .zip(polynomial)
            .try_collect::<BiMap<_, _>>()
            .expect("participants are unique");

        Self::Verifier {
            participants,
            identity,
        }
    }

    /// Creates a verifier that only checks recovered certificates.
    ///
    /// This lightweight verifier can authenticate recovered threshold certificates but cannot
    /// verify individual votes or partial signatures.
    ///
    /// * `identity` - public identity of the committee (constant across reshares)
    pub const fn certificate_verifier(identity: V::Public) -> Self {
        Self::CertificateVerifier { identity }
    }

    /// Returns the ordered set of participant public identity keys in the committee.
    pub fn participants(&self) -> &Set<P> {
        match self {
            Self::Signer { participants, .. } => participants.keys(),
            Self::Verifier { participants, .. } => participants.keys(),
            _ => panic!("can only be called for signer and verifier"),
        }
    }

    /// Returns the public identity of the committee (constant across reshares).
    pub const fn identity(&self) -> &V::Public {
        match self {
            Self::Signer { identity, .. } => identity,
            Self::Verifier { identity, .. } => identity,
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
    fn polynomial(&self) -> &[V::Public] {
        match self {
            Self::Signer { participants, .. } => participants.values(),
            Self::Verifier { participants, .. } => participants.values(),
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

    /// Signs a vote and returns it.
    pub fn sign_vote<S, D>(
        &self,
        namespace: &[u8],
        context: S::Context<'_, D>,
    ) -> Option<Signature<S>>
    where
        S: Scheme<Signature = V::Signature>,
        D: Digest,
    {
        let share = self.share()?;

        let (namespace, message) = context.namespace_and_message(namespace);
        let signature =
            partial_sign_message::<V>(share, Some(namespace.as_ref()), message.as_ref()).value;

        Some(Signature {
            signer: share.index,
            signature,
        })
    }

    /// Verifies a single vote from a signer.
    pub fn verify_vote<S, D>(
        &self,
        namespace: &[u8],
        context: S::Context<'_, D>,
        signature: &Signature<S>,
    ) -> bool
    where
        S: Scheme<Signature = V::Signature>,
        D: Digest,
    {
        let Some(evaluated) = self.polynomial().get(signature.signer as usize) else {
            return false;
        };

        let (namespace, message) = context.namespace_and_message(namespace);
        verify_message::<V>(
            evaluated,
            Some(namespace.as_ref()),
            message.as_ref(),
            &signature.signature,
        )
        .is_ok()
    }

    /// Batch-verifies votes and returns verified votes and invalid signers.
    pub fn verify_votes<S, R, D, I>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        context: S::Context<'_, D>,
        signatures: I,
    ) -> SignatureVerification<S>
    where
        S: Scheme<Signature = V::Signature>,
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Signature<S>>,
    {
        let mut invalid = BTreeSet::new();
        let partials: Vec<_> = signatures
            .into_iter()
            .map(|vote| PartialSignature::<V> {
                index: vote.signer,
                value: vote.signature,
            })
            .collect();

        let polynomial = self.polynomial();
        let (namespace, message) = context.namespace_and_message(namespace);
        if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
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
            .map(|partial| Signature {
                signer: partial.index,
                signature: partial.value,
            })
            .collect();

        let invalid_signers = invalid.into_iter().collect();

        SignatureVerification::new(verified, invalid_signers)
    }

    /// Assembles a certificate from a collection of votes.
    pub fn assemble_certificate<S, I>(&self, signatures: I) -> Option<V::Signature>
    where
        S: Scheme<Signature = V::Signature>,
        I: IntoIterator<Item = Signature<S>>,
    {
        let partials: Vec<_> = signatures
            .into_iter()
            .map(|vote| PartialSignature::<V> {
                index: vote.signer,
                value: vote.signature,
            })
            .collect();

        let quorum = self.participants().quorum();
        if partials.len() < quorum as usize {
            return None;
        }

        threshold_signature_recover::<V, _>(quorum, partials.iter()).ok()
    }

    /// Verifies a certificate.
    pub fn verify_certificate<S, R, D>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        context: S::Context<'_, D>,
        certificate: &V::Signature,
    ) -> bool
    where
        S: Scheme,
        R: Rng + CryptoRng,
        D: Digest,
    {
        let identity = self.identity();
        let (namespace, message) = context.namespace_and_message(namespace);
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
        I: Iterator<Item = (S::Context<'a, D>, &'a V::Signature)>,
    {
        let identity = self.identity();

        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        for (context, certificate) in certificates {
            let (namespace, message) = context.namespace_and_message(namespace);
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
    /// This macro creates a pure proxy wrapper that delegates to the raw implementation.
    #[macro_export]
    macro_rules! impl_bls12381_threshold_scheme {
        ($context:ty) => {
            /// BLS12-381 threshold signature scheme wrapper.
            #[derive(Clone, Debug)]
            pub struct Scheme<
                P: commonware_cryptography::PublicKey,
                V: commonware_cryptography::bls12381::primitives::variant::Variant,
            > {
                raw: $crate::signing_scheme::bls12381_threshold::Bls12381Threshold<P, V>,
            }

            impl<
                P: commonware_cryptography::PublicKey,
                V: commonware_cryptography::bls12381::primitives::variant::Variant,
            > Scheme<P, V> {
                /// Creates a new signer instance with a private share and evaluated public polynomial.
                pub fn new(
                    participants: commonware_utils::ordered::Set<P>,
                    polynomial: &commonware_cryptography::bls12381::primitives::poly::Public<V>,
                    share: commonware_cryptography::bls12381::primitives::group::Share,
                ) -> Self {
                    Self {
                        raw: $crate::signing_scheme::bls12381_threshold::Bls12381Threshold::new(
                            participants,
                            polynomial,
                            share,
                        ),
                    }
                }

                /// Creates a verifier that can authenticate partial signatures.
                pub fn verifier(
                    participants: commonware_utils::ordered::Set<P>,
                    polynomial: &commonware_cryptography::bls12381::primitives::poly::Public<V>,
                ) -> Self {
                    Self {
                        raw: $crate::signing_scheme::bls12381_threshold::Bls12381Threshold::verifier(
                            participants,
                            polynomial,
                        ),
                    }
                }

                /// Creates a lightweight verifier that only checks recovered certificates.
                pub const fn certificate_verifier(identity: V::Public) -> Self {
                    Self {
                        raw: $crate::signing_scheme::bls12381_threshold::Bls12381Threshold::certificate_verifier(
                            identity,
                        ),
                    }
                }
            }

            impl<
                P: commonware_cryptography::PublicKey,
                V: commonware_cryptography::bls12381::primitives::variant::Variant + Send + Sync,
            > $crate::signing_scheme::Scheme for Scheme<P, V> {
                type Context<'a, D: commonware_cryptography::Digest> = $context;
                type PublicKey = P;
                type Signature = V::Signature;
                type Certificate = V::Signature;

                fn me(&self) -> Option<u32> {
                    self.raw.me()
                }

                fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
                    self.raw.participants()
                }

                fn sign_vote<D: commonware_cryptography::Digest>(
                    &self,
                    namespace: &[u8],
                    context: Self::Context<'_, D>,
                ) -> Option<$crate::signing_scheme::Signature<Self>> {
                    self.raw.sign_vote(namespace, context)
                }

                fn verify_vote<D: commonware_cryptography::Digest>(
                    &self,
                    namespace: &[u8],
                    context: Self::Context<'_, D>,
                    signature: &$crate::signing_scheme::Signature<Self>,
                ) -> bool {
                    self.raw.verify_vote(namespace, context, signature)
                }

                fn verify_votes<R, D, I>(
                    &self,
                    rng: &mut R,
                    namespace: &[u8],
                    context: Self::Context<'_, D>,
                    signatures: I,
                ) -> $crate::signing_scheme::SignatureVerification<Self>
                where
                    R: rand::Rng + rand::CryptoRng,
                    D: commonware_cryptography::Digest,
                    I: IntoIterator<Item = $crate::signing_scheme::Signature<Self>>,
                {
                    self.raw.verify_votes(rng, namespace, context, signatures)
                }

                fn assemble_certificate<I>(&self, signatures: I) -> Option<Self::Certificate>
                where
                    I: IntoIterator<Item = $crate::signing_scheme::Signature<Self>>,
                {
                    self.raw.assemble_certificate(signatures)
                }

                fn verify_certificate<
                    R: rand::Rng + rand::CryptoRng,
                    D: commonware_cryptography::Digest,
                >(
                    &self,
                    rng: &mut R,
                    namespace: &[u8],
                    context: Self::Context<'_, D>,
                    certificate: &Self::Certificate,
                ) -> bool {
                    self.raw.verify_certificate::<Self, _, _>(rng, namespace, context, certificate)
                }

                fn verify_certificates<'a, R, D, I>(
                    &self,
                    rng: &mut R,
                    namespace: &[u8],
                    certificates: I,
                ) -> bool
                where
                    R: rand::Rng + rand::CryptoRng,
                    D: commonware_cryptography::Digest,
                    I: Iterator<Item = (Self::Context<'a, D>, &'a Self::Certificate)>,
                {
                    self.raw.verify_certificates::<Self, _, _, _>(rng, namespace, certificates)
                }

                fn is_attributable(&self) -> bool {
                    self.raw.is_attributable()
                }

                fn certificate_codec_config(
                    &self,
                ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    self.raw.certificate_codec_config()
                }

                fn certificate_codec_config_unbounded(
                ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    $crate::signing_scheme::bls12381_threshold::Bls12381Threshold::<P, V>::certificate_codec_config_unbounded()
                }
            }
        };
    }
}
