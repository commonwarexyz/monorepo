//! BLS12-381 multi-signature signing scheme implementation.
//!
//! This module provides both the raw BLS12-381 multisig implementation and a macro to generate
//! protocol-specific wrappers.

use crate::signing_scheme::{utils::Signers, Context, Scheme, Signature, SignatureVerification};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Private,
        ops::{
            aggregate_signatures, aggregate_verify_multiple_public_keys, compute_public,
            sign_message, verify_message,
        },
        variant::Variant,
    },
    Digest, PublicKey,
};
use commonware_utils::ordered::{BiMap, Quorum, Set};
use rand::{CryptoRng, Rng};
use std::collections::BTreeSet;

/// BLS12-381 multi-signature implementation of the [`Scheme`] trait.
#[derive(Clone, Debug)]
pub struct Bls12381Multisig<P: PublicKey, V: Variant> {
    /// Participants in the committee.
    pub participants: BiMap<P, V::Public>,
    /// Key used for generating signatures.
    pub signer: Option<(u32, Private)>,
}

impl<P: PublicKey, V: Variant> Bls12381Multisig<P, V> {
    /// Creates a new scheme instance with the provided key material.
    ///
    /// Participants have both an identity key and a consensus key. The identity key
    /// is used for committee ordering and indexing, while the consensus key is used for
    /// signing and verification.
    ///
    /// If the provided private key does not match any consensus key in the committee,
    /// the instance will act as a verifier (unable to generate signatures).
    pub fn new(participants: BiMap<P, V::Public>, private_key: Private) -> Self {
        let public_key = compute_public::<V>(&private_key);
        let signer = participants
            .values()
            .iter()
            .position(|p| p == &public_key)
            .map(|index| (index as u32, private_key));

        Self {
            participants,
            signer,
        }
    }

    /// Builds a verifier that can authenticate votes and certificates.
    ///
    /// Participants have both an identity key and a consensus key. The identity key
    /// is used for committee ordering and indexing, while the consensus key is used for
    /// verification.
    pub fn verifier(participants: BiMap<P, V::Public>) -> Self {
        Self {
            participants,
            signer: None,
        }
    }

    /// Returns the ordered set of identity keys.
    pub fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns the index of "self" in the participant set, if available.
    pub fn me(&self) -> Option<u32> {
        self.signer.as_ref().map(|(index, _)| *index)
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
        let (index, private_key) = self.signer.as_ref()?;

        let (namespace, message) = context.namespace_and_message(namespace);
        let signature = sign_message::<V>(private_key, Some(namespace.as_ref()), message.as_ref());

        Some(Signature {
            signer: *index,
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
        let Some(public_key) = self.participants.value(signature.signer as usize) else {
            return false;
        };

        let (namespace, message) = context.namespace_and_message(namespace);
        verify_message::<V>(
            public_key,
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
        let mut candidates = Vec::new();
        let mut publics = Vec::new();
        let mut sigs = Vec::new();
        for sig in signatures.into_iter() {
            let Some(public_key) = self.participants.value(sig.signer as usize) else {
                invalid.insert(sig.signer);
                continue;
            };

            publics.push(*public_key);
            sigs.push(sig.signature);
            candidates.push(sig);
        }

        // If there are no candidates to verify, return before doing any work.
        if candidates.is_empty() {
            return SignatureVerification::new(candidates, invalid.into_iter().collect());
        }

        // Verify the aggregate signature.
        let (namespace, message) = context.namespace_and_message(namespace);
        if aggregate_verify_multiple_public_keys::<V, _>(
            publics.iter(),
            Some(namespace.as_ref()),
            message.as_ref(),
            &aggregate_signatures::<V, _>(sigs.iter()),
        )
        .is_err()
        {
            for (vote, public_key) in candidates.iter().zip(publics.iter()) {
                if verify_message::<V>(
                    public_key,
                    Some(namespace.as_ref()),
                    message.as_ref(),
                    &vote.signature,
                )
                .is_err()
                {
                    invalid.insert(vote.signer);
                }
            }
        }

        // Collect the invalid signers.
        let verified = candidates
            .into_iter()
            .filter(|vote| !invalid.contains(&vote.signer))
            .collect();
        let invalid_signers: Vec<_> = invalid.into_iter().collect();

        SignatureVerification::new(verified, invalid_signers)
    }

    /// Assembles a certificate from a collection of votes.
    pub fn assemble_certificate<S, I>(&self, signatures: I) -> Option<Certificate<V>>
    where
        S: Scheme<Signature = V::Signature>,
        I: IntoIterator<Item = Signature<S>>,
    {
        // Collect the signers and signatures.
        let mut entries = Vec::new();
        for Signature { signer, signature } in signatures {
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
        context: S::Context<'_, D>,
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
        let (namespace, message) = context.namespace_and_message(namespace);
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
        I: Iterator<Item = (S::Context<'a, D>, &'a Certificate<V>)>,
    {
        for (context, certificate) in certificates {
            if !self.verify_certificate::<S, R, D>(rng, namespace, context, certificate) {
                return false;
            }
        }
        true
    }

    pub fn is_attributable(&self) -> bool {
        true
    }

    pub fn certificate_codec_config(&self) -> <Certificate<V> as Read>::Cfg {
        self.participants.len()
    }

    pub fn certificate_codec_config_unbounded() -> <Certificate<V> as Read>::Cfg {
        u32::MAX as usize
    }
}

/// Certificate formed by an aggregated BLS12-381 signature plus the signers that
/// contributed to it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<V: Variant> {
    /// Bitmap of validator indices that contributed signatures.
    pub signers: Signers,
    /// Aggregated BLS signature covering all votes in this certificate.
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
                "consensus::signing_scheme::bls12381_multisig::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signature = V::Signature::read(reader)?;

        Ok(Self { signers, signature })
    }
}

mod macros {
    /// Generates a BLS12-381 multisig signing scheme wrapper for a specific protocol.
    ///
    /// This macro creates a pure proxy wrapper that delegates to the raw implementation.
    #[macro_export]
    macro_rules! impl_bls12381_multisig_scheme {
        ($context:ty) => {
            /// BLS12-381 multi-signature signing scheme wrapper.
            #[derive(Clone, Debug)]
            pub struct Scheme<
                P: commonware_cryptography::PublicKey,
                V: commonware_cryptography::bls12381::primitives::variant::Variant,
            > {
                raw: $crate::signing_scheme::bls12381_multisig::Bls12381Multisig<P, V>,
            }

            impl<
                P: commonware_cryptography::PublicKey,
                V: commonware_cryptography::bls12381::primitives::variant::Variant,
            > Scheme<P, V> {
                /// Creates a new scheme instance with the provided key material.
                pub fn new(
                    participants: commonware_utils::ordered::BiMap<P, V::Public>,
                    private_key: commonware_cryptography::bls12381::primitives::group::Private,
                ) -> Self {
                    Self {
                        raw: $crate::signing_scheme::bls12381_multisig::Bls12381Multisig::new(
                            participants,
                            private_key,
                        ),
                    }
                }

                /// Builds a verifier that can authenticate votes and certificates.
                pub fn verifier(
                    participants: commonware_utils::ordered::BiMap<P, V::Public>,
                ) -> Self {
                    Self {
                        raw: $crate::signing_scheme::bls12381_multisig::Bls12381Multisig::verifier(
                            participants,
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
                type Certificate = $crate::signing_scheme::bls12381_multisig::Certificate<V>;

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

                fn certificate_codec_config_unbounded() -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    $crate::signing_scheme::bls12381_multisig::Bls12381Multisig::<P, V>::certificate_codec_config_unbounded()
                }
            }
        };
    }
}
