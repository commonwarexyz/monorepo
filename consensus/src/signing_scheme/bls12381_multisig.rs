///! BLS12-381 multi-signature signing scheme implementation.
///!
///! This module provides both the raw BLS12-381 multisig implementation and a macro to generate
///! protocol-specific wrappers.

/// Generates a BLS12-381 multisig signing scheme wrapper for a specific protocol.
///
/// This macro creates a complete wrapper struct with constructors and `Scheme` trait implementation.
/// The only required parameter is the `Context` type, which varies per protocol.
///
/// # Example
/// ```ignore
/// impl_bls12381_multisig_scheme!(VoteContext<'a, D>);
/// ```
#[macro_export]
macro_rules! impl_bls12381_multisig_scheme {
    ($context:ty) => {
        /// BLS12-381 multi-signature signing scheme wrapper.
        ///
        /// Participants have both an identity key (P) and a consensus key (V::Public).
        #[derive(Clone, Debug)]
        pub struct Scheme<P: commonware_cryptography::PublicKey, V: commonware_cryptography::bls12381::primitives::variant::Variant> {
            participants: commonware_utils::set::OrderedAssociated<P, V::Public>,
            raw: $crate::signing_scheme::bls12381_multisig::Bls12381Multisig<V>,
        }

        impl<P: commonware_cryptography::PublicKey, V: commonware_cryptography::bls12381::primitives::variant::Variant> Scheme<P, V> {
            /// Creates a new scheme instance with the provided key material.
            ///
            /// Participants have both an identity key and a consensus key. The identity key
            /// is used for committee ordering and indexing, while the consensus key is used for
            /// signing and verification.
            ///
            /// If the provided private key does not match any consensus key in the committee,
            /// the instance will act as a verifier (unable to generate signatures).
            pub fn new(
                participants: commonware_utils::set::OrderedAssociated<P, V::Public>,
                private_key: commonware_cryptography::bls12381::primitives::group::Private,
            ) -> Self {
                let consensus_keys = participants.values().to_vec();
                let quorum = commonware_utils::quorum(participants.len() as u32);
                Self {
                    participants: participants.clone(),
                    raw: $crate::signing_scheme::bls12381_multisig::Bls12381Multisig::new(consensus_keys, private_key, quorum),
                }
            }

            /// Builds a verifier that can authenticate votes and certificates.
            ///
            /// Participants have both an identity key and a consensus key. The identity key
            /// is used for committee ordering and indexing, while the consensus key is used for
            /// verification.
            pub fn verifier(participants: commonware_utils::set::OrderedAssociated<P, V::Public>) -> Self {
                let consensus_keys = participants.values().to_vec();
                let quorum = commonware_utils::quorum(participants.len() as u32);
                Self {
                    participants: participants.clone(),
                    raw: $crate::signing_scheme::bls12381_multisig::Bls12381Multisig::verifier(consensus_keys, quorum),
                }
            }
        }

        impl<P: commonware_cryptography::PublicKey, V: commonware_cryptography::bls12381::primitives::variant::Variant + Send + Sync>
            $crate::signing_scheme::Scheme for Scheme<P, V>
        {
            type Context<'a, D: commonware_cryptography::Digest> = $context;
            type PublicKey = P;
            type Signature = V::Signature;
            type Certificate = $crate::signing_scheme::bls12381_multisig::Certificate<V>;

            fn me(&self) -> Option<u32> {
                self.raw.me()
            }

            fn participants(&self) -> &commonware_utils::set::Ordered<Self::PublicKey> {
                self.participants.keys()
            }

            fn sign_vote<D: commonware_cryptography::Digest>(
                &self,
                namespace: &[u8],
                context: Self::Context<'_, D>,
            ) -> Option<$crate::signing_scheme::Vote<Self>> {
                use $crate::signing_scheme::Context as _;
                let (namespace, message) = context.namespace_and_message(namespace);
                let (signer, signature) = self.raw.sign_vote(namespace.as_ref(), message.as_ref())?;
                Some($crate::signing_scheme::Vote { signer, signature })
            }

            fn verify_vote<D: commonware_cryptography::Digest>(
                &self,
                namespace: &[u8],
                context: Self::Context<'_, D>,
                vote: &$crate::signing_scheme::Vote<Self>,
            ) -> bool {
                use $crate::signing_scheme::Context as _;
                let (namespace, message) = context.namespace_and_message(namespace);
                self.raw.verify_vote(namespace.as_ref(), message.as_ref(), vote.signer, &vote.signature)
            }

            fn verify_votes<R, D, I>(
                &self,
                rng: &mut R,
                namespace: &[u8],
                context: Self::Context<'_, D>,
                votes: I,
            ) -> $crate::signing_scheme::VoteVerification<Self>
            where
                R: rand::Rng + rand::CryptoRng,
                D: commonware_cryptography::Digest,
                I: IntoIterator<Item = $crate::signing_scheme::Vote<Self>>,
            {
                use $crate::signing_scheme::Context as _;
                let (namespace, message) = context.namespace_and_message(namespace);

                let votes_raw = votes
                    .into_iter()
                    .map(|vote| (vote.signer, vote.signature))
                    .collect::<Vec<_>>();

                let (verified_raw, invalid) = self.raw.verify_votes(
                    rng,
                    namespace.as_ref(),
                    message.as_ref(),
                    votes_raw,
                );

                let verified = verified_raw
                    .into_iter()
                    .map(|(signer, signature)| $crate::signing_scheme::Vote { signer, signature })
                    .collect();

                $crate::signing_scheme::VoteVerification::new(verified, invalid)
            }

            fn assemble_certificate<I>(&self, votes: I) -> Option<Self::Certificate>
            where
                I: IntoIterator<Item = $crate::signing_scheme::Vote<Self>>,
            {
                let votes_raw = votes
                    .into_iter()
                    .map(|vote| (vote.signer, vote.signature));
                self.raw.assemble_certificate(votes_raw)
            }

            fn verify_certificate<R: rand::Rng + rand::CryptoRng, D: commonware_cryptography::Digest>(
                &self,
                rng: &mut R,
                namespace: &[u8],
                context: Self::Context<'_, D>,
                certificate: &Self::Certificate,
            ) -> bool {
                use $crate::signing_scheme::Context as _;
                let (namespace, message) = context.namespace_and_message(namespace);
                self.raw.verify_certificate(
                    rng,
                    namespace.as_ref(),
                    message.as_ref(),
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
                D: commonware_cryptography::Digest,
                I: Iterator<Item = (Self::Context<'a, D>, &'a Self::Certificate)>,
            {
                use $crate::signing_scheme::Context as _;
                let certificates_raw = certificates.map(|(context, cert)| {
                    let (ns, msg) = context.namespace_and_message(namespace);
                    (ns, msg, cert)
                });

                let certificates_collected: Vec<_> = certificates_raw
                    .map(|(ns, msg, cert)| (ns, msg, cert))
                    .collect();

                self.raw.verify_certificates(
                    rng,
                    certificates_collected
                        .iter()
                        .map(|(ns, msg, cert)| (ns.as_ref(), msg.as_ref(), *cert)),
                )
            }

            fn is_attributable(&self) -> bool {
                true
            }

            fn certificate_codec_config(&self) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                self.participants().len()
            }

            fn certificate_codec_config_unbounded() -> <Self::Certificate as commonware_codec::Read>::Cfg {
                u32::MAX as usize
            }
        }
    };
}

use crate::signing_scheme::utils::Signers;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::bls12381::primitives::{
    group::Private,
    ops::{
        aggregate_signatures, aggregate_verify_multiple_public_keys, compute_public, sign_message,
        verify_message,
    },
    variant::Variant,
};
use rand::{CryptoRng, Rng};

/// Core BLS12-381 multi-signature implementation.
#[derive(Clone, Debug)]
pub struct Bls12381Multisig<V: Variant> {
    /// Consensus public keys for verification.
    pub consensus_keys: Vec<V::Public>,
    /// Key used for generating signatures.
    pub signer: Option<(u32, Private)>,
    /// Quorum size for certificate assembly.
    pub quorum: u32,
}

impl<V: Variant> Bls12381Multisig<V> {
    /// Creates a new raw BLS12-381 multisig scheme instance.
    pub fn new(consensus_keys: Vec<V::Public>, private_key: Private, quorum: u32) -> Self {
        let public_key = compute_public::<V>(&private_key);
        let signer = consensus_keys
            .iter()
            .position(|p| p == &public_key)
            .map(|index| (index as u32, private_key));

        Self {
            consensus_keys,
            signer,
            quorum,
        }
    }

    /// Builds a verifier that can authenticate votes and certificates.
    pub fn verifier(consensus_keys: Vec<V::Public>, quorum: u32) -> Self {
        Self {
            consensus_keys,
            signer: None,
            quorum,
        }
    }

    /// Returns the index of "self" in the participant set, if available.
    pub fn me(&self) -> Option<u32> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    /// Signs a message and returns the signer index and signature.
    pub fn sign_vote(&self, namespace: &[u8], message: &[u8]) -> Option<(u32, V::Signature)> {
        let (index, private_key) = self.signer.as_ref()?;
        let signature = sign_message::<V>(private_key, Some(namespace), message);
        Some((*index, signature))
    }

    /// Verifies a single vote from a signer.
    pub fn verify_vote(
        &self,
        namespace: &[u8],
        message: &[u8],
        signer: u32,
        signature: &V::Signature,
    ) -> bool {
        let Some(public_key) = self.consensus_keys.get(signer as usize) else {
            return false;
        };
        verify_message::<V>(public_key, Some(namespace), message, signature).is_ok()
    }

    /// Batch-verifies votes using aggregate verification.
    ///
    /// Returns verified votes and invalid signers.
    pub fn verify_votes<R: Rng + CryptoRng>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        message: &[u8],
        votes: impl IntoIterator<Item = (u32, V::Signature)>,
    ) -> (Vec<(u32, V::Signature)>, Vec<u32>) {
        let mut invalid = Vec::new();
        let mut candidates = Vec::new();
        let mut publics = Vec::new();
        let mut signatures = Vec::new();

        for (signer, signature) in votes {
            let Some(public_key) = self.consensus_keys.get(signer as usize) else {
                invalid.push(signer);
                continue;
            };

            publics.push(*public_key);
            signatures.push(signature);
            candidates.push((signer, signature));
        }

        // If there are no candidates to verify, return before doing any work.
        if candidates.is_empty() {
            return (candidates, invalid);
        }

        // Verify the aggregate signature.
        if aggregate_verify_multiple_public_keys::<V, _>(
            publics.iter(),
            Some(namespace),
            message,
            &aggregate_signatures::<V, _>(signatures.iter()),
        )
        .is_err()
        {
            // Aggregate failed: fall back to per-signer verification.
            for ((signer, sig), public_key) in candidates.iter().zip(publics.iter()) {
                if verify_message::<V>(public_key, Some(namespace), message, sig).is_err() {
                    invalid.push(*signer);
                }
            }
        }

        let verified = candidates
            .into_iter()
            .filter(|(signer, _)| !invalid.contains(signer))
            .collect();

        (verified, invalid)
    }

    /// Assembles a certificate from a collection of votes.
    pub fn assemble_certificate(
        &self,
        votes: impl IntoIterator<Item = (u32, V::Signature)>,
    ) -> Option<Certificate<V>> {
        // Collect the signers and signatures.
        let mut entries = Vec::new();
        for (signer, signature) in votes {
            if (signer as usize) >= self.consensus_keys.len() {
                return None;
            }
            entries.push((signer, signature));
        }
        if entries.len() < self.quorum as usize {
            return None;
        }

        // Produce signers and aggregate signature.
        let (signers, signatures): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::from(self.consensus_keys.len(), signers);
        let signature = aggregate_signatures::<V, _>(signatures.iter());

        Some(Certificate { signers, signature })
    }

    /// Verifies a certificate.
    pub fn verify_certificate<R: Rng + CryptoRng>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        message: &[u8],
        certificate: &Certificate<V>,
    ) -> bool {
        // If the certificate signers length does not match the participant set, return false.
        if certificate.signers.len() != self.consensus_keys.len() {
            return false;
        }

        // If the certificate does not meet the quorum, return false.
        if certificate.signers.count() < self.quorum as usize {
            return false;
        }

        // Collect the public keys.
        let mut publics = Vec::with_capacity(certificate.signers.count());
        for signer in certificate.signers.iter() {
            let Some(public_key) = self.consensus_keys.get(signer as usize) else {
                return false;
            };
            publics.push(*public_key);
        }

        // Verify the aggregate signature.
        aggregate_verify_multiple_public_keys::<V, _>(
            publics.iter(),
            Some(namespace),
            message,
            &certificate.signature,
        )
        .is_ok()
    }

    /// Verifies multiple certificates (no batch optimization for BLS multisig).
    pub fn verify_certificates<'a, R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        certificates: impl Iterator<Item = (&'a [u8], &'a [u8], &'a Certificate<V>)>,
    ) -> bool {
        for (namespace, message, certificate) in certificates {
            if !self.verify_certificate(rng, namespace, message, certificate) {
                return false;
            }
        }
        true
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
                "consensus::simplex::signing_scheme::bls12381_multisig::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signature = V::Signature::read(reader)?;

        Ok(Self { signers, signature })
    }
}
