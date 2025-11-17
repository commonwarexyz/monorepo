//! BLS12-381 threshold signature scheme implementation.
//!
//! This module provides both the raw BLS12-381 threshold implementation and a macro to generate
//! protocol-specific wrappers.
//!
//! Unlike multi-signature schemes, threshold signatures:
//! - Use partial signatures that can be combined to form a threshold signature
//! - Require a quorum of signatures to recover the full signature
//! - Are **non-attributable**: partial signatures can be forged by holders of enough other partials

/// Generates a BLS12-381 threshold signing scheme wrapper for a specific protocol.
///
/// This macro creates a complete wrapper struct with constructors and `Scheme` trait implementation.
/// The only required parameter is the `Context` type, which varies per protocol.
///
/// # Example
/// ```ignore
/// impl_bls12381_threshold_scheme!(AckContext<'a, P, D>);
/// ```
#[macro_export]
macro_rules! impl_bls12381_threshold_scheme {
    ($context:ty) => {
        /// BLS12-381 threshold signature scheme wrapper.
        #[derive(Clone, Debug)]
        pub struct Bls12381Threshold<P: commonware_cryptography::PublicKey, V: commonware_cryptography::bls12381::primitives::variant::Variant> {
            /// Ordered set of participant public keys.
            pub participants: commonware_utils::set::Ordered<P>,
            /// Raw BLS12-381 threshold implementation.
            pub raw: $crate::signing_scheme::bls12381_threshold::Bls12381Threshold<V>,
        }

        impl<P: commonware_cryptography::PublicKey, V: commonware_cryptography::bls12381::primitives::variant::Variant>
            Bls12381Threshold<P, V>
        {
            /// Creates a new scheme with participants and the raw threshold implementation.
            pub fn new(
                participants: commonware_utils::set::Ordered<P>,
                raw: $crate::signing_scheme::bls12381_threshold::Bls12381Threshold<V>,
            ) -> Self {
                Self { participants, raw }
            }
        }

        impl<P: commonware_cryptography::PublicKey, V: commonware_cryptography::bls12381::primitives::variant::Variant + Send + Sync>
            $crate::signing_scheme::Scheme for Bls12381Threshold<P, V>
        {
            type Context<'a, D: commonware_cryptography::Digest> = $context;
            type PublicKey = P;
            type Signature = V::Signature;
            type Certificate = V::Signature;

            fn me(&self) -> Option<u32> {
                self.raw.me()
            }

            fn participants(&self) -> &commonware_utils::set::Ordered<Self::PublicKey> {
                &self.participants
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
                false  // Threshold schemes are NOT attributable
            }

            fn certificate_codec_config(&self) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                ()  // Threshold certificates use unit config
            }

            fn certificate_codec_config_unbounded() -> <Self::Certificate as commonware_codec::Read>::Cfg {
                ()  // Threshold certificates use unit config
            }
        }
    };
}

use commonware_cryptography::bls12381::primitives::{
    group::Share,
    ops::{
        aggregate_signatures, aggregate_verify_multiple_messages, partial_sign_message,
        partial_verify_multiple_public_keys_precomputed, threshold_signature_recover,
        verify_message,
    },
    poly::PartialSignature,
    variant::Variant,
};
use rand::{CryptoRng, Rng};
use std::collections::BTreeSet;

/// BLS12-381 threshold signature scheme.
///
/// A node can play one of three roles:
/// - **Signer**: holds a share and can generate partial signatures
/// - **Verifier**: holds the polynomial and can verify partial signatures
/// - **CertificateVerifier**: holds only the identity and can verify recovered certificates
#[derive(Clone, Debug)]
pub enum Bls12381Threshold<V: Variant> {
    /// Signer role with share for generating partial signatures.
    Signer {
        /// Public identity (constant across reshares).
        identity: V::Public,
        /// Evaluated public polynomial for verification.
        polynomial: Vec<V::Public>,
        /// Local share for signing.
        share: Share,
        /// Quorum threshold.
        quorum: u32,
    },
    /// Verifier role that can authenticate partial signatures.
    Verifier {
        /// Public identity (constant across reshares).
        identity: V::Public,
        /// Evaluated public polynomial for verification.
        polynomial: Vec<V::Public>,
        /// Quorum threshold.
        quorum: u32,
    },
    /// Lightweight verifier that only checks recovered certificates.
    CertificateVerifier {
        /// Public identity (constant across reshares).
        identity: V::Public,
    },
}

impl<V: Variant> Bls12381Threshold<V> {
    /// Creates a signer instance with a private share and evaluated public polynomial.
    ///
    /// If the provided share does not match the polynomial evaluation at its index,
    /// the instance will act as a verifier (unable to sign).
    ///
    /// * `identity` - public identity of the committee (constant across reshares)
    /// * `polynomial` - evaluated public polynomial for threshold verification
    /// * `share` - local threshold share for signing
    /// * `quorum` - number of signatures required to recover threshold signature
    pub fn new(identity: V::Public, polynomial: Vec<V::Public>, share: Share, quorum: u32) -> Self {
        let public_key = share.public::<V>();
        if let Some(index) = polynomial.iter().position(|p| p == &public_key) {
            assert_eq!(
                index as u32, share.index,
                "share index must match polynomial position"
            );
            Self::Signer {
                identity,
                polynomial,
                share,
                quorum,
            }
        } else {
            Self::Verifier {
                identity,
                polynomial,
                quorum,
            }
        }
    }

    /// Creates a verifier that can authenticate partial signatures.
    ///
    /// * `identity` - public identity of the committee (constant across reshares)
    /// * `polynomial` - evaluated public polynomial for threshold verification
    /// * `quorum` - number of signatures required to recover threshold signature
    pub fn verifier(identity: V::Public, polynomial: Vec<V::Public>, quorum: u32) -> Self {
        Self::Verifier {
            identity,
            polynomial,
            quorum,
        }
    }

    /// Creates a lightweight verifier that only checks recovered certificates.
    ///
    /// * `identity` - public identity of the committee (constant across reshares)
    pub fn certificate_verifier(identity: V::Public) -> Self {
        Self::CertificateVerifier { identity }
    }

    /// Returns the index of "self" in the participant set, if available.
    pub fn me(&self) -> Option<u32> {
        match self {
            Self::Signer { share, .. } => Some(share.index),
            _ => None,
        }
    }

    /// Returns the public identity.
    pub fn identity(&self) -> &V::Public {
        match self {
            Self::Signer { identity, .. } => identity,
            Self::Verifier { identity, .. } => identity,
            Self::CertificateVerifier { identity } => identity,
        }
    }

    /// Returns the evaluated public polynomial, if available.
    fn polynomial(&self) -> &[V::Public] {
        match self {
            Self::Signer { polynomial, .. } => polynomial,
            Self::Verifier { polynomial, .. } => polynomial,
            Self::CertificateVerifier { .. } => {
                panic!("polynomial not available for certificate verifier")
            }
        }
    }

    /// Returns the quorum threshold, if available.
    fn quorum(&self) -> u32 {
        match self {
            Self::Signer { quorum, .. } => *quorum,
            Self::Verifier { quorum, .. } => *quorum,
            Self::CertificateVerifier { .. } => {
                panic!("quorum not available for certificate verifier")
            }
        }
    }

    /// Signs a message and returns the signer index and partial signature.
    pub fn sign_vote(&self, namespace: &[u8], message: &[u8]) -> Option<(u32, V::Signature)> {
        match self {
            Self::Signer { share, .. } => {
                let partial = partial_sign_message::<V>(share, Some(namespace), message);
                Some((partial.index, partial.value))
            }
            _ => None,
        }
    }

    /// Verifies a single partial signature from a signer.
    pub fn verify_vote(
        &self,
        namespace: &[u8],
        message: &[u8],
        signer: u32,
        signature: &V::Signature,
    ) -> bool {
        let polynomial = self.polynomial();
        let Some(evaluated) = polynomial.get(signer as usize) else {
            return false;
        };

        verify_message::<V>(evaluated, Some(namespace), message, signature).is_ok()
    }

    /// Batch-verifies partial signatures.
    ///
    /// Returns verified votes and invalid signers.
    pub fn verify_votes<R: Rng + CryptoRng>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        message: &[u8],
        votes: impl IntoIterator<Item = (u32, V::Signature)>,
    ) -> (Vec<(u32, V::Signature)>, Vec<u32>) {
        let polynomial = self.polynomial();
        let partials: Vec<_> = votes
            .into_iter()
            .map(|(index, value)| PartialSignature::<V> { index, value })
            .collect();

        let mut invalid = BTreeSet::new();
        if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
            polynomial,
            Some(namespace),
            message,
            partials.iter(),
        ) {
            for partial in errs {
                invalid.insert(partial.index);
            }
        }

        let verified = partials
            .into_iter()
            .filter(|p| !invalid.contains(&p.index))
            .map(|p| (p.index, p.value))
            .collect();

        let invalid_signers = invalid.into_iter().collect();
        (verified, invalid_signers)
    }

    /// Assembles a threshold signature from partial signatures.
    ///
    /// Returns `None` if there are not enough partial signatures to meet the quorum.
    pub fn assemble_certificate(
        &self,
        votes: impl IntoIterator<Item = (u32, V::Signature)>,
    ) -> Option<V::Signature> {
        let partials: Vec<_> = votes
            .into_iter()
            .map(|(index, value)| PartialSignature::<V> { index, value })
            .collect();

        let quorum = self.quorum();
        if partials.len() < quorum as usize {
            return None;
        }

        threshold_signature_recover::<V, _>(quorum, partials.iter()).ok()
    }

    /// Verifies a recovered threshold signature.
    pub fn verify_certificate<R: Rng + CryptoRng>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        message: &[u8],
        certificate: &V::Signature,
    ) -> bool {
        verify_message::<V>(self.identity(), Some(namespace), message, certificate).is_ok()
    }

    /// Batch-verifies multiple threshold signatures over different messages.
    pub fn verify_certificates<'a, R: Rng + CryptoRng>(
        &self,
        _rng: &mut R,
        certificates: impl Iterator<Item = (&'a [u8], &'a [u8], &'a V::Signature)>,
    ) -> bool {
        let identity = self.identity();

        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        for (namespace, message, signature) in certificates {
            messages.push((Some(namespace), message));
            signatures.push(*signature);
        }

        if messages.is_empty() {
            return true;
        }

        let aggregate = aggregate_signatures::<V, _>(signatures.iter());
        aggregate_verify_multiple_messages::<V, _>(
            identity,
            &messages
                .iter()
                .map(|(ns, msg)| (ns.as_deref(), *msg))
                .collect::<Vec<_>>(),
            &aggregate,
            1,
        )
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::bls12381::{
        dkg::ops,
        primitives::variant::{MinPk, MinSig},
    };
    use commonware_utils::quorum;
    use rand::{rngs::StdRng, SeedableRng};

    const NAMESPACE: &[u8] = b"test-threshold";
    const MESSAGE: &[u8] = b"test message";

    fn setup_signers<V: Variant>(
        n: u32,
        seed: u64,
    ) -> (Vec<Bls12381Threshold<V>>, Bls12381Threshold<V>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let quorum = quorum(n);
        let (polynomial, shares) = ops::generate_shares::<_, V>(&mut rng, None, n, quorum);
        let evaluated = ops::evaluate_all::<V>(&polynomial, n);
        let identity =
            *commonware_cryptography::bls12381::primitives::poly::public::<V>(&polynomial);

        let signers = shares
            .into_iter()
            .map(|share| Bls12381Threshold::<V>::new(identity, evaluated.clone(), share, quorum))
            .collect();

        let verifier = Bls12381Threshold::<V>::verifier(identity, evaluated, quorum);

        (signers, verifier)
    }

    fn sign_vote_roundtrip<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 42);
        let scheme = &schemes[0];

        let vote = scheme.sign_vote(NAMESPACE, MESSAGE).unwrap();
        assert!(scheme.verify_vote(NAMESPACE, MESSAGE, vote.0, &vote.1));
    }

    #[test]
    fn test_sign_vote_roundtrip() {
        sign_vote_roundtrip::<MinPk>();
        sign_vote_roundtrip::<MinSig>();
    }

    fn verifier_cannot_sign<V: Variant>() {
        let (_, verifier) = setup_signers::<V>(4, 43);
        assert!(verifier.sign_vote(NAMESPACE, MESSAGE).is_none());
    }

    #[test]
    fn test_verifier_cannot_sign() {
        verifier_cannot_sign::<MinPk>();
        verifier_cannot_sign::<MinSig>();
    }

    fn verify_votes_filters_invalid<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(5, 44);
        let quorum = quorum(schemes.len() as u32) as usize;

        let mut votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| s.sign_vote(NAMESPACE, MESSAGE).unwrap())
            .collect();

        let mut rng = StdRng::seed_from_u64(45);
        let (verified, invalid) =
            schemes[0].verify_votes(&mut rng, NAMESPACE, MESSAGE, votes.clone());
        assert!(invalid.is_empty());
        assert_eq!(verified.len(), quorum);

        // Corrupt one vote
        votes[0].0 = 999;
        let (verified, invalid) = schemes[0].verify_votes(&mut rng, NAMESPACE, MESSAGE, votes);
        assert_eq!(invalid, vec![999]);
        assert_eq!(verified.len(), quorum - 1);
    }

    #[test]
    fn test_verify_votes_filters_invalid() {
        verify_votes_filters_invalid::<MinPk>();
        verify_votes_filters_invalid::<MinSig>();
    }

    fn assemble_and_verify_certificate<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 46);
        let quorum = quorum(schemes.len() as u32) as usize;

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| s.sign_vote(NAMESPACE, MESSAGE).unwrap())
            .collect();

        let certificate = schemes[0].assemble_certificate(votes).unwrap();

        let mut rng = StdRng::seed_from_u64(47);
        assert!(verifier.verify_certificate(&mut rng, NAMESPACE, MESSAGE, &certificate));
    }

    #[test]
    fn test_assemble_and_verify_certificate() {
        assemble_and_verify_certificate::<MinPk>();
        assemble_and_verify_certificate::<MinSig>();
    }

    fn certificate_verifier_works<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 48);
        let quorum = quorum(schemes.len() as u32) as usize;

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| s.sign_vote(NAMESPACE, MESSAGE).unwrap())
            .collect();

        let certificate = schemes[0].assemble_certificate(votes).unwrap();

        let cert_verifier = Bls12381Threshold::<V>::certificate_verifier(*schemes[0].identity());
        let mut rng = StdRng::seed_from_u64(49);
        assert!(cert_verifier.verify_certificate(&mut rng, NAMESPACE, MESSAGE, &certificate));
    }

    #[test]
    fn test_certificate_verifier_works() {
        certificate_verifier_works::<MinPk>();
        certificate_verifier_works::<MinSig>();
    }

    fn verify_certificates_batch<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 50);
        let quorum = quorum(schemes.len() as u32) as usize;

        let messages = [b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];
        let mut certificates = Vec::new();

        for msg in &messages {
            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| s.sign_vote(NAMESPACE, msg).unwrap())
                .collect();
            certificates.push(schemes[0].assemble_certificate(votes).unwrap());
        }

        let certs_iter = messages
            .iter()
            .zip(&certificates)
            .map(|(msg, cert)| (NAMESPACE, *msg, cert));

        let mut rng = StdRng::seed_from_u64(51);
        assert!(verifier.verify_certificates(&mut rng, certs_iter));
    }

    #[test]
    fn test_verify_certificates_batch() {
        verify_certificates_batch::<MinPk>();
        verify_certificates_batch::<MinSig>();
    }
}
