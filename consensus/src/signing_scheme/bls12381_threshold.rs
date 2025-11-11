//! BLS12-381 threshold signature scheme for consensus.
//!
//! This raw implementation operates directly on byte arrays and provides the core
//! cryptographic operations. It can be wrapped by protocol-specific implementations
//! (e.g., simplex with seeds, aggregation, ordered_broadcast).
//!
//! Unlike multi-signature schemes, threshold signatures:
//! - Use partial signatures that can be combined to form a threshold signature
//! - Require a quorum of signatures to recover the full signature
//! - Are **non-attributable**: partial signatures can be forged by holders of enough other partials

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
