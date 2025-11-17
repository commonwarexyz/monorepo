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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::bls12381::primitives::{
        group::Private,
        ops::compute_public,
        variant::{MinPk, MinSig, Variant},
    };
    use commonware_utils::quorum;
    use rand::{rngs::StdRng, thread_rng, SeedableRng};

    const NAMESPACE: &[u8] = b"test-bls-multisig";
    const MESSAGE: &[u8] = b"test message";

    fn setup_signers<V: Variant>(
        n: u32,
        seed: u64,
    ) -> (Vec<Bls12381Multisig<V>>, Bls12381Multisig<V>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let quorum = quorum(n);

        let private_keys: Vec<Private> = (0..n).map(|_| Private::from_rand(&mut rng)).collect();

        let consensus_keys: Vec<V::Public> = private_keys
            .iter()
            .map(|sk| compute_public::<V>(sk))
            .collect();

        let signers = private_keys
            .into_iter()
            .map(|sk| Bls12381Multisig::<V>::new(consensus_keys.clone(), sk, quorum))
            .collect();

        let verifier = Bls12381Multisig::<V>::verifier(consensus_keys, quorum);

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

        // Corrupt one vote - invalid signer index
        votes[0].0 = 999;
        let (verified, invalid) =
            schemes[0].verify_votes(&mut rng, NAMESPACE, MESSAGE, votes.clone());
        assert_eq!(invalid, vec![999]);
        assert_eq!(verified.len(), quorum - 1);

        // Corrupt one vote - invalid signature
        votes[0].0 = 0;
        votes[0].1 = votes[1].1;
        let (verified, invalid) = schemes[0].verify_votes(&mut rng, NAMESPACE, MESSAGE, votes);
        assert_eq!(invalid, vec![0]);
        assert_eq!(verified.len(), quorum - 1);
    }

    #[test]
    fn test_verify_votes_filters_invalid() {
        verify_votes_filters_invalid::<MinPk>();
        verify_votes_filters_invalid::<MinSig>();
    }

    fn assemble_certificate<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 46);
        let quorum = quorum(schemes.len() as u32) as usize;

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| s.sign_vote(NAMESPACE, MESSAGE).unwrap())
            .collect();

        let certificate = schemes[0].assemble_certificate(votes).unwrap();

        // Verify certificate has correct number of signers
        assert_eq!(certificate.signers.count(), quorum);
    }

    #[test]
    fn test_assemble_certificate() {
        assemble_certificate::<MinPk>();
        assemble_certificate::<MinSig>();
    }

    fn verify_certificate<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 47);
        let quorum = quorum(schemes.len() as u32) as usize;

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| s.sign_vote(NAMESPACE, MESSAGE).unwrap())
            .collect();

        let certificate = schemes[0].assemble_certificate(votes).unwrap();

        let mut rng = StdRng::seed_from_u64(48);
        assert!(verifier.verify_certificate(&mut rng, NAMESPACE, MESSAGE, &certificate));
    }

    #[test]
    fn test_verify_certificate() {
        verify_certificate::<MinPk>();
        verify_certificate::<MinSig>();
    }

    fn verify_certificate_detects_corruption<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 49);
        let quorum = quorum(schemes.len() as u32) as usize;

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| s.sign_vote(NAMESPACE, MESSAGE).unwrap())
            .collect();

        let certificate = schemes[0].assemble_certificate(votes).unwrap();

        // Valid certificate passes
        assert!(verifier.verify_certificate(&mut thread_rng(), NAMESPACE, MESSAGE, &certificate));

        // Corrupted certificate fails (corrupt the aggregate signature)
        let mut corrupted = certificate.clone();
        corrupted.signature = schemes[0].sign_vote(NAMESPACE, b"different message").unwrap().1;
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            MESSAGE,
            &corrupted
        ));
    }

    #[test]
    fn test_verify_certificate_detects_corruption() {
        verify_certificate_detects_corruption::<MinPk>();
        verify_certificate_detects_corruption::<MinSig>();
    }

    fn certificate_codec_roundtrip<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 50);
        let quorum = quorum(schemes.len() as u32) as usize;

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| s.sign_vote(NAMESPACE, MESSAGE).unwrap())
            .collect();

        let certificate = schemes[0].assemble_certificate(votes).unwrap();
        let encoded = certificate.encode();
        let decoded =
            Certificate::<V>::decode_cfg(encoded, &schemes.len()).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_codec_roundtrip() {
        certificate_codec_roundtrip::<MinPk>();
        certificate_codec_roundtrip::<MinSig>();
    }

    fn certificate_rejects_sub_quorum<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 51);
        let sub_quorum = 2; // Less than quorum (3)

        let votes: Vec<_> = schemes
            .iter()
            .take(sub_quorum)
            .map(|s| s.sign_vote(NAMESPACE, MESSAGE).unwrap())
            .collect();

        assert!(schemes[0].assemble_certificate(votes).is_none());
    }

    #[test]
    fn test_certificate_rejects_sub_quorum() {
        certificate_rejects_sub_quorum::<MinPk>();
        certificate_rejects_sub_quorum::<MinSig>();
    }

    fn certificate_rejects_invalid_signer<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 52);
        let quorum = quorum(schemes.len() as u32) as usize;

        let mut votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| s.sign_vote(NAMESPACE, MESSAGE).unwrap())
            .collect();

        // Corrupt signer index to be out of range
        votes[0].0 = 999;

        assert!(schemes[0].assemble_certificate(votes).is_none());
    }

    #[test]
    fn test_certificate_rejects_invalid_signer() {
        certificate_rejects_invalid_signer::<MinPk>();
        certificate_rejects_invalid_signer::<MinSig>();
    }

    fn verify_certificate_rejects_sub_quorum<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 53);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| s.sign_vote(NAMESPACE, MESSAGE).unwrap())
            .collect();

        let certificate = schemes[0].assemble_certificate(votes).unwrap();

        // Manually create a sub-quorum certificate by changing quorum in verifier
        let sub_quorum_verifier =
            Bls12381Multisig::<V>::verifier(verifier.consensus_keys.clone(), 4);

        assert!(!sub_quorum_verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            MESSAGE,
            &certificate
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_sub_quorum() {
        verify_certificate_rejects_sub_quorum::<MinPk>();
        verify_certificate_rejects_sub_quorum::<MinSig>();
    }

    fn verify_certificates_batch<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 54);
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

        let mut rng = StdRng::seed_from_u64(55);
        assert!(verifier.verify_certificates(&mut rng, certs_iter));
    }

    #[test]
    fn test_verify_certificates_batch() {
        verify_certificates_batch::<MinPk>();
        verify_certificates_batch::<MinSig>();
    }

    fn verify_certificates_batch_detects_failure<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 56);
        let quorum = quorum(schemes.len() as u32) as usize;

        let messages = [b"msg1".as_slice(), b"msg2".as_slice()];
        let mut certificates = Vec::new();

        for msg in &messages {
            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| s.sign_vote(NAMESPACE, msg).unwrap())
                .collect();
            certificates.push(schemes[0].assemble_certificate(votes).unwrap());
        }

        // Corrupt second certificate
        certificates[1].signature = schemes[0].sign_vote(NAMESPACE, b"wrong").unwrap().1;

        let certs_iter = messages
            .iter()
            .zip(&certificates)
            .map(|(msg, cert)| (NAMESPACE, *msg, cert));

        let mut rng = StdRng::seed_from_u64(57);
        assert!(!verifier.verify_certificates(&mut rng, certs_iter));
    }

    #[test]
    fn test_verify_certificates_batch_detects_failure() {
        verify_certificates_batch_detects_failure::<MinPk>();
        verify_certificates_batch_detects_failure::<MinSig>();
    }
}
