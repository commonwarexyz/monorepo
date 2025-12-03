//! Ed25519 signing scheme implementation.
//!
//! This module provides both the raw Ed25519 implementation and a macro to generate
//! protocol-specific wrappers.
use crate::signing_scheme::{utils::Signers, Context, Scheme, Vote, VoteVerification};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadRangeExt, Write};
use commonware_cryptography::{
    ed25519::{self, Batch},
    BatchVerifier, Digest, Signer as _, Verifier as _,
};
use commonware_utils::set::{Ordered, OrderedQuorum};
use rand::{CryptoRng, Rng};
use std::collections::BTreeSet;

/// Raw Ed25519 signing scheme that operates on raw bytes.
///
/// This module contains the core cryptographic operations without protocol-specific
/// context types. It can be reused across different protocols (simplex, aggregation, etc.)
/// by wrapping it with protocol-specific trait implementations.
/// Core Ed25519 signing scheme implementation.
#[derive(Clone, Debug)]
pub struct Ed25519 {
    /// Participants in the committee.
    pub participants: Ordered<ed25519::PublicKey>,
    /// Key used for generating signatures.
    pub signer: Option<(u32, ed25519::PrivateKey)>,
}

impl Ed25519 {
    /// Creates a new raw Ed25519 scheme instance.
    pub fn new(
        participants: Ordered<ed25519::PublicKey>,
        private_key: ed25519::PrivateKey,
    ) -> Self {
        let signer = participants
            .index(&private_key.public_key())
            .map(|index| (index, private_key));

        Self {
            participants,
            signer,
        }
    }

    /// Builds a verifier that can authenticate votes without generating signatures.
    pub const fn verifier(participants: Ordered<ed25519::PublicKey>) -> Self {
        Self {
            participants,
            signer: None,
        }
    }

    /// Returns the index of "self" in the participant set, if available.
    pub fn me(&self) -> Option<u32> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    /// Signs a message and returns the signer index and signature.
    pub fn sign_vote<S, D>(&self, namespace: &[u8], context: S::Context<'_, D>) -> Option<Vote<S>>
    where
        S: Scheme<Signature = ed25519::Signature>,
        D: Digest,
    {
        let (index, private_key) = self.signer.as_ref()?;

        let (namespace, message) = context.namespace_and_message(namespace);
        let signature = private_key.sign(namespace.as_ref(), message.as_ref());

        Some(Vote {
            signer: *index,
            signature,
        })
    }

    /// Verifies a single vote from a signer.
    pub fn verify_vote<S, D>(
        &self,
        namespace: &[u8],
        context: S::Context<'_, D>,
        vote: &Vote<S>,
    ) -> bool
    where
        S: Scheme<Signature = ed25519::Signature>,
        D: Digest,
    {
        let Some(public_key) = self.participants.key(vote.signer) else {
            return false;
        };

        let (namespace, message) = context.namespace_and_message(namespace);
        public_key.verify(namespace.as_ref(), message.as_ref(), &vote.signature)
    }

    /// Batch-verifies votes and returns verified votes and invalid signers.
    pub fn verify_votes<S, R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        context: S::Context<'_, D>,
        votes: I,
    ) -> VoteVerification<S>
    where
        S: Scheme<Signature = ed25519::Signature>,
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Vote<S>>,
    {
        let (namespace, message) = context.namespace_and_message(namespace);

        let mut invalid = BTreeSet::new();
        let mut candidates = Vec::new();
        let mut batch = Batch::new();

        for vote in votes.into_iter() {
            let Some(public_key) = self.participants.key(vote.signer) else {
                invalid.insert(vote.signer);
                continue;
            };

            batch.add(
                namespace.as_ref(),
                message.as_ref(),
                public_key,
                &vote.signature,
            );

            candidates.push((vote, public_key));
        }

        if !candidates.is_empty() && !batch.verify(rng) {
            // Batch failed: fall back to per-signer verification to isolate faulty votes.
            for (vote, public_key) in &candidates {
                if !public_key.verify(namespace.as_ref(), message.as_ref(), &vote.signature) {
                    invalid.insert(vote.signer);
                }
            }
        }

        let verified = candidates
            .into_iter()
            .filter_map(|(vote, _)| {
                if invalid.contains(&vote.signer) {
                    None
                } else {
                    Some(vote)
                }
            })
            .collect();

        VoteVerification::new(verified, invalid.into_iter().collect())
    }

    /// Assembles a certificate from a collection of votes.
    pub fn assemble_certificate<S, I>(&self, votes: I) -> Option<Certificate>
    where
        S: Scheme<Signature = ed25519::Signature>,
        I: IntoIterator<Item = Vote<S>>,
    {
        // Collect the signers and signatures.
        let mut entries = Vec::new();
        for Vote { signer, signature } in votes {
            if signer as usize >= self.participants.len() {
                return None;
            }

            entries.push((signer, signature));
        }
        if entries.len() < self.participants.quorum() as usize {
            return None;
        }

        // Sort the signatures by signer index.
        entries.sort_by_key(|(signer, _)| *signer);
        let (signer, signatures): (Vec<u32>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::from(self.participants.len(), signer);

        Some(Certificate {
            signers,
            signatures,
        })
    }

    /// Stages a certificate for batch verification.
    ///
    /// Returns false if the certificate structure is invalid.
    pub fn batch_verify_certificate<S, D>(
        &self,
        batch: &mut Batch,
        namespace: &[u8],
        context: S::Context<'_, D>,
        certificate: &Certificate,
    ) -> bool
    where
        S: Scheme,
        D: Digest,
    {
        // If the certificate signers length does not match the participant set, return false.
        if certificate.signers.len() != self.participants.len() {
            return false;
        }

        // If the certificate signers and signatures counts differ, return false.
        if certificate.signers.count() != certificate.signatures.len() {
            return false;
        }

        // If the certificate does not meet the quorum, return false.
        if certificate.signers.count() < self.participants.quorum() as usize {
            return false;
        }

        // Add the certificate to the batch.
        let (namespace, message) = context.namespace_and_message(namespace);
        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            let Some(public_key) = self.participants.key(signer) else {
                return false;
            };

            batch.add(namespace.as_ref(), message.as_ref(), public_key, signature);
        }

        true
    }

    /// Verifies a certificate.
    pub fn verify_certificate<S, D, R>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        context: S::Context<'_, D>,
        certificate: &Certificate,
    ) -> bool
    where
        S: Scheme,
        D: Digest,
        R: Rng + CryptoRng,
    {
        let mut batch = Batch::new();
        if !self.batch_verify_certificate::<S, D>(&mut batch, namespace, context, certificate) {
            return false;
        }

        batch.verify(rng)
    }

    /// Verifies multiple certificates in a batch.
    pub fn verify_certificates<'a, S, D, R, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        certificates: I,
    ) -> bool
    where
        S: Scheme,
        D: Digest,
        R: Rng + CryptoRng,
        I: Iterator<Item = (S::Context<'a, D>, &'a Certificate)>,
    {
        let mut batch = Batch::new();
        for (context, certificate) in certificates {
            if !self.batch_verify_certificate::<S, D>(&mut batch, namespace, context, certificate) {
                return false;
            }
        }

        batch.verify(rng)
    }

    pub const fn is_attributable(&self) -> bool {
        true
    }

    pub const fn certificate_codec_config(&self) -> <Certificate as commonware_codec::Read>::Cfg {
        self.participants.len()
    }

    pub const fn certificate_codec_config_unbounded() -> <Certificate as commonware_codec::Read>::Cfg
    {
        u32::MAX as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    /// Bitmap of validator indices that contributed signatures.
    pub signers: Signers,
    /// Ed25519 signatures emitted by the respective validators ordered by signer index.
    pub signatures: Vec<ed25519::Signature>,
}

impl Write for Certificate {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.signatures.write(writer);
    }
}

impl EncodeSize for Certificate {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.signatures.encode_size()
    }
}

impl Read for Certificate {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, Error> {
        let signers = Signers::read_cfg(reader, participants)?;
        if signers.count() == 0 {
            return Err(Error::Invalid(
                "consensus::signing_scheme::ed25519::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signatures = Vec::<ed25519::Signature>::read_range(reader, ..=*participants)?;
        if signers.count() != signatures.len() {
            return Err(Error::Invalid(
                "consensus::signing_scheme::ed25519::Certificate",
                "Signers and signatures counts differ",
            ));
        }

        Ok(Self {
            signers,
            signatures,
        })
    }
}

mod macros {
    /// Generates an Ed25519 signing scheme wrapper for a specific protocol.
    ///
    /// This macro creates a complete wrapper struct with constructors and `Scheme` trait implementation.
    /// The only required parameter is the `Context` type, which varies per protocol.
    ///
    /// # Example
    /// ```ignore
    /// impl_ed25519_scheme!(VoteContext<'a, D>);
    /// ```
    #[macro_export]
    macro_rules! impl_ed25519_scheme {
        ($context:ty) => {
            /// Ed25519 signing scheme wrapper.
            #[derive(Clone, Debug)]
            pub struct Scheme {
                raw: $crate::signing_scheme::ed25519::Ed25519,
            }

            impl Scheme {
                /// Creates a new scheme instance with the provided key material.
                ///
                /// Participants use the same key for both identity and consensus.
                ///
                /// If the provided private key does not match any consensus key in the committee,
                /// the instance will act as a verifier (unable to generate signatures).
                pub fn new(
                    participants: commonware_utils::set::Ordered<
                        commonware_cryptography::ed25519::PublicKey,
                    >,
                    private_key: commonware_cryptography::ed25519::PrivateKey,
                ) -> Self {
                    Self {
                        raw: $crate::signing_scheme::ed25519::Ed25519::new(
                            participants,
                            private_key,
                        ),
                    }
                }

                /// Builds a verifier that can authenticate votes without generating signatures.
                ///
                /// Participants use the same key for both identity and consensus.
                pub const fn verifier(
                    participants: commonware_utils::set::Ordered<
                        commonware_cryptography::ed25519::PublicKey,
                    >,
                ) -> Self {
                    Self {
                        raw: $crate::signing_scheme::ed25519::Ed25519::verifier(participants),
                    }
                }
            }

            impl $crate::signing_scheme::Scheme for Scheme {
                type Context<'a, D: commonware_cryptography::Digest> = $context;
                type PublicKey = commonware_cryptography::ed25519::PublicKey;
                type Signature = commonware_cryptography::ed25519::Signature;
                type Certificate = $crate::signing_scheme::ed25519::Certificate;

                fn me(&self) -> Option<u32> {
                    self.raw.me()
                }

                fn participants(&self) -> &commonware_utils::set::Ordered<Self::PublicKey> {
                    &self.raw.participants
                }

                fn sign_vote<D: commonware_cryptography::Digest>(
                    &self,
                    namespace: &[u8],
                    context: Self::Context<'_, D>,
                ) -> Option<$crate::signing_scheme::Vote<Self>> {
                    self.raw.sign_vote(namespace, context)
                }

                fn verify_vote<D: commonware_cryptography::Digest>(
                    &self,
                    namespace: &[u8],
                    context: Self::Context<'_, D>,
                    vote: &$crate::signing_scheme::Vote<Self>,
                ) -> bool {
                    self.raw.verify_vote(namespace, context, vote)
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
                    self.raw.verify_votes(rng, namespace, context, votes)
                }

                fn assemble_certificate<I>(&self, votes: I) -> Option<Self::Certificate>
                where
                    I: IntoIterator<Item = $crate::signing_scheme::Vote<Self>>,
                {
                    self.raw.assemble_certificate(votes)
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
                    self.raw
                        .verify_certificate::<Self, _, _>(rng, namespace, context, certificate)
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
                    self.raw
                        .verify_certificates::<Self, _, _, _>(rng, namespace, certificates)
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
                    $crate::signing_scheme::ed25519::Ed25519::certificate_codec_config_unbounded()
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        PrivateKeyExt,
    };
    use commonware_utils::{quorum, set::Ordered};
    use rand::{rngs::StdRng, thread_rng, SeedableRng};
    use std::marker::PhantomData;

    const NAMESPACE: &[u8] = b"test-ed25519";
    const MESSAGE: &[u8] = b"test message";

    #[derive(Clone, Debug)]
    struct TestContext<'a> {
        message: &'a [u8],
    }

    impl<'a> Context for TestContext<'a> {
        fn namespace_and_message(&self, namespace: &[u8]) -> (Vec<u8>, Vec<u8>) {
            (namespace.to_vec(), self.message.to_vec())
        }
    }

    #[derive(Clone, Debug)]
    struct TestScheme {
        raw: super::Ed25519,
        _pd: PhantomData<()>,
    }

    impl TestScheme {
        fn new(participants: Ordered<PublicKey>, private_key: PrivateKey) -> Self {
            Self {
                raw: super::Ed25519::new(participants, private_key),
                _pd: PhantomData,
            }
        }

        fn verifier(participants: Ordered<PublicKey>) -> Self {
            Self {
                raw: super::Ed25519::verifier(participants),
                _pd: PhantomData,
            }
        }
    }

    impl Scheme for TestScheme {
        type Context<'a, D: commonware_cryptography::Digest> = TestContext<'a>;
        type PublicKey = PublicKey;
        type Signature = commonware_cryptography::ed25519::Signature;
        type Certificate = Certificate;

        fn me(&self) -> Option<u32> {
            self.raw.me()
        }

        fn participants(&self) -> &Ordered<Self::PublicKey> {
            &self.raw.participants
        }

        fn sign_vote<D: commonware_cryptography::Digest>(
            &self,
            namespace: &[u8],
            context: Self::Context<'_, D>,
        ) -> Option<Vote<Self>> {
            self.raw.sign_vote::<Self, D>(namespace, context)
        }

        fn verify_vote<D: commonware_cryptography::Digest>(
            &self,
            namespace: &[u8],
            context: Self::Context<'_, D>,
            vote: &Vote<Self>,
        ) -> bool {
            self.raw.verify_vote::<Self, D>(namespace, context, vote)
        }

        fn verify_votes<R, D, I>(
            &self,
            rng: &mut R,
            namespace: &[u8],
            context: Self::Context<'_, D>,
            votes: I,
        ) -> VoteVerification<Self>
        where
            R: rand::Rng + rand::CryptoRng,
            D: commonware_cryptography::Digest,
            I: IntoIterator<Item = Vote<Self>>,
        {
            self.raw
                .verify_votes::<Self, R, D, I>(rng, namespace, context, votes)
        }

        fn assemble_certificate<I>(&self, votes: I) -> Option<Self::Certificate>
        where
            I: IntoIterator<Item = Vote<Self>>,
        {
            self.raw.assemble_certificate::<Self, I>(votes)
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
            self.raw
                .verify_certificate::<Self, D, R>(rng, namespace, context, certificate)
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
            self.raw
                .verify_certificates::<Self, D, R, I>(rng, namespace, certificates)
        }

        fn is_attributable(&self) -> bool {
            self.raw.is_attributable()
        }

        fn certificate_codec_config(&self) -> <Self::Certificate as commonware_codec::Read>::Cfg {
            self.raw.certificate_codec_config()
        }

        fn certificate_codec_config_unbounded() -> <Self::Certificate as commonware_codec::Read>::Cfg
        {
            super::Ed25519::certificate_codec_config_unbounded()
        }
    }

    fn setup_signers(n: u32, seed: u64) -> (Vec<TestScheme>, TestScheme) {
        let mut rng = StdRng::seed_from_u64(seed);
        let private_keys: Vec<_> = (0..n).map(|_| PrivateKey::from_rng(&mut rng)).collect();
        let participants: Ordered<PublicKey> =
            private_keys.iter().map(|sk| sk.public_key()).collect();

        let signers = private_keys
            .into_iter()
            .map(|sk| TestScheme::new(participants.clone(), sk))
            .collect();

        let verifier = TestScheme::verifier(participants);

        (signers, verifier)
    }

    #[test]
    fn test_sign_vote_roundtrip() {
        let (schemes, _) = setup_signers(4, 42);
        let scheme = &schemes[0];

        let vote = scheme
            .sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
            .unwrap();
        assert!(scheme.verify_vote::<Sha256Digest>(
            NAMESPACE,
            TestContext { message: MESSAGE },
            &vote
        ));
    }

    #[test]
    fn test_verifier_cannot_sign() {
        let (_, verifier) = setup_signers(4, 43);
        assert!(verifier
            .sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
            .is_none());
    }

    #[test]
    fn test_verify_votes_filters_invalid() {
        let (schemes, _) = setup_signers(5, 44);
        let quorum = quorum(schemes.len() as u32) as usize;

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut rng = StdRng::seed_from_u64(45);
        let result = schemes[0].verify_votes::<_, Sha256Digest, _>(
            &mut rng,
            NAMESPACE,
            TestContext { message: MESSAGE },
            votes.clone(),
        );
        assert!(result.invalid_signers.is_empty());
        assert_eq!(result.verified.len(), quorum);

        // Test 1: Corrupt one vote - invalid signer index
        let mut votes_corrupted = votes.clone();
        votes_corrupted[0].signer = 999;
        let result = schemes[0].verify_votes::<_, Sha256Digest, _>(
            &mut rng,
            NAMESPACE,
            TestContext { message: MESSAGE },
            votes_corrupted,
        );
        assert_eq!(result.invalid_signers, vec![999]);
        assert_eq!(result.verified.len(), quorum - 1);

        // Test 2: Corrupt one vote - invalid signature
        let mut votes_corrupted = votes;
        votes_corrupted[0].signature = votes_corrupted[1].signature.clone();
        let result = schemes[0].verify_votes::<_, Sha256Digest, _>(
            &mut rng,
            NAMESPACE,
            TestContext { message: MESSAGE },
            votes_corrupted,
        );
        // Batch verification may detect either signer 0 (wrong sig) or signer 1 (duplicate sig)
        assert_eq!(result.invalid_signers.len(), 1);
        assert_eq!(result.verified.len(), quorum - 1);
    }

    #[test]
    fn test_assemble_certificate() {
        let (schemes, _) = setup_signers(4, 46);
        let quorum = quorum(schemes.len() as u32) as usize;

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble_certificate(votes).unwrap();

        // Verify certificate has correct number of signers
        assert_eq!(certificate.signers.count(), quorum);
        assert_eq!(certificate.signatures.len(), quorum);
    }

    #[test]
    fn test_assemble_certificate_sorts_signers() {
        let (schemes, _) = setup_signers(4, 47);

        // Create votes in non-sorted order (indices 2, 0, 1)
        let votes = vec![
            schemes[2]
                .sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                .unwrap(),
            schemes[0]
                .sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                .unwrap(),
            schemes[1]
                .sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                .unwrap(),
        ];

        let certificate = schemes[0].assemble_certificate(votes).unwrap();

        // Verify signers are sorted
        assert_eq!(
            certificate.signers.iter().collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn test_verify_certificate() {
        let (schemes, verifier) = setup_signers(4, 48);
        let quorum = quorum(schemes.len() as u32) as usize;

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble_certificate(votes).unwrap();

        let mut rng = StdRng::seed_from_u64(49);
        assert!(verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            NAMESPACE,
            TestContext { message: MESSAGE },
            &certificate
        ));
    }

    #[test]
    fn test_verify_certificate_detects_corruption() {
        let (schemes, verifier) = setup_signers(4, 50);
        let quorum = quorum(schemes.len() as u32) as usize;

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble_certificate(votes).unwrap();

        // Valid certificate passes
        assert!(verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestContext { message: MESSAGE },
            &certificate
        ));

        // Corrupted certificate fails
        let mut corrupted = certificate;
        corrupted.signatures[0] = corrupted.signatures[1].clone();
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestContext { message: MESSAGE },
            &corrupted
        ));
    }

    #[test]
    fn test_certificate_codec_roundtrip() {
        let (schemes, _) = setup_signers(4, 51);
        let quorum = quorum(schemes.len() as u32) as usize;

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble_certificate(votes).unwrap();
        let encoded = certificate.encode();
        let decoded = Certificate::decode_cfg(encoded, &schemes.len()).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_rejects_sub_quorum() {
        let (schemes, _) = setup_signers(4, 52);
        let sub_quorum = 2; // Less than quorum (3)

        let votes: Vec<_> = schemes
            .iter()
            .take(sub_quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        assert!(schemes[0].assemble_certificate(votes).is_none());
    }

    #[test]
    fn test_certificate_rejects_invalid_signer() {
        let (schemes, _) = setup_signers(4, 53);
        let quorum = quorum(schemes.len() as u32) as usize;

        let mut votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        // Corrupt signer index to be out of range
        votes[0].signer = 999;

        assert!(schemes[0].assemble_certificate(votes).is_none());
    }

    #[test]
    fn test_verify_certificate_rejects_sub_quorum() {
        let (schemes, verifier) = setup_signers(4, 54);
        let participants_len = schemes.len();

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0].assemble_certificate(votes).unwrap();

        // Artificially truncate to below quorum
        let mut signers: Vec<u32> = certificate.signers.iter().collect();
        signers.pop();
        certificate.signers = Signers::from(participants_len, signers);
        certificate.signatures.pop();

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestContext { message: MESSAGE },
            &certificate
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_mismatched_signature_count() {
        let (schemes, verifier) = setup_signers(4, 55);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0].assemble_certificate(votes).unwrap();

        // Remove one signature but keep signers bitmap unchanged
        certificate.signatures.pop();

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestContext { message: MESSAGE },
            &certificate
        ));
    }

    #[test]
    fn test_verify_certificates_batch() {
        let (schemes, verifier) = setup_signers(4, 56);
        let quorum = quorum(schemes.len() as u32) as usize;

        let messages = [b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];
        let mut certificates = Vec::new();

        for msg in &messages {
            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| {
                    s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: msg })
                        .unwrap()
                })
                .collect();
            certificates.push(schemes[0].assemble_certificate(votes).unwrap());
        }

        let certs_iter = messages
            .iter()
            .zip(&certificates)
            .map(|(msg, cert)| (TestContext { message: msg }, cert));

        let mut rng = StdRng::seed_from_u64(57);
        assert!(verifier.verify_certificates::<_, Sha256Digest, _>(&mut rng, NAMESPACE, certs_iter));
    }

    #[test]
    fn test_verify_certificates_batch_detects_failure() {
        let (schemes, verifier) = setup_signers(4, 58);
        let quorum = quorum(schemes.len() as u32) as usize;

        let messages = [b"msg1".as_slice(), b"msg2".as_slice()];
        let mut certificates = Vec::new();

        for msg in &messages {
            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| {
                    s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: msg })
                        .unwrap()
                })
                .collect();
            certificates.push(schemes[0].assemble_certificate(votes).unwrap());
        }

        // Corrupt second certificate
        certificates[1].signatures[0] = certificates[1].signatures[1].clone();

        let certs_iter = messages
            .iter()
            .zip(&certificates)
            .map(|(msg, cert)| (TestContext { message: msg }, cert));

        let mut rng = StdRng::seed_from_u64(59);
        assert!(
            !verifier.verify_certificates::<_, Sha256Digest, _>(&mut rng, NAMESPACE, certs_iter)
        );
    }
}

#[cfg(test)]
mod simplex_tests {
    use super::*;
    use crate::{
        signing_scheme::Scheme as SchemeTrait,
        simplex::{
            mocks::fixtures::{ed25519, Fixture},
            signing_scheme::ed25519::Scheme,
            types::{Proposal, VoteContext},
        },
        types::Round,
    };
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Hasher, Sha256};
    use commonware_utils::quorum;
    use rand::{
        rngs::{OsRng, StdRng},
        thread_rng, SeedableRng,
    };

    const NAMESPACE: &[u8] = b"ed25519-signing-scheme";

    fn setup_signers(
        n: u32,
        seed: u64,
    ) -> (
        Vec<Scheme>,
        Ordered<commonware_cryptography::ed25519::PublicKey>,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519(&mut rng, n);

        (schemes, participants.into())
    }

    fn sample_proposal(round: u64, view: u64, tag: u8) -> Proposal<Sha256Digest> {
        use crate::types::{Epoch, View};
        Proposal::new(
            Round::new(Epoch::new(round), View::new(view)),
            View::new(view.saturating_sub(1)),
            Sha256::hash(&[tag]),
        )
    }

    #[test]
    fn test_sign_vote_roundtrip_for_each_context() {
        let (schemes, _) = setup_signers(4, 42);
        let scheme = &schemes[0];

        let proposal = sample_proposal(0, 2, 1);
        let vote = scheme
            .sign_vote(
                NAMESPACE,
                VoteContext::Notarize {
                    proposal: &proposal,
                },
            )
            .unwrap();
        assert!(scheme.verify_vote(
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
            &vote
        ));

        let vote = scheme
            .sign_vote::<Sha256Digest>(
                NAMESPACE,
                VoteContext::Nullify {
                    round: proposal.round,
                },
            )
            .unwrap();
        assert!(scheme.verify_vote::<Sha256Digest>(
            NAMESPACE,
            VoteContext::Nullify {
                round: proposal.round,
            },
            &vote
        ));

        let vote = scheme
            .sign_vote(
                NAMESPACE,
                VoteContext::Finalize {
                    proposal: &proposal,
                },
            )
            .unwrap();
        assert!(scheme.verify_vote(
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &vote
        ));
    }

    #[test]
    fn test_verify_votes_filters_bad_signers() {
        let (schemes, _) = setup_signers(5, 42);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 5, 3);

        let mut votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let scheme = &schemes[0];
        let verification = scheme.verify_votes(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
            votes.clone(),
        );
        assert!(verification.invalid_signers.is_empty());
        assert_eq!(verification.verified.len(), quorum);

        // Invalid signer index should be detected.
        votes[0].signer = 999;
        let verification = scheme.verify_votes(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
            votes.clone(),
        );
        assert_eq!(verification.invalid_signers, vec![999]);
        assert_eq!(verification.verified.len(), quorum - 1);

        // Invalid signature should be detected.
        votes[0].signer = 0;
        votes[0].signature = votes[1].signature.clone();
        let verification = scheme.verify_votes(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
            votes,
        );
        assert_eq!(verification.invalid_signers, vec![0]);
        assert_eq!(verification.verified.len(), quorum - 1);
    }

    #[test]
    fn test_assemble_certificate_sorts_signers() {
        let (schemes, _) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 7, 4);

        let votes = [
            schemes[2]
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Finalize {
                        proposal: &proposal,
                    },
                )
                .unwrap(),
            schemes[0]
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Finalize {
                        proposal: &proposal,
                    },
                )
                .unwrap(),
            schemes[1]
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Finalize {
                        proposal: &proposal,
                    },
                )
                .unwrap(),
        ];

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");
        assert_eq!(
            certificate.signers.iter().collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn test_assemble_certificate_requires_quorum() {
        let (schemes, _) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 9, 5);

        let votes: Vec<_> = schemes
            .iter()
            .take(2)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        assert!(schemes[0].assemble_certificate(votes).is_none());
    }

    #[test]
    fn test_assemble_certificate_rejects_out_of_range_signer() {
        let (schemes, _) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 13, 7);

        let mut votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();
        votes[0].signer = 42;

        assert!(schemes[0].assemble_certificate(votes).is_none());
    }

    #[test]
    #[should_panic(expected = "duplicate signer index: 2")]
    fn test_assemble_certificate_rejects_duplicate_signers() {
        let (schemes, _) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 25, 13);

        let mut votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        votes.push(votes.last().unwrap().clone());

        schemes[0].assemble_certificate(votes);
    }

    #[test]
    fn test_verify_certificate_detects_corruption() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 15, 8);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        let verifier = Scheme::verifier(participants);
        assert!(verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));

        let mut corrupted = certificate;
        corrupted.signatures[0] = corrupted.signatures[1].clone();
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &corrupted,
        ));
    }

    #[test]
    fn test_certificate_codec_roundtrip() {
        let (schemes, _) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 17, 9);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");
        let encoded = certificate.encode();
        let decoded = Certificate::decode_cfg(encoded, &schemes.len()).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_scheme_clone_and_verifier() {
        let (schemes, participants) = setup_signers(4, 42);
        let signer = schemes[0].clone();
        let proposal = sample_proposal(0, 21, 11);

        assert!(
            signer
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
                        proposal: &proposal,
                    },
                )
                .is_some(),
            "signer should produce votes"
        );

        let verifier = Scheme::verifier(participants);
        assert!(
            verifier
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
                        proposal: &proposal,
                    },
                )
                .is_none(),
            "verifier should not produce votes"
        );
    }

    #[test]
    fn test_certificate_decode_validation() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 19, 10);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        // Well-formed certificate decodes successfully.
        let encoded = certificate.encode();
        let mut cursor = &encoded[..];
        let decoded =
            Certificate::read_cfg(&mut cursor, &participants.len()).expect("decode certificate");
        assert_eq!(decoded, certificate);

        // Certificate with no signers is rejected.
        let empty = Certificate {
            signers: Signers::from(participants.len(), std::iter::empty::<u32>()),
            signatures: Vec::new(),
        };
        assert!(Certificate::decode_cfg(empty.encode(), &participants.len()).is_err());

        // Certificate with mismatched signature count is rejected.
        let mismatched = Certificate {
            signers: Signers::from(participants.len(), [0u32, 1]),
            signatures: vec![certificate.signatures[0].clone()],
        };
        assert!(Certificate::decode_cfg(mismatched.encode(), &participants.len()).is_err());

        // Certificate containing more signers than the participant set is rejected.
        let mut signers = certificate.signers.iter().collect::<Vec<_>>();
        signers.push(participants.len() as u32);
        let mut signatures = certificate.signatures.clone();
        signatures.push(certificate.signatures[0].clone());
        let extended = Certificate {
            signers: Signers::from(participants.len() + 1, signers),
            signatures,
        };
        assert!(Certificate::decode_cfg(extended.encode(), &participants.len()).is_err());
    }

    #[test]
    fn test_verify_certificate() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 21, 11);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum(schemes.len() as u32) as usize)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        let verifier = Scheme::verifier(participants);
        assert!(verifier.verify_certificate(
            &mut OsRng,
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_sub_quorum() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 23, 12);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        let mut truncated = certificate;
        let mut signers: Vec<u32> = truncated.signers.iter().collect();
        signers.pop();
        truncated.signers = Signers::from(participants.len(), signers);
        truncated.signatures.pop();

        let verifier = Scheme::verifier(participants);
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &truncated,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_unknown_signer() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 25, 13);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        let mut signers: Vec<u32> = certificate.signers.iter().collect();
        signers.push(participants.len() as u32);
        certificate.signers = Signers::from(participants.len() + 1, signers);
        certificate
            .signatures
            .push(certificate.signatures[0].clone());

        let verifier = Scheme::verifier(participants);
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_invalid_certificate_signers_size() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 26, 14);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        // The certificate is valid
        let verifier = Scheme::verifier(participants.clone());
        assert!(verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));

        // Make the signers bitmap size smaller
        let signers: Vec<u32> = certificate.signers.iter().collect();
        certificate.signers = Signers::from(participants.len() - 1, signers);

        // The certificate verification should fail
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_mismatched_signature_count() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 27, 14);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");
        certificate.signatures.pop();

        let verifier = Scheme::verifier(participants);
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificates_batch_detects_failure() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal_a = sample_proposal(0, 23, 12);
        let proposal_b = sample_proposal(1, 24, 13);

        let votes_a: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
                            proposal: &proposal_a,
                        },
                    )
                    .unwrap()
            })
            .collect();
        let votes_b: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal_b,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate_a = schemes[0]
            .assemble_certificate(votes_a)
            .expect("assemble certificate");
        let mut bad_certificate = schemes[0]
            .assemble_certificate(votes_b)
            .expect("assemble certificate");
        bad_certificate.signatures[0] = bad_certificate.signatures[1].clone();

        let verifier = Scheme::verifier(participants);
        let mut iter = [
            (
                VoteContext::Notarize {
                    proposal: &proposal_a,
                },
                &certificate_a,
            ),
            (
                VoteContext::Finalize {
                    proposal: &proposal_b,
                },
                &bad_certificate,
            ),
        ]
        .into_iter();

        assert!(!verifier.verify_certificates(&mut thread_rng(), NAMESPACE, &mut iter));
    }
}
