//! Ed25519 signing scheme implementation.
//!
//! This module provides both the generic Ed25519 implementation and a macro to generate
//! protocol-specific wrappers.
use crate::{
    certificate::{utils::Signers, Context, Scheme, Signature, SignatureVerification},
    ed25519::{self, Batch},
    BatchVerifier, Digest, Signer as _, Verifier as _,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadRangeExt, Write};
use commonware_utils::ordered::{Quorum, Set};
use rand::{CryptoRng, Rng};
use std::collections::BTreeSet;

/// Generic Ed25519 signing scheme implementation.
///
/// This struct contains the core cryptographic operations without protocol-specific
/// context types. It can be reused across different protocols (simplex, aggregation, etc.)
/// by wrapping it with protocol-specific trait implementations via the macro.
#[derive(Clone, Debug)]
pub struct Generic {
    /// Participants in the committee.
    pub participants: Set<ed25519::PublicKey>,
    /// Key used for generating signatures.
    pub signer: Option<(u32, ed25519::PrivateKey)>,
}

impl Generic {
    /// Creates a new generic Ed25519 scheme instance.
    pub fn signer(
        participants: Set<ed25519::PublicKey>,
        private_key: ed25519::PrivateKey,
    ) -> Option<Self> {
        let signer = participants
            .index(&private_key.public_key())
            .map(|index| (index, private_key))?;

        Some(Self {
            participants,
            signer: Some(signer),
        })
    }

    /// Builds a verifier that can authenticate votes without generating signatures.
    pub const fn verifier(participants: Set<ed25519::PublicKey>) -> Self {
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
    pub fn sign_vote<S, D>(
        &self,
        namespace: &[u8],
        context: S::Context<'_, D>,
    ) -> Option<Signature<S>>
    where
        S: Scheme<Signature = ed25519::Signature>,
        D: Digest,
    {
        let (index, private_key) = self.signer.as_ref()?;

        let (namespace, message) = context.namespace_and_message(namespace);
        let signature = private_key.sign(namespace.as_ref(), message.as_ref());

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
        S: Scheme<Signature = ed25519::Signature>,
        D: Digest,
    {
        let Some(public_key) = self.participants.key(signature.signer) else {
            return false;
        };

        let (namespace, message) = context.namespace_and_message(namespace);
        public_key.verify(namespace.as_ref(), message.as_ref(), &signature.signature)
    }

    /// Batch-verifies votes and returns verified votes and invalid signers.
    pub fn verify_votes<S, R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        context: S::Context<'_, D>,
        signatures: I,
    ) -> SignatureVerification<S>
    where
        S: Scheme<Signature = ed25519::Signature>,
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Signature<S>>,
    {
        let (namespace, message) = context.namespace_and_message(namespace);

        let mut invalid = BTreeSet::new();
        let mut candidates = Vec::new();
        let mut batch = Batch::new();

        for sig in signatures.into_iter() {
            let Some(public_key) = self.participants.key(sig.signer) else {
                invalid.insert(sig.signer);
                continue;
            };

            batch.add(
                namespace.as_ref(),
                message.as_ref(),
                public_key,
                &sig.signature,
            );

            candidates.push((sig, public_key));
        }

        if !candidates.is_empty() && !batch.verify(rng) {
            // Batch failed: fall back to per-signer verification to isolate faulty votes.
            for (sig, public_key) in &candidates {
                if !public_key.verify(namespace.as_ref(), message.as_ref(), &sig.signature) {
                    invalid.insert(sig.signer);
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

        SignatureVerification::new(verified, invalid.into_iter().collect())
    }

    /// Assembles a certificate from a collection of votes.
    pub fn assemble_certificate<S, I>(&self, signatures: I) -> Option<Certificate>
    where
        S: Scheme<Signature = ed25519::Signature>,
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
    pub fn verify_certificate<S, R, D>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        context: S::Context<'_, D>,
        certificate: &Certificate,
    ) -> bool
    where
        S: Scheme,
        R: Rng + CryptoRng,
        D: Digest,
    {
        let mut batch = Batch::new();
        if !self.batch_verify_certificate::<S, D>(&mut batch, namespace, context, certificate) {
            return false;
        }

        batch.verify(rng)
    }

    /// Verifies multiple certificates in a batch.
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

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Certificate {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let signers = Signers::arbitrary(u)?;
        let signatures = (0..signers.count())
            .map(|_| u.arbitrary::<ed25519::Signature>())
            .collect::<arbitrary::Result<Vec<_>>>()?;
        Ok(Self {
            signers,
            signatures,
        })
    }
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
                "cryptography::certificate::ed25519::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signatures = Vec::<ed25519::Signature>::read_range(reader, ..=*participants)?;
        if signers.count() != signatures.len() {
            return Err(Error::Invalid(
                "cryptography::certificate::ed25519::Certificate",
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
    /// impl_ed25519_certificate!(VoteContext<'a, D>);
    /// ```
    #[macro_export]
    macro_rules! impl_ed25519_certificate {
        ($context:ty) => {
            /// Ed25519 signing scheme wrapper.
            #[derive(Clone, Debug)]
            pub struct Scheme {
                generic: $crate::certificate::ed25519::Generic,
            }

            impl Scheme {
                /// Creates a new scheme instance with the provided key material.
                ///
                /// Participants use the same key for both identity and consensus.
                ///
                /// If the provided private key does not match any consensus key in the committee,
                /// the instance will act as a verifier (unable to generate signatures).
                ///
                /// Returns `None` if the provided private key does not match any participant
                /// in the committee.
                pub fn signer(
                    participants: commonware_utils::ordered::Set<$crate::ed25519::PublicKey>,
                    private_key: $crate::ed25519::PrivateKey,
                ) -> Option<Self> {
                    Some(Self {
                        generic: $crate::certificate::ed25519::Generic::signer(
                            participants,
                            private_key,
                        )?,
                    })
                }

                /// Builds a verifier that can authenticate votes without generating signatures.
                ///
                /// Participants use the same key for both identity and consensus.
                pub const fn verifier(
                    participants: commonware_utils::ordered::Set<$crate::ed25519::PublicKey>,
                ) -> Self {
                    Self {
                        generic: $crate::certificate::ed25519::Generic::verifier(participants),
                    }
                }
            }

            impl $crate::certificate::Scheme for Scheme {
                type Context<'a, D: $crate::Digest> = $context;
                type PublicKey = $crate::ed25519::PublicKey;
                type Signature = $crate::ed25519::Signature;
                type Certificate = $crate::certificate::ed25519::Certificate;

                fn me(&self) -> Option<u32> {
                    self.generic.me()
                }

                fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
                    &self.generic.participants
                }

                fn sign_vote<D: $crate::Digest>(
                    &self,
                    namespace: &[u8],
                    context: Self::Context<'_, D>,
                ) -> Option<$crate::certificate::Signature<Self>> {
                    self.generic.sign_vote::<_, D>(namespace, context)
                }

                fn verify_vote<D: $crate::Digest>(
                    &self,
                    namespace: &[u8],
                    context: Self::Context<'_, D>,
                    signature: &$crate::certificate::Signature<Self>,
                ) -> bool {
                    self.generic
                        .verify_vote::<_, D>(namespace, context, signature)
                }

                fn verify_votes<R, D, I>(
                    &self,
                    rng: &mut R,
                    namespace: &[u8],
                    context: Self::Context<'_, D>,
                    signatures: I,
                ) -> $crate::certificate::SignatureVerification<Self>
                where
                    R: rand::Rng + rand::CryptoRng,
                    D: $crate::Digest,
                    I: IntoIterator<Item = $crate::certificate::Signature<Self>>,
                {
                    self.generic
                        .verify_votes::<_, _, D, _>(rng, namespace, context, signatures)
                }

                fn assemble_certificate<I>(&self, signatures: I) -> Option<Self::Certificate>
                where
                    I: IntoIterator<Item = $crate::certificate::Signature<Self>>,
                {
                    self.generic.assemble_certificate(signatures)
                }

                fn verify_certificate<R: rand::Rng + rand::CryptoRng, D: $crate::Digest>(
                    &self,
                    rng: &mut R,
                    namespace: &[u8],
                    context: Self::Context<'_, D>,
                    certificate: &Self::Certificate,
                ) -> bool {
                    self.generic.verify_certificate::<Self, _, D>(
                        rng,
                        namespace,
                        context,
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
                    D: $crate::Digest,
                    I: Iterator<Item = (Self::Context<'a, D>, &'a Self::Certificate)>,
                {
                    self.generic
                        .verify_certificates::<Self, _, D, _>(rng, namespace, certificates)
                }

                fn is_attributable(&self) -> bool {
                    self.generic.is_attributable()
                }

                fn certificate_codec_config(
                    &self,
                ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    self.generic.certificate_codec_config()
                }

                fn certificate_codec_config_unbounded(
                ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                    $crate::certificate::ed25519::Generic::certificate_codec_config_unbounded()
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        certificate::Scheme as _,
        ed25519::{PrivateKey, PublicKey},
        impl_ed25519_certificate,
        sha256::Digest as Sha256Digest,
    };
    use commonware_codec::{Decode, Encode};
    use commonware_math::algebra::Random;
    use commonware_utils::{ordered::Set, quorum, TryCollect};
    use rand::{rngs::StdRng, thread_rng, SeedableRng};

    const NAMESPACE: &[u8] = b"test-ed25519";
    const MESSAGE: &[u8] = b"test message";

    /// Test context type for generic scheme tests.
    #[derive(Clone, Debug)]
    pub struct TestContext<'a> {
        pub message: &'a [u8],
    }

    impl<'a> Context for TestContext<'a> {
        fn namespace_and_message(&self, namespace: &[u8]) -> (Vec<u8>, Vec<u8>) {
            (namespace.to_vec(), self.message.to_vec())
        }
    }

    // Use the macro to generate the test scheme
    impl_ed25519_certificate!(TestContext<'a>);

    fn setup_signers(n: u32, seed: u64) -> (Vec<Scheme>, Scheme) {
        let mut rng = StdRng::seed_from_u64(seed);
        let private_keys: Vec<_> = (0..n).map(|_| PrivateKey::random(&mut rng)).collect();
        let participants: Set<PublicKey> = private_keys
            .iter()
            .map(|sk| sk.public_key())
            .try_collect()
            .unwrap();

        let signers = private_keys
            .into_iter()
            .map(|sk| Scheme::signer(participants.clone(), sk).unwrap())
            .collect();

        let verifier = Scheme::verifier(participants);

        (signers, verifier)
    }

    #[test]
    fn test_sign_vote_roundtrip() {
        let (schemes, _) = setup_signers(4, 42);
        let scheme = &schemes[0];

        let signature = scheme
            .sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
            .unwrap();
        assert!(scheme.verify_vote::<Sha256Digest>(
            NAMESPACE,
            TestContext { message: MESSAGE },
            &signature
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

        let signatures: Vec<_> = schemes
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
            signatures.clone(),
        );
        assert!(result.invalid_signers.is_empty());
        assert_eq!(result.verified.len(), quorum);

        // Test 1: Corrupt one vote - invalid signer index
        let mut votes_corrupted = signatures.clone();
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
        let mut votes_corrupted = signatures;
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

        let signatures: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble_certificate(signatures).unwrap();

        // Verify certificate has correct number of signers
        assert_eq!(certificate.signers.count(), quorum);
        assert_eq!(certificate.signatures.len(), quorum);
    }

    #[test]
    fn test_assemble_certificate_sorts_signers() {
        let (schemes, _) = setup_signers(4, 47);

        // Create votes in non-sorted order (indices 2, 0, 1)
        let signatures = vec![
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

        let certificate = schemes[0].assemble_certificate(signatures).unwrap();

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

        let signatures: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble_certificate(signatures).unwrap();

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

        let signatures: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble_certificate(signatures).unwrap();

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

        let signatures: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble_certificate(signatures).unwrap();
        let encoded = certificate.encode();
        let decoded = Certificate::decode_cfg(encoded, &schemes.len()).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_rejects_sub_quorum() {
        let (schemes, _) = setup_signers(4, 52);
        let sub_quorum = 2; // Less than quorum (3)

        let signatures: Vec<_> = schemes
            .iter()
            .take(sub_quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        assert!(schemes[0].assemble_certificate(signatures).is_none());
    }

    #[test]
    fn test_certificate_rejects_invalid_signer() {
        let (schemes, _) = setup_signers(4, 53);
        let quorum = quorum(schemes.len() as u32) as usize;

        let mut signatures: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        // Corrupt signer index to be out of range
        signatures[0].signer = 999;

        assert!(schemes[0].assemble_certificate(signatures).is_none());
    }

    #[test]
    fn test_verify_certificate_rejects_sub_quorum() {
        let (schemes, verifier) = setup_signers(4, 54);
        let participants_len = schemes.len();

        let signatures: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0].assemble_certificate(signatures).unwrap();

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

        let signatures: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0].assemble_certificate(signatures).unwrap();

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
            let signatures: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| {
                    s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: msg })
                        .unwrap()
                })
                .collect();
            certificates.push(schemes[0].assemble_certificate(signatures).unwrap());
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
            let signatures: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| {
                    s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: msg })
                        .unwrap()
                })
                .collect();
            certificates.push(schemes[0].assemble_certificate(signatures).unwrap());
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

    #[test]
    #[should_panic(expected = "duplicate signer index")]
    fn test_assemble_certificate_rejects_duplicate_signers() {
        let (schemes, _) = setup_signers(4, 60);

        let mut signatures: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        // Add a duplicate of the last vote
        signatures.push(signatures.last().unwrap().clone());

        // This should panic due to duplicate signer
        schemes[0].assemble_certificate(signatures);
    }

    #[test]
    fn test_scheme_clone_and_verifier() {
        let (schemes, _) = setup_signers(4, 61);
        let participants = schemes[0].participants().clone();

        // Clone a signer
        let signer = schemes[0].clone();
        assert!(
            signer
                .sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                .is_some(),
            "signer should produce votes"
        );

        // A verifier cannot produce votes
        let verifier = Scheme::verifier(participants);
        assert!(
            verifier
                .sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                .is_none(),
            "verifier should not produce votes"
        );
    }

    #[test]
    fn test_certificate_decode_validation() {
        let (schemes, _) = setup_signers(4, 62);
        let participants_len = schemes.len();

        let signatures: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble_certificate(signatures).unwrap();

        // Well-formed certificate decodes successfully
        let encoded = certificate.encode();
        let decoded =
            Certificate::decode_cfg(encoded, &participants_len).expect("decode certificate");
        assert_eq!(decoded, certificate);

        // Certificate with no signers is rejected
        let empty = Certificate {
            signers: Signers::from(participants_len, std::iter::empty::<u32>()),
            signatures: Vec::new(),
        };
        assert!(Certificate::decode_cfg(empty.encode(), &participants_len).is_err());

        // Certificate with mismatched signature count is rejected
        let mismatched = Certificate {
            signers: Signers::from(participants_len, [0u32, 1]),
            signatures: vec![certificate.signatures[0].clone()],
        };
        assert!(Certificate::decode_cfg(mismatched.encode(), &participants_len).is_err());

        // Certificate containing more signers than the participant set is rejected
        let mut signers = certificate.signers.iter().collect::<Vec<_>>();
        signers.push(participants_len as u32);
        let mut sigs = certificate.signatures.clone();
        sigs.push(certificate.signatures[0].clone());
        let extended = Certificate {
            signers: Signers::from(participants_len + 1, signers),
            signatures: sigs,
        };
        assert!(Certificate::decode_cfg(extended.encode(), &participants_len).is_err());
    }

    #[test]
    fn test_verify_certificate_rejects_unknown_signer() {
        let (schemes, verifier) = setup_signers(4, 63);
        let participants_len = schemes.len();

        let signatures: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0].assemble_certificate(signatures).unwrap();

        // Add an unknown signer (out of range)
        let mut signers: Vec<u32> = certificate.signers.iter().collect();
        signers.push(participants_len as u32);
        certificate.signers = Signers::from(participants_len + 1, signers);
        certificate
            .signatures
            .push(certificate.signatures[0].clone());

        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestContext { message: MESSAGE },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_invalid_certificate_signers_size() {
        let (schemes, verifier) = setup_signers(4, 64);
        let participants_len = schemes.len();

        let signatures: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(NAMESPACE, TestContext { message: MESSAGE })
                    .unwrap()
            })
            .collect();

        let mut certificate = schemes[0].assemble_certificate(signatures).unwrap();

        // Valid certificate passes
        assert!(verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestContext { message: MESSAGE },
            &certificate,
        ));

        // Make the signers bitmap size larger (mismatched with participants)
        let signers: Vec<u32> = certificate.signers.iter().collect();
        certificate.signers = Signers::from(participants_len + 1, signers);

        // Certificate verification should fail due to size mismatch
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            TestContext { message: MESSAGE },
            &certificate,
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Certificate>,
        }
    }
}
