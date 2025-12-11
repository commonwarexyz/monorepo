use crate::types::Epoch;
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, CodecFixed, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{Digest, PublicKey};
use commonware_utils::ordered::Set;
use rand::{CryptoRng, Rng};
use std::{collections::BTreeSet, fmt::Debug, hash::Hash, sync::Arc};

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;
pub mod utils;

pub use crate::{
    impl_bls12381_multisig_scheme, impl_bls12381_threshold_scheme, impl_ed25519_scheme,
};

/// Signed vote emitted by a participant.
#[derive(Clone, Debug)]
pub struct Signature<S: Scheme> {
    /// Index of the signer inside the participant set.
    pub signer: u32,
    /// Scheme-specific signature or share produced for the vote context.
    pub signature: S::Signature,
}

impl<S: Scheme> PartialEq for Signature<S> {
    fn eq(&self, other: &Self) -> bool {
        self.signer == other.signer && self.signature == other.signature
    }
}

impl<S: Scheme> Eq for Signature<S> {}

impl<S: Scheme> Hash for Signature<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.signer.hash(state);
        self.signature.hash(state);
    }
}

impl<S: Scheme> Write for Signature<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signer.write(writer);
        self.signature.write(writer);
    }
}

impl<S: Scheme> EncodeSize for Signature<S> {
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.signature.encode_size()
    }
}

impl<S: Scheme> Read for Signature<S> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let signer = u32::read(reader)?;
        let signature = S::Signature::read(reader)?;

        Ok(Self { signer, signature })
    }
}

/// Result of verifying a batch of signatures.
pub struct SignatureVerification<S: Scheme> {
    /// Contains the signatures accepted by the scheme.
    pub verified: Vec<Signature<S>>,
    /// Identifies the participant indices rejected during batch verification.
    pub invalid_signers: Vec<u32>,
}

impl<S: Scheme> SignatureVerification<S> {
    /// Creates a new `VoteVerification` result.
    pub const fn new(verified: Vec<Signature<S>>, invalid_signers: Vec<u32>) -> Self {
        Self {
            verified,
            invalid_signers,
        }
    }
}

pub trait Context: Clone + Debug + Send + Sync {
    fn namespace_and_message(&self, namespace: &[u8]) -> (Vec<u8>, Vec<u8>);
}

/// Cryptographic surface required by `simplex`.
///
/// A `Scheme` produces validator votes, validates them (individually or in batches), assembles
/// quorum certificates, checks recovered certificates and, when available, derives a randomness
/// seed for leader rotation. Implementations may override the provided defaults to take advantage
/// of scheme-specific batching strategies.
///
/// # Identity Keys vs Consensus Keys
///
/// A participant may supply both an identity key and a consensus key. The identity key
/// is used for assigning a unique order to the committee and authenticating connections whereas the consensus key
/// is used for actually signing and verifying votes/certificates.
///
/// This flexibility is supported because some cryptographic schemes are only performant when used in batch verification
/// (like [bls12381_multisig]) and/or are refreshed frequently (like [bls12381_threshold]). Refer to [ed25519]
/// for an example of a scheme that uses the same key for both purposes.
pub trait Scheme: Clone + Debug + Send + Sync + 'static {
    /// Context type for signing and verifying votes.
    type Context<'a, D: Digest>: Context;

    /// Public key type for participant identity used to order and index the committee.
    type PublicKey: PublicKey;
    /// Vote signature emitted by individual validators.
    type Signature: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + CodecFixed<Cfg = ()>;
    /// Quorum certificate recovered from a set of votes.
    type Certificate: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + Codec;

    /// Returns the index of "self" in the participant set, if available.
    /// Returns `None` if the scheme is a verifier-only instance.
    fn me(&self) -> Option<u32>;

    /// Returns the ordered set of participant public identity keys managed by the scheme.
    fn participants(&self) -> &Set<Self::PublicKey>;

    /// Signs a vote for the given context using the supplied namespace for domain separation.
    /// Returns `None` if the scheme cannot sign (e.g. it's a verifier-only instance).
    fn sign_vote<D: Digest>(
        &self,
        namespace: &[u8],
        context: Self::Context<'_, D>,
    ) -> Option<Signature<Self>>;

    /// Verifies a single vote against the participant material managed by the scheme.
    fn verify_vote<D: Digest>(
        &self,
        namespace: &[u8],
        context: Self::Context<'_, D>,
        signature: &Signature<Self>,
    ) -> bool;

    /// Batch-verifies votes and separates valid messages from the voter indices that failed
    /// verification.
    ///
    /// Callers must not include duplicate votes from the same signer.
    fn verify_votes<R, D, I>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        context: Self::Context<'_, D>,
        signatures: I,
    ) -> SignatureVerification<Self>
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Signature<Self>>,
    {
        let mut invalid = BTreeSet::new();

        let verified = signatures.into_iter().filter_map(|vote| {
            if self.verify_vote(namespace, context.clone(), &vote) {
                Some(vote)
            } else {
                invalid.insert(vote.signer);
                None
            }
        });

        SignatureVerification::new(verified.collect(), invalid.into_iter().collect())
    }

    /// Aggregates a quorum of votes into a certificate, returning `None` if the quorum is not met.
    ///
    /// Callers must not include duplicate votes from the same signer.
    fn assemble_certificate<I>(&self, signatures: I) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Signature<Self>>;

    /// Verifies a certificate that was recovered or received from the network.
    fn verify_certificate<R: Rng + CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        context: Self::Context<'_, D>,
        certificate: &Self::Certificate,
    ) -> bool;

    /// Verifies a stream of certificates, returning `false` at the first failure.
    fn verify_certificates<'a, R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        certificates: I,
    ) -> bool
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: Iterator<Item = (Self::Context<'a, D>, &'a Self::Certificate)>,
    {
        for (context, certificate) in certificates {
            if !self.verify_certificate(rng, namespace, context, certificate) {
                return false;
            }
        }

        true
    }

    /// Returns whether per-validator fault evidence can be safely exposed.
    ///
    /// Schemes where individual signatures can be safely reported as fault evidence should
    /// return `true`.
    fn is_attributable(&self) -> bool;

    /// Encoding configuration for bounded-size certificate decoding used in network payloads.
    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg;

    /// Encoding configuration that allows unbounded certificate decoding.
    ///
    /// Only use this when decoding data from trusted local storage, it must not be exposed to
    /// adversarial inputs or network payloads.
    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg;
}

/// Supplies the signing scheme the marshal should use for a given epoch.
pub trait SchemeProvider: Clone + Send + Sync + 'static {
    /// The signing scheme to provide.
    type Scheme: Scheme;

    /// Return the signing scheme that corresponds to `epoch`.
    fn scheme(&self, epoch: Epoch) -> Option<Arc<Self::Scheme>>;

    /// Return a certificate verifier that can validate certificates independent of epoch.
    ///
    /// This method allows implementations to provide a verifier that can validate
    /// certificates from any epoch (without epoch-specific state). For example,
    /// [`bls12381_threshold::Scheme`](crate::scheme::bls12381_threshold) maintains
    /// a static public key across epochs that can be used to verify certificates from any
    /// epoch, even after the committee has rotated and the underlying secret shares have
    /// been refreshed.
    ///
    /// The default implementation returns `None`. Callers should fall back to
    /// [`SchemeProvider::scheme`] for epoch-specific verification.
    fn certificate_verifier(&self) -> Option<Arc<Self::Scheme>> {
        None
    }
}
