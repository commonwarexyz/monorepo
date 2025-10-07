//! Signing abstractions for simplex.

use crate::{
    threshold_simplex::types::{
        finalize_namespace, notarize_namespace, nullify_namespace, seed_namespace, Proposal,
    },
    types::Round,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        ops::{
            aggregate_signatures, aggregate_verify_multiple_messages, partial_sign_message,
            partial_verify_multiple_public_keys_precomputed, threshold_signature_recover_pair,
        },
        poly::PartialSignature,
        variant::Variant,
        Error as ThresholdError,
    },
    Digest,
};
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
    hash::Hash,
};
use thiserror::Error;

/// Errors emitted by signing scheme implementations.
#[derive(Debug, Error)]
pub enum Error {
    /// Placeholder until real logic is implemented in later phases.
    #[error("not implemented")]
    NotImplemented,
    /// Signer index does not match the scheme's share.
    #[error("signer mismatch (expected {expected}, got {actual})")]
    SignerMismatch { expected: u32, actual: u32 },
    /// Not enough votes to assemble a certificate.
    #[error("insufficient votes: required {required}, got {actual}")]
    InsufficientVotes { required: u32, actual: u32 },
    /// Threshold recovery failure.
    #[error("threshold error: {0}")]
    Threshold(#[from] ThresholdError),
}

/// Identifies the context in which a vote or certificate is produced.
pub enum VoteContext<'a, D: Digest> {
    Notarize { proposal: &'a Proposal<D> },
    Nullify { round: Round },
    Finalize { proposal: &'a Proposal<D> },
}

/// Signed vote emitted by a participant.
#[derive(Clone, Debug, Eq)]
pub struct Vote<S: SigningScheme> {
    pub signer: u32,
    pub signature: S::Signature,
}

impl<S: SigningScheme> PartialEq for Vote<S> {
    fn eq(&self, other: &Self) -> bool {
        self.signer == other.signer && self.signature == other.signature
    }
}

impl<S: SigningScheme> Hash for Vote<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.signer.hash(state);
        self.signature.hash(state);
    }
}

/// Result of verifying a batch of votes.
pub struct VoteVerification<S: SigningScheme> {
    pub verified: Vec<Vote<S>>,
    pub invalid_signers: Vec<u32>,
}

impl<S: SigningScheme> VoteVerification<S> {
    pub fn new(verified: Vec<Vote<S>>, invalid_signers: Vec<u32>) -> Self {
        Self {
            verified,
            invalid_signers,
        }
    }
}

impl<S: SigningScheme> Write for Vote<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signer.write(writer);
        self.signature.write(writer);
    }
}

impl<S: SigningScheme> EncodeSize for Vote<S> {
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.signature.encode_size()
    }
}

impl<S: SigningScheme> Read for Vote<S> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let signer = u32::read(reader)?;
        let signature = S::Signature::read_cfg(reader, &S::signature_read_cfg())?;

        Ok(Self { signer, signature })
    }
}

/// Partial notarize vote carrying the proposal and signatures.
#[derive(Clone, Debug, Eq)]
pub struct Notarize<S: SigningScheme, D: Digest> {
    pub proposal: Proposal<D>,
    pub vote: Vote<S>,
}

impl<S: SigningScheme, D: Digest> PartialEq for Notarize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.vote == other.vote
    }
}

impl<S: SigningScheme, D: Digest> Hash for Notarize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.vote.hash(state);
    }
}

impl<S: SigningScheme, D: Digest> Notarize<S, D> {
    pub fn sign(scheme: &S, namespace: &[u8], proposal: Proposal<D>) -> Self {
        let context = VoteContext::Notarize {
            proposal: &proposal,
        };
        let vote = scheme.sign_vote(namespace, context);

        Self { proposal, vote }
    }

    pub fn verify(&self, scheme: &S, namespace: &[u8]) -> bool {
        let context = VoteContext::Notarize {
            proposal: &self.proposal,
        };
        // FIXME: avoid cloning
        let verification =
            scheme.verify_votes(namespace, context, std::iter::once(self.vote.clone()));
        !verification.verified.is_empty()
    }
}

impl<S: SigningScheme, D: Digest> Write for Notarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.vote.write(writer);
    }
}

impl<S: SigningScheme, D: Digest> EncodeSize for Notarize<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.vote.encode_size()
    }
}

impl<S: SigningScheme, D: Digest> Read for Notarize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let proposal = Proposal::read(reader)?;
        let vote = Vote::read(reader)?;

        Ok(Self { proposal, vote })
    }
}

/// Partial nullify vote for a given round.
#[derive(Clone, Debug, Eq)]
pub struct Nullify<S: SigningScheme> {
    pub round: Round,
    pub vote: Vote<S>,
}

impl<S: SigningScheme> PartialEq for Nullify<S> {
    fn eq(&self, other: &Self) -> bool {
        self.round == other.round && self.vote == other.vote
    }
}

impl<S: SigningScheme> Hash for Nullify<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.round.hash(state);
        self.vote.hash(state);
    }
}

impl<S: SigningScheme> Nullify<S> {
    pub fn sign<D: Digest>(scheme: &S, namespace: &[u8], round: Round) -> Self {
        let context: VoteContext<D> = VoteContext::Nullify { round };
        let vote = scheme.sign_vote(namespace, context);

        Self { round, vote }
    }

    // FIXME: this D sucks
    pub fn verify<D: Digest>(&self, scheme: &S, namespace: &[u8]) -> bool {
        let context: VoteContext<D> = VoteContext::Nullify { round: self.round };
        // FIXME: avoid cloning
        let verification =
            scheme.verify_votes(namespace, context, std::iter::once(self.vote.clone()));
        !verification.verified.is_empty()
    }
}

impl<S: SigningScheme> Write for Nullify<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.vote.write(writer);
    }
}

impl<S: SigningScheme> EncodeSize for Nullify<S> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.vote.encode_size()
    }
}

impl<S: SigningScheme> Read for Nullify<S> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let round = Round::read(reader)?;
        let vote = Vote::read(reader)?;

        Ok(Self { round, vote })
    }
}

/// Partial finalize vote carrying the proposal and signatures.
#[derive(Clone, Debug, Eq)]
pub struct Finalize<S: SigningScheme, D: Digest> {
    pub proposal: Proposal<D>,
    pub vote: Vote<S>,
}

impl<S: SigningScheme, D: Digest> PartialEq for Finalize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.vote == other.vote
    }
}

impl<S: SigningScheme, D: Digest> Hash for Finalize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.vote.hash(state);
    }
}

impl<S: SigningScheme, D: Digest> Finalize<S, D> {
    pub fn sign(scheme: &S, namespace: &[u8], proposal: Proposal<D>) -> Self {
        let context = VoteContext::Finalize {
            proposal: &proposal,
        };
        let vote = scheme.sign_vote(namespace, context);

        Self { proposal, vote }
    }

    pub fn verify(&self, scheme: &S, namespace: &[u8]) -> bool {
        let context = VoteContext::Finalize {
            proposal: &self.proposal,
        };
        // FIXME: avoid cloning
        let verification =
            scheme.verify_votes(namespace, context, std::iter::once(self.vote.clone()));
        !verification.verified.is_empty()
    }
}

impl<S: SigningScheme, D: Digest> Write for Finalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.vote.write(writer);
    }
}

impl<S: SigningScheme, D: Digest> EncodeSize for Finalize<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.vote.encode_size()
    }
}

impl<S: SigningScheme, D: Digest> Read for Finalize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let proposal = Proposal::read(reader)?;
        let vote = Vote::read(reader)?;

        Ok(Self { proposal, vote })
    }
}

/// Aggregated notarization certificate with randomness seed.
#[derive(Clone, Debug, Eq)]
pub struct Notarization<S: SigningScheme, D: Digest> {
    pub proposal: Proposal<D>,
    pub certificate: S::Certificate,
}

impl<S: SigningScheme, D: Digest> PartialEq for Notarization<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.certificate == other.certificate
    }
}

impl<S: SigningScheme, D: Digest> Hash for Notarization<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.certificate.hash(state);
    }
}

impl<S: SigningScheme, D: Digest> Notarization<S, D> {
    pub fn verify(&self, scheme: &S, namespace: &[u8]) -> bool {
        let context = VoteContext::Notarize {
            proposal: &self.proposal,
        };

        scheme
            .verify_certificate(namespace, context, &self.certificate)
            .is_ok()
    }
}

impl<S: SigningScheme, D: Digest> Write for Notarization<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: SigningScheme, D: Digest> EncodeSize for Notarization<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.certificate.encode_size()
    }
}

impl<S: SigningScheme, D: Digest> Read for Notarization<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let proposal = Proposal::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, &S::certificate_read_cfg())?;

        Ok(Self {
            proposal,
            certificate,
        })
    }
}

/// Aggregated nullification certificate for a round.
#[derive(Clone, Debug, Eq)]
pub struct Nullification<S: SigningScheme> {
    pub round: Round,
    pub certificate: S::Certificate,
}

impl<S: SigningScheme> PartialEq for Nullification<S> {
    fn eq(&self, other: &Self) -> bool {
        self.round == other.round && self.certificate == other.certificate
    }
}

impl<S: SigningScheme> Hash for Nullification<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.round.hash(state);
        self.certificate.hash(state);
    }
}

impl<S: SigningScheme> Write for Nullification<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: SigningScheme> Nullification<S> {
    pub fn verify<D: Digest>(&self, scheme: &S, namespace: &[u8]) -> bool {
        let context: VoteContext<D> = VoteContext::Nullify { round: self.round };
        scheme
            .verify_certificate(namespace, context, &self.certificate)
            .is_ok()
    }
}

impl<S: SigningScheme> EncodeSize for Nullification<S> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.certificate.encode_size()
    }
}

impl<S: SigningScheme> Read for Nullification<S> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let round = Round::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, &S::certificate_read_cfg())?;

        Ok(Self { round, certificate })
    }
}

/// Aggregated finalization certificate.
#[derive(Clone, Debug, Eq)]
pub struct Finalization<S: SigningScheme, D: Digest> {
    pub proposal: Proposal<D>,
    pub certificate: S::Certificate,
}

impl<S: SigningScheme, D: Digest> PartialEq for Finalization<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.certificate == other.certificate
    }
}

impl<S: SigningScheme, D: Digest> Hash for Finalization<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.certificate.hash(state);
    }
}

impl<S: SigningScheme, D: Digest> Finalization<S, D> {
    pub fn verify(&self, scheme: &S, namespace: &[u8]) -> bool {
        let context = VoteContext::Finalize {
            proposal: &self.proposal,
        };
        scheme
            .verify_certificate(namespace, context, &self.certificate)
            .is_ok()
    }
}

impl<S: SigningScheme, D: Digest> Write for Finalization<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: SigningScheme, D: Digest> EncodeSize for Finalization<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.certificate.encode_size()
    }
}

impl<S: SigningScheme, D: Digest> Read for Finalization<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let proposal = Proposal::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, &S::certificate_read_cfg())?;

        Ok(Self {
            proposal,
            certificate,
        })
    }
}

/// Trait that signing schemes must implement.
pub trait SigningScheme: Clone + Send + Sync + 'static {
    type Signature: Clone
        + Debug
        + PartialEq
        + Eq
        + Hash
        + Send
        + Sync
        + EncodeSize
        + Write
        + Read<Cfg = Self::SignatureReadCfg>;

    type Certificate: Clone
        + Debug
        + PartialEq
        + Eq
        + Hash
        + Send
        + Sync
        + EncodeSize
        + Write
        + Read<Cfg = Self::CertificateReadCfg>;

    type Randomness: EncodeSize + Write + Send;

    type SignatureReadCfg;
    type CertificateReadCfg;

    fn can_sign(&self) -> bool;

    fn sign_vote<D: Digest>(&self, namespace: &[u8], context: VoteContext<'_, D>) -> Vote<Self>
    where
        Self: Sized;

    // FIXME: avoid cloning votes, maybe just Iterator<&Vote>?
    fn verify_votes<D: Digest, I>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        votes: I,
    ) -> VoteVerification<Self>
    where
        I: IntoIterator<Item = Vote<Self>>,
        Self: Sized;

    fn assemble_certificate<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        votes: &[Vote<Self>],
    ) -> Result<Self::Certificate, Error>
    where
        Self: Sized;

    // FIXME: just return bool
    fn verify_certificate<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        certificate: &Self::Certificate,
    ) -> Result<Option<Self::Randomness>, Error>;

    fn verify_certificates<'a, D: Digest, I>(&self, namespace: &[u8], certificates: I) -> bool
    where
        I: Iterator<Item = (VoteContext<'a, D>, &'a Self::Certificate)>,
        Self: Sized,
    {
        for (context, certificate) in certificates {
            if self
                .verify_certificate(namespace, context, certificate)
                .is_err()
            {
                return false;
            }
        }

        true
    }

    fn randomness(&self, certificate: &Self::Certificate) -> Option<Self::Randomness>;

    // FIXME: this probably doesn't make sense, only needed for certificates
    fn signature_read_cfg() -> Self::SignatureReadCfg;
    fn certificate_read_cfg() -> Self::CertificateReadCfg;
}

/// Placeholder for the upcoming BLS threshold implementation.
#[derive(Clone, Debug)]
pub struct BlsThresholdScheme<V: Variant> {
    signer: u32,
    polynomial: Vec<V::Public>,
    identity: V::Public,
    share: Option<Share>,
    threshold: u32,
}

impl<V: Variant> BlsThresholdScheme<V> {
    pub fn new(
        signer: u32,
        polynomial: Vec<V::Public>,
        identity: V::Public,
        share: Share,
        threshold: u32,
    ) -> Self {
        Self {
            signer,
            polynomial,
            identity,
            share: Some(share),
            threshold,
        }
    }

    pub fn into_verifier(mut self) -> Self {
        self.share.take();
        self
    }

    pub fn identity(&self) -> V::Public {
        self.identity
    }
}

impl<V: Variant + Send + Sync> SigningScheme for BlsThresholdScheme<V> {
    type Signature = (V::Signature, V::Signature);
    type Certificate = (V::Signature, V::Signature);
    type Randomness = V::Signature;

    type SignatureReadCfg = ((), ());
    type CertificateReadCfg = ((), ());

    fn can_sign(&self) -> bool {
        self.share.is_some()
    }

    fn sign_vote<D: Digest>(&self, namespace: &[u8], context: VoteContext<'_, D>) -> Vote<Self> {
        let share = self
            .share
            .as_ref()
            .expect("can only be called after checking can_sign");

        let signature = match context {
            VoteContext::Notarize { proposal } => {
                let notarize_ns = notarize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let proposal_sig = partial_sign_message::<V>(
                    share,
                    Some(notarize_ns.as_ref()),
                    proposal_bytes.as_ref(),
                )
                .value;

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_sig =
                    partial_sign_message::<V>(share, Some(seed_ns.as_ref()), seed_bytes.as_ref())
                        .value;

                (proposal_sig, seed_sig)
            }
            VoteContext::Nullify { round } => {
                let nullify_ns = nullify_namespace(namespace);
                let message_bytes = round.encode();
                let view_sig = partial_sign_message::<V>(
                    share,
                    Some(nullify_ns.as_ref()),
                    message_bytes.as_ref(),
                )
                .value;

                let seed_ns = seed_namespace(namespace);
                let seed_sig = partial_sign_message::<V>(
                    share,
                    Some(seed_ns.as_ref()),
                    message_bytes.as_ref(),
                )
                .value;

                (view_sig, seed_sig)
            }
            VoteContext::Finalize { proposal } => {
                let finalize_ns = finalize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let proposal_sig = partial_sign_message::<V>(
                    share,
                    Some(finalize_ns.as_ref()),
                    proposal_bytes.as_ref(),
                )
                .value;

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_sig =
                    partial_sign_message::<V>(share, Some(seed_ns.as_ref()), seed_bytes.as_ref())
                        .value;

                (proposal_sig, seed_sig)
            }
        };

        Vote {
            signer: self.signer,
            signature,
        }
    }

    fn assemble_certificate<D: Digest>(
        &self,
        _namespace: &[u8],
        _context: VoteContext<'_, D>,
        votes: &[Vote<Self>],
    ) -> Result<Self::Certificate, Error> {
        if votes.len() < self.threshold as usize {
            return Err(Error::InsufficientVotes {
                required: self.threshold,
                actual: votes.len() as u32,
            });
        }

        let proposal_partials: Vec<_> = votes
            .iter()
            .map(|vote| PartialSignature::<V> {
                index: vote.signer,
                value: vote.signature.0.clone(),
            })
            .collect();

        let seed_partials: Vec<_> = votes
            .iter()
            .map(|vote| PartialSignature::<V> {
                index: vote.signer,
                value: vote.signature.1.clone(),
            })
            .collect();

        let (proposal_sig, seed_sig) = threshold_signature_recover_pair::<V, _>(
            self.threshold,
            proposal_partials.iter(),
            seed_partials.iter(),
        )?;

        Ok((proposal_sig, seed_sig))
    }

    fn verify_votes<D: Digest, I>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        votes: I,
    ) -> VoteVerification<Self>
    where
        I: IntoIterator<Item = Vote<Self>>,
    {
        let votes: Vec<Vote<Self>> = votes.into_iter().collect();
        if votes.is_empty() {
            return VoteVerification::new(Vec::new(), Vec::new());
        }

        let mut invalid = BTreeSet::new();

        match context {
            VoteContext::Notarize { proposal } => {
                let notarize_ns = notarize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let proposal_partials: Vec<_> = votes
                    .iter()
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.0.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(notarize_ns.as_ref()),
                    proposal_bytes.as_ref(),
                    proposal_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_partials: Vec<_> = votes
                    .iter()
                    .filter(|vote| !invalid.contains(&vote.signer))
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.1.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(seed_ns.as_ref()),
                    seed_bytes.as_ref(),
                    seed_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }
            }
            VoteContext::Nullify { round } => {
                let nullify_ns = nullify_namespace(namespace);
                let message_bytes = round.encode();
                let view_partials: Vec<_> = votes
                    .iter()
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.0.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(nullify_ns.as_ref()),
                    message_bytes.as_ref(),
                    view_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }

                let seed_ns = seed_namespace(namespace);
                let seed_partials: Vec<_> = votes
                    .iter()
                    .filter(|vote| !invalid.contains(&vote.signer))
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.1.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(seed_ns.as_ref()),
                    message_bytes.as_ref(),
                    seed_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }
            }
            VoteContext::Finalize { proposal } => {
                let finalize_ns = finalize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let proposal_partials: Vec<_> = votes
                    .iter()
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.0.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(finalize_ns.as_ref()),
                    proposal_bytes.as_ref(),
                    proposal_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_partials: Vec<_> = votes
                    .iter()
                    .filter(|vote| !invalid.contains(&vote.signer))
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.1.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(seed_ns.as_ref()),
                    seed_bytes.as_ref(),
                    seed_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }
            }
        }

        let verified = votes
            .into_iter()
            .filter(|vote| !invalid.contains(&vote.signer))
            .collect();

        let invalid_signers = invalid.into_iter().collect();

        VoteVerification::new(verified, invalid_signers)
    }

    fn verify_certificate<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        certificate: &Self::Certificate,
    ) -> Result<Option<Self::Randomness>, Error> {
        let aggregate_pair = |messages: &[_], certificate: &Self::Certificate| {
            let signature =
                aggregate_signatures::<V, _>(&[certificate.0.clone(), certificate.1.clone()]);
            aggregate_verify_multiple_messages::<V, _>(&self.identity, messages, &signature, 1)
        };

        match context {
            VoteContext::Notarize { proposal } => {
                let notarize_ns = notarize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let notarize_message = (Some(notarize_ns.as_ref()), proposal_bytes.as_ref());

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_message = (Some(seed_ns.as_ref()), seed_bytes.as_ref());

                aggregate_pair(&[notarize_message, seed_message], certificate)?;
            }
            VoteContext::Nullify { round } => {
                let nullify_ns = nullify_namespace(namespace);
                let round_bytes = round.encode();
                let nullify_message = (Some(nullify_ns.as_ref()), round_bytes.as_ref());

                let seed_ns = seed_namespace(namespace);
                let seed_message = (Some(seed_ns.as_ref()), round_bytes.as_ref());

                aggregate_pair(&[nullify_message, seed_message], certificate)?;
            }
            VoteContext::Finalize { proposal } => {
                let finalize_ns = finalize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let finalize_message = (Some(finalize_ns.as_ref()), proposal_bytes.as_ref());

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_message = (Some(seed_ns.as_ref()), seed_bytes.as_ref());

                aggregate_pair(&[finalize_message, seed_message], certificate)?;
            }
        };

        Ok(Some(certificate.1.clone()))
    }

    fn verify_certificates<'a, D: Digest, I>(&self, namespace: &[u8], certificates: I) -> bool
    where
        I: Iterator<Item = (VoteContext<'a, D>, &'a Self::Certificate)>,
        Self: Sized,
    {
        let mut seeds = HashMap::new();
        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        let notarize_namespace = notarize_namespace(namespace);
        let nullify_namespace = nullify_namespace(namespace);
        let finalize_namespace = finalize_namespace(namespace);
        let seed_namespace = seed_namespace(namespace);

        for (context, certificate) in certificates {
            match context {
                VoteContext::Notarize { proposal } => {
                    // Prepare notarize message
                    let notarize_message = proposal.encode().to_vec();
                    let notarize_message = (Some(notarize_namespace.as_slice()), notarize_message);
                    messages.push(notarize_message);
                    signatures.push(&certificate.0);

                    // Add seed message (if not already present)
                    if let Some(previous) = seeds.get(&proposal.round.view()) {
                        if *previous != &certificate.1 {
                            return false;
                        }
                    } else {
                        let seed_message: Vec<u8> = proposal.round.encode().into();
                        let seed_message = (Some(seed_namespace.as_slice()), seed_message);
                        messages.push(seed_message);
                        signatures.push(&certificate.1);
                        seeds.insert(proposal.round.view(), &certificate.1);
                    }
                }
                VoteContext::Nullify { round } => {
                    // Prepare nullify message
                    let nullify_message: Vec<u8> = round.encode().into();
                    let nullify_message = (Some(nullify_namespace.as_slice()), nullify_message);
                    messages.push(nullify_message);
                    signatures.push(&certificate.0);

                    // Add seed message (if not already present)
                    if let Some(previous) = seeds.get(&round.view()) {
                        if *previous != &certificate.1 {
                            return false;
                        }
                    } else {
                        let seed_message: Vec<u8> = round.encode().into();
                        let seed_message = (Some(seed_namespace.as_slice()), seed_message);
                        messages.push(seed_message);
                        signatures.push(&certificate.1);
                        seeds.insert(round.view(), &certificate.1);
                    }
                }
                VoteContext::Finalize { proposal } => {
                    // Prepare finalize message
                    let finalize_message = proposal.encode().to_vec();
                    let finalize_message = (Some(finalize_namespace.as_slice()), finalize_message);
                    messages.push(finalize_message);
                    signatures.push(&certificate.0);

                    // Add seed message (if not already present)
                    if let Some(previous) = seeds.get(&proposal.round.view()) {
                        if *previous != &certificate.1 {
                            return false;
                        }
                    } else {
                        let seed_message: Vec<u8> = proposal.round.encode().into();
                        let seed_message = (Some(seed_namespace.as_slice()), seed_message);
                        messages.push(seed_message);
                        signatures.push(&certificate.1);
                        seeds.insert(proposal.round.view(), &certificate.1);
                    }
                }
            }
        }

        // Aggregate signatures
        let signature = aggregate_signatures::<V, _>(signatures);
        aggregate_verify_multiple_messages::<V, _>(
            &self.identity,
            &messages
                .iter()
                .map(|(namespace, message)| (namespace.as_deref(), message.as_ref()))
                .collect::<Vec<_>>(),
            &signature,
            1,
        )
        .is_ok()
    }

    fn randomness(&self, certificate: &Self::Certificate) -> Option<Self::Randomness> {
        Some(certificate.1.clone())
    }

    fn signature_read_cfg() -> Self::SignatureReadCfg {
        ((), ())
    }

    fn certificate_read_cfg() -> Self::CertificateReadCfg {
        ((), ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_simplex::types;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops::{evaluate_all, generate_shares},
            primitives::{group::Element, variant::MinSig},
        },
        sha256::Digest as Sha256Digest,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn vote_context_compiles() {
        let round = Round::new(0, 0);
        let payload = Sha256Digest::from([0u8; 32]);
        let proposal = Proposal::new(round, round.view(), payload);
        let namespace = b"ns";
        let ctx = VoteContext::Notarize {
            proposal: &proposal,
        };
        match ctx {
            VoteContext::Notarize { .. } => {}
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn bls_scheme_stores_configuration() {
        let mut rng = StdRng::seed_from_u64(7);
        let threshold = 3;
        let (public_poly, shares) =
            generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
        let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
        let identity = *public_poly.constant();
        let scheme: BlsThresholdScheme<MinSig> = BlsThresholdScheme::new(
            shares[0].index,
            polynomial.clone(),
            identity,
            shares[0].clone(),
            threshold,
        );
        assert_eq!(scheme.polynomial.len(), polynomial.len());
        assert!(scheme.identity == identity);
        assert_eq!(shares.len(), 4); // ensure we used the DKG outputs
        assert_eq!(scheme.share.unwrap().index, shares[0].index);
    }

    // #[test]
    // fn sign_vote_matches_notarize() {
    //     let mut rng = StdRng::seed_from_u64(11);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(share.index, polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 5);
    //     let payload = Sha256Digest::from([1u8; 32]);
    //     let proposal = Proposal::new(round, 4, payload);
    //     let namespace = b"notarize";

    //     let vote = scheme
    //         .sign_vote(VoteContext::Notarize {
    //             namespace,
    //             proposal: &proposal,
    //         })
    //         .expect("sign vote");

    //     // let legacy = types::Notarize::<MinSig, _>::sign(namespace, &share, proposal.clone());
    //     // assert!(vote.signature.0 == legacy.proposal_signature.value);
    //     // assert!(vote.signature.1 == legacy.seed_signature.value);
    // }

    // #[test]
    // fn sign_vote_matches_nullify() {
    //     let mut rng = StdRng::seed_from_u64(13);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 7);
    //     let namespace = b"nullify";

    //     let vote = scheme
    //         .sign_vote::<Sha256Digest>(VoteContext::Nullify { namespace, round }, share.index)
    //         .expect("sign vote");

    //     let legacy = types::Nullify::<MinSig>::sign(namespace, &share, round);
    //     assert!(vote.signature.0 == legacy.view_signature.value);
    //     assert!(vote.signature.1 == legacy.seed_signature.value);
    // }

    // #[test]
    // fn sign_vote_matches_finalize() {
    //     let mut rng = StdRng::seed_from_u64(17);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 9);
    //     let payload = Sha256Digest::from([2u8; 32]);
    //     let proposal = Proposal::new(round, 8, payload);
    //     let namespace = b"finalize";

    //     let vote = scheme
    //         .sign_vote(
    //             VoteContext::Finalize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             share.index,
    //         )
    //         .expect("sign vote");

    //     let legacy = types::Finalize::<MinSig, _>::sign(namespace, &share, proposal.clone());
    //     assert!(vote.signature.0 == legacy.proposal_signature.value);
    //     let seed_ns = seed_namespace(namespace);
    //     let seed_bytes = proposal.round.encode();
    //     let expected_seed =
    //         partial_sign_message::<MinSig>(&share, Some(seed_ns.as_ref()), seed_bytes.as_ref());
    //     assert!(vote.signature.1 == expected_seed.value);
    // }

    // #[test]
    // fn sign_vote_rejects_wrong_signer() {
    //     let mut rng = StdRng::seed_from_u64(19);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 1);
    //     let payload = Sha256Digest::from([3u8; 32]);
    //     let proposal = Proposal::new(round, 0, payload);

    //     let err = scheme
    //         .sign_vote(
    //             VoteContext::Notarize {
    //                 namespace: b"ns",
    //                 proposal: &proposal,
    //             },
    //             share.index + 1,
    //         )
    //         .expect_err("expected mismatch");

    //     match err {
    //         Error::SignerMismatch { expected, actual } => {
    //             assert_eq!(expected, share.index);
    //             assert_eq!(actual, share.index + 1);
    //         }
    //         other => panic!("unexpected error: {other:?}"),
    //     }
    // }

    // #[test]
    // fn vote_codec_roundtrip() {
    //     let mut rng = StdRng::seed_from_u64(41);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 7);
    //     let payload = Sha256Digest::from([2u8; 32]);
    //     let proposal = Proposal::new(round, 6, payload);

    //     let vote = scheme
    //         .sign_vote(
    //             VoteContext::Notarize {
    //                 namespace: b"codec-vote",
    //                 proposal: &proposal,
    //             },
    //             share.index,
    //         )
    //         .expect("vote");

    //     let encoded = vote.encode();
    //     let decoded = <Vote<BlsThresholdScheme<MinSig>>>::decode(encoded).expect("decode");
    //     assert_eq!(decoded, vote);
    // }

    // #[test]
    // fn notarize_vote_codec_roundtrip() {
    //     let mut rng = StdRng::seed_from_u64(43);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 9);
    //     let payload = Sha256Digest::from([9u8; 32]);
    //     let proposal = Proposal::new(round, 8, payload);

    //     let vote = scheme
    //         .sign_vote(
    //             VoteContext::Notarize {
    //                 namespace: b"codec-notarize-vote",
    //                 proposal: &proposal,
    //             },
    //             share.index,
    //         )
    //         .expect("vote");

    //     let message: Notarize<BlsThresholdScheme<MinSig>, Sha256Digest> = Notarize {
    //         proposal: proposal.clone(),
    //         vote,
    //     };

    //     let encoded = message.encode();
    //     let decoded =
    //         <Notarize<BlsThresholdScheme<MinSig>, Sha256Digest>>::decode(encoded).expect("decode");
    //     assert_eq!(decoded.proposal, message.proposal);
    //     assert_eq!(decoded.vote, message.vote);
    // }

    // #[test]
    // fn notarization_certificate_codec_roundtrip() {
    //     let threshold = 3usize;
    //     let (schemes, _) = build_scheme_set(45, 4, threshold);
    //     let round = Round::new(0, 30);
    //     let payload = Sha256Digest::from([4u8; 32]);
    //     let proposal = Proposal::new(round, 29, payload);
    //     let namespace = b"codec-notarization";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Notarize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let certificate = schemes[0]
    //         .assemble_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &votes,
    //         )
    //         .expect("assemble");

    //     let message: Notarization<BlsThresholdScheme<MinSig>, Sha256Digest> = Notarization {
    //         proposal: proposal.clone(),
    //         certificate,
    //     };

    //     let encoded = message.encode();
    //     let decoded = <Notarization<BlsThresholdScheme<MinSig>, Sha256Digest>>::decode(encoded)
    //         .expect("decode");
    //     assert_eq!(decoded.proposal, message.proposal);
    //     assert_eq!(decoded.certificate, message.certificate);
    // }

    // #[test]
    // fn verify_votes_notarize_filters_invalid() {
    //     let mut rng = StdRng::seed_from_u64(23);
    //     let threshold = 3usize;
    //     let (public_poly, shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 5, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 5);
    //     let identity = *public_poly.constant();

    //     let schemes: Vec<_> = shares
    //         .iter()
    //         .map(|share| {
    //             BlsThresholdScheme::<MinSig>::new(
    //                 polynomial.clone(),
    //                 identity,
    //                 share.clone(),
    //                 threshold,
    //             )
    //         })
    //         .collect();

    //     let round = Round::new(0, 12);
    //     let payload = Sha256Digest::from([4u8; 32]);
    //     let proposal = Proposal::new(round, 11, payload);
    //     let namespace = b"verify-notarize";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(3)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Notarize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let verifier = &schemes[0];

    //     let verification = verifier.verify_votes(
    //         VoteContext::Notarize {
    //             namespace,
    //             proposal: &proposal,
    //         },
    //         votes.clone(),
    //     );
    //     assert!(verification.invalid_signers.is_empty());
    //     assert_eq!(verification.verified.len(), votes.len());

    //     let mut corrupted = votes.clone();
    //     corrupted[0].signer = 42;
    //     let verification = verifier.verify_votes(
    //         VoteContext::Notarize {
    //             namespace,
    //             proposal: &proposal,
    //         },
    //         corrupted,
    //     );
    //     assert_eq!(verification.invalid_signers, vec![42]);
    //     assert_eq!(verification.verified.len(), votes.len() - 1);
    // }

    // #[test]
    // fn assemble_certificate_notarize() {
    //     let mut rng = StdRng::seed_from_u64(29);
    //     let threshold = 3usize;
    //     let (public_poly, shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let schemes: Vec<_> = shares
    //         .iter()
    //         .map(|share| {
    //             BlsThresholdScheme::<MinSig>::new(
    //                 polynomial.clone(),
    //                 identity,
    //                 share.clone(),
    //                 threshold,
    //             )
    //         })
    //         .collect();

    //     let round = Round::new(0, 15);
    //     let payload = Sha256Digest::from([5u8; 32]);
    //     let proposal = Proposal::new(round, 14, payload);
    //     let namespace = b"assemble-notarize";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Notarize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let certificate = schemes[0]
    //         .assemble_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &votes,
    //         )
    //         .expect("assemble");

    //     let expected_proposal: Vec<_> = votes
    //         .iter()
    //         .map(|vote| PartialSignature::<MinSig> {
    //             index: vote.signer,
    //             value: vote.signature.0.clone(),
    //         })
    //         .collect();
    //     let expected_seed: Vec<_> = votes
    //         .iter()
    //         .map(|vote| PartialSignature::<MinSig> {
    //             index: vote.signer,
    //             value: vote.signature.1.clone(),
    //         })
    //         .collect();
    //     let expected = threshold_signature_recover_pair::<MinSig, _>(
    //         threshold as u32,
    //         expected_proposal.iter(),
    //         expected_seed.iter(),
    //     )
    //     .expect("recover");

    //     assert_eq!(certificate.0, expected.0);
    //     assert_eq!(certificate.1, expected.1);
    // }

    // #[test]
    // fn assemble_certificate_requires_quorum() {
    //     let mut rng = StdRng::seed_from_u64(31);
    //     let threshold = 3usize;
    //     let (public_poly, shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let schemes: Vec<_> = shares
    //         .iter()
    //         .map(|share| {
    //             BlsThresholdScheme::<MinSig>::new(
    //                 polynomial.clone(),
    //                 identity,
    //                 share.clone(),
    //                 threshold,
    //             )
    //         })
    //         .collect();

    //     let round = Round::new(0, 18);
    //     let payload = Sha256Digest::from([6u8; 32]);
    //     let proposal = Proposal::new(round, 17, payload);
    //     let namespace = b"assemble-insufficient";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold - 1)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Notarize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let err = schemes[0]
    //         .assemble_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &votes,
    //         )
    //         .expect_err("expected insufficient votes");

    //     match err {
    //         Error::InsufficientVotes { required, actual } => {
    //             assert_eq!(required, threshold);
    //             assert_eq!(actual, votes.len());
    //         }
    //         other => panic!("unexpected error: {other:?}"),
    //     }
    // }

    // fn build_scheme_set(
    //     seed: u64,
    //     n: usize,
    //     threshold: usize,
    // ) -> (Vec<BlsThresholdScheme<MinSig>>, Vec<Share>) {
    //     let mut rng = StdRng::seed_from_u64(seed);
    //     let (public_poly, shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, n as u32, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, n as u32);
    //     let identity = *public_poly.constant();
    //     let schemes = shares
    //         .iter()
    //         .map(|share| {
    //             BlsThresholdScheme::new(polynomial.clone(), identity, share.clone(), threshold)
    //         })
    //         .collect();
    //     (schemes, shares)
    // }

    // #[test]
    // fn verify_certificate_notarize_success_and_failure() {
    //     let threshold = 3;
    //     let (schemes, _) = build_scheme_set(33, 4, threshold);
    //     let round = Round::new(0, 20);
    //     let payload = Sha256Digest::from([7u8; 32]);
    //     let proposal = Proposal::new(round, 19, payload);
    //     let namespace = b"verify-cert-notarize";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Notarize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let certificate = schemes[0]
    //         .assemble_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &votes,
    //         )
    //         .expect("assemble");

    //     let randomness = schemes[1]
    //         .verify_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &certificate,
    //         )
    //         .expect("verify");
    //     let expected_seed = (proposal.round, certificate.1.clone());
    //     assert_eq!(randomness, Some(expected_seed));

    //     let mut bad_certificate = certificate.clone();
    //     let mut corrupted = bad_certificate.0.clone();
    //     corrupted.add(&<MinSig as Variant>::Signature::one());
    //     bad_certificate.0 = corrupted;
    //     let err = schemes[1]
    //         .verify_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &bad_certificate,
    //         )
    //         .expect_err("expected invalid certificate");
    //     assert!(matches!(err, Error::Threshold(_)));
    // }

    // #[test]
    // fn verify_certificate_nullify_success_and_failure() {
    //     let threshold = 3;
    //     let (schemes, _) = build_scheme_set(35, 4, threshold);
    //     let round = Round::new(0, 22);
    //     let namespace = b"verify-cert-nullify";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote::<Sha256Digest>(
    //                     VoteContext::Nullify { namespace, round },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let certificate = schemes[0]
    //         .assemble_certificate::<Sha256Digest>(VoteContext::Nullify { namespace, round }, &votes)
    //         .expect("assemble");

    //     let randomness = schemes[1]
    //         .verify_certificate::<Sha256Digest>(
    //             VoteContext::Nullify { namespace, round },
    //             &certificate,
    //         )
    //         .expect("verify");
    //     let expected_seed = (round, certificate.1.clone());
    //     assert_eq!(randomness, Some(expected_seed));

    //     let mut bad_certificate = certificate.clone();
    //     let mut corrupted = bad_certificate.1.clone();
    //     corrupted.add(&<MinSig as Variant>::Signature::one());
    //     bad_certificate.1 = corrupted;
    //     let err = schemes[1]
    //         .verify_certificate::<Sha256Digest>(
    //             VoteContext::Nullify { namespace, round },
    //             &bad_certificate,
    //         )
    //         .expect_err("expected invalid certificate");
    //     assert!(matches!(err, Error::Threshold(_)));
    // }

    // #[test]
    // fn verify_certificate_finalize_success_and_failure() {
    //     let threshold = 3;
    //     let (schemes, _) = build_scheme_set(37, 4, threshold);
    //     let round = Round::new(0, 25);
    //     let payload = Sha256Digest::from([8u8; 32]);
    //     let proposal = Proposal::new(round, 24, payload);
    //     let namespace = b"verify-cert-finalize";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Finalize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let certificate = schemes[0]
    //         .assemble_certificate(
    //             VoteContext::Finalize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &votes,
    //         )
    //         .expect("assemble");

    //     let randomness = schemes[1]
    //         .verify_certificate(
    //             VoteContext::Finalize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &certificate,
    //         )
    //         .expect("verify");
    //     let expected_seed = (proposal.round, certificate.1.clone());
    //     assert_eq!(randomness, Some(expected_seed));

    //     let mut bad_certificate = certificate.clone();
    //     let mut corrupted = bad_certificate.0.clone();
    //     corrupted.add(&<MinSig as Variant>::Signature::one());
    //     bad_certificate.0 = corrupted;
    //     let err = schemes[1]
    //         .verify_certificate(
    //             VoteContext::Finalize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &bad_certificate,
    //         )
    //         .expect_err("expected invalid certificate");
    //     assert!(matches!(err, Error::Threshold(_)));
    // }
}
