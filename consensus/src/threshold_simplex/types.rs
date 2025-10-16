//! Types used in [crate::threshold_simplex].

use crate::{
    threshold_simplex::signing_scheme::SigningScheme,
    types::{Epoch, Round, View},
    Epochable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Error, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{Digest, PublicKey};
use commonware_utils::quorum_from_slice;
use rand::{CryptoRng, Rng};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    ops::Deref,
};

/// Context is a collection of metadata from consensus about a given payload.
/// It provides information about the current epoch/view and the parent payload that new proposals are built on.
#[derive(Clone)]
pub struct Context<D: Digest> {
    /// Current round of consensus.
    pub round: Round,
    /// Parent the payload is built on.
    ///
    /// If there is a gap between the current view and the parent view, the participant
    /// must possess a nullification for each discarded view to safely vote on the proposed
    /// payload (any view without a nullification may eventually be finalized and skipping
    /// it would result in a fork).
    pub parent: (View, D),
}

impl<D: Digest> Epochable for Context<D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<D: Digest> Viewable for Context<D> {
    type View = View;

    fn view(&self) -> View {
        self.round.view()
    }
}

/// Attributable is a trait that provides access to the signer index.
/// This is used to identify which participant signed a given message.
pub trait Attributable {
    /// Returns the index of the signer (validator) who produced this message.
    fn signer(&self) -> u32;
}

/// Identifies the signing domain for a vote or certificate.
///
/// Implementations use the context to derive domain-separated message bytes for both
/// individual votes and recovered certificates.
#[derive(Copy, Clone)]
pub enum VoteContext<'a, D: Digest> {
    /// Signing context for notarize votes and certificates, carrying the proposal.
    Notarize { proposal: &'a Proposal<D> },
    /// Signing context for nullify votes and certificates, scoped to a round.
    Nullify { round: Round },
    /// Signing context for finalize votes and certificates, carrying the proposal.
    Finalize { proposal: &'a Proposal<D> },
}

/// Signed vote emitted by a participant.
#[derive(Clone, Debug, Eq)]
pub struct Vote<S: SigningScheme> {
    /// Index of the signer inside the participant set.
    pub signer: u32,
    /// Scheme-specific signature or share produced for the vote context.
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

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let signer = u32::read(reader)?;
        let signature = S::Signature::read(reader)?;

        Ok(Self { signer, signature })
    }
}

/// Result of verifying a batch of votes.
pub struct VoteVerification<S: SigningScheme> {
    /// Contains the votes accepted by the scheme.
    pub verified: Vec<Vote<S>>,
    /// Identifies the participant indices rejected during batch verification.
    pub invalid_signers: Vec<u32>,
}

impl<S: SigningScheme> VoteVerification<S> {
    /// Creates a new `VoteVerification` result.
    pub fn new(verified: Vec<Vote<S>>, invalid_signers: Vec<u32>) -> Self {
        Self {
            verified,
            invalid_signers,
        }
    }
}

/// The set of consensus participants.
///
/// Keys are stored in sorted order to provide stable, deterministic indices for
/// signing schemes.
#[derive(Clone, Debug)]
pub struct Participants<P: PublicKey + Eq + Hash> {
    /// Sorted list of participant public keys.
    keys: Vec<P>,
    /// Reverse lookup from public key to signer index.
    index_by_key: HashMap<P, u32>,
    /// Quorum (2f+1) computed from the participant set.
    quorum: u32,
}

impl<P: PublicKey + Eq + Hash> Participants<P> {
    /// Builds a new participant set from the provided keys.
    pub fn new(mut keys: Vec<P>) -> Self {
        let quorum = quorum_from_slice(&keys);
        keys.sort();
        let index_by_key = keys
            .iter()
            .enumerate()
            .map(|(idx, key)| (key.clone(), idx as u32))
            .collect();

        Self {
            keys,
            index_by_key,
            quorum,
        }
    }

    /// Returns the participant key at the given signer index.
    pub fn get(&self, signer: u32) -> Option<&P> {
        self.keys.get(signer as usize)
    }

    /// Returns the signer index for the given key, if present.
    pub fn signer_index(&self, key: &P) -> Option<u32> {
        self.index_by_key.get(key).copied()
    }

    /// Returns the cached quorum value for this participant set.
    pub fn quorum(&self) -> u32 {
        self.quorum
    }
}

impl<P: PublicKey + Eq + Hash> Deref for Participants<P> {
    type Target = [P];

    fn deref(&self) -> &Self::Target {
        self.keys.as_slice()
    }
}

impl<P: PublicKey + Eq + Hash> From<Vec<P>> for Participants<P> {
    fn from(keys: Vec<P>) -> Self {
        Self::new(keys)
    }
}

/// `BatchVerifier` is a utility for tracking and batch verifying consensus messages.
///
/// In consensus, verifying multiple signatures at the same time can be much more efficient
/// than verifying them one by one. This struct collects messages from participants in consensus
/// and signals they are ready to be verified when certain conditions are met (e.g., enough messages
/// to potentially reach a quorum, or when a leader's message is received).
///
/// To avoid unnecessary verification, it also tracks the number of already verified messages (ensuring
/// we no longer attempt to verify messages after a quorum of valid messages have already been verified).
/// The verifier retains a clone of the active [`SigningScheme`] so it can batch-verify votes on demand.
pub struct BatchVerifier<S: SigningScheme, D: Digest> {
    /// Signing scheme used to verify votes and assemble certificates.
    signing: S,

    /// Required quorum size. `None` disables quorum-based readiness.
    quorum: Option<usize>,

    /// Current leader index.
    leader: Option<u32>,
    /// Proposal associated with the current leader.
    leader_proposal: Option<Proposal<D>>,

    /// Pending notarize votes waiting to be verified.
    notarizes: Vec<Notarize<S, D>>,
    /// Forces notarize verification as soon as possible (set when the leader proposal is known).
    notarizes_force: bool,
    /// Count of already-verified notarize votes.
    notarizes_verified: usize,

    /// Pending nullify votes waiting to be verified.
    nullifies: Vec<Nullify<S>>,
    /// Count of already-verified nullify votes.
    nullifies_verified: usize,

    /// Pending finalize votes waiting to be verified.
    finalizes: Vec<Finalize<S, D>>,
    /// Count of already-verified finalize votes.
    finalizes_verified: usize,
}

impl<S: SigningScheme, D: Digest> BatchVerifier<S, D> {
    /// Creates a new `BatchVerifier`.
    ///
    /// # Arguments
    ///
    /// * `signing` - Scheme handle used to verify and aggregate votes.
    /// * `quorum` - An optional `u32` specifying the number of votes (2f+1)
    ///   required to reach a quorum. If `None`, batch verification readiness
    ///   checks based on quorum size are skipped.
    pub fn new(signing: S, quorum: Option<u32>) -> Self {
        Self {
            signing,

            // Store quorum as usize to simplify comparisons against queue lengths.
            quorum: quorum.map(|q| q as usize),

            leader: None,
            leader_proposal: None,

            notarizes: Vec::new(),
            notarizes_force: false,
            notarizes_verified: 0,

            nullifies: Vec::new(),
            nullifies_verified: 0,

            finalizes: Vec::new(),
            finalizes_verified: 0,
        }
    }

    /// Clears any pending messages that are not for the leader's proposal and forces
    /// the notarizes to be verified.
    ///
    /// We force verification because we need to know the leader's proposal
    /// to begin verifying it.
    fn set_leader_proposal(&mut self, proposal: Proposal<D>) {
        // Drop all notarizes/finalizes that aren't for the leader proposal
        self.notarizes.retain(|n| n.proposal == proposal);
        self.finalizes.retain(|f| f.proposal == proposal);

        // Set the leader proposal
        self.leader_proposal = Some(proposal);

        // Force the notarizes to be verified
        self.notarizes_force = true;
    }

    /// Adds a [Voter] message to the batch for later verification.
    ///
    /// If the message has already been verified (e.g., we built it), it increments
    /// the count of verified messages directly. Otherwise, it adds the message to
    /// the appropriate pending queue.
    ///
    /// If a leader is known and the message is a [Voter::Notarize] from that leader,
    /// this method may trigger `set_leader_proposal`.
    ///
    /// Recovered messages (e.g., [Voter::Notarization], [Voter::Nullification], [Voter::Finalization])
    /// are not expected here and will cause a panic.
    ///
    /// # Arguments
    ///
    /// * `msg` - The [Voter] message to add.
    /// * `verified` - A boolean indicating if the message has already been verified.
    pub fn add(&mut self, msg: Voter<S, D>, verified: bool) {
        match msg {
            Voter::Notarize(notarize) => {
                if let Some(ref leader_proposal) = self.leader_proposal {
                    // If leader proposal is set and the message is not for it, drop it
                    if leader_proposal != &notarize.proposal {
                        return;
                    }
                } else if let Some(leader) = self.leader {
                    // If leader is set but leader proposal is not, set it
                    if leader == notarize.signer() {
                        // Set the leader proposal
                        self.set_leader_proposal(notarize.proposal.clone());
                    }
                }

                // If we've made it this far, add the notarize
                if verified {
                    self.notarizes_verified += 1;
                } else {
                    self.notarizes.push(notarize);
                }
            }
            Voter::Nullify(nullify) => {
                if verified {
                    self.nullifies_verified += 1;
                } else {
                    self.nullifies.push(nullify);
                }
            }
            Voter::Finalize(finalize) => {
                // If leader proposal is set and the message is not for it, drop it
                if let Some(ref leader_proposal) = self.leader_proposal {
                    if leader_proposal != &finalize.proposal {
                        return;
                    }
                }

                // If we've made it this far, add the finalize
                if verified {
                    self.finalizes_verified += 1;
                } else {
                    self.finalizes.push(finalize);
                }
            }
            Voter::Notarization(_) | Voter::Nullification(_) | Voter::Finalization(_) => {
                unreachable!("should not be adding recovered messages to partial verifier");
            }
        }
    }

    /// Sets the leader for the current consensus view.
    ///
    /// If the leader is found, we may call `set_leader_proposal` to clear any pending
    /// messages that are not for the leader's proposal and to force verification of said
    /// proposal.
    ///
    /// # Arguments
    ///
    /// * `leader` - The `u32` identifier of the leader.
    pub fn set_leader(&mut self, leader: u32) {
        // Set the leader
        assert!(self.leader.is_none());
        self.leader = Some(leader);

        // Look for a notarize from the leader
        let Some(notarize) = self.notarizes.iter().find(|n| n.signer() == leader) else {
            return;
        };

        // Set the leader proposal
        self.set_leader_proposal(notarize.proposal.clone());
    }

    /// Verifies a batch of pending [Voter::Notarize] messages.
    ///
    /// It uses `S::verify_votes` for efficient batch verification.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    /// * `namespace` - The namespace for signature domain separation.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A `Vec<Voter<S, D>>` of successfully verified [Voter::Notarize] messages (wrapped as [Voter]).
    /// * A `Vec<u32>` of signer indices for whom verification failed.
    pub fn verify_notarizes<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        namespace: &[u8],
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        self.notarizes_force = false;

        let mut notarizes = std::mem::take(&mut self.notarizes);

        // Early return if there are no notarizes to verify
        if notarizes.is_empty() {
            return (vec![], vec![]);
        }

        // If there is only one notarize, we can skip batch verification
        if notarizes.len() == 1 {
            let notarize = notarizes.pop().expect("checked above that length is 1");
            if self.signing.verify_vote(
                namespace,
                VoteContext::Notarize {
                    proposal: &notarize.proposal,
                },
                &notarize.vote,
            ) {
                self.notarizes_verified += 1;
                return (vec![Voter::Notarize(notarize)], vec![]);
            } else {
                return (vec![], vec![notarize.signer()]);
            };
        }

        // Otherwise, we need to batch verify
        let (proposals, votes): (Vec<_>, Vec<_>) =
            notarizes.into_iter().map(|n| (n.proposal, n.vote)).unzip();

        let proposal = &proposals[0];

        let VoteVerification {
            verified,
            invalid_signers,
        } = self
            .signing
            .verify_votes(rng, namespace, VoteContext::Notarize { proposal }, votes);

        self.notarizes_verified += verified.len();

        (
            verified
                .into_iter()
                .zip(proposals)
                .map(|(vote, proposal)| Voter::Notarize(Notarize { proposal, vote }))
                .collect(),
            invalid_signers,
        )
    }

    /// Checks if there are [Voter::Notarize] messages ready for batch verification.
    ///
    /// Verification is considered "ready" if:
    /// 1. `notarizes_force` is true (e.g., after a leader's proposal is set).
    /// 2. A leader and their proposal are known, and:
    ///    a. The quorum (if set) has not yet been met by verified messages.
    ///    b. The sum of verified and pending messages is enough to potentially reach the quorum.
    /// 3. There are pending [Voter::Notarize] messages to verify.
    ///
    /// # Returns
    ///
    /// `true` if [Voter::Notarize] messages should be verified, `false` otherwise.
    pub fn ready_notarizes(&self) -> bool {
        // If there are no pending notarizes, there is nothing to do.
        if self.notarizes.is_empty() {
            return false;
        }

        // If we have the leader's notarize, we should verify immediately to start
        // block verification.
        if self.notarizes_force {
            return true;
        }

        // If we don't yet know the leader, notarizes may contain messages for
        // a number of different proposals.
        if self.leader.is_none() || self.leader_proposal.is_none() {
            return false;
        }

        // If we have a quorum, we need to check if we have enough verified and pending
        if let Some(quorum) = self.quorum {
            // If we have already performed sufficient verifications, there is nothing more
            // to do.
            if self.notarizes_verified >= quorum {
                return false;
            }

            // If we don't have enough to reach the quorum, there is nothing to do yet.
            if self.notarizes_verified + self.notarizes.len() < quorum {
                return false;
            }
        }

        // If there is no required quorum and we have pending notarizes, we should verify.
        true
    }

    /// Verifies a batch of pending [Voter::Nullify] messages.
    ///
    /// It uses `S::verify_votes` for efficient batch verification.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    /// * `namespace` - The namespace for signature domain separation.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A `Vec<Voter<S, D>>` of successfully verified [Voter::Nullify] messages (wrapped as [Voter]).
    /// * A `Vec<u32>` of signer indices for whom verification failed.
    pub fn verify_nullifies<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        namespace: &[u8],
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        let mut nullifies = std::mem::take(&mut self.nullifies);

        // Early return if there are no nullifies to verify
        if nullifies.is_empty() {
            return (vec![], vec![]);
        }

        // If there is only one nullify, we can skip batch verification
        if nullifies.len() == 1 {
            let nullify = nullifies.pop().expect("checked above that length is 1");
            if self.signing.verify_vote::<D>(
                namespace,
                VoteContext::Nullify {
                    round: nullify.round,
                },
                &nullify.vote,
            ) {
                self.nullifies_verified += 1;
                return (vec![Voter::Nullify(nullify)], vec![]);
            } else {
                return (vec![], vec![nullify.signer()]);
            };
        }

        // Otherwise, we need to batch verify
        let round = nullifies[0].round;

        let VoteVerification {
            verified,
            invalid_signers,
        } = self.signing.verify_votes::<_, D, _>(
            rng,
            namespace,
            VoteContext::Nullify { round },
            nullifies.into_iter().map(|nullify| nullify.vote),
        );

        self.nullifies_verified += verified.len();

        (
            verified
                .into_iter()
                .map(|vote| Voter::Nullify(Nullify { round, vote }))
                .collect(),
            invalid_signers,
        )
    }

    /// Checks if there are [Voter::Nullify] messages ready for batch verification.
    ///
    /// Verification is considered "ready" if:
    /// 1. The quorum (if set) has not yet been met by verified messages.
    /// 2. The sum of verified and pending messages is enough to potentially reach the quorum.
    /// 3. There are pending [Voter::Nullify] messages to verify.
    ///
    /// # Returns
    ///
    /// `true` if [Voter::Nullify] messages should be verified, `false` otherwise.
    pub fn ready_nullifies(&self) -> bool {
        // If there are no pending nullifies, there is nothing to do.
        if self.nullifies.is_empty() {
            return false;
        }

        if let Some(quorum) = self.quorum {
            // If we have already performed sufficient verifications, there is nothing more
            // to do.
            if self.nullifies_verified >= quorum {
                return false;
            }

            // If we don't have enough to reach the quorum, there is nothing to do yet.
            if self.nullifies_verified + self.nullifies.len() < quorum {
                return false;
            }
        }

        // If there is no required quorum and we have pending nullifies, we should verify.
        true
    }

    /// Verifies a batch of pending [Voter::Finalize] messages.
    ///
    /// It uses `S::verify_votes` for efficient batch verification.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    /// * `namespace` - The namespace for signature domain separation.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A `Vec<Voter<S, D>>` of successfully verified [Voter::Finalize] messages (wrapped as [Voter]).
    /// * A `Vec<u32>` of signer indices for whom verification failed.
    pub fn verify_finalizes<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        namespace: &[u8],
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        let mut finalizes = std::mem::take(&mut self.finalizes);

        // Early return if there are no finalizes to verify
        if finalizes.is_empty() {
            return (vec![], vec![]);
        }

        // If there is only one finalize, we can skip batch verification
        if finalizes.len() == 1 {
            let finalize = finalizes.pop().expect("checked above that length is 1");
            if self.signing.verify_vote(
                namespace,
                VoteContext::Finalize {
                    proposal: &finalize.proposal,
                },
                &finalize.vote,
            ) {
                self.finalizes_verified += 1;
                return (vec![Voter::Finalize(finalize)], vec![]);
            } else {
                return (vec![], vec![finalize.signer()]);
            };
        }

        // Otherwise, we need to batch verify
        let (proposals, votes): (Vec<_>, Vec<_>) =
            finalizes.into_iter().map(|n| (n.proposal, n.vote)).unzip();

        let proposal = &proposals[0];

        let VoteVerification {
            verified,
            invalid_signers,
        } = self
            .signing
            .verify_votes(rng, namespace, VoteContext::Finalize { proposal }, votes);

        self.finalizes_verified += verified.len();

        (
            verified
                .into_iter()
                .zip(proposals)
                .map(|(vote, proposal)| Voter::Finalize(Finalize { proposal, vote }))
                .collect(),
            invalid_signers,
        )
    }

    /// Checks if there are [Voter::Finalize] messages ready for batch verification.
    ///
    /// Verification is considered "ready" if:
    /// 1. A leader and their proposal are known (finalizes are proposal-specific).
    /// 2. The quorum (if set) has not yet been met by verified messages.
    /// 3. The sum of verified and pending messages is enough to potentially reach the quorum.
    /// 4. There are pending [Voter::Finalize] messages to verify.
    ///
    /// # Returns
    ///
    /// `true` if [Voter::Finalize] messages should be verified, `false` otherwise.
    pub fn ready_finalizes(&self) -> bool {
        // If there are no pending finalizes, there is nothing to do.
        if self.finalizes.is_empty() {
            return false;
        }

        // If we don't yet know the leader, finalizers may contain messages for
        // a number of different proposals.
        if self.leader.is_none() || self.leader_proposal.is_none() {
            return false;
        }
        if let Some(quorum) = self.quorum {
            // If we have already performed sufficient verifications, there is nothing more
            // to do.
            if self.finalizes_verified >= quorum {
                return false;
            }

            // If we don't have enough to reach the quorum, there is nothing to do yet.
            if self.finalizes_verified + self.finalizes.len() < quorum {
                return false;
            }
        }

        // If there is no required quorum and we have pending finalizes, we should verify.
        true
    }
}

/// Voter represents all possible message types that can be sent by validators
/// in the consensus protocol.
#[derive(Clone, Debug, PartialEq)]
pub enum Voter<S: SigningScheme, D: Digest> {
    /// A validator's notarize vote over a proposal
    Notarize(Notarize<S, D>),
    /// A recovered certificate for a notarization (scheme-specific)
    Notarization(Notarization<S, D>),
    /// A validator's nullify vote used to skip the current view (usually when the leader is unresponsive)
    Nullify(Nullify<S>),
    /// A recovered certificate for a nullification (scheme-specific)
    Nullification(Nullification<S>),
    /// A validator's finalize vote over a proposal
    Finalize(Finalize<S, D>),
    /// A recovered certificate for a finalization (scheme-specific)
    Finalization(Finalization<S, D>),
}

impl<S: SigningScheme, D: Digest> Write for Voter<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Voter::Notarize(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Voter::Notarization(v) => {
                1u8.write(writer);
                v.write(writer);
            }
            Voter::Nullify(v) => {
                2u8.write(writer);
                v.write(writer);
            }
            Voter::Nullification(v) => {
                3u8.write(writer);
                v.write(writer);
            }
            Voter::Finalize(v) => {
                4u8.write(writer);
                v.write(writer);
            }
            Voter::Finalization(v) => {
                5u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<S: SigningScheme, D: Digest> EncodeSize for Voter<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Voter::Notarize(v) => v.encode_size(),
            Voter::Notarization(v) => v.encode_size(),
            Voter::Nullify(v) => v.encode_size(),
            Voter::Nullification(v) => v.encode_size(),
            Voter::Finalize(v) => v.encode_size(),
            Voter::Finalization(v) => v.encode_size(),
        }
    }
}

impl<S: SigningScheme, D: Digest> Read for Voter<S, D> {
    type Cfg = S::CertificateCfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Notarize::read(reader)?;
                Ok(Voter::Notarize(v))
            }
            1 => {
                let v = Notarization::read_cfg(reader, cfg)?;
                Ok(Voter::Notarization(v))
            }
            2 => {
                let v = Nullify::read(reader)?;
                Ok(Voter::Nullify(v))
            }
            3 => {
                let v = Nullification::read_cfg(reader, cfg)?;
                Ok(Voter::Nullification(v))
            }
            4 => {
                let v = Finalize::read(reader)?;
                Ok(Voter::Finalize(v))
            }
            5 => {
                let v = Finalization::read_cfg(reader, cfg)?;
                Ok(Voter::Finalization(v))
            }
            _ => Err(Error::Invalid(
                "consensus::threshold_simplex::Voter",
                "Invalid type",
            )),
        }
    }
}

impl<S: SigningScheme, D: Digest> Epochable for Voter<S, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        match self {
            Voter::Notarize(v) => v.epoch(),
            Voter::Notarization(v) => v.epoch(),
            Voter::Nullify(v) => v.epoch(),
            Voter::Nullification(v) => v.epoch(),
            Voter::Finalize(v) => v.epoch(),
            Voter::Finalization(v) => v.epoch(),
        }
    }
}

impl<S: SigningScheme, D: Digest> Viewable for Voter<S, D> {
    type View = View;

    fn view(&self) -> View {
        match self {
            Voter::Notarize(v) => v.view(),
            Voter::Notarization(v) => v.view(),
            Voter::Nullify(v) => v.view(),
            Voter::Nullification(v) => v.view(),
            Voter::Finalize(v) => v.view(),
            Voter::Finalization(v) => v.view(),
        }
    }
}

/// Proposal represents a proposed block in the protocol.
/// It includes the view number, the parent view, and the actual payload (typically a digest of block data).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Proposal<D: Digest> {
    /// The round in which this proposal is made
    pub round: Round,
    /// The view of the parent proposal that this one builds upon
    pub parent: View,
    /// The actual payload/content of the proposal (typically a digest of the block data)
    pub payload: D,
}

impl<D: Digest> Proposal<D> {
    /// Creates a new proposal with the specified view, parent view, and payload.
    pub fn new(round: Round, parent: View, payload: D) -> Self {
        Proposal {
            round,
            parent,
            payload,
        }
    }
}

impl<D: Digest> Write for Proposal<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        UInt(self.parent).write(writer);
        self.payload.write(writer)
    }
}

impl<D: Digest> Read for Proposal<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let parent = UInt::read(reader)?.into();
        let payload = D::read(reader)?;
        Ok(Self {
            round,
            parent,
            payload,
        })
    }
}

impl<D: Digest> EncodeSize for Proposal<D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + UInt(self.parent).encode_size() + self.payload.encode_size()
    }
}

impl<D: Digest> Epochable for Proposal<D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<D: Digest> Viewable for Proposal<D> {
    type View = View;

    fn view(&self) -> View {
        self.round.view()
    }
}

/// Validator vote that endorses a proposal for notarization.
#[derive(Clone, Debug, Eq)]
pub struct Notarize<S: SigningScheme, D: Digest> {
    /// Proposal being notarized.
    pub proposal: Proposal<D>,
    /// Scheme-specific vote material.
    pub vote: Vote<S>,
}

impl<S: SigningScheme, D: Digest> Notarize<S, D> {
    /// Returns the round associated with this notarize vote.
    pub fn round(&self) -> Round {
        self.proposal.round
    }
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
    /// Signs a notarize vote for the provided proposal.
    pub fn sign(scheme: &S, namespace: &[u8], proposal: Proposal<D>) -> Self {
        let vote = scheme.sign_vote(
            namespace,
            VoteContext::Notarize {
                proposal: &proposal,
            },
        );

        Self { proposal, vote }
    }

    /// Verifies the notarize vote against the provided signing scheme.
    pub fn verify(&self, scheme: &S, namespace: &[u8]) -> bool {
        scheme.verify_vote(
            namespace,
            VoteContext::Notarize {
                proposal: &self.proposal,
            },
            &self.vote,
        )
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

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let vote = Vote::read(reader)?;

        Ok(Self { proposal, vote })
    }
}

impl<S: SigningScheme, D: Digest> Attributable for Notarize<S, D> {
    fn signer(&self) -> u32 {
        self.vote.signer
    }
}

impl<S: SigningScheme, D: Digest> Epochable for Notarize<S, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: SigningScheme, D: Digest> Viewable for Notarize<S, D> {
    type View = View;

    fn view(&self) -> View {
        self.proposal.view()
    }
}

/// Aggregated notarization certificate recovered from notarize votes.
///
/// Some signing schemes embed an additional randomness seed in the certificate (used for
/// leader rotation), it can be accessed via [`SigningScheme::seed`].
#[derive(Clone, Debug, Eq)]
pub struct Notarization<S: SigningScheme, D: Digest> {
    pub proposal: Proposal<D>,
    pub certificate: S::Certificate,
}

impl<S: SigningScheme, D: Digest> Notarization<S, D> {
    /// Builds a notarization certificate from matching notarize votes, if enough are present.
    pub fn from_notarizes(signing: &S, notarizes: &[Notarize<S, D>]) -> Option<Self> {
        if notarizes.is_empty() {
            return None;
        }

        let proposal = notarizes[0].proposal.clone();

        // All votes must endorse the same proposal to be aggregated into a single certificate.
        if notarizes.iter().skip(1).any(|n| n.proposal != proposal) {
            return None;
        }

        let notarization_certificate =
            signing.assemble_certificate(notarizes.iter().map(|n| n.vote.clone()), None)?;

        Some(Notarization {
            proposal,
            certificate: notarization_certificate,
        })
    }

    /// Returns the round associated with the notarized proposal.
    pub fn round(&self) -> Round {
        self.proposal.round
    }
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
    /// Verifies the notarization certificate against the provided signing scheme.
    pub fn verify<R: Rng + CryptoRng>(&self, rng: &mut R, scheme: &S, namespace: &[u8]) -> bool {
        scheme.verify_certificate(
            rng,
            namespace,
            VoteContext::Notarize {
                proposal: &self.proposal,
            },
            &self.certificate,
        )
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
    type Cfg = S::CertificateCfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;

        Ok(Self {
            proposal,
            certificate,
        })
    }
}

impl<S: SigningScheme, D: Digest> Epochable for Notarization<S, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: SigningScheme, D: Digest> Viewable for Notarization<S, D> {
    type View = View;

    fn view(&self) -> View {
        self.proposal.view()
    }
}

/// Validator vote for nullifying the current round.
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
    /// Signs a nullify vote for the given round.
    pub fn sign<D: Digest>(scheme: &S, namespace: &[u8], round: Round) -> Self {
        let vote = scheme.sign_vote::<D>(namespace, VoteContext::Nullify { round });

        Self { round, vote }
    }

    /// Verifies the nullify vote against the provided signing scheme.
    pub fn verify<D: Digest>(&self, scheme: &S, namespace: &[u8]) -> bool {
        scheme.verify_vote::<D>(
            namespace,
            VoteContext::Nullify { round: self.round },
            &self.vote,
        )
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

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let vote = Vote::read(reader)?;

        Ok(Self { round, vote })
    }
}

impl<S: SigningScheme> Attributable for Nullify<S> {
    fn signer(&self) -> u32 {
        self.vote.signer
    }
}

impl<S: SigningScheme> Epochable for Nullify<S> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<S: SigningScheme> Viewable for Nullify<S> {
    type View = View;

    fn view(&self) -> View {
        self.round.view()
    }
}

/// Aggregated nullification certificate for a round.
#[derive(Clone, Debug, Eq)]
pub struct Nullification<S: SigningScheme> {
    pub round: Round,
    pub certificate: S::Certificate,
}

impl<S: SigningScheme> Nullification<S> {
    /// Builds a nullification certificate from matching nullify votes.
    pub fn from_nullifies(signing: &S, nullifies: &[Nullify<S>]) -> Option<Self> {
        if nullifies.is_empty() {
            return None;
        }

        let round = nullifies[0].round;

        // Nullify votes must all target the same round.
        if nullifies.iter().skip(1).any(|n| n.round != round) {
            return None;
        }

        let nullification_certificate =
            signing.assemble_certificate(nullifies.iter().map(|n| n.vote.clone()), None)?;

        Some(Nullification {
            round,
            certificate: nullification_certificate,
        })
    }
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
    /// Verifies the nullification certificate against the provided signing scheme.
    pub fn verify<R: Rng + CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        scheme: &S,
        namespace: &[u8],
    ) -> bool {
        scheme.verify_certificate::<_, D>(
            rng,
            namespace,
            VoteContext::Nullify { round: self.round },
            &self.certificate,
        )
    }
}

impl<S: SigningScheme> EncodeSize for Nullification<S> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.certificate.encode_size()
    }
}

impl<S: SigningScheme> Read for Nullification<S> {
    type Cfg = S::CertificateCfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;

        Ok(Self { round, certificate })
    }
}

impl<S: SigningScheme> Epochable for Nullification<S> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<S: SigningScheme> Viewable for Nullification<S> {
    type View = View;

    fn view(&self) -> View {
        self.round.view()
    }
}

/// Validator vote finalizing a proposal after notarization.
#[derive(Clone, Debug, Eq)]
pub struct Finalize<S: SigningScheme, D: Digest> {
    pub proposal: Proposal<D>,
    pub vote: Vote<S>,
}

impl<S: SigningScheme, D: Digest> Finalize<S, D> {
    /// Returns the round associated with this finalize vote.
    pub fn round(&self) -> Round {
        self.proposal.round
    }
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
    /// Signs a finalize vote for the provided proposal.
    pub fn sign(scheme: &S, namespace: &[u8], proposal: Proposal<D>) -> Self {
        let vote = scheme.sign_vote(
            namespace,
            VoteContext::Finalize {
                proposal: &proposal,
            },
        );

        Self { proposal, vote }
    }

    /// Verifies the finalize vote against the provided signing scheme.
    pub fn verify(&self, scheme: &S, namespace: &[u8]) -> bool {
        scheme.verify_vote(
            namespace,
            VoteContext::Finalize {
                proposal: &self.proposal,
            },
            &self.vote,
        )
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

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let vote = Vote::read(reader)?;

        Ok(Self { proposal, vote })
    }
}

impl<S: SigningScheme, D: Digest> Attributable for Finalize<S, D> {
    fn signer(&self) -> u32 {
        self.vote.signer
    }
}

impl<S: SigningScheme, D: Digest> Epochable for Finalize<S, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: SigningScheme, D: Digest> Viewable for Finalize<S, D> {
    type View = View;

    fn view(&self) -> View {
        self.proposal.view()
    }
}

/// Aggregated finalization certificate.
#[derive(Clone, Debug, Eq)]
pub struct Finalization<S: SigningScheme, D: Digest> {
    pub proposal: Proposal<D>,
    pub certificate: S::Certificate,
}

impl<S: SigningScheme, D: Digest> Finalization<S, D> {
    /// Builds a finalization certificate from matching finalize votes.
    ///
    /// `notarization` carries an optional notarization certificate for the same proposal.
    /// Schemes that embed a seed signature inside the notarization (e.g. threshold BLS)
    /// can reuse it when aggregating finalize votes, while other schemes may simply
    /// ignore the hint.
    pub fn from_finalizes(
        signing: &S,
        finalizes: &[Finalize<S, D>],
        notarization: Option<&Notarization<S, D>>,
    ) -> Option<Self> {
        if finalizes.is_empty() {
            return None;
        }

        let proposal = finalizes[0].proposal.clone();

        // Finalize votes must agree on the exact proposal that is being committed.
        if finalizes.iter().skip(1).any(|f| f.proposal != proposal) {
            return None;
        }

        if let Some(notarization) = notarization {
            // Ensure the notarization matches the finalization proposal
            if notarization.proposal != proposal {
                return None;
            }
        }

        let finalization_certificate = signing.assemble_certificate(
            finalizes.iter().map(|n| n.vote.clone()),
            notarization.map(|n| n.certificate.clone()),
        )?;

        Some(Finalization {
            proposal,
            certificate: finalization_certificate,
        })
    }

    /// Returns the round associated with the finalized proposal.
    pub fn round(&self) -> Round {
        self.proposal.round
    }
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
    /// Verifies the finalization certificate against the provided signing scheme.
    pub fn verify<R: Rng + CryptoRng>(&self, rng: &mut R, scheme: &S, namespace: &[u8]) -> bool {
        scheme.verify_certificate(
            rng,
            namespace,
            VoteContext::Finalize {
                proposal: &self.proposal,
            },
            &self.certificate,
        )
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
    type Cfg = S::CertificateCfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;

        Ok(Self {
            proposal,
            certificate,
        })
    }
}

impl<S: SigningScheme, D: Digest> Epochable for Finalization<S, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: SigningScheme, D: Digest> Viewable for Finalization<S, D> {
    type View = View;

    fn view(&self) -> View {
        self.proposal.view()
    }
}

/// Backfiller is a message type for requesting and receiving missing consensus artifacts.
/// This is used to synchronize validators that have fallen behind or just joined the network.
#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<S: SigningScheme, D: Digest> {
    /// Request for missing notarizations and nullifications
    Request(Request),
    /// Response containing requested notarizations and nullifications
    Response(Response<S, D>),
}

impl<S: SigningScheme, D: Digest> Write for Backfiller<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Backfiller::Request(request) => {
                0u8.write(writer);
                request.write(writer);
            }
            Backfiller::Response(response) => {
                1u8.write(writer);
                response.write(writer);
            }
        }
    }
}

impl<S: SigningScheme, D: Digest> EncodeSize for Backfiller<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Backfiller::Request(v) => v.encode_size(),
            Backfiller::Response(v) => v.encode_size(),
        }
    }
}

impl<S: SigningScheme, D: Digest> Read for Backfiller<S, D> {
    type Cfg = (usize, S::CertificateCfg);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let (max_len, _) = cfg;
                let v = Request::read_cfg(reader, max_len)?;
                Ok(Backfiller::Request(v))
            }
            1 => {
                let v = Response::<S, D>::read_cfg(reader, cfg)?;
                Ok(Backfiller::Response(v))
            }
            _ => Err(Error::Invalid(
                "consensus::threshold_simplex::Backfiller",
                "Invalid type",
            )),
        }
    }
}

/// Request is a message to request missing notarizations and nullifications.
/// This is used by validators who need to catch up with the consensus state.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    /// Unique identifier for this request (used to match responses)
    pub id: u64,
    /// Views for which notarizations are requested
    pub notarizations: Vec<View>,
    /// Views for which nullifications are requested
    pub nullifications: Vec<View>,
}

impl Request {
    /// Creates a new request for missing notarizations and nullifications.
    pub fn new(id: u64, notarizations: Vec<View>, nullifications: Vec<View>) -> Self {
        Request {
            id,
            notarizations,
            nullifications,
        }
    }
}

impl Write for Request {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.id).write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        UInt(self.id).encode_size()
            + self.notarizations.encode_size()
            + self.nullifications.encode_size()
    }
}

impl Read for Request {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let id = UInt::read(reader)?.into();
        let mut views = HashSet::new();
        let notarizations = Vec::<View>::read_range(reader, ..=*max_len)?;
        for view in notarizations.iter() {
            if !views.insert(view) {
                return Err(Error::Invalid(
                    "consensus::threshold_simplex::Request",
                    "Duplicate notarization",
                ));
            }
        }
        let remaining = max_len - notarizations.len();
        views.clear();
        let nullifications = Vec::<View>::read_range(reader, ..=remaining)?;
        for view in nullifications.iter() {
            if !views.insert(view) {
                return Err(Error::Invalid(
                    "consensus::threshold_simplex::Request",
                    "Duplicate nullification",
                ));
            }
        }
        Ok(Request {
            id,
            notarizations,
            nullifications,
        })
    }
}

/// Response is a message containing the requested notarizations and nullifications.
/// This is sent in response to a Request message.
#[derive(Clone, Debug, PartialEq)]
pub struct Response<S: SigningScheme, D: Digest> {
    /// Identifier matching the original request
    pub id: u64,
    /// Notarizations for the requested views
    pub notarizations: Vec<Notarization<S, D>>,
    /// Nullifications for the requested views
    pub nullifications: Vec<Nullification<S>>,
}

impl<S: SigningScheme, D: Digest> Response<S, D> {
    /// Creates a new response with the given id, notarizations, and nullifications.
    pub fn new(
        id: u64,
        notarizations: Vec<Notarization<S, D>>,
        nullifications: Vec<Nullification<S>>,
    ) -> Self {
        Response {
            id,
            notarizations,
            nullifications,
        }
    }

    /// Verifies the certificates contained in this response against the signing scheme.
    pub fn verify<R: Rng + CryptoRng>(&self, rng: &mut R, signing: &S, namespace: &[u8]) -> bool {
        // Prepare to verify
        if self.notarizations.is_empty() && self.nullifications.is_empty() {
            return true;
        }

        let notarizations = self.notarizations.iter().map(|notarization| {
            let context = VoteContext::Notarize {
                proposal: &notarization.proposal,
            };

            (context, &notarization.certificate)
        });

        let nullifications = self.nullifications.iter().map(|nullification| {
            let context = VoteContext::Nullify {
                round: nullification.round,
            };

            (context, &nullification.certificate)
        });

        signing.verify_certificates(rng, namespace, notarizations.chain(nullifications))
    }
}

impl<S: SigningScheme, D: Digest> Write for Response<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.id).write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl<S: SigningScheme, D: Digest> EncodeSize for Response<S, D> {
    fn encode_size(&self) -> usize {
        UInt(self.id).encode_size()
            + self.notarizations.encode_size()
            + self.nullifications.encode_size()
    }
}

impl<S: SigningScheme, D: Digest> Read for Response<S, D> {
    type Cfg = (usize, S::CertificateCfg);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let (max_len, certificate_cfg) = cfg;
        let id = UInt::read(reader)?.into();
        let mut views = HashSet::new();
        let notarizations = Vec::<Notarization<S, D>>::read_cfg(
            reader,
            &((..=*max_len).into(), certificate_cfg.clone()),
        )?;
        for notarization in notarizations.iter() {
            if !views.insert(notarization.view()) {
                return Err(Error::Invalid(
                    "consensus::threshold_simplex::Response",
                    "Duplicate notarization",
                ));
            }
        }
        let remaining = max_len - notarizations.len();
        views.clear();
        let nullifications = Vec::<Nullification<S>>::read_cfg(
            reader,
            &((..=remaining).into(), certificate_cfg.clone()),
        )?;
        for nullification in nullifications.iter() {
            if !views.insert(nullification.view()) {
                return Err(Error::Invalid(
                    "consensus::threshold_simplex::Response",
                    "Duplicate nullification",
                ));
            }
        }
        Ok(Response {
            id,
            notarizations,
            nullifications,
        })
    }
}

/// Activity represents all possible activities that can occur in the consensus protocol.
/// This includes both regular consensus messages and fault evidence.
///
/// Some activities issued by consensus are not verified. To determine if an activity has been verified,
/// use the `verified` method.
///
/// # Warning
///
/// Certain signing schemes produce aggregated artifacts that do not expose every contributor.
/// Unless the scheme provides attributable signatures, do not use unverified activities for
/// incentives, an attacker may be able to synthesize contributions for offline participants.
#[derive(Clone, Debug)]
pub enum Activity<S: SigningScheme, D: Digest> {
    /// A validator's notarize vote over a proposal
    Notarize(Notarize<S, D>),
    /// A recovered certificate for a notarization (scheme-specific)
    Notarization(Notarization<S, D>),
    /// A validator's nullify vote used to skip the current view
    Nullify(Nullify<S>),
    /// A recovered certificate for a nullification (scheme-specific)
    Nullification(Nullification<S>),
    /// A validator's finalize vote over a proposal
    Finalize(Finalize<S, D>),
    /// A recovered certificate for a finalization (scheme-specific)
    Finalization(Finalization<S, D>),
    /// Evidence of a validator sending conflicting notarizes (Byzantine behavior)
    ConflictingNotarize(ConflictingNotarize<S, D>),
    /// Evidence of a validator sending conflicting finalizes (Byzantine behavior)
    ConflictingFinalize(ConflictingFinalize<S, D>),
    /// Evidence of a validator sending both nullify and finalize for the same view (Byzantine behavior)
    NullifyFinalize(NullifyFinalize<S, D>),
}

impl<S: SigningScheme, D: Digest> PartialEq for Activity<S, D> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Activity::Notarize(a), Activity::Notarize(b)) => a == b,
            (Activity::Notarization(a), Activity::Notarization(b)) => a == b,
            (Activity::Nullify(a), Activity::Nullify(b)) => a == b,
            (Activity::Nullification(a), Activity::Nullification(b)) => a == b,
            (Activity::Finalize(a), Activity::Finalize(b)) => a == b,
            (Activity::Finalization(a), Activity::Finalization(b)) => a == b,
            (Activity::ConflictingNotarize(a), Activity::ConflictingNotarize(b)) => a == b,
            (Activity::ConflictingFinalize(a), Activity::ConflictingFinalize(b)) => a == b,
            (Activity::NullifyFinalize(a), Activity::NullifyFinalize(b)) => a == b,
            _ => false,
        }
    }
}

impl<S: SigningScheme, D: Digest> Eq for Activity<S, D> {}

impl<S: SigningScheme, D: Digest> Hash for Activity<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Activity::Notarize(v) => {
                0u8.hash(state);
                v.hash(state);
            }
            Activity::Notarization(v) => {
                1u8.hash(state);
                v.hash(state);
            }
            Activity::Nullify(v) => {
                2u8.hash(state);
                v.hash(state);
            }
            Activity::Nullification(v) => {
                3u8.hash(state);
                v.hash(state);
            }
            Activity::Finalize(v) => {
                4u8.hash(state);
                v.hash(state);
            }
            Activity::Finalization(v) => {
                5u8.hash(state);
                v.hash(state);
            }
            Activity::ConflictingNotarize(v) => {
                6u8.hash(state);
                v.hash(state);
            }
            Activity::ConflictingFinalize(v) => {
                7u8.hash(state);
                v.hash(state);
            }
            Activity::NullifyFinalize(v) => {
                8u8.hash(state);
                v.hash(state);
            }
        }
    }
}

impl<S: SigningScheme, D: Digest> Activity<S, D> {
    /// Indicates whether the activity has been verified by consensus.
    pub fn verified(&self) -> bool {
        match self {
            Activity::Notarize(_) => false,
            Activity::Notarization(_) => true,
            Activity::Nullify(_) => false,
            Activity::Nullification(_) => true,
            Activity::Finalize(_) => false,
            Activity::Finalization(_) => true,
            Activity::ConflictingNotarize(_) => false,
            Activity::ConflictingFinalize(_) => false,
            Activity::NullifyFinalize(_) => false,
        }
    }
}

impl<S: SigningScheme, D: Digest> Write for Activity<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Activity::Notarize(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Activity::Notarization(v) => {
                1u8.write(writer);
                v.write(writer);
            }
            Activity::Nullify(v) => {
                2u8.write(writer);
                v.write(writer);
            }
            Activity::Nullification(v) => {
                3u8.write(writer);
                v.write(writer);
            }
            Activity::Finalize(v) => {
                4u8.write(writer);
                v.write(writer);
            }
            Activity::Finalization(v) => {
                5u8.write(writer);
                v.write(writer);
            }
            Activity::ConflictingNotarize(v) => {
                6u8.write(writer);
                v.write(writer);
            }
            Activity::ConflictingFinalize(v) => {
                7u8.write(writer);
                v.write(writer);
            }
            Activity::NullifyFinalize(v) => {
                8u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<S: SigningScheme, D: Digest> EncodeSize for Activity<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Activity::Notarize(v) => v.encode_size(),
            Activity::Notarization(v) => v.encode_size(),
            Activity::Nullify(v) => v.encode_size(),
            Activity::Nullification(v) => v.encode_size(),
            Activity::Finalize(v) => v.encode_size(),
            Activity::Finalization(v) => v.encode_size(),
            Activity::ConflictingNotarize(v) => v.encode_size(),
            Activity::ConflictingFinalize(v) => v.encode_size(),
            Activity::NullifyFinalize(v) => v.encode_size(),
        }
    }
}

impl<S: SigningScheme, D: Digest> Read for Activity<S, D> {
    type Cfg = S::CertificateCfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Notarize::<S, D>::read(reader)?;
                Ok(Activity::Notarize(v))
            }
            1 => {
                let v = Notarization::<S, D>::read_cfg(reader, cfg)?;
                Ok(Activity::Notarization(v))
            }
            2 => {
                let v = Nullify::<S>::read(reader)?;
                Ok(Activity::Nullify(v))
            }
            3 => {
                let v = Nullification::<S>::read_cfg(reader, cfg)?;
                Ok(Activity::Nullification(v))
            }
            4 => {
                let v = Finalize::<S, D>::read(reader)?;
                Ok(Activity::Finalize(v))
            }
            5 => {
                let v = Finalization::<S, D>::read_cfg(reader, cfg)?;
                Ok(Activity::Finalization(v))
            }
            6 => {
                let v = ConflictingNotarize::<S, D>::read(reader)?;
                Ok(Activity::ConflictingNotarize(v))
            }
            7 => {
                let v = ConflictingFinalize::<S, D>::read(reader)?;
                Ok(Activity::ConflictingFinalize(v))
            }
            8 => {
                let v = NullifyFinalize::<S, D>::read(reader)?;
                Ok(Activity::NullifyFinalize(v))
            }
            _ => Err(Error::Invalid(
                "consensus::threshold_simplex::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<S: SigningScheme, D: Digest> Epochable for Activity<S, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        match self {
            Activity::Notarize(v) => v.epoch(),
            Activity::Notarization(v) => v.epoch(),
            Activity::Nullify(v) => v.epoch(),
            Activity::Nullification(v) => v.epoch(),
            Activity::Finalize(v) => v.epoch(),
            Activity::Finalization(v) => v.epoch(),
            Activity::ConflictingNotarize(v) => v.epoch(),
            Activity::ConflictingFinalize(v) => v.epoch(),
            Activity::NullifyFinalize(v) => v.epoch(),
        }
    }
}

impl<S: SigningScheme, D: Digest> Viewable for Activity<S, D> {
    type View = View;

    fn view(&self) -> View {
        match self {
            Activity::Notarize(v) => v.view(),
            Activity::Notarization(v) => v.view(),
            Activity::Nullify(v) => v.view(),
            Activity::Nullification(v) => v.view(),
            Activity::Finalize(v) => v.view(),
            Activity::Finalization(v) => v.view(),
            Activity::ConflictingNotarize(v) => v.view(),
            Activity::ConflictingFinalize(v) => v.view(),
            Activity::NullifyFinalize(v) => v.view(),
        }
    }
}

/// ConflictingNotarize represents evidence of a Byzantine validator sending conflicting notarizes.
/// This is used to prove that a validator has equivocated (voted for different proposals in the same view).
#[derive(Clone, Debug, Eq)]
pub struct ConflictingNotarize<S: SigningScheme, D: Digest> {
    notarize_1: Notarize<S, D>,
    notarize_2: Notarize<S, D>,
}

impl<S: SigningScheme, D: Digest> PartialEq for ConflictingNotarize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.notarize_1 == other.notarize_1 && self.notarize_2 == other.notarize_2
    }
}

impl<S: SigningScheme, D: Digest> Hash for ConflictingNotarize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.notarize_1.hash(state);
        self.notarize_2.hash(state);
    }
}

impl<S: SigningScheme, D: Digest> ConflictingNotarize<S, D> {
    /// Creates a new conflicting notarize evidence from two conflicting notarizes.
    pub fn new(notarize_1: Notarize<S, D>, notarize_2: Notarize<S, D>) -> Self {
        assert_eq!(notarize_1.round(), notarize_2.round());
        assert_eq!(notarize_1.signer(), notarize_2.signer());

        ConflictingNotarize {
            notarize_1,
            notarize_2,
        }
    }

    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify(&self, signing: &S, namespace: &[u8]) -> bool {
        self.notarize_1.verify(signing, namespace) && self.notarize_2.verify(signing, namespace)
    }
}

impl<S: SigningScheme, D: Digest> Attributable for ConflictingNotarize<S, D> {
    fn signer(&self) -> u32 {
        self.notarize_1.signer()
    }
}

impl<S: SigningScheme, D: Digest> Epochable for ConflictingNotarize<S, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.notarize_1.epoch()
    }
}

impl<S: SigningScheme, D: Digest> Viewable for ConflictingNotarize<S, D> {
    type View = View;

    fn view(&self) -> View {
        self.notarize_1.view()
    }
}

impl<S: SigningScheme, D: Digest> Write for ConflictingNotarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.notarize_1.write(writer);
        self.notarize_2.write(writer);
    }
}

impl<S: SigningScheme, D: Digest> Read for ConflictingNotarize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let notarize_1 = Notarize::read(reader)?;
        let notarize_2 = Notarize::read(reader)?;

        if notarize_1.signer() != notarize_2.signer() || notarize_1.round() != notarize_2.round() {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::ConflictingNotarize",
                "invalid conflicting notarize",
            ));
        }

        Ok(ConflictingNotarize {
            notarize_1,
            notarize_2,
        })
    }
}

impl<S: SigningScheme, D: Digest> EncodeSize for ConflictingNotarize<S, D> {
    fn encode_size(&self) -> usize {
        self.notarize_1.encode_size() + self.notarize_2.encode_size()
    }
}

/// ConflictingFinalize represents evidence of a Byzantine validator sending conflicting finalizes.
/// Similar to ConflictingNotarize, but for finalizes.
#[derive(Clone, Debug, Eq)]
pub struct ConflictingFinalize<S: SigningScheme, D: Digest> {
    finalize_1: Finalize<S, D>,
    finalize_2: Finalize<S, D>,
}

impl<S: SigningScheme, D: Digest> PartialEq for ConflictingFinalize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.finalize_1 == other.finalize_1 && self.finalize_2 == other.finalize_2
    }
}

impl<S: SigningScheme, D: Digest> Hash for ConflictingFinalize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.finalize_1.hash(state);
        self.finalize_2.hash(state);
    }
}

impl<S: SigningScheme, D: Digest> ConflictingFinalize<S, D> {
    /// Creates a new conflicting finalize evidence from two conflicting finalizes.
    pub fn new(finalize_1: Finalize<S, D>, finalize_2: Finalize<S, D>) -> Self {
        assert_eq!(finalize_1.round(), finalize_2.round());
        assert_eq!(finalize_1.signer(), finalize_2.signer());

        ConflictingFinalize {
            finalize_1,
            finalize_2,
        }
    }

    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify(&self, signing: &S, namespace: &[u8]) -> bool {
        self.finalize_1.verify(signing, namespace) && self.finalize_2.verify(signing, namespace)
    }
}

impl<S: SigningScheme, D: Digest> Attributable for ConflictingFinalize<S, D> {
    fn signer(&self) -> u32 {
        self.finalize_1.signer()
    }
}

impl<S: SigningScheme, D: Digest> Epochable for ConflictingFinalize<S, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.finalize_1.epoch()
    }
}

impl<S: SigningScheme, D: Digest> Viewable for ConflictingFinalize<S, D> {
    type View = View;

    fn view(&self) -> View {
        self.finalize_1.view()
    }
}

impl<S: SigningScheme, D: Digest> Write for ConflictingFinalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.finalize_1.write(writer);
        self.finalize_2.write(writer);
    }
}

impl<S: SigningScheme, D: Digest> Read for ConflictingFinalize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let finalize_1 = Finalize::read(reader)?;
        let finalize_2 = Finalize::read(reader)?;

        if finalize_1.signer() != finalize_2.signer() || finalize_1.round() != finalize_2.round() {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::ConflictingFinalize",
                "invalid conflicting finalize",
            ));
        }

        Ok(ConflictingFinalize {
            finalize_1,
            finalize_2,
        })
    }
}

impl<S: SigningScheme, D: Digest> EncodeSize for ConflictingFinalize<S, D> {
    fn encode_size(&self) -> usize {
        self.finalize_1.encode_size() + self.finalize_2.encode_size()
    }
}

/// NullifyFinalize represents evidence of a Byzantine validator sending both a nullify and finalize
/// for the same view, which is contradictory behavior (a validator should either try to skip a view OR
/// finalize a proposal, not both).
#[derive(Clone, Debug, Eq)]
pub struct NullifyFinalize<S: SigningScheme, D: Digest> {
    nullify: Nullify<S>,
    finalize: Finalize<S, D>,
}

impl<S: SigningScheme, D: Digest> PartialEq for NullifyFinalize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.nullify == other.nullify && self.finalize == other.finalize
    }
}

impl<S: SigningScheme, D: Digest> Hash for NullifyFinalize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.nullify.hash(state);
        self.finalize.hash(state);
    }
}

impl<S: SigningScheme, D: Digest> NullifyFinalize<S, D> {
    /// Creates a new nullify-finalize evidence from a nullify and a finalize.
    pub fn new(nullify: Nullify<S>, finalize: Finalize<S, D>) -> Self {
        assert_eq!(nullify.round, finalize.round());
        assert_eq!(nullify.signer(), finalize.signer());

        NullifyFinalize { nullify, finalize }
    }

    /// Verifies that both the nullify and finalize signatures are valid, proving Byzantine behavior.
    pub fn verify(&self, signing: &S, namespace: &[u8]) -> bool {
        self.nullify.verify::<D>(signing, namespace) && self.finalize.verify(signing, namespace)
    }
}

impl<S: SigningScheme, D: Digest> Attributable for NullifyFinalize<S, D> {
    fn signer(&self) -> u32 {
        self.nullify.signer()
    }
}

impl<S: SigningScheme, D: Digest> Epochable for NullifyFinalize<S, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.nullify.epoch()
    }
}

impl<S: SigningScheme, D: Digest> Viewable for NullifyFinalize<S, D> {
    type View = View;

    fn view(&self) -> View {
        self.nullify.view()
    }
}

impl<S: SigningScheme, D: Digest> Write for NullifyFinalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.nullify.write(writer);
        self.finalize.write(writer);
    }
}

impl<S: SigningScheme, D: Digest> Read for NullifyFinalize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let nullify = Nullify::read(reader)?;
        let finalize = Finalize::read(reader)?;

        if nullify.signer() != finalize.signer() || nullify.round != finalize.round() {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::NullifyFinalize",
                "mismatched signatures",
            ));
        }

        Ok(NullifyFinalize { nullify, finalize })
    }
}

impl<S: SigningScheme, D: Digest> EncodeSize for NullifyFinalize<S, D> {
    fn encode_size(&self) -> usize {
        self.nullify.encode_size() + self.finalize.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_simplex::signing_scheme::{bls12381_threshold, ed25519};
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops::{self},
            primitives::variant::MinSig,
        },
        ed25519::{PrivateKey as EdPrivateKey, PublicKey as EdPublicKey},
        sha256::Digest as Sha256,
        PrivateKeyExt, Signer,
    };
    use commonware_utils::quorum;
    use rand::{
        rngs::{OsRng, StdRng},
        SeedableRng,
    };

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256 {
        Sha256::from([v; 32]) // Simple fixed digest for testing
    }

    fn generate_bls12381_threshold_schemes(
        n: u32,
        seed: u64,
    ) -> Vec<bls12381_threshold::Scheme<MinSig>> {
        let mut rng = StdRng::seed_from_u64(seed);
        let t = quorum(n);
        let (polynomial, shares) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, t);

        shares
            .into_iter()
            .map(|share| bls12381_threshold::Scheme::new(&vec![0; n as usize], &polynomial, share))
            .collect()
    }

    fn generate_bls12381_threshold_verifier(
        n: u32,
        seed: u64,
    ) -> bls12381_threshold::Scheme<MinSig> {
        let mut schemes = generate_bls12381_threshold_schemes(n, seed);
        schemes.remove(0).into_verifier()
    }

    fn generate_ed25519_schemes(n: usize) -> Vec<ed25519::Scheme> {
        let mut private_keys: Vec<_> = (0..n)
            .map(|idx| EdPrivateKey::from_seed(idx as u64))
            .collect();
        private_keys.sort_by_key(|key| key.public_key());
        let participants: Vec<EdPublicKey> =
            private_keys.iter().map(|key| key.public_key()).collect();
        private_keys
            .into_iter()
            .map(|sk| ed25519::Scheme::new(participants.clone(), sk))
            .collect()
    }

    fn generate_ed25519_verifier_with_offset(n: usize, offset: u64) -> ed25519::Scheme {
        let mut private_keys: Vec<_> = (0..n)
            .map(|idx| EdPrivateKey::from_seed(idx as u64 + offset))
            .collect();
        private_keys.sort_by_key(|key| key.public_key());
        let participants: Vec<_> = private_keys.iter().map(|key| key.public_key()).collect();
        ed25519::Scheme::verifier(participants)
    }

    #[test]
    fn test_proposal_encode_decode() {
        let proposal = Proposal::new(Round::new(0, 10), 5, sample_digest(1));
        let encoded = proposal.encode();
        let decoded = Proposal::<Sha256>::decode(encoded).unwrap();
        assert_eq!(proposal, decoded);
    }

    fn notarize_encode_decode<S: SigningScheme>(schemes: &[S]) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));
        let notarize = Notarize::sign(&schemes[0], NAMESPACE, proposal);

        let encoded = notarize.encode();
        let decoded = Notarize::decode(encoded).unwrap();

        assert_eq!(notarize, decoded);
        assert!(decoded.verify(&schemes[0], NAMESPACE));
    }

    #[test]
    fn test_notarize_encode_decode() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 0);
        notarize_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        notarize_encode_decode(&ed_schemes);
    }

    fn notarization_encode_decode<S: SigningScheme>(schemes: &[S]) {
        let proposal = Proposal::new(Round::new(0, 10), 5, sample_digest(1));
        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()))
            .collect();
        let notarization = Notarization::from_notarizes(&schemes[0], &notarizes).unwrap();
        let encoded = notarization.encode();
        let cfg = schemes[0].certificate_codec_config();
        let decoded = Notarization::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(notarization, decoded);
        assert!(decoded.verify(&mut OsRng, &schemes[0], NAMESPACE));
    }

    #[test]
    fn test_notarization_encode_decode() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 1);
        notarization_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        notarization_encode_decode(&ed_schemes);
    }

    fn nullify_encode_decode<S: SigningScheme>(schemes: &[S]) {
        let round = Round::new(0, 10);
        let nullify = Nullify::sign::<Sha256>(&schemes[0], NAMESPACE, round);
        let encoded = nullify.encode();
        let decoded = Nullify::decode(encoded).unwrap();
        assert_eq!(nullify, decoded);
        assert!(decoded.verify::<Sha256>(&schemes[0], NAMESPACE));
    }

    #[test]
    fn test_nullify_encode_decode() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 2);
        nullify_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        nullify_encode_decode(&ed_schemes);
    }

    fn nullification_encode_decode<S: SigningScheme>(schemes: &[S]) {
        let round = Round::new(333, 10);
        let nullifies: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256>(scheme, NAMESPACE, round))
            .collect();
        let nullification = Nullification::from_nullifies(&schemes[0], &nullifies).unwrap();
        let encoded = nullification.encode();
        let cfg = schemes[0].certificate_codec_config();
        let decoded = Nullification::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(nullification, decoded);
        assert!(decoded.verify::<_, Sha256>(&mut OsRng, &schemes[0], NAMESPACE));
    }

    #[test]
    fn test_nullification_encode_decode() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 3);
        nullification_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        nullification_encode_decode(&ed_schemes);
    }

    fn finalize_encode_decode<S: SigningScheme>(schemes: &[S]) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));
        let finalize = Finalize::sign(&schemes[0], NAMESPACE, proposal);
        let encoded = finalize.encode();
        let decoded = Finalize::decode(encoded).unwrap();
        assert_eq!(finalize, decoded);
        assert!(decoded.verify(&schemes[0], NAMESPACE));
    }

    #[test]
    fn test_finalize_encode_decode() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 4);
        finalize_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        finalize_encode_decode(&ed_schemes);
    }

    fn finalization_encode_decode<S: SigningScheme>(schemes: &[S]) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, NAMESPACE, proposal.clone()))
            .collect();
        let finalization = Finalization::from_finalizes(&schemes[0], &finalizes, None).unwrap();
        let encoded = finalization.encode();
        let cfg = schemes[0].certificate_codec_config();
        let decoded = Finalization::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(finalization, decoded);
        assert!(decoded.verify(&mut OsRng, &schemes[0], NAMESPACE));
    }

    #[test]
    fn test_finalization_encode_decode() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 5);
        finalization_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        finalization_encode_decode(&ed_schemes);
    }

    fn finalization_rejects_mismatched_notarization<S: SigningScheme>(schemes: &[S]) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, NAMESPACE, proposal.clone()))
            .collect();

        let other_proposal = Proposal::new(Round::new(0, 11), 5, sample_digest(2));
        let notarization: Notarization<S, Sha256> = Notarization::from_notarizes(
            &schemes[0],
            &schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, NAMESPACE, other_proposal.clone()))
                .collect::<Vec<_>>(),
        )
        .expect("failed to build mismatched notarization");

        assert!(
            Finalization::from_finalizes(&schemes[0], &finalizes, Some(&notarization)).is_none()
        );
    }

    #[test]
    fn test_finalization_rejects_mismatched_notarization() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 5);
        finalization_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        finalization_rejects_mismatched_notarization(&ed_schemes);
    }

    fn backfiller_encode_decode<S: SigningScheme>(schemes: &[S]) {
        let cfg = schemes[0].certificate_codec_config();
        let request = Request::new(1, vec![10, 11], vec![12, 13]);
        let encoded_request = Backfiller::<S, Sha256>::Request(request.clone()).encode();
        let decoded_request =
            Backfiller::<S, Sha256>::decode_cfg(encoded_request, &(usize::MAX, cfg.clone()))
                .unwrap();
        assert!(matches!(decoded_request, Backfiller::Request(r) if r == request));

        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));
        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()))
            .collect();
        let notarization = Notarization::from_notarizes(&schemes[0], &notarizes).unwrap();

        let nullifies: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256>(scheme, NAMESPACE, round))
            .collect();
        let nullification = Nullification::from_nullifies(&schemes[0], &nullifies).unwrap();

        let response = Response::<S, Sha256>::new(1, vec![notarization], vec![nullification]);
        let encoded_response = Backfiller::<S, Sha256>::Response(response.clone()).encode();
        let decoded_response =
            Backfiller::<S, Sha256>::decode_cfg(encoded_response, &(usize::MAX, cfg)).unwrap();
        assert!(matches!(decoded_response, Backfiller::Response(r) if r.id == response.id));
    }

    #[test]
    fn test_backfiller_encode_decode() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 6);
        backfiller_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        backfiller_encode_decode(&ed_schemes);
    }

    #[test]
    fn test_request_encode_decode() {
        let request = Request::new(1, vec![10, 11], vec![12, 13]);
        let encoded = request.encode();
        let decoded = Request::decode_cfg(encoded, &usize::MAX).unwrap();
        assert_eq!(request, decoded);
    }

    fn response_encode_decode<S: SigningScheme>(schemes: &[S]) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));

        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()))
            .collect();
        let notarization = Notarization::from_notarizes(&schemes[0], &notarizes).unwrap();

        let nullifies: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256>(scheme, NAMESPACE, round))
            .collect();
        let nullification = Nullification::from_nullifies(&schemes[0], &nullifies).unwrap();

        let response = Response::<S, Sha256>::new(1, vec![notarization], vec![nullification]);
        let cfg = schemes[0].certificate_codec_config();
        let mut decoded =
            Response::<S, Sha256>::decode_cfg(response.encode(), &(usize::MAX, cfg.clone()))
                .unwrap();
        assert_eq!(response.id, decoded.id);
        assert_eq!(response.notarizations.len(), decoded.notarizations.len());
        assert_eq!(response.nullifications.len(), decoded.nullifications.len());

        let mut rng = OsRng;
        assert!(decoded.verify(&mut rng, &schemes[0], NAMESPACE));

        decoded.nullifications[0].round = Round::new(
            decoded.nullifications[0].round.epoch(),
            decoded.nullifications[0].round.view() + 1,
        );
        assert!(!decoded.verify(&mut rng, &schemes[0], NAMESPACE));
    }

    #[test]
    fn test_response_encode_decode() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 7);
        response_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        response_encode_decode(&ed_schemes);
    }

    fn conflicting_notarize_encode_decode<S: SigningScheme>(schemes: &[S]) {
        let proposal1 = Proposal::new(Round::new(0, 10), 5, sample_digest(1));
        let proposal2 = Proposal::new(Round::new(0, 10), 5, sample_digest(2));
        let notarize1 = Notarize::sign(&schemes[0], NAMESPACE, proposal1);
        let notarize2 = Notarize::sign(&schemes[0], NAMESPACE, proposal2);
        let conflicting = ConflictingNotarize::new(notarize1, notarize2);

        let encoded = conflicting.encode();
        let decoded = ConflictingNotarize::<S, Sha256>::decode(encoded).unwrap();

        assert_eq!(conflicting, decoded);
        assert!(decoded.verify(&schemes[0], NAMESPACE));
    }

    #[test]
    fn test_conflicting_notarize_encode_decode() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 8);
        conflicting_notarize_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        conflicting_notarize_encode_decode(&ed_schemes);
    }

    fn conflicting_finalize_encode_decode<S: SigningScheme>(schemes: &[S]) {
        let proposal1 = Proposal::new(Round::new(0, 10), 5, sample_digest(1));
        let proposal2 = Proposal::new(Round::new(0, 10), 5, sample_digest(2));
        let finalize1 = Finalize::sign(&schemes[0], NAMESPACE, proposal1);
        let finalize2 = Finalize::sign(&schemes[0], NAMESPACE, proposal2);
        let conflicting = ConflictingFinalize::new(finalize1, finalize2);

        let encoded = conflicting.encode();
        let decoded = ConflictingFinalize::<S, Sha256>::decode(encoded).unwrap();

        assert_eq!(conflicting, decoded);
        assert!(decoded.verify(&schemes[0], NAMESPACE));
    }

    #[test]
    fn test_conflicting_finalize_encode_decode() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 9);
        conflicting_finalize_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        conflicting_finalize_encode_decode(&ed_schemes);
    }

    fn nullify_finalize_encode_decode<S: SigningScheme>(schemes: &[S]) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));
        let nullify = Nullify::sign::<Sha256>(&schemes[0], NAMESPACE, round);
        let finalize = Finalize::sign(&schemes[0], NAMESPACE, proposal);
        let conflict = NullifyFinalize::new(nullify, finalize);

        let encoded = conflict.encode();
        let decoded = NullifyFinalize::<S, Sha256>::decode(encoded).unwrap();

        assert_eq!(conflict, decoded);
        assert!(decoded.verify(&schemes[0], NAMESPACE));
    }

    #[test]
    fn test_nullify_finalize_encode_decode() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 10);
        nullify_finalize_encode_decode(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        nullify_finalize_encode_decode(&ed_schemes);
    }

    fn notarize_verify_wrong_namespace<S: SigningScheme>(scheme: &S) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));
        let notarize = Notarize::sign(scheme, NAMESPACE, proposal);

        assert!(notarize.verify(scheme, NAMESPACE));
        assert!(!notarize.verify(scheme, b"wrong_namespace"));
    }

    #[test]
    fn test_notarize_verify_wrong_namespace() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 220);
        notarize_verify_wrong_namespace(&bls_threshold_schemes[0]);

        let ed_schemes = generate_ed25519_schemes(5);
        notarize_verify_wrong_namespace(&ed_schemes[0]);
    }

    fn notarize_verify_wrong_scheme<S: SigningScheme>(scheme: &S, wrong_scheme: &S) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(2));
        let notarize = Notarize::sign(scheme, NAMESPACE, proposal);

        assert!(notarize.verify(scheme, NAMESPACE));
        assert!(!notarize.verify(wrong_scheme, NAMESPACE));
    }

    #[test]
    fn test_notarize_verify_wrong_polynomial() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 221);
        let bls_threshold_wrong_scheme = generate_bls12381_threshold_verifier(5, 501);
        notarize_verify_wrong_scheme(&bls_threshold_schemes[0], &bls_threshold_wrong_scheme);

        let ed_schemes = generate_ed25519_schemes(5);
        let ed_wrong_scheme = generate_ed25519_verifier_with_offset(5, 100);
        notarize_verify_wrong_scheme(&ed_schemes[0], &ed_wrong_scheme);
    }

    fn notarization_verify_wrong_scheme<S: SigningScheme>(schemes: &[S], wrong_scheme: &S) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(3));
        let quorum = quorum(schemes.len() as u32);
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()))
            .collect();

        let notarization =
            Notarization::from_notarizes(&schemes[0], &notarizes).expect("quorum notarization");
        let mut rng = OsRng;
        assert!(notarization.verify(&mut rng, &schemes[0], NAMESPACE));

        let mut rng = OsRng;
        assert!(!notarization.verify(&mut rng, wrong_scheme, NAMESPACE));
    }

    #[test]
    fn test_notarization_verify_wrong_keys() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 222);
        let bls_threshold_wrong_scheme = generate_bls12381_threshold_verifier(5, 502);
        notarization_verify_wrong_scheme(&bls_threshold_schemes, &bls_threshold_wrong_scheme);

        let ed_schemes = generate_ed25519_schemes(5);
        let ed_wrong_scheme = generate_ed25519_verifier_with_offset(5, 200);
        notarization_verify_wrong_scheme(&ed_schemes, &ed_wrong_scheme);
    }

    fn notarization_verify_wrong_namespace<S: SigningScheme>(schemes: &[S]) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(4));
        let quorum = quorum(schemes.len() as u32);
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()))
            .collect();

        let notarization =
            Notarization::from_notarizes(&schemes[0], &notarizes).expect("quorum notarization");
        let mut rng = OsRng;
        assert!(notarization.verify(&mut rng, &schemes[0], NAMESPACE));

        let mut rng = OsRng;
        assert!(!notarization.verify(&mut rng, &schemes[0], b"wrong_namespace"));
    }

    #[test]
    fn test_notarization_verify_wrong_namespace() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 223);
        notarization_verify_wrong_namespace(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        notarization_verify_wrong_namespace(&ed_schemes);
    }

    fn notarization_recover_insufficient_signatures<S: SigningScheme>(schemes: &[S]) {
        let quorum = quorum(schemes.len() as u32);
        assert!(quorum > 1, "test requires quorum larger than one");
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(5));
        let notarizes: Vec<_> = schemes
            .iter()
            .take((quorum - 1) as usize)
            .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()))
            .collect();

        assert!(
            Notarization::from_notarizes(&schemes[0], &notarizes).is_none(),
            "insufficient votes should not form a notarization"
        );
    }

    #[test]
    fn test_notarization_recover_insufficient_signatures() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 224);
        notarization_recover_insufficient_signatures(&bls_threshold_schemes);

        let ed_schemes = generate_ed25519_schemes(5);
        notarization_recover_insufficient_signatures(&ed_schemes);
    }

    fn conflicting_notarize_detection<S: SigningScheme>(scheme: &S, wrong_scheme: &S) {
        let round = Round::new(0, 10);
        let proposal1 = Proposal::new(round, 5, sample_digest(6));
        let proposal2 = Proposal::new(round, 5, sample_digest(7));

        let notarize1 = Notarize::sign(scheme, NAMESPACE, proposal1);
        let notarize2 = Notarize::sign(scheme, NAMESPACE, proposal2);
        let conflict = ConflictingNotarize::new(notarize1, notarize2);

        assert!(conflict.verify(scheme, NAMESPACE));
        assert!(!conflict.verify(scheme, b"wrong_namespace"));
        assert!(!conflict.verify(wrong_scheme, NAMESPACE));
    }

    #[test]
    fn test_conflicting_notarize_detection() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 225);
        let bls_threshold_wrong_scheme = generate_bls12381_threshold_verifier(5, 503);
        conflicting_notarize_detection(&bls_threshold_schemes[0], &bls_threshold_wrong_scheme);

        let ed_schemes = generate_ed25519_schemes(5);
        let ed_wrong_scheme = generate_ed25519_verifier_with_offset(5, 300);
        conflicting_notarize_detection(&ed_schemes[0], &ed_wrong_scheme);
    }

    fn nullify_finalize_detection<S: SigningScheme>(scheme: &S, wrong_scheme: &S) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(8));

        let nullify = Nullify::sign::<Sha256>(scheme, NAMESPACE, round);
        let finalize = Finalize::sign(scheme, NAMESPACE, proposal);
        let conflict = NullifyFinalize::new(nullify, finalize);

        assert!(conflict.verify(scheme, NAMESPACE));
        assert!(!conflict.verify(scheme, b"wrong_namespace"));
        assert!(!conflict.verify(wrong_scheme, NAMESPACE));
    }

    #[test]
    fn test_nullify_finalize_detection() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 226);
        let bls_threshold_wrong_scheme = generate_bls12381_threshold_verifier(5, 504);
        nullify_finalize_detection(&bls_threshold_schemes[0], &bls_threshold_wrong_scheme);

        let ed_schemes = generate_ed25519_schemes(5);
        let ed_wrong_scheme = generate_ed25519_verifier_with_offset(5, 400);
        nullify_finalize_detection(&ed_schemes[0], &ed_wrong_scheme);
    }

    fn finalization_verify_wrong_scheme<S: SigningScheme>(schemes: &[S], wrong_scheme: &S) {
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(9));
        let quorum = quorum(schemes.len() as u32);
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Finalize::sign(scheme, NAMESPACE, proposal.clone()))
            .collect();

        let finalization = Finalization::from_finalizes(&schemes[0], &finalizes, None)
            .expect("quorum finalization");
        let mut rng = OsRng;
        assert!(finalization.verify(&mut rng, &schemes[0], NAMESPACE));

        let mut rng = OsRng;
        assert!(!finalization.verify(&mut rng, wrong_scheme, NAMESPACE));
    }

    #[test]
    fn test_finalization_wrong_signature() {
        let bls_threshold_schemes = generate_bls12381_threshold_schemes(5, 227);
        let bls_threshold_wrong_scheme = generate_bls12381_threshold_verifier(5, 505);
        finalization_verify_wrong_scheme(&bls_threshold_schemes, &bls_threshold_wrong_scheme);

        let ed_schemes = generate_ed25519_schemes(5);
        let ed_wrong_scheme = generate_ed25519_verifier_with_offset(5, 500);
        finalization_verify_wrong_scheme(&ed_schemes, &ed_wrong_scheme);
    }

    // Helper to create a Notarize message for any signing scheme
    fn create_notarize<S: SigningScheme>(
        scheme: &S,
        round: Round,
        parent_view: View,
        payload_val: u8,
    ) -> Notarize<S, Sha256> {
        let proposal = Proposal::new(round, parent_view, sample_digest(payload_val));
        Notarize::sign(scheme, NAMESPACE, proposal)
    }

    // Helper to create a Nullify message for any signing scheme
    #[allow(dead_code)]
    fn create_nullify<S: SigningScheme>(scheme: &S, round: Round) -> Nullify<S> {
        Nullify::sign::<Sha256>(scheme, NAMESPACE, round)
    }

    // Helper to create a Finalize message for any signing scheme
    #[allow(dead_code)]
    fn create_finalize<S: SigningScheme>(
        scheme: &S,
        round: Round,
        parent_view: View,
        payload_val: u8,
    ) -> Finalize<S, Sha256> {
        let proposal = Proposal::new(round, parent_view, sample_digest(payload_val));
        Finalize::sign(scheme, NAMESPACE, proposal)
    }

    fn create_notarization<S: SigningScheme>(
        schemes: &[S],
        round: Round,
        parent_view: View,
        payload_val: u8,
        quorum: u32,
    ) -> Notarization<S, Sha256> {
        let proposal = Proposal::new(round, parent_view, sample_digest(payload_val));
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()))
            .collect();
        Notarization::from_notarizes(&schemes[0], &notarizes).unwrap()
    }

    fn batch_verifier_add_notarize<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));

        let round = Round::new(0, 1);
        let notarize1 = create_notarize(&schemes[0], round, 0, 1);
        let notarize2 = create_notarize(&schemes[1], round, 0, 1);
        let notarize_diff = create_notarize(&schemes[2], round, 0, 2);

        verifier.add(Voter::Notarize(notarize1.clone()), false);
        assert_eq!(verifier.notarizes.len(), 1);
        assert_eq!(verifier.notarizes_verified, 0);

        verifier.add(Voter::Notarize(notarize1.clone()), true);
        assert_eq!(verifier.notarizes.len(), 1);
        assert_eq!(verifier.notarizes_verified, 1);

        verifier.set_leader(notarize1.signer());
        assert!(verifier.leader_proposal.is_some());
        assert_eq!(
            verifier.leader_proposal.as_ref().unwrap(),
            &notarize1.proposal
        );
        assert!(verifier.notarizes_force);
        assert_eq!(verifier.notarizes.len(), 1);

        verifier.add(Voter::Notarize(notarize2.clone()), false);
        assert_eq!(verifier.notarizes.len(), 2);

        verifier.add(Voter::Notarize(notarize_diff.clone()), false);
        assert_eq!(verifier.notarizes.len(), 2);

        let mut verifier2 = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round2 = Round::new(0, 2);
        let notarize_non_leader = create_notarize(&schemes[1], round2, 1, 3);
        let notarize_leader = create_notarize(&schemes[0], round2, 1, 3);

        verifier2.set_leader(notarize_leader.signer());
        verifier2.add(Voter::Notarize(notarize_non_leader.clone()), false);
        assert!(verifier2.leader_proposal.is_none());
        assert_eq!(verifier2.notarizes.len(), 1);

        verifier2.add(Voter::Notarize(notarize_leader.clone()), false);
        assert!(verifier2.leader_proposal.is_some());
        assert_eq!(
            verifier2.leader_proposal.as_ref().unwrap(),
            &notarize_leader.proposal
        );
        assert_eq!(verifier2.notarizes.len(), 2);
    }

    #[test]
    fn test_batch_verifier_add_notarize() {
        batch_verifier_add_notarize(generate_bls12381_threshold_schemes(5, 123));
        batch_verifier_add_notarize(generate_ed25519_schemes(5));
    }

    fn batch_verifier_set_leader<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));

        let round = Round::new(0, 1);
        let leader_notarize = create_notarize(&schemes[0], round, 0, 1);
        let other_notarize = create_notarize(&schemes[1], round, 0, 1);

        verifier.add(Voter::Notarize(other_notarize.clone()), false);
        assert_eq!(verifier.notarizes.len(), 1);

        let leader = leader_notarize.signer();
        verifier.set_leader(leader);
        assert_eq!(verifier.leader, Some(leader));
        assert!(verifier.leader_proposal.is_none());
        assert!(!verifier.notarizes_force);
        assert_eq!(verifier.notarizes.len(), 1);

        verifier.add(Voter::Notarize(leader_notarize.clone()), false);
        assert!(verifier.leader_proposal.is_some());
        assert_eq!(
            verifier.leader_proposal.as_ref().unwrap(),
            &leader_notarize.proposal
        );
        assert!(verifier.notarizes_force);
        assert_eq!(verifier.notarizes.len(), 2);
    }

    #[test]
    fn test_batch_verifier_set_leader() {
        batch_verifier_set_leader(generate_bls12381_threshold_schemes(5, 124));
        batch_verifier_set_leader(generate_ed25519_schemes(5));
    }

    fn batch_verifier_ready_and_verify_notarizes<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        let round = Round::new(0, 1);
        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| create_notarize(scheme, round, 0, 1))
            .collect();

        assert!(!verifier.ready_notarizes());

        verifier.set_leader(notarizes[0].signer());
        verifier.add(Voter::Notarize(notarizes[0].clone()), false);
        assert!(verifier.ready_notarizes());
        assert_eq!(verifier.notarizes.len(), 1);

        let (verified_once, failed_once) = verifier.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified_once.len(), 1);
        assert!(failed_once.is_empty());
        assert_eq!(verifier.notarizes_verified, 1);
        assert!(verifier.notarizes.is_empty());
        assert!(!verifier.notarizes_force);

        verifier.add(Voter::Notarize(notarizes[1].clone()), false);
        assert!(!verifier.ready_notarizes());
        verifier.add(Voter::Notarize(notarizes[2].clone()), false);
        assert!(!verifier.ready_notarizes());
        verifier.add(Voter::Notarize(notarizes[3].clone()), false);
        assert!(verifier.ready_notarizes());
        assert_eq!(verifier.notarizes.len(), 3);

        let (verified_bulk, failed_bulk) = verifier.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified_bulk.len(), 3);
        assert!(failed_bulk.is_empty());
        assert_eq!(verifier.notarizes_verified, 4);
        assert!(verifier.notarizes.is_empty());
        assert!(!verifier.ready_notarizes());

        let mut verifier2 = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round2 = Round::new(0, 2);
        let leader_vote = create_notarize(&schemes[0], round2, 1, 10);
        let mut faulty_vote = create_notarize(&schemes[1], round2, 1, 10);
        verifier2.set_leader(leader_vote.signer());
        verifier2.add(Voter::Notarize(leader_vote.clone()), false);
        faulty_vote.vote.signer = (schemes.len() as u32) + 10;
        verifier2.add(Voter::Notarize(faulty_vote.clone()), false);
        assert!(verifier2.ready_notarizes());

        let (verified_second, failed_second) = verifier2.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified_second.len(), 1);
        assert!(verified_second
            .into_iter()
            .any(|v| matches!(v, Voter::Notarize(ref n) if n == &leader_vote)));
        assert_eq!(failed_second, vec![faulty_vote.signer()]);
    }

    #[test]
    fn test_batch_verifier_ready_and_verify_notarizes() {
        batch_verifier_ready_and_verify_notarizes(generate_bls12381_threshold_schemes(5, 125));
        batch_verifier_ready_and_verify_notarizes(generate_ed25519_schemes(5));
    }

    fn batch_verifier_add_nullify<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(0, 1);
        let nullify = create_nullify(&schemes[0], round);

        verifier.add(Voter::Nullify(nullify.clone()), false);
        assert_eq!(verifier.nullifies.len(), 1);
        assert_eq!(verifier.nullifies_verified, 0);

        verifier.add(Voter::Nullify(nullify.clone()), true);
        assert_eq!(verifier.nullifies.len(), 1);
        assert_eq!(verifier.nullifies_verified, 1);
    }

    #[test]
    fn test_batch_verifier_add_nullify() {
        batch_verifier_add_nullify(generate_bls12381_threshold_schemes(5, 127));
        batch_verifier_add_nullify(generate_ed25519_schemes(5));
    }

    fn batch_verifier_ready_and_verify_nullifies<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        let round = Round::new(0, 1);
        let nullifies: Vec<_> = schemes
            .iter()
            .map(|scheme| create_nullify(scheme, round))
            .collect();

        verifier.add(Voter::Nullify(nullifies[0].clone()), true);
        assert_eq!(verifier.nullifies_verified, 1);

        verifier.add(Voter::Nullify(nullifies[1].clone()), false);
        assert!(!verifier.ready_nullifies());
        verifier.add(Voter::Nullify(nullifies[2].clone()), false);
        assert!(!verifier.ready_nullifies());
        verifier.add(Voter::Nullify(nullifies[3].clone()), false);
        assert!(verifier.ready_nullifies());
        assert_eq!(verifier.nullifies.len(), 3);

        let (verified, failed) = verifier.verify_nullifies(&mut rng, NAMESPACE);
        assert_eq!(verified.len(), 3);
        assert!(failed.is_empty());
        assert_eq!(verifier.nullifies_verified, 4);
        assert!(verifier.nullifies.is_empty());
        assert!(!verifier.ready_nullifies());
    }

    #[test]
    fn test_batch_verifier_ready_and_verify_nullifies() {
        batch_verifier_ready_and_verify_nullifies(generate_bls12381_threshold_schemes(5, 128));
        batch_verifier_ready_and_verify_nullifies(generate_ed25519_schemes(5));
    }

    fn batch_verifier_add_finalize<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(0, 1);
        let finalize_a = create_finalize(&schemes[0], round, 0, 1);
        let finalize_b = create_finalize(&schemes[1], round, 0, 2);

        verifier.add(Voter::Finalize(finalize_b.clone()), false);
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes_verified, 0);

        verifier.add(Voter::Finalize(finalize_a.clone()), false);
        assert_eq!(verifier.finalizes.len(), 2);

        verifier.set_leader(finalize_a.signer());
        assert!(verifier.leader_proposal.is_none());
        verifier.set_leader_proposal(finalize_a.proposal.clone());
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes[0], finalize_a);
        assert_eq!(verifier.finalizes_verified, 0);

        verifier.add(Voter::Finalize(finalize_a.clone()), true);
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes_verified, 1);

        verifier.add(Voter::Finalize(finalize_b.clone()), false);
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes_verified, 1);
    }

    #[test]
    fn test_batch_verifier_add_finalize() {
        batch_verifier_add_finalize(generate_bls12381_threshold_schemes(5, 129));
        batch_verifier_add_finalize(generate_ed25519_schemes(5));
    }

    fn batch_verifier_ready_and_verify_finalizes<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        let round = Round::new(0, 1);
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| create_finalize(scheme, round, 0, 1))
            .collect();

        assert!(!verifier.ready_finalizes());

        verifier.set_leader(finalizes[0].signer());
        verifier.set_leader_proposal(finalizes[0].proposal.clone());

        verifier.add(Voter::Finalize(finalizes[0].clone()), true);
        assert_eq!(verifier.finalizes_verified, 1);
        assert!(verifier.finalizes.is_empty());

        verifier.add(Voter::Finalize(finalizes[1].clone()), false);
        assert!(!verifier.ready_finalizes());
        verifier.add(Voter::Finalize(finalizes[2].clone()), false);
        assert!(!verifier.ready_finalizes());
        verifier.add(Voter::Finalize(finalizes[3].clone()), false);
        assert!(verifier.ready_finalizes());

        let (verified, failed) = verifier.verify_finalizes(&mut rng, NAMESPACE);
        assert_eq!(verified.len(), 3);
        assert!(failed.is_empty());
        assert_eq!(verifier.finalizes_verified, 4);
        assert!(verifier.finalizes.is_empty());
        assert!(!verifier.ready_finalizes());
    }

    #[test]
    fn test_batch_verifier_ready_and_verify_finalizes() {
        batch_verifier_ready_and_verify_finalizes(generate_bls12381_threshold_schemes(5, 130));
        batch_verifier_ready_and_verify_finalizes(generate_ed25519_schemes(5));
    }

    fn batch_verifier_quorum_none<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let mut rng = OsRng;
        let round = Round::new(0, 1);

        let mut verifier_notarize = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), None);
        let notarize = create_notarize(&schemes[0], round, 0, 1);
        assert!(!verifier_notarize.ready_notarizes());
        verifier_notarize.set_leader(notarize.signer());
        verifier_notarize.add(Voter::Notarize(notarize.clone()), false);
        assert!(verifier_notarize.ready_notarizes());
        let (verified_notarize, failed_notarize) =
            verifier_notarize.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified_notarize.len(), 1);
        assert!(failed_notarize.is_empty());
        assert_eq!(verifier_notarize.notarizes_verified, 1);
        assert!(!verifier_notarize.ready_notarizes());

        let mut verifier_null = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), None);
        let nullify = create_nullify(&schemes[0], round);
        assert!(!verifier_null.ready_nullifies());
        verifier_null.add(Voter::Nullify(nullify.clone()), false);
        assert!(verifier_null.ready_nullifies());
        let (verified_null, failed_null) = verifier_null.verify_nullifies(&mut rng, NAMESPACE);
        assert_eq!(verified_null.len(), 1);
        assert!(failed_null.is_empty());
        assert_eq!(verifier_null.nullifies_verified, 1);
        assert!(!verifier_null.ready_nullifies());

        let mut verifier_final = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), None);
        let finalize = create_finalize(&schemes[0], round, 0, 1);
        assert!(!verifier_final.ready_finalizes());
        verifier_final.set_leader(finalize.signer());
        verifier_final.set_leader_proposal(finalize.proposal.clone());
        verifier_final.add(Voter::Finalize(finalize.clone()), false);
        assert!(verifier_final.ready_finalizes());
        let (verified_fin, failed_fin) = verifier_final.verify_finalizes(&mut rng, NAMESPACE);
        assert_eq!(verified_fin.len(), 1);
        assert!(failed_fin.is_empty());
        assert_eq!(verifier_final.finalizes_verified, 1);
        assert!(!verifier_final.ready_finalizes());
    }

    #[test]
    fn test_batch_verifier_quorum_none() {
        batch_verifier_quorum_none(generate_bls12381_threshold_schemes(3, 200));
        batch_verifier_quorum_none(generate_ed25519_schemes(3));
    }

    fn batch_verifier_leader_proposal_filters_messages<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(0, 1);
        let proposal_a = Proposal::new(round, 0, sample_digest(10));
        let proposal_b = Proposal::new(round, 0, sample_digest(20));

        let notarize_a = Notarize::sign(&schemes[0], NAMESPACE, proposal_a.clone());
        let notarize_b = Notarize::sign(&schemes[1], NAMESPACE, proposal_b.clone());
        let finalize_a = Finalize::sign(&schemes[0], NAMESPACE, proposal_a.clone());
        let finalize_b = Finalize::sign(&schemes[1], NAMESPACE, proposal_b.clone());

        verifier.add(Voter::Notarize(notarize_a.clone()), false);
        verifier.add(Voter::Notarize(notarize_b.clone()), false);
        verifier.add(Voter::Finalize(finalize_a.clone()), false);
        verifier.add(Voter::Finalize(finalize_b.clone()), false);

        assert_eq!(verifier.notarizes.len(), 2);
        assert_eq!(verifier.finalizes.len(), 2);

        verifier.set_leader(notarize_a.signer());

        assert!(verifier.notarizes_force);
        assert_eq!(verifier.notarizes.len(), 1);
        assert_eq!(verifier.notarizes[0].proposal, proposal_a);
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes[0].proposal, proposal_a);
    }

    #[test]
    fn test_batch_verifier_leader_proposal_filters_messages() {
        batch_verifier_leader_proposal_filters_messages(generate_bls12381_threshold_schemes(
            3, 201,
        ));
        batch_verifier_leader_proposal_filters_messages(generate_ed25519_schemes(3));
    }

    fn batch_verifier_set_leader_twice_panics<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(3));
        verifier.set_leader(0);
        verifier.set_leader(1);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_batch_verifier_set_leader_twice_panics_bls() {
        batch_verifier_set_leader_twice_panics(generate_bls12381_threshold_schemes(3, 212));
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_batch_verifier_set_leader_twice_panics_ed() {
        batch_verifier_set_leader_twice_panics(generate_ed25519_schemes(3));
    }

    fn batch_verifier_add_recovered_message_panics<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let notarization = create_notarization(&schemes, Round::new(0, 1), 0, 1, quorum);
        verifier.add(Voter::Notarization(notarization), false);
    }

    #[test]
    #[should_panic(expected = "should not be adding recovered messages to partial verifier")]
    fn test_batch_verifier_add_recovered_message_panics_bls() {
        batch_verifier_add_recovered_message_panics(generate_bls12381_threshold_schemes(3, 213));
    }

    #[test]
    #[should_panic(expected = "should not be adding recovered messages to partial verifier")]
    fn test_batch_verifier_add_recovered_message_panics_ed() {
        batch_verifier_add_recovered_message_panics(generate_ed25519_schemes(3));
    }

    fn batch_verifier_notarizes_force_flag<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        let round = Round::new(0, 1);
        let leader_vote = create_notarize(&schemes[0], round, 0, 1);

        verifier.set_leader(leader_vote.signer());
        verifier.add(Voter::Notarize(leader_vote.clone()), false);

        assert!(
            verifier.notarizes_force,
            "notarizes_force should be true after leader's proposal is set"
        );
        assert!(verifier.ready_notarizes());

        let (verified, _) = verifier.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified.len(), 1);
        assert!(
            !verifier.notarizes_force,
            "notarizes_force should be false after verification"
        );
        assert!(!verifier.ready_notarizes());
    }

    #[test]
    fn test_ready_notarizes_behavior_with_force_flag() {
        batch_verifier_notarizes_force_flag(generate_bls12381_threshold_schemes(3, 203));
        batch_verifier_notarizes_force_flag(generate_ed25519_schemes(3));
    }

    fn batch_verifier_ready_notarizes_without_leader<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(0, 1);

        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| create_notarize(scheme, round, 0, 1))
            .collect();

        for vote in notarizes.iter() {
            verifier.add(Voter::Notarize(vote.clone()), false);
        }

        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready without leader/proposal set"
        );

        verifier.set_leader(notarizes[0].signer());
        assert!(
            verifier.ready_notarizes(),
            "Should be ready once leader is set"
        );
    }

    #[test]
    fn test_ready_notarizes_without_leader_or_proposal() {
        batch_verifier_ready_notarizes_without_leader(generate_bls12381_threshold_schemes(3, 204));
        batch_verifier_ready_notarizes_without_leader(generate_ed25519_schemes(3));
    }

    fn batch_verifier_ready_finalizes_without_leader<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(0, 1);
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| create_finalize(scheme, round, 0, 1))
            .collect();

        for finalize in finalizes.iter() {
            verifier.add(Voter::Finalize(finalize.clone()), false);
        }

        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready without leader/proposal set"
        );

        verifier.set_leader(finalizes[0].signer());
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready without leader_proposal set"
        );
    }

    #[test]
    fn test_ready_finalizes_without_leader_or_proposal() {
        batch_verifier_ready_finalizes_without_leader(generate_bls12381_threshold_schemes(3, 205));
        batch_verifier_ready_finalizes_without_leader(generate_ed25519_schemes(3));
    }

    fn batch_verifier_verify_notarizes_empty<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(0, 1);
        let leader_proposal = Proposal::new(round, 0, sample_digest(1));
        verifier.set_leader_proposal(leader_proposal);
        assert!(verifier.notarizes_force);
        assert!(verifier.notarizes.is_empty());
        assert!(!verifier.ready_notarizes());
    }

    #[test]
    fn test_verify_notarizes_empty_pending_when_forced() {
        batch_verifier_verify_notarizes_empty(generate_bls12381_threshold_schemes(3, 206));
        batch_verifier_verify_notarizes_empty(generate_ed25519_schemes(3));
    }

    fn batch_verifier_verify_nullifies_empty<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        assert!(verifier.nullifies.is_empty());
        assert!(!verifier.ready_nullifies());
        let (verified, failed) = verifier.verify_nullifies(&mut rng, NAMESPACE);
        assert!(verified.is_empty());
        assert!(failed.is_empty());
        assert_eq!(verifier.nullifies_verified, 0);
    }

    #[test]
    fn test_verify_nullifies_empty_pending() {
        batch_verifier_verify_nullifies_empty(generate_bls12381_threshold_schemes(3, 207));
        batch_verifier_verify_nullifies_empty(generate_ed25519_schemes(3));
    }

    fn batch_verifier_verify_finalizes_empty<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        verifier.set_leader(0);
        assert!(verifier.finalizes.is_empty());
        assert!(!verifier.ready_finalizes());
        let (verified, failed) = verifier.verify_finalizes(&mut rng, NAMESPACE);
        assert!(verified.is_empty());
        assert!(failed.is_empty());
        assert_eq!(verifier.finalizes_verified, 0);
    }

    #[test]
    fn test_verify_finalizes_empty_pending() {
        batch_verifier_verify_finalizes_empty(generate_bls12381_threshold_schemes(3, 208));
        batch_verifier_verify_finalizes_empty(generate_ed25519_schemes(3));
    }

    fn batch_verifier_ready_notarizes_exact_quorum<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        let round = Round::new(0, 1);

        let leader_vote = create_notarize(&schemes[0], round, 0, 1);
        verifier.set_leader(leader_vote.signer());
        verifier.add(Voter::Notarize(leader_vote.clone()), true);
        assert_eq!(verifier.notarizes_verified, 1);

        let second_vote = create_notarize(&schemes[1], round, 0, 1);
        verifier.add(Voter::Notarize(second_vote.clone()), false);
        assert!(verifier.ready_notarizes());
        let (verified_once, failed_once) = verifier.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified_once.len(), 1);
        assert!(failed_once.is_empty());
        assert_eq!(verifier.notarizes_verified, 2);

        for scheme in schemes.iter().take(quorum as usize).skip(2) {
            assert!(!verifier.ready_notarizes());
            verifier.add(Voter::Notarize(create_notarize(scheme, round, 0, 1)), false);
        }

        assert!(verifier.ready_notarizes());
    }

    #[test]
    fn test_ready_notarizes_exact_quorum() {
        batch_verifier_ready_notarizes_exact_quorum(generate_bls12381_threshold_schemes(5, 209));
        batch_verifier_ready_notarizes_exact_quorum(generate_ed25519_schemes(5));
    }

    fn batch_verifier_ready_nullifies_exact_quorum<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(0, 1);

        verifier.add(Voter::Nullify(create_nullify(&schemes[0], round)), true);
        assert_eq!(verifier.nullifies_verified, 1);

        for scheme in schemes.iter().take(quorum as usize).skip(1) {
            assert!(!verifier.ready_nullifies());
            verifier.add(Voter::Nullify(create_nullify(scheme, round)), false);
        }

        assert!(verifier.ready_nullifies());
    }

    #[test]
    fn test_ready_nullifies_exact_quorum() {
        batch_verifier_ready_nullifies_exact_quorum(generate_bls12381_threshold_schemes(5, 210));
        batch_verifier_ready_nullifies_exact_quorum(generate_ed25519_schemes(5));
    }

    fn batch_verifier_ready_finalizes_exact_quorum<S: SigningScheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(0, 1);
        let leader_finalize = create_finalize(&schemes[0], round, 0, 1);
        verifier.set_leader(leader_finalize.signer());
        verifier.set_leader_proposal(leader_finalize.proposal.clone());
        verifier.add(Voter::Finalize(leader_finalize), true);
        assert_eq!(verifier.finalizes_verified, 1);

        for scheme in schemes.iter().take(quorum as usize).skip(1) {
            assert!(!verifier.ready_finalizes());
            verifier.add(Voter::Finalize(create_finalize(scheme, round, 0, 1)), false);
        }

        assert!(verifier.ready_finalizes());
    }

    #[test]
    fn test_ready_finalizes_exact_quorum() {
        batch_verifier_ready_finalizes_exact_quorum(generate_bls12381_threshold_schemes(5, 211));
        batch_verifier_ready_finalizes_exact_quorum(generate_ed25519_schemes(5));
    }

    fn batch_verifier_ready_notarizes_quorum_already_met_by_verified<S: SigningScheme + Clone>(
        schemes: Vec<S>,
    ) {
        let quorum = quorum(schemes.len() as u32);
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(0, 1);

        // Pre-load the leader vote as if it had already been processed.
        let leader_vote = create_notarize(&schemes[0], round, 0, 1);
        verifier.set_leader(leader_vote.signer());
        verifier.add(Voter::Notarize(leader_vote.clone()), false);
        verifier.notarizes_force = false;

        // Mark enough verified notarizes to satisfy the quorum outright.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(Voter::Notarize(create_notarize(scheme, round, 0, 1)), true);
        }
        assert_eq!(verifier.notarizes_verified, quorum as usize);
        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Additional pending votes must not flip readiness in this situation.
        let extra_vote = create_notarize(&schemes[quorum as usize], round, 0, 1);
        verifier.add(Voter::Notarize(extra_vote), false);
        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_notarizes_quorum_already_met_by_verified() {
        batch_verifier_ready_notarizes_quorum_already_met_by_verified(
            generate_bls12381_threshold_schemes(5, 212),
        );
        batch_verifier_ready_notarizes_quorum_already_met_by_verified(generate_ed25519_schemes(5));
    }

    fn batch_verifier_ready_nullifies_quorum_already_met_by_verified<S: SigningScheme + Clone>(
        schemes: Vec<S>,
    ) {
        let quorum = quorum(schemes.len() as u32);
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(0, 1);

        // First mark a quorum's worth of verified nullifies.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(Voter::Nullify(create_nullify(scheme, round)), true);
        }
        assert_eq!(verifier.nullifies_verified, quorum as usize);
        assert!(
            !verifier.ready_nullifies(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Pending messages alone cannot transition the batch to ready.
        let extra_nullify = create_nullify(&schemes[quorum as usize], round);
        verifier.add(Voter::Nullify(extra_nullify), false);
        assert!(
            !verifier.ready_nullifies(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_nullifies_quorum_already_met_by_verified() {
        batch_verifier_ready_nullifies_quorum_already_met_by_verified(
            generate_bls12381_threshold_schemes(5, 213),
        );
        batch_verifier_ready_nullifies_quorum_already_met_by_verified(generate_ed25519_schemes(5));
    }

    fn batch_verifier_ready_finalizes_quorum_already_met_by_verified<S: SigningScheme + Clone>(
        schemes: Vec<S>,
    ) {
        let quorum = quorum(schemes.len() as u32);
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = BatchVerifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(0, 1);

        // Prime the leader state so the quorum is already satisfied by verified finalizes.
        let leader_finalize = create_finalize(&schemes[0], round, 0, 1);
        verifier.set_leader(leader_finalize.signer());
        verifier.set_leader_proposal(leader_finalize.proposal.clone());

        // Feed exactly the number of verified finalizes required to hit the quorum.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(Voter::Finalize(create_finalize(scheme, round, 0, 1)), true);
        }
        assert_eq!(verifier.finalizes_verified, quorum as usize);
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Ensure additional pending finalizes do not incorrectly trigger readiness.
        let extra_finalize = create_finalize(&schemes[quorum as usize], round, 0, 1);
        verifier.add(Voter::Finalize(extra_finalize), false);
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_finalizes_quorum_already_met_by_verified() {
        batch_verifier_ready_finalizes_quorum_already_met_by_verified(
            generate_bls12381_threshold_schemes(5, 214),
        );
        batch_verifier_ready_finalizes_quorum_already_met_by_verified(generate_ed25519_schemes(5));
    }
}
