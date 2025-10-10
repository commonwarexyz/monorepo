//! Types used in [crate::threshold_simplex].

use crate::{
    types::{Epoch, Round, View},
    Epochable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Encode, EncodeSize, Error, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        ops::{
            aggregate_signatures, aggregate_verify_multiple_messages, partial_sign_message,
            partial_verify_multiple_public_keys_precomputed, verify_message,
        },
        poly::PartialSignature,
        variant::Variant,
    },
    Digest,
};
use commonware_utils::union;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    hash::Hash,
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

/// Seedable is a trait that provides access to the seed associated with a message.
pub trait Seedable<V: Variant> {
    /// Returns the seed associated with this object.
    fn seed(&self) -> Seed<V>;
}

// Constants for domain separation in signature verification
// These are used to prevent cross-protocol attacks and message-type confusion
pub const SEED_SUFFIX: &[u8] = b"_SEED";
pub const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
pub const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
pub const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

/// Creates a namespace for seed messages by appending the SEED_SUFFIX
/// The seed is used for leader election and randomness generation
#[inline]
pub fn seed_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, SEED_SUFFIX)
}

/// Creates a namespace for notarize messages by appending the NOTARIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

/// Creates a namespace for nullify messages by appending the NULLIFY_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

/// Creates a namespace for finalize messages by appending the FINALIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
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
pub struct BatchVerifier<V: Variant, D: Digest> {
    quorum: Option<usize>,

    leader: Option<u32>,
    leader_proposal: Option<Proposal<D>>,

    notarizes: Vec<Notarize<V, D>>,
    notarizes_force: bool,
    notarizes_verified: usize,

    nullifies: Vec<Nullify<V>>,
    nullifies_verified: usize,

    finalizes: Vec<Finalize<V, D>>,
    finalizes_verified: usize,
}

impl<V: Variant, D: Digest> BatchVerifier<V, D> {
    /// Creates a new `BatchVerifier`.
    ///
    /// # Arguments
    ///
    /// * `quorum` - An optional `u32` specifying the number of votes (2f+1)
    ///   required to reach a quorum. If `None`, batch verification readiness
    ///   checks based on quorum size are skipped.
    pub fn new(quorum: Option<u32>) -> Self {
        Self {
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
    pub fn add(&mut self, msg: Voter<V, D>, verified: bool) {
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
    /// It uses `Notarize::verify_multiple` for efficient batch verification against
    /// the provided `polynomial`.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace for signature domain separation.
    /// * `polynomial` - The public polynomial (`Poly<V::Public>`) of the DKG.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A `Vec<Voter<V, D>>` of successfully verified [Voter::Notarize] messages (wrapped as [Voter]).
    /// * A `Vec<u32>` of signer indices for whom verification failed.
    pub fn verify_notarizes(
        &mut self,
        namespace: &[u8],
        polynomial: &[V::Public],
    ) -> (Vec<Voter<V, D>>, Vec<u32>) {
        self.notarizes_force = false;
        let (notarizes, failed) =
            Notarize::verify_multiple(namespace, polynomial, std::mem::take(&mut self.notarizes));
        self.notarizes_verified += notarizes.len();
        (notarizes.into_iter().map(Voter::Notarize).collect(), failed)
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
    /// It uses `Nullify::verify_multiple` for efficient batch verification against
    /// the provided `polynomial`.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace for signature domain separation.
    /// * `polynomial` - The public polynomial (`Poly<V::Public>`) of the DKG.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A `Vec<Voter<V, D>>` of successfully verified [Voter::Nullify] messages (wrapped as [Voter]).
    /// * A `Vec<u32>` of signer indices for whom verification failed.
    pub fn verify_nullifies(
        &mut self,
        namespace: &[u8],
        polynomial: &[V::Public],
    ) -> (Vec<Voter<V, D>>, Vec<u32>) {
        let (nullifies, failed) =
            Nullify::verify_multiple(namespace, polynomial, std::mem::take(&mut self.nullifies));
        self.nullifies_verified += nullifies.len();
        (nullifies.into_iter().map(Voter::Nullify).collect(), failed)
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
    /// It uses `Finalize::verify_multiple` for efficient batch verification against
    /// the provided `polynomial`.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace for signature domain separation.
    /// * `polynomial` - The public polynomial (`Poly<V::Public>`) of the DKG.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A `Vec<Voter<V, D>>` of successfully verified [Voter::Finalize] messages (wrapped as [Voter]).
    /// * A `Vec<u32>` of signer indices for whom verification failed.
    pub fn verify_finalizes(
        &mut self,
        namespace: &[u8],
        polynomial: &[V::Public],
    ) -> (Vec<Voter<V, D>>, Vec<u32>) {
        let (finalizes, failed) =
            Finalize::verify_multiple(namespace, polynomial, std::mem::take(&mut self.finalizes));
        self.finalizes_verified += finalizes.len();
        (finalizes.into_iter().map(Voter::Finalize).collect(), failed)
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
pub enum Voter<V: Variant, D: Digest> {
    /// A single validator notarize over a proposal
    Notarize(Notarize<V, D>),
    /// A recovered threshold signature for a notarization
    Notarization(Notarization<V, D>),
    /// A single validator nullify to skip the current view (usually when leader is unresponsive)
    Nullify(Nullify<V>),
    /// A recovered threshold signature for a nullification
    Nullification(Nullification<V>),
    /// A single validator finalize over a proposal
    Finalize(Finalize<V, D>),
    /// A recovered threshold signature for a finalization
    Finalization(Finalization<V, D>),
}

impl<V: Variant, D: Digest> Write for Voter<V, D> {
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

impl<V: Variant, D: Digest> EncodeSize for Voter<V, D> {
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

impl<V: Variant, D: Digest> Read for Voter<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Notarize::read(reader)?;
                Ok(Voter::Notarize(v))
            }
            1 => {
                let v = Notarization::read(reader)?;
                Ok(Voter::Notarization(v))
            }
            2 => {
                let v = Nullify::read(reader)?;
                Ok(Voter::Nullify(v))
            }
            3 => {
                let v = Nullification::read(reader)?;
                Ok(Voter::Nullification(v))
            }
            4 => {
                let v = Finalize::read(reader)?;
                Ok(Voter::Finalize(v))
            }
            5 => {
                let v = Finalization::read(reader)?;
                Ok(Voter::Finalization(v))
            }
            _ => Err(Error::Invalid(
                "consensus::threshold_simplex::Voter",
                "Invalid type",
            )),
        }
    }
}

impl<V: Variant, D: Digest> Epochable for Voter<V, D> {
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

impl<V: Variant, D: Digest> Viewable for Voter<V, D> {
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

/// Notarize represents a validator's vote to notarize a proposal.
/// In threshold_simplex, it contains a partial signature on the proposal and a partial signature for the seed.
/// The seed is used for leader election and as a source of randomness.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Notarize<V: Variant, D: Digest> {
    /// The proposal that is being notarized
    pub proposal: Proposal<D>,
    /// The validator's partial signature on the proposal
    pub proposal_signature: PartialSignature<V>,
    /// The validator's partial signature on the seed (for leader election/randomness)
    pub seed_signature: PartialSignature<V>,
}

impl<V: Variant, D: Digest> Notarize<V, D> {
    /// Creates a new notarize with the given proposal and signatures.
    pub fn new(
        proposal: Proposal<D>,
        proposal_signature: PartialSignature<V>,
        seed_signature: PartialSignature<V>,
    ) -> Self {
        Notarize {
            proposal,
            proposal_signature,
            seed_signature,
        }
    }

    /// Verifies the [PartialSignature]s on this [Notarize].
    ///
    /// This ensures that:
    /// 1. The notarize signature is valid for the claimed proposal
    /// 2. The seed signature is valid for the view
    /// 3. Both signatures are from the same signer
    pub fn verify(&self, namespace: &[u8], polynomial: &[V::Public]) -> bool {
        let notarize_namespace = notarize_namespace(namespace);
        let notarize_message = self.proposal.encode();
        let notarize_message = (Some(notarize_namespace.as_ref()), notarize_message.as_ref());
        let seed_namespace = seed_namespace(namespace);
        let seed_message = self.proposal.round.encode();
        let seed_message = (Some(seed_namespace.as_ref()), seed_message.as_ref());
        let Some(evaluated) = polynomial.get(self.signer() as usize) else {
            return false;
        };
        let signature = aggregate_signatures::<V, _>(&[
            self.proposal_signature.value,
            self.seed_signature.value,
        ]);
        aggregate_verify_multiple_messages::<V, _>(
            evaluated,
            &[notarize_message, seed_message],
            &signature,
            1,
        )
        .is_ok()
    }

    /// Verifies a batch of [Notarize] messages using BLS aggregate verification.
    ///
    /// This function verifies a batch of [Notarize] messages using BLS aggregate verification.
    /// It returns a tuple containing:
    /// * A vector of successfully verified [Notarize] messages.
    /// * A vector of signer indices for whom verification failed.
    pub fn verify_multiple(
        namespace: &[u8],
        polynomial: &[V::Public],
        notarizes: Vec<Notarize<V, D>>,
    ) -> (Vec<Notarize<V, D>>, Vec<u32>) {
        // Prepare to verify
        if notarizes.is_empty() {
            return (notarizes, vec![]);
        } else if notarizes.len() == 1 {
            // If there is only one notarize, verify it directly (will perform
            // inner aggregation)
            let valid = notarizes[0].verify(namespace, polynomial);
            if valid {
                return (notarizes, vec![]);
            } else {
                return (vec![], vec![notarizes[0].signer()]);
            }
        }
        let proposal = &notarizes[0].proposal;
        let mut invalid = BTreeSet::new();

        // Verify proposal signatures
        let notarize_namespace = notarize_namespace(namespace);
        let notarize_message = proposal.encode();
        let notarize_signatures = notarizes.iter().map(|n| &n.proposal_signature);
        if let Err(err) = partial_verify_multiple_public_keys_precomputed::<V, _>(
            polynomial,
            Some(&notarize_namespace),
            &notarize_message,
            notarize_signatures,
        ) {
            for signature in err.iter() {
                invalid.insert(signature.index);
            }
        }

        // Verify seed signatures
        let seed_namespace = seed_namespace(namespace);
        let seed_message = proposal.round.encode();
        let seed_signatures = notarizes
            .iter()
            .filter(|n| !invalid.contains(&n.seed_signature.index))
            .map(|n| &n.seed_signature);
        if let Err(err) = partial_verify_multiple_public_keys_precomputed::<V, _>(
            polynomial,
            Some(&seed_namespace),
            &seed_message,
            seed_signatures,
        ) {
            for signature in err.iter() {
                invalid.insert(signature.index);
            }
        }

        // Remove invalid notarizes
        (
            notarizes
                .into_iter()
                .filter(|n| !invalid.contains(&n.signer()))
                .collect(),
            invalid.into_iter().collect(),
        )
    }

    /// Creates a [PartialSignature] over this [Notarize].
    pub fn sign(namespace: &[u8], share: &Share, proposal: Proposal<D>) -> Self {
        let notarize_namespace = notarize_namespace(namespace);
        let proposal_message = proposal.encode();
        let proposal_signature =
            partial_sign_message::<V>(share, Some(notarize_namespace.as_ref()), &proposal_message);
        let seed_namespace = seed_namespace(namespace);
        let seed_message = proposal.round.encode();
        let seed_signature =
            partial_sign_message::<V>(share, Some(seed_namespace.as_ref()), &seed_message);
        Notarize::new(proposal, proposal_signature, seed_signature)
    }
}

impl<V: Variant, D: Digest> Attributable for Notarize<V, D> {
    fn signer(&self) -> u32 {
        self.proposal_signature.index
    }
}

impl<V: Variant, D: Digest> Epochable for Notarize<V, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for Notarize<V, D> {
    type View = View;

    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<V: Variant, D: Digest> Write for Notarize<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for Notarize<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let proposal_signature = PartialSignature::<V>::read(reader)?;
        let seed_signature = PartialSignature::<V>::read(reader)?;
        if proposal_signature.index != seed_signature.index {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::Notarize",
                "mismatched signatures",
            ));
        }
        Ok(Notarize {
            proposal,
            proposal_signature,
            seed_signature,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for Notarize<V, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size()
            + self.proposal_signature.encode_size()
            + self.seed_signature.encode_size()
    }
}

/// Notarization represents a recovered threshold signature certifying a proposal.
/// When a proposal is notarized, it means at least 2f+1 validators have voted for it.
/// The threshold signatures provide compact verification compared to collecting individual signatures.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Notarization<V: Variant, D: Digest> {
    /// The proposal that has been notarized
    pub proposal: Proposal<D>,
    /// The recovered threshold signature on the proposal
    pub proposal_signature: V::Signature,
    /// The recovered threshold signature on the seed (for leader election/randomness)
    pub seed_signature: V::Signature,
}

impl<V: Variant, D: Digest> Notarization<V, D> {
    /// Creates a new notarization with the given proposal and aggregated signatures.
    pub fn new(
        proposal: Proposal<D>,
        proposal_signature: V::Signature,
        seed_signature: V::Signature,
    ) -> Self {
        Notarization {
            proposal,
            proposal_signature,
            seed_signature,
        }
    }

    /// Returns the round in which this notarization is made.
    pub fn round(&self) -> Round {
        self.proposal.round
    }

    /// Verifies the threshold signatures on this [Notarization].
    ///
    /// This ensures that:
    /// 1. The notarization signature is a valid threshold signature for the proposal
    /// 2. The seed signature is a valid threshold signature for the view
    pub fn verify(&self, namespace: &[u8], identity: &V::Public) -> bool {
        let notarize_namespace = notarize_namespace(namespace);
        let notarize_message = self.proposal.encode();
        let notarize_message = (Some(notarize_namespace.as_ref()), notarize_message.as_ref());
        let seed_namespace = seed_namespace(namespace);
        let seed_message = self.proposal.round.encode();
        let seed_message = (Some(seed_namespace.as_ref()), seed_message.as_ref());
        let signature =
            aggregate_signatures::<V, _>(&[self.proposal_signature, self.seed_signature]);
        aggregate_verify_multiple_messages::<V, _>(
            identity,
            &[notarize_message, seed_message],
            &signature,
            1,
        )
        .is_ok()
    }
}

impl<V: Variant, D: Digest> Epochable for Notarization<V, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for Notarization<V, D> {
    type View = View;

    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<V: Variant, D: Digest> Write for Notarization<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
        self.seed_signature.write(writer)
    }
}

impl<V: Variant, D: Digest> Read for Notarization<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let proposal_signature = V::Signature::read(reader)?;
        let seed_signature = V::Signature::read(reader)?;
        Ok(Notarization {
            proposal,
            proposal_signature,
            seed_signature,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for Notarization<V, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size()
            + self.proposal_signature.encode_size()
            + self.seed_signature.encode_size()
    }
}

impl<V: Variant, D: Digest> Seedable<V> for Notarization<V, D> {
    fn seed(&self) -> Seed<V> {
        Seed::new(self.proposal.round, self.seed_signature)
    }
}

/// Nullify represents a validator's vote to skip the current view.
/// This is typically used when the leader is unresponsive or fails to propose a valid block.
/// It contains partial signatures for the view and seed.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Nullify<V: Variant> {
    /// The round to be nullified (skipped)
    pub round: Round,
    /// The validator's partial signature on the view
    pub view_signature: PartialSignature<V>,
    /// The validator's partial signature on the seed (for leader election/randomness)
    pub seed_signature: PartialSignature<V>,
}

impl<V: Variant> Nullify<V> {
    /// Creates a new nullify with the given view and signatures.
    pub fn new(
        round: Round,
        view_signature: PartialSignature<V>,
        seed_signature: PartialSignature<V>,
    ) -> Self {
        Nullify {
            round,
            view_signature,
            seed_signature,
        }
    }

    /// Verifies the [PartialSignature]s on this [Nullify].
    ///
    /// This ensures that:
    /// 1. The view signature is valid for the given view
    /// 2. The seed signature is valid for the view
    /// 3. Both signatures are from the same signer
    pub fn verify(&self, namespace: &[u8], polynomial: &[V::Public]) -> bool {
        let nullify_namespace = nullify_namespace(namespace);
        let msg = self.round.encode();
        let nullify_message = (Some(nullify_namespace.as_ref()), msg.as_ref());
        let seed_namespace = seed_namespace(namespace);
        let seed_message = (Some(seed_namespace.as_ref()), msg.as_ref());
        let Some(evaluated) = polynomial.get(self.signer() as usize) else {
            return false;
        };
        let signature =
            aggregate_signatures::<V, _>(&[self.view_signature.value, self.seed_signature.value]);
        aggregate_verify_multiple_messages::<V, _>(
            evaluated,
            &[nullify_message, seed_message],
            &signature,
            1,
        )
        .is_ok()
    }

    /// Verifies a batch of [Nullify] messages using BLS aggregate verification.
    ///
    /// This function verifies a batch of [Nullify] messages using BLS aggregate verification.
    /// It returns a tuple containing:
    /// * A vector of successfully verified [Nullify] messages.
    /// * A vector of signer indices for whom verification failed.
    pub fn verify_multiple(
        namespace: &[u8],
        polynomial: &[V::Public],
        nullifies: Vec<Nullify<V>>,
    ) -> (Vec<Nullify<V>>, Vec<u32>) {
        // Prepare to verify
        if nullifies.is_empty() {
            return (nullifies, vec![]);
        } else if nullifies.len() == 1 {
            let valid = nullifies[0].verify(namespace, polynomial);
            if valid {
                return (nullifies, vec![]);
            } else {
                return (vec![], vec![nullifies[0].signer()]);
            }
        }
        let selected = &nullifies[0];
        let mut invalid = BTreeSet::new();

        // Verify view signature
        let nullify_namespace = nullify_namespace(namespace);
        let msg = selected.round.encode();
        let view_signatures = nullifies.iter().map(|n| &n.view_signature);
        if let Err(err) = partial_verify_multiple_public_keys_precomputed::<V, _>(
            polynomial,
            Some(&nullify_namespace),
            &msg,
            view_signatures,
        ) {
            for signature in err.iter() {
                invalid.insert(signature.index);
            }
        }

        // Verify seed signature
        let seed_namespace = seed_namespace(namespace);
        let seed_signatures = nullifies
            .iter()
            .filter(|n| !invalid.contains(&n.seed_signature.index))
            .map(|n| &n.seed_signature);
        if let Err(err) = partial_verify_multiple_public_keys_precomputed::<V, _>(
            polynomial,
            Some(&seed_namespace),
            &msg,
            seed_signatures,
        ) {
            for signature in err.iter() {
                invalid.insert(signature.index);
            }
        }

        // Return valid nullifies and invalid signers
        (
            nullifies
                .into_iter()
                .filter(|n| !invalid.contains(&n.signer()))
                .collect(),
            invalid.into_iter().collect(),
        )
    }

    /// Creates a [PartialSignature] over this [Nullify].
    pub fn sign(namespace: &[u8], share: &Share, round: Round) -> Self {
        let msg = round.encode();
        let ns = nullify_namespace(namespace);
        let view_signature = partial_sign_message::<V>(share, Some(&ns), &msg);
        let ns = seed_namespace(namespace);
        let seed_signature = partial_sign_message::<V>(share, Some(&ns), &msg);
        Nullify::new(round, view_signature, seed_signature)
    }
}

impl<V: Variant> Attributable for Nullify<V> {
    fn signer(&self) -> u32 {
        self.view_signature.index
    }
}

impl<V: Variant> Epochable for Nullify<V> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant> Viewable for Nullify<V> {
    type View = View;

    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant> Write for Nullify<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.view_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl<V: Variant> Read for Nullify<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let view_signature = PartialSignature::<V>::read(reader)?;
        let seed_signature = PartialSignature::<V>::read(reader)?;
        if view_signature.index != seed_signature.index {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::Nullify",
                "mismatched signatures",
            ));
        }
        Ok(Nullify {
            round,
            view_signature,
            seed_signature,
        })
    }
}

impl<V: Variant> EncodeSize for Nullify<V> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.view_signature.encode_size()
            + self.seed_signature.encode_size()
    }
}

/// Nullification represents a recovered threshold signature to skip a view.
/// When a view is nullified, the consensus moves to the next view without finalizing a block.
/// The threshold signatures provide compact verification compared to collecting individual signatures.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Nullification<V: Variant> {
    /// The round in which this nullification is made
    pub round: Round,
    /// The recovered threshold signature on the view
    pub view_signature: V::Signature,
    /// The recovered threshold signature on the seed (for leader election/randomness)
    pub seed_signature: V::Signature,
}

impl<V: Variant> Nullification<V> {
    /// Creates a new nullification with the given view and aggregated signatures.
    pub fn new(round: Round, view_signature: V::Signature, seed_signature: V::Signature) -> Self {
        Nullification {
            round,
            view_signature,
            seed_signature,
        }
    }

    /// Verifies the threshold signatures on this [Nullification].
    ///
    /// This ensures that:
    /// 1. The view signature is a valid threshold signature for the view
    /// 2. The seed signature is a valid threshold signature for the view
    pub fn verify(&self, namespace: &[u8], identity: &V::Public) -> bool {
        let nullify_namespace = nullify_namespace(namespace);
        let msg = self.round.encode();
        let nullify_message = (Some(nullify_namespace.as_ref()), msg.as_ref());
        let seed_namespace = seed_namespace(namespace);
        let seed_message = (Some(seed_namespace.as_ref()), msg.as_ref());
        let signature = aggregate_signatures::<V, _>(&[self.view_signature, self.seed_signature]);
        aggregate_verify_multiple_messages::<V, _>(
            identity,
            &[nullify_message, seed_message],
            &signature,
            1,
        )
        .is_ok()
    }
}

impl<V: Variant> Epochable for Nullification<V> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant> Viewable for Nullification<V> {
    type View = View;

    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant> Write for Nullification<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.view_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl<V: Variant> Read for Nullification<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let view_signature = V::Signature::read(reader)?;
        let seed_signature = V::Signature::read(reader)?;
        Ok(Nullification {
            round,
            view_signature,
            seed_signature,
        })
    }
}

impl<V: Variant> EncodeSize for Nullification<V> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.view_signature.encode_size()
            + self.seed_signature.encode_size()
    }
}

impl<V: Variant> Seedable<V> for Nullification<V> {
    fn seed(&self) -> Seed<V> {
        Seed::new(self.round, self.seed_signature)
    }
}

/// Finalize represents a validator's vote to finalize a proposal.
/// This happens after a proposal has been notarized, confirming it as the canonical block for this view.
/// It contains a partial signature on the proposal and a partial signature for the seed.
/// The seed is used for leader election and as a source of randomness.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Finalize<V: Variant, D: Digest> {
    /// The proposal to be finalized
    pub proposal: Proposal<D>,
    /// The validator's partial signature on the proposal
    pub proposal_signature: PartialSignature<V>,
    /// The validator's partial signature on the seed (for leader election/randomness)
    pub seed_signature: PartialSignature<V>,
}

impl<V: Variant, D: Digest> Finalize<V, D> {
    /// Creates a new finalize with the given proposal and signatures.
    pub fn new(
        proposal: Proposal<D>,
        proposal_signature: PartialSignature<V>,
        seed_signature: PartialSignature<V>,
    ) -> Self {
        Finalize {
            proposal,
            proposal_signature,
            seed_signature,
        }
    }

    /// Verifies the [PartialSignature]s on this [Finalize].
    ///
    /// This ensures that:
    /// 1. The finalize signature is valid for the claimed proposal
    /// 2. The seed signature is valid for the view
    /// 3. Both signatures are from the same signer
    pub fn verify(&self, namespace: &[u8], polynomial: &[V::Public]) -> bool {
        let finalize_namespace = finalize_namespace(namespace);
        let finalize_message = self.proposal.encode();
        let finalize_message = (Some(finalize_namespace.as_ref()), finalize_message.as_ref());
        let seed_namespace = seed_namespace(namespace);
        let seed_message = self.proposal.round.encode();
        let seed_message = (Some(seed_namespace.as_ref()), seed_message.as_ref());
        let Some(evaluated) = polynomial.get(self.signer() as usize) else {
            return false;
        };
        let signature = aggregate_signatures::<V, _>(&[
            self.proposal_signature.value,
            self.seed_signature.value,
        ]);
        aggregate_verify_multiple_messages::<V, _>(
            evaluated,
            &[finalize_message, seed_message],
            &signature,
            1,
        )
        .is_ok()
    }

    /// Verifies a batch of [Finalize] messages using BLS aggregate verification.
    ///
    /// This function verifies a batch of [Finalize] messages using BLS aggregate verification.
    /// It returns a tuple containing:
    /// * A vector of successfully verified [Finalize] messages.
    /// * A vector of signer indices for whom verification failed.
    pub fn verify_multiple(
        namespace: &[u8],
        polynomial: &[V::Public],
        finalizes: Vec<Finalize<V, D>>,
    ) -> (Vec<Finalize<V, D>>, Vec<u32>) {
        // Prepare to verify
        if finalizes.is_empty() {
            return (finalizes, vec![]);
        } else if finalizes.len() == 1 {
            let valid = finalizes[0].verify(namespace, polynomial);
            if valid {
                return (finalizes, vec![]);
            } else {
                return (vec![], vec![finalizes[0].signer()]);
            }
        }
        let proposal = &finalizes[0].proposal;
        let mut invalid = BTreeSet::new();

        // Verify proposal signature
        let finalize_namespace = finalize_namespace(namespace);
        let finalize_message = proposal.encode();
        let finalize_signatures = finalizes.iter().map(|f| &f.proposal_signature);
        if let Err(err) = partial_verify_multiple_public_keys_precomputed::<V, _>(
            polynomial,
            Some(&finalize_namespace),
            &finalize_message,
            finalize_signatures,
        ) {
            for signature in err.iter() {
                invalid.insert(signature.index);
            }
        }

        // Verify seed signatures
        let seed_namespace = seed_namespace(namespace);
        let seed_message = proposal.round.encode();
        let seed_signatures = finalizes
            .iter()
            .filter(|n| !invalid.contains(&n.seed_signature.index))
            .map(|n| &n.seed_signature);
        if let Err(err) = partial_verify_multiple_public_keys_precomputed::<V, _>(
            polynomial,
            Some(&seed_namespace),
            &seed_message,
            seed_signatures,
        ) {
            for signature in err.iter() {
                invalid.insert(signature.index);
            }
        }

        // Return valid finalizes and invalid signers
        (
            finalizes
                .into_iter()
                .filter(|f| !invalid.contains(&f.signer()))
                .collect(),
            invalid.into_iter().collect(),
        )
    }

    /// Creates a [PartialSignature] over this [Finalize].
    pub fn sign(namespace: &[u8], share: &Share, proposal: Proposal<D>) -> Self {
        let finalize_namespace = finalize_namespace(namespace);
        let proposal_message = proposal.encode();
        let proposal_signature =
            partial_sign_message::<V>(share, Some(finalize_namespace.as_ref()), &proposal_message);
        let seed_namespace = seed_namespace(namespace);
        let seed_message = proposal.round.encode();
        let seed_signature =
            partial_sign_message::<V>(share, Some(seed_namespace.as_ref()), &seed_message);
        Finalize::new(proposal, proposal_signature, seed_signature)
    }
}

impl<V: Variant, D: Digest> Attributable for Finalize<V, D> {
    fn signer(&self) -> u32 {
        self.proposal_signature.index
    }
}

impl<V: Variant, D: Digest> Epochable for Finalize<V, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for Finalize<V, D> {
    type View = View;

    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<V: Variant, D: Digest> Write for Finalize<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for Finalize<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let proposal_signature = PartialSignature::<V>::read(reader)?;
        let seed_signature = PartialSignature::<V>::read(reader)?;
        if proposal_signature.index != seed_signature.index {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::Finalize",
                "mismatched signatures",
            ));
        }
        Ok(Finalize {
            proposal,
            proposal_signature,
            seed_signature,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for Finalize<V, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size()
            + self.proposal_signature.encode_size()
            + self.seed_signature.encode_size()
    }
}

/// Finalization represents a recovered threshold signature to finalize a proposal.
/// When a proposal is finalized, it becomes the canonical block for its view.
/// The threshold signatures provide compact verification compared to collecting individual signatures.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Finalization<V: Variant, D: Digest> {
    /// The proposal that has been finalized
    pub proposal: Proposal<D>,
    /// The recovered threshold signature on the proposal
    pub proposal_signature: V::Signature,
    /// The recovered threshold signature on the seed (for leader election/randomness)
    pub seed_signature: V::Signature,
}

impl<V: Variant, D: Digest> Finalization<V, D> {
    /// Creates a new finalization with the given proposal and aggregated signatures.
    pub fn new(
        proposal: Proposal<D>,
        proposal_signature: V::Signature,
        seed_signature: V::Signature,
    ) -> Self {
        Finalization {
            proposal,
            proposal_signature,
            seed_signature,
        }
    }

    /// Returns the round in which this finalization is made.
    pub fn round(&self) -> Round {
        self.proposal.round
    }

    /// Verifies the threshold signatures on this [Finalization].
    ///
    /// This ensures that:
    /// 1. The proposal signature is a valid threshold signature for the proposal
    /// 2. The seed signature is a valid threshold signature for the view
    pub fn verify(&self, namespace: &[u8], identity: &V::Public) -> bool {
        let finalize_namespace = finalize_namespace(namespace);
        let finalize_message = self.proposal.encode();
        let finalize_message = (Some(finalize_namespace.as_ref()), finalize_message.as_ref());
        let seed_namespace = seed_namespace(namespace);
        let seed_message = self.proposal.round.encode();
        let seed_message = (Some(seed_namespace.as_ref()), seed_message.as_ref());
        let signature =
            aggregate_signatures::<V, _>(&[self.proposal_signature, self.seed_signature]);
        aggregate_verify_multiple_messages::<V, _>(
            identity,
            &[finalize_message, seed_message],
            &signature,
            1,
        )
        .is_ok()
    }
}

impl<V: Variant, D: Digest> Epochable for Finalization<V, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for Finalization<V, D> {
    type View = View;

    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<V: Variant, D: Digest> Write for Finalization<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for Finalization<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let proposal_signature = V::Signature::read(reader)?;
        let seed_signature = V::Signature::read(reader)?;
        Ok(Finalization {
            proposal,
            proposal_signature,
            seed_signature,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for Finalization<V, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size()
            + self.proposal_signature.encode_size()
            + self.seed_signature.encode_size()
    }
}

impl<V: Variant, D: Digest> Seedable<V> for Finalization<V, D> {
    fn seed(&self) -> Seed<V> {
        Seed::new(self.proposal.round, self.seed_signature)
    }
}

/// Backfiller is a message type for requesting and receiving missing consensus artifacts.
/// This is used to synchronize validators that have fallen behind or just joined the network.
#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<V: Variant, D: Digest> {
    /// Request for missing notarizations and nullifications
    Request(Request),
    /// Response containing requested notarizations and nullifications
    Response(Response<V, D>),
}

impl<V: Variant, D: Digest> Write for Backfiller<V, D> {
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

impl<V: Variant, D: Digest> EncodeSize for Backfiller<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Backfiller::Request(v) => v.encode_size(),
            Backfiller::Response(v) => v.encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Read for Backfiller<V, D> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, cfg: &usize) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Request::read_cfg(reader, cfg)?;
                Ok(Backfiller::Request(v))
            }
            1 => {
                let v = Response::<V, D>::read_cfg(reader, cfg)?;
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
pub struct Response<V: Variant, D: Digest> {
    /// Identifier matching the original request
    pub id: u64,
    /// Notarizations for the requested views
    pub notarizations: Vec<Notarization<V, D>>,
    /// Nullifications for the requested views
    pub nullifications: Vec<Nullification<V>>,
}

impl<V: Variant, D: Digest> Response<V, D> {
    /// Creates a new response with the given id, notarizations, and nullifications.
    pub fn new(
        id: u64,
        notarizations: Vec<Notarization<V, D>>,
        nullifications: Vec<Nullification<V>>,
    ) -> Self {
        Response {
            id,
            notarizations,
            nullifications,
        }
    }

    /// Verifies the signatures on this response using BLS aggregate verification.
    pub fn verify(&self, namespace: &[u8], identity: &V::Public) -> bool {
        // Prepare to verify
        if self.notarizations.is_empty() && self.nullifications.is_empty() {
            return true;
        }
        let mut seeds = HashMap::new();
        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        // Parse all notarizations
        let notarize_namespace = notarize_namespace(namespace);
        let seed_namespace = seed_namespace(namespace);
        for notarization in self.notarizations.iter() {
            // Prepare notarize message
            let notarize_message = notarization.proposal.encode().to_vec();
            let notarize_message = (Some(notarize_namespace.as_slice()), notarize_message);
            messages.push(notarize_message);
            signatures.push(&notarization.proposal_signature);

            // Add seed message (if not already present)
            if let Some(previous) = seeds.get(&notarization.proposal.view()) {
                if *previous != &notarization.seed_signature {
                    return false;
                }
            } else {
                let seed_message: Vec<u8> = notarization.proposal.round.encode().into();
                let seed_message = (Some(seed_namespace.as_slice()), seed_message);
                messages.push(seed_message);
                signatures.push(&notarization.seed_signature);
                seeds.insert(notarization.proposal.view(), &notarization.seed_signature);
            }
        }

        // Parse all nullifications
        let nullify_namespace = nullify_namespace(namespace);
        for nullification in self.nullifications.iter() {
            // Prepare nullify message
            let nullify_message: Vec<u8> = nullification.round.encode().into();
            let nullify_message = (Some(nullify_namespace.as_slice()), nullify_message);
            messages.push(nullify_message);
            signatures.push(&nullification.view_signature);

            // Add seed message (if not already present)
            if let Some(previous) = seeds.get(&nullification.view()) {
                if *previous != &nullification.seed_signature {
                    return false;
                }
            } else {
                let seed_message: Vec<u8> = nullification.round.encode().into();
                let seed_message = (Some(seed_namespace.as_slice()), seed_message);
                messages.push(seed_message);
                signatures.push(&nullification.seed_signature);
                seeds.insert(nullification.view(), &nullification.seed_signature);
            }
        }

        // Aggregate signatures
        let signature = aggregate_signatures::<V, _>(signatures);
        aggregate_verify_multiple_messages::<V, _>(
            identity,
            &messages
                .iter()
                .map(|(namespace, message)| (namespace.as_deref(), message.as_ref()))
                .collect::<Vec<_>>(),
            &signature,
            1,
        )
        .is_ok()
    }
}

impl<V: Variant, D: Digest> Write for Response<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.id).write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl<V: Variant, D: Digest> EncodeSize for Response<V, D> {
    fn encode_size(&self) -> usize {
        UInt(self.id).encode_size()
            + self.notarizations.encode_size()
            + self.nullifications.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for Response<V, D> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let id = UInt::read(reader)?.into();
        let mut views = HashSet::new();
        let notarizations = Vec::<Notarization<V, D>>::read_range(reader, ..=*max_len)?;
        for notarization in notarizations.iter() {
            if !views.insert(notarization.proposal.view()) {
                return Err(Error::Invalid(
                    "consensus::threshold_simplex::Response",
                    "Duplicate notarization",
                ));
            }
        }
        let remaining = max_len - notarizations.len();
        views.clear();
        let nullifications = Vec::<Nullification<V>>::read_range(reader, ..=remaining)?;
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
/// After collecting `t` [PartialSignature]s for the same [Activity], an attacker can derive
/// the [PartialSignature] for the `n-t` remaining participants.
///
/// For this reason, it is not sound to use [PartialSignature]-backed [Activity] to reward participants
/// for their contributions (as an attacker, for example, could forge contributions from offline participants).
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum Activity<V: Variant, D: Digest> {
    /// A single validator notarize over a proposal
    Notarize(Notarize<V, D>),
    /// A threshold signature for a notarization
    Notarization(Notarization<V, D>),
    /// A single validator nullify to skip the current view
    Nullify(Nullify<V>),
    /// A threshold signature for a nullification
    Nullification(Nullification<V>),
    /// A single validator finalize over a proposal
    Finalize(Finalize<V, D>),
    /// A threshold signature for a finalization
    Finalization(Finalization<V, D>),
    /// Evidence of a validator sending conflicting notarizes (Byzantine behavior)
    ConflictingNotarize(ConflictingNotarize<V, D>),
    /// Evidence of a validator sending conflicting finalizes (Byzantine behavior)
    ConflictingFinalize(ConflictingFinalize<V, D>),
    /// Evidence of a validator sending both nullify and finalize for the same view (Byzantine behavior)
    NullifyFinalize(NullifyFinalize<V, D>),
}

impl<V: Variant, D: Digest> Activity<V, D> {
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

impl<V: Variant, D: Digest> Write for Activity<V, D> {
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

impl<V: Variant, D: Digest> EncodeSize for Activity<V, D> {
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

impl<V: Variant, D: Digest> Read for Activity<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Notarize::<V, D>::read(reader)?;
                Ok(Activity::Notarize(v))
            }
            1 => {
                let v = Notarization::<V, D>::read(reader)?;
                Ok(Activity::Notarization(v))
            }
            2 => {
                let v = Nullify::<V>::read(reader)?;
                Ok(Activity::Nullify(v))
            }
            3 => {
                let v = Nullification::<V>::read(reader)?;
                Ok(Activity::Nullification(v))
            }
            4 => {
                let v = Finalize::<V, D>::read(reader)?;
                Ok(Activity::Finalize(v))
            }
            5 => {
                let v = Finalization::<V, D>::read(reader)?;
                Ok(Activity::Finalization(v))
            }
            6 => {
                let v = ConflictingNotarize::<V, D>::read(reader)?;
                Ok(Activity::ConflictingNotarize(v))
            }
            7 => {
                let v = ConflictingFinalize::<V, D>::read(reader)?;
                Ok(Activity::ConflictingFinalize(v))
            }
            8 => {
                let v = NullifyFinalize::<V, D>::read(reader)?;
                Ok(Activity::NullifyFinalize(v))
            }
            _ => Err(Error::Invalid(
                "consensus::threshold_simplex::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<V: Variant, D: Digest> Epochable for Activity<V, D> {
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

impl<V: Variant, D: Digest> Viewable for Activity<V, D> {
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

/// Seed represents a threshold signature over the current view.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Seed<V: Variant> {
    /// The round for which this seed is generated
    pub round: Round,
    /// The partial signature on the seed
    pub signature: V::Signature,
}

impl<V: Variant> Seed<V> {
    /// Creates a new seed with the given view and signature.
    pub fn new(round: Round, signature: V::Signature) -> Self {
        Seed { round, signature }
    }

    /// Verifies the threshold signature on this [Seed].
    pub fn verify(&self, namespace: &[u8], identity: &V::Public) -> bool {
        let seed_namespace = seed_namespace(namespace);
        let message = self.round.encode();
        verify_message::<V>(identity, Some(&seed_namespace), &message, &self.signature).is_ok()
    }
}

impl<V: Variant> Epochable for Seed<V> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant> Viewable for Seed<V> {
    type View = View;

    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant> Write for Seed<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant> Read for Seed<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let signature = V::Signature::read(reader)?;
        Ok(Seed { round, signature })
    }
}

impl<V: Variant> EncodeSize for Seed<V> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.signature.encode_size()
    }
}

/// ConflictingNotarize represents evidence of a Byzantine validator sending conflicting notarizes.
/// This is used to prove that a validator has equivocated (voted for different proposals in the same view).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConflictingNotarize<V: Variant, D: Digest> {
    /// The round in which the conflict occurred
    pub round: Round,
    /// The parent view of the first conflicting proposal
    pub parent_1: View,
    /// The payload of the first conflicting proposal
    pub payload_1: D,
    /// The signature on the first conflicting proposal
    pub signature_1: PartialSignature<V>,
    /// The parent view of the second conflicting proposal
    pub parent_2: View,
    /// The payload of the second conflicting proposal
    pub payload_2: D,
    /// The signature on the second conflicting proposal
    pub signature_2: PartialSignature<V>,
}

impl<V: Variant, D: Digest> ConflictingNotarize<V, D> {
    /// Creates a new conflicting notarize evidence from two conflicting notarizes.
    pub fn new(notarize_1: Notarize<V, D>, notarize_2: Notarize<V, D>) -> Self {
        assert_eq!(notarize_1.view(), notarize_2.view());
        assert_eq!(notarize_1.signer(), notarize_2.signer());
        ConflictingNotarize {
            round: notarize_1.proposal.round,
            parent_1: notarize_1.proposal.parent,
            payload_1: notarize_1.proposal.payload,
            signature_1: notarize_1.proposal_signature,
            parent_2: notarize_2.proposal.parent,
            payload_2: notarize_2.proposal.payload,
            signature_2: notarize_2.proposal_signature,
        }
    }

    /// Reconstructs the original proposals from this evidence.
    pub fn proposals(&self) -> (Proposal<D>, Proposal<D>) {
        (
            Proposal::new(self.round, self.parent_1, self.payload_1),
            Proposal::new(self.round, self.parent_2, self.payload_2),
        )
    }

    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify(&self, namespace: &[u8], polynomial: &[V::Public]) -> bool {
        let (proposal_1, proposal_2) = self.proposals();
        let notarize_namespace = notarize_namespace(namespace);
        let notarize_message_1 = proposal_1.encode();
        let notarize_message_1 = (
            Some(notarize_namespace.as_ref()),
            notarize_message_1.as_ref(),
        );
        let notarize_message_2 = proposal_2.encode();
        let notarize_message_2 = (
            Some(notarize_namespace.as_ref()),
            notarize_message_2.as_ref(),
        );
        let Some(evaluated) = polynomial.get(self.signer() as usize) else {
            return false;
        };
        let signature =
            aggregate_signatures::<V, _>(&[self.signature_1.value, self.signature_2.value]);
        aggregate_verify_multiple_messages::<V, _>(
            evaluated,
            &[notarize_message_1, notarize_message_2],
            &signature,
            1,
        )
        .is_ok()
    }
}

impl<V: Variant, D: Digest> Attributable for ConflictingNotarize<V, D> {
    fn signer(&self) -> u32 {
        self.signature_1.index
    }
}

impl<V: Variant, D: Digest> Epochable for ConflictingNotarize<V, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for ConflictingNotarize<V, D> {
    type View = View;

    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant, D: Digest> Write for ConflictingNotarize<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        UInt(self.parent_1).write(writer);
        self.payload_1.write(writer);
        self.signature_1.write(writer);
        UInt(self.parent_2).write(writer);
        self.payload_2.write(writer);
        self.signature_2.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for ConflictingNotarize<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let parent_1 = UInt::read(reader)?.into();
        let payload_1 = D::read(reader)?;
        let signature_1 = PartialSignature::<V>::read(reader)?;
        let parent_2 = UInt::read(reader)?.into();
        let payload_2 = D::read(reader)?;
        let signature_2 = PartialSignature::<V>::read(reader)?;
        if signature_1.index != signature_2.index {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::ConflictingNotarize",
                "mismatched signatures",
            ));
        }
        Ok(ConflictingNotarize {
            round,
            parent_1,
            payload_1,
            signature_1,
            parent_2,
            payload_2,
            signature_2,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for ConflictingNotarize<V, D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + UInt(self.parent_1).encode_size()
            + self.payload_1.encode_size()
            + self.signature_1.encode_size()
            + UInt(self.parent_2).encode_size()
            + self.payload_2.encode_size()
            + self.signature_2.encode_size()
    }
}

/// ConflictingFinalize represents evidence of a Byzantine validator sending conflicting finalizes.
/// Similar to ConflictingNotarize, but for finalizes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConflictingFinalize<V: Variant, D: Digest> {
    /// The round in which the conflict occurred
    pub round: Round,
    /// The parent view of the first conflicting proposal
    pub parent_1: View,
    /// The payload of the first conflicting proposal
    pub payload_1: D,
    /// The signature on the first conflicting proposal
    pub signature_1: PartialSignature<V>,
    /// The parent view of the second conflicting proposal
    pub parent_2: View,
    /// The payload of the second conflicting proposal
    pub payload_2: D,
    /// The signature on the second conflicting proposal
    pub signature_2: PartialSignature<V>,
}

impl<V: Variant, D: Digest> ConflictingFinalize<V, D> {
    /// Creates a new conflicting finalize evidence from two conflicting finalizes.
    pub fn new(finalize_1: Finalize<V, D>, finalize_2: Finalize<V, D>) -> Self {
        assert_eq!(finalize_1.view(), finalize_2.view());
        assert_eq!(finalize_1.signer(), finalize_2.signer());
        ConflictingFinalize {
            round: finalize_1.proposal.round,
            parent_1: finalize_1.proposal.parent,
            payload_1: finalize_1.proposal.payload,
            signature_1: finalize_1.proposal_signature,
            parent_2: finalize_2.proposal.parent,
            payload_2: finalize_2.proposal.payload,
            signature_2: finalize_2.proposal_signature,
        }
    }

    /// Reconstructs the original proposals from this evidence.
    pub fn proposals(&self) -> (Proposal<D>, Proposal<D>) {
        (
            Proposal::new(self.round, self.parent_1, self.payload_1),
            Proposal::new(self.round, self.parent_2, self.payload_2),
        )
    }

    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify(&self, namespace: &[u8], polynomial: &[V::Public]) -> bool {
        let (proposal_1, proposal_2) = self.proposals();
        let finalize_namespace = finalize_namespace(namespace);
        let finalize_message_1 = proposal_1.encode();
        let finalize_message_1 = (
            Some(finalize_namespace.as_ref()),
            finalize_message_1.as_ref(),
        );
        let finalize_message_2 = proposal_2.encode();
        let finalize_message_2 = (
            Some(finalize_namespace.as_ref()),
            finalize_message_2.as_ref(),
        );
        let Some(evaluated) = polynomial.get(self.signer() as usize) else {
            return false;
        };
        let signature =
            aggregate_signatures::<V, _>(&[self.signature_1.value, self.signature_2.value]);
        aggregate_verify_multiple_messages::<V, _>(
            evaluated,
            &[finalize_message_1, finalize_message_2],
            &signature,
            1,
        )
        .is_ok()
    }
}

impl<V: Variant, D: Digest> Attributable for ConflictingFinalize<V, D> {
    fn signer(&self) -> u32 {
        self.signature_1.index
    }
}

impl<V: Variant, D: Digest> Epochable for ConflictingFinalize<V, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for ConflictingFinalize<V, D> {
    type View = View;

    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant, D: Digest> Write for ConflictingFinalize<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        UInt(self.parent_1).write(writer);
        self.payload_1.write(writer);
        self.signature_1.write(writer);
        UInt(self.parent_2).write(writer);
        self.payload_2.write(writer);
        self.signature_2.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for ConflictingFinalize<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let parent_1 = UInt::read(reader)?.into();
        let payload_1 = D::read(reader)?;
        let signature_1 = PartialSignature::<V>::read(reader)?;
        let parent_2 = UInt::read(reader)?.into();
        let payload_2 = D::read(reader)?;
        let signature_2 = PartialSignature::<V>::read(reader)?;
        if signature_1.index != signature_2.index {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::ConflictingFinalize",
                "mismatched signatures",
            ));
        }
        Ok(ConflictingFinalize {
            round,
            parent_1,
            payload_1,
            signature_1,
            parent_2,
            payload_2,
            signature_2,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for ConflictingFinalize<V, D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + UInt(self.parent_1).encode_size()
            + self.payload_1.encode_size()
            + self.signature_1.encode_size()
            + UInt(self.parent_2).encode_size()
            + self.payload_2.encode_size()
            + self.signature_2.encode_size()
    }
}

/// NullifyFinalize represents evidence of a Byzantine validator sending both a nullify and finalize
/// for the same view, which is contradictory behavior (a validator should either try to skip a view OR
/// finalize a proposal, not both).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NullifyFinalize<V: Variant, D: Digest> {
    /// The proposal that the validator tried to finalize
    pub proposal: Proposal<D>,
    /// The signature on the nullify
    pub view_signature: PartialSignature<V>,
    /// The signature on the finalize
    pub finalize_signature: PartialSignature<V>,
}

impl<V: Variant, D: Digest> NullifyFinalize<V, D> {
    /// Creates a new nullify-finalize evidence from a nullify and a finalize.
    pub fn new(nullify: Nullify<V>, finalize: Finalize<V, D>) -> Self {
        assert_eq!(nullify.view(), finalize.view());
        assert_eq!(nullify.signer(), finalize.signer());
        NullifyFinalize {
            proposal: finalize.proposal,
            view_signature: nullify.view_signature,
            finalize_signature: finalize.proposal_signature,
        }
    }

    /// Verifies that both the nullify and finalize signatures are valid, proving Byzantine behavior.
    pub fn verify(&self, namespace: &[u8], polynomial: &[V::Public]) -> bool {
        let nullify_namespace = nullify_namespace(namespace);
        let nullify_message = self.proposal.round.encode();
        let nullify_message = (Some(nullify_namespace.as_ref()), nullify_message.as_ref());
        let finalize_namespace = finalize_namespace(namespace);
        let finalize_message = self.proposal.encode();
        let finalize_message = (Some(finalize_namespace.as_ref()), finalize_message.as_ref());
        let Some(evaluated) = polynomial.get(self.signer() as usize) else {
            return false;
        };
        let signature = aggregate_signatures::<V, _>(&[
            self.view_signature.value,
            self.finalize_signature.value,
        ]);
        aggregate_verify_multiple_messages::<V, _>(
            evaluated,
            &[nullify_message, finalize_message],
            &signature,
            1,
        )
        .is_ok()
    }
}

impl<V: Variant, D: Digest> Attributable for NullifyFinalize<V, D> {
    fn signer(&self) -> u32 {
        self.view_signature.index
    }
}

impl<V: Variant, D: Digest> Epochable for NullifyFinalize<V, D> {
    type Epoch = Epoch;

    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for NullifyFinalize<V, D> {
    type View = View;

    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<V: Variant, D: Digest> Write for NullifyFinalize<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.view_signature.write(writer);
        self.finalize_signature.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for NullifyFinalize<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let view_signature = PartialSignature::<V>::read(reader)?;
        let finalize_signature = PartialSignature::<V>::read(reader)?;
        if view_signature.index != finalize_signature.index {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::NullifyFinalize",
                "mismatched signatures",
            ));
        }
        Ok(NullifyFinalize {
            proposal,
            view_signature,
            finalize_signature,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for NullifyFinalize<V, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size()
            + self.view_signature.encode_size()
            + self.finalize_signature.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops::{self, evaluate_all},
            primitives::{
                group::{Element, Share},
                ops::threshold_signature_recover,
                poly,
                variant::MinSig,
            },
        },
        sha256::Digest as Sha256,
    };
    use commonware_utils::quorum;
    use rand::{rngs::StdRng, SeedableRng};

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256 {
        Sha256::from([v; 32]) // Simple fixed digest for testing
    }

    // Helper function to generate BLS shares and polynomial
    fn generate_test_data(
        n: u32,
        t: u32,
        seed: u64,
    ) -> (
        <MinSig as Variant>::Public,
        Vec<<MinSig as Variant>::Public>,
        Vec<Share>,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (polynomial, shares) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, t);
        let identity = poly::public::<MinSig>(&polynomial);
        let polynomial = evaluate_all::<MinSig>(&polynomial, n);
        (*identity, polynomial, shares)
    }

    #[test]
    fn test_proposal_encode_decode() {
        let proposal = Proposal::new(Round::new(0, 10), 5, sample_digest(1));
        let encoded = proposal.encode();
        let decoded = Proposal::<Sha256>::decode(encoded).unwrap();
        assert_eq!(proposal, decoded);
    }

    #[test]
    fn test_notarize_encode_decode() {
        let n = 5;
        let t = quorum(n);
        let (_, polynomial, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(Round::new(0, 10), 5, sample_digest(1));
        let notarize = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal);

        let encoded = notarize.encode();
        let decoded = Notarize::<MinSig, Sha256>::decode(encoded).unwrap();

        assert_eq!(notarize, decoded);
        assert!(decoded.verify(NAMESPACE, &polynomial));
    }

    #[test]
    fn test_notarization_encode_decode() {
        let n = 5;
        let t = quorum(n);
        let (identity, _, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(Round::new(0, 10), 5, sample_digest(1));

        // Create notarizes
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::<MinSig, _>::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Recover threshold signature
        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let proposal_signature =
            threshold_signature_recover::<MinSig, _>(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover::<MinSig, _>(t, seed_partials).unwrap();

        // Create notarization
        let notarization = Notarization::new(proposal, proposal_signature, seed_signature);
        let encoded = notarization.encode();
        let decoded = Notarization::<MinSig, Sha256>::decode(encoded).unwrap();
        assert_eq!(notarization, decoded);

        // Verify the notarization
        assert!(decoded.verify(NAMESPACE, &identity));

        // Create seed
        let seed = notarization.seed();
        let encoded = seed.encode();
        let decoded = Seed::<MinSig>::decode(encoded).unwrap();
        assert_eq!(seed, decoded);

        // Verify the seed
        assert!(decoded.verify(NAMESPACE, &identity));
    }

    #[test]
    fn test_nullify_encode_decode() {
        let n = 5;
        let t = quorum(n);
        let (_, polynomial, shares) = generate_test_data(n, t, 0);
        let round = Round::new(0, 10);

        let nullify = Nullify::<MinSig>::sign(NAMESPACE, &shares[0], round);

        let encoded = nullify.encode();
        let decoded = Nullify::<MinSig>::decode(encoded).unwrap();

        assert_eq!(nullify, decoded);
        assert!(decoded.verify(NAMESPACE, &polynomial));
    }

    #[test]
    fn test_nullification_encode_decode() {
        let n = 5;
        let t = quorum(n);
        let (identity, _, shares) = generate_test_data(n, t, 0);
        let round = Round::new(333, 10);

        // Create nullifies
        let nullifies: Vec<_> = shares
            .iter()
            .map(|s| Nullify::<MinSig>::sign(NAMESPACE, s, round))
            .collect();

        // Recover threshold signature
        let view_partials = nullifies.iter().map(|n| &n.view_signature);
        let view_signature = threshold_signature_recover::<MinSig, _>(t, view_partials).unwrap();
        let seed_partials = nullifies.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover::<MinSig, _>(t, seed_partials).unwrap();

        // Create nullification
        let nullification = Nullification::new(round, view_signature, seed_signature);
        let encoded = nullification.encode();
        let decoded = Nullification::<MinSig>::decode(encoded).unwrap();
        assert_eq!(nullification, decoded);

        // Verify the nullification
        assert!(decoded.verify(NAMESPACE, &identity));

        // Create seed
        let seed = nullification.seed();
        let encoded = seed.encode();
        let decoded = Seed::<MinSig>::decode(encoded).unwrap();
        assert_eq!(seed, decoded);

        // Verify the seed
        assert!(decoded.verify(NAMESPACE, &identity));
    }

    #[test]
    fn test_finalize_encode_decode() {
        let n = 5;
        let t = quorum(n);
        let (_, polynomial, shares) = generate_test_data(n, t, 0);

        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));
        let finalize = Finalize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal);

        let encoded = finalize.encode();
        let decoded = Finalize::<MinSig, Sha256>::decode(encoded).unwrap();

        assert_eq!(finalize, decoded);
        assert!(decoded.verify(NAMESPACE, &polynomial));
    }

    #[test]
    fn test_finalization_encode_decode() {
        let n = 5;
        let t = quorum(n);
        let (identity, _, shares) = generate_test_data(n, t, 0);

        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));

        // Create finalizes
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::<MinSig, _>::sign(NAMESPACE, s, proposal.clone()))
            .collect();
        let finalizes: Vec<_> = shares
            .iter()
            .map(|s| Finalize::<MinSig, _>::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Recover threshold signatures
        let proposal_partials = finalizes.iter().map(|f| &f.proposal_signature);
        let proposal_signature =
            threshold_signature_recover::<MinSig, _>(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover::<MinSig, _>(t, seed_partials).unwrap();

        // Create finalization
        let finalization = Finalization::new(proposal, proposal_signature, seed_signature);
        let encoded = finalization.encode();
        let decoded = Finalization::<MinSig, Sha256>::decode(encoded).unwrap();
        assert_eq!(finalization, decoded);

        // Verify the finalization
        assert!(decoded.verify(NAMESPACE, &identity));

        // Create seed
        let seed = finalization.seed();
        let encoded = seed.encode();
        let decoded = Seed::<MinSig>::decode(encoded).unwrap();
        assert_eq!(seed, decoded);

        // Verify the seed
        assert!(decoded.verify(NAMESPACE, &identity));
    }

    #[test]
    fn test_backfiller_encode_decode() {
        // Test Request
        let request = Request::new(1, vec![10, 11], vec![12, 13]);
        let backfiller = Backfiller::<MinSig, Sha256>::Request(request.clone());
        let encoded = backfiller.encode();
        let decoded = Backfiller::<MinSig, Sha256>::decode_cfg(encoded, &usize::MAX).unwrap();
        assert!(matches!(decoded, Backfiller::Request(r) if r == request));

        // Test Response
        let n = 5;
        let t = quorum(n);
        let (_, _, shares) = generate_test_data(n, t, 0);

        // Create a notarization
        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::<MinSig, _>::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let proposal_signature =
            threshold_signature_recover::<MinSig, _>(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover::<MinSig, _>(t, seed_partials).unwrap();

        let notarization = Notarization::new(proposal, proposal_signature, seed_signature);

        // Create a nullification
        let nullifies: Vec<_> = shares
            .iter()
            .map(|s| Nullify::<MinSig>::sign(NAMESPACE, s, round))
            .collect();

        let view_partials = nullifies.iter().map(|n| &n.view_signature);
        let view_signature = threshold_signature_recover::<MinSig, _>(t, view_partials).unwrap();
        let seed_partials = nullifies.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover::<MinSig, _>(t, seed_partials).unwrap();

        let nullification = Nullification::new(round, view_signature, seed_signature);

        // Create a response
        let response = Response::new(1, vec![notarization], vec![nullification]);
        let backfiller = Backfiller::<MinSig, Sha256>::Response(response.clone());
        let encoded = backfiller.encode();
        let decoded = Backfiller::<MinSig, Sha256>::decode_cfg(encoded, &usize::MAX).unwrap();
        assert!(matches!(decoded, Backfiller::Response(r) if r.id == response.id));
    }

    #[test]
    fn test_request_encode_decode() {
        let request = Request::new(1, vec![10, 11], vec![12, 13]);
        let encoded = request.encode();
        let decoded = Request::decode_cfg(encoded, &usize::MAX).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn test_response_encode_decode() {
        let n = 5;
        let t = quorum(n);
        let (identity, _, shares) = generate_test_data(n, t, 0);
        let notarized_round = Round::new(333, 10);
        let nullified_round = Round::new(333, 11);

        // Create a notarization
        let proposal = Proposal::new(notarized_round, 5, sample_digest(1));
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::<MinSig, _>::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let proposal_signature =
            threshold_signature_recover::<MinSig, _>(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover::<MinSig, _>(t, seed_partials).unwrap();

        let notarization = Notarization::new(proposal, proposal_signature, seed_signature);

        // Create a nullification
        let nullifies: Vec<_> = shares
            .iter()
            .map(|s| Nullify::<MinSig>::sign(NAMESPACE, s, nullified_round))
            .collect();

        let view_partials = nullifies.iter().map(|n| &n.view_signature);
        let view_signature = threshold_signature_recover::<MinSig, _>(t, view_partials).unwrap();
        let seed_partials = nullifies.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover::<MinSig, _>(t, seed_partials).unwrap();

        let nullification = Nullification::new(nullified_round, view_signature, seed_signature);

        // Create a response
        let response = Response::<MinSig, Sha256>::new(1, vec![notarization], vec![nullification]);
        let encoded = response.encode();
        let mut decoded = Response::<MinSig, Sha256>::decode_cfg(encoded, &usize::MAX).unwrap();
        assert_eq!(response.id, decoded.id);
        assert_eq!(response.notarizations.len(), decoded.notarizations.len());
        assert_eq!(response.nullifications.len(), decoded.nullifications.len());

        // Verify the response
        assert!(decoded.verify(NAMESPACE, &identity));

        // Modify the response
        decoded.nullifications[0]
            .view_signature
            .add(&<MinSig as Variant>::Signature::one());

        // Verify the modified response
        assert!(!decoded.verify(NAMESPACE, &identity));
    }

    #[test]
    fn test_conflicting_notarize_encode_decode() {
        let n = 5;
        let t = quorum(n);
        let (_, polynomial, shares) = generate_test_data(n, t, 0);

        let proposal1 = Proposal::new(Round::new(0, 10), 5, sample_digest(1));
        let proposal2 = Proposal::new(Round::new(0, 10), 5, sample_digest(2));
        let notarize1 = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal1);
        let notarize2 = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal2);
        let conflicting_notarize = ConflictingNotarize::new(notarize1, notarize2);

        let encoded = conflicting_notarize.encode();
        let decoded = ConflictingNotarize::<MinSig, Sha256>::decode(encoded).unwrap();

        assert_eq!(conflicting_notarize, decoded);
        assert!(decoded.verify(NAMESPACE, &polynomial));
    }

    #[test]
    fn test_conflicting_finalize_encode_decode() {
        let n = 5;
        let t = quorum(n);
        let (_, polynomial, shares) = generate_test_data(n, t, 0);

        let proposal1 = Proposal::new(Round::new(0, 10), 5, sample_digest(1));
        let proposal2 = Proposal::new(Round::new(0, 10), 5, sample_digest(2));
        let finalize1 = Finalize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal1);
        let finalize2 = Finalize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal2);
        let conflicting_finalize = ConflictingFinalize::new(finalize1, finalize2);

        let encoded = conflicting_finalize.encode();
        let decoded = ConflictingFinalize::<MinSig, Sha256>::decode(encoded).unwrap();

        assert_eq!(conflicting_finalize, decoded);
        assert!(decoded.verify(NAMESPACE, &polynomial));
    }

    #[test]
    fn test_nullify_finalize_encode_decode() {
        let n = 5;
        let t = quorum(n);
        let (_, polynomial, shares) = generate_test_data(n, t, 0);
        let round = Round::new(0, 10);

        let proposal = Proposal::new(round, 5, sample_digest(1));
        let nullify = Nullify::<MinSig>::sign(NAMESPACE, &shares[0], round);
        let finalize = Finalize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal);
        let nullify_finalize = NullifyFinalize::new(nullify, finalize);

        let encoded = nullify_finalize.encode();
        let decoded = NullifyFinalize::<MinSig, Sha256>::decode(encoded).unwrap();

        assert_eq!(nullify_finalize, decoded);
        assert!(decoded.verify(NAMESPACE, &polynomial));
    }

    #[test]
    fn test_notarize_verify_wrong_namespace() {
        let n = 5;
        let t = quorum(n);
        let (_, polynomial, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(Round::new(0, 10), 5, sample_digest(1));
        let notarize = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal);

        // Verify with correct namespace and polynomial - should pass
        assert!(notarize.verify(NAMESPACE, &polynomial));

        // Verify with wrong namespace - should fail
        assert!(!notarize.verify(b"wrong_namespace", &polynomial));
    }

    #[test]
    fn test_notarize_verify_wrong_polynomial() {
        let n = 5;
        let t = quorum(n);
        let (_, polynomial1, shares1) = generate_test_data(n, t, 0);

        // Generate a different set of BLS keys/shares
        let (_, polynomial2, _) = generate_test_data(n, t, 1);

        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));
        let notarize = Notarize::<MinSig, _>::sign(NAMESPACE, &shares1[0], proposal);

        // Verify with correct polynomial - should pass
        assert!(notarize.verify(NAMESPACE, &polynomial1));

        // Verify with wrong polynomial - should fail
        assert!(!notarize.verify(NAMESPACE, &polynomial2));
    }

    #[test]
    fn test_notarization_verify_wrong_keys() {
        let n = 5;
        let t = quorum(n);
        let (identity, _, shares) = generate_test_data(n, t, 0);

        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));

        // Create notarizes
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::<MinSig, _>::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Recover threshold signature
        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let proposal_signature =
            threshold_signature_recover::<MinSig, _>(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover::<MinSig, _>(t, seed_partials).unwrap();

        // Create notarization
        let notarization =
            Notarization::<MinSig, _>::new(proposal, proposal_signature, seed_signature);

        // Verify with correct public key - should pass
        assert!(notarization.verify(NAMESPACE, &identity));

        // Generate a different set of BLS keys/shares
        let (wrong_identity, _, _) = generate_test_data(n, t, 1);

        // Verify with wrong public key - should fail
        assert!(!notarization.verify(NAMESPACE, &wrong_identity));
    }

    #[test]
    fn test_notarization_verify_wrong_namespace() {
        let n = 5;
        let t = quorum(n);
        let (identity, _, shares) = generate_test_data(n, t, 0);

        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));

        // Create notarizes
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::<MinSig, _>::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Recover threshold signature
        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let proposal_signature =
            threshold_signature_recover::<MinSig, _>(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover::<MinSig, _>(t, seed_partials).unwrap();

        // Create notarization
        let notarization =
            Notarization::<MinSig, _>::new(proposal, proposal_signature, seed_signature);

        // Verify with correct namespace - should pass
        assert!(notarization.verify(NAMESPACE, &identity));

        // Verify with wrong namespace - should fail
        assert!(!notarization.verify(b"wrong_namespace", &identity));
    }

    #[test]
    fn test_threshold_recover_insufficient_signatures() {
        let n = 5;
        let t = quorum(n); // For n=5, t should be 4 (2f+1 where f=1)
        let (_, _, shares) = generate_test_data(n, t, 0);

        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));

        // Create notarizes, but only collect t-1 of them
        let notarizes: Vec<_> = shares
            .iter()
            .take((t as usize) - 1) // One less than the threshold
            .map(|s| Notarize::<MinSig, _>::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Try to recover threshold signature with insufficient partials - should fail
        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let result = threshold_signature_recover::<MinSig, _>(t, proposal_partials);

        // Should not be able to recover the threshold signature
        assert!(result.is_err());
    }

    #[test]
    fn test_conflicting_notarize_detection() {
        let n = 5;
        let t = quorum(n);
        let (_, polynomial, shares) = generate_test_data(n, t, 0);

        // Create two different proposals for the same view
        let round = Round::new(0, 10);
        let proposal1 = Proposal::new(round, 5, sample_digest(1));
        let proposal2 = Proposal::new(round, 5, sample_digest(2)); // Same view, different payload

        // Create notarizes for both proposals from the same validator
        let notarize1 = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal1.clone());
        let notarize2 = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal2);

        // Create conflict evidence
        let conflict = ConflictingNotarize::new(notarize1, notarize2.clone());

        // Verify the evidence is valid
        assert!(conflict.verify(NAMESPACE, &polynomial));

        // Now create invalid evidence using different validator keys
        let notarize3 = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[1], proposal1.clone());

        // This should compile but verification should fail because the signatures
        // are from different validators
        let invalid_conflict: ConflictingNotarize<MinSig, Sha256> = ConflictingNotarize {
            round: conflict.round,
            parent_1: conflict.parent_1,
            payload_1: conflict.payload_1,
            signature_1: conflict.signature_1.clone(),
            parent_2: notarize3.proposal.parent,
            payload_2: notarize3.proposal.payload,
            signature_2: notarize3.proposal_signature,
        };

        // Verification should still fail even with correct polynomial
        assert!(!invalid_conflict.verify(NAMESPACE, &polynomial));
    }

    #[test]
    fn test_nullify_finalize_detection() {
        let n = 5;
        let t = quorum(n);
        let (_, polynomial, shares) = generate_test_data(n, t, 0);

        let round = Round::new(0, 10);

        // Create a nullify for view 10
        let nullify = Nullify::<MinSig>::sign(NAMESPACE, &shares[0], round);

        // Create a finalize for the same view
        let proposal = Proposal::new(round, 5, sample_digest(1));
        let finalize = Finalize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal);

        // Create nullify+finalize evidence
        let conflict = NullifyFinalize::new(nullify, finalize.clone());

        // Verify the evidence is valid
        assert!(conflict.verify(NAMESPACE, &polynomial));

        // Now try with wrong namespace
        assert!(!conflict.verify(b"wrong_namespace", &polynomial));

        // Now create invalid evidence with different validators
        let nullify2 = Nullify::<MinSig>::sign(NAMESPACE, &shares[1], round);

        // Compile but verification should fail because signatures are from different validators
        let invalid_conflict: NullifyFinalize<MinSig, Sha256> = NullifyFinalize {
            proposal: finalize.proposal.clone(),
            view_signature: conflict.view_signature.clone(),
            finalize_signature: nullify2.view_signature,
        };

        // Verification should fail
        assert!(!invalid_conflict.verify(NAMESPACE, &polynomial));
    }

    #[test]
    fn test_finalization_wrong_signature() {
        let n = 5;
        let t = quorum(n);
        let (identity, _, shares) = generate_test_data(n, t, 0);

        // Create a completely different key set
        let (wrong_identity, _, _) = generate_test_data(n, t, 1);

        let round = Round::new(0, 10);
        let proposal = Proposal::new(round, 5, sample_digest(1));

        // Create finalizes and notarizes for threshold signatures
        let finalizes: Vec<_> = shares
            .iter()
            .map(|s| Finalize::<MinSig, _>::sign(NAMESPACE, s, proposal.clone()))
            .collect();
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::<MinSig, _>::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Recover threshold signatures
        let proposal_partials = finalizes.iter().map(|f| &f.proposal_signature);
        let proposal_signature =
            threshold_signature_recover::<MinSig, _>(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover::<MinSig, _>(t, seed_partials).unwrap();

        // Create finalization
        let finalization =
            Finalization::<MinSig, _>::new(proposal, proposal_signature, seed_signature);

        // Verify with correct public key - should pass
        assert!(finalization.verify(NAMESPACE, &identity));

        // Verify with wrong public key - should fail
        assert!(!finalization.verify(NAMESPACE, &wrong_identity));
    }

    // Helper to create a Notarize message
    fn create_notarize(
        share: &Share,
        round: Round,
        parent_view: View,
        payload_val: u8,
    ) -> Notarize<MinSig, Sha256> {
        let proposal = Proposal::new(round, parent_view, sample_digest(payload_val));
        Notarize::<MinSig, _>::sign(NAMESPACE, share, proposal)
    }

    // Helper to create a Nullify message
    fn create_nullify(share: &Share, round: Round) -> Nullify<MinSig> {
        Nullify::<MinSig>::sign(NAMESPACE, share, round)
    }

    // Helper to create a Finalize message
    fn create_finalize(
        share: &Share,
        round: Round,
        parent_view: View,
        payload_val: u8,
    ) -> Finalize<MinSig, Sha256> {
        let proposal = Proposal::new(round, parent_view, sample_digest(payload_val));
        Finalize::<MinSig, _>::sign(NAMESPACE, share, proposal)
    }

    // Helper to create a Notarization (for panic test)
    fn create_notarization(
        proposal_round: Round,
        parent_view: View,
        payload_val: u8,
        shares: &[Share],
        threshold: u32,
    ) -> Notarization<MinSig, Sha256> {
        let proposal = Proposal::new(proposal_round, parent_view, sample_digest(payload_val));
        let notarizes: Vec<_> = shares
            .iter()
            .take(threshold as usize)
            .map(|s| Notarize::<MinSig, _>::sign(NAMESPACE, s, proposal.clone()))
            .collect();
        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let proposal_signature =
            threshold_signature_recover::<MinSig, _>(threshold, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature =
            threshold_signature_recover::<MinSig, _>(threshold, seed_partials).unwrap();
        Notarization::new(proposal, proposal_signature, seed_signature)
    }

    #[test]
    fn test_batch_verifier_add_notarize() {
        let n_validators = 5;
        let threshold = quorum(n_validators);
        let (_, _, shares) = generate_test_data(n_validators, threshold, 123);

        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));

        let round = Round::new(0, 1);
        let notarize1_s0 = create_notarize(&shares[0], round, 0, 1); // validator 0
        let notarize2_s1 = create_notarize(&shares[1], round, 0, 1); // validator 1 (same proposal)
        let notarize_diff_prop_s2 = create_notarize(&shares[2], round, 0, 2); // validator 2 (different proposal)

        // Add notarize1 (unverified)
        verifier.add(Voter::Notarize(notarize1_s0.clone()), false);
        assert_eq!(verifier.notarizes.len(), 1);
        assert_eq!(verifier.notarizes_verified, 0);

        // Add notarize1 again (verified)
        verifier.add(Voter::Notarize(notarize1_s0.clone()), true);
        assert_eq!(verifier.notarizes.len(), 1); // Still 1 pending
        assert_eq!(verifier.notarizes_verified, 1); // Verified count increases

        // Set leader to validator 0 (signer of notarize1)
        // This should trigger set_leader_proposal with notarize1's proposal
        verifier.set_leader(shares[0].index);
        assert!(verifier.leader_proposal.is_some());
        assert_eq!(
            verifier.leader_proposal.as_ref().unwrap(),
            &notarize1_s0.proposal
        );
        assert!(verifier.notarizes_force); // Force verification
        assert_eq!(verifier.notarizes.len(), 1); // notarize1 still there

        // Add notarize2 (matches leader proposal)
        verifier.add(Voter::Notarize(notarize2_s1.clone()), false);
        assert_eq!(verifier.notarizes.len(), 2);

        // Add notarize_diff_prop (does not match leader proposal, should be dropped)
        verifier.add(Voter::Notarize(notarize_diff_prop_s2.clone()), false);
        assert_eq!(verifier.notarizes.len(), 2); // Should not have been added

        // Test adding when leader is set, but proposal comes from non-leader first
        let mut verifier2 = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 2);
        let notarize_s1_v2 = create_notarize(&shares[1], round, 1, 3); // from validator 1
        let notarize_s0_v2_leader = create_notarize(&shares[0], round, 1, 3); // from validator 0 (leader)

        verifier2.set_leader(shares[0].index); // Leader is 0
        verifier2.add(Voter::Notarize(notarize_s1_v2.clone()), false); // Add non-leader's msg
        assert!(verifier2.leader_proposal.is_none()); // Leader proposal not set yet
        assert_eq!(verifier2.notarizes.len(), 1);

        verifier2.add(Voter::Notarize(notarize_s0_v2_leader.clone()), false); // Add leader's msg
        assert!(verifier2.leader_proposal.is_some()); // Now set
        assert_eq!(
            verifier2.leader_proposal.as_ref().unwrap(),
            &notarize_s0_v2_leader.proposal
        );
        assert_eq!(verifier2.notarizes.len(), 2); // Both should be there
    }

    #[test]
    fn test_batch_verifier_set_leader() {
        let n_validators = 5;
        let threshold = quorum(n_validators);
        let (_, _, shares) = generate_test_data(n_validators, threshold, 124);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));

        let round = Round::new(0, 1);
        let notarize_s0 = create_notarize(&shares[0], round, 0, 1);
        let notarize_s1 = create_notarize(&shares[1], round, 0, 1);

        // Add notarize from non-leader first
        verifier.add(Voter::Notarize(notarize_s1.clone()), false);
        assert_eq!(verifier.notarizes.len(), 1);

        // Set leader to s0 (no notarize from s0 yet)
        verifier.set_leader(shares[0].index);
        assert_eq!(verifier.leader, Some(shares[0].index));
        assert!(verifier.leader_proposal.is_none()); // No proposal from leader yet
        assert!(!verifier.notarizes_force);
        assert_eq!(verifier.notarizes.len(), 1); // notarize_s1 still there

        // Add notarize from leader (s0)
        verifier.add(Voter::Notarize(notarize_s0.clone()), false);
        assert!(verifier.leader_proposal.is_some()); // Leader proposal now set
        assert_eq!(
            verifier.leader_proposal.as_ref().unwrap(),
            &notarize_s0.proposal
        );
        assert!(verifier.notarizes_force); // Force verification
        assert_eq!(verifier.notarizes.len(), 2); // Both notarizes present (assuming same proposal)
    }

    #[test]
    fn test_batch_verifier_ready_and_verify_notarizes() {
        let n_validators = 5;
        let threshold = quorum(n_validators); // threshold = 4
        let (_, polynomial, shares) = generate_test_data(n_validators, threshold, 125);

        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let proposal = Proposal::new(Round::new(0, 1), 0, sample_digest(1));

        let notarize_s0 = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal.clone());
        let notarize_s1 = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[1], proposal.clone());
        let notarize_s2 = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[2], proposal.clone());
        let notarize_s3 = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[3], proposal.clone()); // Enough for quorum

        // Not ready - no leader/proposal (This specific check is now in test_ready_notarizes_without_leader_or_proposal)
        assert!(!verifier.ready_notarizes());

        // Set leader and add leader's notarize
        verifier.set_leader(shares[0].index);
        verifier.add(Voter::Notarize(notarize_s0.clone()), false);
        assert!(verifier.ready_notarizes()); // notarizes_force is true (Covered by test_ready_notarizes_behavior_with_force_flag)
        assert_eq!(verifier.notarizes.len(), 1);

        let (verified_n, failed_n) = verifier.verify_notarizes(NAMESPACE, &polynomial);
        assert_eq!(verified_n.len(), 1);
        assert!(failed_n.is_empty());
        assert_eq!(verifier.notarizes_verified, 1);
        assert!(verifier.notarizes.is_empty());
        assert!(!verifier.notarizes_force); // Reset after verify (Covered by test_ready_notarizes_behavior_with_force_flag)

        // Not ready - not enough
        verifier.add(Voter::Notarize(notarize_s1.clone()), false); // Verified: 1, Pending: 1. Total: 2 < 4
        assert!(!verifier.ready_notarizes());
        verifier.add(Voter::Notarize(notarize_s2.clone()), false); // Verified: 1, Pending: 2. Total: 3 < 4
        assert!(!verifier.ready_notarizes());
        verifier.add(Voter::Notarize(notarize_s3.clone()), false); // Verified: 1, Pending: 3. Total: 4 == 4
        assert!(verifier.ready_notarizes()); // (Covered by test_ready_notarizes_exact_quorum)
        assert_eq!(verifier.notarizes.len(), 3);

        let (verified_n, failed_n) = verifier.verify_notarizes(NAMESPACE, &polynomial);
        assert_eq!(verified_n.len(), 3);
        assert!(failed_n.is_empty());
        assert_eq!(verifier.notarizes_verified, 1 + 3); // 1 previous + 3 new
        assert!(verifier.notarizes.is_empty());

        // Not ready - quorum met by verified (Covered by test_ready_notarizes_quorum_already_met_by_verified)
        assert!(!verifier.ready_notarizes());

        // Scenario: Verification with a faulty signature
        let mut verifier2 = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        verifier2.set_leader(shares[0].index); // Set leader
        let round = Round::new(0, 2);
        let leader_notarize = create_notarize(&shares[0], round, 1, 10);
        verifier2.add(Voter::Notarize(leader_notarize.clone()), false); // Add leader's notarize
        let mut faulty_notarize = create_notarize(&shares[1], round, 1, 10); // Same proposal as leader

        // Corrupt a signature
        let (_, _, other_shares) = generate_test_data(n_validators, threshold, 126);
        faulty_notarize.proposal_signature = Notarize::<MinSig, _>::sign(
            NAMESPACE,
            &other_shares[1],
            faulty_notarize.proposal.clone(),
        ) // Sign with a "wrong" share for that index
        .proposal_signature;

        verifier2.add(Voter::Notarize(faulty_notarize.clone()), false); // Add invalid notarize
        assert!(verifier2.ready_notarizes()); // Force is true

        let (verified_n, failed_n) = verifier2.verify_notarizes(NAMESPACE, &polynomial);
        assert_eq!(verified_n.len(), 1); // Only leader's should verify
        assert!(verified_n.contains(&Voter::Notarize(leader_notarize)));
        assert_eq!(failed_n.len(), 1);
        assert_eq!(failed_n[0], shares[1].index); // s1's should fail
    }

    #[test]
    fn test_batch_verifier_add_nullify() {
        let n_validators = 5;
        let threshold = quorum(n_validators);
        let (_, _, shares) = generate_test_data(n_validators, threshold, 127);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));

        let round = Round::new(0, 1);
        let nullify1_s0 = create_nullify(&shares[0], round);

        // Add unverified
        verifier.add(Voter::Nullify(nullify1_s0.clone()), false);
        assert_eq!(verifier.nullifies.len(), 1);
        assert_eq!(verifier.nullifies_verified, 0);

        // Add verified
        verifier.add(Voter::Nullify(nullify1_s0.clone()), true);
        assert_eq!(verifier.nullifies.len(), 1);
        assert_eq!(verifier.nullifies_verified, 1);
    }

    #[test]
    fn test_batch_verifier_ready_and_verify_nullifies() {
        let n_validators = 5;
        let threshold = quorum(n_validators); // threshold = 4
        let (_, polynomial, shares) = generate_test_data(n_validators, threshold, 128);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));

        let round = Round::new(0, 1);
        let nullify_s0 = create_nullify(&shares[0], round);
        let nullify_s1 = create_nullify(&shares[1], round);
        let nullify_s2 = create_nullify(&shares[2], round);
        let nullify_s3 = create_nullify(&shares[3], round); // Enough for quorum

        // Not ready, not enough
        verifier.add(Voter::Nullify(nullify_s0.clone()), true); // Verified: 1
        assert_eq!(verifier.nullifies_verified, 1);
        verifier.add(Voter::Nullify(nullify_s1.clone()), false); // Verified: 1, Pending: 1. Total: 2 < 4
        assert!(!verifier.ready_nullifies());
        verifier.add(Voter::Nullify(nullify_s2.clone()), false); // Verified: 1, Pending: 2. Total: 3 < 4
        assert!(!verifier.ready_nullifies());

        // Ready, enough for quorum
        verifier.add(Voter::Nullify(nullify_s3.clone()), false); // Verified: 1, Pending: 3. Total: 4 == 4
        assert!(verifier.ready_nullifies());
        assert_eq!(verifier.nullifies.len(), 3);

        let (verified_null, failed_null) = verifier.verify_nullifies(NAMESPACE, &polynomial);
        assert_eq!(verified_null.len(), 3);
        assert!(failed_null.is_empty());
        assert_eq!(verifier.nullifies_verified, 1 + 3);

        // Nothing to do after verify
        assert!(verifier.nullifies.is_empty());
        assert!(!verifier.ready_nullifies());
    }

    #[test]
    fn test_batch_verifier_add_finalize() {
        let n_validators = 5;
        let threshold = quorum(n_validators);
        let (_, _, shares) = generate_test_data(n_validators, threshold, 129);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));

        let round = Round::new(0, 1);
        let finalize_s0_prop_a = create_finalize(&shares[0], round, 0, 1); // Proposal A
        let finalize_s1_prop_b = create_finalize(&shares[1], round, 0, 2); // Proposal B

        // Add finalize_s1_propB (unverified) - No leader proposal yet, so it's added
        verifier.add(Voter::Finalize(finalize_s1_prop_b.clone()), false);
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes_verified, 0);

        // Add finalize_s0_prop_a (unverified)
        verifier.add(Voter::Finalize(finalize_s0_prop_a.clone()), false);
        assert_eq!(verifier.finalizes.len(), 2); // Both are present

        // Set leader and leader proposal to Proposal A
        // This specific call to set_leader won't set leader_proposal because no notarize from leader exists.
        verifier.set_leader(shares[0].index);
        assert!(verifier.leader_proposal.is_none());
        // Manually set leader_proposal for finalize_s0_propA
        verifier.set_leader_proposal(finalize_s0_prop_a.proposal.clone());
        // Now, finalize_s1_propB should have been removed.
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes[0], finalize_s0_prop_a);
        assert_eq!(verifier.finalizes_verified, 0);

        // Add finalize_s0_propA (verified)
        verifier.add(Voter::Finalize(finalize_s0_prop_a.clone()), true);
        assert_eq!(verifier.finalizes.len(), 1); // Still finalize_s0_propA
        assert_eq!(verifier.finalizes_verified, 1); // Verified count increased

        // Add finalize_s1_propB (unverified) - should be dropped as it doesn't match leader proposal
        verifier.add(Voter::Finalize(finalize_s1_prop_b.clone()), false);
        assert_eq!(verifier.finalizes.len(), 1); // Should still be 1 (finalize_s0_propA)
        assert_eq!(verifier.finalizes_verified, 1);
    }

    #[test]
    fn test_batch_verifier_ready_and_verify_finalizes() {
        let n_validators = 5;
        let threshold = quorum(n_validators); // threshold = 4
        let (_, polynomial, shares) = generate_test_data(n_validators, threshold, 130);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);
        let leader_proposal = Proposal::new(round, 0, sample_digest(1));

        let finalize_s0 =
            Finalize::<MinSig, _>::sign(NAMESPACE, &shares[0], leader_proposal.clone());
        let finalize_s1 =
            Finalize::<MinSig, _>::sign(NAMESPACE, &shares[1], leader_proposal.clone());
        let finalize_s2 =
            Finalize::<MinSig, _>::sign(NAMESPACE, &shares[2], leader_proposal.clone());
        let finalize_s3 =
            Finalize::<MinSig, _>::sign(NAMESPACE, &shares[3], leader_proposal.clone());

        // Not ready - no leader/proposal set (Covered by test_ready_finalizes_without_leader_or_proposal)
        assert!(!verifier.ready_finalizes());

        // Set leader and leader proposal
        verifier.set_leader(shares[0].index); // Leader is s0
                                              // Manually set leader proposal, as set_leader won't do it without a notarize from leader.
        verifier.set_leader_proposal(leader_proposal.clone());

        // Add some (verified and unverified)
        verifier.add(Voter::Finalize(finalize_s0.clone()), true); // Verified: 1
        assert_eq!(verifier.finalizes_verified, 1);
        assert_eq!(verifier.finalizes.len(), 0);

        verifier.add(Voter::Finalize(finalize_s1.clone()), false); // Verified: 1, Pending: 1. Total: 2 < 4
        assert!(!verifier.ready_finalizes());
        verifier.add(Voter::Finalize(finalize_s2.clone()), false); // Verified: 1, Pending: 2. Total: 3 < 4
        assert!(!verifier.ready_finalizes());

        // Ready for finalizes
        verifier.add(Voter::Finalize(finalize_s3.clone()), false); // Verified: 1, Pending: 3. Total: 4 == 4
        assert!(verifier.ready_finalizes()); // (Covered by test_ready_finalizes_exact_quorum)

        let (verified_fin, failed_fin) = verifier.verify_finalizes(NAMESPACE, &polynomial);
        assert_eq!(verified_fin.len(), 3);
        assert!(failed_fin.is_empty());
        assert_eq!(verifier.finalizes_verified, 1 + 3);
        assert!(verifier.finalizes.is_empty());

        // Not ready, quorum met (Covered by test_ready_finalizes_quorum_already_met_by_verified)
        assert!(!verifier.ready_finalizes());
    }

    #[test]
    fn test_batch_verifier_quorum_none() {
        let n_validators = 3;
        let threshold = quorum(n_validators); // Not strictly used by BatchVerifier logic when quorum is None
        let (_, polynomial, shares) = generate_test_data(n_validators, threshold, 200);
        let round = Round::new(0, 1);

        // Test with Notarizes
        let mut verifier_n = BatchVerifier::<MinSig, Sha256>::new(None);
        let prop1 = Proposal::new(round, 0, sample_digest(1));
        let notarize1 = create_notarize(&shares[0], round, 0, 1);

        assert!(!verifier_n.ready_notarizes()); // No leader/proposal
        verifier_n.set_leader(shares[0].index);
        verifier_n.add(Voter::Notarize(notarize1.clone()), false); // Sets leader proposal and notarizes_force
        assert!(verifier_n.ready_notarizes()); // notarizes_force is true, and notarizes is not empty

        let (verified, failed) = verifier_n.verify_notarizes(NAMESPACE, &polynomial);
        assert_eq!(verified.len(), 1);
        assert!(failed.is_empty());
        assert_eq!(verifier_n.notarizes_verified, 1);
        assert!(!verifier_n.ready_notarizes()); // notarizes_force is false, list is empty

        // Test with Nullifies
        let mut verifier_null = BatchVerifier::<MinSig, Sha256>::new(None);
        let nullify1 = create_nullify(&shares[0], round);
        assert!(!verifier_null.ready_nullifies()); // List is empty
        verifier_null.add(Voter::Nullify(nullify1.clone()), false);
        assert!(verifier_null.ready_nullifies()); // List is not empty
        let (verified, failed) = verifier_null.verify_nullifies(NAMESPACE, &polynomial);
        assert_eq!(verified.len(), 1);
        assert!(failed.is_empty());
        assert_eq!(verifier_null.nullifies_verified, 1);
        assert!(!verifier_null.ready_nullifies()); // List is empty

        // Test with Finalizes
        let mut verifier_f = BatchVerifier::<MinSig, Sha256>::new(None);
        let finalize1 = create_finalize(&shares[0], round, 0, 1);
        assert!(!verifier_f.ready_finalizes()); // No leader/proposal
        verifier_f.set_leader(shares[0].index);
        verifier_f.set_leader_proposal(prop1.clone()); // Assume prop1 is the leader's proposal
        verifier_f.add(Voter::Finalize(finalize1.clone()), false);
        assert!(verifier_f.ready_finalizes()); // Leader/proposal set, list not empty
        let (verified, failed) = verifier_f.verify_finalizes(NAMESPACE, &polynomial);
        assert_eq!(verified.len(), 1);
        assert!(failed.is_empty());
        assert_eq!(verifier_f.finalizes_verified, 1);
        assert!(!verifier_f.ready_finalizes()); // List is empty
    }

    #[test]
    fn test_batch_verifier_leader_proposal_filters_messages() {
        let n_validators = 3;
        let threshold = quorum(n_validators);
        let (_, _, shares) = generate_test_data(n_validators, threshold, 201);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));

        let round = Round::new(0, 1);
        let proposal_a = Proposal::new(round, 0, sample_digest(10));
        let proposal_b = Proposal::new(round, 0, sample_digest(20));

        let notarize_a_s0 = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal_a.clone());
        let notarize_b_s1 = Notarize::<MinSig, _>::sign(NAMESPACE, &shares[1], proposal_b.clone());
        let finalize_a_s0 = Finalize::<MinSig, _>::sign(NAMESPACE, &shares[0], proposal_a.clone());
        let finalize_b_s1 = Finalize::<MinSig, _>::sign(NAMESPACE, &shares[1], proposal_b.clone());

        verifier.add(Voter::Notarize(notarize_a_s0.clone()), false);
        verifier.add(Voter::Notarize(notarize_b_s1.clone()), false);
        verifier.add(Voter::Finalize(finalize_a_s0.clone()), false);
        verifier.add(Voter::Finalize(finalize_b_s1.clone()), false);

        assert_eq!(verifier.notarizes.len(), 2);
        assert_eq!(verifier.finalizes.len(), 2);

        // Set leader proposal to proposal_A
        // To make set_leader_proposal get called from set_leader, a notarize from the leader must exist.
        // Or, call it directly.
        verifier.set_leader(shares[0].index);

        assert!(verifier.notarizes_force);
        assert_eq!(verifier.notarizes.len(), 1);
        assert_eq!(verifier.notarizes[0].proposal, proposal_a);
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes[0].proposal, proposal_a);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_batch_verifier_set_leader_twice_panics() {
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(3));
        verifier.set_leader(0);
        verifier.set_leader(1); // This should panic
    }

    #[test]
    #[should_panic(expected = "should not be adding recovered messages to partial verifier")]
    fn test_batch_verifier_add_recovered_message_panics() {
        let n_validators = 3;
        let threshold = quorum(n_validators);
        let (_, _, shares) = generate_test_data(n_validators, threshold, 202);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);

        let notarization = create_notarization(round, 0, 1, &shares, threshold);
        verifier.add(Voter::Notarization(notarization), false); // This should panic
    }

    #[test]
    fn test_ready_notarizes_behavior_with_force_flag() {
        let n_validators = 3;
        let threshold = quorum(n_validators);
        let (_, polynomial, shares) = generate_test_data(n_validators, threshold, 203);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);

        let leader_notarize = create_notarize(&shares[0], round, 0, 1);

        // Set leader and add leader's notarize
        verifier.set_leader(shares[0].index);
        // Manually add leader's notarize for it to pick up leader_proposal
        verifier.add(Voter::Notarize(leader_notarize.clone()), false);

        assert!(
            verifier.notarizes_force,
            "notarizes_force should be true after leader's proposal is set"
        );
        assert!(
            verifier.ready_notarizes(),
            "Ready should be true when notarizes_force is true"
        );

        // Assume leader's own notarize is processed. Let's verify it.
        let (verified, _) = verifier.verify_notarizes(NAMESPACE, &polynomial);
        assert_eq!(verified.len(), 1);

        assert!(
            !verifier.notarizes_force,
            "notarizes_force should be false after verification"
        );
        assert!(
            !verifier.ready_notarizes(),
            "Ready should be false now (no pending, quorum not met by verified alone)"
        );
    }

    #[test]
    fn test_ready_notarizes_without_leader_or_proposal() {
        let n_validators = 3;
        let threshold = quorum(n_validators);
        let (_, _, shares) = generate_test_data(n_validators, threshold, 204);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);

        // Collect sufficient number of unverified notarizes
        for i in 0..threshold {
            verifier.add(
                Voter::Notarize(create_notarize(&shares[i as usize], round, 0, 1)),
                false,
            );
        }
        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready without leader/proposal set"
        );

        // Set leader
        verifier.set_leader(shares[0].index);
        assert!(
            verifier.ready_notarizes(),
            "Should be ready once leader is set"
        );
    }

    #[test]
    fn test_ready_finalizes_without_leader_or_proposal() {
        let n_validators = 3;
        let threshold = quorum(n_validators);
        let (_, _, shares) = generate_test_data(n_validators, threshold, 205);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);

        for i in 0..threshold {
            verifier.add(
                Voter::Finalize(create_finalize(&shares[i as usize], round, 0, 1)),
                false,
            );
        }
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready without leader/proposal set"
        );

        // Set leader, still not ready
        verifier.set_leader(shares[0].index);
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready without leader_proposal set"
        );
    }

    #[test]
    fn test_verify_notarizes_empty_pending_when_forced() {
        let n_validators = 3;
        let threshold = quorum(n_validators);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);

        let leader_proposal = Proposal::new(round, 0, sample_digest(1));
        verifier.set_leader_proposal(leader_proposal); // This sets notarizes_force = true

        assert!(verifier.notarizes_force);
        assert!(verifier.notarizes.is_empty());
        assert!(!verifier.ready_notarizes());
    }

    #[test]
    fn test_verify_nullifies_empty_pending() {
        let n_validators = 3;
        let threshold = quorum(n_validators);
        let (_, polynomial, _) = generate_test_data(n_validators, threshold, 207);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));

        assert!(verifier.nullifies.is_empty());
        // ready_nullifies will be false if the list is empty and quorum is Some
        assert!(!verifier.ready_nullifies());

        let (verified, failed) = verifier.verify_nullifies(NAMESPACE, &polynomial);
        assert!(verified.is_empty());
        assert!(failed.is_empty());
        assert_eq!(verifier.nullifies_verified, 0);
    }

    #[test]
    fn test_verify_finalizes_empty_pending() {
        let n_validators = 3;
        let threshold = quorum(n_validators);
        let (_, polynomial, shares) = generate_test_data(n_validators, threshold, 208);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));

        // ready_finalizes will be false if the list is empty and quorum is Some
        verifier.set_leader(shares[0].index);
        assert!(verifier.finalizes.is_empty());
        assert!(!verifier.ready_finalizes());

        let (verified, failed) = verifier.verify_finalizes(NAMESPACE, &polynomial);
        assert!(verified.is_empty());
        assert!(failed.is_empty());
        assert_eq!(verifier.finalizes_verified, 0);
    }

    #[test]
    fn test_ready_notarizes_exact_quorum() {
        let n_validators = 5;
        let threshold = quorum(n_validators); // threshold = 4
        let (_, polynomial, shares) = generate_test_data(n_validators, threshold, 209);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);

        let leader_notarize = create_notarize(&shares[0], round, 0, 1);
        verifier.set_leader(shares[0].index);
        verifier.add(Voter::Notarize(leader_notarize), true); // 1 verified
        assert_eq!(verifier.notarizes_verified, 1);

        // Add next verified notarize
        verifier.add(
            Voter::Notarize(create_notarize(&shares[1], round, 0, 1)),
            false,
        );

        // Perform forced verification
        assert!(verifier.ready_notarizes());
        let (verified, failed) = verifier.verify_notarizes(NAMESPACE, &polynomial);
        assert_eq!(verified.len(), 1);
        assert!(failed.is_empty());
        assert_eq!(verifier.notarizes_verified, 1 + 1);

        // Add threshold - 1 pending notarizes
        for share in shares.iter().take(threshold as usize).skip(2) {
            assert!(!verifier.ready_notarizes());
            verifier.add(Voter::Notarize(create_notarize(share, round, 0, 1)), false);
        }

        // Now, notarizes_verified = 2, notarizes.len() = 2. Total = 4 == threshold
        assert!(verifier.ready_notarizes());
    }

    #[test]
    fn test_ready_nullifies_exact_quorum() {
        let n_validators = 5;
        let threshold = quorum(n_validators); // threshold = 4
        let (_, _, shares) = generate_test_data(n_validators, threshold, 210);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);

        verifier.add(Voter::Nullify(create_nullify(&shares[0], round)), true); // 1 verified
        assert_eq!(verifier.nullifies_verified, 1);

        for share in shares.iter().take(threshold as usize).skip(1) {
            assert!(!verifier.ready_nullifies());
            verifier.add(Voter::Nullify(create_nullify(share, round)), false);
        }
        assert!(verifier.ready_nullifies());
    }

    #[test]
    fn test_ready_finalizes_exact_quorum() {
        let n_validators = 5;
        let threshold = quorum(n_validators); // threshold = 4
        let (_, _, shares) = generate_test_data(n_validators, threshold, 211);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);

        let leader_proposal = Proposal::new(round, 0, sample_digest(1));
        verifier.set_leader(shares[0].index);
        verifier.set_leader_proposal(leader_proposal.clone());

        verifier.add(
            Voter::Finalize(create_finalize(&shares[0], round, 0, 1)),
            true,
        ); // 1 verified
        assert_eq!(verifier.finalizes_verified, 1);

        for share in shares.iter().take(threshold as usize).skip(1) {
            assert!(!verifier.ready_finalizes());
            verifier.add(Voter::Finalize(create_finalize(share, round, 0, 1)), false);
        }
        assert!(verifier.ready_finalizes());
    }

    #[test]
    fn test_ready_notarizes_quorum_already_met_by_verified() {
        let n_validators = 5;
        let threshold = quorum(n_validators); // threshold = 4
        let (_, _, shares) = generate_test_data(n_validators, threshold, 212);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);

        let leader_notarize = create_notarize(&shares[0], round, 0, 1);
        verifier.set_leader(shares[0].index);
        verifier.add(Voter::Notarize(leader_notarize), false); // This sets leader_proposal and notarizes_force
                                                               // Manually set notarizes_force to false as if verify_notarizes was called.
        verifier.notarizes_force = false;

        for share in shares.iter().take(threshold as usize) {
            verifier.add(Voter::Notarize(create_notarize(share, round, 0, 1)), true);
        }
        assert_eq!(verifier.notarizes_verified as u32, threshold);
        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Add one more pending, still should not be ready
        verifier.add(
            Voter::Notarize(create_notarize(&shares[threshold as usize], round, 0, 1)),
            false,
        );
        assert!(!verifier.ready_notarizes());
    }

    #[test]
    fn test_ready_nullifies_quorum_already_met_by_verified() {
        let n_validators = 5;
        let threshold = quorum(n_validators); // threshold = 4
        let (_, _, shares) = generate_test_data(n_validators, threshold, 213);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);

        for share in shares.iter().take(threshold as usize) {
            verifier.add(Voter::Nullify(create_nullify(share, round)), true);
        }
        assert_eq!(verifier.nullifies_verified as u32, threshold);
        assert!(!verifier.ready_nullifies());

        verifier.add(
            Voter::Nullify(create_nullify(&shares[threshold as usize], round)),
            false,
        );
        assert!(!verifier.ready_nullifies());
    }

    #[test]
    fn test_ready_finalizes_quorum_already_met_by_verified() {
        let n_validators = 5;
        let threshold = quorum(n_validators); // threshold = 4
        let (_, _, shares) = generate_test_data(n_validators, threshold, 214);
        let mut verifier = BatchVerifier::<MinSig, Sha256>::new(Some(threshold));
        let round = Round::new(0, 1);

        let leader_proposal = Proposal::new(round, 0, sample_digest(1));
        verifier.set_leader(shares[0].index);
        verifier.set_leader_proposal(leader_proposal.clone());

        for share in shares.iter().take(threshold as usize) {
            verifier.add(Voter::Finalize(create_finalize(share, round, 0, 1)), true);
        }
        assert_eq!(verifier.finalizes_verified as u32, threshold);
        assert!(!verifier.ready_finalizes());

        verifier.add(
            Voter::Finalize(create_finalize(&shares[threshold as usize], round, 0, 1)),
            false,
        );
        assert!(!verifier.ready_finalizes());
    }
}
