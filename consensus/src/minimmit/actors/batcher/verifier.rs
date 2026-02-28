//! Batch signature verification for Minimmit consensus.
//!
//! This module handles batched verification of votes to enable efficient
//! certificate construction. Unlike Simplex, Minimmit has no separate Finalize
//! vote - finalization uses the same Notarize votes with a higher threshold.

use crate::{
    minimmit::{
        scheme::Scheme,
        types::{Attributable, Notarize, Nullify, Proposal, Subject, Vote},
    },
    types::Participant,
};
use commonware_cryptography::{certificate::Verification, Digest};
use commonware_parallel::Strategy;
use rand_core::CryptoRngCore;
use std::mem;

/// `Verifier` is a utility for tracking and verifying consensus messages.
///
/// For schemes where [`Scheme::is_batchable()`](commonware_cryptography::certificate::Scheme::is_batchable)
/// returns `true` (such as ed25519, bls12381_multisig, and bls12381_threshold), this struct collects
/// messages and defers verification until enough messages exist to potentially reach a quorum,
/// enabling efficient batch verification. For schemes where `is_batchable()` returns `false`
/// (such as secp256r1), signatures are verified eagerly as they arrive.
///
/// Unlike Simplex, Minimmit only has two vote types (Notarize, Nullify).
/// Certificate construction is delegated to the state machine.
pub struct Verifier<S: Scheme<D>, D: Digest> {
    /// Signing scheme used to verify votes and assemble certificates.
    scheme: S,

    /// M-quorum size (2f+1) for MNotarization and Nullification.
    m_quorum: usize,

    /// L-quorum size (n-f) for Finalization.
    l_quorum: usize,

    /// Current leader index.
    leader: Option<Participant>,
    /// Proposal associated with the current leader.
    leader_proposal: Option<Proposal<D>>,

    /// Pending notarize votes waiting to be verified.
    notarizes: Vec<Notarize<S, D>>,
    /// Count of already-verified notarize votes.
    notarizes_verified: usize,

    /// Notarize votes for conflicting proposals.
    conflicting_notarizes: Vec<Notarize<S, D>>,

    /// Pending nullify votes waiting to be verified.
    nullifies: Vec<Nullify<S>>,
    /// Count of already-verified nullify votes.
    nullifies_verified: usize,
}

impl<S: Scheme<D>, D: Digest> Verifier<S, D> {
    /// Creates a new `Verifier`.
    ///
    /// # Arguments
    ///
    /// * `scheme` - Scheme handle used to verify and aggregate votes.
    /// * `m_quorum` - The M-quorum size (2f+1) for MNotarization and Nullification.
    /// * `l_quorum` - The L-quorum size (n-f) for Finalization.
    pub const fn new(scheme: S, m_quorum: u32, l_quorum: u32) -> Self {
        Self {
            scheme,
            m_quorum: m_quorum as usize,
            l_quorum: l_quorum as usize,

            leader: None,
            leader_proposal: None,

            notarizes: Vec::new(),
            notarizes_verified: 0,

            conflicting_notarizes: Vec::new(),

            nullifies: Vec::new(),
            nullifies_verified: 0,
        }
    }

    /// Records the leader's proposal and filters out pending votes for other proposals.
    fn set_leader_proposal(&mut self, proposal: Proposal<D>) {
        let mut retained = Vec::new();
        let mut conflicts = Vec::new();
        for notarize in self.notarizes.drain(..) {
            if notarize.proposal == proposal {
                retained.push(notarize);
            } else {
                conflicts.push(notarize);
            }
        }
        self.notarizes = retained;
        self.conflicting_notarizes.extend(conflicts);
        self.leader_proposal = Some(proposal);
    }

    /// Returns the leader proposal, if it is set.
    pub fn get_leader_proposal(&self) -> Option<(Participant, Proposal<D>)> {
        self.leader_proposal
            .as_ref()
            .map(|proposal| (self.leader.unwrap(), proposal.clone()))
    }

    /// Adds a [Vote] message to the batch for later verification.
    ///
    /// If the message has already been verified (e.g., we built it), it increments
    /// the count of verified messages directly. Otherwise, it adds the message to
    /// the appropriate pending queue.
    ///
    /// If a leader is known and the message is a [Vote::Notarize] from that leader,
    /// this method may trigger `set_leader_proposal`.
    ///
    /// Once the leader's proposal is known, only votes for that proposal are accepted.
    /// Votes for other proposals are dropped since they cannot contribute to a valid
    /// certificate.
    ///
    /// # Arguments
    ///
    /// * `msg` - The [Vote] message to add.
    /// * `verified` - A boolean indicating if the message has already been verified.
    ///
    /// # Returns
    ///
    /// `true` if the vote was accepted.
    pub fn add(&mut self, msg: Vote<S, D>, verified: bool) -> bool {
        match msg {
            Vote::Notarize(notarize) => {
                if let Some(ref leader_proposal) = self.leader_proposal {
                    // Leader proposal is known - only accept votes for it
                    if notarize.proposal != *leader_proposal {
                        self.conflicting_notarizes.push(notarize);
                        return true;
                    }
                } else if let Some(leader) = self.leader {
                    // Leader is known but proposal is not - set it from leader's vote
                    if leader == notarize.signer() {
                        self.set_leader_proposal(notarize.proposal.clone());
                    }
                }

                if verified {
                    self.notarizes_verified += 1;
                } else {
                    self.notarizes.push(notarize);
                }
                true
            }
            Vote::Nullify(nullify) => {
                if verified {
                    self.nullifies_verified += 1;
                } else {
                    self.nullifies.push(nullify);
                }
                true
            }
        }
    }

    /// Sets the leader for the current consensus view.
    ///
    /// If a notarize vote from the leader has already been received, this will
    /// also set the leader's proposal.
    pub fn set_leader(&mut self, leader: Participant) {
        assert!(self.leader.is_none());
        self.leader = Some(leader);

        // If we already have the leader's vote, set the leader proposal
        let Some(notarize) = self.notarizes.iter().find(|n| n.signer() == leader) else {
            return;
        };
        self.set_leader_proposal(notarize.proposal.clone());
    }

    /// Marks that M-quorum was reached for this view.
    ///
    /// This is called when an MNotarization certificate is created or recovered
    /// from the journal. It allows the verifier to know that M-quorum was reached
    /// (even if the individual votes weren't tracked) so it can continue batching
    /// toward L-quorum.
    ///
    /// This is important for crash recovery: after restart, `notarizes_verified`
    /// is 0, but if we have an MNotarization certificate, we know M-quorum was
    /// reached and should batch toward L-quorum rather than M-quorum.
    pub const fn mark_m_quorum_reached(&mut self) {
        // Only update if we haven't already verified M-quorum worth of votes
        if self.notarizes_verified < self.m_quorum {
            self.notarizes_verified = self.m_quorum;
        }
    }

    /// Verifies a batch of pending [Vote::Notarize] messages.
    ///
    /// All pending votes are for the leader's proposal (filtered during `add()`).
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    /// * `strategy` - Parallelization strategy for verification.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A `Vec<Vote<S, D>>` of successfully verified [Vote::Notarize] messages.
    /// * A `Vec<Participant>` of signer indices for whom verification failed.
    pub fn verify_notarizes<R: CryptoRngCore>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> (Vec<Vote<S, D>>, Vec<Participant>) {
        let verify_leader = self.ready_leader_notarizes();
        let notarizes = if verify_leader {
            mem::take(&mut self.notarizes)
        } else {
            Vec::new()
        };
        let conflicting = mem::take(&mut self.conflicting_notarizes);

        let mut verified_votes = Vec::new();
        let mut invalid = Vec::new();

        if verify_leader {
            let Some(proposal) = &self.leader_proposal else {
                return (vec![], vec![]);
            };

            let attestations = notarizes.into_iter().map(|n| n.attestation);
            let Verification {
                verified,
                invalid: invalid_signers,
            } = self.scheme.verify_attestations::<_, D, _>(
                rng,
                Subject::Notarize { proposal },
                attestations,
                strategy,
            );

            verified_votes.extend(verified.into_iter().map(|attestation| {
                Vote::Notarize(Notarize {
                    proposal: proposal.clone(),
                    attestation,
                })
            }));
            invalid.extend(invalid_signers);
            self.notarizes_verified += verified_votes.len();
        }

        for notarize in conflicting {
            if notarize.verify(rng, &self.scheme, strategy) {
                verified_votes.push(Vote::Notarize(notarize));
            } else {
                invalid.push(notarize.signer());
            }
        }

        (verified_votes, invalid)
    }

    /// Checks if there are [Vote::Notarize] messages ready for batch verification.
    ///
    /// Batching strategy:
    /// - Before M-quorum: batch when we can reach M-quorum
    /// - After M-quorum: batch when we can reach L-quorum
    ///
    /// The `notarizes_verified` count may be set via `mark_m_quorum_reached()` when
    /// an MNotarization certificate exists (either newly created or recovered from
    /// journal). This ensures that after crash recovery, we continue batching toward
    /// L-quorum rather than re-batching toward M-quorum.
    pub fn ready_notarizes(&self) -> bool {
        if !self.conflicting_notarizes.is_empty() {
            return true;
        }

        self.ready_leader_notarizes()
    }

    fn ready_leader_notarizes(&self) -> bool {
        // If there are no pending notarizes, there is nothing to do.
        if self.notarizes.is_empty() {
            return false;
        }

        // If we've already verified enough for L-quorum, no need to verify more.
        if self.notarizes_verified >= self.l_quorum {
            return false;
        }

        // If we don't yet know the leader, notarizes may contain messages for
        // a number of different proposals.
        if self.leader.is_none() || self.leader_proposal.is_none() {
            return false;
        }

        // For schemes that don't benefit from batching, verify immediately.
        if !S::is_batchable() {
            return true;
        }

        let total = self.notarizes_verified + self.notarizes.len();

        // If M-quorum was reached (via verification or mark_m_quorum_reached),
        // batch toward L-quorum.
        if self.notarizes_verified >= self.m_quorum {
            return total >= self.l_quorum;
        }

        // Before M-quorum, batch when we can reach M-quorum.
        total >= self.m_quorum
    }

    /// Verifies a batch of pending [Vote::Nullify] messages.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    /// * `strategy` - Parallelization strategy for verification.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A `Vec<Vote<S, D>>` of successfully verified [Vote::Nullify] messages.
    /// * A `Vec<Participant>` of signer indices for whom verification failed.
    pub fn verify_nullifies<R: CryptoRngCore>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> (Vec<Vote<S, D>>, Vec<Participant>) {
        let nullifies = mem::take(&mut self.nullifies);

        // Early return if there are no nullifies to verify
        if nullifies.is_empty() {
            return (vec![], vec![]);
        }

        let round = nullifies[0].round;

        let Verification { verified, invalid } = self.scheme.verify_attestations::<_, D, _>(
            rng,
            Subject::Nullify { round },
            nullifies.into_iter().map(|nullify| nullify.attestation),
            strategy,
        );

        self.nullifies_verified += verified.len();

        (
            verified
                .into_iter()
                .map(|attestation| Vote::Nullify(Nullify { round, attestation }))
                .collect(),
            invalid,
        )
    }

    /// Checks if there are [Vote::Nullify] messages ready for batch verification.
    ///
    /// Verification is considered "ready" when all of the following are true:
    /// 1. There are pending nullify messages to verify.
    /// 2. We haven't already verified enough messages to reach M-quorum.
    /// 3. The sum of verified and pending messages could potentially reach M-quorum,
    ///    or the scheme doesn't benefit from batching (eager verification).
    pub fn ready_nullifies(&self) -> bool {
        // If there are no pending nullifies, there is nothing to do.
        if self.nullifies.is_empty() {
            return false;
        }

        // If we already have enough verified nullifies, stop.
        if self.nullifies_verified >= self.m_quorum {
            return false;
        }

        // For schemes that don't benefit from batching, verify immediately.
        if !S::is_batchable() {
            return true;
        }

        // If we don't have enough to reach M-quorum, there is nothing to do yet.
        if self.nullifies_verified + self.nullifies.len() < self.m_quorum {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        minimmit::scheme::{bls12381_multisig, bls12381_threshold, ed25519, secp256r1},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::PublicKey,
        sha256::Digest as Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, Faults, M5f1, N5f1};
    use rand::rngs::StdRng;

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256 {
        Sha256::from([v; 32])
    }

    // Helper to create a Notarize message for any signing scheme
    fn create_notarize<S: Scheme<Sha256>>(
        scheme: &S,
        round: Round,
        parent_view: View,
        payload_val: u8,
    ) -> Notarize<S, Sha256> {
        // Parent payload uses deterministic value based on parent view
        let parent_payload = sample_digest(parent_view.get() as u8);
        let proposal = Proposal::new(
            round,
            parent_view,
            parent_payload,
            sample_digest(payload_val),
        );
        Notarize::sign(scheme, proposal).unwrap()
    }

    fn create_notarize_with_parent<S: Scheme<Sha256>>(
        scheme: &S,
        round: Round,
        parent_view: View,
        parent_payload: Sha256,
        payload: Sha256,
    ) -> Notarize<S, Sha256> {
        let proposal = Proposal::new(round, parent_view, parent_payload, payload);
        Notarize::sign(scheme, proposal).unwrap()
    }

    // Helper to create a Nullify message for any signing scheme
    fn create_nullify<S: Scheme<Sha256>>(scheme: &S, round: Round) -> Nullify<S> {
        Nullify::sign::<Sha256>(scheme, round).unwrap()
    }

    fn add_notarize<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let n = 6; // Need n >= 5f+1, so for f=1, n=6
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, n);
        let m_quorum = M5f1::quorum(n);
        let l_quorum = N5f1::l_quorum(n);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum, l_quorum);

        let round = Round::new(Epoch::new(0), View::new(1));
        let notarize1 = create_notarize(&schemes[0], round, View::new(0), 1);
        let notarize2 = create_notarize(&schemes[1], round, View::new(0), 1);
        let notarize_diff = create_notarize(&schemes[2], round, View::new(0), 2);

        verifier.add(Vote::Notarize(notarize1.clone()), false);
        assert_eq!(verifier.notarizes.len(), 1);
        assert_eq!(verifier.notarizes_verified, 0);

        verifier.add(Vote::Notarize(notarize1.clone()), true);
        assert_eq!(verifier.notarizes.len(), 1);
        assert_eq!(verifier.notarizes_verified, 1);

        verifier.set_leader(notarize1.signer());
        assert!(verifier.leader_proposal.is_some());
        assert_eq!(
            verifier.leader_proposal.as_ref().unwrap(),
            &notarize1.proposal
        );
        assert_eq!(verifier.notarizes.len(), 1);

        verifier.add(Vote::Notarize(notarize2), false);
        assert_eq!(verifier.notarizes.len(), 2);

        // Different proposal should be tracked separately
        verifier.add(Vote::Notarize(notarize_diff), false);
        assert_eq!(verifier.notarizes.len(), 2);
        assert_eq!(verifier.conflicting_notarizes.len(), 1);

        // Test with leader set before receiving their vote
        let mut verifier2 = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum, l_quorum);
        let round2 = Round::new(Epoch::new(0), View::new(2));
        let notarize_non_leader = create_notarize(&schemes[1], round2, View::new(1), 3);
        let notarize_leader = create_notarize(&schemes[0], round2, View::new(1), 3);
        let notarize_third = create_notarize(&schemes[2], round2, View::new(1), 3);

        verifier2.set_leader(notarize_leader.signer());
        verifier2.add(Vote::Notarize(notarize_non_leader), false);
        assert!(verifier2.leader_proposal.is_none());
        assert_eq!(verifier2.notarizes.len(), 1);
        assert!(verifier2.conflicting_notarizes.is_empty());

        verifier2.add(Vote::Notarize(notarize_leader.clone()), false);
        assert!(verifier2.leader_proposal.is_some());
        assert_eq!(
            verifier2.leader_proposal.as_ref().unwrap(),
            &notarize_leader.proposal
        );
        assert_eq!(verifier2.notarizes.len(), 2);
        assert!(verifier2.conflicting_notarizes.is_empty());

        verifier2.add(Vote::Notarize(notarize_third), false);
        assert_eq!(verifier2.notarizes.len(), 3);

        // Leader votes are verified; proposals that match are verified together
        let (verified_bulk, failed_bulk) = verifier2.verify_notarizes(&mut rng, &Sequential);
        assert_eq!(verified_bulk.len(), m_quorum as usize);
        assert!(failed_bulk.is_empty());
        assert_eq!(verifier2.notarizes.len(), 0);
    }

    #[test]
    fn test_add_notarize() {
        add_notarize(bls12381_threshold::fixture::<MinSig, _>);
        add_notarize(bls12381_threshold::fixture::<MinPk, _>);
        add_notarize(bls12381_multisig::fixture::<MinSig, _>);
        add_notarize(bls12381_multisig::fixture::<MinPk, _>);
        add_notarize(ed25519::fixture);
        add_notarize(secp256r1::fixture);
    }

    fn same_payload_different_parent_not_marked_invalid<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let n = 6;
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, n);
        let m_quorum = M5f1::quorum(n);
        let l_quorum = N5f1::l_quorum(n);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum, l_quorum);

        let round = Round::new(Epoch::new(0), View::new(1));
        let payload = sample_digest(42);
        let proposal_a = create_notarize_with_parent(
            &schemes[0],
            round,
            View::new(0),
            sample_digest(0),
            payload,
        );
        let proposal_b = create_notarize_with_parent(
            &schemes[1],
            round,
            View::new(0),
            sample_digest(9),
            payload,
        );
        let proposal_c = create_notarize_with_parent(
            &schemes[2],
            round,
            View::new(0),
            sample_digest(0),
            payload,
        );

        verifier.set_leader(proposal_a.signer());
        verifier.add(Vote::Notarize(proposal_a), false);
        verifier.add(Vote::Notarize(proposal_b.clone()), false);
        verifier.add(Vote::Notarize(proposal_c), false);
        assert!(verifier.ready_notarizes());

        let (_verified, failed) = verifier.verify_notarizes(&mut rng, &Sequential);

        assert!(
            !failed.contains(&proposal_b.signer()),
            "a valid vote for a distinct proposal (same payload, different parent) must not be classified as invalid"
        );
    }

    #[test]
    fn test_same_payload_different_parent_not_marked_invalid() {
        same_payload_different_parent_not_marked_invalid(bls12381_threshold::fixture::<MinSig, _>);
        same_payload_different_parent_not_marked_invalid(bls12381_threshold::fixture::<MinPk, _>);
        same_payload_different_parent_not_marked_invalid(bls12381_multisig::fixture::<MinSig, _>);
        same_payload_different_parent_not_marked_invalid(bls12381_multisig::fixture::<MinPk, _>);
        same_payload_different_parent_not_marked_invalid(ed25519::fixture);
        same_payload_different_parent_not_marked_invalid(secp256r1::fixture);
    }

    fn conflicting_notarizes_are_verified<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let n = 6;
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, n);
        let m_quorum = M5f1::quorum(n);
        let l_quorum = N5f1::l_quorum(n);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum, l_quorum);

        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.add(Vote::Notarize(leader_vote.clone()), false);
        verifier.set_leader(leader_vote.signer());

        let leader_vote2 = create_notarize(&schemes[1], round, View::new(0), 1);
        let leader_vote3 = create_notarize(&schemes[2], round, View::new(0), 1);
        verifier.add(Vote::Notarize(leader_vote2), false);
        verifier.add(Vote::Notarize(leader_vote3), false);

        let conflict_vote = create_notarize(&schemes[3], round, View::new(0), 2);
        verifier.add(Vote::Notarize(conflict_vote.clone()), false);

        assert!(verifier.ready_notarizes());
        let (verified, failed) = verifier.verify_notarizes(&mut rng, &Sequential);
        assert!(failed.is_empty());
        assert!(verified.iter().any(|vote| match vote {
            Vote::Notarize(notarize) => notarize.proposal.payload == conflict_vote.proposal.payload,
            _ => false,
        }));
    }

    #[test]
    fn test_conflicting_notarizes_are_verified() {
        conflicting_notarizes_are_verified(bls12381_threshold::fixture::<MinSig, _>);
        conflicting_notarizes_are_verified(bls12381_threshold::fixture::<MinPk, _>);
        conflicting_notarizes_are_verified(bls12381_multisig::fixture::<MinSig, _>);
        conflicting_notarizes_are_verified(bls12381_multisig::fixture::<MinPk, _>);
        conflicting_notarizes_are_verified(ed25519::fixture);
        conflicting_notarizes_are_verified(secp256r1::fixture);
    }

    fn set_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let n = 6;
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, n);
        let m_quorum = M5f1::quorum(n);
        let l_quorum = N5f1::l_quorum(n);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum, l_quorum);

        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        let other_notarize = create_notarize(&schemes[1], round, View::new(0), 1);

        verifier.add(Vote::Notarize(other_notarize), false);
        assert_eq!(verifier.notarizes.len(), 1);

        let leader = leader_notarize.signer();
        verifier.set_leader(leader);
        assert_eq!(verifier.leader, Some(leader));
        assert!(verifier.leader_proposal.is_none());
        assert_eq!(verifier.notarizes.len(), 1);

        verifier.add(Vote::Notarize(leader_notarize.clone()), false);
        assert!(verifier.leader_proposal.is_some());
        assert_eq!(
            verifier.leader_proposal.as_ref().unwrap(),
            &leader_notarize.proposal
        );
        assert_eq!(verifier.notarizes.len(), 2);
    }

    #[test]
    fn test_set_leader() {
        set_leader(bls12381_threshold::fixture::<MinSig, _>);
        set_leader(bls12381_threshold::fixture::<MinPk, _>);
        set_leader(bls12381_multisig::fixture::<MinSig, _>);
        set_leader(bls12381_multisig::fixture::<MinPk, _>);
        set_leader(ed25519::fixture);
        set_leader(secp256r1::fixture);
    }

    fn ready_and_verify_notarizes<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let n = 6;
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, n);
        let m_quorum = M5f1::quorum(n);
        let l_quorum = N5f1::l_quorum(n);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum, l_quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| create_notarize(scheme, round, View::new(0), 1))
            .collect();

        assert!(!verifier.ready_notarizes());

        verifier.set_leader(notarizes[0].signer());
        verifier.add(Vote::Notarize(notarizes[0].clone()), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.ready_notarizes(), S::is_batchable());
        assert_eq!(verifier.notarizes.len(), 1);

        verifier.add(Vote::Notarize(notarizes[1].clone()), false);
        assert_eq!(!verifier.ready_notarizes(), S::is_batchable());
        verifier.add(Vote::Notarize(notarizes[2].clone()), false);
        // At m_quorum (3 for n=6), should be ready
        assert!(verifier.ready_notarizes());
        assert_eq!(verifier.notarizes.len(), 3);

        let (verified_bulk, failed_bulk) = verifier.verify_notarizes(&mut rng, &Sequential);
        assert_eq!(verified_bulk.len(), 3);
        assert!(failed_bulk.is_empty());
        assert_eq!(verifier.notarizes_verified, 3);
        assert!(verifier.notarizes.is_empty());
        assert!(!verifier.ready_notarizes()); // No more pending
    }

    #[test]
    fn test_ready_and_verify_notarizes() {
        ready_and_verify_notarizes(bls12381_threshold::fixture::<MinSig, _>);
        ready_and_verify_notarizes(bls12381_threshold::fixture::<MinPk, _>);
        ready_and_verify_notarizes(bls12381_multisig::fixture::<MinSig, _>);
        ready_and_verify_notarizes(bls12381_multisig::fixture::<MinPk, _>);
        ready_and_verify_notarizes(ed25519::fixture);
        ready_and_verify_notarizes(secp256r1::fixture);
    }

    fn add_nullify<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let n = 6;
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, n);
        let m_quorum = M5f1::quorum(n);
        let l_quorum = N5f1::l_quorum(n);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum, l_quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let nullify = create_nullify(&schemes[0], round);

        verifier.add(Vote::Nullify(nullify.clone()), false);
        assert_eq!(verifier.nullifies.len(), 1);
        assert_eq!(verifier.nullifies_verified, 0);

        verifier.add(Vote::Nullify(nullify), true);
        assert_eq!(verifier.nullifies.len(), 1);
        assert_eq!(verifier.nullifies_verified, 1);
    }

    #[test]
    fn test_add_nullify() {
        add_nullify(bls12381_threshold::fixture::<MinSig, _>);
        add_nullify(bls12381_threshold::fixture::<MinPk, _>);
        add_nullify(bls12381_multisig::fixture::<MinSig, _>);
        add_nullify(bls12381_multisig::fixture::<MinPk, _>);
        add_nullify(ed25519::fixture);
        add_nullify(secp256r1::fixture);
    }

    fn ready_and_verify_nullifies<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let n = 6;
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, n);
        let m_quorum = M5f1::quorum(n);
        let l_quorum = N5f1::l_quorum(n);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum, l_quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let nullifies: Vec<_> = schemes
            .iter()
            .map(|scheme| create_nullify(scheme, round))
            .collect();

        verifier.add(Vote::Nullify(nullifies[0].clone()), true);
        assert_eq!(verifier.nullifies_verified, 1);

        verifier.add(Vote::Nullify(nullifies[1].clone()), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.ready_nullifies(), S::is_batchable());
        verifier.add(Vote::Nullify(nullifies[2].clone()), false);
        // At m_quorum (3 for n=6), should be ready
        assert!(verifier.ready_nullifies());
        assert_eq!(verifier.nullifies.len(), 2);

        let (verified, failed) = verifier.verify_nullifies(&mut rng, &Sequential);
        assert_eq!(verified.len(), 2);
        assert!(failed.is_empty());
        assert_eq!(verifier.nullifies_verified, 3);
        assert!(verifier.nullifies.is_empty());
        assert!(!verifier.ready_nullifies());
    }

    #[test]
    fn test_ready_and_verify_nullifies() {
        ready_and_verify_nullifies(bls12381_threshold::fixture::<MinSig, _>);
        ready_and_verify_nullifies(bls12381_threshold::fixture::<MinPk, _>);
        ready_and_verify_nullifies(bls12381_multisig::fixture::<MinSig, _>);
        ready_and_verify_nullifies(bls12381_multisig::fixture::<MinPk, _>);
        ready_and_verify_nullifies(ed25519::fixture);
        ready_and_verify_nullifies(secp256r1::fixture);
    }

    fn set_leader_twice_panics<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let n = 6;
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, n);
        let m_quorum = M5f1::quorum(n);
        let l_quorum = N5f1::l_quorum(n);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum, l_quorum);
        verifier.set_leader(Participant::new(0));
        verifier.set_leader(Participant::new(1));
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_bls_threshold_minsig() {
        set_leader_twice_panics(bls12381_threshold::fixture::<MinSig, _>);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_bls_threshold_minpk() {
        set_leader_twice_panics(bls12381_threshold::fixture::<MinPk, _>);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_bls_multisig_minsig() {
        set_leader_twice_panics(bls12381_multisig::fixture::<MinSig, _>);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_bls_multisig_minpk() {
        set_leader_twice_panics(bls12381_multisig::fixture::<MinPk, _>);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_ed() {
        set_leader_twice_panics(ed25519::fixture);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_secp() {
        set_leader_twice_panics(secp256r1::fixture);
    }

    fn ready_notarizes_without_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let n = 6;
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, n);
        let m_quorum = M5f1::quorum(n);
        let l_quorum = N5f1::l_quorum(n);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum, l_quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        let notarizes: Vec<_> = schemes
            .iter()
            .take(m_quorum as usize)
            .map(|scheme| create_notarize(scheme, round, View::new(0), 1))
            .collect();

        for vote in notarizes.iter() {
            verifier.add(Vote::Notarize(vote.clone()), false);
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
        ready_notarizes_without_leader(bls12381_threshold::fixture::<MinSig, _>);
        ready_notarizes_without_leader(bls12381_threshold::fixture::<MinPk, _>);
        ready_notarizes_without_leader(bls12381_multisig::fixture::<MinSig, _>);
        ready_notarizes_without_leader(bls12381_multisig::fixture::<MinPk, _>);
        ready_notarizes_without_leader(ed25519::fixture);
        ready_notarizes_without_leader(secp256r1::fixture);
    }
}
