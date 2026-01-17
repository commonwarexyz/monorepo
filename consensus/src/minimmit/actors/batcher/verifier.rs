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
use std::collections::{BTreeMap, BTreeSet};

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

    /// Current leader index.
    leader: Option<Participant>,
    /// Proposal associated with the current leader.
    leader_proposal: Option<Proposal<D>>,

    /// Pending notarize votes waiting to be verified.
    notarizes: Vec<Notarize<S, D>>,
    /// Count of already-verified notarize votes.
    notarizes_verified: usize,

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
    pub const fn new(scheme: S, m_quorum: u32) -> Self {
        Self {
            scheme,
            m_quorum: m_quorum as usize,

            leader: None,
            leader_proposal: None,

            notarizes: Vec::new(),
            notarizes_verified: 0,

            nullifies: Vec::new(),
            nullifies_verified: 0,
        }
    }

    /// Records the leader's proposal when it becomes known.
    const fn set_leader_proposal(&mut self, proposal: Proposal<D>) {
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
                if self.leader_proposal.is_none() {
                    if let Some(leader) = self.leader {
                        if leader == notarize.signer() {
                            self.set_leader_proposal(notarize.proposal.clone());
                        }
                    }
                }

                // If we've made it this far, add the notarize
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

    /// Verifies a batch of pending [Vote::Notarize] messages.
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
        let notarizes = std::mem::take(&mut self.notarizes);

        // Early return if there are no notarizes to verify
        if notarizes.is_empty() {
            return (vec![], vec![]);
        }

        let leader_payload = match &self.leader_proposal {
            Some(proposal) => proposal.payload,
            None => return (vec![], vec![]),
        };

        let mut grouped: BTreeMap<Proposal<D>, Vec<Notarize<S, D>>> = BTreeMap::new();
        for notarize in notarizes {
            grouped
                .entry(notarize.proposal.clone())
                .or_default()
                .push(notarize);
        }

        let mut verified_votes = Vec::new();
        let mut invalid_signers = BTreeSet::new();

        for (proposal, votes) in grouped {
            if proposal.payload != leader_payload {
                self.notarizes.extend(votes);
                continue;
            }
            let attestations = votes.into_iter().map(|n| n.attestation);

            let Verification { verified, invalid } = self.scheme.verify_attestations::<_, D, _>(
                rng,
                Subject::Notarize {
                    proposal: &proposal,
                },
                attestations,
                strategy,
            );

            for signer in invalid {
                invalid_signers.insert(signer);
            }

            for attestation in verified {
                verified_votes.push(Vote::Notarize(Notarize {
                    proposal: proposal.clone(),
                    attestation,
                }));
            }
        }

        self.notarizes_verified += verified_votes.len();

        (verified_votes, invalid_signers.into_iter().collect())
    }

    /// Checks if there are [Vote::Notarize] messages ready for batch verification.
    ///
    /// Verification is considered "ready" when all of the following are true:
    /// 1. There are pending notarize messages to verify.
    /// 2. The leader and their proposal are known (so we know which proposal to verify for).
    /// 3. We haven't already verified enough messages to reach L-quorum.
    /// 4. The sum of verified and pending messages could potentially reach M-quorum,
    ///    or the scheme doesn't benefit from batching (eager verification).
    ///
    /// Note: We track up to L-quorum because notarize votes are used for both
    /// MNotarization (M-quorum) and Finalization (L-quorum).
    pub fn ready_notarizes(&self) -> bool {
        // If there are no pending notarizes, there is nothing to do.
        if self.notarizes.is_empty() {
            return false;
        }

        // If we don't yet know the leader, notarizes may contain messages for
        // a number of different proposals.
        if self.leader.is_none() || self.leader_proposal.is_none() {
            return false;
        }

        let leader_payload = self
            .leader_proposal
            .as_ref()
            .expect("leader proposal set")
            .payload;
        let leader_votes = self
            .notarizes
            .iter()
            .filter(|vote| vote.proposal.payload == leader_payload)
            .count();

        // For schemes that don't benefit from batching, verify immediately.
        if !S::is_batchable() {
            return leader_votes > 0;
        }

        // If we don't have enough leader votes to reach M-quorum, there is nothing to do yet.
        if self.notarizes_verified + leader_votes < self.m_quorum {
            return false;
        }

        true
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
        let nullifies = std::mem::take(&mut self.nullifies);

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
    use commonware_utils::{test_rng, Faults, M5f1};
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
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum);

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

        // Different proposal should still be tracked for contradiction handling
        verifier.add(Vote::Notarize(notarize_diff), false);
        assert_eq!(verifier.notarizes.len(), 3);

        // Test with leader set before receiving their vote
        let mut verifier2 = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum);
        let round2 = Round::new(Epoch::new(0), View::new(2));
        let notarize_non_leader = create_notarize(&schemes[1], round2, View::new(1), 3);
        let notarize_leader = create_notarize(&schemes[0], round2, View::new(1), 3);

        verifier2.set_leader(notarize_leader.signer());
        verifier2.add(Vote::Notarize(notarize_non_leader), false);
        assert!(verifier2.leader_proposal.is_none());
        assert_eq!(verifier2.notarizes.len(), 1);

        verifier2.add(Vote::Notarize(notarize_leader.clone()), false);
        assert!(verifier2.leader_proposal.is_some());
        assert_eq!(
            verifier2.leader_proposal.as_ref().unwrap(),
            &notarize_leader.proposal
        );
        assert_eq!(verifier2.notarizes.len(), 2);

        // Leader votes are verified; proposals that match are verified together
        let (verified_bulk, failed_bulk) = verifier2.verify_notarizes(&mut rng, &Sequential);
        assert_eq!(verified_bulk.len(), 2);
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

    fn set_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let n = 6;
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, n);
        let m_quorum = M5f1::quorum(n);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum);

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
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum);
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
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum);
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
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum);
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
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum);
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
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), m_quorum);
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
