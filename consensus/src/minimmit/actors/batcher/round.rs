//! Per-view state for vote tracking and verification.
//!
//! Each round tracks votes for a single view, handling duplicate detection,
//! conflict reporting, and batch verification. Certificate construction is
//! delegated to the state machine.

use super::Verifier;
use crate::{
    minimmit::{
        scheme::Scheme,
        types::{
            Activity, Attributable, Certificate, ConflictingNotarize, Proposal, Vote, VoteTracker,
        },
    },
    types::Participant,
    Reporter,
};
use commonware_cryptography::Digest;
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_utils::{
    ordered::{Quorum, Set},
    M5f1, N5f1,
};
use rand_core::CryptoRngCore;
use std::collections::BTreeSet;
use tracing::warn;

/// Per-view state for vote tracking and verification.
///
/// Unlike Simplex, certificate construction is delegated to the state machine.
/// The batcher's role is to batch-verify signatures and forward verified votes.
pub struct Round<S, B, D, R>
where
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
{
    participants: Set<S::PublicKey>,

    blocker: B,
    reporter: R,

    /// Verifier handles batch signature verification.
    verifier: Verifier<S, D>,

    /// Votes received from network (may not be verified yet).
    /// Used for duplicate detection and conflict reporting.
    pending_votes: VoteTracker<S, D>,

    /// Whether we've already received and forwarded the leader's proposal.
    proposal_sent: bool,

    /// Cached certificate flags to avoid re-forwarding.
    /// For M-notarizations, we track the full proposal since multiple
    /// proposals may share a payload in Minimmit.
    m_notarization_proposals: BTreeSet<Proposal<D>>,
    has_nullification: bool,
    has_finalization: bool,
}

impl<S, B, D, R> Round<S, B, D, R>
where
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
{
    pub fn new(participants: Set<S::PublicKey>, scheme: S, blocker: B, reporter: R) -> Self {
        let m_quorum = participants.quorum::<M5f1>();
        let l_quorum = N5f1::l_quorum(participants.len());
        let len = participants.len();
        Self {
            participants,

            blocker,
            reporter,
            verifier: Verifier::new(scheme, m_quorum, l_quorum),

            pending_votes: VoteTracker::new(len),

            proposal_sent: false,

            m_notarization_proposals: BTreeSet::new(),
            has_nullification: false,
            has_finalization: false,
        }
    }

    /// Returns true if we already have an M-notarization certificate for the proposal.
    pub fn has_m_notarization(&self, proposal: &Proposal<D>) -> bool {
        self.m_notarization_proposals.contains(proposal)
    }

    /// Returns true if we already have a nullification certificate for this view.
    pub const fn has_nullification(&self) -> bool {
        self.has_nullification
    }

    /// Returns true if we already have a finalization certificate for this view.
    pub const fn has_finalization(&self) -> bool {
        self.has_finalization
    }

    /// Adds a vote from the network to this round's verifier.
    ///
    /// Returns true if the vote was accepted (not a duplicate).
    pub async fn add_network(&mut self, sender: S::PublicKey, message: Vote<S, D>) -> bool {
        // Check if sender is a participant
        let Some(index) = self.participants.index(&sender) else {
            warn!(?sender, "blocking peer");
            self.blocker.block(sender).await;
            return false;
        };

        // Attempt to reserve
        match message {
            Vote::Notarize(notarize) => {
                // Verify sender is signer
                if index != notarize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Try to reserve
                match self.pending_votes.notarize(index) {
                    Some(previous) => {
                        if previous != &notarize {
                            let activity = ConflictingNotarize {
                                first: previous.clone(),
                                second: notarize.clone(),
                            };
                            self.reporter
                                .report(Activity::ConflictingNotarize(activity))
                                .await;
                            warn!(?sender, "blocking peer");
                            self.blocker.block(sender).await;
                        }
                        false
                    }
                    None => {
                        self.reporter
                            .report(Activity::Notarize(notarize.clone()))
                            .await;
                        self.pending_votes.insert_notarize(notarize.clone());
                        self.verifier.add(Vote::Notarize(notarize), false)
                    }
                }
            }
            Vote::Nullify(nullify) => {
                // Verify sender is signer
                if index != nullify.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Try to reserve
                match self.pending_votes.nullify(index) {
                    Some(previous) => {
                        if previous != &nullify {
                            warn!(?sender, "blocking peer");
                            self.blocker.block(sender).await;
                        }
                        false
                    }
                    None => {
                        self.reporter
                            .report(Activity::Nullify(nullify.clone()))
                            .await;
                        self.pending_votes.insert_nullify(nullify.clone());
                        self.verifier.add(Vote::Nullify(nullify), false)
                    }
                }
            }
        }
    }

    /// Adds a vote that we constructed ourselves to the verifier.
    pub async fn add_constructed(&mut self, message: Vote<S, D>) {
        match &message {
            Vote::Notarize(notarize) => {
                // Report activity
                self.reporter
                    .report(Activity::Notarize(notarize.clone()))
                    .await;

                // Our own votes are already verified
                assert!(
                    self.pending_votes.insert_notarize(notarize.clone()),
                    "duplicate notarize"
                );
            }
            Vote::Nullify(nullify) => {
                // Report activity
                self.reporter
                    .report(Activity::Nullify(nullify.clone()))
                    .await;

                // Our own votes are already verified
                assert!(
                    self.pending_votes.insert_nullify(nullify.clone()),
                    "duplicate nullify"
                );
            }
        }

        // Add to verifier as already verified
        self.verifier.add(message, true);
    }

    /// Sets the leader for this view.
    pub fn set_leader(&mut self, leader: Participant) {
        self.verifier.set_leader(leader);
    }

    /// Marks that M-quorum was reached for this view.
    ///
    /// Called when an MNotarization certificate exists (either newly created or
    /// recovered from journal). This allows batching toward L-quorum even after
    /// crash recovery where the verified vote count is lost.
    pub const fn mark_m_quorum_reached(&mut self) {
        self.verifier.mark_m_quorum_reached();
    }

    /// Returns the leader's proposal to forward to the voter, if:
    /// 1. We haven't already processed this (called at most once per round).
    /// 2. The leader's proposal is known.
    /// 3. We are not the leader (leaders don't need to forward their own proposal).
    pub fn forward_proposal(&mut self, me: Participant) -> Option<Proposal<D>> {
        if self.proposal_sent {
            return None;
        }
        let (leader, proposal) = self.verifier.get_leader_proposal()?;
        self.proposal_sent = true;
        if leader == me {
            return None;
        }
        Some(proposal)
    }

    pub fn ready_notarizes(&self) -> bool {
        self.verifier.ready_notarizes()
    }

    pub fn verify_notarizes<E: CryptoRngCore>(
        &mut self,
        rng: &mut E,
        strategy: &impl Strategy,
    ) -> (Vec<Vote<S, D>>, Vec<Participant>) {
        self.verifier.verify_notarizes(rng, strategy)
    }

    pub fn ready_nullifies(&self) -> bool {
        self.verifier.ready_nullifies()
    }

    pub fn verify_nullifies<E: CryptoRngCore>(
        &mut self,
        rng: &mut E,
        strategy: &impl Strategy,
    ) -> (Vec<Vote<S, D>>, Vec<Participant>) {
        self.verifier.verify_nullifies(rng, strategy)
    }

    /// Returns true if the leader was active in this round.
    ///
    /// We use pending votes to determine activeness because we only verify the first
    /// quorum of votes. If we used verified, we would always consider the slowest peers offline.
    pub fn is_active(&self, leader: Participant) -> bool {
        self.pending_votes.has_notarize(leader) || self.pending_votes.has_nullify(leader)
    }

    /// Marks a certificate as received to avoid duplicate forwarding.
    pub fn mark_certificate(&mut self, certificate: &Certificate<S, D>) {
        match certificate {
            Certificate::MNotarization(m) => {
                self.m_notarization_proposals.insert(m.proposal.clone());
            }
            Certificate::Nullification(_) => {
                self.has_nullification = true;
            }
            Certificate::Finalization(_) => {
                self.has_finalization = true;
            }
        }
    }
}
