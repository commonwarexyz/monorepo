use super::Verifier;
use crate::{
    simplex::{
        scheme::Scheme,
        types::{
            Activity, Attributable, ConflictingFinalize, ConflictingNotarize, Finalization,
            Notarization, Nullification, NullifyFinalize, Proposal, Vote, VoteTracker,
        },
    },
    Reporter,
};
use commonware_cryptography::Digest;
use commonware_p2p::Blocker;
use commonware_utils::ordered::{Quorum, Set};
use rand::{CryptoRng, Rng};
use tracing::warn;

/// Per-view state for vote accumulation and certificate tracking.
pub struct Round<
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    participants: Set<S::PublicKey>,

    blocker: B,
    reporter: R,
    /// Verifier only attempts to recover a certificate from votes for the first proposal
    /// we see from a leader. If we are on the wrong side of an equivocation, the verifier
    /// will not produce anything of value (and we'll only participate by forwarding certificates).
    verifier: Verifier<S, D>,
    /// Votes received from network (may not be verified yet).
    /// Used for duplicate detection and conflict reporting.
    pending_votes: VoteTracker<S, D>,
    /// Votes that have been verified through batch verification.
    /// Only these votes are used for certificate construction.
    verified_votes: VoteTracker<S, D>,

    /// Whether we've already received and forwarded the leader's proposal.
    proposal_sent: bool,

    /// Cached certificates for this view.
    /// Once a certificate exists, we stop verifying votes of that type.
    notarization: Option<Notarization<S, D>>,
    nullification: Option<Nullification<S>>,
    finalization: Option<Finalization<S, D>>,
}

impl<
        S: Scheme<D>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
        R: Reporter<Activity = Activity<S, D>>,
    > Round<S, B, D, R>
{
    pub fn new(participants: Set<S::PublicKey>, scheme: S, blocker: B, reporter: R) -> Self {
        let quorum = participants.quorum();
        let len = participants.len();
        Self {
            participants,

            blocker,
            reporter,
            verifier: Verifier::new(scheme, quorum),

            pending_votes: VoteTracker::new(len),
            verified_votes: VoteTracker::new(len),

            proposal_sent: false,

            notarization: None,
            nullification: None,
            finalization: None,
        }
    }

    /// Returns true if we already have a notarization certificate for this view.
    pub const fn has_notarization(&self) -> bool {
        self.notarization.is_some()
    }

    /// Returns true if we already have a nullification certificate for this view.
    pub const fn has_nullification(&self) -> bool {
        self.nullification.is_some()
    }

    /// Returns true if we already have a finalization certificate for this view.
    pub const fn has_finalization(&self) -> bool {
        self.finalization.is_some()
    }

    /// Stores a notarization certificate.
    pub fn set_notarization(&mut self, notarization: Notarization<S, D>) {
        self.notarization = Some(notarization);
    }

    /// Stores a nullification certificate.
    pub fn set_nullification(&mut self, nullification: Nullification<S>) {
        self.nullification = Some(nullification);
    }

    /// Stores a finalization certificate.
    pub fn set_finalization(&mut self, finalization: Finalization<S, D>) {
        self.finalization = Some(finalization);
    }

    /// Adds a vote from the network to this round's verifier.
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
                            let activity = ConflictingNotarize::new(previous.clone(), notarize);
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
                        self.verifier.add(Vote::Notarize(notarize), false);
                        true
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

                // Check if finalized
                if let Some(previous) = self.pending_votes.finalize(index) {
                    let activity = NullifyFinalize::new(nullify, previous.clone());
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
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
                        self.verifier.add(Vote::Nullify(nullify), false);
                        true
                    }
                }
            }
            Vote::Finalize(finalize) => {
                // Verify sender is signer
                if index != finalize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Check if nullified
                if let Some(previous) = self.pending_votes.nullify(index) {
                    let activity = NullifyFinalize::new(previous.clone(), finalize);
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Try to reserve
                match self.pending_votes.finalize(index) {
                    Some(previous) => {
                        if previous != &finalize {
                            let activity = ConflictingFinalize::new(previous.clone(), finalize);
                            self.reporter
                                .report(Activity::ConflictingFinalize(activity))
                                .await;
                            warn!(?sender, "blocking peer");
                            self.blocker.block(sender).await;
                        }
                        false
                    }
                    None => {
                        self.reporter
                            .report(Activity::Finalize(finalize.clone()))
                            .await;
                        self.pending_votes.insert_finalize(finalize.clone());
                        self.verifier.add(Vote::Finalize(finalize), false);
                        true
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
            Vote::Finalize(finalize) => {
                // Report activity
                self.reporter
                    .report(Activity::Finalize(finalize.clone()))
                    .await;

                // Our own votes are already verified
                assert!(
                    self.pending_votes.insert_finalize(finalize.clone()),
                    "duplicate finalize"
                );
            }
        }

        // Only add to verified_votes if the verifier accepts the vote.
        // The verifier may reject votes for a different proposal than the leader's.
        if self.verifier.add(message.clone(), true) {
            self.add_verified(message);
        }
    }

    /// Sets the leader for this view. If the leader's vote has already been
    /// received, this will also set the leader's proposal (filtering out votes
    /// for other proposals).
    pub fn set_leader(&mut self, leader: u32) {
        self.verifier.set_leader(leader);
    }

    /// Returns the leader's proposal to forward to the voter, if:
    /// 1. We haven't already processed this (called at most once per round).
    /// 2. The leader's proposal is known.
    /// 3. We are not the leader (leaders don't need to forward their own proposal).
    pub fn forward_proposal(&mut self, me: u32) -> Option<Proposal<D>> {
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

    pub const fn ready_notarizes(&self) -> bool {
        // Don't bother verifying if we already have a certificate
        if self.has_notarization() {
            return false;
        }
        self.verifier.ready_notarizes()
    }

    pub fn verify_notarizes<E: Rng + CryptoRng>(
        &mut self,
        rng: &mut E,
        namespace: &[u8],
    ) -> (Vec<Vote<S, D>>, Vec<u32>) {
        self.verifier.verify_notarizes(rng, namespace)
    }

    pub const fn ready_nullifies(&self) -> bool {
        // Don't bother verifying if we already have a certificate
        if self.has_nullification() {
            return false;
        }
        self.verifier.ready_nullifies()
    }

    pub fn verify_nullifies<E: Rng + CryptoRng>(
        &mut self,
        rng: &mut E,
        namespace: &[u8],
    ) -> (Vec<Vote<S, D>>, Vec<u32>) {
        self.verifier.verify_nullifies(rng, namespace)
    }

    pub const fn ready_finalizes(&self) -> bool {
        // Don't bother verifying if we already have a certificate
        if self.has_finalization() {
            return false;
        }
        self.verifier.ready_finalizes()
    }

    pub fn verify_finalizes<E: Rng + CryptoRng>(
        &mut self,
        rng: &mut E,
        namespace: &[u8],
    ) -> (Vec<Vote<S, D>>, Vec<u32>) {
        self.verifier.verify_finalizes(rng, namespace)
    }

    pub fn is_active(&self, leader: u32) -> bool {
        self.pending_votes.has_notarize(leader)
            || self.pending_votes.has_nullify(leader)
            || self.pending_votes.has_finalize(leader)
    }

    /// Stores a verified vote for certificate construction.
    pub fn add_verified(&mut self, vote: Vote<S, D>) {
        match vote {
            Vote::Notarize(n) => {
                self.verified_votes.insert_notarize(n);
            }
            Vote::Nullify(n) => {
                self.verified_votes.insert_nullify(n);
            }
            Vote::Finalize(f) => {
                self.verified_votes.insert_finalize(f);
            }
        }
    }

    /// Attempts to construct a notarization certificate from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    pub fn try_construct_notarization(&mut self, scheme: &S) -> Option<Notarization<S, D>> {
        if self.has_notarization() {
            return None;
        }
        if self.verified_votes.len_notarizes() < self.participants.quorum() {
            return None;
        }
        let notarization =
            Notarization::from_notarizes(scheme, self.verified_votes.iter_notarizes())?;
        self.set_notarization(notarization.clone());
        Some(notarization)
    }

    /// Attempts to construct a nullification certificate from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    pub fn try_construct_nullification(&mut self, scheme: &S) -> Option<Nullification<S>> {
        if self.has_nullification() {
            return None;
        }
        if self.verified_votes.len_nullifies() < self.participants.quorum() {
            return None;
        }
        let nullification =
            Nullification::from_nullifies(scheme, self.verified_votes.iter_nullifies())?;
        self.set_nullification(nullification.clone());
        Some(nullification)
    }

    /// Attempts to construct a finalization certificate from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    pub fn try_construct_finalization(&mut self, scheme: &S) -> Option<Finalization<S, D>> {
        if self.has_finalization() {
            return None;
        }
        if self.verified_votes.len_finalizes() < self.participants.quorum() {
            return None;
        }
        let finalization =
            Finalization::from_finalizes(scheme, self.verified_votes.iter_finalizes())?;
        self.set_finalization(finalization.clone());
        Some(finalization)
    }
}
