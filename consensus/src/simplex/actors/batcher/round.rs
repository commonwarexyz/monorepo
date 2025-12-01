use super::BatchVerifier;
use crate::{
    simplex::{
        metrics::Inbound,
        signing_scheme::Scheme,
        types::{
            Activity, Attributable, ConflictingFinalize, ConflictingNotarize, Finalization,
            Notarization, Nullification, NullifyFinalize, Proposal, VoteTracker, Voter,
        },
    },
    Reporter,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_p2p::Blocker;
use commonware_utils::set::{Ordered, OrderedQuorum};
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand::{CryptoRng, Rng};
use tracing::warn;

/// Action to take after adding a vote to a round.
pub enum Action<D: Digest> {
    /// Vote was not added (duplicate, invalid, or certificate already exists).
    Skip,
    /// Vote was added and needs verification.
    Verify,
    /// Vote was added and this is the leader's first vote (forward proposal to voter).
    VerifyAndForward(Proposal<D>),
}

/// Per-view state for vote accumulation and certificate tracking.
pub struct Round<
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    participants: Ordered<P>,

    blocker: B,
    reporter: R,
    /// Verifier only attempts to recover a certificate from votes for the first proposal
    /// we see from a leader. If we are on the wrong side of an equivocation, the verifier
    /// will not produce anything of value (and we'll only participate by forwarding certificates).
    verifier: BatchVerifier<S, D>,
    /// Votes received from network (may not be verified yet).
    /// Used for duplicate detection and conflict reporting.
    pending_votes: VoteTracker<S, D>,
    /// Votes that have been verified through batch verification.
    /// Only these votes are used for certificate construction.
    verified_votes: VoteTracker<S, D>,

    /// Whether we've already received and forwarded the leader's proposal.
    proposal_sent: bool,

    /// Cached certificates for this view.
    /// Once a certificate exists, we stop accumulating votes of that type.
    notarization: Option<Notarization<S, D>>,
    nullification: Option<Nullification<S>>,
    finalization: Option<Finalization<S, D>>,

    inbound_messages: Family<Inbound, Counter>,
}

impl<
        P: PublicKey,
        S: Scheme<PublicKey = P>,
        B: Blocker<PublicKey = P>,
        D: Digest,
        R: Reporter<Activity = Activity<S, D>>,
    > Round<P, S, B, D, R>
{
    pub fn new(
        participants: Ordered<P>,
        scheme: S,
        blocker: B,
        reporter: R,
        inbound_messages: Family<Inbound, Counter>,
        batch: bool,
    ) -> Self {
        // Configure quorum params
        let quorum = if batch {
            Some(participants.quorum())
        } else {
            None
        };

        let len = participants.len();
        // Initialize data structures
        Self {
            participants,

            blocker,
            reporter,
            verifier: BatchVerifier::new(scheme, quorum),

            pending_votes: VoteTracker::new(len),
            verified_votes: VoteTracker::new(len),

            proposal_sent: false,

            notarization: None,
            nullification: None,
            finalization: None,

            inbound_messages,
        }
    }

    /// Returns true if we already have a notarization certificate for this view.
    pub fn has_notarization(&self) -> bool {
        self.notarization.is_some()
    }

    /// Returns true if we already have a nullification certificate for this view.
    pub fn has_nullification(&self) -> bool {
        self.nullification.is_some()
    }

    /// Returns true if we already have a finalization certificate for this view.
    pub fn has_finalization(&self) -> bool {
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
    pub async fn add_network(&mut self, sender: P, message: Voter<S, D>, leader: u32) -> Action<D> {
        // Check if sender is a participant
        let Some(index) = self.participants.index(&sender) else {
            warn!(?sender, "blocking peer");
            self.blocker.block(sender).await;
            return Action::Skip;
        };

        // Attempt to reserve
        match message {
            Voter::Notarize(notarize) => {
                // Update metrics
                self.inbound_messages
                    .get_or_create(&Inbound::notarize(&sender))
                    .inc();

                // Skip if we already have a notarization or finalization certificate
                if self.has_notarization() || self.has_finalization() {
                    return Action::Skip;
                }

                // Verify sender is signer
                if index != notarize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return Action::Skip;
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
                        Action::Skip
                    }
                    None => {
                        // Check if this is the leader's first notarize vote
                        let is_leader_proposal = index == leader && !self.proposal_sent;
                        let action = if is_leader_proposal {
                            self.proposal_sent = true;
                            Action::VerifyAndForward(notarize.proposal.clone())
                        } else {
                            Action::Verify
                        };

                        self.reporter
                            .report(Activity::Notarize(notarize.clone()))
                            .await;
                        self.pending_votes.insert_notarize(notarize.clone());
                        self.verifier.add(Voter::Notarize(notarize), false);

                        action
                    }
                }
            }
            Voter::Nullify(nullify) => {
                // Update metrics
                self.inbound_messages
                    .get_or_create(&Inbound::nullify(&sender))
                    .inc();

                // Skip if we already have a nullification certificate
                if self.has_nullification() {
                    return Action::Skip;
                }

                // Verify sender is signer
                if index != nullify.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return Action::Skip;
                }

                // Check if finalized
                if let Some(previous) = self.pending_votes.finalize(index) {
                    let activity = NullifyFinalize::new(nullify, previous.clone());
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return Action::Skip;
                }

                // Try to reserve
                match self.pending_votes.nullify(index) {
                    Some(previous) => {
                        if previous != &nullify {
                            warn!(?sender, "blocking peer");
                            self.blocker.block(sender).await;
                        }
                        Action::Skip
                    }
                    None => {
                        self.reporter
                            .report(Activity::Nullify(nullify.clone()))
                            .await;
                        self.pending_votes.insert_nullify(nullify.clone());
                        self.verifier.add(Voter::Nullify(nullify), false);
                        Action::Verify
                    }
                }
            }
            Voter::Finalize(finalize) => {
                // Update metrics
                self.inbound_messages
                    .get_or_create(&Inbound::finalize(&sender))
                    .inc();

                // Skip if we already have a finalization certificate
                if self.has_finalization() {
                    return Action::Skip;
                }

                // Verify sender is signer
                if index != finalize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return Action::Skip;
                }

                // Check if nullified
                if let Some(previous) = self.pending_votes.nullify(index) {
                    let activity = NullifyFinalize::new(previous.clone(), finalize);
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return Action::Skip;
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
                        Action::Skip
                    }
                    None => {
                        // Check if this is the leader's first finalize vote
                        let is_leader_proposal = index == leader && !self.proposal_sent;
                        let action = if is_leader_proposal {
                            self.proposal_sent = true;
                            Action::VerifyAndForward(finalize.proposal.clone())
                        } else {
                            Action::Verify
                        };

                        self.reporter
                            .report(Activity::Finalize(finalize.clone()))
                            .await;
                        self.pending_votes.insert_finalize(finalize.clone());
                        self.verifier.add(Voter::Finalize(finalize), false);
                        action
                    }
                }
            }
            Voter::Notarization(_) | Voter::Finalization(_) | Voter::Nullification(_) => {
                // Certificates should be handled separately, not through add()
                warn!(
                    ?sender,
                    "blocking peer for sending certificate on vote channel"
                );
                self.blocker.block(sender).await;
                Action::Skip
            }
        }
    }

    /// Adds a vote that we constructed ourselves to the verifier.
    ///
    /// Returns true if the vote was added (may be needed for quorum).
    /// Skips votes if we already have the corresponding certificate.
    pub async fn add_constructed(&mut self, message: Voter<S, D>) -> bool {
        match &message {
            Voter::Notarize(notarize) => {
                // Skip if we already have a notarization or finalization certificate
                if self.has_notarization() || self.has_finalization() {
                    return false;
                }
                self.reporter
                    .report(Activity::Notarize(notarize.clone()))
                    .await;
                self.pending_votes.insert_notarize(notarize.clone());
                // Our own votes are already verified
                self.verified_votes.insert_notarize(notarize.clone());
            }
            Voter::Nullify(nullify) => {
                // Skip if we already have a nullification certificate
                if self.has_nullification() {
                    return false;
                }
                self.reporter
                    .report(Activity::Nullify(nullify.clone()))
                    .await;
                self.pending_votes.insert_nullify(nullify.clone());
                // Our own votes are already verified
                self.verified_votes.insert_nullify(nullify.clone());
            }
            Voter::Finalize(finalize) => {
                // Skip if we already have a finalization certificate
                if self.has_finalization() {
                    return false;
                }
                self.reporter
                    .report(Activity::Finalize(finalize.clone()))
                    .await;
                self.pending_votes.insert_finalize(finalize.clone());
                // Our own votes are already verified
                self.verified_votes.insert_finalize(finalize.clone());
            }
            Voter::Notarization(_) | Voter::Finalization(_) | Voter::Nullification(_) => {
                unreachable!("certificates should not be sent via add_constructed");
            }
        }
        self.verifier.add(message, true);
        true
    }

    pub fn set_leader(&mut self, leader: u32) {
        self.verifier.set_leader(leader);
    }

    pub fn ready_notarizes(&self) -> bool {
        // Don't bother verifying if we already have a certificate
        if self.has_notarization() || self.has_finalization() {
            return false;
        }
        self.verifier.ready_notarizes()
    }

    pub fn verify_notarizes<E: Rng + CryptoRng>(
        &mut self,
        rng: &mut E,
        namespace: &[u8],
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        self.verifier.verify_notarizes(rng, namespace)
    }

    pub fn ready_nullifies(&self) -> bool {
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
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        self.verifier.verify_nullifies(rng, namespace)
    }

    pub fn ready_finalizes(&self) -> bool {
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
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        self.verifier.verify_finalizes(rng, namespace)
    }

    pub fn is_active(&self, leader: u32) -> Option<bool> {
        Some(self.pending_votes.has_notarize(leader) || self.pending_votes.has_nullify(leader))
    }

    /// Stores a verified vote for certificate construction.
    pub fn add_recovered(&mut self, vote: Voter<S, D>) {
        match vote {
            Voter::Notarize(n) => {
                self.verified_votes.insert_notarize(n);
            }
            Voter::Nullify(n) => {
                self.verified_votes.insert_nullify(n);
            }
            Voter::Finalize(f) => {
                self.verified_votes.insert_finalize(f);
            }
            _ => {}
        }
    }

    /// Attempts to construct a notarization certificate from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    pub fn try_construct_notarization(&mut self, scheme: &S) -> Option<Notarization<S, D>> {
        if self.has_notarization() || self.has_finalization() {
            return None;
        }
        let quorum = self.participants.quorum() as usize;
        if self.verified_votes.len_notarizes() < quorum {
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
        let quorum = self.participants.quorum() as usize;
        if self.verified_votes.len_nullifies() < quorum {
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
        let quorum = self.participants.quorum() as usize;
        if self.verified_votes.len_finalizes() < quorum {
            return None;
        }
        let finalization =
            Finalization::from_finalizes(scheme, self.verified_votes.iter_finalizes())?;
        self.set_finalization(finalization.clone());
        Some(finalization)
    }
}
