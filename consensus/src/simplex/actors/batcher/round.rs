use super::{Verifier, verifier::ProposalState};
use crate::{
    Reporter,
    simplex::{
        actors::span::ViewSpan,
        scheme::Scheme,
        types::{
            Activity, Attributable, Certificate, ConflictingFinalize, ConflictingNotarize, Kind,
            NullifyFinalize, Proposal, Vote, VoteTracker,
        },
    },
    types::{Participant, Round as Rnd},
};
use commonware_cryptography::Digest;
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_utils::{N3f1, ordered::Quorum};
use rand_core::CryptoRng;
use std::sync::Arc;
use tracing::Span;

/// Per-view state for vote accumulation and certificate tracking.
pub struct Round<
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    blocker: B,
    reporter: R,
    /// The verifier attempts to recover notarizations and finalizations only
    /// from votes for one proposal. It initially filters to the first proposal
    /// observed from the known leader. Independently authenticated proposal
    /// evidence is authoritative and switches the filter.
    verifier: Verifier<S, D>,
    /// At most one vote of each kind per signer.
    ///
    /// Includes locally constructed votes and network votes that may not be
    /// verified. Used for duplicate detection, conflict reporting, and
    /// proposal-switch recovery.
    votes: VoteTracker<S, D>,
    /// Whether to retain full votes for conflict evidence after certification.
    report_conflicting_votes: bool,

    /// Whether we've already sent the selected proposal to the voter.
    proposal_sent: bool,

    /// Root span of the view, shared with the voter's round.
    ///
    /// Pending until the voter announces the view via an update.
    span: ViewSpan,
}

impl<
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> Round<S, B, D, R>
{
    pub fn new(
        round: Rnd,
        scheme: Arc<S>,
        blocker: B,
        reporter: R,
        report_conflicting_votes: bool,
    ) -> Self {
        let quorum = scheme.participants().quorum::<N3f1>();
        let len = scheme.participants().len();
        Self {
            blocker,
            reporter,
            verifier: Verifier::new(round, scheme, quorum),

            votes: VoteTracker::new(len),
            report_conflicting_votes,

            proposal_sent: false,

            span: ViewSpan::new(),
        }
    }

    /// Returns the root span of the view.
    pub fn span(&self) -> Span {
        self.span.get()
    }

    /// Adopts the root span of the view from the voter.
    pub fn set_span(&mut self, span: Span) {
        self.span.adopt(span);
    }

    /// Closes the view's root span once the view is decided.
    ///
    /// The round is retained until it is no longer interesting, but its work no
    /// longer anchors a trace.
    pub fn close_span(&mut self) {
        self.span.close();
    }

    /// Returns true if we already have a certificate of `kind` for this view.
    pub const fn has_certificate(&self, kind: Kind) -> bool {
        self.verifier.has_certificate(kind)
    }

    /// Records a verified certificate.
    ///
    /// The first notarization or finalization establishes an authoritative
    /// proposal and may replace one learned from the leader's vote. Returns
    /// `true` when a notarization selects a new proposal, making its buffered
    /// finalize votes eligible for processing.
    pub fn record_certificate(&mut self, certificate: &Certificate<S, D>) -> bool {
        let process_votes = match certificate {
            Certificate::Notarization(notarization) => {
                self.set_authoritative_proposal(&notarization.proposal)
            }
            Certificate::Finalization(finalization) => {
                // A finalization may replace the leader-selected proposal, but its
                // certificate makes reprocessing buffered finalize votes unnecessary.
                self.verifier
                    .set_proposal(ProposalState::Certificate(finalization.proposal.clone()));
                false
            }
            Certificate::Nullification(_) => false,
        };
        self.verifier.record_certificate(certificate.kind());
        self.release_votes(certificate.kind());
        process_votes
    }

    /// Releases full votes that are no longer needed for certificate assembly.
    fn release_votes(&mut self, kind: Kind) {
        if self.report_conflicting_votes {
            return;
        }

        match kind {
            Kind::Notarization => {
                let proposal = self
                    .verifier
                    .proposal()
                    .expect("notarization must establish a proposal");
                self.votes.release_notarizes(proposal);
            }
            Kind::Nullification => self.votes.release_nullifies(),
            Kind::Finalization => {
                let proposal = self
                    .verifier
                    .proposal()
                    .expect("finalization must establish a proposal");
                self.votes.release_finalizes(proposal);
            }
        }
    }

    /// Makes an independently authenticated proposal authoritative, restoring
    /// finalize votes filtered by a conflicting leader proposal.
    ///
    /// Returns whether the selected proposal changed.
    fn set_authoritative_proposal(&mut self, proposal: &Proposal<D>) -> bool {
        let update = self
            .verifier
            .set_proposal(ProposalState::Certificate(proposal.clone()));
        if update.replaced {
            // Matching tracked finalizes are unverified network votes: the conflicting
            // leader proposal filtered them, while constructed finalizes establish the
            // proposal before entering the tracker.
            for finalize in self
                .votes
                .iter_finalizes()
                .filter(|finalize| &finalize.proposal == proposal)
            {
                self.verifier.add(Vote::Finalize(finalize.clone()), false);
            }
        }
        update.changed
    }

    /// Adds a vote from the network to this round's verifier.
    pub fn add_network(&mut self, sender: S::PublicKey, message: Vote<S, D>) -> bool {
        // Check if sender is a participant
        let Some(index) = self.verifier.participants().index(&sender) else {
            commonware_p2p::block!(self.blocker, sender, "unknown participant");
            return false;
        };

        // Attempt to reserve
        match message {
            Vote::Notarize(notarize) => {
                // Verify sender is signer
                if index != notarize.signer() {
                    commonware_p2p::block!(self.blocker, sender, "notarize signer mismatch");
                    return false;
                }

                // Once certified, the vote is useful only for activity and
                // proposal-forwarding hints unless conflict checking is enabled.
                if !self.report_conflicting_votes && self.has_certificate(Kind::Notarization) {
                    let matching = self.verifier.proposal() == Some(&notarize.proposal);
                    if !self.votes.remember_notarize(index, matching) {
                        return false;
                    }
                    self.reporter.report(Activity::Notarize(notarize));
                    return true;
                }

                // Try to reserve
                match (self.report_conflicting_votes, self.votes.notarize(index)) {
                    (true, Some(previous)) if previous.proposal != notarize.proposal => {
                        let activity = ConflictingNotarize::new(previous.clone(), notarize);
                        self.reporter
                            .report(Activity::ConflictingNotarize(activity));
                        commonware_p2p::block!(self.blocker, sender, "conflicting notarize");
                        false
                    }
                    (true, Some(previous)) if previous != &notarize => {
                        commonware_p2p::block!(self.blocker, sender, "invalid signature");
                        false
                    }
                    (_, Some(_)) => false,
                    (_, None) => {
                        self.reporter.report(Activity::Notarize(notarize.clone()));
                        self.votes.insert_notarize(notarize.clone());
                        self.verifier.add(Vote::Notarize(notarize), false);
                        true
                    }
                }
            }
            Vote::Nullify(nullify) => {
                // Verify sender is signer
                if index != nullify.signer() {
                    commonware_p2p::block!(self.blocker, sender, "nullify signer mismatch");
                    return false;
                }

                // Once certified, retain only the signer for duplicate suppression.
                // The full vote is only needed when conflict reporting is enabled.
                if !self.report_conflicting_votes && self.has_certificate(Kind::Nullification) {
                    if !self.votes.remember_nullify(index) {
                        return false;
                    }
                    self.reporter.report(Activity::Nullify(nullify));
                    return true;
                }

                // Check if finalized
                if self.report_conflicting_votes
                    && let Some(previous) = self.votes.finalize(index)
                {
                    let activity = NullifyFinalize::new(nullify, previous.clone());
                    self.reporter.report(Activity::NullifyFinalize(activity));
                    commonware_p2p::block!(self.blocker, sender, "nullify after finalize");
                    return false;
                }

                // Try to reserve
                match (self.report_conflicting_votes, self.votes.nullify(index)) {
                    (true, Some(previous)) if previous != &nullify => {
                        commonware_p2p::block!(self.blocker, sender, "conflicting nullify");
                        false
                    }
                    (_, Some(_)) => false,
                    (_, None) => {
                        self.reporter.report(Activity::Nullify(nullify.clone()));
                        self.votes.insert_nullify(nullify.clone());
                        self.verifier.add(Vote::Nullify(nullify), false);
                        true
                    }
                }
            }
            Vote::Finalize(finalize) => {
                // Verify sender is signer
                if index != finalize.signer() {
                    commonware_p2p::block!(self.blocker, sender, "finalize signer mismatch");
                    return false;
                }

                // Once certified, retain only compact state for duplicate suppression
                // and proposal forwarding. The full vote is only needed when conflict
                // reporting is enabled.
                if !self.report_conflicting_votes && self.has_certificate(Kind::Finalization) {
                    let matching = self.verifier.proposal() == Some(&finalize.proposal);
                    if !self.votes.remember_finalize(index, matching) {
                        return false;
                    }
                    self.reporter.report(Activity::Finalize(finalize));
                    return true;
                }

                // Check if nullified
                if self.report_conflicting_votes
                    && let Some(previous) = self.votes.nullify(index)
                {
                    let activity = NullifyFinalize::new(previous.clone(), finalize);
                    self.reporter.report(Activity::NullifyFinalize(activity));
                    commonware_p2p::block!(self.blocker, sender, "finalize after nullify");
                    return false;
                }

                // Try to reserve
                match (self.report_conflicting_votes, self.votes.finalize(index)) {
                    (true, Some(previous)) if previous.proposal != finalize.proposal => {
                        let activity = ConflictingFinalize::new(previous.clone(), finalize);
                        self.reporter
                            .report(Activity::ConflictingFinalize(activity));
                        commonware_p2p::block!(self.blocker, sender, "conflicting finalize");
                        false
                    }
                    (true, Some(previous)) if previous != &finalize => {
                        commonware_p2p::block!(self.blocker, sender, "invalid signature");
                        false
                    }
                    (_, Some(_)) => false,
                    (_, None) => {
                        self.reporter.report(Activity::Finalize(finalize.clone()));
                        self.votes.insert_finalize(finalize.clone());
                        self.verifier.add(Vote::Finalize(finalize), false);
                        true
                    }
                }
            }
        }
    }

    /// Adds a durable locally constructed vote to the verifier and reporter.
    ///
    /// Duplicate nullifies are ignored (the voter re-sends its nullify vote on
    /// every timeout retry).
    ///
    /// # Panics
    ///
    /// Panics if a notarize or finalize vote is added more than once.
    pub fn add_constructed(&mut self, message: Vote<S, D>) {
        match &message {
            Vote::Notarize(notarize) => {
                if !self.report_conflicting_votes && self.has_certificate(Kind::Notarization) {
                    let matching = self.verifier.proposal() == Some(&notarize.proposal);
                    if !self.votes.remember_notarize(notarize.signer(), matching) {
                        return;
                    }
                    self.reporter.report(Activity::Notarize(notarize.clone()));
                    return;
                }

                // Our own votes are already verified
                assert!(
                    self.votes.insert_notarize(notarize.clone()),
                    "duplicate notarize"
                );

                // Report activity
                self.reporter.report(Activity::Notarize(notarize.clone()));
            }
            Vote::Nullify(nullify) => {
                if !self.report_conflicting_votes && self.has_certificate(Kind::Nullification) {
                    if !self.votes.remember_nullify(nullify.signer()) {
                        return;
                    }
                    self.reporter.report(Activity::Nullify(nullify.clone()));
                    return;
                }

                // The voter re-sends its nullify on every timeout retry (the
                // batcher's state does not survive a restart), so duplicates
                // are expected and ignored.
                if !self.votes.insert_nullify(nullify.clone()) {
                    return;
                }

                // Report activity
                self.reporter.report(Activity::Nullify(nullify.clone()));
            }
            Vote::Finalize(finalize) => {
                if !self.report_conflicting_votes && self.has_certificate(Kind::Finalization) {
                    let matching = self.verifier.proposal() == Some(&finalize.proposal);
                    if !self.votes.remember_finalize(finalize.signer(), matching) {
                        return;
                    }
                    self.reporter.report(Activity::Finalize(finalize.clone()));
                    return;
                }

                // The voter only constructs a finalize after independently
                // authenticating the proposal.
                self.set_authoritative_proposal(&finalize.proposal);
                assert!(
                    self.votes.insert_finalize(finalize.clone()),
                    "duplicate finalize"
                );

                // Report activity
                self.reporter.report(Activity::Finalize(finalize.clone()));
            }
        }

        // The verifier drops votes for a different proposal than the selected one.
        self.verifier.add(message, true);
    }

    /// Sets the leader for this view. If the leader's notarize has already
    /// been received, this will also set the leader's proposal (filtering out
    /// votes for other proposals).
    pub fn set_leader(&mut self, leader: Participant) {
        // Certification drops the verifier's buffered notarizes, so read an
        // uncertified leader vote from the tracker.
        self.verifier
            .set_leader(leader, self.votes.notarize(leader));
    }

    /// Returns the proposal to forward to the voter, marking it sent (at most
    /// once per round). Returns `None` if we already forwarded one, the
    /// proposal is unknown, or the known leader is us.
    pub fn try_forward_proposal(&mut self, me: Participant) -> Option<Proposal<D>> {
        if self.proposal_sent {
            return None;
        }
        let proposal = self.verifier.proposal()?;
        if self.verifier.leader() == Some(me) {
            return None;
        }
        let proposal = proposal.clone();
        self.proposal_sent = true;
        Some(proposal)
    }

    /// Batch verifies the first kind of vote worth verifying (notarizes, then
    /// nullifies, then finalizes), or `None` if no kind is worthwhile.
    ///
    /// Returns the number of votes processed and the signers that failed
    /// verification.
    pub async fn try_verify<E: CryptoRng>(
        &mut self,
        rng: &mut E,
        strategy: &impl Strategy,
    ) -> Option<(usize, Vec<Participant>)> {
        if let Some(result) = self.verifier.try_verify_notarizes(rng, strategy).await {
            return Some(result);
        }
        if let Some(result) = self.verifier.try_verify_nullifies(rng, strategy).await {
            return Some(result);
        }
        self.verifier.try_verify_finalizes(rng, strategy).await
    }

    /// Returns true if `signer` has a nullify vote in this round.
    pub fn has_nullify(&self, signer: Participant) -> bool {
        self.votes.has_nullify(signer)
    }

    #[cfg(test)]
    pub(super) fn has_notarize(&self, signer: Participant) -> bool {
        self.votes.has_notarize(signer)
    }

    /// Returns participant indices whose matching vote for `proposal` was not
    /// observed locally.
    ///
    /// Uses the vote tracker and compact post-certificate membership rather
    /// than the verified vote vectors because we only verify the first quorum
    /// of votes. A peer whose matching vote arrived after quorum is still
    /// tracked for forwarding.
    ///
    /// Both notarize and finalize votes are checked: a participant who sent
    /// either for the same proposal already has the block and does not need
    /// it forwarded. Votes for a conflicting proposal are treated as missing
    /// because those peers still need the winning block forwarded.
    pub fn is_missing_voter(&self, proposal: &Proposal<D>, participant: Participant) -> bool {
        if self.votes.has_notarize_for(participant, proposal) {
            return false;
        }

        !self.votes.has_finalize_for(participant, proposal)
    }

    /// Returns participant indices whose matching vote for `proposal` was not
    /// observed locally.
    ///
    /// Uses the vote tracker and compact post-certificate membership rather
    /// than the verified vote vectors because we only verify the first quorum
    /// of votes. A peer whose matching vote arrived after quorum is still
    /// tracked for forwarding.
    ///
    /// Both notarize and finalize votes are checked: a participant who sent
    /// either for the same proposal already has the block and does not need
    /// it forwarded. Votes for a conflicting proposal are treated as missing
    /// because those peers still need the winning block forwarded.
    pub fn missing_voters(&self, proposal: &Proposal<D>) -> Vec<Participant> {
        (0..self.verifier.participants().len())
            .map(Participant::from_usize)
            .filter(|&p| self.is_missing_voter(proposal, p))
            .collect()
    }

    /// Attempts to construct a certificate from verified votes: the first kind
    /// (notarization, then nullification, then finalization) with an unconsumed
    /// verified quorum. Call repeatedly to drain every constructible kind.
    ///
    /// Once recovery starts, it consumes the verified votes. Do not cancel unless the round will
    /// also be discarded.
    pub async fn try_construct_certificate(
        &mut self,
        strategy: &impl Strategy,
    ) -> Option<Certificate<S, D>> {
        let certificate = self.verifier.try_construct_certificate(strategy).await?;
        self.release_votes(certificate.kind());
        Some(certificate)
    }
}
