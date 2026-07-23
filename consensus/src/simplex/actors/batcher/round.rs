use super::Verifier;
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
    /// Verifier only attempts to recover a certificate from votes for the first proposal
    /// we see from a leader. If we are on the wrong side of an equivocation, the verifier
    /// will not produce anything of value (and we'll only participate by forwarding certificates).
    verifier: Verifier<S, D>,
    /// Votes received from network (may not be verified yet).
    /// Used for duplicate detection and conflict reporting.
    votes: VoteTracker<S, D>,

    /// Whether we've already sent the leader's proposal to the voter.
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
    pub fn new(round: Rnd, scheme: Arc<S>, blocker: B, reporter: R) -> Self {
        let quorum = scheme.participants().quorum::<N3f1>();
        let len = scheme.participants().len();
        Self {
            blocker,
            reporter,
            verifier: Verifier::new(round, scheme, quorum),

            votes: VoteTracker::new(len),

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

    /// Records that a certificate of `kind` exists, dropping its buffered votes.
    pub fn record_certificate(&mut self, kind: Kind) {
        self.verifier.record_certificate(kind);
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

                // Try to reserve
                match self.votes.notarize(index) {
                    Some(previous) => {
                        if previous.proposal != notarize.proposal {
                            let activity = ConflictingNotarize::new(previous.clone(), notarize);
                            self.reporter
                                .report(Activity::ConflictingNotarize(activity));
                            commonware_p2p::block!(self.blocker, sender, "conflicting notarize");
                        } else if previous != &notarize {
                            commonware_p2p::block!(self.blocker, sender, "invalid signature");
                        }
                        false
                    }
                    None => {
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

                // Check if finalized
                if let Some(previous) = self.votes.finalize(index) {
                    let activity = NullifyFinalize::new(nullify, previous.clone());
                    self.reporter.report(Activity::NullifyFinalize(activity));
                    commonware_p2p::block!(self.blocker, sender, "nullify after finalize");
                    return false;
                }

                // Try to reserve
                match self.votes.nullify(index) {
                    Some(previous) => {
                        if previous != &nullify {
                            commonware_p2p::block!(self.blocker, sender, "conflicting nullify");
                        }
                        false
                    }
                    None => {
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

                // Check if nullified
                if let Some(previous) = self.votes.nullify(index) {
                    let activity = NullifyFinalize::new(previous.clone(), finalize);
                    self.reporter.report(Activity::NullifyFinalize(activity));
                    commonware_p2p::block!(self.blocker, sender, "finalize after nullify");
                    return false;
                }

                // Try to reserve
                match self.votes.finalize(index) {
                    Some(previous) => {
                        if previous.proposal != finalize.proposal {
                            let activity = ConflictingFinalize::new(previous.clone(), finalize);
                            self.reporter
                                .report(Activity::ConflictingFinalize(activity));
                            commonware_p2p::block!(self.blocker, sender, "conflicting finalize");
                        } else if previous != &finalize {
                            commonware_p2p::block!(self.blocker, sender, "invalid signature");
                        }
                        false
                    }
                    None => {
                        self.reporter.report(Activity::Finalize(finalize.clone()));
                        self.votes.insert_finalize(finalize.clone());
                        self.verifier.add(Vote::Finalize(finalize), false);
                        true
                    }
                }
            }
        }
    }

    /// Adds a vote that we constructed ourselves to the verifier.
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
                // Our own votes are already verified
                assert!(
                    self.votes.insert_notarize(notarize.clone()),
                    "duplicate notarize"
                );

                // Report activity
                self.reporter.report(Activity::Notarize(notarize.clone()));
            }
            Vote::Nullify(nullify) => {
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
                // Our own votes are already verified
                assert!(
                    self.votes.insert_finalize(finalize.clone()),
                    "duplicate finalize"
                );

                // Report activity
                self.reporter.report(Activity::Finalize(finalize.clone()));
            }
        }

        // The verifier drops votes for a different proposal than the leader's.
        self.verifier.add(message, true);
    }

    /// Sets the leader for this view. If the leader's notarize has already
    /// been received, this will also set the leader's proposal (filtering out
    /// votes for other proposals).
    pub fn set_leader(&mut self, leader: Participant) {
        // Certification drops the verifier's buffered notarizes, so read the
        // leader's vote from the tracker, which holds it for the round's lifetime.
        self.verifier
            .set_leader(leader, self.votes.notarize(leader));
    }

    /// Returns the leader's proposal to forward to the voter, marking it sent
    /// (at most once per round). Returns `None` if we already forwarded one,
    /// the leader's proposal is unknown, or we are the leader (leaders don't
    /// need to forward their own proposal).
    pub fn try_forward_proposal(&mut self, me: Participant) -> Option<Proposal<D>> {
        if self.proposal_sent {
            return None;
        }
        let (leader, proposal) = self.verifier.get_leader_proposal()?;
        if leader == me {
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

    /// Returns participant indices whose matching vote for `proposal` was not
    /// observed locally.
    ///
    /// Uses `votes` rather than the verified vote vectors because we only
    /// verify the first quorum of votes. A peer whose matching vote arrived
    /// after quorum but before the certificate is still tracked in pending.
    ///
    /// Both notarize and finalize votes are checked: a participant who sent
    /// either for the same proposal already has the block and does not need
    /// it forwarded. Votes for a conflicting proposal are treated as missing
    /// because those peers still need the winning block forwarded.
    pub fn is_missing_voter(&self, proposal: &Proposal<D>, participant: Participant) -> bool {
        if self
            .votes
            .notarize(participant)
            .is_some_and(|vote| &vote.proposal == proposal)
        {
            return false;
        }

        self.votes
            .finalize(participant)
            .is_none_or(|vote| &vote.proposal != proposal)
    }

    /// Returns participant indices whose matching vote for `proposal` was not
    /// observed locally.
    ///
    /// Uses `votes` rather than the verified vote vectors because we only
    /// verify the first quorum of votes. A peer whose matching vote arrived
    /// after quorum but before the certificate is still tracked in pending.
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
        self.verifier.try_construct_certificate(strategy).await
    }
}
