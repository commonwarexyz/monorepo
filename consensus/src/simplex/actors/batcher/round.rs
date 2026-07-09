use super::{verifier::Queue, Verifier};
use crate::{
    simplex::{
        actors::span::ViewSpan,
        scheme::Scheme,
        types::{
            phase, Activity, Attributable, AttributableMap, Certificate, Certified,
            ConflictingFinalize, ConflictingNotarize, Finalization, Notarization, Nullification,
            NullifyFinalize, Proposal, Signed, Vote, VoteTracker,
        },
    },
    types::{Participant, Round as Rnd},
    Reporter,
};
use commonware_cryptography::Digest;
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::{
    ordered::{Quorum, Set},
    N3f1,
};
use rand_core::CryptoRng;
use tracing::{info_span, span::EnteredSpan, Span};

/// Per-view state for vote accumulation and certificate tracking.
pub struct Round<
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    round: Rnd,
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

    /// Whether we've already sent the leader's proposal to the voter.
    proposal_sent: bool,

    /// Cached certificates for this view.
    /// Once a certificate exists, we stop verifying votes of its phase.
    certificates: Certificates<S, D>,

    /// Root span of the view, shared with the voter's round.
    ///
    /// Pending until the voter announces the view via an update.
    span: ViewSpan,
}

/// The certificates recovered or received for a view, one slot per phase.
pub(in crate::simplex) struct Certificates<S: Scheme<D>, D: Digest> {
    notarization: Option<Notarization<S, D>>,
    nullification: Option<Nullification<S, D>>,
    finalization: Option<Finalization<S, D>>,
}

/// Per-phase glue used by [Round] to drive the vote pipeline generically: which
/// pending map and certificate slot belong to this phase, how its votes embed into
/// [Vote] and [Activity], what evidence contradictory votes constitute, and the
/// phase's telemetry spans (span names must be string literals, so each phase
/// carries its own).
pub(in crate::simplex) trait Ingest<S: Scheme<D>, D: Digest>:
    Queue<S, D>
{
    /// Returns the map tracking votes of this phase.
    fn tracker(votes: &mut VoteTracker<S, D>) -> &mut AttributableMap<Signed<Self, S, D>>;

    /// Returns the certificate slot of this phase.
    fn slot(certificates: &Certificates<S, D>) -> &Option<Certified<Self, S, D>>;

    /// Returns the certificate slot of this phase.
    fn slot_mut(certificates: &mut Certificates<S, D>) -> &mut Option<Certified<Self, S, D>>;

    /// Embeds a vote of this phase into [Vote].
    fn vote(vote: Signed<Self, S, D>) -> Vote<S, D>;

    /// Embeds a vote of this phase into [Activity].
    fn activity(vote: Signed<Self, S, D>) -> Activity<S, D>;

    /// Returns equivocation evidence if the two votes contradict.
    fn equivocation(
        previous: &Signed<Self, S, D>,
        incoming: &Signed<Self, S, D>,
    ) -> Option<Activity<S, D>>;

    /// Returns cross-phase evidence if the signer's earlier vote of another phase
    /// contradicts `incoming` by rule.
    fn contradicted_by(
        votes: &VoteTracker<S, D>,
        incoming: &Signed<Self, S, D>,
    ) -> Option<Activity<S, D>>;

    /// Opens the span covering batch verification of this phase's votes.
    fn verify_span(round: Rnd) -> EnteredSpan;

    /// Opens the span covering certificate construction for this phase.
    fn construct_span(round: Rnd) -> EnteredSpan;
}

impl<S: Scheme<D>, D: Digest> Ingest<S, D> for phase::Notarize {
    fn tracker(votes: &mut VoteTracker<S, D>) -> &mut AttributableMap<Signed<Self, S, D>> {
        &mut votes.notarizes
    }

    fn slot(certificates: &Certificates<S, D>) -> &Option<Certified<Self, S, D>> {
        &certificates.notarization
    }

    fn slot_mut(certificates: &mut Certificates<S, D>) -> &mut Option<Certified<Self, S, D>> {
        &mut certificates.notarization
    }

    fn vote(vote: Signed<Self, S, D>) -> Vote<S, D> {
        Vote::Notarize(vote)
    }

    fn activity(vote: Signed<Self, S, D>) -> Activity<S, D> {
        Activity::Notarize(vote)
    }

    fn equivocation(
        previous: &Signed<Self, S, D>,
        incoming: &Signed<Self, S, D>,
    ) -> Option<Activity<S, D>> {
        ConflictingNotarize::try_new_canonical(previous, incoming)
            .map(Activity::ConflictingNotarize)
    }

    /// No other phase contradicts a notarize by rule.
    fn contradicted_by(_: &VoteTracker<S, D>, _: &Signed<Self, S, D>) -> Option<Activity<S, D>> {
        None
    }

    fn verify_span(round: Rnd) -> EnteredSpan {
        info_span!(
            "simplex.batcher.verify_notarizes",
            epoch = round.epoch().traced(),
            view = round.view().traced()
        )
        .entered()
    }

    fn construct_span(round: Rnd) -> EnteredSpan {
        info_span!(
            "simplex.batcher.try_construct_notarization",
            epoch = round.epoch().traced(),
            view = round.view().traced()
        )
        .entered()
    }
}

impl<S: Scheme<D>, D: Digest> Ingest<S, D> for phase::Nullify {
    fn tracker(votes: &mut VoteTracker<S, D>) -> &mut AttributableMap<Signed<Self, S, D>> {
        &mut votes.nullifies
    }

    fn slot(certificates: &Certificates<S, D>) -> &Option<Certified<Self, S, D>> {
        &certificates.nullification
    }

    fn slot_mut(certificates: &mut Certificates<S, D>) -> &mut Option<Certified<Self, S, D>> {
        &mut certificates.nullification
    }

    fn vote(vote: Signed<Self, S, D>) -> Vote<S, D> {
        Vote::Nullify(vote)
    }

    fn activity(vote: Signed<Self, S, D>) -> Activity<S, D> {
        Activity::Nullify(vote)
    }

    /// Nullifies cannot equivocate: their claim is the round itself, so `Signed<Nullify>`
    /// does not implement the `Contradicts` relation and evidence is unconstructible.
    /// Returning [None] here is what lets a single [Round::reserve] engine serve all
    /// three phases.
    fn equivocation(_: &Signed<Self, S, D>, _: &Signed<Self, S, D>) -> Option<Activity<S, D>> {
        None
    }

    /// A finalize from the same signer contradicts the nullify by rule.
    fn contradicted_by(
        votes: &VoteTracker<S, D>,
        incoming: &Signed<Self, S, D>,
    ) -> Option<Activity<S, D>> {
        let previous = votes.finalizes.get(incoming.signer())?;
        Some(Activity::NullifyFinalize(NullifyFinalize::new(
            incoming.clone(),
            previous.clone(),
        )))
    }

    fn verify_span(round: Rnd) -> EnteredSpan {
        info_span!(
            "simplex.batcher.verify_nullifies",
            epoch = round.epoch().traced(),
            view = round.view().traced()
        )
        .entered()
    }

    fn construct_span(round: Rnd) -> EnteredSpan {
        info_span!(
            "simplex.batcher.try_construct_nullification",
            epoch = round.epoch().traced(),
            view = round.view().traced()
        )
        .entered()
    }
}

impl<S: Scheme<D>, D: Digest> Ingest<S, D> for phase::Finalize {
    fn tracker(votes: &mut VoteTracker<S, D>) -> &mut AttributableMap<Signed<Self, S, D>> {
        &mut votes.finalizes
    }

    fn slot(certificates: &Certificates<S, D>) -> &Option<Certified<Self, S, D>> {
        &certificates.finalization
    }

    fn slot_mut(certificates: &mut Certificates<S, D>) -> &mut Option<Certified<Self, S, D>> {
        &mut certificates.finalization
    }

    fn vote(vote: Signed<Self, S, D>) -> Vote<S, D> {
        Vote::Finalize(vote)
    }

    fn activity(vote: Signed<Self, S, D>) -> Activity<S, D> {
        Activity::Finalize(vote)
    }

    fn equivocation(
        previous: &Signed<Self, S, D>,
        incoming: &Signed<Self, S, D>,
    ) -> Option<Activity<S, D>> {
        ConflictingFinalize::try_new_canonical(previous, incoming)
            .map(Activity::ConflictingFinalize)
    }

    /// A nullify from the same signer contradicts the finalize by rule.
    fn contradicted_by(
        votes: &VoteTracker<S, D>,
        incoming: &Signed<Self, S, D>,
    ) -> Option<Activity<S, D>> {
        let previous = votes.nullifies.get(incoming.signer())?;
        Some(Activity::NullifyFinalize(NullifyFinalize::new(
            previous.clone(),
            incoming.clone(),
        )))
    }

    fn verify_span(round: Rnd) -> EnteredSpan {
        info_span!(
            "simplex.batcher.verify_finalizes",
            epoch = round.epoch().traced(),
            view = round.view().traced()
        )
        .entered()
    }

    fn construct_span(round: Rnd) -> EnteredSpan {
        info_span!(
            "simplex.batcher.try_construct_finalization",
            epoch = round.epoch().traced(),
            view = round.view().traced()
        )
        .entered()
    }
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
        participants: Set<S::PublicKey>,
        scheme: S,
        blocker: B,
        reporter: R,
    ) -> Self {
        let quorum = participants.quorum::<N3f1>();
        let len = participants.len();
        Self {
            round,
            participants,

            blocker,
            reporter,
            verifier: Verifier::new(scheme, quorum),

            pending_votes: VoteTracker::new(len),
            verified_votes: VoteTracker::new(len),

            proposal_sent: false,

            certificates: Certificates {
                notarization: None,
                nullification: None,
                finalization: None,
            },

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

    /// Returns true if we already have a notarization certificate for this view.
    pub const fn has_notarization(&self) -> bool {
        self.certificates.notarization.is_some()
    }

    /// Returns true if we already have a nullification certificate for this view.
    pub const fn has_nullification(&self) -> bool {
        self.certificates.nullification.is_some()
    }

    /// Returns true if we already have a finalization certificate for this view.
    pub const fn has_finalization(&self) -> bool {
        self.certificates.finalization.is_some()
    }

    /// Stores a verified certificate.
    pub fn set_certificate(&mut self, certificate: Certificate<S, D>) {
        match certificate {
            Certificate::Notarization(notarization) => {
                self.certificates.notarization = Some(notarization)
            }
            Certificate::Nullification(nullification) => {
                self.certificates.nullification = Some(nullification)
            }
            Certificate::Finalization(finalization) => {
                self.certificates.finalization = Some(finalization)
            }
        }
    }

    /// Reconciles an incoming vote with the signer's previous vote of the same phase.
    ///
    /// A first vote is reported, recorded, and handed to the verifier. A byte-identical
    /// duplicate is ignored. Contradictory claims are reported as equivocation evidence,
    /// while the same claim with a different attestation means at least one signature is
    /// invalid; both block the sender.
    fn reserve<P: Ingest<S, D>>(&mut self, sender: S::PublicKey, vote: Signed<P, S, D>) -> bool {
        // A vote of another phase from the same signer may contradict this one by rule
        if let Some(evidence) = P::contradicted_by(&self.pending_votes, &vote) {
            self.reporter.report(evidence);
            commonware_p2p::block!(
                self.blocker,
                sender,
                phase = ?P::TAG,
                "contradictory votes"
            );
            return false;
        }

        let votes = P::tracker(&mut self.pending_votes);
        match votes.get(vote.signer()) {
            None => {
                self.reporter.report(P::activity(vote.clone()));
                votes.insert(vote.clone());
                self.verifier.add(P::vote(vote));
                true
            }
            Some(previous) if previous == &vote => false,
            Some(previous) => {
                if let Some(evidence) = P::equivocation(previous, &vote) {
                    self.reporter.report(evidence);
                    commonware_p2p::block!(
                        self.blocker,
                        sender,
                        phase = ?P::TAG,
                        "conflicting votes"
                    );
                } else {
                    commonware_p2p::block!(
                        self.blocker,
                        sender,
                        phase = ?P::TAG,
                        "invalid signature"
                    );
                }
                false
            }
        }
    }

    /// Adds a vote from the network to this round's verifier.
    pub fn add_network(&mut self, sender: S::PublicKey, message: Vote<S, D>) -> bool {
        // Check if sender is a participant
        let Some(index) = self.participants.index(&sender) else {
            commonware_p2p::block!(self.blocker, sender, "unknown participant");
            return false;
        };

        // Verify sender is signer
        if index != message.signer() {
            commonware_p2p::block!(
                self.blocker,
                sender,
                phase = ?message.phase(),
                "vote signer mismatch"
            );
            return false;
        }

        match message {
            Vote::Notarize(notarize) => self.reserve(sender, notarize),
            Vote::Nullify(nullify) => self.reserve(sender, nullify),
            Vote::Finalize(finalize) => self.reserve(sender, finalize),
        }
    }

    /// Adds a vote that we constructed ourselves to the verifier.
    pub fn add_constructed(&mut self, message: Vote<S, D>) {
        // Report activity
        self.reporter.report(Activity::from(message.clone()));

        // Our own votes are already verified
        let phase = message.phase();
        assert!(
            self.pending_votes.insert(message.clone()),
            "duplicate {phase:?} vote"
        );

        // Only add to verified_votes if the verifier accepts the vote.
        // The verifier may reject votes for a different proposal than the leader's.
        if self.verifier.add_verified(message.clone()) {
            self.add_verified(message);
        }
    }

    /// Sets the leader for this view. If the leader's vote has already been
    /// received, this will also set the leader's proposal (filtering out votes
    /// for other proposals).
    pub fn set_leader(&mut self, leader: Participant) {
        self.verifier.set_leader(leader);
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

    /// Checks if votes of phase `P` are ready for batch verification.
    pub fn ready<P: Ingest<S, D>>(&self) -> bool {
        // Don't bother verifying if we already have a certificate
        if P::slot(&self.certificates).is_some() {
            return false;
        }
        self.verifier.ready::<P>()
    }

    /// Verifies pending votes of phase `P` as a batch.
    ///
    /// Returns the successfully verified votes and the signer indices for whom
    /// verification failed.
    pub fn verify<P: Ingest<S, D>>(
        &mut self,
        rng: &mut impl CryptoRng,
        strategy: &impl Strategy,
    ) -> (Vec<Vote<S, D>>, Vec<Participant>) {
        let _span = P::verify_span(self.round);
        let (verified, invalid) = self.verifier.verify::<P>(rng, strategy);
        (verified.into_iter().map(P::vote).collect(), invalid)
    }

    /// Returns true if `signer` has a nullify vote in this round.
    pub fn has_nullify(&self, signer: Participant) -> bool {
        self.pending_votes.nullifies.contains(signer)
    }

    /// Returns true if `participant`'s matching vote for `proposal` was not
    /// observed locally.
    ///
    /// Uses `pending_votes` rather than `verified_votes` because we only
    /// verify the first quorum of votes. A peer whose matching vote arrived
    /// after quorum but before the certificate is still tracked in pending.
    ///
    /// Both notarize and finalize votes are checked: a participant who sent
    /// either for the same proposal already has the block and does not need
    /// it forwarded. Votes for a conflicting proposal are treated as missing
    /// because those peers still need the winning block forwarded.
    pub fn is_missing_voter(&self, proposal: &Proposal<D>, participant: Participant) -> bool {
        if self
            .pending_votes
            .notarizes
            .get(participant)
            .is_some_and(|vote| &vote.claim == proposal)
        {
            return false;
        }

        self.pending_votes
            .finalizes
            .get(participant)
            .is_none_or(|vote| &vote.claim != proposal)
    }

    /// Returns all participants whose matching vote for `proposal` was not
    /// observed locally (see [Self::is_missing_voter]).
    pub fn missing_voters(&self, proposal: &Proposal<D>) -> Vec<Participant> {
        (0..self.participants.len())
            .map(Participant::from_usize)
            .filter(|&p| self.is_missing_voter(proposal, p))
            .collect()
    }

    /// Stores a verified vote for certificate construction.
    pub fn add_verified(&mut self, vote: Vote<S, D>) {
        self.verified_votes.insert(vote);
    }

    /// Attempts to construct a certificate of phase `P` from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    /// The construction span is entered only once construction is attempted.
    pub fn try_construct<P: Ingest<S, D>>(
        &mut self,
        strategy: &impl Strategy,
    ) -> Option<Certified<P, S, D>> {
        let slot = P::slot_mut(&mut self.certificates);
        if slot.is_some() {
            return None;
        }
        let votes = &*P::tracker(&mut self.verified_votes);
        if votes.len() < self.participants.quorum::<N3f1>() as usize {
            return None;
        }
        let _span = P::construct_span(self.round);
        let certificate = Certified::from_votes(self.verifier.scheme(), votes, strategy)?;
        *slot = Some(certificate.clone());
        Some(certificate)
    }
}
