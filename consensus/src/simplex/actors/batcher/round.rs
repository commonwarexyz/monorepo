use super::Verifier;
use crate::{
    simplex::{
        actors::span::ViewSpan,
        scheme::Scheme,
        types::{
            phase, Activity, Attributable, AttributableMap, Certificate, Certified,
            ConflictingFinalize, ConflictingNotarize, Finalization, Notarization, Nullification,
            NullifyFinalize, Phase, Proposal, Signed, Vote, VoteTracker,
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
    /// Once a certificate exists, we stop verifying votes of that type.
    notarization: Option<Notarization<S, D>>,
    nullification: Option<Nullification<S, D>>,
    finalization: Option<Finalization<S, D>>,

    /// Root span of the view, shared with the voter's round.
    ///
    /// Pending until the voter announces the view via an update.
    span: ViewSpan,
}

/// Per-phase glue used by [Round::add_network] to ingest votes generically: which
/// pending map tracks votes of this phase, how they embed into [Vote] and [Activity],
/// and what evidence two contradictory votes constitute.
trait Ingest<S: Scheme<D>, D: Digest>: Phase {
    /// Returns the map tracking votes of this phase.
    fn tracker(votes: &mut VoteTracker<S, D>) -> &mut AttributableMap<Signed<Self, S, D>>;

    /// Embeds a vote of this phase into [Vote].
    fn vote(vote: Signed<Self, S, D>) -> Vote<S, D>;

    /// Embeds a vote of this phase into [Activity].
    fn activity(vote: Signed<Self, S, D>) -> Activity<S, D>;

    /// Returns equivocation evidence if the two votes contradict.
    fn equivocation(
        previous: &Signed<Self, S, D>,
        incoming: &Signed<Self, S, D>,
    ) -> Option<Activity<S, D>>;
}

impl<S: Scheme<D>, D: Digest> Ingest<S, D> for phase::Notarize {
    fn tracker(votes: &mut VoteTracker<S, D>) -> &mut AttributableMap<Signed<Self, S, D>> {
        &mut votes.notarizes
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
        // Order by claim so one equivocation has one encoding.
        let (first, second) = if previous.claim <= incoming.claim {
            (previous, incoming)
        } else {
            (incoming, previous)
        };
        ConflictingNotarize::try_new(first, second).map(Activity::ConflictingNotarize)
    }
}

impl<S: Scheme<D>, D: Digest> Ingest<S, D> for phase::Nullify {
    fn tracker(votes: &mut VoteTracker<S, D>) -> &mut AttributableMap<Signed<Self, S, D>> {
        &mut votes.nullifies
    }

    fn vote(vote: Signed<Self, S, D>) -> Vote<S, D> {
        Vote::Nullify(vote)
    }

    fn activity(vote: Signed<Self, S, D>) -> Activity<S, D> {
        Activity::Nullify(vote)
    }

    /// Nullifies cannot equivocate: their claim is the round itself.
    fn equivocation(_: &Signed<Self, S, D>, _: &Signed<Self, S, D>) -> Option<Activity<S, D>> {
        None
    }
}

impl<S: Scheme<D>, D: Digest> Ingest<S, D> for phase::Finalize {
    fn tracker(votes: &mut VoteTracker<S, D>) -> &mut AttributableMap<Signed<Self, S, D>> {
        &mut votes.finalizes
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
        // Order by claim so one equivocation has one encoding.
        let (first, second) = if previous.claim <= incoming.claim {
            (previous, incoming)
        } else {
            (incoming, previous)
        };
        ConflictingFinalize::try_new(first, second).map(Activity::ConflictingFinalize)
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

            notarization: None,
            nullification: None,
            finalization: None,

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

    /// Stores a verified certificate.
    pub fn set_certificate(&mut self, certificate: Certificate<S, D>) {
        match certificate {
            Certificate::Notarization(notarization) => self.notarization = Some(notarization),
            Certificate::Nullification(nullification) => self.nullification = Some(nullification),
            Certificate::Finalization(finalization) => self.finalization = Some(finalization),
        }
    }

    /// Reconciles an incoming vote with the signer's previous vote of the same phase.
    ///
    /// A first vote is reported, recorded, and handed to the verifier. A byte-identical
    /// duplicate is ignored. Contradictory claims are reported as equivocation evidence,
    /// while the same claim with a different attestation means at least one signature is
    /// invalid; both block the sender.
    fn reserve<P: Ingest<S, D>>(&mut self, sender: S::PublicKey, vote: Signed<P, S, D>) -> bool {
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
            Vote::Nullify(nullify) => {
                // A finalize from the same signer contradicts the nullify by rule
                if let Some(previous) = self.pending_votes.finalizes.get(index) {
                    let activity = NullifyFinalize::new(nullify, previous.clone());
                    self.reporter.report(Activity::NullifyFinalize(activity));
                    commonware_p2p::block!(self.blocker, sender, "nullify after finalize");
                    return false;
                }
                self.reserve(sender, nullify)
            }
            Vote::Finalize(finalize) => {
                // A nullify from the same signer contradicts the finalize by rule
                if let Some(previous) = self.pending_votes.nullifies.get(index) {
                    let activity = NullifyFinalize::new(previous.clone(), finalize);
                    self.reporter.report(Activity::NullifyFinalize(activity));
                    commonware_p2p::block!(self.blocker, sender, "finalize after nullify");
                    return false;
                }
                self.reserve(sender, finalize)
            }
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

    pub fn ready_notarizes(&self) -> bool {
        // Don't bother verifying if we already have a certificate
        if self.has_notarization() {
            return false;
        }
        self.verifier.ready_notarizes()
    }

    #[tracing::instrument(name = "simplex.batcher.verify_notarizes", level = "info", skip_all, fields(epoch = self.round.epoch().traced(), view = self.round.view().traced()))]
    pub fn verify_notarizes<E: CryptoRng>(
        &mut self,
        rng: &mut E,
        strategy: &impl Strategy,
    ) -> (Vec<Vote<S, D>>, Vec<Participant>) {
        self.verifier.verify_notarizes(rng, strategy)
    }

    pub fn ready_nullifies(&self) -> bool {
        // Don't bother verifying if we already have a certificate
        if self.has_nullification() {
            return false;
        }
        self.verifier.ready_nullifies()
    }

    #[tracing::instrument(name = "simplex.batcher.verify_nullifies", level = "info", skip_all, fields(epoch = self.round.epoch().traced(), view = self.round.view().traced()))]
    pub fn verify_nullifies<E: CryptoRng>(
        &mut self,
        rng: &mut E,
        strategy: &impl Strategy,
    ) -> (Vec<Vote<S, D>>, Vec<Participant>) {
        self.verifier.verify_nullifies(rng, strategy)
    }

    pub fn ready_finalizes(&self) -> bool {
        // Don't bother verifying if we already have a certificate
        if self.has_finalization() {
            return false;
        }
        self.verifier.ready_finalizes()
    }

    #[tracing::instrument(name = "simplex.batcher.verify_finalizes", level = "info", skip_all, fields(epoch = self.round.epoch().traced(), view = self.round.view().traced()))]
    pub fn verify_finalizes<E: CryptoRng>(
        &mut self,
        rng: &mut E,
        strategy: &impl Strategy,
    ) -> (Vec<Vote<S, D>>, Vec<Participant>) {
        self.verifier.verify_finalizes(rng, strategy)
    }

    /// Returns true if `signer` has a nullify vote in this round.
    pub fn has_nullify(&self, signer: Participant) -> bool {
        self.pending_votes.nullifies.contains(signer)
    }

    /// Returns participant indices whose matching vote for `proposal` was not
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

    /// Returns participant indices whose matching vote for `proposal` was not
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

    /// Attempts to construct a certificate of kind `P` from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    /// `span` is entered only once construction is attempted.
    fn try_construct<P: Phase>(
        slot: &mut Option<Certified<P, S, D>>,
        votes: &AttributableMap<Signed<P, S, D>>,
        quorum: u32,
        scheme: &S,
        strategy: &impl Strategy,
        span: impl FnOnce() -> EnteredSpan,
    ) -> Option<Certified<P, S, D>> {
        if slot.is_some() {
            return None;
        }
        if votes.len() < quorum as usize {
            return None;
        }
        let _span = span();
        let certificate = Certified::from_votes(scheme, votes, strategy)?;
        *slot = Some(certificate.clone());
        Some(certificate)
    }

    /// Attempts to construct a notarization certificate from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    pub fn try_construct_notarization(
        &mut self,
        scheme: &S,
        strategy: &impl Strategy,
    ) -> Option<Notarization<S, D>> {
        let (epoch, view) = (self.round.epoch().traced(), self.round.view().traced());
        Self::try_construct(
            &mut self.notarization,
            &self.verified_votes.notarizes,
            self.participants.quorum::<N3f1>(),
            scheme,
            strategy,
            || {
                info_span!(
                    "simplex.batcher.try_construct_notarization",
                    epoch = epoch,
                    view = view
                )
                .entered()
            },
        )
    }

    /// Attempts to construct a nullification certificate from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    pub fn try_construct_nullification(
        &mut self,
        scheme: &S,
        strategy: &impl Strategy,
    ) -> Option<Nullification<S, D>> {
        let (epoch, view) = (self.round.epoch().traced(), self.round.view().traced());
        Self::try_construct(
            &mut self.nullification,
            &self.verified_votes.nullifies,
            self.participants.quorum::<N3f1>(),
            scheme,
            strategy,
            || {
                info_span!(
                    "simplex.batcher.try_construct_nullification",
                    epoch = epoch,
                    view = view
                )
                .entered()
            },
        )
    }

    /// Attempts to construct a finalization certificate from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    pub fn try_construct_finalization(
        &mut self,
        scheme: &S,
        strategy: &impl Strategy,
    ) -> Option<Finalization<S, D>> {
        let (epoch, view) = (self.round.epoch().traced(), self.round.view().traced());
        Self::try_construct(
            &mut self.finalization,
            &self.verified_votes.finalizes,
            self.participants.quorum::<N3f1>(),
            scheme,
            strategy,
            || {
                info_span!(
                    "simplex.batcher.try_construct_finalization",
                    epoch = epoch,
                    view = view
                )
                .entered()
            },
        )
    }
}
