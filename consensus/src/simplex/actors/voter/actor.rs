use super::{Config, Mailbox, Message};
use crate::{
    simplex::{
        actors::{batcher, resolver},
        interesting,
        metrics::{self, Inbound, Outbound},
        min_active, select_leader,
        signing_scheme::Scheme,
        types::{
            Activity, Attributable, AttributableMap, Context, Finalization, Finalize, Notarization,
            Notarize, Nullification, Nullify, OrderedExt, Proposal, Voter,
        },
    },
    types::{Epoch, Round as Rnd, View},
    Automaton, Epochable, Relay, Reporter, Viewable, LATENCY,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    buffer::PoolRef,
    spawn_cell,
    telemetry::metrics::histogram::{self, Buckets},
    Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    pin_mut, StreamExt,
};
use prometheus_client::metrics::{
    counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
};
use rand::{CryptoRng, Rng};
use std::{
    collections::BTreeMap,
    mem::replace,
    num::NonZeroUsize,
    sync::{atomic::AtomicI64, Arc},
    time::{Duration, SystemTime},
};
use tracing::{debug, info, trace, warn};

const GENESIS_VIEW: View = 0;

/// Action to take after processing a message.
enum Action {
    /// Skip processing the message.
    Skip,
    /// Block the peer from sending any more messages.
    Block,
    /// Process the message.
    Process,
}

/// A leader of a given round.
#[derive(Debug, Clone)]
struct Leader<P: PublicKey> {
    /// The index of the leader.
    idx: u32,
    /// The public key of the leader.
    key: P,
}

/// Status of proposal verification for a round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalStatus {
    /// No proposal exists yet
    None,
    /// Proposal exists but has not been verified
    Unverified,
    /// Proposal exists and has been verified
    Verified,
    /// Proposal was replaced by a certificate (equivocation)
    Replaced,
}

/// Describes how the tracked proposal changed after a slot update.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProposalChange<D>
where
    D: Digest,
{
    /// A new proposal was recorded.
    New,
    /// Proposal already matched the existing one.
    Unchanged,
    /// Proposal conflicted with the existing one and was replaced.
    Replaced {
        previous: Proposal<D>,
        new: Proposal<D>,
    },
    /// Proposal was ignored because the round was already marked replaced.
    Skipped,
}

/// Tracks proposal state for a round, including verification and build flags.
struct ProposalSlot<D>
where
    D: Digest,
{
    proposal: Option<Proposal<D>>,
    status: ProposalStatus,
    requested_build: bool,
    requested_verify: bool,
}

impl<D> ProposalSlot<D>
where
    D: Digest + Clone + PartialEq,
{
    /// Creates an empty slot with no proposal or outstanding requests.
    ///
    /// The slot starts in [`ProposalStatus::None`] with both build and verify
    /// requests unset.
    fn new() -> Self {
        Self {
            proposal: None,
            status: ProposalStatus::None,
            requested_build: false,
            requested_verify: false,
        }
    }

    /// Returns the currently tracked proposal, if one has been recorded.
    fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.as_ref()
    }

    /// Returns the current [`ProposalStatus`] for the slot.
    fn status(&self) -> ProposalStatus {
        self.status
    }

    /// Returns `true` when the caller should begin constructing a proposal.
    ///
    /// This method does not mutate the slot; callers must invoke [`Self::set_building`]
    /// once they commit to building so future calls to `should_build` short-circuit.
    /// It returns `false` if a proposal already exists or [`Self::set_building`] has
    /// been called.
    fn should_build(&self) -> bool {
        if self.requested_build || self.proposal.is_some() {
            return false;
        }
        true
    }

    /// Records that proposal construction is in progress so subsequent calls to
    /// [`Self::should_build`] return `false`.
    fn set_building(&mut self) {
        self.requested_build = true;
    }

    /// Returns `true` if verifying the proposal has already been requested.
    fn has_requested_verify(&self) -> bool {
        self.requested_verify
    }

    /// Attempts to request verification of the proposal.
    ///
    /// Returns `true` if the verify request is marked during this call, or
    /// `false` if verification was already requested.
    fn request_verify(&mut self) -> bool {
        if self.requested_verify {
            return false;
        }
        self.requested_verify = true;
        true
    }

    /// Records the proposal that we produced locally.
    ///
    /// The slot must not already contain a proposal. Recording our proposal
    /// immediately marks it as verified and ensures both build and verify
    /// requests are set so future calls short-circuit.
    fn record_our_proposal(&mut self, replay: bool, proposal: Proposal<D>) {
        assert!(self.proposal.is_none() || replay, "proposal already set");
        self.proposal = Some(proposal);
        self.status = ProposalStatus::Verified;
        self.requested_build = true;
        self.requested_verify = true;
    }

    /// Promotes the slot back to [`ProposalStatus::Verified`] if it was unverified.
    ///
    /// Returns `true` if the status changed, or `false` if it was already in a
    /// different state.
    fn mark_verified(&mut self) -> bool {
        if self.status != ProposalStatus::Unverified {
            return false;
        }
        self.status = ProposalStatus::Verified;
        true
    }

    /// Updates the slot with a proposal observed from the network or replay.
    ///
    /// Returns a [`ProposalChange`] describing how the slot was mutated.
    ///
    /// When `certificate` is `true`, the provided proposal is considered authoritative
    /// and should override any conflicting votes that may have already been tracked.
    fn update(&mut self, proposal: &Proposal<D>, certificate: bool) -> ProposalChange<D> {
        if self.status == ProposalStatus::Replaced && !certificate {
            return ProposalChange::Skipped;
        }

        match &self.proposal {
            Some(current) if *current == *proposal => {
                if certificate {
                    self.status = ProposalStatus::Verified;
                }
                ProposalChange::Unchanged
            }
            Some(current) => {
                let new = proposal.clone();
                self.status = ProposalStatus::Replaced;
                if certificate {
                    let previous = self
                        .proposal
                        .replace(new.clone())
                        .expect("existing proposal must be present");
                    ProposalChange::Replaced { previous, new }
                } else {
                    ProposalChange::Replaced {
                        previous: new,
                        new: current.clone(),
                    }
                }
            }
            None => {
                self.proposal = Some(proposal.clone());
                if certificate {
                    self.status = ProposalStatus::Verified;
                } else {
                    self.status = ProposalStatus::Unverified;
                }
                ProposalChange::New
            }
        }
    }
}

/// A round of consensus.
struct Round<E: Clock, S: Scheme, D: Digest> {
    start: SystemTime,
    scheme: S,

    round: Rnd,

    // Leader is set as soon as we know the seed for the view (if any).
    leader: Option<Leader<S::PublicKey>>,

    // We explicitly distinguish between the proposal being verified (we checked it)
    // and the proposal being recovered (network has determined its validity). As a sanity
    // check, we'll never notarize or finalize a proposal that we did not verify.
    //
    // We will, however, construct a notarization or finalization (if we have enough partial
    // signatures of either) even if we did not verify the proposal.
    proposal: ProposalSlot<D>,

    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,

    // We only receive verified notarizes for the leader's proposal, so we don't
    // need to track multiple proposals here.
    notarizes: AttributableMap<Notarize<S, D>>,
    notarization: Option<Notarization<S, D>>,
    broadcast_notarize: bool,
    broadcast_notarization: bool,

    // Track nullifies (ensuring any participant only has one recorded nullify)
    nullifies: AttributableMap<Nullify<S>>,
    nullification: Option<Nullification<S>>,
    broadcast_nullify: bool,
    broadcast_nullification: bool,

    // We only receive verified finalizes for the leader's proposal, so we don't
    // need to track multiple proposals here.
    finalizes: AttributableMap<Finalize<S, D>>,
    finalization: Option<Finalization<S, D>>,
    broadcast_finalize: bool,
    broadcast_finalization: bool,

    recover_latency: histogram::Timed<E>,
}

impl<E: Clock, S: Scheme, D: Digest> Round<E, S, D> {
    pub fn new(
        context: &ContextCell<E>,
        scheme: S,
        recover_latency: histogram::Timed<E>,
        round: Rnd,
    ) -> Self {
        // On restart, we may both see a notarize/nullify/finalize from replaying our journal and from
        // new messages forwarded from the batcher. To ensure we don't wrongly assume we have enough
        // signatures to construct a notarization/nullification/finalization, we use an AttributableMap
        // to ensure we only count a message from a given signer once.
        let participants = scheme.participants().len();
        let notarizes = AttributableMap::new(participants);
        let nullifies = AttributableMap::new(participants);
        let finalizes = AttributableMap::new(participants);

        Self {
            start: context.current(),
            scheme,

            round,

            leader: None,

            proposal: ProposalSlot::new(),

            leader_deadline: None,
            advance_deadline: None,
            nullify_retry: None,

            notarizes,
            notarization: None,
            broadcast_notarize: false,
            broadcast_notarization: false,

            nullifies,
            nullification: None,
            broadcast_nullify: false,
            broadcast_nullification: false,

            finalizes,
            finalization: None,
            broadcast_finalize: false,
            broadcast_finalization: false,

            recover_latency,
        }
    }

    fn leader(&self) -> Option<Leader<S::PublicKey>> {
        self.leader.clone()
    }

    fn clear_votes(&mut self) {
        self.notarizes.clear();
        self.finalizes.clear();
    }

    fn record_equivocation_and_clear(&mut self) -> Option<S::PublicKey> {
        self.clear_votes();
        self.leader().map(|leader| leader.key)
    }

    fn clear_deadlines(&mut self) {
        self.leader_deadline = None;
        self.advance_deadline = None;
    }

    pub fn set_leader(&mut self, seed: Option<S::Seed>) {
        let (leader, leader_idx) =
            select_leader::<S, _>(self.scheme.participants().as_ref(), self.round, seed);
        debug!(round=?self.round, ?leader, ?leader_idx, "leader elected");

        self.leader = Some(Leader {
            idx: leader_idx,
            key: leader,
        });
    }

    /// Returns the equivocator if the new proposal overrides an existing one.
    fn add_recovered_proposal(&mut self, proposal: Proposal<D>) -> Option<S::PublicKey> {
        match self.proposal.update(&proposal, true) {
            ProposalChange::New => {
                debug!(?proposal, "setting verified proposal from certificate");
                None
            }
            ProposalChange::Replaced { previous, new } => {
                let equivocator = self.record_equivocation_and_clear();
                warn!(
                    ?equivocator,
                    ?new,
                    ?previous,
                    "certificate proposal overrides local proposal (equivocation detected)"
                );
                equivocator
            }
            ProposalChange::Unchanged | ProposalChange::Skipped => None,
        }
    }

    async fn add_verified_notarize(&mut self, notarize: Notarize<S, D>) -> Option<S::PublicKey> {
        match self.proposal.update(&notarize.proposal, false) {
            ProposalChange::New | ProposalChange::Unchanged => {}
            ProposalChange::Replaced { previous, new } => {
                let equivocator = self.record_equivocation_and_clear();
                warn!(
                    ?equivocator,
                    ?new,
                    ?previous,
                    "notarize conflicts with certificate proposal (equivocation detected)"
                );
                return equivocator;
            }
            ProposalChange::Skipped => return None,
        }
        self.notarizes.insert(notarize);
        None
    }

    async fn add_verified_nullify(&mut self, nullify: Nullify<S>) {
        // We don't consider a nullify vote as being active.
        self.nullifies.insert(nullify);
    }

    async fn add_verified_finalize(&mut self, finalize: Finalize<S, D>) -> Option<S::PublicKey> {
        match self.proposal.update(&finalize.proposal, false) {
            ProposalChange::New | ProposalChange::Unchanged => {}
            ProposalChange::Replaced { previous, new } => {
                let equivocator = self.record_equivocation_and_clear();
                warn!(
                    ?equivocator,
                    ?new,
                    ?previous,
                    "finalize conflicts with certificate proposal (equivocation detected)"
                );
                return equivocator;
            }
            ProposalChange::Skipped => return None,
        }
        self.finalizes.insert(finalize);
        None
    }

    fn add_verified_notarization(
        &mut self,
        notarization: Notarization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        if self.notarization.is_some() {
            return (false, None);
        }

        // Clear leader and advance deadlines (if they exist)
        self.clear_deadlines();

        // If proposal is missing or unverified, set it. If it conflicts with existing proposal, record equivocation.
        let equivocator = self.add_recovered_proposal(notarization.proposal.clone());

        // Store notarization
        self.notarization = Some(notarization);
        (true, equivocator)
    }

    fn add_verified_nullification(&mut self, nullification: Nullification<S>) -> bool {
        // If already have nullification, ignore
        if self.nullification.is_some() {
            return false;
        }

        // Clear leader and advance deadlines (if they exist)
        self.clear_deadlines();

        // Store the nullification
        self.nullification = Some(nullification);
        true
    }

    fn add_verified_finalization(
        &mut self,
        finalization: Finalization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        if self.finalization.is_some() {
            return (false, None);
        }

        // Clear leader and advance deadlines (if they exist)
        self.clear_deadlines();

        // If proposal is missing or unverified, set it. If it conflicts with existing proposal, record equivocation.
        let equivocator = self.add_recovered_proposal(finalization.proposal.clone());

        // Store finalization
        self.finalization = Some(finalization);
        (true, equivocator)
    }

    async fn notarizable(&mut self, force: bool) -> Option<Notarization<S, D>> {
        // Ensure we haven't already broadcast
        if !force && (self.broadcast_notarization || self.broadcast_nullification) {
            // We want to broadcast a notarization, even if we haven't yet verified a proposal.
            return None;
        }

        // If already constructed, return
        if let Some(notarization) = &self.notarization {
            self.broadcast_notarization = true;
            return Some(notarization.clone());
        }

        // Attempt to construct notarization
        let quorum = self.scheme.participants().quorum() as usize;
        if self.notarizes.len() < quorum {
            return None;
        }

        // Construct notarization
        let mut timer = self.recover_latency.timer();
        let notarization = Notarization::from_notarizes(&self.scheme, self.notarizes.iter())
            .expect("failed to recover notarization certificate");
        timer.observe();

        self.broadcast_notarization = true;
        Some(notarization)
    }

    async fn nullifiable(&mut self, force: bool) -> Option<Nullification<S>> {
        // Ensure we haven't already broadcast
        if !force && (self.broadcast_nullification || self.broadcast_notarization) {
            return None;
        }

        // If already constructed, return
        if let Some(nullification) = &self.nullification {
            self.broadcast_nullification = true;
            return Some(nullification.clone());
        }

        // Attempt to construct nullification
        let quorum = self.scheme.participants().quorum() as usize;
        if self.nullifies.len() < quorum {
            return None;
        }

        // Construct nullification
        let mut timer = self.recover_latency.timer();
        let nullification = Nullification::from_nullifies(&self.scheme, self.nullifies.iter())
            .expect("failed to recover nullification certificate");
        timer.observe();

        self.broadcast_nullification = true;
        Some(nullification)
    }

    async fn finalizable(&mut self, force: bool) -> Option<Finalization<S, D>> {
        // Ensure we haven't already broadcast
        if !force && self.broadcast_finalization {
            // We want to broadcast a finalization, even if we haven't yet verified a proposal.
            return None;
        }

        // If already constructed, return
        if let Some(finalization) = &self.finalization {
            self.broadcast_finalization = true;
            return Some(finalization.clone());
        }

        // Attempt to construct finalization
        let quorum = self.scheme.participants().quorum() as usize;
        if self.finalizes.len() < quorum {
            return None;
        }

        // It is not possible to have a finalization that does not match the notarization proposal. If this
        // is detected, there is a critical bug or there has been a safety violation.
        if let Some(notarization) = &self.notarization {
            let proposal = self.proposal.proposal().expect("proposal missing");
            assert_eq!(
                notarization.proposal, *proposal,
                "finalization proposal does not match notarization"
            );
        }

        // Construct finalization
        let mut timer = self.recover_latency.timer();
        let finalization = Finalization::from_finalizes(&self.scheme, self.finalizes.iter())
            .expect("failed to recover finalization certificate");
        timer.observe();

        self.broadcast_finalization = true;
        Some(finalization)
    }

    /// Returns true if the votes for this proposal imply that its ancestry is valid.
    ///
    /// We use this status to determine if we should backfill missing certificates implied by
    /// the proposal (if any).
    ///
    /// We determine support by checking if at least one honest participant notarized the proposal for
    /// this view. That is, if any of the following are true:
    /// - a finalization for this view exists, or
    /// - a notarization certificate for this view exists, or
    /// - the number of notarize votes exceeds the maximum number of faulty participants.
    pub fn proposal_ancestry_supported(&self) -> bool {
        // While this check is not strictly necessary, it's a good sanity check.
        if self.proposal.proposal().is_none() {
            return false;
        }

        if self.finalization.is_some() {
            return true;
        }
        if self.notarization.is_some() {
            return true;
        }

        // If there are more notarizations than the number of faulty nodes,
        // then at least one of the notarizations is from an honest node.
        let max_faults = self.scheme.participants().max_faults() as usize;
        self.notarizes.len() > max_faults
    }
}

pub struct Actor<
    E: Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    A: Automaton<Digest = D, Context = Context<D, P>>,
    R: Relay,
    F: Reporter<Activity = Activity<S, D>>,
> {
    context: ContextCell<E>,
    scheme: S,
    blocker: B,
    automaton: A,
    relay: R,
    reporter: F,

    partition: String,
    replay_buffer: NonZeroUsize,
    write_buffer: NonZeroUsize,
    buffer_pool: PoolRef,
    journal: Option<Journal<E, Voter<S, D>>>,

    genesis: Option<D>,

    epoch: Epoch,
    namespace: Vec<u8>,

    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    activity_timeout: View,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,

    view: View,
    views: BTreeMap<View, Round<E, S, D>>,
    last_finalized: View,

    current_view: Gauge,
    tracked_views: Gauge,
    skipped_views: Counter,
    inbound_messages: Family<Inbound, Counter>,
    outbound_messages: Family<Outbound, Counter>,
    notarization_latency: Histogram,
    finalization_latency: Histogram,
    recover_latency: histogram::Timed<E>,
}

impl<
        E: Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
        P: PublicKey,
        S: Scheme<PublicKey = P>,
        B: Blocker<PublicKey = P>,
        D: Digest,
        A: Automaton<Digest = D, Context = Context<D, P>>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<S, D>>,
    > Actor<E, P, S, B, D, A, R, F>
{
    pub fn new(context: E, cfg: Config<S, B, D, A, R, F>) -> (Self, Mailbox<S, D>) {
        // Assert correctness of timeouts
        if cfg.leader_timeout > cfg.notarization_timeout {
            panic!("leader timeout must be less than or equal to notarization timeout");
        }

        // Initialize metrics
        let current_view = Gauge::<i64, AtomicI64>::default();
        let tracked_views = Gauge::<i64, AtomicI64>::default();
        let skipped_views = Counter::default();
        let inbound_messages = Family::<Inbound, Counter>::default();
        let outbound_messages = Family::<Outbound, Counter>::default();
        let notarization_latency = Histogram::new(LATENCY.into_iter());
        let finalization_latency = Histogram::new(LATENCY.into_iter());
        let recover_latency = Histogram::new(Buckets::CRYPTOGRAPHY.into_iter());
        context.register("current_view", "current view", current_view.clone());
        context.register("tracked_views", "tracked views", tracked_views.clone());
        context.register("skipped_views", "skipped views", skipped_views.clone());
        context.register(
            "inbound_messages",
            "number of inbound messages",
            inbound_messages.clone(),
        );
        context.register(
            "outbound_messages",
            "number of outbound messages",
            outbound_messages.clone(),
        );
        context.register(
            "notarization_latency",
            "notarization latency",
            notarization_latency.clone(),
        );
        context.register(
            "finalization_latency",
            "finalization latency",
            finalization_latency.clone(),
        );
        context.register(
            "recover_latency",
            "certificate recover latency",
            recover_latency.clone(),
        );
        // TODO(#1833): Metrics should use the post-start context
        let clock = Arc::new(context.clone());

        // Initialize store
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        (
            Self {
                context: ContextCell::new(context),
                scheme: cfg.scheme,
                blocker: cfg.blocker,
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,

                partition: cfg.partition,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                buffer_pool: cfg.buffer_pool,
                journal: None,

                genesis: None,

                epoch: cfg.epoch,
                namespace: cfg.namespace,

                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,

                activity_timeout: cfg.activity_timeout,

                mailbox_receiver,

                last_finalized: 0,
                view: 0,
                views: BTreeMap::new(),

                current_view,
                tracked_views,
                skipped_views,
                inbound_messages,
                outbound_messages,
                notarization_latency,
                finalization_latency,
                recover_latency: histogram::Timed::new(recover_latency, clock),
            },
            mailbox,
        )
    }

    fn round_mut(&mut self, view: View) -> &mut Round<E, S, D> {
        self.views.entry(view).or_insert_with(|| {
            Round::new(
                &self.context,
                self.scheme.clone(),
                self.recover_latency.clone(),
                Rnd::new(self.epoch, view),
            )
        })
    }

    fn is_me(scheme: &S, other: u32) -> bool {
        scheme.me().map(|me| me == other).unwrap_or(false)
    }

    fn is_notarized(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(notarization) = &round.notarization {
            return Some(&notarization.proposal.payload);
        }
        let proposal = round.proposal.proposal()?;
        let quorum = self.scheme.participants().quorum() as usize;
        if round.notarizes.len() >= quorum {
            return Some(&proposal.payload);
        }
        None
    }

    fn is_nullified(&self, view: View) -> bool {
        let round = match self.views.get(&view) {
            Some(round) => round,
            None => return false,
        };
        let quorum = self.scheme.participants().quorum() as usize;
        round.nullification.is_some() || round.nullifies.len() >= quorum
    }

    fn is_finalized(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(finalization) = &round.finalization {
            return Some(&finalization.proposal.payload);
        }
        let proposal = round.proposal.proposal()?;
        let quorum = self.scheme.participants().quorum() as usize;
        if round.finalizes.len() >= quorum {
            return Some(&proposal.payload);
        }
        None
    }

    fn find_parent(&self) -> Result<(View, D), View> {
        let mut cursor = self.view - 1; // self.view always at least 1
        loop {
            if cursor == 0 {
                return Ok((GENESIS_VIEW, *self.genesis.as_ref().unwrap()));
            }

            // If have notarization, return
            let parent = self.is_notarized(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, *parent));
            }

            // If have finalization, return
            //
            // We never want to build on some view less than finalized and this prevents that
            let parent = self.is_finalized(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, *parent));
            }

            // If have nullification, continue
            if self.is_nullified(cursor) {
                cursor -= 1;
                continue;
            }

            // We can't find a valid parent, return
            return Err(cursor);
        }
    }

    #[allow(clippy::question_mark)]
    async fn propose(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
    ) -> Option<(Context<D, P>, oneshot::Receiver<D>)> {
        // Check if we are leader
        let round = self.views.get(&self.view).unwrap();
        let leader = round.leader()?;
        if !Self::is_me(&self.scheme, leader.idx) {
            return None;
        }

        // Check if we should build
        if !round.proposal.should_build() {
            return None;
        }

        // Find best parent
        let (parent_view, parent_payload) = match self.find_parent() {
            Ok(parent) => parent,
            Err(view) => {
                debug!(
                    view = self.view,
                    missing = view,
                    "skipping proposal opportunity"
                );
                resolver.fetch(vec![view], vec![view]).await;
                return None;
            }
        };

        // Set building (if some parent is available)
        let round = self.views.get_mut(&self.view).unwrap();
        round.proposal.set_building();

        // Request proposal from application
        debug!(view = self.view, "requested proposal from automaton");
        let context = Context {
            round: Rnd::new(self.epoch, self.view),
            leader: leader.key,
            parent: (parent_view, parent_payload),
        };
        Some((context.clone(), self.automaton.propose(context).await))
    }

    fn timeout_deadline(&mut self) -> SystemTime {
        // Return the earliest deadline
        let view = self.views.get_mut(&self.view).unwrap();
        if let Some(deadline) = view.leader_deadline {
            return deadline;
        }
        if let Some(deadline) = view.advance_deadline {
            return deadline;
        }

        // If no deadlines are still set (waiting for nullify),
        // return next try for nullify.
        if let Some(deadline) = view.nullify_retry {
            return deadline;
        }

        // Set nullify retry, if none already set
        let null_retry = self.context.current() + self.nullify_retry;
        view.nullify_retry = Some(null_retry);
        null_retry
    }

    async fn timeout<Sp: Sender, Sr: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        pending_sender: &mut WrappedSender<Sp, Voter<S, D>>,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
    ) {
        // Set timeout fired
        let round = self.views.get_mut(&self.view).unwrap();
        let retry = replace(&mut round.broadcast_nullify, true);

        // Remove deadlines
        round.clear_deadlines();
        round.nullify_retry = None;

        // If retry, broadcast notarization that led us to enter this view
        let past_view = self.view - 1;
        if retry && past_view > 0 {
            if let Some(finalization) = self.construct_finalization(past_view, true).await {
                self.outbound_messages
                    .get_or_create(metrics::Outbound::finalization())
                    .inc();
                let msg = Voter::Finalization(finalization);
                recovered_sender
                    .send(Recipients::All, msg, true)
                    .await
                    .unwrap();
                debug!(view = past_view, "rebroadcast entry finalization");
            } else if let Some(notarization) = self.construct_notarization(past_view, true).await {
                self.outbound_messages
                    .get_or_create(metrics::Outbound::notarization())
                    .inc();
                let msg = Voter::Notarization(notarization);
                recovered_sender
                    .send(Recipients::All, msg, true)
                    .await
                    .unwrap();
                debug!(view = past_view, "rebroadcast entry notarization");
            } else if let Some(nullification) = self.construct_nullification(past_view, true).await
            {
                self.outbound_messages
                    .get_or_create(metrics::Outbound::nullification())
                    .inc();
                let msg = Voter::Nullification(nullification);
                recovered_sender
                    .send(Recipients::All, msg, true)
                    .await
                    .unwrap();
                debug!(view = past_view, "rebroadcast entry nullification");
            } else {
                warn!(
                    current = self.view,
                    "unable to rebroadcast entry notarization/nullification/finalization"
                );
            }
        }

        // Construct nullify
        let Some(nullify) = Nullify::sign::<D>(
            &self.scheme,
            &self.namespace,
            Rnd::new(self.epoch, self.view),
        ) else {
            return;
        };

        // Handle the nullify
        if !retry {
            batcher.constructed(Voter::Nullify(nullify.clone())).await;
            self.handle_nullify(nullify.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(self.view)
                .await
                .expect("unable to sync journal");
        }

        // Broadcast nullify
        self.outbound_messages
            .get_or_create(metrics::Outbound::nullify())
            .inc();
        debug!(round=?nullify.round(), "broadcasting nullify");
        let msg = Voter::Nullify(nullify);
        pending_sender
            .send(Recipients::All, msg, true)
            .await
            .unwrap();
    }

    async fn handle_nullify(&mut self, nullify: Nullify<S>) {
        // Get view for nullify
        let view = nullify.view();

        // Handle nullify
        if let Some(journal) = self.journal.as_mut() {
            let msg = Voter::Nullify(nullify.clone());
            journal
                .append(view, msg)
                .await
                .expect("unable to append nullify");
        }

        // Create round (if it doesn't exist) and add verified nullify
        self.round_mut(view).add_verified_nullify(nullify).await
    }

    async fn our_proposal(&mut self, proposal: Proposal<D>) -> bool {
        // Store the proposal
        let round = self.views.get_mut(&proposal.view()).expect("view missing");

        // Check if view timed out
        if round.broadcast_nullify {
            debug!(
                ?proposal,
                reason = "view timed out",
                "dropping our proposal"
            );
            return false;
        }

        // Store the proposal
        debug!(?proposal, "generated proposal");
        round.proposal.record_our_proposal(false, proposal);
        round.leader_deadline = None;
        true
    }

    // Attempt to set proposal from each message received over the wire
    #[allow(clippy::question_mark)]
    async fn peer_proposal(&mut self) -> Option<(Context<D, P>, oneshot::Receiver<bool>)> {
        // Get round
        let (proposal, leader) = {
            // Get view or exit
            let round = self.views.get(&self.view)?;

            // If we are the leader, drop peer proposals
            let Some(leader) = round.leader() else {
                debug!(
                    view = self.view,
                    "dropping peer proposal because leader is not set"
                );
                return None;
            };
            if Self::is_me(&self.scheme, leader.idx) {
                return None;
            }

            // If we already broadcast nullify or set proposal, do nothing
            if round.broadcast_nullify {
                return None;
            }
            if round.proposal.has_requested_verify() {
                return None;
            }

            // Check if leader has signed a digest
            let Some(proposal) = round.proposal.proposal() else {
                return None;
            };

            // Sanity-check the epoch is correct. It should have already been checked.
            assert_eq!(proposal.epoch(), self.epoch, "proposal epoch mismatch");

            // Check parent validity
            if proposal.view() <= proposal.parent {
                debug!(
                    round = ?proposal.round,
                    parent = proposal.parent,
                    "dropping peer proposal because parent is invalid"
                );
                return None;
            }
            if proposal.parent < self.last_finalized {
                debug!(
                    round = ?proposal.round,
                    parent = proposal.parent,
                    last_finalized = self.last_finalized,
                    "dropping peer proposal because parent is less than last finalized"
                );
                return None;
            }
            (proposal, leader)
        };

        // Ensure we have required notarizations
        let mut cursor = match self.view {
            0 => {
                return None;
            }
            _ => self.view - 1,
        };
        let parent_payload = loop {
            if cursor == proposal.parent {
                // Check if first block
                if proposal.parent == GENESIS_VIEW {
                    break self.genesis.as_ref().unwrap();
                }

                // Check notarization exists
                let parent_proposal = match self.is_notarized(cursor) {
                    Some(parent) => parent,
                    None => {
                        debug!(view = cursor, "parent proposal is not notarized");
                        return None;
                    }
                };

                // Peer proposal references a valid parent
                break parent_proposal;
            }

            // Check nullification exists in gap
            if !self.is_nullified(cursor) {
                debug!(
                    view = cursor,
                    "missing nullification during proposal verification"
                );
                return None;
            }
            cursor -= 1;
        };

        // Request verification
        debug!(?proposal, "requested proposal verification",);
        let context = Context {
            round: proposal.round,
            leader: leader.key,
            parent: (proposal.parent, *parent_payload),
        };
        let proposal = proposal.clone();
        let payload = proposal.payload;
        let round = self.views.get_mut(&context.view()).unwrap();
        round.proposal.request_verify();
        Some((
            context.clone(),
            self.automaton.verify(context, payload).await,
        ))
    }

    async fn verified(&mut self, view: View) -> bool {
        // Check if view still relevant
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return false;
            }
        };

        // Ensure we haven't timed out
        if round.broadcast_nullify {
            debug!(
                round=?round.round,
                reason = "view timed out",
                "dropping verified proposal"
            );
            return false;
        }

        // Only proceed with verification if the proposal is currently unverified.
        // If status is None, Verified, or Replaced, the verification request is no longer valid.
        if !round.proposal.mark_verified() {
            return false;
        }

        // Mark proposal as verified
        round.leader_deadline = None;

        // Indicate that verification is done
        debug!(
            round=?round.round,
            proposal=?round.proposal.proposal(),
            "verified proposal"
        );
        true
    }

    fn since_view_start(&self, view: u64) -> Option<(bool, f64)> {
        let round = self.views.get(&view)?;
        let Ok(elapsed) = self.context.current().duration_since(round.start) else {
            return None;
        };
        Some((
            Self::is_me(&self.scheme, round.leader()?.idx),
            elapsed.as_secs_f64(),
        ))
    }

    fn enter_view(&mut self, view: u64, seed: Option<S::Seed>) {
        // Ensure view is valid
        if view <= self.view {
            trace!(
                view = view,
                our_view = self.view,
                "skipping useless view change"
            );
            return;
        }

        // Setup new view
        let leader_deadline = self.context.current() + self.leader_timeout;
        let advance_deadline = self.context.current() + self.notarization_timeout;
        let round = self.round_mut(view);
        round.leader_deadline = Some(leader_deadline);
        round.advance_deadline = Some(advance_deadline);
        round.set_leader(seed);
        self.view = view;

        // Update metrics
        self.current_view.set(view as i64);
    }

    async fn prune_views(&mut self) {
        // Get last min
        let min = min_active(self.activity_timeout, self.last_finalized);
        let mut pruned = false;
        loop {
            // Get next key
            let next = match self.views.keys().next() {
                Some(next) => *next,
                None => return,
            };

            // If less than min, prune
            if next >= min {
                break;
            }
            self.views.remove(&next);
            debug!(
                view = next,
                last_finalized = self.last_finalized,
                "pruned view"
            );
            pruned = true;
        }

        // Prune journal up to min
        if pruned {
            self.journal
                .as_mut()
                .unwrap()
                .prune(min)
                .await
                .expect("unable to prune journal");
        }

        // Update metrics
        self.tracked_views.set(self.views.len() as i64);
    }

    async fn handle_notarize(&mut self, notarize: Notarize<S, D>) {
        // Get view for notarize
        let view = notarize.view();

        // Handle notarize
        if let Some(journal) = self.journal.as_mut() {
            let msg = Voter::Notarize(notarize.clone());
            journal
                .append(view, msg)
                .await
                .expect("unable to append to journal");
        }

        // Create round (if it doesn't exist) and add verified notarize
        let equivocator = self.round_mut(view).add_verified_notarize(notarize).await;
        self.block_equivocator(equivocator).await;
    }

    async fn notarization(&mut self, notarization: Notarization<S, D>) -> Action {
        // Check if we are still in a view where this notarization could help
        let view = notarization.view();
        if !interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            view,
            true,
        ) {
            return Action::Skip;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&view) {
            if round.broadcast_notarization {
                return Action::Skip;
            }
        }

        // Verify notarization
        if !notarization.verify(&mut self.context, &self.scheme, &self.namespace) {
            return Action::Block;
        }

        // Handle notarization
        self.handle_notarization(notarization).await;
        Action::Process
    }

    async fn handle_notarization(&mut self, notarization: Notarization<S, D>) {
        // Get view for notarization
        let view = notarization.view();

        // Store notarization
        let msg = Voter::Notarization(notarization.clone());
        let seed = self
            .scheme
            .seed(notarization.round(), &notarization.certificate);

        // Create round (if it doesn't exist) and add verified notarization
        let (added, equivocator) = self.round_mut(view).add_verified_notarization(notarization);
        if added {
            if let Some(journal) = self.journal.as_mut() {
                journal
                    .append(view, msg)
                    .await
                    .expect("unable to append to journal");
            }
        }
        self.block_equivocator(equivocator).await;

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn nullification(&mut self, nullification: Nullification<S>) -> Action {
        // Check if we are still in a view where this notarization could help
        if !interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            nullification.view(),
            true,
        ) {
            return Action::Skip;
        }

        // Determine if we already broadcast nullification for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&nullification.view()) {
            if round.broadcast_nullification {
                return Action::Skip;
            }
        }

        // Verify nullification
        if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.namespace) {
            return Action::Block;
        }

        // Handle notarization
        self.handle_nullification(nullification).await;
        Action::Process
    }

    async fn handle_nullification(&mut self, nullification: Nullification<S>) {
        // Store nullification
        let msg = Voter::Nullification(nullification.clone());
        let seed = self
            .scheme
            .seed(nullification.round, &nullification.certificate);

        // Create round (if it doesn't exist) and add verified nullification
        let view = nullification.view();
        if self
            .round_mut(view)
            .add_verified_nullification(nullification)
        {
            if let Some(journal) = self.journal.as_mut() {
                journal
                    .append(view, msg)
                    .await
                    .expect("unable to append to journal");
            }
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn handle_finalize(&mut self, finalize: Finalize<S, D>) {
        // Get view for finalize
        let view = finalize.view();

        // Handle finalize
        if let Some(journal) = self.journal.as_mut() {
            let msg = Voter::Finalize(finalize.clone());
            journal
                .append(view, msg)
                .await
                .expect("unable to append to journal");
        }

        // Create round (if it doesn't exist) and add verified finalize
        let equivocator = self.round_mut(view).add_verified_finalize(finalize).await;
        self.block_equivocator(equivocator).await;
    }

    async fn finalization(&mut self, finalization: Finalization<S, D>) -> Action {
        // Check if we are still in a view where this finalization could help
        let view = finalization.view();
        if !interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            view,
            true,
        ) {
            return Action::Skip;
        }

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&view) {
            if round.broadcast_finalization {
                return Action::Skip;
            }
        }

        // Verify finalization
        if !finalization.verify(&mut self.context, &self.scheme, &self.namespace) {
            return Action::Block;
        }

        // Process finalization
        self.handle_finalization(finalization).await;
        Action::Process
    }

    async fn handle_finalization(&mut self, finalization: Finalization<S, D>) {
        // Store finalization
        let msg = Voter::Finalization(finalization.clone());
        let seed = self
            .scheme
            .seed(finalization.round(), &finalization.certificate);

        // Create round (if it doesn't exist) and add verified finalization
        let view = finalization.view();
        let (added, equivocator) = self.round_mut(view).add_verified_finalization(finalization);
        if added {
            if let Some(journal) = self.journal.as_mut() {
                journal
                    .append(view, msg)
                    .await
                    .expect("unable to append to journal");
            }
        }
        self.block_equivocator(equivocator).await;

        // Track view finalized
        if view > self.last_finalized {
            self.last_finalized = view;
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    fn construct_notarize(&mut self, view: u64) -> Option<Notarize<S, D>> {
        // Determine if it makes sense to broadcast a notarize
        let round = self.views.get_mut(&view)?;
        if round.broadcast_notarize {
            return None;
        }
        if round.broadcast_nullify {
            return None;
        }
        if round.proposal.status() != ProposalStatus::Verified {
            // We have replaced the proposal or it's not verified, so the votes we are tracking make no sense.
            return None;
        }
        round.broadcast_notarize = true;

        // Construct notarize
        let proposal = round.proposal.proposal().expect("proposal missing");
        Notarize::sign(&self.scheme, &self.namespace, proposal.clone())
    }

    async fn construct_notarization(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Notarization<S, D>> {
        // Get requested view
        let round = self.views.get_mut(&view)?;

        // Attempt to construct notarization
        round.notarizable(force).await
    }

    async fn construct_nullification(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Nullification<S>> {
        // Get requested view
        let round = self.views.get_mut(&view)?;

        // Attempt to construct nullification
        round.nullifiable(force).await
    }

    fn construct_finalize(&mut self, view: u64) -> Option<Finalize<S, D>> {
        // Determine if it makes sense to broadcast a finalize
        let round = self.views.get_mut(&view)?;
        if round.broadcast_finalize {
            return None;
        }
        if round.broadcast_nullify {
            return None;
        }
        if !round.broadcast_notarize {
            // Ensure we broadcast notarize before we finalize
            return None;
        }
        if !round.broadcast_notarization {
            // Ensure we broadcast notarization before we finalize
            return None;
        }
        if round.proposal.status() != ProposalStatus::Verified {
            // We have replaced the proposal or it's not verified, so the votes we are tracking make no sense.
            return None;
        }
        round.broadcast_finalize = true;

        // Construct finalize
        let proposal = round.proposal.proposal().expect("proposal missing");
        Finalize::sign(&self.scheme, &self.namespace, proposal.clone())
    }

    async fn construct_finalization(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Finalization<S, D>> {
        let round = self.views.get_mut(&view)?;

        // Attempt to construct finalization
        round.finalizable(force).await
    }

    async fn block_equivocator(&mut self, equivocator: Option<S::PublicKey>) {
        if let Some(equivocator) = equivocator {
            warn!(?equivocator, "blocking equivocator");
            self.blocker.block(equivocator).await;
        }
    }

    async fn notify<Sp: Sender, Sr: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        resolver: &mut resolver::Mailbox<S, D>,
        pending_sender: &mut WrappedSender<Sp, Voter<S, D>>,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
        view: u64,
    ) {
        // Attempt to notarize
        if let Some(notarize) = self.construct_notarize(view) {
            // Handle the notarize
            self.outbound_messages
                .get_or_create(metrics::Outbound::notarize())
                .inc();
            batcher.constructed(Voter::Notarize(notarize.clone())).await;
            self.handle_notarize(notarize.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the notarize
            debug!(round=?notarize.round(), proposal=?notarize.proposal, "broadcasting notarize");
            let msg = Voter::Notarize(notarize);
            pending_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();
        };

        // Attempt to notarization
        if let Some(notarization) = self.construct_notarization(view, false).await {
            // Record latency if we are the leader (only way to get unbiased observation)
            if let Some((leader, elapsed)) = self.since_view_start(view) {
                if leader {
                    self.notarization_latency.observe(elapsed);
                }
            }

            // Update resolver
            resolver.notarized(notarization.clone()).await;

            // Handle the notarization
            self.outbound_messages
                .get_or_create(metrics::Outbound::notarization())
                .inc();
            self.handle_notarization(notarization.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Alert application
            self.reporter
                .report(Activity::Notarization(notarization.clone()))
                .await;

            // Broadcast the notarization
            debug!(proposal=?notarization.proposal, "broadcasting notarization");
            let msg = Voter::Notarization(notarization.clone());
            recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();
        };

        // Attempt to nullification
        //
        // We handle broadcast of nullify in `timeout`.
        if let Some(nullification) = self.construct_nullification(view, false).await {
            // Update resolver
            resolver.nullified(nullification.clone()).await;

            // Handle the nullification
            self.outbound_messages
                .get_or_create(metrics::Outbound::nullification())
                .inc();
            self.handle_nullification(nullification.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Alert application
            self.reporter
                .report(Activity::Nullification(nullification.clone()))
                .await;

            // Broadcast the nullification
            debug!(round=?nullification.round(), "broadcasting nullification");
            let msg = Voter::Nullification(nullification.clone());
            recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();

            // If the view isn't yet finalized and at least one honest node notarized a proposal in this view,
            // then backfill any missing certificates.
            let round = self.views.get(&view).expect("missing round");
            if view > self.last_finalized && round.proposal_ancestry_supported() {
                // Compute certificates that we know are missing
                let parent = round.proposal.proposal().expect("proposal missing").parent;
                let missing_notarizations = match self.is_notarized(parent) {
                    Some(_) => Vec::new(),
                    None if parent == GENESIS_VIEW => Vec::new(),
                    None => vec![parent],
                };
                let missing_nullifications = ((parent + 1)..view)
                    .filter(|v| !self.is_nullified(*v))
                    .collect::<Vec<_>>();

                // Fetch any missing certificates
                if !missing_notarizations.is_empty() || !missing_nullifications.is_empty() {
                    warn!(
                        proposal_view = view,
                        parent,
                        ?missing_notarizations,
                        ?missing_nullifications,
                        ">= 1 honest notarize for nullified parent"
                    );
                    resolver
                        .fetch(missing_notarizations, missing_nullifications)
                        .await;
                }
            }
        }

        // Attempt to finalize
        if let Some(finalize) = self.construct_finalize(view) {
            // Handle the finalize
            self.outbound_messages
                .get_or_create(metrics::Outbound::finalize())
                .inc();
            batcher.constructed(Voter::Finalize(finalize.clone())).await;
            self.handle_finalize(finalize.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the finalize
            debug!(round=?finalize.round(), proposal=?finalize.proposal, "broadcasting finalize");
            let msg = Voter::Finalize(finalize);
            pending_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();
        };

        // Attempt to finalization
        if let Some(finalization) = self.construct_finalization(view, false).await {
            // Record latency if we are the leader (only way to get unbiased observation)
            if let Some((leader, elapsed)) = self.since_view_start(view) {
                if leader {
                    self.finalization_latency.observe(elapsed);
                }
            }

            // Update resolver
            resolver.finalized(view).await;

            // Handle the finalization
            self.outbound_messages
                .get_or_create(metrics::Outbound::finalization())
                .inc();
            self.handle_finalization(finalization.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Alert application
            self.reporter
                .report(Activity::Finalization(finalization.clone()))
                .await;

            // Broadcast the finalization
            debug!(proposal=?finalization.proposal, "broadcasting finalization");
            let msg = Voter::Finalization(finalization.clone());
            recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();
        };
    }

    pub fn start(
        mut self,
        batcher: batcher::Mailbox<S, D>,
        resolver: resolver::Mailbox<S, D>,
        pending_sender: impl Sender<PublicKey = P>,
        recovered_sender: impl Sender<PublicKey = P>,
        recovered_receiver: impl Receiver<PublicKey = P>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(
                batcher,
                resolver,
                pending_sender,
                recovered_sender,
                recovered_receiver
            )
            .await
        )
    }

    async fn run(
        mut self,
        mut batcher: batcher::Mailbox<S, D>,
        mut resolver: resolver::Mailbox<S, D>,
        pending_sender: impl Sender<PublicKey = P>,
        recovered_sender: impl Sender<PublicKey = P>,
        recovered_receiver: impl Receiver<PublicKey = P>,
    ) {
        // Wrap channel
        let mut pending_sender = WrappedSender::new(pending_sender);
        let (mut recovered_sender, mut recovered_receiver) = wrap::<_, _, Voter<S, D>>(
            self.scheme.certificate_codec_config(),
            recovered_sender,
            recovered_receiver,
        );

        // Compute genesis
        let genesis = self.automaton.genesis(self.epoch).await;
        self.genesis = Some(genesis);

        // Add initial view
        //
        // We start on view 1 because the genesis container occupies view 0/height 0.
        self.enter_view(1, None);

        // Initialize journal
        let journal = Journal::<_, Voter<S, D>>::init(
            self.context.with_label("journal").into(),
            JConfig {
                partition: self.partition.clone(),
                compression: None, // most of the data is not compressible
                codec_config: self.scheme.certificate_codec_config(),
                buffer_pool: self.buffer_pool.clone(),
                write_buffer: self.write_buffer,
            },
        )
        .await
        .expect("unable to open journal");

        // Rebuild from journal
        let start = self.context.current();
        {
            let stream = journal
                .replay(0, 0, self.replay_buffer)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);
            while let Some(msg) = stream.next().await {
                let (_, _, _, msg) = msg.expect("unable to replay journal");
                let view = msg.view();
                match msg {
                    Voter::Notarize(notarize) => {
                        // Handle notarize
                        let public_key_index = notarize.signer();
                        let proposal = notarize.proposal.clone();
                        self.handle_notarize(notarize.clone()).await;
                        self.reporter.report(Activity::Notarize(notarize)).await;

                        // Update round info
                        if Self::is_me(&self.scheme, public_key_index) {
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.proposal.record_our_proposal(true, proposal); // we bypass the proposal check because we just set it above
                            round.broadcast_notarize = true;
                        }
                    }
                    Voter::Notarization(notarization) => {
                        // Handle notarization
                        self.handle_notarization(notarization.clone()).await;
                        self.reporter
                            .report(Activity::Notarization(notarization))
                            .await;

                        // Update round info
                        let round = self.views.get_mut(&view).expect("missing round");
                        round.broadcast_notarization = true;
                    }
                    Voter::Nullify(nullify) => {
                        // Handle nullify
                        let public_key_index = nullify.signer();
                        self.handle_nullify(nullify.clone()).await;
                        self.reporter.report(Activity::Nullify(nullify)).await;

                        // Update round info
                        if Self::is_me(&self.scheme, public_key_index) {
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_nullify = true;
                        }
                    }
                    Voter::Nullification(nullification) => {
                        // Handle nullification
                        self.handle_nullification(nullification.clone()).await;
                        self.reporter
                            .report(Activity::Nullification(nullification))
                            .await;

                        // Update round info
                        let round = self.views.get_mut(&view).expect("missing round");
                        round.broadcast_nullification = true;
                    }
                    Voter::Finalize(finalize) => {
                        // Handle finalize
                        let public_key_index = finalize.signer();
                        self.handle_finalize(finalize.clone()).await;
                        self.reporter.report(Activity::Finalize(finalize)).await;

                        // Update round info
                        //
                        // If we are sending a finalize message, we must be in the next view
                        if Self::is_me(&self.scheme, public_key_index) {
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_finalize = true;
                        }
                    }
                    Voter::Finalization(finalization) => {
                        // Handle finalization
                        self.handle_finalization(finalization.clone()).await;
                        self.reporter
                            .report(Activity::Finalization(finalization))
                            .await;

                        // Update round info
                        let round = self.views.get_mut(&view).expect("missing round");
                        round.broadcast_finalization = true;
                    }
                }
            }
        }
        self.journal = Some(journal);

        // Update current view and immediately move to timeout (very unlikely we restarted and still within timeout)
        let end = self.context.current();
        let elapsed = end.duration_since(start).unwrap_or_default();
        let observed_view = self.view;
        info!(
            current_view = observed_view,
            ?elapsed,
            "consensus initialized"
        );
        {
            let round = self.views.get_mut(&observed_view).expect("missing round");
            round.leader_deadline = Some(self.context.current());
            round.advance_deadline = Some(self.context.current());
        }
        self.current_view.set(observed_view as i64);
        self.tracked_views.set(self.views.len() as i64);

        // Initialize verifier with leader
        let round = self.views.get_mut(&observed_view).expect("missing round");
        let leader = round.leader().expect("leader not set").idx;
        batcher
            .update(observed_view, leader, self.last_finalized)
            .await;

        // Create shutdown tracker
        let mut shutdown = self.context.stopped();

        // Process messages
        let mut pending_set = None;
        let mut pending_propose_context = None;
        let mut pending_propose = None;
        let mut pending_verify_context = None;
        let mut pending_verify = None;
        loop {
            // Reset pending set if we have moved to a new view
            if let Some(view) = pending_set {
                if view != self.view {
                    pending_set = None;
                    pending_propose_context = None;
                    pending_propose = None;
                    pending_verify_context = None;
                    pending_verify = None;
                }
            }

            // Attempt to propose a container
            if let Some((context, new_propose)) = self.propose(&mut resolver).await {
                pending_set = Some(self.view);
                pending_propose_context = Some(context);
                pending_propose = Some(new_propose);
            }
            let propose_wait = match &mut pending_propose {
                Some(propose) => Either::Left(propose),
                None => Either::Right(futures::future::pending()),
            };

            // Attempt to verify current view
            if let Some((context, new_verify)) = self.peer_proposal().await {
                pending_set = Some(self.view);
                pending_verify_context = Some(context);
                pending_verify = Some(new_verify);
            }
            let verify_wait = match &mut pending_verify {
                Some(verify) => Either::Left(verify),
                None => Either::Right(futures::future::pending()),
            };

            // Wait for a timeout to fire or for a message to arrive
            let timeout = self.timeout_deadline();
            let start = self.view;
            let view;
            select! {
                _ = &mut shutdown => {
                    // Close journal
                    self.journal
                        .take()
                        .unwrap()
                        .close()
                        .await
                        .expect("unable to close journal");
                    return;
                },
                _ = self.context.sleep_until(timeout) => {
                    // Trigger the timeout
                    self.timeout(&mut batcher, &mut pending_sender, &mut recovered_sender).await;
                    view = self.view;
                },
                proposed = propose_wait => {
                    // Clear propose waiter
                    let context = pending_propose_context.take().unwrap();
                    pending_propose = None;

                    // Try to use result
                    let proposed = match proposed {
                        Ok(proposed) => proposed,
                        Err(err) => {
                            debug!(?err, round = ?context.round, "failed to propose container");
                            continue;
                        }
                    };

                    // If we have already moved to another view, drop the response as we will
                    // not broadcast it
                    let our_round = Rnd::new(self.epoch, self.view);
                    if our_round != context.round {
                        debug!(round = ?context.round, ?our_round, reason = "no longer in required view", "dropping requested proposal");
                        continue;
                    }

                    // Construct proposal
                    let proposal = Proposal::new(
                        context.round,
                        context.parent.0,
                        proposed,
                    );
                    if !self.our_proposal(proposal).await {
                        warn!(round = ?context.round, "dropped our proposal");
                        continue;
                    }
                    view = self.view;

                    // Notify application of proposal
                    self.relay.broadcast(proposed).await;
                },
                verified = verify_wait => {
                    // Clear verify waiter
                    let context = pending_verify_context.take().unwrap();
                    pending_verify = None;

                    // Try to use result
                    match verified {
                        Ok(verified) => {
                            if !verified {
                                debug!(round = ?context.round, "proposal failed verification");
                                continue;
                            }
                        },
                        Err(err) => {
                            debug!(?err, round = ?context.round, "failed to verify proposal");
                            continue;
                        }
                    };

                    // Handle verified proposal
                    view = context.view();
                    if !self.verified(view).await {
                        continue;
                    }
                },
                mailbox = self.mailbox_receiver.next() => {
                    // Extract message
                    let Some(msg) = mailbox else {
                        break;
                    };
                    let Message::Verified(msg) = msg;

                    // Ensure view is still useful.
                    //
                    // It is possible that we make a request to the resolver and prune the view
                    // before we receive the response. In this case, we should ignore the response (not
                    // doing so may result in attempting to store before the prune boundary).
                    //
                    // We do not need to allow `future` here because any notarization or nullification we see
                    // here must've been requested by us (something we only do when ahead of said view).
                    view = msg.view();
                    if !interesting(
                        self.activity_timeout,
                        self.last_finalized,
                        self.view,
                        view,
                        false,
                    ) {
                        debug!(view, "verified message is not interesting");
                        continue;
                    }

                    // Handle verifier and resolver
                    match msg {
                        Voter::Notarize(notarize) => {
                            self.handle_notarize(notarize).await;
                        }
                        Voter::Nullify(nullify) => {
                            self.handle_nullify(nullify).await;
                        }
                        Voter::Finalize(finalize) => {
                            self.handle_finalize(finalize).await;
                        }
                        Voter::Notarization(notarization)  => {
                            trace!(view, "received notarization from resolver");
                            self.handle_notarization(notarization).await;
                        },
                        Voter::Nullification(nullification) => {
                            trace!(view, "received nullification from resolver");
                            self.handle_nullification(nullification).await;
                        },
                        Voter::Finalization(_) => {
                            unreachable!("unexpected message type");
                        }
                    }
                },
                msg = recovered_receiver.recv() => {
                    // Break if there is an internal error
                    let Ok((sender, msg)) = msg else {
                        break;
                    };

                    // Block if there is a decoding error
                    let Ok(msg) = msg else {
                        warn!(?sender, "blocking peer for decoding error");
                        self.blocker.block(sender).await;
                        continue;
                    };

                    // Block if the epoch is not the current epoch
                    if msg.epoch() != self.epoch {
                        warn!(?sender, "blocking peer for epoch mismatch");
                        self.blocker.block(sender).await;
                        continue;
                    }

                    // Process message
                    //
                    // We opt to not filter by `interesting()` here because each message type has a different
                    // configuration for handling `future` messages.
                    view = msg.view();
                    let action = match msg {
                        Voter::Notarization(notarization) => {
                            self.inbound_messages
                                .get_or_create(&Inbound::notarization(&sender))
                                .inc();
                            self.notarization(notarization).await
                        }
                        Voter::Nullification(nullification) => {
                            self.inbound_messages
                                .get_or_create(&Inbound::nullification(&sender))
                                .inc();
                            self.nullification(nullification).await
                        }
                        Voter::Finalization(finalization) => {
                            self.inbound_messages
                                .get_or_create(&Inbound::finalization(&sender))
                                .inc();
                            self.finalization(finalization).await
                        }
                        Voter::Notarize(_) | Voter::Nullify(_) | Voter::Finalize(_) => {
                            warn!(?sender, "blocking peer for invalid message type");
                            self.blocker.block(sender).await;
                            continue;
                        }
                    };
                    match action {
                        Action::Process => {}
                        Action::Skip => {
                            trace!(?sender, view, "dropped useless");
                            continue;
                        }
                        Action::Block => {
                            warn!(?sender, view, "blocking peer");
                            self.blocker.block(sender).await;
                            continue;
                        }
                    }
                },
            };

            // Attempt to send any new view messages
            self.notify(
                &mut batcher,
                &mut resolver,
                &mut pending_sender,
                &mut recovered_sender,
                view,
            )
            .await;

            // After sending all required messages, prune any views
            // we no longer need
            self.prune_views().await;

            // Update the verifier if we have moved to a new view
            if self.view > start {
                let round = self.views.get_mut(&self.view).expect("missing round");
                let leader = round.leader().expect("leader not set").idx;
                let is_active = batcher.update(self.view, leader, self.last_finalized).await;

                // If the leader is not active (and not us), we should reduce leader timeout to now
                if !is_active && !Self::is_me(&self.scheme, leader) {
                    debug!(view, ?leader, "skipping leader timeout due to inactivity");
                    self.skipped_views.inc();
                    round.leader_deadline = Some(self.context.current());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher, Sha256};

    type Digest = <Sha256 as Hasher>::Digest;

    #[test]
    fn proposal_slot_request_build_behavior() {
        let mut slot = ProposalSlot::<Digest>::new();
        assert!(slot.should_build());
        assert!(slot.should_build());
        slot.set_building();
        assert!(!slot.should_build());

        let mut slot = ProposalSlot::<Digest>::new();
        let round = Rnd::new(7, 3);
        let proposal = Proposal::new(round, 2, Sha256::hash(b"proposal"));
        slot.record_our_proposal(false, proposal);
        assert!(!slot.should_build());
    }

    #[test]
    fn proposal_slot_records_local_proposal_with_flags() {
        let mut slot = ProposalSlot::<Digest>::new();
        assert!(slot.proposal().is_none());

        let round = Rnd::new(9, 1);
        let proposal = Proposal::new(round, 0, Sha256::hash(b"ours"));
        slot.record_our_proposal(false, proposal.clone());

        match slot.proposal() {
            Some(stored) => assert_eq!(stored, &proposal),
            None => panic!("proposal missing after recording"),
        }
        assert_eq!(slot.status(), ProposalStatus::Verified);
        assert!(slot.has_requested_verify());
        assert!(!slot.should_build());
        assert!(!slot.request_verify());
    }

    #[test]
    fn proposal_slot_replay_allows_existing_proposal() {
        let mut slot = ProposalSlot::<Digest>::new();
        let round = Rnd::new(17, 6);
        let proposal = Proposal::new(round, 5, Sha256::hash(b"replay"));

        slot.record_our_proposal(false, proposal.clone());
        // Replaying the same proposal should behave idempotently.
        slot.record_our_proposal(true, proposal.clone());

        assert!(slot.has_requested_verify());
        assert!(!slot.should_build());
        assert_eq!(slot.status(), ProposalStatus::Verified);
        assert_eq!(slot.proposal(), Some(&proposal));
    }

    #[test]
    fn proposal_slot_update_preserves_status_when_equal() {
        let mut slot = ProposalSlot::<Digest>::new();
        let round = Rnd::new(13, 2);
        let proposal = Proposal::new(round, 1, Sha256::hash(b"identical"));

        assert!(matches!(slot.update(&proposal, false), ProposalChange::New));
        assert!(matches!(
            slot.update(&proposal, true),
            ProposalChange::Unchanged
        ));
        assert_eq!(slot.status(), ProposalStatus::Verified);
    }

    #[test]
    fn proposal_slot_certificate_then_vote() {
        let mut slot = ProposalSlot::<Digest>::new();
        let round = Rnd::new(21, 4);
        let proposal_a = Proposal::new(round, 2, Sha256::hash(b"a"));
        let proposal_b = Proposal::new(round, 2, Sha256::hash(b"b"));

        assert!(matches!(
            slot.update(&proposal_a, true),
            ProposalChange::New
        ));
        assert_eq!(slot.status(), ProposalStatus::Verified);
        let result = slot.update(&proposal_b, false);
        match result {
            ProposalChange::Replaced { previous, new } => {
                assert_eq!(previous, proposal_b);
                assert_eq!(new, proposal_a);
            }
            other => panic!("unexpected change: {other:?}"),
        }
        assert_eq!(slot.status(), ProposalStatus::Replaced);
    }

    #[test]
    fn proposal_slot_certificates_override_votes() {
        let mut slot = ProposalSlot::<Digest>::new();
        let round = Rnd::new(21, 4);
        let proposal_a = Proposal::new(round, 2, Sha256::hash(b"a"));
        let proposal_b = Proposal::new(round, 2, Sha256::hash(b"b"));

        assert!(matches!(
            slot.update(&proposal_a, false),
            ProposalChange::New
        ));
        assert_eq!(slot.status(), ProposalStatus::Unverified);

        match slot.update(&proposal_b, true) {
            ProposalChange::Replaced { previous, new } => {
                assert_eq!(previous, proposal_a);
                assert_eq!(new, proposal_b);
            }
            other => panic!("certificate should override votes, got {other:?}"),
        }
        assert_eq!(slot.status(), ProposalStatus::Replaced);
        assert_eq!(slot.proposal(), Some(&proposal_b));
    }
}
