use super::{Config, Mailbox, Message, Round, VerifiedVotes};
use crate::{
    Epochable, Relay, Reporter, Viewable,
    simplex::{
        Lookahead, Plan, Viewport,
        actors::voter,
        config::ForwardingPolicy,
        metrics::{Inbound, Peer, TimeoutReason},
        scheme::Scheme,
        types::{Activity, Certificate, Proposal, Vote},
    },
    types::{Epoch, Participant, Round as Rnd, View, ViewDelta},
};
use commonware_actor::mailbox;
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, utils::codec::WrappedReceiver};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::{
        metrics::{
            Counter, CounterFamily, GaugeExt, GaugeFamily, Histogram, MetricsExt as _,
            histogram::{self, Buckets},
        },
        traces::TracedExt as _,
    },
};
use commonware_utils::{N3f1, futures::Pool, ordered::Quorum};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{Span, debug, info_span, trace};

/// Tracks the current view, its leader, and whether the voter has already been
/// sent the leader-nullify hint for it.
///
/// The hint is tracked separately from other timeout reasons because the
/// voter may ignore an inactivity hint (a buffered proposal disproves it)
/// but must always act on the leader's own nullify.
struct Current {
    view: View,
    leader: Option<Participant>,
    leader_nullify_hinted: bool,
}

/// Moves each dirty view into one dispatch pass, prioritizing the current view.
fn prepare_dispatch(
    dirty_views: &mut BTreeSet<View>,
    current: View,
    dispatch_views: &mut Vec<View>,
) {
    dispatch_views.clear();
    if dirty_views.remove(&current) {
        dispatch_views.push(current);
    }
    dispatch_views.extend(dirty_views.iter().copied());
    dirty_views.clear();
}

/// A completed crypto job from the actor's dispatch pool.
pub(super) enum Done<S: Scheme<D>, D: Digest> {
    /// A verification batch completed: its verified votes must be
    /// reintegrated into the view's round (see [Round::finish_verify]) and
    /// invalid signers blocked.
    Verified {
        view: View,
        batch: usize,
        timer: histogram::Timer,
        votes: VerifiedVotes<S, D>,
        invalid: Vec<Participant>,
    },
    /// A certificate was recovered from a verified quorum and must be
    /// recorded on the view's round (see [Round::record_certificate]) and
    /// forwarded to the voter.
    Recovered {
        view: View,
        timer: histogram::Timer,
        certificate: Certificate<S, D>,
    },
}

pub struct Actor<E, S, B, D, Re, Rl, T>
where
    E: Spawner + Metrics + Clock + CryptoRng,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    Re: Reporter<Activity = Activity<S, D>>,
    Rl: Relay,
    T: Strategy,
{
    context: ContextCell<E>,

    scheme: Arc<S>,

    blocker: B,
    reporter: Re,
    track_historical_votes: bool,
    relay: Rl,
    strategy: T,

    view_retention: ViewDelta,
    skip_timeout: Duration,
    forwarding: ForwardingPolicy,
    epoch: Epoch,
    lookahead: Lookahead,
    floor: View,

    /// Tracks the last activity time for each participant, indexed by
    /// participant. `None` means no activity has been observed.
    last_activity: Vec<Option<SystemTime>>,

    /// Number of observed participants that must be recently active for the
    /// network to be considered responsive (see [Self::is_active]). We never
    /// observe our own messages, so when we are a participant we count
    /// ourselves as live by construction.
    required_active: usize,

    mailbox_receiver: mailbox::Receiver<Message<S, D>>,

    added: Counter,
    verified: Counter,
    inbound_messages: CounterFamily<Inbound>,
    latest_vote: GaugeFamily<Peer<S::PublicKey>>,
    batch_size: Histogram,
    verify_latency: histogram::Timed,
    recover_latency: histogram::Timed,
}

impl<E, S, B, D, Re, Rl, T> Actor<E, S, B, D, Re, Rl, T>
where
    E: Spawner + Metrics + Clock + CryptoRng,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    Re: Reporter<Activity = Activity<S, D>>,
    Rl: Relay<Digest = D, PublicKey = S::PublicKey, Plan = Plan<S::PublicKey>>,
    T: Strategy,
{
    pub fn new(context: E, cfg: Config<S, B, Re, Rl, T>) -> (Self, Mailbox<S, D>) {
        let scheme = Arc::new(cfg.scheme);
        let participants = scheme.participants();
        let added = context.counter("added", "number of messages added to the verifier");
        let verified = context.counter("verified", "number of messages verified");
        let inbound_messages = context.family("inbound_messages", "number of inbound messages");
        let latest_vote: GaugeFamily<Peer<S::PublicKey>> =
            context.family("latest_vote", "view of latest vote received per peer");
        for participant in participants.iter() {
            latest_vote.get_or_create_by(participant).set(0);
        }
        let batch_size = context.histogram(
            "batch_size",
            "number of messages in a signature verification batch",
            [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0],
        );
        let verify_latency = context.histogram(
            "verify_latency",
            "latency of signature verification",
            Buckets::CRYPTOGRAPHY,
        );
        let recover_latency = context.histogram(
            "recover_latency",
            "certificate recover latency",
            Buckets::CRYPTOGRAPHY,
        );
        let (sender, receiver) = mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        let mut required_active = participants.quorum::<N3f1>() as usize;
        if scheme.me().is_some() {
            // We are live by construction (we never observe our own messages).
            required_active = required_active
                .checked_sub(1)
                .expect("quorum is never zero");
        }
        (
            Self {
                context: ContextCell::new(context),

                last_activity: vec![None; participants.len()],
                required_active,
                scheme,

                blocker: cfg.blocker,
                reporter: cfg.reporter,
                track_historical_votes: cfg.track_historical_votes,
                relay: cfg.relay,
                strategy: cfg.strategy,

                view_retention: cfg.view_retention,
                skip_timeout: cfg.skip_timeout,
                forwarding: cfg.forwarding,
                epoch: cfg.epoch,
                lookahead: cfg.lookahead,
                floor: cfg.floor,

                mailbox_receiver: receiver,

                added,
                verified,
                inbound_messages,
                latest_vote,
                batch_size,
                verify_latency: histogram::Timed::new(verify_latency),
                recover_latency: histogram::Timed::new(recover_latency),
            },
            Mailbox::new(sender),
        )
    }

    fn new_round(&self, view: View) -> Round<S, B, D, Re> {
        Round::new(
            Rnd::new(self.epoch, view),
            Arc::clone(&self.scheme),
            self.blocker.clone(),
            self.reporter.clone(),
            self.track_historical_votes,
        )
    }

    /// Records the current time as the last activity time for a participant.
    ///
    /// This mechanism is not resistant to malicious validators (nor is it meant to be).
    fn record_activity(&mut self, participant: Participant) {
        self.last_activity[usize::from(participant)] = Some(self.context.current());
    }

    /// Records activity for a network sender, if it is a participant.
    fn record_peer_activity(&mut self, sender: &S::PublicKey) {
        if let Some(participant) = self.scheme.participants().index(sender) {
            self.record_activity(participant);
        }
    }

    /// Returns true if the participant has sent a recent message, or if fewer
    /// than a quorum of participants have (fail-open).
    fn is_active(&self, participant: Participant) -> bool {
        // Track activity with wall-clock time rather than raw view deltas. Stable-leader terms can
        // skip many view numbers at once, so we only fast-timeout when a quorum has been active
        // within `skip_timeout`, and the selected leader has not.
        let min_time = self
            .context
            .current()
            .checked_sub(self.skip_timeout)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let recent =
            |activity: &Option<SystemTime>| activity.is_some_and(|activity| activity >= min_time);

        // If fewer than the required number of participants are recently active, we "fail-open"
        // since we know the network is not expected to be responsive.
        let active = self.last_activity.iter().filter(|a| recent(a)).count();
        if active < self.required_active {
            return true;
        }

        // Return true if we have recent activity from the participant.
        recent(&self.last_activity[usize::from(participant)])
    }

    /// Returns the window of views the batcher tracks, given the voter's
    /// last-published finalized and current views.
    const fn viewport(&self, finalized: View, current: View) -> Viewport {
        Viewport {
            finalized,
            current,
            view_retention: self.view_retention,
            lookahead: self.lookahead,
        }
    }

    /// Maps `missing` participants to targeted forward recipients, excluding self.
    fn forward_recipients(&self, missing: &[Participant]) -> Vec<S::PublicKey> {
        let me = self.scheme.me();
        missing
            .iter()
            .filter(|&&p| Some(p) != me)
            .filter_map(|&p| self.scheme.participants().key(p).cloned())
            .collect()
    }

    /// Selects forwarding targets for a forwardable proposal under the active policy.
    fn forward_targets(
        &self,
        round: &Round<S, B, D, Re>,
        proposal: &Proposal<D>,
        next_leader: Participant,
    ) -> Vec<Participant> {
        match self.forwarding {
            ForwardingPolicy::Disabled => Vec::new(),
            ForwardingPolicy::SilentVoters => round.missing_voters(proposal),
            ForwardingPolicy::SilentLeader => round
                .is_missing_voter(proposal, next_leader)
                .then_some(next_leader)
                .into_iter()
                .collect(),
        }
    }

    /// Forwards a proposal to the requested peers.
    fn forward_proposal(&mut self, proposal: Proposal<D>, missing: Vec<Participant>) {
        let peers = self.forward_recipients(&missing);
        if peers.is_empty() {
            return;
        }
        let _ = self.relay.broadcast(
            proposal.payload,
            Plan::Forward {
                round: proposal.round,
                recipients: Recipients::Some(peers),
            },
        );
    }

    /// Returns true if the leader has nullified the current view
    /// and we have not yet notified the voter.
    fn leader_nullified(current: &Current, work: &BTreeMap<View, Round<S, B, D, Re>>) -> bool {
        if current.leader_nullify_hinted {
            return false;
        }
        let Some(leader) = current.leader else {
            return false;
        };
        work.get(&current.view)
            .is_some_and(|round| round.has_nullify(leader))
    }

    /// Returns the round for `view`, creating it if needed and stamping the
    /// stable leader when the view is within the admission window.
    fn round_for_view<'a>(
        &self,
        current: &Current,
        work: &'a mut BTreeMap<View, Round<S, B, D, Re>>,
        view: View,
    ) -> &'a mut Round<S, B, D, Re> {
        let round = work.entry(view).or_insert_with(|| self.new_round(view));
        self.stamp_leader(current, view, round);
        round
    }

    /// Stamps the current term's stable leader on `view`'s round when the
    /// view is current or inside the admission window.
    fn stamp_leader(&self, current: &Current, view: View, round: &mut Round<S, B, D, Re>) {
        let Some(leader) = current.leader else {
            return;
        };

        if view == current.view || self.lookahead.in_admission_window(current.view, view) {
            round.set_leader(leader);
        }
    }

    /// Dispatches any ready crypto work for `view` into `pool` without
    /// blocking the event loop: one verification batch per vote kind (each
    /// kind independently tracks an in-flight batch) plus recovery of every
    /// certificate with a verified quorum.
    ///
    /// Results arrive through the pool's completion branch, which reintegrates
    /// them and marks the view dirty so this dispatch runs again (e.g. to
    /// recover a certificate from a quorum a batch just completed).
    ///
    /// Returns true when the strategy's execution capacity is full. The caller
    /// must retain the view for a later pass because more work may be ready.
    pub(super) fn dispatch_view(
        &mut self,
        pool: &mut Pool<Done<S, D>>,
        view: View,
        round: &mut Round<S, B, D, Re>,
    ) -> bool {
        let capacity = self.strategy.manual().parallelism();

        // Begin a verification batch for every vote kind with work worth
        // verifying.
        while pool.len() < capacity
            && let Some((batch, job)) = round.begin_verify(self.context.as_mut(), &self.strategy)
        {
            let timer = self.verify_latency.timer(self.context.as_ref());
            pool.push(async move {
                let (votes, invalid) = job.await;
                Done::Verified {
                    view,
                    batch,
                    timer,
                    votes,
                    invalid,
                }
            });
        }

        // Begin recovery of every certificate with a verified quorum.
        while pool.len() < capacity
            && let Some(job) = round.begin_construct_certificate(&self.strategy)
        {
            let timer = self.recover_latency.timer(self.context.as_ref());
            pool.push(async move {
                Done::Recovered {
                    view,
                    timer,
                    certificate: job.await,
                }
            });
        }

        pool.len() == capacity
    }

    /// Reintegrates a completed crypto job from the dispatch pool.
    ///
    /// A verification batch's votes return to the view's round. A recovered
    /// certificate is recorded on the round and forwarded to the voter. A
    /// view pruned while its job was in flight drops the votes but still
    /// forwards the certificate: the voter prunes independently.
    ///
    /// Returns the view to revisit when the completion may have made new
    /// work ready: a batch may have completed a quorum, or more votes may
    /// have buffered while it was in flight.
    pub(super) fn handle_done(
        &mut self,
        voter: &mut voter::Mailbox<S, D>,
        work: &mut BTreeMap<View, Round<S, B, D, Re>>,
        done: Done<S, D>,
    ) -> Option<View> {
        match done {
            Done::Verified {
                view,
                batch,
                timer,
                votes,
                invalid,
            } => {
                timer.observe(self.context.as_ref());
                self.verified.inc_by(batch as u64);
                self.batch_size.observe(batch as f64);

                for signer in invalid {
                    if let Some(signer) = self.scheme.participants().key(signer) {
                        commonware_p2p::block!(self.blocker, signer.clone(), "invalid signature");
                    }
                }

                // The round may have been pruned while the batch was in flight.
                // The monotonic retention floor also gates vote admission, so a
                // pruned view cannot be recreated and its votes are no longer needed.
                let round = work.get_mut(&view)?;
                let _guard = round.span().entered();
                trace!(%view, batch, "batch verified votes");
                round.finish_verify(votes);

                // Revisit the view: the batch may have completed a
                // quorum (certificate recovery) or more votes may have
                // buffered while it was in flight (another batch).
                Some(view)
            }
            Done::Recovered {
                view,
                timer,
                certificate,
            } => {
                timer.observe(self.context.as_ref());
                let kind = certificate.kind();

                // Record the certificate on its round (completing the
                // certified phase and applying the retention policy)
                // unless the round was pruned while recovery was in
                // flight. Recording may unlock already-buffered votes.
                let recorded = work.get_mut(&view).is_some_and(|round| {
                    let _guard = round.span().entered();
                    debug!(%view, %kind, "constructed certificate, forwarding to voter");
                    round.record_certificate(&certificate)
                });
                voter.recovered(certificate);
                recorded.then_some(view)
            }
        }
    }

    pub fn start(
        mut self,
        voter: voter::Mailbox<S, D>,
        vote_receiver: impl Receiver<PublicKey = S::PublicKey>,
        certificate_receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(voter, vote_receiver, certificate_receiver)
        )
    }

    pub async fn run(
        mut self,
        mut voter: voter::Mailbox<S, D>,
        vote_receiver: impl Receiver<PublicKey = S::PublicKey>,
        certificate_receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) {
        // Wrap channels
        let mut vote_receiver: WrappedReceiver<_, Vote<S, D>> =
            WrappedReceiver::new((), vote_receiver);
        let mut certificate_receiver: WrappedReceiver<_, Certificate<S, D>> =
            WrappedReceiver::new(self.scheme.certificate_codec_config(), certificate_receiver);

        // Initialize view data structures
        let mut current = Current {
            view: View::zero(),
            leader: None,
            leader_nullify_hinted: false,
        };
        let mut finalized = self.floor;
        let mut work: BTreeMap<View, Round<S, B, D, Re>> = BTreeMap::new();

        // Views whose rounds may have become actionable. Views that cannot be
        // dispatched at capacity remain queued for a later completion.
        let mut dirty_views: BTreeSet<View> = BTreeSet::new();
        let mut dispatch_views: Vec<View> = Vec::new();
        // In-flight crypto (verification batches and certificate recoveries).
        // Dispatching instead of awaiting keeps the event loop free to ingest
        // votes while the strategy's workers verify, so multiple batches (and
        // views) make progress concurrently.
        let mut crypto_pool: Pool<Done<S, D>> = Pool::default();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping batcher");
            },
            Some(message) = self.mailbox_receiver.recv() else break => {
                let view = message.view();
                let operation = message.name();
                let epoch = self.epoch;
                let process_span = |parent: Span| {
                    info_span!(
                        parent: parent,
                        "simplex.batcher.process",
                        operation,
                        epoch = epoch.traced(),
                        view = view.traced()
                    )
                };
                match message {
                    Message::Update {
                        span,
                        current: new_current,
                        leader,
                        finalized: new_finalized,
                        forwardable_proposal,
                    } => {
                        let process = process_span(span.clone());
                        let _guard = process.entered();
                        let me = self.scheme.me();
                        let am_leader = me.is_some_and(|me| me == leader);
                        current = Current {
                            view: new_current,
                            leader: Some(leader),
                            leader_nullify_hinted: false,
                        };
                        finalized = new_finalized;

                        // Close the root span of any view the chain has now decided
                        for (_, round) in work.range_mut(..=finalized) {
                            round.close_span();
                        }

                        // Track the new current view, adopting the voter's view
                        // span so all of its work shares one trace
                        let round = self.round_for_view(&current, &mut work, current.view);
                        round.set_span(span);
                        dirty_views.insert(current.view);

                        // Revisit rounds in the admission window now that the
                        // current view advanced: rounds already visited are
                        // cheap no-ops to reprocess.
                        let limit = self.lookahead.admission_limit(current.view);
                        if current.view < limit {
                            for (&view, round) in work.range_mut(current.view.next()..=limit) {
                                self.stamp_leader(&current, view, round);
                                dirty_views.insert(view);
                            }
                        }

                        // If the leader nullified this view or has not been active
                        // recently, tell the voter to reduce the leader timeout to now.
                        //
                        // Activity is a best-effort, wall-clock signal: leader messages
                        // still queued inbound are not yet recorded, so a spurious
                        // fast-timeout here is possible and tolerated. That is safe and
                        // bounded: safety is unaffected, and nodes that already observed
                        // the leader's activity will not time out.
                        let timeout_reason = match Self::leader_nullified(&current, &work) {
                            // Leader already buffered a nullify for this now-current view
                            // (allowed because we accept votes at or below `current`, at
                            // `current+1`, or at the next term start)
                            true => Some(TimeoutReason::LeaderNullify),
                            false => match am_leader {
                                // If we are the leader, we should not timeout
                                true => None,
                                // If we are not the leader and the leader isn't
                                // active, we should timeout.
                                false => (!self.is_active(leader))
                                    .then_some(TimeoutReason::Inactivity)
                            },
                        };
                        if let Some(timeout_reason) = timeout_reason {
                            current.leader_nullify_hinted =
                                matches!(timeout_reason, TimeoutReason::LeaderNullify);
                            voter.timeout(Rnd::new(self.epoch, current.view), timeout_reason);
                        }

                        // Forward the proposal, if enabled and we have something to forward
                        if let Some((proposal, round)) = forwardable_proposal
                            .filter(|_| self.forwarding.is_enabled())
                            .and_then(|proposal| {
                                work.get(&proposal.view()).map(|round| (proposal, round))
                            })
                        {
                            let participants = self.forward_targets(round, &proposal, leader);
                            self.forward_proposal(proposal, participants);
                        }

                    }
                    Message::Constructed(message) => {
                        // Skip votes below the viewport floor. Our own votes
                        // are not future-bounded: the voter constructs them
                        // before sending the update that advances our view
                        // (so they can be ahead of it after a certificate
                        // jump), and admission bounds exist for untrusted
                        // network input.
                        if !self.viewport(finalized, current.view).retains(view) {
                            continue;
                        }

                        // Add the message to the verifier. Since these are our own
                        // votes, we can safely add the message even if the view is
                        // arbitrarily far in the future.
                        let round = self.round_for_view(&current, &mut work, view);
                        let process = process_span(round.span());
                        let _guard = process.entered();
                        round.accept_vote(message, true);
                        self.added.inc();
                        dirty_views.insert(view);
                    }
                }
            },
            // Handle completed crypto work (verification batches and
            // certificate recoveries)
            done = crypto_pool.next_completed() => {
                if let Some(view) = self.handle_done(&mut voter, &mut work, done) {
                    dirty_views.insert(view);
                }
            },
            // Handle certificates from the network
            Ok((sender, message)) = certificate_receiver.recv() else break => {
                // If there is a decoding error, block
                let Ok(message) = message else {
                    commonware_p2p::block!(self.blocker, sender, "decoding error");
                    continue;
                };

                // Update metrics
                let label = match &message {
                    Certificate::Notarization(_) => Inbound::notarization(&sender),
                    Certificate::Nullification(_) => Inbound::nullification(&sender),
                    Certificate::Finalization(_) => Inbound::finalization(&sender),
                };
                self.inbound_messages.get_or_create(&label).inc();

                // If the epoch is not the current epoch, block
                if message.epoch() != self.epoch {
                    commonware_p2p::block!(self.blocker, sender, "epoch mismatch");
                    continue;
                }

                // Record activity from the sender even if we don't process the certificate.
                let view = message.view();
                self.record_peer_activity(&sender);

                // Skip certificates outside the viewport
                if !self.viewport(finalized, current.view).admits_certificate(view) {
                    continue;
                }

                // Skip certificates we already have for the view
                let kind = message.kind();
                let round = work.get(&view);
                if round.is_some_and(|round| round.has_certificate(kind)) {
                    trace!(%view, %kind, "skipping duplicate certificate");
                    continue;
                }

                // Parent under the view's span if we already track the view (we avoid
                // creating per-view state for certificates that fail verification)
                let parent = round.map(|round| round.span()).unwrap_or_else(Span::none);
                let span = info_span!(
                    parent: parent,
                    "simplex.batcher.verify_certificate",
                    %kind,
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let _guard = span.entered();

                // Verify the certificate.
                if !message.verify(self.context.as_mut(), self.scheme.as_ref(), &self.strategy) {
                    commonware_p2p::block!(self.blocker, sender, %view, %kind, "invalid certificate");
                    continue;
                }

                // Store and forward to voter, revisiting the round when the
                // certificate may have unlocked already-buffered votes.
                let round = self.round_for_view(&current, &mut work, view);
                if round.record_certificate(&message) {
                    dirty_views.insert(view);
                }
                voter.recovered(message);
            },
            // Handle votes from the network
            Ok((sender, message)) = vote_receiver.recv() else break => {
                // If there is a decoding error, block
                let Ok(message) = message else {
                    commonware_p2p::block!(self.blocker, sender, "decoding error");
                    continue;
                };

                // Update metrics
                let label = match &message {
                    Vote::Notarize(_) => Inbound::notarize(&sender),
                    Vote::Nullify(_) => Inbound::nullify(&sender),
                    Vote::Finalize(_) => Inbound::finalize(&sender),
                };
                self.inbound_messages.get_or_create(&label).inc();

                // If the epoch is not the current epoch, block
                if message.epoch() != self.epoch {
                    commonware_p2p::block!(self.blocker, sender, "epoch mismatch");
                    continue;
                }

                // Any same-epoch traffic from a known peer counts as activity, even if the vote is
                // later ignored. Skip-timeout is a liveness heuristic, not Byzantine evidence.
                let view = message.view();
                self.record_peer_activity(&sender);

                // Skip votes outside the viewport
                if !self.viewport(finalized, current.view).admits_vote(view) {
                    continue;
                }

                // Add the vote to the verifier
                let round = self.round_for_view(&current, &mut work, view);
                if round.add_network(sender.clone(), message) {
                    self.added.inc();

                    // Update per-peer latest vote metric (only if higher than current)
                    let _ = self
                        .latest_vote
                        .get_or_create_by(&sender)
                        .try_set_max(view.get());

                    // If the current leader explicitly nullifies the current view, signal
                    // the voter so it can fast-path timeout without waiting for its local
                    // timer. We check after adding because duplicate votes are rejected.
                    if Self::leader_nullified(&current, &work) {
                        current.leader_nullify_hinted = true;
                        let round = Rnd::new(self.epoch, current.view);
                        let _guard = work
                            .get(&current.view)
                            .map(|round| round.span())
                            .unwrap_or_else(Span::none)
                            .entered();
                        voter.timeout(round, TimeoutReason::LeaderNullify);
                    }
                    dirty_views.insert(view);
                }
            },
            on_end => {
                if dirty_views.is_empty() {
                    continue;
                }

                let me = self.scheme.me();

                // Process each currently dirty view once. Saturated views are
                // reinserted for a later pass.
                prepare_dispatch(&mut dirty_views, current.view, &mut dispatch_views);
                for view in dispatch_views.drain(..) {
                    // Skip verification and construction for views at or below
                    // finalized. We still admit votes there (see
                    // [Viewport::retains]) to notify the reporter of all votes
                    // within the retained window (even if we don't need them
                    // in the voter).
                    if view <= finalized {
                        continue;
                    }
                    let Some(round) = work.get_mut(&view) else {
                        continue;
                    };

                    // Forward the round's proposal once known, keeping
                    // optimistic followers fed. No window check needed: the
                    // proposal comes from a stamped leader's vote (stamping is
                    // window-gated) or from a verified certificate.
                    if let Some(me) = me
                        && let Some(proposal) = round.try_forward_proposal(me)
                    {
                        round.span().in_scope(|| voter.proposal(proposal));
                    }

                    // We only process bounded future work. This keeps memory and
                    // verification bounded while still enabling optimistic lookahead.
                    if !self.lookahead.admits(current.view, view) {
                        trace!(current = %current.view, %view, "skipping out-of-window round processing");
                        continue;
                    }

                    let span = round.span();
                    if span.in_scope(|| self.dispatch_view(&mut crypto_pool, view, round)) {
                        dirty_views.insert(view);
                    }
                }

                // Drop any rounds that are no longer retained
                let viewport = self.viewport(finalized, current.view);
                while work
                    .first_key_value()
                    .is_some_and(|(&view, _)| !viewport.retains(view))
                {
                    work.pop_first();
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BTreeSet, View, prepare_dispatch};

    #[test]
    fn dispatch_pass_prioritizes_current_without_reprocessing() {
        let current = View::new(3);
        let mut dirty = BTreeSet::from([View::new(1), current, View::new(4)]);
        let mut dispatch = vec![View::new(9)];

        prepare_dispatch(&mut dirty, current, &mut dispatch);

        assert_eq!(dispatch, [current, View::new(1), View::new(4)]);
        assert!(dirty.is_empty());
    }
}
