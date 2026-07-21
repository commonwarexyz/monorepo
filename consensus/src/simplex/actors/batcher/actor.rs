use super::{Config, Mailbox, Message, Round};
use crate::{
    Epochable, Relay, Reporter, Viewable,
    simplex::{
        Plan, Viewport,
        actors::voter,
        config::ForwardingPolicy,
        metrics::{Inbound, Peer, TimeoutReason},
        scheme::Scheme,
        types::{Activity, Certificate, Proposal, Vote},
    },
    types::{Epoch, Participant, Round as Rnd, TermLength, View, ViewDelta},
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
use commonware_utils::{N3f1, ordered::Quorum};
use rand_core::CryptoRng;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{Instrument as _, Span, debug, info_span, trace};

/// Tracks the current view, its leader, and whether the voter has
/// already been told to timeout this view.
struct Current {
    view: View,
    leader: Option<Participant>,
    timed_out: bool,
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
    relay: Rl,
    strategy: T,

    view_retention: ViewDelta,
    skip_timeout: Duration,
    forwarding: ForwardingPolicy,
    epoch: Epoch,
    term_length: TermLength,
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
                relay: cfg.relay,
                strategy: cfg.strategy,

                view_retention: cfg.view_retention,
                skip_timeout: cfg.skip_timeout,
                forwarding: cfg.forwarding,
                epoch: cfg.epoch,
                term_length: cfg.term_length,
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
            term_length: self.term_length,
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

    /// Selects forwarding targets for a certified proposal under the active policy.
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
        if current.timed_out {
            return false;
        }
        let Some(leader) = current.leader else {
            return false;
        };
        work.get(&current.view)
            .is_some_and(|round| round.has_nullify(leader))
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
            timed_out: false,
        };
        let mut finalized = self.floor;
        let mut work: BTreeMap<View, Round<S, B, D, Re>> = BTreeMap::new();
        select_loop! {
            self.context,
            on_start => {
                // Track which view was modified (if any) for certificate construction
                let updated_view;
            },
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
                        certified_proposal,
                    } => {
                        let process = process_span(span.clone());
                        let _guard = process.entered();
                        let me = self.scheme.me();
                        let am_leader = me.is_some_and(|me| me == leader);
                        current = Current {
                            view: new_current,
                            leader: Some(leader),
                            timed_out: false,
                        };
                        finalized = new_finalized;

                        // Close the root span of any view the chain has now decided
                        for (_, round) in work.range_mut(..=finalized) {
                            round.close_span();
                        }

                        // Track the new current view, adopting the voter's view
                        // span so all of its work shares one trace
                        let round = work
                            .entry(current.view)
                            .or_insert_with(|| self.new_round(current.view));
                        round.set_span(span);
                        round.set_leader(leader);

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
                            current.timed_out = true;
                            voter.timeout(Rnd::new(self.epoch, current.view), timeout_reason);
                        }

                        // Forward the proposal, if enabled and we have something to forward
                        if let Some((proposal, round)) = certified_proposal
                            .filter(|_| self.forwarding.is_enabled())
                            .and_then(|proposal| {
                                work.get(&proposal.view()).map(|round| (proposal, round))
                            })
                        {
                            let participants = self.forward_targets(round, &proposal, leader);
                            self.forward_proposal(proposal, participants);
                        }

                        // Setting leader may enable batch verification
                        updated_view = current.view;
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

                        // Add the message to the verifier
                        let round = work.entry(view).or_insert_with(|| self.new_round(view));
                        let process = process_span(round.span());
                        let _guard = process.entered();
                        round.add_constructed(message);
                        self.added.inc();
                        updated_view = view;
                    }
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
                let duplicate = round.is_some_and(|round| round.has_certificate(kind));
                if duplicate {
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

                match message {
                    Certificate::Notarization(notarization) => {
                        // Verify the certificate
                        if !notarization.verify(
                            self.context.as_mut(),
                            self.scheme.as_ref(),
                            &self.strategy,
                        ) {
                            commonware_p2p::block!(self.blocker, sender, %view, "invalid notarization");
                            continue;
                        }

                        // Store and forward to voter
                        work.entry(view)
                            .or_insert_with(|| self.new_round(view))
                            .record_certificate(kind);
                        voter.recovered(Certificate::Notarization(notarization));
                    }
                    Certificate::Nullification(nullification) => {
                        // Verify the certificate
                        if !nullification.verify::<_, D>(
                            self.context.as_mut(),
                            self.scheme.as_ref(),
                            &self.strategy,
                        ) {
                            commonware_p2p::block!(self.blocker, sender, %view, "invalid nullification");
                            continue;
                        }

                        // Store and forward to voter
                        work.entry(view)
                            .or_insert_with(|| self.new_round(view))
                            .record_certificate(kind);
                        voter.recovered(Certificate::Nullification(nullification));
                    }
                    Certificate::Finalization(finalization) => {
                        // Verify the certificate
                        if !finalization.verify(
                            self.context.as_mut(),
                            self.scheme.as_ref(),
                            &self.strategy,
                        ) {
                            commonware_p2p::block!(self.blocker, sender, %view, "invalid finalization");
                            continue;
                        }

                        // Store and forward to voter
                        work.entry(view)
                            .or_insert_with(|| self.new_round(view))
                            .record_certificate(kind);
                        voter.recovered(Certificate::Finalization(finalization));
                    }
                }

                // Certificates are already forwarded to voter, no need for construction
                continue;
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
                if work
                    .entry(view)
                    .or_insert_with(|| self.new_round(view))
                    .add_network(sender.clone(), message)
                {
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
                        current.timed_out = true;
                        let round = Rnd::new(self.epoch, current.view);
                        let _guard = work
                            .get(&current.view)
                            .map(|round| round.span())
                            .unwrap_or_else(Span::none)
                            .entered();
                        voter.timeout(round, TimeoutReason::LeaderNullify);
                    }
                }
                updated_view = view;
            },
            on_end => {
                assert!(
                    updated_view != View::zero(),
                    "updated view must be greater than zero"
                );

                // Forward leader's proposal to voter (if we're not the leader and haven't already)
                if let Some(round) = work.get_mut(&current.view)
                    && let Some(me) = self.scheme.me()
                    && let Some(proposal) = round.try_forward_proposal(me)
                {
                    round.span().in_scope(|| voter.proposal(proposal));
                }

                // Skip verification and construction for views at or below finalized.
                //
                // We still admit votes at or below finalized (see
                // [Viewport::retains]) because we want to notify the reporter of
                // all votes within the activity timeout (even if we don't need
                // them in the voter).
                if updated_view <= finalized {
                    continue;
                }

                // Process the updated view (if any)
                let Some(round) = work.get_mut(&updated_view) else {
                    continue;
                };
                let span = round.span();
                async {
                    // Batch verify votes if ready
                    let timer = self.verify_latency.timer(self.context.as_ref());
                    if let Some((batch, failed)) = round
                        .try_verify(self.context.as_mut(), &self.strategy)
                        .await
                    {
                        timer.observe(self.context.as_ref());

                        // Process verified votes.
                        trace!(%updated_view, batch, "batch verified votes");
                        self.verified.inc_by(batch as u64);
                        self.batch_size.observe(batch as f64);

                        // Block invalid signers
                        for invalid in failed {
                            if let Some(signer) = self.scheme.participants().key(invalid) {
                                commonware_p2p::block!(
                                    self.blocker,
                                    signer.clone(),
                                    "invalid signature"
                                );
                            }
                        }
                    } else {
                        trace!(
                            current = %current.view,
                            %finalized,
                            "no verifier ready"
                        );
                    }

                    // Construct and forward every certificate with a verified quorum
                    while let Some(certificate) = self
                        .recover_latency
                        .time_some(
                            self.context.as_ref(),
                            round.try_construct_certificate(&self.strategy),
                        )
                        .await
                    {
                        let kind = certificate.kind();
                        debug!(
                            %updated_view,
                            %kind,
                            "constructed certificate, forwarding to voter"
                        );
                        voter.recovered(certificate);
                    }
                }
                .instrument(span)
                .await;

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
