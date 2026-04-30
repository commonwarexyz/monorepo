use super::{Config, Mailbox, Message, Round};
use crate::{
    simplex::{
        accepts_optimistic_future_view,
        actors::voter,
        config::ForwardingPolicy,
        in_same_term_optimistic_window,
        metrics::{Inbound, Peer, TimeoutReason},
        same_term_optimistic_limit,
        scheme::Scheme,
        types::{Activity, Certificate, Proposal, Vote},
        Plan,
    },
    types::{Epoch, Participant, View},
    Epochable, Relay, Reporter, Viewable,
};
use commonware_actor::mailbox;
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{utils::codec::WrappedReceiver, Blocker, Receiver, Recipients};
use commonware_parallel::Strategy;
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{
        histogram::{self, Buckets},
        Counter, CounterFamily, GaugeExt, GaugeFamily, Histogram, MetricsExt as _,
    },
    Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::{
    ordered::{Quorum, Set},
    N3f1, PrioritySet,
};
use core::num::NonZeroU64;
use rand_core::CryptoRngCore;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime},
};
use tracing::{debug, trace};

/// Tracks the current view, its leader, and whether the voter has
/// already been told to timeout this view.
struct Current {
    view: View,
    leader: Option<Participant>,
    timed_out: bool,
}

#[allow(dead_code)]
pub struct Actor<E, S, B, D, Re, Rl, T>
where
    E: Spawner + Metrics + Clock + CryptoRngCore,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    Re: Reporter<Activity = Activity<S, D>>,
    Rl: Relay,
    T: Strategy,
{
    context: ContextCell<E>,

    participants: Set<S::PublicKey>,
    scheme: S,

    blocker: B,
    reporter: Re,
    relay: Rl,
    strategy: T,

    skip_timeout: Duration,
    forwarding: ForwardingPolicy,
    epoch: Epoch,
    term_length: NonZeroU64,

    term_optimistic_views: u64,

    /// Tracks the last activity time for each participant.
    /// Entries may be pruned when the latest activity is no longer recent.
    last_activity: PrioritySet<Participant, SystemTime>,

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
    E: Spawner + Metrics + Clock + CryptoRngCore,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    Re: Reporter<Activity = Activity<S, D>>,
    Rl: Relay<Digest = D, PublicKey = S::PublicKey, Plan = Plan<S::PublicKey>>,
    T: Strategy,
{
    pub fn new(context: E, cfg: Config<S, B, Re, Rl, T>) -> (Self, Mailbox<S, D>) {
        let participants = cfg.scheme.participants().clone();
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
        let (sender, receiver) = mailbox::new(cfg.mailbox_size);
        let last_activity = PrioritySet::new();
        (
            Self {
                context: ContextCell::new(context),

                participants,
                scheme: cfg.scheme,

                blocker: cfg.blocker,
                reporter: cfg.reporter,
                relay: cfg.relay,
                strategy: cfg.strategy,

                skip_timeout: cfg.skip_timeout,
                forwarding: cfg.forwarding,
                epoch: cfg.epoch,
                term_length: cfg.term_length,
                term_optimistic_views: cfg.term_optimistic_views,

                last_activity,

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

    fn new_round(&self) -> Round<S, B, D, Re> {
        Round::new(
            self.participants.clone(),
            self.scheme.clone(),
            self.blocker.clone(),
            self.reporter.clone(),
        )
    }

    /// Records the current time as the last activity time for a participant.
    ///
    /// This mechanism is not resistant to malicious validators (nor is it meant to be).
    fn record_activity(&mut self, participant: Participant) {
        self.last_activity.put(participant, self.context.current());
    }

    /// Returns true if the participant has sent a recent message.
    fn is_active(&mut self, participant: &Participant) -> bool {
        // Track activity with wall-clock time rather than raw view deltas. Stable-leader terms can
        // skip many view numbers at once, so we only fast-timeout when a quorum has been active
        // within `skip_timeout`, and the selected leader has not.
        // Prune all stale activity timestamps.
        let min_time = self
            .context
            .current()
            .checked_sub(self.skip_timeout)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        while self
            .last_activity
            .peek()
            .is_some_and(|(_, a)| *a < min_time)
        {
            self.last_activity.pop();
        }

        // If there is not a quorum of recently active participants, then we "fail-open" since we
        // know the network is not expected to be responsive.
        if self.last_activity.len() < self.participants.quorum::<N3f1>() as usize {
            return true;
        }

        // Return true if we have recent activity from the participant.
        self.last_activity.contains(participant)
    }

    /// Maps `missing` participants to targeted forward recipients, excluding self.
    fn forward_recipients(&self, missing: &[Participant]) -> Vec<S::PublicKey> {
        let me = self.scheme.me();
        missing
            .iter()
            .filter(|&&p| Some(p) != me)
            .filter_map(|&p| self.participants.key(p).cloned())
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

    fn accepts_future_view(&self, current: View, view: View) -> bool {
        accepts_optimistic_future_view(current, view, self.term_length, self.term_optimistic_views)
    }

    fn round_for_view<'a>(
        &self,
        current: &Current,
        work: &'a mut BTreeMap<View, Round<S, B, D, Re>>,
        view: View,
    ) -> &'a mut Round<S, B, D, Re> {
        let round = work.entry(view).or_insert_with(|| self.new_round());
        self.ensure_round_context(current, view, round);
        round
    }

    fn ensure_round_context(&self, current: &Current, view: View, round: &mut Round<S, B, D, Re>) {
        let Some(leader) = current.leader else {
            return;
        };

        if view == current.view
            || in_same_term_optimistic_window(
                current.view,
                view,
                self.term_length,
                self.term_optimistic_views,
            )
        {
            round.set_leader(leader);
        }
    }

    async fn process_view(
        &mut self,
        voter: &mut voter::Mailbox<S, D>,
        view: View,
        round: &mut Round<S, B, D, Re>,
    ) {
        let timer = self.verify_latency.timer(self.context.as_ref());
        let verified = if round.ready_notarizes() {
            Some(round.verify_notarizes(self.context.as_mut(), &self.strategy))
        } else if round.ready_nullifies() {
            Some(round.verify_nullifies(self.context.as_mut(), &self.strategy))
        } else if round.ready_finalizes() {
            Some(round.verify_finalizes(self.context.as_mut(), &self.strategy))
        } else {
            None
        };

        if let Some((voters, failed)) = verified {
            timer.observe(self.context.as_ref());

            let batch = voters.len() + failed.len();
            trace!(view = %view, batch, "batch verified votes");
            self.verified.inc_by(batch as u64);
            self.batch_size.observe(batch as f64);

            for invalid in failed {
                if let Some(signer) = self.participants.key(invalid) {
                    commonware_p2p::block!(self.blocker, signer.clone(), "invalid signature");
                }
            }

            for valid in voters {
                round.add_verified(valid);
            }
        } else {
            trace!(view = %view, "no verifier ready");
        }

        if let Some(notarization) = self.recover_latency.time_some(self.context.as_ref(), || {
            round.try_construct_notarization(&self.scheme, &self.strategy)
        }) {
            debug!(view = %view, "constructed notarization, forwarding to voter");
            voter.recovered(Certificate::Notarization(notarization));
        }
        if let Some(nullification) = self.recover_latency.time_some(self.context.as_ref(), || {
            round.try_construct_nullification(&self.scheme, &self.strategy)
        }) {
            debug!(view = %view, "constructed nullification, forwarding to voter");
            voter.recovered(Certificate::Nullification(nullification));
        }
        if let Some(finalization) = self.recover_latency.time_some(self.context.as_ref(), || {
            round.try_construct_finalization(&self.scheme, &self.strategy)
        }) {
            debug!(view = %view, "constructed finalization, forwarding to voter");
            voter.recovered(Certificate::Finalization(finalization));
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
            timed_out: false,
        };
        let mut finalized = View::zero();
        let mut pruned_finalized = View::zero();
        let mut work: BTreeMap<View, Round<S, B, D, Re>> = BTreeMap::new();
        select_loop! {
            self.context,
            on_start => {
                let mut dirty_views = BTreeSet::new();
            },
            on_stopped => {
                debug!("context shutdown, stopping batcher");
            },
            Some(message) = self.mailbox_receiver.recv() else break => match message {
                Message::Update {
                    current: new_current,
                    leader,
                    finalized: new_finalized,
                    forwardable_proposal,
                } => {
                    let previous_view = current.view;
                    let am_leader = self.scheme.me().is_some_and(|me| me == leader);
                    current = Current {
                        view: new_current,
                        leader: Some(leader),
                        timed_out: false,
                    };
                    finalized = new_finalized;

                    {
                        self.round_for_view(&current, &mut work, current.view);
                    }
                    dirty_views.insert(current.view);

                    if let Some(limit) = same_term_optimistic_limit(
                        current.view,
                        self.term_length,
                        self.term_optimistic_views,
                    ) {
                        if current.view < limit {
                            for (&view, round) in work.range_mut(current.view.next()..=limit) {
                                // Revisit only views that newly enter the accepted optimistic
                                // window when current view advances.
                                if !self.accepts_future_view(previous_view, view) {
                                    self.ensure_round_context(&current, view, round);
                                    dirty_views.insert(view);
                                }
                            }
                        }
                    }

                    // If the leader nullified this view or has not been active
                    // recently, tell the voter to reduce the leader timeout to now
                    let timeout_reason = match Self::leader_nullified(&current, &work) {
                        // Leader already buffered a nullify for this now-current view
                        // (allowed because we accept votes up to `current+1`)
                        true => Some(TimeoutReason::LeaderNullify),
                        false => match am_leader {
                            // If we are the leader, we should not timeout
                            true => None,
                            // If we are not the leader and the leader isn't active, we should timeout
                            false => (!self.is_active(&leader)).then_some(TimeoutReason::Inactivity),
                        },
                    };
                    if let Some(timeout_reason) = timeout_reason {
                        current.timed_out = true;
                        voter.timeout(current.view, timeout_reason);
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
                    let view = message.view();

                    // Record activity for ourselves.
                    if let Some(me) = self.scheme.me() {
                        self.record_activity(me);
                    }

                    // Ignore non-useful votes.
                    if view <= finalized {
                        continue;
                    }

                    // Add the message to the verifier. Since these are our own votes, we can safely
                    // add the message even if the view is arbitrarily far in the future.
                    let round = self.round_for_view(&current, &mut work, view);
                    round.add_constructed(message);
                    self.added.inc();
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
                if let Some(participant) = self.participants.index(&sender) {
                    self.record_activity(participant);
                }

                // Ignore certificates below the highest finalized view since they aren't useful.
                // Allow certificates from arbitrarily-future views since they advance our view.
                if view <= finalized {
                    continue;
                }

                // Skip if we already have a certificate of the same type for this view.
                if work
                    .get(&view)
                    .is_some_and(|round| round.has_certificate(&message))
                {
                    trace!(%view, certificate = message.kind_name(), "skipping duplicate certificate");
                    continue;
                }

                // Verify the certificate.
                if !message.verify(self.context.as_mut(), &self.scheme, &self.strategy) {
                    commonware_p2p::block!(
                        self.blocker,
                        sender,
                        %view,
                        certificate = message.kind_name(),
                        "invalid certificate"
                    );
                    continue;
                }

                // Store and forward to voter.
                let round = self.round_for_view(&current, &mut work, view);
                round.set_certificate(message.clone());
                voter.recovered(message);

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
                if let Some(participant) = self.participants.index(&sender) {
                    self.record_activity(participant);
                }

                // Ignore non-useful votes.
                if view <= finalized {
                    continue;
                }

                // Ignore votes from arbitrarily-future views (DOS via memory exhaustion).
                // Allow votes from the next view since we may be slightly behind, from
                // the next term start, and from bounded same-term optimistic future views.
                if view > current.view && !self.accepts_future_view(current.view, view) {
                    continue;
                }

                // Add the vote to the verifier
                let round = self.round_for_view(&current, &mut work, view);
                if round.add_network(sender.clone(), message).await {
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
                        voter.timeout(current.view, TimeoutReason::LeaderNullify);
                    }
                    dirty_views.insert(view);
                }
            },
            on_end => {
                if dirty_views.is_empty() {
                    continue;
                }

                let me = self.scheme.me();

                for view in dirty_views {
                    if view <= finalized {
                        continue;
                    }

                    // Forward each round's leader proposal once it becomes known.
                    // This keeps optimistic followers fed with future proposals.
                    if let (Some(me), Some(round)) = (me, work.get_mut(&view)) {
                        if let Some(proposal) = round.forward_proposal(me) {
                            voter.proposal(proposal);
                        }
                    }

                    // We only process bounded future work. This keeps memory and
                    // verification bounded while still enabling optimistic lookahead.
                    if view > current.view && !self.accepts_future_view(current.view, view) {
                        trace!(current = %current.view, %view, "skipping out-of-window round processing");
                        continue;
                    }

                    let Some(round) = work.get_mut(&view) else {
                        continue;
                    };
                    self.process_view(&mut voter, view, round).await;
                }

                // Drop rounds below the highest finalized view when that floor advances.
                if finalized > pruned_finalized {
                    work = work.split_off(&finalized);
                    pruned_finalized = finalized;
                }
            },
        }
    }
}
