use super::{Config, Mailbox, Message, Round};
use crate::{
    simplex::{
        actors::voter,
        interesting,
        metrics::{Inbound, Peer},
        scheme::Scheme,
        types::{Activity, Certificate, Vote},
    },
    types::{Epoch, Participant, View, ViewDelta},
    Epochable, Reporter, Viewable,
};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{utils::codec::WrappedReceiver, Blocker, Receiver};
use commonware_parallel::Strategy;
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{
        histogram::{self, Buckets},
        status::GaugeExt,
    },
    Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::{
    channel::{fallible::OneshotExt, mpsc},
    ordered::{Quorum, Set},
};
use prometheus_client::metrics::{
    counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
};
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, sync::Arc};
use tracing::{debug, trace, warn};

/// Tracks the current view together with its elected leader so they update atomically.
type CurrentState = (View, Option<Participant>);

pub struct Actor<
    E: Spawner + Metrics + Clock + CryptoRngCore,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
> {
    context: ContextCell<E>,

    participants: Set<S::PublicKey>,
    scheme: S,

    blocker: B,
    reporter: R,
    strategy: T,

    activity_timeout: ViewDelta,
    skip_timeout: ViewDelta,
    epoch: Epoch,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,

    added: Counter,
    verified: Counter,
    inbound_messages: Family<Inbound, Counter>,
    latest_vote: Family<Peer, Gauge>,
    batch_size: Histogram,
    verify_latency: histogram::Timed<E>,
    recover_latency: histogram::Timed<E>,
}

impl<
        E: Spawner + Metrics + Clock + CryptoRngCore,
        S: Scheme<D>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
        R: Reporter<Activity = Activity<S, D>>,
        T: Strategy,
    > Actor<E, S, B, D, R, T>
{
    pub fn new(context: E, cfg: Config<S, B, R, T>) -> (Self, Mailbox<S, D>) {
        let added = Counter::default();
        let verified = Counter::default();
        let inbound_messages = Family::<Inbound, Counter>::default();
        let batch_size =
            Histogram::new([1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0]);
        context.register(
            "added",
            "number of messages added to the verifier",
            added.clone(),
        );
        context.register("verified", "number of messages verified", verified.clone());
        context.register(
            "inbound_messages",
            "number of inbound messages",
            inbound_messages.clone(),
        );
        let latest_vote = Family::<Peer, Gauge>::default();
        context.register(
            "latest_vote",
            "view of latest vote received per peer",
            latest_vote.clone(),
        );
        for participant in cfg.scheme.participants().iter() {
            latest_vote.get_or_create(&Peer::new(participant)).set(0);
        }
        context.register(
            "batch_size",
            "number of messages in a signature verification batch",
            batch_size.clone(),
        );
        let verify_latency = Histogram::new(Buckets::CRYPTOGRAPHY);
        context.register(
            "verify_latency",
            "latency of signature verification",
            verify_latency.clone(),
        );
        let recover_latency = Histogram::new(Buckets::CRYPTOGRAPHY);
        context.register(
            "recover_latency",
            "certificate recover latency",
            recover_latency.clone(),
        );
        // TODO(#1833): Metrics should use the post-start context
        let clock = Arc::new(context.clone());
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),

                participants: cfg.scheme.participants().clone(),
                scheme: cfg.scheme,

                blocker: cfg.blocker,
                reporter: cfg.reporter,
                strategy: cfg.strategy,

                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
                epoch: cfg.epoch,

                mailbox_receiver: receiver,

                added,
                verified,
                inbound_messages,
                latest_vote,
                batch_size,
                verify_latency: histogram::Timed::new(verify_latency, clock.clone()),
                recover_latency: histogram::Timed::new(recover_latency, clock),
            },
            Mailbox::new(sender),
        )
    }

    fn new_round(&self) -> Round<S, B, D, R> {
        Round::new(
            self.participants.clone(),
            self.scheme.clone(),
            self.blocker.clone(),
            self.reporter.clone(),
        )
    }

    /// Returns true if this network message is a current-view nullify from the elected leader.
    fn should_hint_leader_nullify(
        &self,
        current: CurrentState,
        sender: &S::PublicKey,
        message: &Vote<S, D>,
    ) -> bool {
        let (current_view, current_leader) = current;
        let view = message.view();
        if view != current_view || !matches!(message, Vote::Nullify(_)) {
            return false;
        }

        // Skip local-leader hinting (only useful for verifiers).
        if self
            .scheme
            .me()
            .is_some_and(|me| current_leader == Some(me))
        {
            return false;
        }

        current_leader
            .and_then(|leader| self.participants.key(leader))
            .is_some_and(|leader_key| leader_key == sender)
    }

    pub fn start(
        mut self,
        voter: voter::Mailbox<S, D>,
        vote_receiver: impl Receiver<PublicKey = S::PublicKey>,
        certificate_receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(voter, vote_receiver, certificate_receiver).await
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
        let mut current: CurrentState = (View::zero(), None);
        let mut finalized = View::zero();
        let mut work = BTreeMap::new();
        select_loop! {
            self.context,
            on_start => {
                // Track which view was modified (if any) for certificate construction
                let updated_view;
            },
            on_stopped => {
                debug!("context shutdown, stopping batcher");
            },
            Some(message) = self.mailbox_receiver.recv() else break => match message {
                Message::Update {
                    current: new_current,
                    leader,
                    finalized: new_finalized,
                    active,
                } => {
                    current = (new_current, Some(leader));
                    finalized = new_finalized;
                    work.entry(current.0)
                        .or_insert_with(|| self.new_round())
                        .set_leader(leader);

                    // If we already buffered a leader nullify for this now-current view
                    // (allowed because we accept votes up to `current+1`), we can skip
                    // the leader timeout immediately via the `is_active` response below.
                    let local_is_leader = self.scheme.me().is_some_and(|me| me == leader);
                    let leader_nullified_current = !local_is_leader
                        && work
                            .get(&current.0)
                            .is_some_and(|round| round.has_pending_nullify(leader));

                    // Check if the leader has been active recently
                    let skip_timeout = self.skip_timeout.get() as usize;
                    let is_active = !leader_nullified_current
                        && (
                            // Ensure we have enough data to judge activity (none of this
                            // data may be in the last skip_timeout views if we jumped ahead
                            // to a new view)
                            work.len() < skip_timeout
                            // Leader active in at least one recent round
                            || work
                                .iter()
                                .rev()
                                .take(skip_timeout)
                                .any(|(_, round)| round.is_active(leader))
                        );
                    active.send_lossy(is_active);

                    // Setting leader may enable batch verification
                    updated_view = current.0;
                }
                Message::Constructed(message) => {
                    // If the view isn't interesting, we can skip
                    let view = message.view();
                    if !interesting(self.activity_timeout, finalized, current.0, view, false) {
                        continue;
                    }

                    // Add the message to the verifier
                    work.entry(view)
                        .or_insert_with(|| self.new_round())
                        .add_constructed(message)
                        .await;
                    self.added.inc();
                    updated_view = view;
                }
            },
            // Handle certificates from the network
            Ok((sender, message)) = certificate_receiver.recv() else break => {
                // If there is a decoding error, block
                let Ok(message) = message else {
                    warn!(?sender, "blocking peer for decoding error");
                    self.blocker.block(sender).await;
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
                    warn!(?sender, "blocking peer for epoch mismatch");
                    self.blocker.block(sender).await;
                    continue;
                }

                // Allow future certificates (they advance our view)
                let view = message.view();
                if !interesting(
                    self.activity_timeout,
                    finalized,
                    current.0,
                    view,
                    true, // allow future
                ) {
                    continue;
                }

                match message {
                    Certificate::Notarization(notarization) => {
                        // Skip if we already have a notarization for this view
                        if work.get(&view).is_some_and(|r| r.has_notarization()) {
                            trace!(%view, "skipping duplicate notarization");
                            continue;
                        }

                        // Verify the certificate
                        if !notarization.verify(&mut self.context, &self.scheme, &self.strategy) {
                            warn!(?sender, %view, "blocking peer for invalid notarization");
                            self.blocker.block(sender).await;
                            continue;
                        }

                        // Store and forward to voter
                        work.entry(view)
                            .or_insert_with(|| self.new_round())
                            .set_notarization(notarization.clone());
                        voter
                            .recovered(Certificate::Notarization(notarization))
                            .await;
                    }
                    Certificate::Nullification(nullification) => {
                        // Skip if we already have a nullification for this view
                        if work.get(&view).is_some_and(|r| r.has_nullification()) {
                            trace!(%view, "skipping duplicate nullification");
                            continue;
                        }

                        // Verify the certificate
                        if !nullification.verify::<_, D>(
                            &mut self.context,
                            &self.scheme,
                            &self.strategy,
                        ) {
                            warn!(?sender, %view, "blocking peer for invalid nullification");
                            self.blocker.block(sender).await;
                            continue;
                        }

                        // Store and forward to voter
                        work.entry(view)
                            .or_insert_with(|| self.new_round())
                            .set_nullification(nullification.clone());
                        voter
                            .recovered(Certificate::Nullification(nullification))
                            .await;
                    }
                    Certificate::Finalization(finalization) => {
                        // Skip if we already have a finalization for this view
                        if work.get(&view).is_some_and(|r| r.has_finalization()) {
                            trace!(%view, "skipping duplicate finalization");
                            continue;
                        }

                        // Verify the certificate
                        if !finalization.verify(&mut self.context, &self.scheme, &self.strategy) {
                            warn!(?sender, %view, "blocking peer for invalid finalization");
                            self.blocker.block(sender).await;
                            continue;
                        }

                        // Store and forward to voter
                        work.entry(view)
                            .or_insert_with(|| self.new_round())
                            .set_finalization(finalization.clone());
                        voter
                            .recovered(Certificate::Finalization(finalization))
                            .await;
                    }
                }

                // Certificates are already forwarded to voter, no need for construction
                continue;
            },
            // Handle votes from the network
            Ok((sender, message)) = vote_receiver.recv() else break => {
                // If there is a decoding error, block
                let Ok(message) = message else {
                    warn!(?sender, "blocking peer for decoding error");
                    self.blocker.block(sender).await;
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
                    warn!(?sender, "blocking peer for epoch mismatch");
                    self.blocker.block(sender).await;
                    continue;
                }

                // If the view isn't interesting, we can skip
                let view = message.view();
                if !interesting(self.activity_timeout, finalized, current.0, view, false) {
                    continue;
                }

                // If the current leader explicitly nullifies the current view, hint the voter so
                // it can fast-path timeout without waiting for its local timer. We do this because
                // `nullify` still counts as "activity" for skip-timeout heuristics.
                let leader_nullified_current =
                    self.should_hint_leader_nullify(current, &sender, &message);

                // Add the vote to the verifier
                let peer = Peer::new(&sender);
                let added = work
                    .entry(view)
                    .or_insert_with(|| self.new_round())
                    .add_network(sender, message)
                    .await;
                if added {
                    self.added.inc();

                    // Update per-peer latest vote metric (only if higher than current)
                    let _ = self
                        .latest_vote
                        .get_or_create(&peer)
                        .try_set_max(view.get());

                    // Only fast-path once for the first accepted leader nullify vote.
                    if leader_nullified_current {
                        voter.expire(view).await;
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
                if let Some(round) = work.get_mut(&current.0) {
                    if let Some(me) = self.scheme.me() {
                        if let Some(proposal) = round.forward_proposal(me) {
                            voter.proposal(proposal).await;
                        }
                    }
                }

                // Skip verification and construction for views at or below finalized.
                //
                // We still use interesting() for filtering votes because we want to
                // notify the reporter of all votes within the activity timeout (even
                // if we don't need them in the voter).
                if updated_view <= finalized {
                    continue;
                }

                // Process the updated view (if any)
                let Some(round) = work.get_mut(&updated_view) else {
                    continue;
                };

                // Batch verify votes if ready
                let mut timer = self.verify_latency.timer();
                let verified = if round.ready_notarizes() {
                    Some(round.verify_notarizes(&mut self.context, &self.strategy))
                } else if round.ready_nullifies() {
                    Some(round.verify_nullifies(&mut self.context, &self.strategy))
                } else if round.ready_finalizes() {
                    Some(round.verify_finalizes(&mut self.context, &self.strategy))
                } else {
                    None
                };

                // Process batch verification results
                if let Some((voters, failed)) = verified {
                    timer.observe();

                    // Process verified votes
                    let batch = voters.len() + failed.len();
                    trace!(view = %updated_view, batch, "batch verified votes");
                    self.verified.inc_by(batch as u64);
                    self.batch_size.observe(batch as f64);

                    // Block invalid signers
                    for invalid in failed {
                        if let Some(signer) = self.participants.key(invalid) {
                            warn!(?signer, "blocking peer for invalid signature");
                            self.blocker.block(signer.clone()).await;
                        }
                    }

                    // Store verified votes for certificate construction
                    for valid in voters {
                        round.add_verified(valid);
                    }
                } else {
                    timer.cancel();
                    trace!(
                        current = %current.0,
                        %finalized,
                        "no verifier ready"
                    );
                }

                // Try to construct and forward certificates
                if let Some(notarization) = self
                    .recover_latency
                    .time_some(|| round.try_construct_notarization(&self.scheme, &self.strategy))
                {
                    debug!(view = %updated_view, "constructed notarization, forwarding to voter");
                    voter
                        .recovered(Certificate::Notarization(notarization))
                        .await;
                }
                if let Some(nullification) = self
                    .recover_latency
                    .time_some(|| round.try_construct_nullification(&self.scheme, &self.strategy))
                {
                    debug!(view = %updated_view, "constructed nullification, forwarding to voter");
                    voter
                        .recovered(Certificate::Nullification(nullification))
                        .await;
                }
                if let Some(finalization) = self
                    .recover_latency
                    .time_some(|| round.try_construct_finalization(&self.scheme, &self.strategy))
                {
                    debug!(view = %updated_view, "constructed finalization, forwarding to voter");
                    voter
                        .recovered(Certificate::Finalization(finalization))
                        .await;
                }

                // Drop any rounds that are no longer interesting
                while work.first_key_value().is_some_and(|(&view, _)| {
                    !interesting(self.activity_timeout, finalized, current.0, view, false)
                }) {
                    work.pop_first();
                }
            },
        }
    }
}
