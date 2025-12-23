use super::{Config, Mailbox, Message, Round};
use crate::{
    simplex::{
        actors::voter,
        interesting,
        metrics::Inbound,
        scheme::Scheme,
        types::{Activity, Certificate, Vote},
    },
    types::{Epoch, View, ViewDelta},
    Epochable, Reporter, Viewable,
};
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_p2p::{utils::codec::WrappedReceiver, Blocker, Receiver};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::histogram::{self, Buckets},
    Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::ordered::{Quorum, Set};
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family, histogram::Histogram};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, sync::Arc};
use tracing::{debug, trace, warn};

pub struct Actor<
    E: Spawner + Metrics + Clock + Rng + CryptoRng,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    context: ContextCell<E>,

    participants: Set<S::PublicKey>,
    scheme: S,

    blocker: B,
    reporter: R,

    activity_timeout: ViewDelta,
    skip_timeout: ViewDelta,
    epoch: Epoch,
    namespace: Vec<u8>,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,

    added: Counter,
    verified: Counter,
    inbound_messages: Family<Inbound, Counter>,
    batch_size: Histogram,
    verify_latency: histogram::Timed<E>,
    recover_latency: histogram::Timed<E>,
}

impl<
        E: Spawner + Metrics + Clock + Rng + CryptoRng,
        S: Scheme<D>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
        R: Reporter<Activity = Activity<S, D>>,
    > Actor<E, S, B, D, R>
{
    pub fn new(context: E, cfg: Config<S, B, R>) -> (Self, Mailbox<S, D>) {
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
        let participants = cfg.scheme.participants().clone();
        (
            Self {
                context: ContextCell::new(context),

                participants,
                scheme: cfg.scheme,

                blocker: cfg.blocker,
                reporter: cfg.reporter,

                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
                epoch: cfg.epoch,
                namespace: cfg.namespace,

                mailbox_receiver: receiver,

                added,
                verified,
                inbound_messages,
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
        let mut current = View::zero();
        let mut finalized = View::zero();
        let mut work = BTreeMap::new();
        let mut shutdown = self.context.stopped();
        loop {
            // Track which view was modified (if any) for certificate construction
            let updated_view;

            // Handle next message
            select! {
                _ = &mut shutdown => {
                    debug!("context shutdown, stopping batcher");
                    break;
                },
                message = self.mailbox_receiver.next() => {
                    match message {
                        Some(Message::Update {
                            current: new_current,
                            leader,
                            finalized: new_finalized,
                            active,
                        }) => {
                            current = new_current;
                            finalized = new_finalized;
                            work
                                .entry(current)
                                .or_insert_with(|| self.new_round())
                                .set_leader(leader);

                            // Check if the leader has been active recently
                            let skip_timeout = self.skip_timeout.get() as usize;
                            let is_active =
                                // Ensure we have enough data to judge activity (none of this
                                // data may be in the last skip_timeout views if we jumped ahead
                                // to a new view)
                                work.len() < skip_timeout
                                // Leader active in at least one recent round
                                || work.iter().rev().take(skip_timeout).any(|(_, round)| round.is_active(leader));
                            active.send(is_active).unwrap();

                            // Setting leader may enable batch verification
                            updated_view = current;
                        }
                        Some(Message::Constructed(message)) => {
                            // If the view isn't interesting, we can skip
                            let view = message.view();
                            if !interesting(
                                self.activity_timeout,
                                finalized,
                                current,
                                view,
                                false,
                            ) {
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
                        None => {
                            break;
                        }
                    }
                },
                // Handle certificates from the network
                message = certificate_receiver.recv() => {
                    // If the channel is closed, we should exit
                    let Ok((sender, message)) = message else {
                        break;
                    };

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
                        current,
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
                            if !notarization.verify(
                                &mut self.context,
                                &self.scheme,
                                &self.namespace,
                            ) {
                                warn!(?sender, %view, "blocking peer for invalid notarization");
                                self.blocker.block(sender).await;
                                continue;
                            }

                            // Store and forward to voter
                            work
                                .entry(view)
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
                                &self.namespace,
                            ) {
                                warn!(?sender, %view, "blocking peer for invalid nullification");
                                self.blocker.block(sender).await;
                                continue;
                            }

                            // Store and forward to voter
                            work
                                .entry(view)
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
                            if !finalization.verify(
                                &mut self.context,
                                &self.scheme,
                                &self.namespace,
                            ) {
                                warn!(?sender, %view, "blocking peer for invalid finalization");
                                self.blocker.block(sender).await;
                                continue;
                            }

                            // Store and forward to voter
                            work
                                .entry(view)
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
                message = vote_receiver.recv() => {
                    // If the channel is closed, we should exit
                    let Ok((sender, message)) = message else {
                        break;
                    };

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
                    if !interesting(
                        self.activity_timeout,
                        finalized,
                        current,
                        view,
                        false,
                    ) {
                        continue;
                    }

                    // Add the vote to the verifier
                    if work
                        .entry(view)
                        .or_insert_with(|| self.new_round())
                        .add_network(sender, message)
                        .await {
                            self.added.inc();
                        }
                    updated_view = view;
                },
            }
            assert!(
                updated_view != View::zero(),
                "updated view must be greater than zero"
            );

            // Forward leader's proposal to voter (if we're not the leader and haven't already)
            if let Some(round) = work.get_mut(&current) {
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
                Some(round.verify_notarizes(&mut self.context, &self.namespace))
            } else if round.ready_nullifies() {
                Some(round.verify_nullifies(&mut self.context, &self.namespace))
            } else if round.ready_finalizes() {
                Some(round.verify_finalizes(&mut self.context, &self.namespace))
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
                    %current,
                    %finalized,
                    "no verifier ready"
                );
            }

            // Try to construct and forward certificates
            if let Some(notarization) = self
                .recover_latency
                .time_some(|| round.try_construct_notarization(&self.scheme))
            {
                debug!(view = %updated_view, "constructed notarization, forwarding to voter");
                voter
                    .recovered(Certificate::Notarization(notarization))
                    .await;
            }
            if let Some(nullification) = self
                .recover_latency
                .time_some(|| round.try_construct_nullification(&self.scheme))
            {
                debug!(view = %updated_view, "constructed nullification, forwarding to voter");
                voter
                    .recovered(Certificate::Nullification(nullification))
                    .await;
            }
            if let Some(finalization) = self
                .recover_latency
                .time_some(|| round.try_construct_finalization(&self.scheme))
            {
                debug!(view = %updated_view, "constructed finalization, forwarding to voter");
                voter
                    .recovered(Certificate::Finalization(finalization))
                    .await;
            }

            // Drop any rounds that are no longer interesting
            while work.first_key_value().is_some_and(|(&view, _)| {
                !interesting(self.activity_timeout, finalized, current, view, false)
            }) {
                work.pop_first();
            }
        }
    }
}
