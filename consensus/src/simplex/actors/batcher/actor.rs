use super::{Action, Config, Mailbox, Message, Round};
use crate::{
    simplex::{
        actors::voter,
        interesting,
        metrics::Inbound,
        signing_scheme::Scheme,
        types::{Activity, Voter},
    },
    types::{Epoch, View, ViewDelta},
    Epochable, Reporter, Viewable,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{utils::codec::WrappedReceiver, Blocker, Receiver};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::histogram::{self, Buckets},
    Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::set::{Ordered, OrderedQuorum};
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family, histogram::Histogram};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, sync::Arc};
use tracing::{debug, trace, warn};

pub struct Actor<
    E: Spawner + Metrics + Clock + Rng + CryptoRng,
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    context: ContextCell<E>,

    participants: Ordered<P>,
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
        P: PublicKey,
        S: Scheme<PublicKey = P>,
        B: Blocker<PublicKey = P>,
        D: Digest,
        R: Reporter<Activity = Activity<S, D>>,
    > Actor<E, P, S, B, D, R>
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

    fn new_round(&self, batch: bool) -> Round<P, S, B, D, R> {
        Round::new(
            self.participants.clone(),
            self.scheme.clone(),
            self.blocker.clone(),
            self.reporter.clone(),
            self.inbound_messages.clone(),
            batch,
        )
    }

    pub fn start(
        mut self,
        voter: voter::Mailbox<S, D>,
        vote_receiver: impl Receiver<PublicKey = P>,
        certificate_receiver: impl Receiver<PublicKey = P>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(voter, vote_receiver, certificate_receiver).await
        )
    }

    pub async fn run(
        mut self,
        mut voter: voter::Mailbox<S, D>,
        vote_receiver: impl Receiver<PublicKey = P>,
        certificate_receiver: impl Receiver<PublicKey = P>,
    ) {
        // Wrap channels
        //
        // vote_receiver: receives votes from network
        // certificate_receiver: receives certificates from network
        let mut vote_receiver: WrappedReceiver<_, Voter<S, D>> =
            WrappedReceiver::new(self.scheme.certificate_codec_config(), vote_receiver);
        let mut certificate_receiver: WrappedReceiver<_, Voter<S, D>> =
            WrappedReceiver::new(self.scheme.certificate_codec_config(), certificate_receiver);

        // Initialize view data structures
        let mut current = View::zero();
        let mut finalized = View::zero();
        let mut leader = 0u32;
        #[allow(clippy::type_complexity)]
        let mut work: BTreeMap<View, Round<P, S, B, D, R>> = BTreeMap::new();
        let mut initialized = false;
        let mut shutdown = self.context.stopped();
        loop {
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
                            leader: new_leader,
                            finalized: new_finalized,
                            active,
                        }) => {
                            current = new_current;
                            finalized = new_finalized;
                            leader = new_leader;
                            work.entry(current)
                                .or_insert_with(|| self.new_round(initialized))
                                .set_leader(leader);
                            initialized = true;

                            // If we haven't seen enough rounds yet, assume active
                            if current < View::new(self.skip_timeout.get())
                                || (work.len() as u64) < self.skip_timeout.get()
                            {
                                active.send(true).unwrap();
                                continue;
                            }
                            let min_view = current.saturating_sub(self.skip_timeout);

                            // Check if the leader is active within the views we know about
                            let mut is_active = false;
                            for (view, round) in work.iter().rev() {
                                // If we haven't seen activity within the skip timeout, break
                                if *view < min_view {
                                    break;
                                }

                                // Don't penalize leader for not being a participant
                                let Some(active) = round.is_active(leader) else {
                                    is_active = true;
                                    break;
                                };

                                // If the leader is explicitly active, we can stop
                                if active {
                                    is_active = true;
                                    break;
                                }
                            }
                            active.send(is_active).unwrap();
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
                            let added = work.entry(view)
                                .or_insert_with(|| self.new_round(initialized))
                                .add_constructed(message)
                                .await;
                            if added {
                                self.added.inc();
                            }
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

                    // If the epoch is not the current epoch, block
                    if message.epoch() != self.epoch {
                        warn!(?sender, "blocking peer for epoch mismatch");
                        self.blocker.block(sender).await;
                        continue;
                    }

                    // Handle certificate based on type
                    let view = message.view();

                    // Allow future certificates (they advance our view)
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
                        Voter::Notarization(notarization) => {
                            // Update metrics
                            self.inbound_messages
                                .get_or_create(&Inbound::notarization(&sender))
                                .inc();

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
                            let round = work
                                .entry(view)
                                .or_insert_with(|| self.new_round(initialized));
                            round.set_notarization(notarization.clone());
                            voter
                                .recovered(Voter::Notarization(notarization))
                                .await;
                        }
                        Voter::Nullification(nullification) => {
                            // Update metrics
                            self.inbound_messages
                                .get_or_create(&Inbound::nullification(&sender))
                                .inc();

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
                            let round = work
                                .entry(view)
                                .or_insert_with(|| self.new_round(initialized));
                            round.set_nullification(nullification.clone());
                            voter
                                .recovered(Voter::Nullification(nullification))
                                .await;
                        }
                        Voter::Finalization(finalization) => {
                            // Update metrics
                            self.inbound_messages
                                .get_or_create(&Inbound::finalization(&sender))
                                .inc();

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
                            let round = work
                                .entry(view)
                                .or_insert_with(|| self.new_round(initialized));
                            round.set_finalization(finalization.clone());
                            voter
                                .recovered(Voter::Finalization(finalization))
                                .await;
                        }
                        Voter::Notarize(_) | Voter::Nullify(_) | Voter::Finalize(_) => {
                            // Votes should come through vote_receiver, not certificate_receiver
                            warn!(?sender, "blocking peer for sending vote on certificate channel");
                            self.blocker.block(sender).await;
                            continue;
                        }
                    }
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
                    let result = work
                        .entry(view)
                        .or_insert_with(|| self.new_round(initialized))
                        .add_network(sender, message, leader)
                        .await;
                    match result {
                        Action::Skip => {}
                        Action::Verify => {
                            self.added.inc();
                        }
                        Action::VerifyAndForward(proposal) => {
                            self.added.inc();
                            // Forward leader's proposal immediately so voter can start verification
                            debug!(%view, ?proposal, "forwarding leader proposal to voter");
                            voter.proposal(proposal).await;
                        }
                    }
                },
            }

            // Look for a ready verifier (prioritizing the current view)
            let mut timer = self.verify_latency.timer();
            #[allow(clippy::type_complexity)]
            let mut selected: Option<(View, Vec<Voter<S, D>>, Vec<u32>)> = None;
            if let Some(round) = work.get_mut(&current) {
                if round.ready_notarizes() {
                    let (voters, failed) =
                        round.verify_notarizes(&mut self.context, &self.namespace);
                    selected = Some((current, voters, failed));
                } else if round.ready_nullifies() {
                    let (voters, failed) =
                        round.verify_nullifies(&mut self.context, &self.namespace);
                    selected = Some((current, voters, failed));
                }
            }
            if selected.is_none() {
                let potential = work
                    .iter_mut()
                    .rev()
                    .find(|(view, round)| {
                        **view != current && **view >= finalized && round.ready_finalizes()
                    })
                    .map(|(view, round)| (*view, round));
                if let Some((view, round)) = potential {
                    let (voters, failed) =
                        round.verify_finalizes(&mut self.context, &self.namespace);
                    selected = Some((view, voters, failed));
                }
            }
            let Some((view, voters, failed)) = selected else {
                trace!(
                    %current,
                    %finalized,
                    waiting = work.len(),
                    "no verifier ready"
                );
                continue;
            };
            timer.observe();

            // Process verified votes
            let batch = voters.len() + failed.len();
            trace!(%view, batch, "batch verified votes");
            self.verified.inc_by(batch as u64);
            self.batch_size.observe(batch as f64);

            // Block invalid signers
            for invalid in failed {
                if let Some(signer) = self.participants.key(invalid) {
                    warn!(?signer, "blocking peer for invalid signature");
                    self.blocker.block(signer.clone()).await;
                }
            }

            // Get the round for this view to construct certificates
            let Some(round) = work.get_mut(&view) else {
                continue;
            };

            // Store verified votes for certificate construction
            for voter in voters {
                round.add_recovered(voter);
            }

            // Try to construct and forward certificates
            let mut recover_timer = self.recover_latency.timer();
            if let Some(notarization) = round.try_construct_notarization(&self.scheme) {
                recover_timer.observe();
                debug!(%view, "constructed notarization, forwarding to voter");
                voter.recovered(Voter::Notarization(notarization)).await;
            } else {
                recover_timer.cancel();
            }
            let mut recover_timer = self.recover_latency.timer();
            if let Some(nullification) = round.try_construct_nullification(&self.scheme) {
                recover_timer.observe();
                debug!(%view, "constructed nullification, forwarding to voter");
                voter.recovered(Voter::Nullification(nullification)).await;
            } else {
                recover_timer.cancel();
            }
            let mut recover_timer = self.recover_latency.timer();
            if let Some(finalization) = round.try_construct_finalization(&self.scheme) {
                recover_timer.observe();
                debug!(%view, "constructed finalization, forwarding to voter");
                voter.recovered(Voter::Finalization(finalization)).await;
            } else {
                recover_timer.cancel();
            }

            // Drop any rounds that are no longer interesting
            loop {
                let Some((view, _)) = work.first_key_value() else {
                    break;
                };
                let view = *view;
                if interesting(self.activity_timeout, finalized, current, view, false) {
                    break;
                }
                work.remove(&view);
            }
        }
    }
}
