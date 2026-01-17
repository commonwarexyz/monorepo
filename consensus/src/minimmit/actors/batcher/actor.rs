//! Batcher actor implementation for Minimmit consensus.
//!
//! The batcher handles:
//! - Receiving votes from the network
//! - Batch signature verification
//! - Forwarding verified votes to the voter (state machine handles certificate construction)
//! - Forwarding verified certificates from the network to the voter

use super::{ingress::Message, Config, Mailbox, Round};
use crate::{
    minimmit::{
        actors::voter,
        interesting,
        metrics::{Inbound, Peer},
        scheme::Scheme,
        types::{Activity, Certificate, Vote},
    },
    types::{Epoch, View, ViewDelta},
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

/// Batcher actor for Minimmit consensus.
///
/// Handles message batching, verification, and forwarding to voter.
/// Certificate construction is delegated to the state machine in the voter.
pub struct Actor<E, S, B, D, R, T>
where
    E: Spawner + Metrics + Clock + CryptoRngCore,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
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
}

impl<E, S, B, D, R, T> Actor<E, S, B, D, R, T>
where
    E: Spawner + Metrics + Clock + CryptoRngCore,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
    /// Create a new batcher actor.
    pub fn new(context: E, cfg: Config<S, B, D, R, T>) -> (Self, Mailbox<S, D>) {
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
                verify_latency: histogram::Timed::new(verify_latency, clock),
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

    /// Start the batcher actor.
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
        select_loop! {
            self.context,
            on_start => {
                // Track which view was modified (if any) for verification
                let updated_view;
            },
            on_stopped => {
                debug!("context shutdown, stopping batcher");
            },
            Some(message) = self.mailbox_receiver.recv() else break => {
                match message {
                    Message::Update {
                        current: new_current,
                        leader,
                        finalized: new_finalized,
                        active,
                    } => {
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
                        active.send_lossy(is_active);

                        // Setting leader may enable batch verification
                        updated_view = current;
                    }
                    Message::Constructed(message) => {
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
                    Message::MNotarizationExists(view) => {
                        // Mark that M-quorum was reached for this view.
                        // This allows batching toward L-quorum even after crash
                        // recovery where the verified vote count is lost.
                        if let Some(round) = work.get_mut(&view) {
                            round.mark_m_quorum_reached();
                        }
                        // No verification needed, just continue
                        continue;
                    }
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
                    Certificate::MNotarization(_) => Inbound::m_notarization(&sender),
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

                // Check if we already have this certificate type for this view
                let round = work.entry(view).or_insert_with(|| self.new_round());
                let already_have = match &message {
                    Certificate::MNotarization(m) => round.has_m_notarization(m.proposal.payload),
                    Certificate::Nullification(_) => round.has_nullification(),
                    Certificate::Finalization(_) => round.has_finalization(),
                };
                if already_have {
                    trace!(%view, "skipping duplicate certificate");
                    continue;
                }

                // Verify the certificate signature
                let valid = match &message {
                    Certificate::MNotarization(m) => {
                        m.verify(&mut self.context, &self.scheme, &self.strategy)
                    }
                    Certificate::Nullification(n) => {
                        n.verify::<_, D>(&mut self.context, &self.scheme, &self.strategy)
                    }
                    Certificate::Finalization(f) => {
                        f.verify(&mut self.context, &self.scheme, &self.strategy)
                    }
                };

                if !valid {
                    warn!(?sender, %view, "blocking peer for invalid certificate");
                    self.blocker.block(sender).await;
                    continue;
                }

                // Mark as received and forward to voter
                round.mark_certificate(&message);
                voter.verified_certificate(message);

                // Certificates are forwarded directly, no need for further processing
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
                    let peer = Peer::new(&sender);
                    if work
                        .entry(view)
                        .or_insert_with(|| self.new_round())
                        .add_network(sender, message)
                        .await {
                            self.added.inc();

                            // Update per-peer latest vote metric (only if higher than current)
                            let _ = self
                                .latest_vote
                                .get_or_create(&peer)
                                .try_set_max(view.get());
                        }
                    updated_view = view;
            },
            on_end => {
                assert!(
                    updated_view != View::zero(),
                    "updated view must be greater than zero"
                );

                // Forward leader's proposal to voter (if we're not the leader and haven't already)
                if let Some(round) = work.get_mut(&current) {
                    if let Some(me) = self.scheme.me() {
                        if let Some(proposal) = round.forward_proposal(me) {
                            voter.proposal(proposal);
                        }
                    }
                }

                // Skip verification for views at or below finalized.
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

                    // Forward verified votes to voter (state machine handles certificate construction)
                    for vote in voters {
                        match vote {
                            Vote::Notarize(notarize) => {
                                voter.verified_notarize(notarize);
                            }
                            Vote::Nullify(nullify) => {
                                voter.verified_nullify(nullify);
                            }
                        }
                    }
                } else {
                    timer.cancel();
                    trace!(
                        %current,
                        %finalized,
                        "no verifier ready"
                    );
                }

                // Drop any rounds that are no longer interesting
                while work.first_key_value().is_some_and(|(&view, _)| {
                    !interesting(self.activity_timeout, finalized, current, view, false)
                }) {
                    work.pop_first();
                }
            },
        }
    }
}
