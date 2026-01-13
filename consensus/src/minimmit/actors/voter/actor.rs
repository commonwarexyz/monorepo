//! Voter actor implementation for minimmit consensus.
//!
//! Unlike simplex which has separate batcher and voter actors, minimmit combines
//! vote collection and consensus state management into a single actor. This simplifies
//! the architecture while handling:
//!
//! - Vote collection and verification
//! - Certificate assembly at M threshold (2f+1)
//! - Finalization at L threshold (n-f)
//! - Nullify-by-contradiction logic
//! - Proposal and verification
//! - Journal persistence for crash recovery

use super::{
    ingress::Message,
    state::{Config as StateConfig, State},
    Mailbox,
};
use crate::{
    minimmit::{
        actors::resolver,
        elector::Config as Elector,
        metrics::{self, Inbound, Outbound},
        scheme::Scheme,
        types::{
            Activity, Artifact, Attributable, Certificate, ConflictingNotarize, Context,
            Notarization, Notarize, Nullification, Nullify, Proposal, Vote,
        },
    },
    types::{Epoch, Round as Rnd, View, ViewDelta},
    Automaton, Epochable, Relay, Reporter, Viewable, LATENCY,
};
use commonware_codec::Read;
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_p2p::{
    utils::codec::{WrappedReceiver, WrappedSender},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
use core::panic;
use futures::{
    channel::{mpsc, oneshot},
    pin_mut, StreamExt,
};
use prometheus_client::metrics::{counter::Counter, family::Family, histogram::Histogram};
use rand_core::CryptoRngCore;
use std::{
    num::NonZeroUsize,
    pin::Pin,
    task::{self, Poll},
    time::Duration,
};
use tracing::{debug, info, trace, warn};

/// Tracks which certificate type was received from the resolver in the current iteration.
///
/// Used to prevent "boomerang" where we send a certificate back to the resolver
/// that we just received from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Resolved {
    #[default]
    None,
    Notarization,
    Nullification,
}

/// An outstanding request to the automaton.
struct Request<V: Viewable, R>(
    /// Attached context for the pending item. Must yield a view.
    V,
    /// Oneshot receiver that the automaton is expected to respond over.
    oneshot::Receiver<R>,
);

impl<V: Viewable, R> Viewable for Request<V, R> {
    fn view(&self) -> View {
        self.0.view()
    }
}

/// Adapter that polls an [Option<Request<V, R>>] in place.
struct Waiter<'a, V: Viewable, R>(&'a mut Option<Request<V, R>>);

impl<V: Viewable, R> core::future::Future for Waiter<'_, V, R> {
    type Output = (V, Result<R, oneshot::Canceled>);

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let Waiter(slot) = self.get_mut();
        let res = match slot.as_mut() {
            Some(Request(_, ref mut receiver)) => match Pin::new(receiver).poll(cx) {
                Poll::Ready(res) => res,
                Poll::Pending => return Poll::Pending,
            },
            None => return Poll::Pending,
        };
        let Request(v, _) = slot.take().expect("request must exist");
        Poll::Ready((v, res))
    }
}

/// Configuration for the voter actor.
pub struct Config<
    S: commonware_cryptography::certificate::Scheme,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: Automaton<Context = Context<D, S::PublicKey>, Digest = D>,
    R: Relay,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
> {
    /// Signing scheme.
    pub scheme: S,
    /// Leader elector configuration.
    pub elector: L,
    /// Network blocker.
    pub blocker: B,
    /// Application automaton.
    pub automaton: A,
    /// Relay for broadcasting.
    pub relay: R,
    /// Activity reporter.
    pub reporter: F,
    /// Verification strategy.
    pub strategy: T,
    /// Storage partition.
    pub partition: String,
    /// Current epoch.
    pub epoch: Epoch,
    /// M quorum threshold (2f+1).
    pub m_quorum: usize,
    /// L quorum threshold (n-f).
    pub l_quorum: usize,
    /// Leader timeout duration.
    pub leader_timeout: Duration,
    /// Nullify retry duration.
    pub nullify_retry: Duration,
    /// Activity tracking window.
    pub activity_timeout: ViewDelta,
    /// Mailbox size.
    pub mailbox_size: usize,
    /// Replay buffer size.
    pub replay_buffer: NonZeroUsize,
    /// Write buffer size.
    pub write_buffer: NonZeroUsize,
    /// Buffer pool.
    pub buffer_pool: PoolRef,
}

/// The voter actor.
pub struct Actor<
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: Automaton<Context = Context<D, S::PublicKey>, Digest = D>,
    R: Relay,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
> {
    context: ContextCell<E>,
    state: State<E, S, L, D>,
    blocker: B,
    automaton: A,
    relay: R,
    reporter: F,
    strategy: T,

    epoch: Epoch,
    m_quorum: usize,
    l_quorum: usize,
    certificate_config: <S::Certificate as Read>::Cfg,
    partition: String,
    replay_buffer: NonZeroUsize,
    write_buffer: NonZeroUsize,
    buffer_pool: PoolRef,
    journal: Option<Journal<E, Artifact<S, D>>>,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,

    inbound_messages: Family<Inbound, Counter>,
    outbound_messages: Family<Outbound, Counter>,
    notarization_latency: Histogram,
}

impl<
        E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
        S: Scheme<D>,
        L: Elector<S>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
        A: Automaton<Context = Context<D, S::PublicKey>, Digest = D>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<S, D>>,
        T: Strategy,
    > Actor<E, S, L, B, D, A, R, F, T>
{
    /// Creates a new voter actor and returns the actor and its mailbox.
    pub fn new(context: E, cfg: Config<S, L, B, D, A, R, F, T>) -> (Self, Mailbox<S, D>) {
        // Initialize metrics
        let inbound_messages = Family::<Inbound, Counter>::default();
        let outbound_messages = Family::<Outbound, Counter>::default();
        let notarization_latency = Histogram::new(LATENCY);
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

        // Initialize mailbox
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        let certificate_config = cfg.scheme.certificate_codec_config();

        // Initialize state
        let epoch = cfg.epoch;
        let activity_timeout = cfg.activity_timeout;
        let state = State::new(
            context.with_label("state"),
            StateConfig {
                scheme: cfg.scheme,
                elector: cfg.elector,
                epoch,
                activity_timeout,
                leader_timeout: cfg.leader_timeout,
                nullify_retry: cfg.nullify_retry,
            },
        );

        (
            Self {
                context: ContextCell::new(context),
                state,
                blocker: cfg.blocker,
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,
                strategy: cfg.strategy,

                epoch,
                m_quorum: cfg.m_quorum,
                l_quorum: cfg.l_quorum,
                certificate_config,
                partition: cfg.partition,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                buffer_pool: cfg.buffer_pool,
                journal: None,

                mailbox_receiver,

                inbound_messages,
                outbound_messages,
                notarization_latency,
            },
            mailbox,
        )
    }

    /// Returns the elapsed wall-clock seconds for `view` when we are its leader.
    fn leader_elapsed(&self, view: View) -> Option<f64> {
        let elapsed = self.state.elapsed_since_start(view)?;
        let leader = self.state.leader_index(view)?;
        if !self.state.is_me(leader) {
            return None;
        }
        Some(elapsed.as_secs_f64())
    }

    /// Drops views that are below the activity floor.
    async fn prune_views(&mut self) {
        let removed = self.state.prune();
        if removed.is_empty() {
            return;
        }
        for view in &removed {
            debug!(
                %view,
                last_finalized = %self.state.last_finalized(),
                "pruned view"
            );
        }
        if let Some(journal) = self.journal.as_mut() {
            journal
                .prune(self.state.min_active().get())
                .await
                .expect("unable to prune journal");
        }
    }

    /// Appends a verified message to the journal.
    async fn append_journal(&mut self, view: View, artifact: Artifact<S, D>) {
        if let Some(journal) = self.journal.as_mut() {
            journal
                .append(view.get(), artifact)
                .await
                .expect("unable to append to journal");
        }
    }

    /// Syncs the journal so other replicas can recover messages in `view`.
    async fn sync_journal(&mut self, view: View) {
        if let Some(journal) = self.journal.as_mut() {
            journal
                .sync(view.get())
                .await
                .expect("unable to sync journal");
        }
    }

    /// Send a vote to every peer.
    async fn broadcast_vote<Sp: Sender>(
        &mut self,
        sender: &mut WrappedSender<Sp, Vote<S, D>>,
        vote: Vote<S, D>,
    ) {
        // Update outbound metrics
        let metric = match &vote {
            Vote::Notarize(_) => metrics::Outbound::notarize(),
            Vote::Nullify(_) => metrics::Outbound::nullify(),
        };
        self.outbound_messages.get_or_create(metric).inc();

        // Broadcast vote
        sender.send(Recipients::All, vote, true).await.unwrap();
    }

    /// Send a certificate to every peer.
    async fn broadcast_certificate<Sp: Sender>(
        &mut self,
        sender: &mut WrappedSender<Sp, Certificate<S, D>>,
        certificate: Certificate<S, D>,
    ) {
        // Update outbound metrics
        let metric = match &certificate {
            Certificate::Notarization(_) => metrics::Outbound::notarization(),
            Certificate::Nullification(_) => metrics::Outbound::nullification(),
        };
        self.outbound_messages.get_or_create(metric).inc();

        // Broadcast certificate
        sender
            .send(Recipients::All, certificate, true)
            .await
            .unwrap();
    }

    /// Blocks an equivocator.
    async fn block_equivocator(&mut self, equivocator: Option<S::PublicKey>) {
        let Some(equivocator) = equivocator else {
            return;
        };
        warn!(?equivocator, "blocking equivocator");
        self.blocker.block(equivocator).await;
    }

    /// Attempt to propose a new block.
    async fn try_propose(&mut self) -> Option<Request<Context<D, S::PublicKey>, D>> {
        // Check if we are ready to propose
        let context = self.state.try_propose()?;

        // Request proposal from application
        debug!(round = ?context.round, "requested proposal from automaton");
        let receiver = self.automaton.propose(context.clone()).await;
        Some(Request(context, receiver))
    }

    /// Attempt to verify a proposed block.
    async fn try_verify(&mut self) -> Option<Request<Context<D, S::PublicKey>, bool>> {
        // Check if we are ready to verify
        let (context, proposal) = self.state.try_verify()?;

        // Request verification
        debug!(?proposal, "requested proposal verification");
        let receiver = self
            .automaton
            .verify(context.clone(), proposal.payload)
            .await;
        Some(Request(context, receiver))
    }

    /// Handle a timeout.
    async fn handle_timeout<Sp: Sender, Sr: Sender>(
        &mut self,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
    ) {
        // Process nullify (and persist it if it is a first attempt)
        let (retry, nullify, entry) = self.state.handle_timeout();
        if let Some(nullify) = nullify {
            if !retry {
                self.handle_nullify(nullify.clone()).await;

                // Sync the journal
                self.sync_journal(nullify.view()).await;
            }

            // Add local vote to VoteTracker for certificate assembly
            self.state.add_nullify_vote(nullify.view(), nullify.clone());

            // Report local vote activity
            self.reporter
                .report(Activity::Nullify(nullify.clone()))
                .await;

            // Broadcast nullify
            debug!(round=?nullify.round(), "broadcasting nullify");
            self.broadcast_vote(vote_sender, Vote::Nullify(nullify))
                .await;
        }

        // Broadcast entry to help others enter the view
        if let Some(certificate) = entry {
            self.broadcast_certificate(certificate_sender, certificate)
                .await;
        }
    }

    /// Records a locally verified nullify vote and ensures the round exists.
    async fn handle_nullify(&mut self, nullify: Nullify<S>) {
        self.append_journal(nullify.view(), Artifact::Nullify(nullify))
            .await;
    }

    /// Tracks a verified nullification certificate if it is new.
    async fn handle_nullification(&mut self, nullification: Nullification<S>) {
        let view = nullification.view();
        let artifact = Artifact::Nullification(nullification.clone());

        // Add verified nullification to journal
        if !self.state.add_nullification(nullification) {
            return;
        }
        self.append_journal(view, artifact).await;
    }

    /// Persists our notarize vote to the journal for crash recovery.
    async fn handle_notarize(&mut self, notarize: Notarize<S, D>) {
        self.append_journal(notarize.view(), Artifact::Notarize(notarize))
            .await;
    }

    /// Records a notarization certificate and blocks any equivocating leader.
    async fn handle_notarization(&mut self, notarization: Notarization<S, D>) {
        let view = notarization.view();
        let artifact = Artifact::Notarization(notarization.clone());
        let (added, equivocator) = self.state.add_notarization(notarization);
        if added {
            self.append_journal(view, artifact).await;
        }
        self.block_equivocator(equivocator).await;
    }

    /// Handles a vote received from the network.
    ///
    /// This verifies the vote signature, adds it to the VoteTracker,
    /// and checks for certificate thresholds.
    async fn handle_vote<Sp: Sender, Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        sender: S::PublicKey,
        vote: Vote<S, D>,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
    ) {
        let view = vote.view();

        // Verify the vote signature and add to tracker
        match vote {
            Vote::Notarize(notarize) => {
                // Verify signature
                if !notarize.verify(&mut self.context, self.state.scheme(), &self.strategy) {
                    warn!(?sender, %view, "blocking peer for invalid notarize signature");
                    self.blocker.block(sender).await;
                    return;
                }

                // If this is from the leader, extract the proposal
                // (In minimmit, the leader's notarize vote serves as the proposal)
                if let Some(leader_idx) = self.state.leader_index(view) {
                    if notarize.signer() == leader_idx {
                        trace!(%view, "received leader's notarize vote, setting proposal");
                        self.state.set_proposal(view, notarize.proposal.clone());
                    }
                }

                // Report activity
                self.reporter
                    .report(Activity::Notarize(notarize.clone()))
                    .await;

                // Add to vote tracker
                let (added, equivocator, conflict) = self.state.add_notarize_vote(view, notarize);

                // Report and handle conflict if detected
                if let Some(conflicting) = conflict {
                    self.reporter
                        .report(Activity::ConflictingNotarize(conflicting))
                        .await;
                }

                if !added {
                    self.block_equivocator(equivocator).await;
                    return;
                }
            }
            Vote::Nullify(nullify) => {
                // Verify signature
                if !nullify.verify::<_, D>(&mut self.context, self.state.scheme(), &self.strategy) {
                    warn!(?sender, %view, "blocking peer for invalid nullify signature");
                    self.blocker.block(sender).await;
                    return;
                }

                // Report activity
                self.reporter
                    .report(Activity::Nullify(nullify.clone()))
                    .await;

                // Add to vote tracker
                let (added, equivocator) = self.state.add_nullify_vote(view, nullify);
                if !added {
                    return;
                }
                self.block_equivocator(equivocator).await;
            }
        }

        // Check for certificate thresholds and finalization
        self.check_thresholds(resolver, vote_sender, certificate_sender, view)
            .await;
    }

    /// Handles a certificate received from the network (not from resolver).
    async fn handle_certificate_from_network(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        sender: S::PublicKey,
        certificate: Certificate<S, D>,
    ) {
        let view = certificate.view();

        // Verify the certificate signature
        match &certificate {
            Certificate::Notarization(notarization) => {
                if !notarization.verify(&mut self.context, self.state.scheme(), &self.strategy) {
                    warn!(?sender, %view, "blocking peer for invalid notarization");
                    self.blocker.block(sender).await;
                    return;
                }
                trace!(%view, "received notarization from network");
                self.handle_notarization(notarization.clone()).await;
                // Notify resolver (not from resolver, so don't skip)
                resolver
                    .updated(Certificate::Notarization(notarization.clone()))
                    .await;
            }
            Certificate::Nullification(nullification) => {
                if !nullification.verify::<_, D>(
                    &mut self.context,
                    self.state.scheme(),
                    &self.strategy,
                ) {
                    warn!(?sender, %view, "blocking peer for invalid nullification");
                    self.blocker.block(sender).await;
                    return;
                }
                trace!(%view, "received nullification from network");
                self.handle_nullification(nullification.clone()).await;
                // Notify resolver (not from resolver, so don't skip)
                resolver
                    .updated(Certificate::Nullification(nullification.clone()))
                    .await;
            }
        }
    }

    /// Checks for certificate thresholds and finalization after adding a vote.
    async fn check_thresholds<Sp: Sender, Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
        view: View,
    ) {
        // Check for M threshold (notarization certificate)
        if let Some(notarization) =
            self.state
                .try_assemble_notarization(view, self.m_quorum, &self.strategy)
        {
            // Record latency for leader
            if let Some(elapsed) = self.leader_elapsed(view) {
                self.notarization_latency.observe(elapsed);
            }

            // Notify resolver
            resolver
                .updated(Certificate::Notarization(notarization.clone()))
                .await;

            // Update local state
            self.handle_notarization(notarization.clone()).await;
            self.sync_journal(view).await;

            // Broadcast the certificate
            debug!(proposal=?notarization.proposal, "broadcasting notarization from votes");
            self.broadcast_certificate(
                certificate_sender,
                Certificate::Notarization(notarization.clone()),
            )
            .await;

            // Report activity
            self.reporter
                .report(Activity::Notarization(notarization))
                .await;
        }

        // Check for M threshold (nullification certificate)
        if let Some(nullification) =
            self.state
                .try_assemble_nullification(view, self.m_quorum, &self.strategy)
        {
            // Notify resolver
            resolver
                .updated(Certificate::Nullification(nullification.clone()))
                .await;

            // Update local state
            self.handle_nullification(nullification.clone()).await;
            self.sync_journal(view).await;

            // Broadcast the certificate
            debug!(round=?nullification.round(), "broadcasting nullification from votes");
            self.broadcast_certificate(
                certificate_sender,
                Certificate::Nullification(nullification.clone()),
            )
            .await;

            // Report activity
            self.reporter
                .report(Activity::Nullification(nullification))
                .await;
        }

        // Check for L threshold (finalization)
        if self.state.check_finalization(view, self.l_quorum) {
            debug!(%view, "finalized at L threshold");
            // Finalization triggers pruning
            self.prune_views().await;
        }

        // Check for nullify-by-contradiction
        self.try_broadcast_nullify_by_contradiction(vote_sender, view)
            .await;
    }

    /// Build, persist, and broadcast a notarize vote when this view is ready.
    async fn try_broadcast_notarize<Sp: Sender>(
        &mut self,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        view: View,
    ) {
        // Construct a notarize vote
        let Some(notarize) = self.state.construct_notarize(view) else {
            return;
        };

        // Record the vote locally before sharing it.
        self.handle_notarize(notarize.clone()).await;
        // Keep the vote durable for crash recovery.
        self.sync_journal(view).await;

        // Add local vote to VoteTracker for certificate assembly
        // Local votes won't conflict with themselves, so we ignore the return value
        let _ = self.state.add_notarize_vote(view, notarize.clone());

        // Report local vote activity
        self.reporter
            .report(Activity::Notarize(notarize.clone()))
            .await;

        // Broadcast the notarize vote
        debug!(
            proposal=?notarize.proposal,
            "broadcasting notarize"
        );
        self.broadcast_vote(vote_sender, Vote::Notarize(notarize))
            .await;
    }

    /// Check for nullify-by-contradiction and broadcast if triggered.
    async fn try_broadcast_nullify_by_contradiction<Sp: Sender>(
        &mut self,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        view: View,
    ) {
        // Construct a nullify vote if contradiction detected
        let Some(nullify) = self
            .state
            .construct_nullify_by_contradiction(view, self.m_quorum)
        else {
            return;
        };

        // Record the vote locally before sharing it.
        self.handle_nullify(nullify.clone()).await;
        // Keep the vote durable for crash recovery.
        self.sync_journal(view).await;

        // Add local vote to VoteTracker for certificate assembly
        self.state.add_nullify_vote(view, nullify.clone());

        // Report local vote activity
        self.reporter
            .report(Activity::Nullify(nullify.clone()))
            .await;

        // Broadcast the nullify vote
        debug!(
            round=?nullify.round(),
            "broadcasting nullify by contradiction"
        );
        self.broadcast_vote(vote_sender, Vote::Nullify(nullify))
            .await;
    }

    /// Share a notarization certificate once we can assemble it locally.
    async fn try_broadcast_notarization<Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
        view: View,
        resolved: Resolved,
    ) {
        // Construct a notarization certificate
        let Some(notarization) = self.state.broadcast_notarization(view) else {
            return;
        };

        // Only the leader sees an unbiased latency sample, so record it now.
        if let Some(elapsed) = self.leader_elapsed(view) {
            self.notarization_latency.observe(elapsed);
        }

        // Tell the resolver this view is complete so it can stop requesting it.
        // Skip if the resolver just sent us this certificate (avoid boomerang).
        if resolved != Resolved::Notarization {
            resolver
                .updated(Certificate::Notarization(notarization.clone()))
                .await;
        }
        // Update our local round with the certificate.
        self.handle_notarization(notarization.clone()).await;
        // Persist the certificate before informing others.
        self.sync_journal(view).await;
        // Broadcast the notarization certificate
        debug!(proposal=?notarization.proposal, "broadcasting notarization");
        self.broadcast_certificate(
            certificate_sender,
            Certificate::Notarization(notarization.clone()),
        )
        .await;
        // Surface the event to the application for observability.
        self.reporter
            .report(Activity::Notarization(notarization))
            .await;
    }

    /// Broadcast a nullification certificate if the round provides a candidate.
    async fn try_broadcast_nullification<Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
        view: View,
        resolved: Resolved,
    ) {
        // Construct the nullification certificate.
        let Some(nullification) = self.state.broadcast_nullification(view) else {
            return;
        };

        // Notify resolver so dependent parents can progress.
        // Skip if the resolver just sent us this certificate (avoid boomerang).
        if resolved != Resolved::Nullification {
            resolver
                .updated(Certificate::Nullification(nullification.clone()))
                .await;
        }
        // Track the certificate locally to avoid rebuilding it.
        self.handle_nullification(nullification.clone()).await;
        // Ensure deterministic restarts.
        self.sync_journal(view).await;
        // Broadcast the nullification certificate.
        debug!(round=?nullification.round(), "broadcasting nullification");
        self.broadcast_certificate(
            certificate_sender,
            Certificate::Nullification(nullification.clone()),
        )
        .await;
        // Surface the event to the application for observability.
        self.reporter
            .report(Activity::Nullification(nullification))
            .await;
    }

    /// Emits any votes or certificates that became available for `view`.
    async fn notify<Sp: Sender, Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
        view: View,
        resolved: Resolved,
    ) {
        self.try_broadcast_notarize(vote_sender, view).await;
        self.try_broadcast_notarization(resolver, certificate_sender, view, resolved)
            .await;
        // Check for nullify-by-contradiction
        self.try_broadcast_nullify_by_contradiction(vote_sender, view)
            .await;
        // We handle broadcast of `Nullify` votes in `timeout`, so this only emits certificates.
        self.try_broadcast_nullification(resolver, certificate_sender, view, resolved)
            .await;

        // Check thresholds after adding local votes to potentially form certificates
        self.check_thresholds(resolver, vote_sender, certificate_sender, view)
            .await;
    }

    /// Spawns the actor event loop with the provided channels.
    pub fn start(
        mut self,
        resolver: resolver::Mailbox<S, D>,
        vote_sender: impl Sender<PublicKey = S::PublicKey>,
        vote_receiver: impl Receiver<PublicKey = S::PublicKey>,
        certificate_sender: impl Sender<PublicKey = S::PublicKey>,
        certificate_receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(
                resolver,
                vote_sender,
                vote_receiver,
                certificate_sender,
                certificate_receiver,
            )
            .await
        )
    }

    /// Core event loop that drives proposal, voting, networking, and recovery.
    async fn run(
        mut self,
        mut resolver: resolver::Mailbox<S, D>,
        vote_sender: impl Sender<PublicKey = S::PublicKey>,
        vote_receiver: impl Receiver<PublicKey = S::PublicKey>,
        certificate_sender: impl Sender<PublicKey = S::PublicKey>,
        certificate_receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) {
        // Wrap channels
        let mut vote_sender = WrappedSender::new(vote_sender);
        let mut vote_receiver: WrappedReceiver<_, Vote<S, D>> =
            WrappedReceiver::new((), vote_receiver);
        let mut certificate_sender = WrappedSender::new(certificate_sender);
        let mut certificate_receiver: WrappedReceiver<_, Certificate<S, D>> =
            WrappedReceiver::new(self.certificate_config.clone(), certificate_receiver);

        // Add initial view
        //
        // We start on view 1 because the genesis container occupies view 0/height 0.
        self.state
            .set_genesis(self.automaton.genesis(self.state.epoch()).await);

        // Initialize journal
        let journal = Journal::<_, Artifact<S, D>>::init(
            self.context.with_label("journal").into_present(),
            JConfig {
                partition: self.partition.clone(),
                compression: None, // most of the data is not compressible
                codec_config: self.certificate_config.clone(),
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
            while let Some(artifact) = stream.next().await {
                let (_, _, _, artifact) = artifact.expect("unable to replay journal");
                self.state.replay(&artifact);
                match artifact {
                    Artifact::Notarize(notarize) => {
                        self.handle_notarize(notarize.clone()).await;
                        self.reporter.report(Activity::Notarize(notarize)).await;
                    }
                    Artifact::Notarization(notarization) => {
                        self.handle_notarization(notarization.clone()).await;
                        resolver
                            .updated(Certificate::Notarization(notarization.clone()))
                            .await;
                        self.reporter
                            .report(Activity::Notarization(notarization))
                            .await;
                    }
                    Artifact::Nullify(nullify) => {
                        self.handle_nullify(nullify.clone()).await;
                        self.reporter.report(Activity::Nullify(nullify)).await;
                    }
                    Artifact::Nullification(nullification) => {
                        self.handle_nullification(nullification.clone()).await;
                        resolver
                            .updated(Certificate::Nullification(nullification.clone()))
                            .await;
                        self.reporter
                            .report(Activity::Nullification(nullification))
                            .await;
                    }
                }
            }
        }
        self.journal = Some(journal);

        // Update current view and immediately move to timeout (very unlikely we restarted and still within timeout)
        let end = self.context.current();
        let elapsed = end.duration_since(start).unwrap_or_default();
        let observed_view = self.state.current_view();
        info!(
            current_view = %observed_view,
            ?elapsed,
            "consensus initialized"
        );
        self.state.expire_round(observed_view);

        // Create shutdown tracker
        let mut shutdown = self.context.stopped();

        // Process messages
        let mut pending_propose: Option<Request<Context<D, S::PublicKey>, D>> = None;
        let mut pending_verify: Option<Request<Context<D, S::PublicKey>, bool>> = None;
        loop {
            // Drop any pending items if we have moved to a new view
            if let Some(ref pp) = pending_propose {
                if pp.view() != self.state.current_view() {
                    pending_propose = None;
                }
            }
            if let Some(ref pv) = pending_verify {
                if pv.view() != self.state.current_view() {
                    pending_verify = None;
                }
            }

            // If needed, propose a container
            if pending_propose.is_none() {
                pending_propose = self.try_propose().await;
            }

            // If needed, verify current view
            if pending_verify.is_none() {
                pending_verify = self.try_verify().await;
            }

            // Prepare waiters
            let propose_wait = Waiter(&mut pending_propose);
            let verify_wait = Waiter(&mut pending_verify);

            // Wait for a timeout to fire or for a message to arrive
            let timeout = self.state.next_timeout_deadline();
            let start = self.state.current_view();
            let mut resolved = Resolved::None;
            let view;
            select! {
                _ = &mut shutdown => {
                    debug!("context shutdown, stopping voter");

                    // Sync journal before dropping
                    let journal = self.journal.take().unwrap();
                    journal.sync_all().await.expect("unable to sync journal");
                    drop(journal);

                    // Only drop shutdown once journal is synced
                    drop(shutdown);
                    return;
                },
                _ = self.context.sleep_until(timeout) => {
                    // Trigger the timeout
                    self.handle_timeout(&mut vote_sender, &mut certificate_sender).await;
                    view = self.state.current_view();
                },
                (context, proposed) = propose_wait => {
                    // Clear propose waiter
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
                    let our_round = Rnd::new(self.state.epoch(), self.state.current_view());
                    if our_round != context.round {
                        debug!(round = ?context.round, ?our_round, "dropping requested proposal");
                        continue;
                    }

                    // Construct proposal
                    let proposal = Proposal::new(
                        context.round,
                        context.parent.0,
                        proposed,
                    );
                    if !self.state.proposed(proposal) {
                        warn!(round = ?context.round, "dropped our proposal");
                        continue;
                    }
                    view = self.state.current_view();

                    // Notify application of proposal
                    self.relay.broadcast(proposed).await;
                },
                (context, verified) = verify_wait => {
                    // Clear verify waiter
                    pending_verify = None;

                    // Try to use result
                    view = context.view();
                    match verified {
                        Ok(true) => {
                            // Mark verification complete
                            self.state.verified(view);
                        },
                        Ok(false) => {
                            // Verification failed for current view proposal, treat as immediate timeout
                            debug!(round = ?context.round, "proposal failed verification");
                            self.handle_timeout(&mut vote_sender, &mut certificate_sender)
                                .await;
                        },
                        Err(err) => {
                            debug!(?err, round = ?context.round, "failed to verify proposal");
                        }
                    };
                },
                mailbox = self.mailbox_receiver.next() => {
                    // Extract message
                    let Some(msg) = mailbox else {
                        break;
                    };

                    // Handle messages from resolver
                    match msg {
                        Message::Proposal(proposal) => {
                            view = proposal.view();
                            if !self.state.is_interesting(view, false) {
                                trace!(%view, "proposal is not interesting");
                                continue;
                            }
                            trace!(%view, "received proposal");
                            if !self.state.set_proposal(view, proposal) {
                                continue;
                            }
                        }
                        Message::Verified(certificate, from_resolver) => {
                            // Certificates can come from future views (they advance our view)
                            view = certificate.view();
                            if !self.state.is_interesting(view, true) {
                                trace!(%view, "certificate is not interesting");
                                continue;
                            }

                            // Track resolved status to avoid sending back to resolver
                            match certificate {
                                Certificate::Notarization(notarization) => {
                                    trace!(%view, from_resolver, "received notarization");
                                    self.handle_notarization(notarization).await;
                                    if from_resolver {
                                        resolved = Resolved::Notarization;
                                    }
                                }
                                Certificate::Nullification(nullification) => {
                                    trace!(%view, from_resolver, "received nullification");
                                    self.handle_nullification(nullification).await;
                                    if from_resolver {
                                        resolved = Resolved::Nullification;
                                    }
                                }
                            }
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
                        warn!(?sender, "blocking peer for vote decoding error");
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
                    view = message.view();
                    if !self.state.is_interesting(view, false) {
                        continue;
                    }

                    // Handle the vote
                    self.handle_vote(&mut resolver, sender, message, &mut vote_sender, &mut certificate_sender).await;
                },
                // Handle certificates from the network
                message = certificate_receiver.recv() => {
                    // If the channel is closed, we should exit
                    let Ok((sender, message)) = message else {
                        break;
                    };

                    // If there is a decoding error, block
                    let Ok(message) = message else {
                        warn!(?sender, "blocking peer for certificate decoding error");
                        self.blocker.block(sender).await;
                        continue;
                    };

                    // Update metrics
                    let label = match &message {
                        Certificate::Notarization(_) => Inbound::notarization(&sender),
                        Certificate::Nullification(_) => Inbound::nullification(&sender),
                    };
                    self.inbound_messages.get_or_create(&label).inc();

                    // If the epoch is not the current epoch, block
                    if message.epoch() != self.epoch {
                        warn!(?sender, "blocking peer for epoch mismatch");
                        self.blocker.block(sender).await;
                        continue;
                    }

                    // Allow future certificates (they advance our view)
                    view = message.view();
                    if !self.state.is_interesting(view, true) {
                        continue;
                    }

                    // Handle the certificate
                    self.handle_certificate_from_network(&mut resolver, sender, message).await;
                },
            };

            // Attempt to send any new view messages
            self.notify(
                &mut resolver,
                &mut vote_sender,
                &mut certificate_sender,
                view,
                resolved,
            )
            .await;

            // After sending all required messages, prune any views
            // we no longer need
            self.prune_views().await;

            // Update the resolver if we have moved to a new view
            let current_view = self.state.current_view();
            if current_view > start {
                let leader = self
                    .state
                    .leader_index(current_view)
                    .expect("leader not set");

                // TODO: Check if the leader is not active (and not us), we should reduce leader timeout to now
                let _ = leader;
            }
        }
    }
}
