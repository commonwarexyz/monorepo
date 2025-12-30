use super::{
    ingress::Message,
    round::CertifyResult,
    state::{Config as StateConfig, State},
    Config, Mailbox,
};
use crate::{
    simplex::{
        actors::{batcher, resolver},
        elector::Config as Elector,
        metrics::{self, Outbound},
        scheme::Scheme,
        types::{
            Activity, Artifact, Certificate, Context, Finalization, Finalize, Notarization,
            Notarize, Nullification, Nullify, Proposal, Vote,
        },
    },
    types::{Round as Rnd, View},
    CertifiableAutomaton, Relay, Reporter, Viewable, LATENCY,
};
use commonware_codec::Read;
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_p2p::{utils::codec::WrappedSender, Blocker, Recipients, Sender};
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
use commonware_utils::futures::AbortablePool;
use core::{future::Future, panic};
use futures::{
    channel::{mpsc, oneshot},
    pin_mut, StreamExt,
};
use prometheus_client::metrics::{counter::Counter, family::Family, histogram::Histogram};
use rand::{CryptoRng, Rng};
use std::{
    collections::BTreeSet,
    mem::take,
    num::NonZeroUsize,
    pin::Pin,
    task::{self, Poll},
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
    Finalization,
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

impl<'a, V: Viewable, R> Future for Waiter<'a, V, R> {
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

/// Actor responsible for driving participation in the consensus protocol.
pub struct Actor<
    E: Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: CertifiableAutomaton<Digest = D, Context = Context<D, S::PublicKey>>,
    R: Relay,
    F: Reporter<Activity = Activity<S, D>>,
> {
    context: ContextCell<E>,
    state: State<E, S, L, D>,
    blocker: B,
    automaton: A,
    relay: R,
    reporter: F,

    certificate_config: <S::Certificate as Read>::Cfg,
    partition: String,
    replay_buffer: NonZeroUsize,
    write_buffer: NonZeroUsize,
    buffer_pool: PoolRef,
    journal: Option<Journal<E, Artifact<S, D>>>,
    certification_candidates: BTreeSet<View>,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,

    outbound_messages: Family<Outbound, Counter>,
    notarization_latency: Histogram,
    finalization_latency: Histogram,
}

impl<
        E: Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
        S: Scheme<D>,
        L: Elector<S>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
        A: CertifiableAutomaton<Digest = D, Context = Context<D, S::PublicKey>>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<S, D>>,
    > Actor<E, S, L, B, D, A, R, F>
{
    pub fn new(context: E, cfg: Config<S, L, B, D, A, R, F>) -> (Self, Mailbox<S, D>) {
        // Assert correctness of timeouts
        if cfg.leader_timeout > cfg.notarization_timeout {
            panic!("leader timeout must be less than or equal to notarization timeout");
        }

        // Initialize metrics
        let outbound_messages = Family::<Outbound, Counter>::default();
        let notarization_latency = Histogram::new(LATENCY);
        let finalization_latency = Histogram::new(LATENCY);
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

        // Initialize store
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        let certificate_config = cfg.scheme.certificate_codec_config();
        let state = State::new(
            context.with_label("state"),
            StateConfig {
                scheme: cfg.scheme,
                elector: cfg.elector,
                namespace: cfg.namespace.clone(),
                epoch: cfg.epoch,
                activity_timeout: cfg.activity_timeout,
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
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

                certificate_config,
                partition: cfg.partition,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                buffer_pool: cfg.buffer_pool,
                journal: None,
                certification_candidates: BTreeSet::new(),

                mailbox_receiver,

                outbound_messages,
                notarization_latency,
                finalization_latency,
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
    async fn broadcast_vote<T: Sender>(
        &mut self,
        sender: &mut WrappedSender<T, Vote<S, D>>,
        vote: Vote<S, D>,
    ) {
        // Update outbound metrics
        let metric = match &vote {
            Vote::Notarize(_) => metrics::Outbound::notarize(),
            Vote::Nullify(_) => metrics::Outbound::nullify(),
            Vote::Finalize(_) => metrics::Outbound::finalize(),
        };
        self.outbound_messages.get_or_create(metric).inc();

        // Broadcast vote
        sender.send(Recipients::All, vote, true).await.unwrap();
    }

    /// Send a certificate to every peer.
    async fn broadcast_certificate<T: Sender>(
        &mut self,
        sender: &mut WrappedSender<T, Certificate<S, D>>,
        certificate: Certificate<S, D>,
    ) {
        // Update outbound metrics
        let metric = match &certificate {
            Certificate::Notarization(_) => metrics::Outbound::notarization(),
            Certificate::Nullification(_) => metrics::Outbound::nullification(),
            Certificate::Finalization(_) => metrics::Outbound::finalization(),
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

    /// Attempt to certify a proposal for the given view.
    ///
    /// If the proposal is not yet available but certification is pending,
    /// the view is re-added to candidates for later retry.
    async fn try_certify(&mut self, view: View) -> Option<Request<Rnd, bool>> {
        match self.state.try_certify(view) {
            CertifyResult::Ready(proposal) => {
                let receiver = self.automaton.certify(proposal.payload).await;
                Some(Request(proposal.round, receiver))
            }
            CertifyResult::Pending => {
                self.certification_candidates.insert(view);
                None
            }
            CertifyResult::Skip => None,
        }
    }

    /// Handle a timeout.
    async fn handle_timeout<Sp: Sender, Sr: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
    ) {
        // Process nullify (and persist it if it is a first attempt)
        let (retry, nullify, entry) = self.state.handle_timeout();
        if let Some(nullify) = nullify {
            if !retry {
                batcher.constructed(Vote::Nullify(nullify.clone())).await;
                self.handle_nullify(nullify.clone()).await;

                // Sync the journal
                self.sync_journal(nullify.view()).await;
            }

            // Broadcast nullify
            debug!(round=?nullify.round(), "broadcasting nullify");
            self.broadcast_vote(vote_sender, Vote::Nullify(nullify))
                .await;
        }

        // Broadcast entry to help others enter the view
        //
        // We don't worry about recording this certificate because it must've already existed (and thus
        // we must've already broadcast and persisted it).
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
    ///
    /// Returns the best notarization or finalization we know of (i.e. the "floor") if we were the leader
    /// in the provided view (regardless of whether we built a proposal).
    async fn handle_nullification(
        &mut self,
        nullification: Nullification<S>,
    ) -> Option<Certificate<S, D>> {
        let view = nullification.view();
        let artifact = Artifact::Nullification(nullification.clone());

        // Add verified nullification to journal
        if !self.state.add_nullification(nullification) {
            return None;
        }
        self.append_journal(view, artifact).await;

        // If we were the leader and proposed, we should emit the parent certificate (a notarization or finalization)
        // of our proposal
        self.state
            .leader_index(view)
            .filter(|&leader| self.state.is_me(leader))
            .and_then(|_| self.state.parent_certificate(view))
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
            self.certification_candidates.insert(view);
            self.append_journal(view, artifact).await;
        }
        self.block_equivocator(equivocator).await;
    }

    /// Handles the certification of a proposal.
    ///
    /// The certification may succeed, in which case the proposal can be used in future views—
    /// or fail, in which case we should nullify the view as fast as possible.
    async fn handle_certification(
        &mut self,
        view: View,
        success: bool,
    ) -> Option<Notarization<S, D>> {
        // Get the notarization before advancing state
        let notarization = self.state.certified(view, success)?;

        // Remove from candidates since certification is complete
        self.certification_candidates.remove(&view);

        // Persist certification result for recovery
        let artifact = Artifact::Certification(Rnd::new(self.state.epoch(), view), success);
        self.append_journal(view, artifact.clone()).await;
        self.sync_journal(view).await;

        Some(notarization)
    }

    /// Persists our finalize vote to the journal for crash recovery.
    async fn handle_finalize(&mut self, finalize: Finalize<S, D>) {
        self.append_journal(finalize.view(), Artifact::Finalize(finalize))
            .await;
    }

    /// Stores a finalization certificate and guards against leader equivocation.
    async fn handle_finalization(&mut self, finalization: Finalization<S, D>) {
        let view = finalization.view();
        let artifact = Artifact::Finalization(finalization.clone());
        let (added, equivocator) = self.state.add_finalization(finalization);
        if added {
            self.append_journal(view, artifact).await;
        }
        self.block_equivocator(equivocator).await;

        // Prune certification candidates that are no longer needed. This also
        // bounds the size of certification_candidates during replay (views are
        // added when notarizations are replayed, then removed here when
        // finalizations are replayed).
        let last_finalized = self.state.last_finalized();
        self.certification_candidates
            .retain(|v| *v > last_finalized);
    }

    /// Build, persist, and broadcast a notarize vote when this view is ready.
    async fn try_broadcast_notarize<Sp: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        view: View,
    ) {
        // Construct a notarize vote
        let Some(notarize) = self.state.construct_notarize(view) else {
            return;
        };

        // Inform the batcher so it can aggregate our vote with others.
        batcher.constructed(Vote::Notarize(notarize.clone())).await;
        // Record the vote locally before sharing it.
        self.handle_notarize(notarize.clone()).await;
        // Keep the vote durable for crash recovery.
        self.sync_journal(view).await;

        // Broadcast the notarize vote
        debug!(
            proposal=?notarize.proposal,
            "broadcasting notarize"
        );
        self.broadcast_vote(vote_sender, Vote::Notarize(notarize))
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
        if let Some(floor) = self.handle_nullification(nullification.clone()).await {
            warn!(?floor, "broadcasting nullification floor");
            self.broadcast_certificate(certificate_sender, floor).await;
        }
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

    /// Broadcast a finalize vote if the round provides a candidate.
    async fn try_broadcast_finalize<Sp: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        view: View,
    ) {
        // Construct the finalize vote.
        let Some(finalize) = self.state.construct_finalize(view) else {
            return;
        };

        // Provide the vote to the batcher pipeline.
        batcher.constructed(Vote::Finalize(finalize.clone())).await;
        // Update the round before persisting.
        self.handle_finalize(finalize.clone()).await;
        // Keep the vote durable for recovery.
        self.sync_journal(view).await;

        // Broadcast the finalize vote.
        debug!(
            proposal=?finalize.proposal,
            "broadcasting finalize"
        );
        self.broadcast_vote(vote_sender, Vote::Finalize(finalize))
            .await;
    }

    /// Share a finalization certificate and notify observers of the new height.
    async fn try_broadcast_finalization<Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
        view: View,
        resolved: Resolved,
    ) {
        // Construct the finalization certificate.
        let Some(finalization) = self.state.broadcast_finalization(view) else {
            return;
        };

        // Only record latency if we are the current leader.
        if let Some(elapsed) = self.leader_elapsed(view) {
            self.finalization_latency.observe(elapsed);
        }

        // Tell the resolver this view is complete so it can stop requesting it.
        // Skip if the resolver just sent us this certificate (avoid boomerang).
        if resolved != Resolved::Finalization {
            resolver
                .updated(Certificate::Finalization(finalization.clone()))
                .await;
        }
        // Advance the consensus core with the finalization proof.
        self.handle_finalization(finalization.clone()).await;
        // Persist the proof before broadcasting it.
        self.sync_journal(view).await;
        // Broadcast the finalization certificate.
        debug!(proposal=?finalization.proposal, "broadcasting finalization");
        self.broadcast_certificate(
            certificate_sender,
            Certificate::Finalization(finalization.clone()),
        )
        .await;
        // Surface the event to the application for observability.
        self.reporter
            .report(Activity::Finalization(finalization))
            .await;
    }

    /// Emits any votes or certificates that became available for `view`.
    ///
    /// We don't need to iterate over all views to check for new actions because messages we receive
    /// only affect a single view.
    async fn notify<Sp: Sender, Sr: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        resolver: &mut resolver::Mailbox<S, D>,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
        view: View,
        resolved: Resolved,
    ) {
        self.try_broadcast_notarize(batcher, vote_sender, view)
            .await;
        self.try_broadcast_notarization(resolver, certificate_sender, view, resolved)
            .await;
        // We handle broadcast of `Nullify` votes in `timeout`, so this only emits certificates.
        self.try_broadcast_nullification(resolver, certificate_sender, view, resolved)
            .await;
        self.try_broadcast_finalize(batcher, vote_sender, view)
            .await;
        self.try_broadcast_finalization(resolver, certificate_sender, view, resolved)
            .await;
    }

    /// Spawns the actor event loop with the provided channels.
    pub fn start(
        mut self,
        batcher: batcher::Mailbox<S, D>,
        resolver: resolver::Mailbox<S, D>,
        vote_sender: impl Sender<PublicKey = S::PublicKey>,
        certificate_sender: impl Sender<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(batcher, resolver, vote_sender, certificate_sender)
                .await
        )
    }

    /// Core event loop that drives proposal, voting, networking, and recovery.
    async fn run(
        mut self,
        mut batcher: batcher::Mailbox<S, D>,
        mut resolver: resolver::Mailbox<S, D>,
        vote_sender: impl Sender<PublicKey = S::PublicKey>,
        certificate_sender: impl Sender<PublicKey = S::PublicKey>,
    ) {
        // Wrap channels
        let mut vote_sender = WrappedSender::new(vote_sender);
        let mut certificate_sender = WrappedSender::new(certificate_sender);

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
                    Artifact::Certification(round, success) => {
                        let Some(notarization) =
                            self.handle_certification(round.view(), success).await
                        else {
                            continue;
                        };
                        resolver.certified(round.view(), success).await;
                        if success {
                            self.reporter
                                .report(Activity::Certification(notarization))
                                .await;
                        }
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
                    Artifact::Finalize(finalize) => {
                        self.handle_finalize(finalize.clone()).await;
                        self.reporter.report(Activity::Finalize(finalize)).await;
                    }
                    Artifact::Finalization(finalization) => {
                        self.handle_finalization(finalization.clone()).await;
                        resolver
                            .updated(Certificate::Finalization(finalization.clone()))
                            .await;
                        self.reporter
                            .report(Activity::Finalization(finalization))
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

        // Initialize batcher with leader for current view
        //
        // We don't worry about sending any constructed messages here because we expect the view to immediately timeout
        // and we'll send our nullify vote shortly.
        let leader = self
            .state
            .leader_index(observed_view)
            .expect("leader not set");
        batcher
            .update(observed_view, leader, self.state.last_finalized())
            .await;

        // Create shutdown tracker
        let mut shutdown = self.context.stopped();

        // Process messages
        let mut pending_propose: Option<Request<Context<D, S::PublicKey>, D>> = None;
        let mut pending_verify: Option<Request<Context<D, S::PublicKey>, bool>> = None;
        let mut certify_pool: AbortablePool<(Rnd, Result<bool, oneshot::Canceled>)> =
            Default::default();
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

            // Attempt to certify any views that we have notarizations for.
            // Use split_off to only process views above last_finalized to handle edge cases
            // where finalization arrives between iterations.
            for v in take(&mut self.certification_candidates)
                .split_off(&self.state.last_finalized().next())
            {
                if let Some(Request(ctx, receiver)) = self.try_certify(v).await {
                    debug!(%v, "attempting certification");
                    let view = ctx.view();
                    let handle = certify_pool.push(async move { (ctx, receiver.await) });
                    self.state.set_certify_handle(view, handle);
                }
            }

            // Prepare waiters
            let propose_wait = Waiter(&mut pending_propose);
            let verify_wait = Waiter(&mut pending_verify);
            let certify_wait = certify_pool.next_completed();

            // Wait for a timeout to fire or for a message to arrive
            let timeout = self.state.next_timeout_deadline();
            let start = self.state.current_view();
            let mut resolved = Resolved::None;
            let view;
            select! {
                _ = &mut shutdown => {
                    debug!("context shutdown, stopping voter");

                    // Close journal
                    self.journal
                        .take()
                        .unwrap()
                        .close()
                        .await
                        .expect("unable to close journal");

                    // Only drop shutdown once journal is closed
                    drop(shutdown);
                    return;
                },
                _ = self.context.sleep_until(timeout) => {
                    // Trigger the timeout
                    self.handle_timeout(&mut batcher, &mut vote_sender, &mut certificate_sender).await;
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
                            self.handle_timeout(&mut batcher, &mut vote_sender, &mut certificate_sender)
                                .await;
                        },
                        Err(err) => {
                            debug!(?err, round = ?context.round, "failed to verify proposal");
                        }
                    };
                },
                result = certify_wait => {
                    // Aborted futures are expected when old views are pruned.
                    let Ok((round, certified)) = result else {
                        continue;
                    };

                    // Handle response to our certification request.
                    view = round.view();
                    match certified {
                        Ok(certified) => {
                            let Some(notarization) = self.handle_certification(view, certified).await
                            else {
                                continue;
                            };
                            resolver.certified(view, certified).await;
                            if certified {
                                self.reporter
                                    .report(Activity::Certification(notarization))
                                    .await;
                            }
                        }
                        Err(err) => {
                            // The application did not explicitly respond whether certification succeeded.
                            // Retry the certification request (we should never assume failure here because
                            // we persist certification results to the journal).
                            debug!(?err, ?round, "failed to certify proposal");
                            self.state.retry_certification(view);
                            self.certification_candidates.insert(view);
                        }
                    };
                },
                mailbox = self.mailbox_receiver.next() => {
                    // Extract message
                    let Some(msg) = mailbox else {
                        break;
                    };

                    // Handle messages from resolver and batcher
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
                                    if let Some(floor) = self.handle_nullification(nullification).await {
                                        warn!(?floor, "broadcasting nullification floor");
                                        self.broadcast_certificate(&mut certificate_sender, floor)
                                            .await;
                                    }
                                    if from_resolver {
                                        resolved = Resolved::Nullification;
                                    }
                                }
                                Certificate::Finalization(finalization) => {
                                    trace!(%view, from_resolver, "received finalization");
                                    self.handle_finalization(finalization).await;
                                    if from_resolver {
                                        resolved = Resolved::Finalization;
                                    }
                                }
                            }
                        }
                    }
                },
            };

            // Attempt to send any new view messages
            //
            // The batcher may drop votes we construct here if it has not yet been updated to the
            // message's view. This only happens when we skip ahead multiple views, which always
            // coincides with entering a new view (triggering a batcher update below before we send
            // any votes for the new current view). This has no impact on liveness, however, we may miss
            // building a finalization for an old view where we otherwise could have contributed.
            self.notify(
                &mut batcher,
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

            // Update the batcher if we have moved to a new view
            let current_view = self.state.current_view();
            if current_view > start {
                let leader = self
                    .state
                    .leader_index(current_view)
                    .expect("leader not set");

                // If the leader is not active (and not us), we should reduce leader timeout to now
                let is_active = batcher
                    .update(current_view, leader, self.state.last_finalized())
                    .await;
                if !is_active && !self.state.is_me(leader) {
                    debug!(%view, ?leader, "skipping leader timeout due to inactivity");
                    self.state.expire_round(current_view);
                }
            }
        }
    }
}
