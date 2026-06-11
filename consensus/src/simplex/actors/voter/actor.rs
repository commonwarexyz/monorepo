use super::{
    ingress::Message,
    state::{Config as StateConfig, State},
    Config, Mailbox,
};
use crate::{
    simplex::{
        actors::{batcher, resolver},
        elector::Config as Elector,
        metrics::{self, Outbound, TimeoutReason},
        scheme::Scheme,
        types::{
            Activity, Artifact, Certificate, Context, Finalization, Finalize, Notarization,
            Notarize, Nullification, Nullify, Proposal, Vote,
        },
        Floor, Plan,
    },
    types::{Round as Rnd, View},
    CertifiableAutomaton, Relay, Reporter, Viewable, LATENCY,
};
use commonware_actor::mailbox;
use commonware_codec::Read;
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{utils::codec::WrappedSender, Blocker, Recipients, Sender};
use commonware_runtime::{
    buffer::paged::CacheRef,
    spawn_cell,
    telemetry::{
        metrics::{CounterFamily, Histogram, MetricsExt as _},
        traces::TracedExt as _,
    },
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
use commonware_utils::{channel::oneshot, futures::AbortablePool};
use core::{future::Future, panic};
use futures::{
    future::{ready, Either},
    pin_mut, StreamExt,
};
use rand_core::CryptoRngCore;
use std::{
    num::NonZeroUsize,
    pin::Pin,
    task::{self, Poll},
};
use tracing::{debug, info, info_span, trace, warn, Instrument as _, Span};

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
    /// Span tracking the request from issuance to processed response.
    Span,
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
    type Output = (V, Span, Result<R, oneshot::error::RecvError>);

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let Waiter(slot) = self.get_mut();
        let res = match slot.as_mut() {
            Some(Request(_, _, ref mut receiver)) => match Pin::new(receiver).poll(cx) {
                Poll::Ready(res) => res,
                Poll::Pending => return Poll::Pending,
            },
            None => return Poll::Pending,
        };
        let Request(v, span, _) = slot.take().expect("request must exist");
        Poll::Ready((v, span, res))
    }
}

/// Actor responsible for driving participation in the consensus protocol.
pub struct Actor<
    E: BufferPooler + Clock + CryptoRngCore + Spawner + Storage + Metrics,
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
    floor: Option<Floor<S, D>>,

    certificate_config: <S::Certificate as Read>::Cfg,
    partition: String,
    replay_buffer: NonZeroUsize,
    write_buffer: NonZeroUsize,
    page_cache: CacheRef,
    journal: Option<Journal<E, Artifact<S, D>>>,

    mailbox_receiver: mailbox::Receiver<Message<S, D>>,

    outbound_messages: CounterFamily<Outbound>,
    notarization_latency: Histogram,
    finalization_latency: Histogram,
}

impl<
        E: BufferPooler + Clock + CryptoRngCore + Spawner + Storage + Metrics,
        S: Scheme<D>,
        L: Elector<S>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
        A: CertifiableAutomaton<Digest = D, Context = Context<D, S::PublicKey>>,
        R: Relay<Digest = D, PublicKey = S::PublicKey, Plan = Plan<S::PublicKey>>,
        F: Reporter<Activity = Activity<S, D>>,
    > Actor<E, S, L, B, D, A, R, F>
{
    pub fn new(context: E, cfg: Config<S, L, B, D, A, R, F>) -> (Self, Mailbox<S, D>) {
        // Initialize metrics
        let outbound_messages = context.family("outbound_messages", "number of outbound messages");
        let notarization_latency =
            context.histogram("notarization_latency", "notarization latency", LATENCY);
        let finalization_latency =
            context.histogram("finalization_latency", "finalization latency", LATENCY);

        // Initialize store
        let (mailbox_sender, mailbox_receiver) =
            mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        let certificate_config = cfg.scheme.certificate_codec_config();
        let state = State::new(
            context.child("state"),
            StateConfig {
                scheme: cfg.scheme,
                elector: cfg.elector,
                epoch: cfg.epoch,
                activity_timeout: cfg.activity_timeout,
                leader_timeout: cfg.leader_timeout,
                certification_timeout: cfg.certification_timeout,
                timeout_retry: cfg.timeout_retry,
                term_length: cfg.term_length,
                finalization_timeout: cfg.finalization_timeout,
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
                floor: Some(cfg.floor),

                certificate_config,
                partition: cfg.partition,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                page_cache: cfg.page_cache,
                journal: None,

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

    /// Drops views and journal entries that are below their retention floors.
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
        let retention_floor = self.state.retention_floor();
        if let Some(journal) = self.journal.as_mut() {
            journal
                .prune(retention_floor.get())
                .instrument(info_span!(
                    "simplex.voter.journal.prune",
                    epoch = self.state.epoch().traced(),
                    min = retention_floor.traced()
                ))
                .await
                .expect("unable to prune journal");
        }
    }

    /// Appends a verified message to the journal.
    async fn append_journal(&mut self, view: View, artifact: Artifact<S, D>) {
        if let Some(journal) = self.journal.as_mut() {
            journal
                .append(view.get(), &artifact)
                .await
                .expect("unable to append to journal");
        }
    }

    /// Syncs the journal so other replicas can recover messages in `view`.
    #[tracing::instrument(name = "simplex.voter.journal.sync", level = "info", skip_all, fields(epoch = self.state.epoch().traced(), view = view.traced()))]
    async fn sync_journal(&mut self, view: View) {
        if let Some(journal) = self.journal.as_mut() {
            journal
                .sync(view.get())
                .await
                .expect("unable to sync journal");
        }
    }

    /// Send a vote to every peer.
    fn broadcast_vote<T: Sender>(
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
        sender.send(Recipients::All, vote, true);
    }

    /// Send a certificate to every peer.
    fn broadcast_certificate<T: Sender>(
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
        sender.send(Recipients::All, certificate, true);
    }

    /// Blocks an equivocator.
    fn block_equivocator(&mut self, equivocator: Option<S::PublicKey>) {
        let Some(equivocator) = equivocator else {
            return;
        };
        commonware_p2p::block!(self.blocker, equivocator, "blocking equivocator");
    }

    /// Attempt to propose a new block.
    #[allow(clippy::async_yields_async)]
    async fn try_propose(&mut self) -> Option<Request<Context<D, S::PublicKey>, D>> {
        // Check if we are ready to propose
        let context = self.state.try_propose()?;

        // Request proposal from application
        let span = info_span!(
            parent: self.state.view_span(context.view()),
            "simplex.voter.propose",
            epoch = context.round.epoch().traced(),
            view = context.view().traced()
        );
        let receiver = async {
            debug!(round = ?context.round, "requested proposal from automaton");
            self.automaton.propose(context.clone()).await
        }
        .instrument(span.clone())
        .await;
        Some(Request(context, span, receiver))
    }

    /// Attempt to verify a proposed block.
    #[allow(clippy::async_yields_async)]
    async fn try_verify(&mut self) -> Option<Request<Context<D, S::PublicKey>, bool>> {
        // Check if we are ready to verify
        let (context, proposal) = self.state.try_verify()?;

        // Request verification
        let span = info_span!(
            parent: self.state.view_span(context.view()),
            "simplex.voter.verify",
            epoch = context.round.epoch().traced(),
            view = context.view().traced()
        );
        let receiver = async {
            debug!(?proposal, "requested proposal verification");
            self.automaton
                .verify(context.clone(), proposal.payload)
                .await
        }
        .instrument(span.clone())
        .await;
        Some(Request(context, span, receiver))
    }

    /// Persists our nullify vote to the journal for crash recovery.
    async fn handle_nullify(&mut self, nullify: Nullify<S>) {
        self.append_journal(nullify.view(), Artifact::Nullify(nullify))
            .await;
    }

    /// Emits a nullify vote (and persists it if it is a first attempt).
    async fn broadcast_nullify<Sp: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        retry: bool,
        nullify: Nullify<S>,
    ) {
        // Process nullify (and persist it if it is a first attempt)
        if !retry {
            batcher.constructed(Vote::Nullify(nullify.clone()));
            self.handle_nullify(nullify.clone()).await;

            // Sync the journal so first-attempt nullify votes survive restarts.
            self.sync_journal(nullify.view()).await;
        }

        // Broadcast nullify vote (regardless)
        debug!(round=?nullify.round(), "broadcasting nullify");
        self.broadcast_vote(vote_sender, Vote::Nullify(nullify));
    }

    /// Handle a timeout.
    async fn timeout<Sp: Sender, Sr: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
        reason: TimeoutReason,
    ) {
        let view = self.state.current_view();
        if reason != TimeoutReason::Retry {
            self.state.trigger_timeout(view, reason);
        }

        // Attempt to broadcast a nullify vote for the current view (as many times as required
        // until we exit the view)
        let Some(retry) = self.try_broadcast_nullify(batcher, vote_sender, view).await else {
            return;
        };

        // Broadcast entry to help others enter the view (if on retry).
        //
        // We don't worry about recording this certificate because it must've already existed (and thus
        // we must've already broadcast and persisted it).
        if !retry {
            return;
        }
        if let Some(certificate) = self.state.get_best_certificate() {
            self.broadcast_certificate(certificate_sender, certificate);
        }
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
            self.append_journal(view, artifact).await;
        }
        self.block_equivocator(equivocator);
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
    ///
    /// The finalization is appended to the journal without an immediate sync.
    /// If a crash loses a finalization that healed the same-term finalize
    /// gate, replay restores the blocked gate (which is safe) and it heals
    /// again as soon as peers redeliver any covering finalization.
    async fn handle_finalization(&mut self, finalization: Finalization<S, D>) {
        let view = finalization.view();
        let artifact = Artifact::Finalization(finalization.clone());
        let (added, equivocator) = self.state.add_finalization(finalization);
        if added {
            self.append_journal(view, artifact).await;
        }
        self.block_equivocator(equivocator);
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
        batcher.constructed(Vote::Notarize(notarize.clone()));
        // Record the vote locally before sharing it.
        self.handle_notarize(notarize.clone()).await;
        // Keep the vote durable for crash recovery.
        self.sync_journal(view).await;

        // Broadcast the notarize vote
        debug!(
            proposal=?notarize.proposal,
            "broadcasting notarize"
        );
        self.broadcast_vote(vote_sender, Vote::Notarize(notarize));
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
            resolver.updated(Certificate::Notarization(notarization.clone()));
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
        );
        // Surface the event to the application for observability.
        self.reporter.report(Activity::Notarization(notarization));
    }

    /// Broadcast a nullify vote for `view` if the state machine allows it.
    async fn try_broadcast_nullify<Sp: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        view: View,
    ) -> Option<bool> {
        let (was_retry, nullify) = self.state.construct_nullify(view)?;
        self.broadcast_nullify(batcher, vote_sender, was_retry, nullify)
            .await;
        Some(was_retry)
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
            resolver.updated(Certificate::Nullification(nullification.clone()));
        }
        // Track the certificate locally to avoid rebuilding it.
        if let Some(floor) = self.handle_nullification(nullification.clone()).await {
            warn!(?floor, "broadcasting nullification floor");
            self.broadcast_certificate(certificate_sender, floor);
        }
        // Ensure deterministic restarts.
        self.sync_journal(view).await;
        // Broadcast the nullification certificate.
        debug!(round=?nullification.round(), "broadcasting nullification");
        self.broadcast_certificate(
            certificate_sender,
            Certificate::Nullification(nullification.clone()),
        );
        // Surface the event to the application for observability.
        self.reporter.report(Activity::Nullification(nullification));
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
        batcher.constructed(Vote::Finalize(finalize.clone()));
        // Update the round before persisting.
        self.handle_finalize(finalize.clone()).await;
        // Keep the vote durable for recovery.
        self.sync_journal(view).await;

        // Broadcast the finalize vote.
        debug!(
            proposal=?finalize.proposal,
            "broadcasting finalize"
        );
        self.broadcast_vote(vote_sender, Vote::Finalize(finalize));
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
            resolver.updated(Certificate::Finalization(finalization.clone()));
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
        );
        // Surface the event to the application for observability.
        self.reporter.report(Activity::Finalization(finalization));
    }

    /// Processes the automaton's response to a proposal request.
    ///
    /// Returns the view to notify if the proposal was recorded.
    fn process_proposed(
        &mut self,
        context: Context<D, S::PublicKey>,
        proposed: Result<D, oneshot::error::RecvError>,
    ) -> Option<View> {
        // Try to use result
        let proposed = match proposed {
            Ok(proposed) => proposed,
            Err(err) => {
                debug!(?err, round = ?context.round, "failed to propose container");
                self.state
                    .trigger_timeout(context.view(), TimeoutReason::MissingProposal);
                return None;
            }
        };

        // If we have already moved to another view, drop the response as we will
        // not broadcast it
        let our_round = Rnd::new(self.state.epoch(), self.state.current_view());
        if our_round != context.round {
            debug!(round = ?context.round, ?our_round, "dropping requested proposal");
            return None;
        }

        // Construct proposal
        let proposal = Proposal::new(context.round, context.parent.0, proposed);
        if !self.state.proposed(proposal) {
            warn!(round = ?context.round, "dropped our proposal");
            return None;
        }
        let view = self.state.current_view();

        // Notify application of proposal.
        let _ = self.relay.broadcast(
            proposed,
            Plan::Propose {
                round: context.round,
            },
        );
        Some(view)
    }

    /// Processes the automaton's response to a verification request.
    ///
    /// Returns the view to notify.
    fn process_verified(
        &mut self,
        context: Context<D, S::PublicKey>,
        verified: Result<bool, oneshot::error::RecvError>,
    ) -> View {
        let view = context.view();
        match verified {
            Ok(true) => {
                // Mark verification complete
                self.state.verified(view);
            }
            Ok(false) => {
                warn!(round = ?context.round, "proposal failed verification");
                self.state
                    .trigger_timeout(context.view(), TimeoutReason::InvalidProposal);
            }
            Err(err) => {
                debug!(?err, round = ?context.round, "failed to verify proposal");
                self.state
                    .trigger_timeout(context.view(), TimeoutReason::IgnoredProposal);
            }
        };
        view
    }

    /// Processes the automaton's response to a certification request.
    ///
    /// Returns false if the view was already pruned (nothing to notify).
    async fn process_certified(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        round: Rnd,
        certified: Result<bool, oneshot::error::RecvError>,
    ) -> bool {
        match certified {
            Ok(certified) => {
                if !certified {
                    warn!(?round, "proposal failed certification");
                }
                let view = round.view();
                let Some(notarization) = self.handle_certification(view, certified).await else {
                    return false;
                };

                // Always forward certification outcomes to resolver.
                // This can happen after a nullification for the same view because
                // certification is asynchronous; finalization is the boundary that
                // cancels in-flight certification and suppresses late reporting.
                resolver.certified(round, certified);
                if certified {
                    self.reporter.report(Activity::Certification(notarization));
                }
            }
            Err(err) => {
                // Unlike propose/verify (where failing to act will lead to a timeout
                // and subsequent nullification), failing to certify can lead to a halt
                // because we'll never exit the view without a notarization + certification.
                //
                // We do not assume failure here because certification results are persisted
                // to the journal and will be recovered on restart.
                debug!(?err, ?round, "failed to certify proposal");
            }
        };
        true
    }

    /// Processes a message from the resolver or batcher.
    ///
    /// Returns the view to notify and whether the message was a certificate
    /// from the resolver.
    async fn process_message<Sr: Sender>(
        &mut self,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
        msg: Message<S, D>,
    ) -> Option<(View, Resolved)> {
        match msg {
            Message::Proposal { proposal, .. } => {
                let view = proposal.view();
                if !self.state.is_interesting_vote(view) {
                    trace!(%view, "proposal is not interesting");
                    return None;
                }
                trace!(%view, "received proposal");
                if !self.state.set_proposal(view, proposal) {
                    return None;
                }
                Some((view, Resolved::None))
            }
            Message::Verified {
                certificate,
                from_resolver,
                ..
            } => {
                // Certificates can come from future views (they advance our view)
                let view = certificate.view();
                if !self.state.is_interesting_certificate(view) {
                    trace!(%view, "certificate is not interesting");
                    return None;
                }

                // Track resolved status to avoid sending back to resolver
                let mut resolved = Resolved::None;
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
                            self.broadcast_certificate(certificate_sender, floor);
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
                Some((view, resolved))
            }
            Message::Timeout { round, reason, .. } => {
                let view = round.view();
                debug!(%view, ?reason, "timing out view");
                self.state.trigger_timeout(view, reason);
                Some((view, Resolved::None))
            }
        }
    }

    /// Emits any votes or certificates that became available for `view`.
    ///
    /// We don't need to iterate over all views to check for new actions because messages we receive
    /// only affect a single view. In particular, healing the same-term finalize gate deliberately
    /// does not retry finalize votes for views certified while the gate was blocked (see the module
    /// documentation on same-term vote safety for the consequences).
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
        let pool = self.context.network_buffer_pool();
        let mut vote_sender = WrappedSender::new(pool.clone(), vote_sender);
        let mut certificate_sender = WrappedSender::new(pool.clone(), certificate_sender);

        // Initialize journal
        let journal = Journal::<_, Artifact<S, D>>::init(
            self.context.child("journal"),
            JConfig {
                partition: self.partition.clone(),
                compression: None, // most of the data is not compressible
                codec_config: self.certificate_config.clone(),
                page_cache: self.page_cache.clone(),
                write_buffer: self.write_buffer,
            },
        )
        .await
        .expect("unable to open journal");

        // Add initial view from the configured floor. Genesis starts from view
        // zero; non-genesis floors skip replayed artifacts at or below the floor
        // certificate view.
        let floor = self.floor.take().expect("floor not initialized");
        let replay_floor = match &floor {
            Floor::Genesis(_) => View::zero(),
            Floor::Finalized(finalization) => finalization.view(),
        };

        // Anchor all startup work under a single root span. The floor
        // finalization and journal replay both run here before any view span
        // exists, so without this root their work would emit as orphan traces.
        let start = self.context.current();
        let epoch = self.state.epoch();
        let start_span = info_span!("simplex.voter.start", epoch = epoch.traced());

        // Apply the configured floor, forwarding and reporting any finalization.
        start_span.in_scope(|| {
            if let Some(finalization) = self.state.set_floor(floor) {
                let report = finalization.clone();
                resolver.updated(Certificate::Finalization(finalization));
                self.reporter.report(Activity::Finalization(report));
            }
        });

        // Rebuild from journal, nested under the startup span.
        async {
            let stream = journal
                .replay(0, 0, self.replay_buffer)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);
            while let Some(artifact) = stream.next().await {
                let (_, _, _, artifact) = artifact.expect("unable to replay journal");
                if artifact.view() <= replay_floor {
                    continue;
                }

                self.state.replay(&artifact);
                match artifact {
                    Artifact::Notarize(notarize) => {
                        self.handle_notarize(notarize.clone()).await;
                        self.reporter.report(Activity::Notarize(notarize));
                    }
                    Artifact::Notarization(notarization) => {
                        self.handle_notarization(notarization.clone()).await;
                        resolver.updated(Certificate::Notarization(notarization.clone()));
                        self.reporter.report(Activity::Notarization(notarization));
                    }
                    Artifact::Certification(round, success) => {
                        let Some(notarization) =
                            self.handle_certification(round.view(), success).await
                        else {
                            continue;
                        };
                        resolver.certified(round, success);
                        if success {
                            self.reporter.report(Activity::Certification(notarization));
                        }
                    }
                    Artifact::Nullify(nullify) => {
                        self.handle_nullify(nullify.clone()).await;
                        self.reporter.report(Activity::Nullify(nullify));
                    }
                    Artifact::Nullification(nullification) => {
                        self.handle_nullification(nullification.clone()).await;
                        resolver.updated(Certificate::Nullification(nullification.clone()));
                        self.reporter.report(Activity::Nullification(nullification));
                    }
                    Artifact::Finalize(finalize) => {
                        self.handle_finalize(finalize.clone()).await;
                        self.reporter.report(Activity::Finalize(finalize));
                    }
                    Artifact::Finalization(finalization) => {
                        self.handle_finalization(finalization.clone()).await;
                        resolver.updated(Certificate::Finalization(finalization.clone()));
                        self.reporter.report(Activity::Finalization(finalization));
                    }
                }

                // We deliberately avoid re-seeding the batcher with our
                // own votes (or the votes of other peers) on replay. We assume that
                // whatever view we were in during shutdown is no longer the latest
                // and we'll quickly jump ahead to a new view.
                //
                // If this is not the case (cluster-wide shutdown), we will recover
                // when timing out.
            }
        }
        .instrument(info_span!(parent: &start_span, "simplex.voter.replay", epoch = epoch.traced()))
        .await;
        self.journal = Some(journal);

        // Log current view after recovery
        let end = self.context.current();
        let elapsed = end.duration_since(start).unwrap_or_default();
        let observed_view = self.state.current_view();
        info!(
            %observed_view,
            ?elapsed,
            "consensus initialized"
        );

        // Initialize batcher with leader for current view
        let leader = self
            .state
            .leader_index(observed_view)
            .expect("leader not set");
        let (span, finalized) = self.state.batcher_context(observed_view);
        batcher.update(span, observed_view, leader, finalized, None);

        // Process messages
        let mut pending_propose: Option<Request<Context<D, S::PublicKey>, D>> = None;
        let mut pending_verify: Option<Request<Context<D, S::PublicKey>, bool>> = None;
        let mut certify_pool: AbortablePool<(Rnd, Span, Result<bool, oneshot::error::RecvError>)> =
            Default::default();
        select_loop! {
            self.context,
            on_start => {
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
                for (proposal, is_local) in self.state.certify_candidates() {
                    let round = proposal.round;
                    let view = round.view();
                    debug!(%view, "attempting certification");
                    let span = info_span!(
                        parent: self.state.view_span(view),
                        "simplex.voter.certify",
                        epoch = round.epoch().traced(),
                        view = view.traced()
                    );
                    let result = if is_local {
                        Either::Left(ready(Ok(true)))
                    } else {
                        #[allow(clippy::async_yields_async)]
                        let receiver = async { self.automaton.certify(round, proposal.payload).await }
                            .instrument(span.clone())
                            .await;
                        Either::Right(receiver)
                    };
                    let handle = certify_pool.push(async move { (round, span, result.await) });
                    self.state.set_certify_handle(view, handle);
                }

                // Prepare waiters
                let propose_wait = Waiter(&mut pending_propose);
                let verify_wait = Waiter(&mut pending_verify);
                let certify_wait = certify_pool.next_completed();

                // Wait for a timeout to fire or for a message to arrive
                let (timeout, timeout_reason) = self.state.next_timeout();
                let start = self.state.current_view();
                let mut resolved = Resolved::None;
                let view;
            },
            on_stopped => {
                debug!("context shutdown, stopping voter");
            },
            _ = self.context.sleep_until(timeout) => {
                // Process the timeout
                let current_view = self.state.current_view();
                let span = info_span!(
                    parent: self.state.view_span(current_view),
                    "simplex.voter.timeout",
                    epoch = self.state.epoch().traced(),
                    view = current_view.traced()
                );
                self.timeout(
                    &mut batcher,
                    &mut vote_sender,
                    &mut certificate_sender,
                    timeout_reason,
                )
                    .instrument(span)
                    .await;
                view = self.state.current_view();
            },
            (context, span, proposed) = propose_wait => {
                // Clear propose waiter
                pending_propose = None;

                // Process the automaton's response
                let Some(proposed_view) = span.in_scope(|| self.process_proposed(context, proposed)) else {
                    continue;
                };
                view = proposed_view;
            },
            (context, span, verified) = verify_wait => {
                // Clear verify waiter
                pending_verify = None;

                // Process the automaton's response
                view = span.in_scope(|| self.process_verified(context, verified));
            },
            // Aborted futures are expected when old views are pruned
            Ok((round, span, certified)) = certify_wait else continue => {
                // Handle response to our certification request.
                view = round.view();
                if !self
                    .process_certified(&mut resolver, round, certified)
                    .instrument(span)
                    .await
                {
                    continue;
                }
            },
            Some(msg) = self.mailbox_receiver.recv() else break => {
                // Handle messages from resolver and batcher
                let span = info_span!(
                    parent: msg.span(),
                    "simplex.voter.process",
                    operation = msg.name(),
                    epoch = self.state.epoch().traced(),
                    view = msg.view().traced()
                );
                let Some((processed_view, processed_resolved)) = self
                    .process_message(&mut certificate_sender, msg)
                    .instrument(span)
                    .await
                else {
                    continue;
                };
                view = processed_view;
                resolved = processed_resolved;
            },
            on_end => {
                // Attempt to send any new view messages
                //
                // The batcher may drop votes we construct here if it has not yet been updated to the
                // message's view. This only happens when we skip ahead multiple views, which always
                // coincides with entering a new view (triggering a batcher update below before we send
                // any votes for the new current view). This has no impact on liveness, however, we may miss
                // building a finalization for an old view where we otherwise could have contributed.
                let span = info_span!(
                    parent: self.state.view_span(view),
                    "simplex.voter.notify",
                    epoch = self.state.epoch().traced(),
                    view = view.traced()
                );
                self.notify(
                    &mut batcher,
                    &mut resolver,
                    &mut vote_sender,
                    &mut certificate_sender,
                    view,
                    resolved,
                )
                .instrument(span)
                .await;

                // Close the root span of any view the chain has now decided.
                // This runs after notify so the finalization broadcast and the
                // report into the application still nest under the view span.
                self.state.close_decided_spans();

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

                    // If we skip a view, we don't worry about forwarding our latest certified proposal
                    // because the network has already moved on
                    let forwardable_proposal = current_view
                        .previous()
                        .and_then(|view| self.state.forwardable_proposal(view));

                    // If the leader nullified or is inactive, reduce leader
                    // timeout to now
                    let (span, finalized) = self.state.batcher_context(current_view);
                    batcher.update(span, current_view, leader, finalized, forwardable_proposal);
                }
            },
        }

        // Sync and drop the journal
        self.journal
            .take()
            .expect("journal missing on voter exit")
            .sync_all()
            .await
            .expect("unable to sync journal");
    }
}
