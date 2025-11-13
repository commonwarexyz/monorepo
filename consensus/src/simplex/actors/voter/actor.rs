use super::{
    state::{Config as StateConfig, ProposeResult, State},
    Config, Mailbox, Message,
};
use crate::{
    simplex::{
        actors::{batcher, resolver},
        metrics::{self, Inbound, Outbound},
        signing_scheme::Scheme,
        types::{
            Activity, Context, Finalization, Finalize, Notarization, Notarize, Nullification,
            Nullify, Proposal, Voter,
        },
    },
    types::{Round as Rnd, View},
    Automaton, Epochable, Relay, Reporter, Viewable, LATENCY,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    buffer::PoolRef,
    spawn_cell,
    telemetry::metrics::{
        histogram::{self, Buckets},
        status::GaugeExt,
    },
    Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    pin_mut, StreamExt,
};
use prometheus_client::metrics::{
    counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
};
use rand::{CryptoRng, Rng};
use std::{
    num::NonZeroUsize,
    sync::{atomic::AtomicI64, Arc},
};
use tracing::{debug, info, trace, warn};

/// Action to take after processing a message.
enum Action {
    /// Skip processing the message.
    Skip,
    /// Block the peer from sending any more messages.
    Block,
    /// Process the message.
    Process,
}

/// Actor responsible for driving participation in the consensus protocol.
pub struct Actor<
    E: Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    A: Automaton<Digest = D, Context = Context<D, P>>,
    R: Relay,
    F: Reporter<Activity = Activity<S, D>>,
> {
    context: ContextCell<E>,
    state: State<E, S, D>,
    blocker: B,
    automaton: A,
    relay: R,
    reporter: F,

    partition: String,
    replay_buffer: NonZeroUsize,
    write_buffer: NonZeroUsize,
    buffer_pool: PoolRef,
    journal: Option<Journal<E, Voter<S, D>>>,

    namespace: Vec<u8>,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,

    current_view: Gauge,
    tracked_views: Gauge,
    skipped_views: Counter,
    inbound_messages: Family<Inbound, Counter>,
    outbound_messages: Family<Outbound, Counter>,
    notarization_latency: Histogram,
    finalization_latency: Histogram,
    recover_latency: histogram::Timed<E>,
}

impl<
        E: Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
        P: PublicKey,
        S: Scheme<PublicKey = P>,
        B: Blocker<PublicKey = P>,
        D: Digest,
        A: Automaton<Digest = D, Context = Context<D, P>>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<S, D>>,
    > Actor<E, P, S, B, D, A, R, F>
{
    pub fn new(context: E, cfg: Config<S, B, D, A, R, F>) -> (Self, Mailbox<S, D>) {
        // Assert correctness of timeouts
        if cfg.leader_timeout > cfg.notarization_timeout {
            panic!("leader timeout must be less than or equal to notarization timeout");
        }

        // Initialize metrics
        let current_view = Gauge::<i64, AtomicI64>::default();
        let tracked_views = Gauge::<i64, AtomicI64>::default();
        let skipped_views = Counter::default();
        let inbound_messages = Family::<Inbound, Counter>::default();
        let outbound_messages = Family::<Outbound, Counter>::default();
        let notarization_latency = Histogram::new(LATENCY.into_iter());
        let finalization_latency = Histogram::new(LATENCY.into_iter());
        let recover_latency = Histogram::new(Buckets::CRYPTOGRAPHY.into_iter());
        context.register("current_view", "current view", current_view.clone());
        context.register("tracked_views", "tracked views", tracked_views.clone());
        context.register("skipped_views", "skipped views", skipped_views.clone());
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
        context.register(
            "finalization_latency",
            "finalization latency",
            finalization_latency.clone(),
        );
        context.register(
            "recover_latency",
            "certificate recover latency",
            recover_latency.clone(),
        );
        // TODO(#1833): Metrics should use the post-start context
        let clock = Arc::new(context.clone());

        // Initialize store
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        let state = State::new(
            context.with_label("state"),
            StateConfig {
                scheme: cfg.scheme,
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

                partition: cfg.partition,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                buffer_pool: cfg.buffer_pool,
                journal: None,

                namespace: cfg.namespace,

                mailbox_receiver,

                current_view,
                tracked_views,
                skipped_views,
                inbound_messages,
                outbound_messages,
                notarization_latency,
                finalization_latency,
                recover_latency: histogram::Timed::new(recover_latency, clock),
            },
            mailbox,
        )
    }

    /// Attempt to propose a new block.
    async fn try_propose(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
    ) -> Option<(Context<D, P>, oneshot::Receiver<D>)> {
        // Check if we are ready to propose
        let context = match self.state.try_propose() {
            ProposeResult::Ready(context) => context,
            ProposeResult::Missing(view) => {
                debug!(view, "fetching missing ancestor");
                resolver.fetch(vec![view], vec![view]).await;
                return None;
            }
            ProposeResult::Pending => return None,
        };

        // Request proposal from application
        debug!(round = ?context.round, "requested proposal from automaton");
        Some((context.clone(), self.automaton.propose(context).await))
    }

    /// Attempt to verify a proposed block.
    async fn try_verify(&mut self) -> Option<(Context<D, P>, oneshot::Receiver<bool>)> {
        // Check if we are ready to verify
        let current_view = self.state.current_view();
        let (context, proposal) = self.state.try_verify(current_view)?;
        // Unlike during proposal, we don't use a verification opportunity
        // to backfill missing certificates (a malicious proposer could
        // ask us to fetch junk).

        // Request verification
        debug!(?proposal, "requested proposal verification");
        Some((
            context.clone(),
            self.automaton.verify(context, proposal.payload).await,
        ))
    }

    /// Handle a timeout.
    async fn timeout<Sp: Sender, Sr: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        pending_sender: &mut WrappedSender<Sp, Voter<S, D>>,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
    ) {
        // Set timeout fired
        let current_view = self.state.current_view();
        let (was_retry, Some(nullify)) = self.state.handle_timeout(current_view) else {
            return;
        };

        // When retrying we immediately re-share the certificate that let us enter
        // this view so slow peers do not stall our next round.
        let past_view = current_view - 1;
        if was_retry
            && past_view > 0
            && !self
                .rebroadcast_entry_certificates(recovered_sender, past_view)
                .await
        {
            warn!(
                current = current_view,
                "unable to rebroadcast entry notarization/nullification/finalization"
            );
        }

        // Handle the nullify
        if !was_retry {
            batcher.constructed(Voter::Nullify(nullify.clone())).await;
            self.handle_nullify(nullify.clone()).await;

            // Sync the journal
            self.sync_journal(current_view).await;
        }

        // Broadcast nullify
        debug!(round=?nullify.round(), "broadcasting nullify");
        self.broadcast_all(pending_sender, Voter::Nullify(nullify))
            .await;
    }

    async fn handle_nullify(&mut self, nullify: Nullify<S>) {
        // Get view for nullify
        let view = nullify.view();

        // Handle nullify
        self.append_journal(view, Voter::Nullify(nullify.clone()))
            .await;

        // Create round (if it doesn't exist) and add verified nullify
        self.state.add_verified_nullify(nullify);
    }

    fn leader_elapsed(&self, view: u64) -> Option<f64> {
        let elapsed = self
            .state
            .elapsed_since_start(view, self.context.current())?;
        let leader = self.state.leader_index(view)?;
        if !self.state.is_me(leader) {
            return None;
        }
        Some(elapsed.as_secs_f64())
    }

    fn enter_view(&mut self, view: u64, seed: Option<S::Seed>) {
        if self.state.enter_view(view, seed) {
            let _ = self.current_view.try_set(view);
        }
    }

    async fn prune_views(&mut self) {
        let removed = self.state.prune();
        if removed.is_empty() {
            return;
        }
        for view in &removed {
            debug!(
                view = *view,
                last_finalized = self.state.last_finalized(),
                "pruned view"
            );
        }
        if let Some(journal) = self.journal.as_mut() {
            journal
                .prune(self.state.min_active())
                .await
                .expect("unable to prune journal");
        }
        let _ = self.tracked_views.try_set(self.state.tracked_views());
    }

    /// Persist a verified message for `view` when journaling is enabled.
    async fn append_journal(&mut self, view: View, msg: Voter<S, D>) {
        if let Some(journal) = self.journal.as_mut() {
            journal
                .append(view, msg)
                .await
                .expect("unable to append to journal");
        }
    }

    /// Flush journal buffers so other replicas can recover up to `view`.
    async fn sync_journal(&mut self, view: View) {
        if let Some(journal) = self.journal.as_mut() {
            journal.sync(view).await.expect("unable to sync journal");
        }
    }

    /// Emit `msg` to every peer while recording the associated outbound metric.
    async fn broadcast_all<T: Sender>(
        &mut self,
        sender: &mut WrappedSender<T, Voter<S, D>>,
        msg: Voter<S, D>,
    ) {
        // Update outbound metrics
        let metric = match msg {
            Voter::Notarize(_) => metrics::Outbound::notarize(),
            Voter::Notarization(_) => metrics::Outbound::notarization(),
            Voter::Nullify(_) => metrics::Outbound::nullify(),
            Voter::Nullification(_) => metrics::Outbound::nullification(),
            Voter::Finalize(_) => metrics::Outbound::finalize(),
            Voter::Finalization(_) => metrics::Outbound::finalization(),
        };
        self.outbound_messages.get_or_create(metric).inc();

        // Broadcast message
        sender.send(Recipients::All, msg, true).await.unwrap();
    }

    async fn handle_notarize(&mut self, notarize: Notarize<S, D>) {
        // Get view for notarize
        let view = notarize.view();

        // Handle notarize
        self.append_journal(view, Voter::Notarize(notarize.clone()))
            .await;

        // Create round (if it doesn't exist) and add verified notarize
        let equivocator = self.state.add_verified_notarize(notarize);
        self.block_equivocator(equivocator).await;
    }

    async fn notarization(&mut self, notarization: Notarization<S, D>) -> Action {
        // Check if we are still in a view where this notarization could help
        let view = notarization.view();
        if !self.state.is_interesting(view, true) {
            return Action::Skip;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        if self.state.has_broadcast_notarization(view) {
            return Action::Skip;
        }

        // Verify notarization
        if !notarization.verify(&mut self.context, self.state.scheme(), &self.namespace) {
            return Action::Block;
        }

        // Handle notarization
        self.handle_notarization(notarization).await;
        Action::Process
    }

    async fn handle_notarization(&mut self, notarization: Notarization<S, D>) {
        // Get view for notarization
        let view = notarization.view();

        // Store notarization
        let msg = Voter::Notarization(notarization.clone());
        let seed = self
            .state
            .scheme()
            .seed(notarization.round(), &notarization.certificate);

        // Create round (if it doesn't exist) and add verified notarization
        let (added, equivocator) = self.state.add_verified_notarization(notarization);
        if added {
            self.append_journal(view, msg).await;
        }
        self.block_equivocator(equivocator).await;

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn nullification(&mut self, nullification: Nullification<S>) -> Action {
        // Check if we are still in a view where this notarization could help
        if !self.state.is_interesting(nullification.view(), true) {
            return Action::Skip;
        }

        // Determine if we already broadcast nullification for this view (in which
        // case we can ignore this message)
        if self.state.has_broadcast_nullification(nullification.view()) {
            return Action::Skip;
        }

        // Verify nullification
        if !nullification.verify::<_, D>(&mut self.context, self.state.scheme(), &self.namespace) {
            return Action::Block;
        }

        // Handle notarization
        self.handle_nullification(nullification).await;
        Action::Process
    }

    async fn handle_nullification(&mut self, nullification: Nullification<S>) {
        // Store nullification
        let msg = Voter::Nullification(nullification.clone());
        let seed = self
            .state
            .scheme()
            .seed(nullification.round, &nullification.certificate);

        // Create round (if it doesn't exist) and add verified nullification
        let view = nullification.view();
        if self.state.add_verified_nullification(nullification) {
            self.append_journal(view, msg).await;
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn handle_finalize(&mut self, finalize: Finalize<S, D>) {
        // Get view for finalize
        let view = finalize.view();

        // Handle finalize
        self.append_journal(view, Voter::Finalize(finalize.clone()))
            .await;

        // Create round (if it doesn't exist) and add verified finalize
        let equivocator = self.state.add_verified_finalize(finalize);
        self.block_equivocator(equivocator).await;
    }

    async fn finalization(&mut self, finalization: Finalization<S, D>) -> Action {
        // Check if we are still in a view where this finalization could help
        let view = finalization.view();
        if !self.state.is_interesting(view, true) {
            return Action::Skip;
        }

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        if self.state.has_broadcast_finalization(view) {
            return Action::Skip;
        }

        // Verify finalization
        if !finalization.verify(&mut self.context, self.state.scheme(), &self.namespace) {
            return Action::Block;
        }

        // Process finalization
        self.handle_finalization(finalization).await;
        Action::Process
    }

    async fn handle_finalization(&mut self, finalization: Finalization<S, D>) {
        // Store finalization
        let msg = Voter::Finalization(finalization.clone());
        let seed = self
            .state
            .scheme()
            .seed(finalization.round(), &finalization.certificate);

        // Create round (if it doesn't exist) and add verified finalization
        let view = finalization.view();
        let (added, equivocator) = self.state.add_verified_finalization(finalization);
        if added {
            self.append_journal(view, msg).await;
        }
        self.block_equivocator(equivocator).await;

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    fn construct_notarization(&mut self, view: u64, force: bool) -> Option<Notarization<S, D>> {
        let mut timer = self.recover_latency.timer();
        match self.state.notarization_candidate(view, force) {
            Some((new, notarization)) => {
                if new {
                    timer.observe();
                } else {
                    timer.cancel();
                }
                Some(notarization)
            }
            None => {
                timer.cancel();
                None
            }
        }
    }

    fn construct_nullification(&mut self, view: u64, force: bool) -> Option<Nullification<S>> {
        let mut timer = self.recover_latency.timer();
        match self.state.nullification_candidate(view, force) {
            Some((new, nullification)) => {
                if new {
                    timer.observe();
                } else {
                    timer.cancel();
                }
                Some(nullification)
            }
            None => {
                timer.cancel();
                None
            }
        }
    }

    fn construct_finalization(&mut self, view: u64, force: bool) -> Option<Finalization<S, D>> {
        let mut timer = self.recover_latency.timer();
        match self.state.finalization_candidate(view, force) {
            Some((new, finalization)) => {
                if new {
                    timer.observe();
                } else {
                    timer.cancel();
                }
                Some(finalization)
            }
            None => {
                timer.cancel();
                None
            }
        }
    }

    async fn block_equivocator(&mut self, equivocator: Option<S::PublicKey>) {
        if let Some(equivocator) = equivocator {
            warn!(?equivocator, "blocking equivocator");
            self.blocker.block(equivocator).await;
        }
    }

    /// Attempt to retransmit whichever certificate allowed us to enter `view + 1`.
    async fn rebroadcast_entry_certificates<Sr: Sender>(
        &mut self,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
        view: View,
    ) -> bool {
        if let Some(finalization) = self.construct_finalization(view, true) {
            // Finalizations are the strongest evidence, so resend them first.
            self.broadcast_all(recovered_sender, Voter::Finalization(finalization))
                .await;
            debug!(view, "rebroadcast entry finalization");
            return true;
        }

        if let Some(notarization) = self.construct_notarization(view, true) {
            // Otherwise rebroadcast the notarization that advanced us.
            self.broadcast_all(recovered_sender, Voter::Notarization(notarization))
                .await;
            debug!(view, "rebroadcast entry notarization");
            return true;
        }

        if let Some(nullification) = self.construct_nullification(view, true) {
            // Finally fall back to the nullification evidence if that is all we have.
            self.broadcast_all(recovered_sender, Voter::Nullification(nullification))
                .await;
            debug!(view, "rebroadcast entry nullification");
            return true;
        }

        false
    }

    /// Build, persist, and broadcast a notarize vote when this view is ready.
    async fn try_broadcast_notarize<Sp: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        pending_sender: &mut WrappedSender<Sp, Voter<S, D>>,
        view: u64,
    ) {
        // Construct a notarize vote
        let Some(notarize) = self.state.construct_notarize(view) else {
            return;
        };

        // Inform the verifier so it can aggregate our vote with others.
        batcher.constructed(Voter::Notarize(notarize.clone())).await;
        // Record the vote locally before sharing it.
        self.handle_notarize(notarize.clone()).await;
        // Keep the vote durable for crash recovery.
        self.sync_journal(view).await;

        // Broadcast the notarize vote
        debug!(
            round=?notarize.round(),
            proposal=?notarize.proposal,
            "broadcasting notarize"
        );
        self.broadcast_all(pending_sender, Voter::Notarize(notarize))
            .await;
    }

    /// Share a notarization certificate once we can assemble it locally.
    async fn try_broadcast_notarization<Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
        view: u64,
    ) {
        // Construct a notarization certificate
        let Some(notarization) = self.construct_notarization(view, false) else {
            return;
        };

        // Only the leader sees an unbiased latency sample, so record it now.
        if let Some(elapsed) = self.leader_elapsed(view) {
            self.notarization_latency.observe(elapsed);
        }

        // Tell the resolver this view is complete so it can stop requesting it.
        resolver.notarized(notarization.clone()).await;
        // Update our local round with the certificate.
        self.handle_notarization(notarization.clone()).await;
        // Persist the certificate before informing others.
        self.sync_journal(view).await;
        // Surface the event to the application for observability.
        self.reporter
            .report(Activity::Notarization(notarization.clone()))
            .await;

        // Broadcast the notarization certificate
        debug!(proposal=?notarization.proposal, "broadcasting notarization");
        self.broadcast_all(recovered_sender, Voter::Notarization(notarization))
            .await;
    }

    /// Broadcast a nullification vote if the round provides a candidate.
    async fn try_broadcast_nullification<Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
        view: u64,
    ) {
        // Construct the nullification certificate.
        let Some(nullification) = self.construct_nullification(view, false) else {
            return;
        };

        // Notify resolver so dependent parents can progress.
        resolver.nullified(nullification.clone()).await;
        // Track the certificate locally to avoid rebuilding it.
        self.handle_nullification(nullification.clone()).await;
        // Ensure deterministic restarts.
        self.sync_journal(view).await;
        // Report upstream for metrics/logging.
        self.reporter
            .report(Activity::Nullification(nullification.clone()))
            .await;

        // Broadcast the nullification certificate.
        debug!(round=?nullification.round(), "broadcasting nullification");
        self.broadcast_all(recovered_sender, Voter::Nullification(nullification))
            .await;

        // If there is enough support for some proposal, fetch any missing certificates it implies.
        //
        // TODO(#2192): Replace with a more robust mechanism
        if let Some(missing) = self.state.missing_certificates(view) {
            debug!(
                proposal_view = view,
                parent = missing.parent,
                ?missing.notarizations,
                ?missing.nullifications,
                "fetching missing certificates after nullification"
            );
            resolver
                .fetch(missing.notarizations, missing.nullifications)
                .await;
        }
    }

    /// Broadcast a finalize vote if the round provides a candidate.
    async fn try_broadcast_finalize<Sp: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        pending_sender: &mut WrappedSender<Sp, Voter<S, D>>,
        view: u64,
    ) {
        // Construct the finalize vote.
        let Some(finalize) = self.state.construct_finalize(view) else {
            return;
        };

        // Provide the vote to the verifier pipeline.
        batcher.constructed(Voter::Finalize(finalize.clone())).await;
        // Update the round before persisting.
        self.handle_finalize(finalize.clone()).await;
        // Keep the vote durable for recovery.
        self.sync_journal(view).await;

        // Broadcast the finalize vote.
        debug!(
            round=?finalize.round(),
            proposal=?finalize.proposal,
            "broadcasting finalize"
        );
        self.broadcast_all(pending_sender, Voter::Finalize(finalize))
            .await;
    }

    /// Share a finalization certificate and notify observers of the new height.
    async fn try_broadcast_finalization<Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
        view: u64,
    ) {
        // Construct the finalization certificate.
        let Some(finalization) = self.construct_finalization(view, false) else {
            return;
        };

        // Only record latency if we are the current leader.
        if let Some(elapsed) = self.leader_elapsed(view) {
            self.finalization_latency.observe(elapsed);
        }

        // Inform resolver so other components know the view is done.
        resolver.finalized(view).await;
        // Advance the consensus core with the finalization proof.
        self.handle_finalization(finalization.clone()).await;
        // Persist the proof before broadcasting it.
        self.sync_journal(view).await;
        // Notify the application so clients can observe the new height.
        self.reporter
            .report(Activity::Finalization(finalization.clone()))
            .await;

        // Broadcast the finalization certificate.
        debug!(proposal=?finalization.proposal, "broadcasting finalization");
        self.broadcast_all(recovered_sender, Voter::Finalization(finalization))
            .await;
    }

    async fn notify<Sp: Sender, Sr: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        resolver: &mut resolver::Mailbox<S, D>,
        pending_sender: &mut WrappedSender<Sp, Voter<S, D>>,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
        view: u64,
    ) {
        self.try_broadcast_notarize(batcher, pending_sender, view)
            .await;
        self.try_broadcast_notarization(resolver, recovered_sender, view)
            .await;
        // We handle broadcast of `Nullify` votes in `timeout`, so this only emits certificates.
        self.try_broadcast_nullification(resolver, recovered_sender, view)
            .await;
        self.try_broadcast_finalize(batcher, pending_sender, view)
            .await;
        self.try_broadcast_finalization(resolver, recovered_sender, view)
            .await;
    }

    pub fn start(
        mut self,
        batcher: batcher::Mailbox<S, D>,
        resolver: resolver::Mailbox<S, D>,
        pending_sender: impl Sender<PublicKey = P>,
        recovered_sender: impl Sender<PublicKey = P>,
        recovered_receiver: impl Receiver<PublicKey = P>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(
                batcher,
                resolver,
                pending_sender,
                recovered_sender,
                recovered_receiver
            )
            .await
        )
    }

    async fn run(
        mut self,
        mut batcher: batcher::Mailbox<S, D>,
        mut resolver: resolver::Mailbox<S, D>,
        pending_sender: impl Sender<PublicKey = P>,
        recovered_sender: impl Sender<PublicKey = P>,
        recovered_receiver: impl Receiver<PublicKey = P>,
    ) {
        // Wrap channel
        let mut pending_sender = WrappedSender::new(pending_sender);
        let (mut recovered_sender, mut recovered_receiver) = wrap::<_, _, Voter<S, D>>(
            self.state.scheme().certificate_codec_config(),
            recovered_sender,
            recovered_receiver,
        );

        // Add initial view
        //
        // We start on view 1 because the genesis container occupies view 0/height 0.
        self.state
            .set_genesis(self.automaton.genesis(self.state.epoch()).await);
        self.enter_view(1, None);

        // Initialize journal
        let journal = Journal::<_, Voter<S, D>>::init(
            self.context.with_label("journal").into(),
            JConfig {
                partition: self.partition.clone(),
                compression: None, // most of the data is not compressible
                codec_config: self.state.scheme().certificate_codec_config(),
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
            while let Some(msg) = stream.next().await {
                let (_, _, _, msg) = msg.expect("unable to replay journal");
                match msg {
                    Voter::Notarize(notarize) => {
                        let replay = Voter::Notarize(notarize.clone());
                        self.handle_notarize(notarize.clone()).await;
                        self.reporter.report(Activity::Notarize(notarize)).await;

                        // Update state info
                        self.state.replay(&replay);
                    }
                    Voter::Notarization(notarization) => {
                        let replay = Voter::Notarization(notarization.clone());
                        self.handle_notarization(notarization.clone()).await;
                        self.reporter
                            .report(Activity::Notarization(notarization))
                            .await;

                        // Update state info
                        self.state.replay(&replay);
                    }
                    Voter::Nullify(nullify) => {
                        let replay = Voter::Nullify(nullify.clone());
                        self.handle_nullify(nullify.clone()).await;
                        self.reporter.report(Activity::Nullify(nullify)).await;

                        // Update state info
                        self.state.replay(&replay);
                    }
                    Voter::Nullification(nullification) => {
                        let replay = Voter::Nullification(nullification.clone());
                        self.handle_nullification(nullification.clone()).await;
                        self.reporter
                            .report(Activity::Nullification(nullification))
                            .await;

                        // Update state info
                        self.state.replay(&replay);
                    }
                    Voter::Finalize(finalize) => {
                        let replay = Voter::Finalize(finalize.clone());
                        self.handle_finalize(finalize.clone()).await;
                        self.reporter.report(Activity::Finalize(finalize)).await;

                        // Update state info
                        self.state.replay(&replay);
                    }
                    Voter::Finalization(finalization) => {
                        let replay = Voter::Finalization(finalization.clone());
                        self.handle_finalization(finalization.clone()).await;
                        self.reporter
                            .report(Activity::Finalization(finalization))
                            .await;

                        // Update state info
                        self.state.replay(&replay);
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
            current_view = observed_view,
            ?elapsed,
            "consensus initialized"
        );
        self.state.expire_round(observed_view);
        let _ = self.current_view.try_set(observed_view);
        let _ = self.tracked_views.try_set(self.state.tracked_views());

        // Initialize verifier with leader
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
        let mut pending_set = None;
        let mut pending_propose_context = None;
        let mut pending_propose = None;
        let mut pending_verify_context = None;
        let mut pending_verify = None;
        loop {
            // Reset pending set if we have moved to a new view
            if let Some(view) = pending_set {
                if view != self.state.current_view() {
                    pending_set = None;
                    pending_propose_context = None;
                    pending_propose = None;
                    pending_verify_context = None;
                    pending_verify = None;
                }
            }

            // Attempt to propose a container
            if let Some((context, new_propose)) = self.try_propose(&mut resolver).await {
                pending_set = Some(self.state.current_view());
                pending_propose_context = Some(context);
                pending_propose = Some(new_propose);
            }
            let propose_wait = match &mut pending_propose {
                Some(propose) => Either::Left(propose),
                None => Either::Right(futures::future::pending()),
            };

            // Attempt to verify current view
            if let Some((context, new_verify)) = self.try_verify().await {
                pending_set = Some(self.state.current_view());
                pending_verify_context = Some(context);
                pending_verify = Some(new_verify);
            }
            let verify_wait = match &mut pending_verify {
                Some(verify) => Either::Left(verify),
                None => Either::Right(futures::future::pending()),
            };

            // Wait for a timeout to fire or for a message to arrive
            let timeout = self.state.next_timeout_deadline();
            let start = self.state.current_view();
            let view;
            select! {
                _ = &mut shutdown => {
                    // Close journal
                    self.journal
                        .take()
                        .unwrap()
                        .close()
                        .await
                        .expect("unable to close journal");
                    return;
                },
                _ = self.context.sleep_until(timeout) => {
                    // Trigger the timeout
                    self.timeout(&mut batcher, &mut pending_sender, &mut recovered_sender).await;
                    view = self.state.current_view();
                },
                proposed = propose_wait => {
                    // Clear propose waiter
                    let context = pending_propose_context.take().unwrap();
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
                        debug!(round = ?context.round, ?our_round, reason = "no longer in required view", "dropping requested proposal");
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
                verified = verify_wait => {
                    // Clear verify waiter
                    let context = pending_verify_context.take().unwrap();
                    pending_verify = None;

                    // Try to use result
                    match verified {
                        Ok(verified) => {
                            if !verified {
                                debug!(round = ?context.round, "proposal failed verification");
                                continue;
                            }
                        },
                        Err(err) => {
                            debug!(?err, round = ?context.round, "failed to verify proposal");
                            continue;
                        }
                    };

                    // Handle verified proposal
                    view = context.view();
                    if !self.state.verified(view) {
                        continue;
                    }
                },
                mailbox = self.mailbox_receiver.next() => {
                    // Extract message
                    let Some(msg) = mailbox else {
                        break;
                    };
                    let Message::Verified(msg) = msg;

                    // Ensure view is still useful.
                    //
                    // It is possible that we make a request to the resolver and prune the view
                    // before we receive the response. In this case, we should ignore the response (not
                    // doing so may result in attempting to store before the prune boundary).
                    //
                    // We do not need to allow `future` here because any notarization or nullification we see
                    // here must've been requested by us (something we only do when ahead of said view).
                    view = msg.view();
                    if !self.state.is_interesting(view, false) {
                        debug!(view, "verified message is not interesting");
                        continue;
                    }

                    // Handle verifier and resolver
                    match msg {
                        Voter::Notarize(notarize) => {
                            self.handle_notarize(notarize).await;
                        }
                        Voter::Nullify(nullify) => {
                            self.handle_nullify(nullify).await;
                        }
                        Voter::Finalize(finalize) => {
                            self.handle_finalize(finalize).await;
                        }
                        Voter::Notarization(notarization)  => {
                            trace!(view, "received notarization from resolver");
                            self.handle_notarization(notarization).await;
                        },
                        Voter::Nullification(nullification) => {
                            trace!(view, "received nullification from resolver");
                            self.handle_nullification(nullification).await;
                        },
                        Voter::Finalization(_) => {
                            unreachable!("unexpected message type");
                        }
                    }
                },
                msg = recovered_receiver.recv() => {
                    // Break if there is an internal error
                    let Ok((sender, msg)) = msg else {
                        break;
                    };

                    // Block if there is a decoding error
                    let Ok(msg) = msg else {
                        warn!(?sender, "blocking peer for decoding error");
                        self.blocker.block(sender).await;
                        continue;
                    };

                    // Block if the epoch is not the current epoch
                if msg.epoch() != self.state.epoch() {
                        warn!(?sender, "blocking peer for epoch mismatch");
                        self.blocker.block(sender).await;
                        continue;
                    }

                    // Process message
                    //
                    // We opt to not filter by `interesting()` here because each message type has a different
                    // configuration for handling `future` messages.
                    view = msg.view();
                    let action = match msg {
                        Voter::Notarization(notarization) => {
                            self.inbound_messages
                                .get_or_create(&Inbound::notarization(&sender))
                                .inc();
                            self.notarization(notarization).await
                        }
                        Voter::Nullification(nullification) => {
                            self.inbound_messages
                                .get_or_create(&Inbound::nullification(&sender))
                                .inc();
                            self.nullification(nullification).await
                        }
                        Voter::Finalization(finalization) => {
                            self.inbound_messages
                                .get_or_create(&Inbound::finalization(&sender))
                                .inc();
                            self.finalization(finalization).await
                        }
                        Voter::Notarize(_) | Voter::Nullify(_) | Voter::Finalize(_) => {
                            warn!(?sender, "blocking peer for invalid message type");
                            self.blocker.block(sender).await;
                            continue;
                        }
                    };
                    match action {
                        Action::Process => {}
                        Action::Skip => {
                            trace!(?sender, view, "dropped useless");
                            continue;
                        }
                        Action::Block => {
                            warn!(?sender, view, "blocking peer");
                            self.blocker.block(sender).await;
                            continue;
                        }
                    }
                },
            };

            // Attempt to send any new view messages
            self.notify(
                &mut batcher,
                &mut resolver,
                &mut pending_sender,
                &mut recovered_sender,
                view,
            )
            .await;

            // After sending all required messages, prune any views
            // we no longer need
            self.prune_views().await;

            // Update the verifier if we have moved to a new view
            if self.state.current_view() > start {
                let current_view = self.state.current_view();
                let leader = self
                    .state
                    .leader_index(current_view)
                    .expect("leader not set");

                // If the leader is not active (and not us), we should reduce leader timeout to now
                let is_active = batcher
                    .update(current_view, leader, self.state.last_finalized())
                    .await;
                if !is_active && !self.state.is_me(leader) {
                    debug!(view, ?leader, "skipping leader timeout due to inactivity");
                    self.skipped_views.inc();
                    self.state.expire_round(current_view);
                }
            }
        }
    }
}
