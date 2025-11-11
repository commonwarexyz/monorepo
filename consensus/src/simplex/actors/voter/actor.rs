use super::{Config, Mailbox, Message};
use crate::{
    simplex::{
        actors::{batcher, resolver},
        metrics::{self, Inbound, Outbound},
        signing_scheme::Scheme,
        state::{
            CoreConfig as SimplexCoreConfig, LocalProposalError, ParentValidationError,
            PeerProposalError, ProposalIntentError, SimplexCore, VerificationError, GENESIS_VIEW,
        },
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
    time::{Duration, SystemTime},
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
    core: SimplexCore<S, D>,
    blocker: B,
    automaton: A,
    relay: R,
    reporter: F,

    partition: String,
    replay_buffer: NonZeroUsize,
    write_buffer: NonZeroUsize,
    buffer_pool: PoolRef,
    journal: Option<Journal<E, Voter<S, D>>>,

    genesis: Option<D>,

    namespace: Vec<u8>,

    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,

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
        let core = SimplexCore::new(SimplexCoreConfig {
            scheme: cfg.scheme,
            epoch: cfg.epoch,
            activity_timeout: cfg.activity_timeout,
            start_view: GENESIS_VIEW,
            last_finalized: GENESIS_VIEW,
        });
        (
            Self {
                context: ContextCell::new(context),
                core,
                blocker: cfg.blocker,
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,

                partition: cfg.partition,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                buffer_pool: cfg.buffer_pool,
                journal: None,

                genesis: None,

                namespace: cfg.namespace,

                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,

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

    fn find_parent(&self) -> Result<(View, D), View> {
        let mut cursor = self.core.current_view() - 1; // current_view always at least 1
        loop {
            if cursor == 0 {
                return Ok((GENESIS_VIEW, *self.genesis.as_ref().unwrap()));
            }

            // If have notarization, return
            let parent = self.core.notarized_payload(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, *parent));
            }

            // If have finalization, return
            //
            // We never want to build on some view less than finalized and this prevents that
            let parent = self.core.finalized_payload(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, *parent));
            }

            // If have nullification, continue
            if self.core.is_nullified(cursor) {
                cursor -= 1;
                continue;
            }

            // We can't find a valid parent, return
            return Err(cursor);
        }
    }

    #[allow(clippy::question_mark)]
    async fn propose(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
    ) -> Option<(Context<D, P>, oneshot::Receiver<D>)> {
        let current_view = self.core.current_view();
        let leader = {
            let round = self.core.ensure_round(current_view, self.context.current());
            match round.begin_local_proposal() {
                Ok(leader) => leader,
                Err(ProposalIntentError::LeaderUnknown) => {
                    debug!(
                        view = current_view,
                        "skipping proposal because leader not yet elected"
                    );
                    return None;
                }
                Err(ProposalIntentError::NotLeader(_))
                | Err(ProposalIntentError::TimedOut(_))
                | Err(ProposalIntentError::AlreadyBuilding(_)) => {
                    return None;
                }
            }
        };

        // Find best parent
        let (parent_view, parent_payload) = match self.find_parent() {
            Ok(parent) => parent,
            Err(view) => {
                debug!(
                    view = current_view,
                    missing = view,
                    "skipping proposal opportunity"
                );
                resolver.fetch(vec![view], vec![view]).await;
                return None;
            }
        };

        // Request proposal from application
        debug!(view = current_view, "requested proposal from automaton");
        let context = Context {
            round: Rnd::new(self.core.epoch(), current_view),
            leader: leader.key,
            parent: (parent_view, parent_payload),
        };
        Some((context.clone(), self.automaton.propose(context).await))
    }

    fn timeout_deadline(&mut self) -> SystemTime {
        let current_view = self.core.current_view();
        let now = self.context.current();
        let retry = self.nullify_retry;
        let round = self.core.ensure_round(current_view, now);
        round.next_timeout_deadline(now, retry)
    }

    async fn timeout<Sp: Sender, Sr: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        pending_sender: &mut WrappedSender<Sp, Voter<S, D>>,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
    ) {
        // Set timeout fired
        let current_view = self.core.current_view();
        let round = self.core.ensure_round(current_view, self.context.current());
        let retry = round.handle_timeout().was_retry;

        // When retrying we immediately re-share the certificate that let us enter
        // this view so slow peers do not stall our next round.
        let past_view = current_view - 1;
        if retry
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

        // Construct nullify
        let Some(nullify) = Nullify::sign::<D>(
            self.core.scheme(),
            &self.namespace,
            Rnd::new(self.core.epoch(), current_view),
        ) else {
            return;
        };

        // Handle the nullify
        if !retry {
            batcher.constructed(Voter::Nullify(nullify.clone())).await;
            self.handle_nullify(nullify.clone()).await;

            // Sync the journal
            self.sync_journal(current_view).await;
        }

        // Broadcast nullify
        debug!(round=?nullify.round(), "broadcasting nullify");
        self.broadcast_all(
            pending_sender,
            metrics::Outbound::nullify(),
            Voter::Nullify(nullify),
        )
        .await;
    }

    async fn handle_nullify(&mut self, nullify: Nullify<S>) {
        // Get view for nullify
        let view = nullify.view();

        // Handle nullify
        self.append_journal(view, Voter::Nullify(nullify.clone()))
            .await;

        // Create round (if it doesn't exist) and add verified nullify
        let round = self.core.ensure_round(view, self.context.current());
        round.add_verified_nullify(nullify);
    }

    async fn our_proposal(&mut self, proposal: Proposal<D>) -> bool {
        // Store the proposal
        let round = self
            .core
            .ensure_round(proposal.view(), self.context.current());
        match round.accept_local_proposal(proposal.clone()) {
            Ok(()) => {
                debug!(?proposal, "generated proposal");
                true
            }
            Err(LocalProposalError::TimedOut) => {
                debug!(
                    ?proposal,
                    reason = "view timed out",
                    "dropping our proposal"
                );
                false
            }
        }
    }

    // Attempt to set proposal from each message received over the wire
    #[allow(clippy::question_mark)]
    async fn peer_proposal(&mut self) -> Option<(Context<D, P>, oneshot::Receiver<bool>)> {
        let current_view = self.core.current_view();
        let peer = {
            let round = self.core.round_mut(current_view)?;
            match round.claim_peer_proposal() {
                Ok(ctx) => ctx,
                Err(PeerProposalError::LeaderUnknown) => {
                    debug!(
                        view = current_view,
                        "dropping peer proposal because leader is not set"
                    );
                    return None;
                }
                Err(PeerProposalError::LocalLeader(_))
                | Err(PeerProposalError::TimedOut)
                | Err(PeerProposalError::MissingProposal)
                | Err(PeerProposalError::AlreadyVerifying) => {
                    return None;
                }
            }
        };
        let proposal = peer.proposal;
        let leader = peer.leader;

        // Sanity-check the epoch is correct. It should have already been checked.
        assert_eq!(
            proposal.epoch(),
            self.core.epoch(),
            "proposal epoch mismatch"
        );

        let genesis = self.genesis.as_ref().expect("genesis payload missing");
        let parent_payload = match self.core.parent_payload(current_view, &proposal, genesis) {
            Ok(payload) => payload,
            Err(ParentValidationError::ParentNotBeforeProposal { parent, .. }) => {
                debug!(
                    round = ?proposal.round,
                    parent,
                    "dropping peer proposal because parent is invalid"
                );
                return None;
            }
            Err(ParentValidationError::ParentBeforeFinalized {
                parent,
                last_finalized,
            }) => {
                debug!(
                    round = ?proposal.round,
                    parent,
                    last_finalized,
                    "dropping peer proposal because parent is less than last finalized"
                );
                return None;
            }
            Err(ParentValidationError::CurrentViewUninitialized) => {
                return None;
            }
            Err(ParentValidationError::ParentNotBeforeCurrent { parent, current }) => {
                debug!(
                    round = ?proposal.round,
                    parent,
                    current,
                    "dropping peer proposal because parent is not in the past"
                );
                return None;
            }
            Err(ParentValidationError::MissingParentNotarization { view }) => {
                debug!(view, "parent proposal is not notarized");
                return None;
            }
            Err(ParentValidationError::MissingNullification { view }) => {
                debug!(view, "missing nullification during proposal verification");
                return None;
            }
        };

        // Request verification
        debug!(?proposal, "requested proposal verification",);
        let context = Context {
            round: proposal.round,
            leader: leader.key,
            parent: (proposal.parent, parent_payload),
        };
        let payload = proposal.payload;
        Some((
            context.clone(),
            self.automaton.verify(context, payload).await,
        ))
    }

    async fn verified(&mut self, view: View) -> bool {
        // Check if view still relevant
        let round = match self.core.round_mut(view) {
            Some(view) => view,
            None => {
                return false;
            }
        };

        match round.complete_peer_verification() {
            Ok(()) => {
                debug!(
                    round=?round.round_id(),
                    proposal=?round.proposal_ref(),
                    "verified proposal"
                );
                true
            }
            Err(VerificationError::TimedOut) => {
                debug!(
                    round=?round.round_id(),
                    reason = "view timed out",
                    "dropping verified proposal"
                );
                false
            }
            Err(VerificationError::NotPending) => false,
        }
    }

    fn since_view_start(&self, view: u64) -> Option<(bool, f64)> {
        let round = self.core.round(view)?;
        let elapsed = round.elapsed_since_start(self.context.current())?;
        Some((self.core.is_me(round.leader()?.idx), elapsed.as_secs_f64()))
    }

    fn enter_view(&mut self, view: u64, seed: Option<S::Seed>) {
        let now = self.context.current();
        let leader_deadline = now + self.leader_timeout;
        let advance_deadline = now + self.notarization_timeout;
        if self
            .core
            .enter_view(view, now, leader_deadline, advance_deadline, seed)
        {
            let _ = self.current_view.try_set(view);
        }
    }

    async fn prune_views(&mut self) {
        let removed = self.core.prune();
        if removed.is_empty() {
            return;
        }
        for view in &removed {
            debug!(
                view = *view,
                last_finalized = self.core.last_finalized(),
                "pruned view"
            );
        }
        if let Some(journal) = self.journal.as_mut() {
            journal
                .prune(self.core.min_active())
                .await
                .expect("unable to prune journal");
        }
        let _ = self.tracked_views.try_set(self.core.tracked_views());
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
        metric: &'static metrics::Outbound,
        msg: Voter<S, D>,
    ) {
        self.outbound_messages.get_or_create(metric).inc();
        sender.send(Recipients::All, msg, true).await.unwrap();
    }

    async fn handle_notarize(&mut self, notarize: Notarize<S, D>) {
        // Get view for notarize
        let view = notarize.view();

        // Handle notarize
        self.append_journal(view, Voter::Notarize(notarize.clone()))
            .await;

        // Create round (if it doesn't exist) and add verified notarize
        let round = self.core.ensure_round(view, self.context.current());
        let equivocator = round.add_verified_notarize(notarize);
        self.block_equivocator(equivocator).await;
    }

    async fn notarization(&mut self, notarization: Notarization<S, D>) -> Action {
        // Check if we are still in a view where this notarization could help
        let view = notarization.view();
        if !self.core.is_interesting(view, true) {
            return Action::Skip;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        if let Some(round) = self.core.round(view) {
            if round.has_broadcast_notarization() {
                return Action::Skip;
            }
        }

        // Verify notarization
        if !notarization.verify(&mut self.context, self.core.scheme(), &self.namespace) {
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
            .core
            .scheme()
            .seed(notarization.round(), &notarization.certificate);

        // Create round (if it doesn't exist) and add verified notarization
        let round = self.core.ensure_round(view, self.context.current());
        let (added, equivocator) = round.add_verified_notarization(notarization);
        if added {
            self.append_journal(view, msg).await;
        }
        self.block_equivocator(equivocator).await;

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn nullification(&mut self, nullification: Nullification<S>) -> Action {
        // Check if we are still in a view where this notarization could help
        if !self.core.is_interesting(nullification.view(), true) {
            return Action::Skip;
        }

        // Determine if we already broadcast nullification for this view (in which
        // case we can ignore this message)
        if let Some(round) = self.core.round(nullification.view()) {
            if round.has_broadcast_nullification() {
                return Action::Skip;
            }
        }

        // Verify nullification
        if !nullification.verify::<_, D>(&mut self.context, self.core.scheme(), &self.namespace) {
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
            .core
            .scheme()
            .seed(nullification.round, &nullification.certificate);

        // Create round (if it doesn't exist) and add verified nullification
        let view = nullification.view();
        let round = self.core.ensure_round(view, self.context.current());
        if round.add_verified_nullification(nullification) {
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
        let round = self.core.ensure_round(view, self.context.current());
        let equivocator = round.add_verified_finalize(finalize);
        self.block_equivocator(equivocator).await;
    }

    async fn finalization(&mut self, finalization: Finalization<S, D>) -> Action {
        // Check if we are still in a view where this finalization could help
        let view = finalization.view();
        if !self.core.is_interesting(view, true) {
            return Action::Skip;
        }

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        if let Some(round) = self.core.round(view) {
            if round.has_broadcast_finalization() {
                return Action::Skip;
            }
        }

        // Verify finalization
        if !finalization.verify(&mut self.context, self.core.scheme(), &self.namespace) {
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
            .core
            .scheme()
            .seed(finalization.round(), &finalization.certificate);

        // Create round (if it doesn't exist) and add verified finalization
        let view = finalization.view();
        let round = self.core.ensure_round(view, self.context.current());
        let (added, equivocator) = round.add_verified_finalization(finalization);
        if added {
            self.append_journal(view, msg).await;
        }
        self.block_equivocator(equivocator).await;

        // Track view finalized
        if view > self.core.last_finalized() {
            self.core.set_last_finalized(view);
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    fn construct_notarize(&mut self, view: u64) -> Option<Notarize<S, D>> {
        // Determine if it makes sense to broadcast a notarize
        let proposal = self.core.round_mut(view)?.notarize_candidate()?.clone();

        // Construct notarize
        Notarize::sign(self.core.scheme(), &self.namespace, proposal)
    }

    fn construct_notarization(&mut self, view: u64, force: bool) -> Option<Notarization<S, D>> {
        let mut timer = self.recover_latency.timer();
        // Get requested view
        let round = self.core.round_mut(view)?;

        // Attempt to construct notarization
        let result = round.notarizable(force);
        if result.is_some() {
            timer.observe();
        }
        result
    }

    fn construct_nullification(&mut self, view: u64, force: bool) -> Option<Nullification<S>> {
        let mut timer = self.recover_latency.timer();
        // Get requested view
        let round = self.core.round_mut(view)?;

        // Attempt to construct nullification
        let result = round.nullifiable(force);
        if result.is_some() {
            timer.observe();
        }
        result
    }

    fn construct_finalize(&mut self, view: u64) -> Option<Finalize<S, D>> {
        // Determine if it makes sense to broadcast a finalize
        let proposal = self.core.round_mut(view)?.finalize_candidate()?.clone();

        // Construct finalize
        Finalize::sign(self.core.scheme(), &self.namespace, proposal)
    }

    fn construct_finalization(&mut self, view: u64, force: bool) -> Option<Finalization<S, D>> {
        let mut timer = self.recover_latency.timer();
        let round = self.core.round_mut(view)?;

        // Attempt to construct finalization
        let result = round.finalizable(force);
        if result.is_some() {
            timer.observe();
        }
        result
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
            self.broadcast_all(
                recovered_sender,
                metrics::Outbound::finalization(),
                Voter::Finalization(finalization),
            )
            .await;
            debug!(view, "rebroadcast entry finalization");
            return true;
        }

        if let Some(notarization) = self.construct_notarization(view, true) {
            // Otherwise rebroadcast the notarization that advanced us.
            self.broadcast_all(
                recovered_sender,
                metrics::Outbound::notarization(),
                Voter::Notarization(notarization),
            )
            .await;
            debug!(view, "rebroadcast entry notarization");
            return true;
        }

        if let Some(nullification) = self.construct_nullification(view, true) {
            // Finally fall back to the nullification evidence if that is all we have.
            self.broadcast_all(
                recovered_sender,
                metrics::Outbound::nullification(),
                Voter::Nullification(nullification),
            )
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
        let Some(notarize) = self.construct_notarize(view) else {
            return;
        };

        // Inform the verifier so it can aggregate our vote with others.
        batcher.constructed(Voter::Notarize(notarize.clone())).await;
        // Record the vote locally before sharing it.
        self.handle_notarize(notarize.clone()).await;
        // Keep the vote durable for crash recovery.
        self.sync_journal(view).await;

        debug!(
            round=?notarize.round(),
            proposal=?notarize.proposal,
            "broadcasting notarize"
        );
        self.broadcast_all(
            pending_sender,
            metrics::Outbound::notarize(),
            Voter::Notarize(notarize),
        )
        .await;
    }

    /// Share a notarization certificate once we can assemble it locally.
    async fn try_share_notarization<Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
        view: u64,
    ) {
        let Some(notarization) = self.construct_notarization(view, false) else {
            return;
        };

        // Only the leader sees an unbiased latency sample, so record it now.
        if let Some((leader, elapsed)) = self.since_view_start(view) {
            if leader {
                self.notarization_latency.observe(elapsed);
            }
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

        debug!(proposal=?notarization.proposal, "broadcasting notarization");
        self.broadcast_all(
            recovered_sender,
            metrics::Outbound::notarization(),
            Voter::Notarization(notarization),
        )
        .await;
    }

    /// Share nullification evidence and request any missing parent certificates.
    async fn try_share_nullification<Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
        view: u64,
    ) {
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

        debug!(round=?nullification.round(), "broadcasting nullification");
        self.broadcast_all(
            recovered_sender,
            metrics::Outbound::nullification(),
            Voter::Nullification(nullification),
        )
        .await;

        if let Some(missing) = self.core.missing_certificates(view) {
            // If an honest node notarized a child, fetch the missing certificates immediately.
            warn!(
                proposal_view = view,
                parent = missing.parent,
                ?missing.notarizations,
                ?missing.nullifications,
                ">= 1 honest notarize for nullified parent"
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
        let Some(finalize) = self.construct_finalize(view) else {
            return;
        };

        // Provide the vote to the verifier pipeline.
        batcher.constructed(Voter::Finalize(finalize.clone())).await;
        // Update the round before persisting.
        self.handle_finalize(finalize.clone()).await;
        // Keep the vote durable for recovery.
        self.sync_journal(view).await;

        debug!(
            round=?finalize.round(),
            proposal=?finalize.proposal,
            "broadcasting finalize"
        );
        self.broadcast_all(
            pending_sender,
            metrics::Outbound::finalize(),
            Voter::Finalize(finalize),
        )
        .await;
    }

    /// Share a finalization certificate and notify observers of the new height.
    async fn try_share_finalization<Sr: Sender>(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        recovered_sender: &mut WrappedSender<Sr, Voter<S, D>>,
        view: u64,
    ) {
        let Some(finalization) = self.construct_finalization(view, false) else {
            return;
        };

        // Only record latency if we are the current leader.
        if let Some((leader, elapsed)) = self.since_view_start(view) {
            if leader {
                self.finalization_latency.observe(elapsed);
            }
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

        debug!(proposal=?finalization.proposal, "broadcasting finalization");
        self.broadcast_all(
            recovered_sender,
            metrics::Outbound::finalization(),
            Voter::Finalization(finalization),
        )
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
        // Each helper encapsulates the logic and side effects for clarity.
        self.try_broadcast_notarize(batcher, pending_sender, view)
            .await;
        self.try_share_notarization(resolver, recovered_sender, view)
            .await;
        // We handle broadcast of `Nullify` votes in `timeout`, so this only emits certificates.
        self.try_share_nullification(resolver, recovered_sender, view)
            .await;
        self.try_broadcast_finalize(batcher, pending_sender, view)
            .await;
        self.try_share_finalization(resolver, recovered_sender, view)
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
            self.core.scheme().certificate_codec_config(),
            recovered_sender,
            recovered_receiver,
        );

        // Compute genesis
        let genesis = self.automaton.genesis(self.core.epoch()).await;
        self.genesis = Some(genesis);

        // Add initial view
        //
        // We start on view 1 because the genesis container occupies view 0/height 0.
        self.enter_view(1, None);

        // Initialize journal
        let journal = Journal::<_, Voter<S, D>>::init(
            self.context.with_label("journal").into(),
            JConfig {
                partition: self.partition.clone(),
                compression: None, // most of the data is not compressible
                codec_config: self.core.scheme().certificate_codec_config(),
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
                let view = msg.view();
                match msg {
                    Voter::Notarize(notarize) => {
                        let replay = Voter::Notarize(notarize.clone());
                        self.handle_notarize(notarize.clone()).await;
                        self.reporter.report(Activity::Notarize(notarize)).await;
                        self.core
                            .ensure_round(view, self.context.current())
                            .replay_message(&replay);
                    }
                    Voter::Notarization(notarization) => {
                        let replay = Voter::Notarization(notarization.clone());
                        self.handle_notarization(notarization.clone()).await;
                        self.reporter
                            .report(Activity::Notarization(notarization))
                            .await;
                        self.core
                            .ensure_round(view, self.context.current())
                            .replay_message(&replay);
                    }
                    Voter::Nullify(nullify) => {
                        let replay = Voter::Nullify(nullify.clone());
                        self.handle_nullify(nullify.clone()).await;
                        self.reporter.report(Activity::Nullify(nullify)).await;
                        self.core
                            .ensure_round(view, self.context.current())
                            .replay_message(&replay);
                    }
                    Voter::Nullification(nullification) => {
                        let replay = Voter::Nullification(nullification.clone());
                        self.handle_nullification(nullification.clone()).await;
                        self.reporter
                            .report(Activity::Nullification(nullification))
                            .await;
                        self.core
                            .ensure_round(view, self.context.current())
                            .replay_message(&replay);
                    }
                    Voter::Finalize(finalize) => {
                        let replay = Voter::Finalize(finalize.clone());
                        self.handle_finalize(finalize.clone()).await;
                        self.reporter.report(Activity::Finalize(finalize)).await;
                        self.core
                            .ensure_round(view, self.context.current())
                            .replay_message(&replay);
                    }
                    Voter::Finalization(finalization) => {
                        let replay = Voter::Finalization(finalization.clone());
                        self.handle_finalization(finalization.clone()).await;
                        self.reporter
                            .report(Activity::Finalization(finalization))
                            .await;
                        self.core
                            .ensure_round(view, self.context.current())
                            .replay_message(&replay);
                    }
                }
            }
        }
        self.journal = Some(journal);

        // Update current view and immediately move to timeout (very unlikely we restarted and still within timeout)
        let end = self.context.current();
        let elapsed = end.duration_since(start).unwrap_or_default();
        let observed_view = self.core.current_view();
        info!(
            current_view = observed_view,
            ?elapsed,
            "consensus initialized"
        );
        let leader_deadline = self.context.current();
        let advance_deadline = self.context.current();
        {
            let round = self
                .core
                .ensure_round(observed_view, self.context.current());
            round.set_deadlines(leader_deadline, advance_deadline);
        }
        let _ = self.current_view.try_set(observed_view);
        let _ = self.tracked_views.try_set(self.core.tracked_views());

        // Initialize verifier with leader
        let round = self
            .core
            .ensure_round(observed_view, self.context.current());
        let leader = round.leader().expect("leader not set").idx;
        batcher
            .update(observed_view, leader, self.core.last_finalized())
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
                if view != self.core.current_view() {
                    pending_set = None;
                    pending_propose_context = None;
                    pending_propose = None;
                    pending_verify_context = None;
                    pending_verify = None;
                }
            }

            // Attempt to propose a container
            if let Some((context, new_propose)) = self.propose(&mut resolver).await {
                pending_set = Some(self.core.current_view());
                pending_propose_context = Some(context);
                pending_propose = Some(new_propose);
            }
            let propose_wait = match &mut pending_propose {
                Some(propose) => Either::Left(propose),
                None => Either::Right(futures::future::pending()),
            };

            // Attempt to verify current view
            if let Some((context, new_verify)) = self.peer_proposal().await {
                pending_set = Some(self.core.current_view());
                pending_verify_context = Some(context);
                pending_verify = Some(new_verify);
            }
            let verify_wait = match &mut pending_verify {
                Some(verify) => Either::Left(verify),
                None => Either::Right(futures::future::pending()),
            };

            // Wait for a timeout to fire or for a message to arrive
            let timeout = self.timeout_deadline();
            let start = self.core.current_view();
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
                    view = self.core.current_view();
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
                    let our_round = Rnd::new(self.core.epoch(), self.core.current_view());
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
                    if !self.our_proposal(proposal).await {
                        warn!(round = ?context.round, "dropped our proposal");
                        continue;
                    }
                    view = self.core.current_view();

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
                    if !self.verified(view).await {
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
                    if !self.core.is_interesting(view, false) {
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
                if msg.epoch() != self.core.epoch() {
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
            if self.core.current_view() > start {
                let current_view = self.core.current_view();
                let leader = {
                    let round = self.core.ensure_round(current_view, self.context.current());
                    round.leader().expect("leader not set").idx
                };
                let is_active = batcher
                    .update(current_view, leader, self.core.last_finalized())
                    .await;

                // If the leader is not active (and not us), we should reduce leader timeout to now
                if !is_active && !self.core.is_me(leader) {
                    debug!(view, ?leader, "skipping leader timeout due to inactivity");
                    self.skipped_views.inc();
                    let now = self.context.current();
                    if let Some(round) = self.core.round_mut(current_view) {
                        round.set_leader_deadline(Some(now));
                    }
                }
            }
        }
    }
}
