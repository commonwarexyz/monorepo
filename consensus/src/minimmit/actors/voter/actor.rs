//! Voter actor implementation.
//!
//! The voter wraps the state machine and coordinates between the batcher,
//! resolver, automaton, and network.
//!
//! ## Crash Recovery
//!
//! The voter uses a journal to persist votes and certificates for crash recovery.
//! On restart, the journal is replayed to rebuild state, ensuring:
//! - We don't double-vote after a crash (safety)
//! - We resume from where we left off (liveness)

use super::{egress::Egress, ingress::Message, Config, Mailbox};
use crate::{
    elector::Config as Elector,
    minimmit::{
        actors::{batcher, resolver},
        metrics::Outbound,
        scheme::Scheme,
        state::{Action, State},
        types::{Activity, Artifact, Certificate, Context, Proposal, Vote},
    },
    types::{Epoch, View, ViewDelta},
    Automaton, Relay, Reporter, Viewable,
};
use commonware_codec::Read;
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef,
    spawn_cell,
    telemetry::metrics::{
        histogram::{self, Buckets},
        status::GaugeExt,
    },
    Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
use commonware_utils::channel::{mpsc, oneshot};
use futures::{pin_mut, StreamExt};
use prometheus_client::metrics::{
    counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
};
use rand_core::CryptoRngCore;
use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    sync::{atomic::AtomicI64, Arc},
    time::{Duration, SystemTime},
};
use tracing::{debug, info, trace};

/// An outstanding request to the automaton.
struct Request<V: Viewable, R>(
    /// Attached context for the pending item.
    V,
    /// Oneshot receiver that the automaton responds over.
    oneshot::Receiver<R>,
);

impl<V: Viewable, R> Viewable for Request<V, R> {
    fn view(&self) -> View {
        self.0.view()
    }
}

/// Voter actor for Minimmit consensus.
///
/// Wraps the state machine and coordinates between batcher, resolver,
/// automaton, and network.
///
/// Uses a journal for crash recovery to ensure safety (no double-voting)
/// and liveness (resume from where we left off).
pub struct Actor<E, S, L, B, D, A, R, F, T>
where
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: Automaton<Digest = D, Context = Context<D, S::PublicKey>>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
    context: ContextCell<E>,

    // State initialization deferred to start/run
    scheme: S,
    elector: Option<L>, // Option because it's consumed during state init
    epoch: Epoch,

    blocker: B,
    automaton: A,
    relay: R,
    reporter: F,
    strategy: T,

    // Journal configuration
    partition: String,
    replay_buffer: NonZeroUsize,
    write_buffer: NonZeroUsize,
    page_cache: CacheRef,
    certificate_config: <S::Certificate as Read>::Cfg,

    // Journal for crash recovery (initialized during run)
    journal: Option<Journal<E, Artifact<S, D>>>,

    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    activity_timeout: ViewDelta,

    receiver: mpsc::Receiver<Message<S, D>>,

    outbound_messages: Family<Outbound, Counter>,
    m_notarization_latency: Histogram,
    finalization_latency: Histogram,
    recover_latency: histogram::Timed<E>,
    current_view: Gauge,
    skipped_views: Counter,

    /// Tracks when we started proposing for each view (as leader).
    /// Used for latency measurement.
    proposal_starts: BTreeMap<View, SystemTime>,
}

impl<E, S, L, B, D, A, R, F, T> Actor<E, S, L, B, D, A, R, F, T>
where
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: Automaton<Digest = D, Context = Context<D, S::PublicKey>>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
    /// Create a new voter actor.
    pub fn new(context: E, config: Config<S, L, B, D, A, R, F, T>) -> (Self, Mailbox<S, D>) {
        // Assert correctness of timeouts
        if config.leader_timeout > config.notarization_timeout {
            panic!("leader timeout must be less than or equal to notarization timeout");
        }

        // Initialize metrics
        let outbound_messages = Family::<Outbound, Counter>::default();
        let m_notarization_latency = Histogram::new(crate::LATENCY);
        let finalization_latency = Histogram::new(crate::LATENCY);
        let current_view = Gauge::<i64, AtomicI64>::default();
        let skipped_views = Counter::default();
        context.register(
            "outbound_messages",
            "number of outbound messages",
            outbound_messages.clone(),
        );
        context.register(
            "m_notarization_latency",
            "M-notarization latency",
            m_notarization_latency.clone(),
        );
        context.register(
            "finalization_latency",
            "finalization latency",
            finalization_latency.clone(),
        );
        let recover_latency = Histogram::new(Buckets::CRYPTOGRAPHY);
        context.register(
            "recover_latency",
            "certificate recover latency",
            recover_latency.clone(),
        );
        context.register("current_view", "current view", current_view.clone());
        context.register("skipped_views", "skipped views", skipped_views.clone());

        // TODO(#1833): Metrics should use the post-start context
        let clock = Arc::new(context.clone());
        let (sender, receiver) = mpsc::channel(config.mailbox_size);
        let mailbox = Mailbox::new(sender);
        (
            Self {
                context: ContextCell::new(context),

                scheme: config.scheme.clone(),
                elector: Some(config.elector),
                epoch: config.epoch,

                blocker: config.blocker,
                automaton: config.automaton,
                relay: config.relay,
                reporter: config.reporter,
                strategy: config.strategy,

                partition: config.partition,
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
                page_cache: config.page_cache,
                certificate_config: config.scheme.certificate_codec_config(),

                journal: None,

                leader_timeout: config.leader_timeout,
                notarization_timeout: config.notarization_timeout,
                nullify_retry: config.nullify_retry,
                activity_timeout: config.activity_timeout,

                receiver,

                outbound_messages,
                m_notarization_latency,
                finalization_latency,
                recover_latency: histogram::Timed::new(recover_latency, clock),
                current_view,
                skipped_views,

                proposal_starts: BTreeMap::new(),
            },
            mailbox,
        )
    }

    /// Start the voter actor.
    pub fn start(
        mut self,
        batcher_mailbox: batcher::Mailbox<S, D>,
        resolver_mailbox: resolver::Mailbox<S, D>,
        vote_sender: impl Sender<PublicKey = S::PublicKey>,
        certificate_sender: impl Sender<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            )
            .await
        )
    }

    /// Compute the next timeout deadline based on leader activity.
    fn next_timeout_deadline(&self, is_active: bool) -> SystemTime {
        let timeout = if is_active {
            self.notarization_timeout
        } else {
            self.leader_timeout
        };
        self.context.current() + timeout
    }

    /// Returns the elapsed wall-clock seconds for `view` when we are its leader.
    ///
    /// Only returns a value if we started proposing for this view (i.e., we are the leader).
    /// Used for unbiased latency measurement - only the leader sees the true end-to-end latency.
    fn leader_elapsed(&self, view: View) -> Option<f64> {
        let start = self.proposal_starts.get(&view)?;
        let now = self.context.current();
        now.duration_since(*start).ok().map(|d| d.as_secs_f64())
    }

    /// Prunes the journal to the given view floor.
    async fn prune_journal(&mut self, view: View) {
        if let Some(journal) = self.journal.as_mut() {
            journal
                .prune(view.get())
                .await
                .expect("unable to prune journal");
        }
    }

    /// Appends a verified artifact to the journal.
    async fn append_journal(&mut self, view: View, artifact: Artifact<S, D>) {
        if let Some(journal) = self.journal.as_mut() {
            journal
                .append(view.get(), artifact)
                .await
                .expect("unable to append to journal");
        }
    }

    /// Syncs the journal so other replicas can recover artifacts in `view`.
    async fn sync_journal(&mut self, view: View) {
        if let Some(journal) = self.journal.as_mut() {
            journal
                .sync(view.get())
                .await
                .expect("unable to sync journal");
        }
    }

    async fn run(
        mut self,
        mut batcher: batcher::Mailbox<S, D>,
        mut resolver: resolver::Mailbox<S, D>,
        vote_sender: impl Sender<PublicKey = S::PublicKey>,
        certificate_sender: impl Sender<PublicKey = S::PublicKey>,
    ) {
        // Get genesis from automaton (async)
        let genesis = self.automaton.clone().genesis(self.epoch).await;

        // Initialize state machine (take elector config, it's consumed by build)
        let elector_config = self
            .elector
            .take()
            .expect("elector should only be taken once during init");
        let elector = elector_config.build(self.scheme.participants());
        let mut state = State::new(self.epoch, self.scheme.clone(), elector, genesis);

        // Initialize journal for crash recovery
        let journal = Journal::<_, Artifact<S, D>>::init(
            self.context.with_label("journal").into_present(),
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

        // Replay from journal to rebuild state
        //
        // During replay, we update state and resolver but don't send votes to the batcher.
        // Votes were already sent before the crash, so the batcher doesn't need to track
        // them again. After replay:
        // - State knows we already voted/nullified (prevents double-voting)
        // - Resolver knows about certificates (for sync)
        // - Timeout will fire and re-broadcast our nullify if needed
        let start = self.context.current();
        let mut recovered_certificates = Vec::new();
        {
            let stream = journal
                .replay(0, 0, self.replay_buffer)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);
            while let Some(artifact) = stream.next().await {
                let (_, _, _, artifact) = artifact.expect("unable to replay journal");
                state
                    .replay(&artifact)
                    .expect("unable to replay artifact: wrong signer or corrupt journal");
                match artifact {
                    Artifact::Notarize(notarize) => {
                        self.reporter
                            .report(Activity::Notarize(notarize.clone()))
                            .await;
                        // Don't send to batcher - vote was already sent before crash
                    }
                    Artifact::MNotarization(m_notarization) => {
                        let view = m_notarization.view();
                        let recovered = m_notarization.clone();
                        resolver
                            .updated(Certificate::MNotarization(m_notarization.clone()))
                            .await;
                        self.reporter
                            .report(Activity::MNotarization(m_notarization))
                            .await;
                        recovered_certificates.push(Certificate::MNotarization(recovered));
                        // Notify batcher that M-quorum was reached for this view.
                        // This allows batching toward L-quorum after crash recovery.
                        batcher.m_notarization_exists(view).await;
                    }
                    Artifact::Nullify(nullify) => {
                        self.reporter
                            .report(Activity::Nullify(nullify.clone()))
                            .await;
                        // Don't send to batcher - vote was already sent before crash
                    }
                    Artifact::Nullification(nullification) => {
                        let recovered = nullification.clone();
                        resolver
                            .updated(Certificate::Nullification(nullification.clone()))
                            .await;
                        self.reporter
                            .report(Activity::Nullification(nullification))
                            .await;
                        recovered_certificates.push(Certificate::Nullification(recovered));
                    }
                    Artifact::Finalization(finalization) => {
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

        // Log replay completion
        let end = self.context.current();
        let elapsed = end.duration_since(start).unwrap_or_default();
        let observed_view = state.view();
        info!(
            current_view = %observed_view,
            ?elapsed,
            "consensus initialized from journal"
        );

        // Create egress for broadcasting
        let mut egress = Egress::new(
            vote_sender,
            certificate_sender,
            self.outbound_messages.clone(),
        );

        // Re-broadcast recovered certificates to guard against crashes that
        // happened after journaling but before network send.
        for certificate in recovered_certificates.drain(..) {
            egress.broadcast_certificate(certificate).await;
        }

        // Initialize view tracking
        let mut current_view = state.view();

        // Notify batcher of initial view
        let leader = state.leader(current_view, None);
        let finalized = state.last_finalized();
        let _is_active = batcher.update(current_view, leader, finalized).await;

        // Force immediate timeout after restart. It's very unlikely we restarted
        // within the original timeout window, so expire immediately and nullify.
        // This ensures nodes can make progress via nullifications even when all
        // nodes restart simultaneously at different views.
        let mut timeout_deadline = self.context.current();

        // Try to propose if we're leader
        if let Some(action) = state.try_propose() {
            self.execute_action(action, &mut state, &mut egress, &mut batcher, &mut resolver)
                .await;
        }

        // Re-broadcast our vote for current view after crash recovery.
        // This ensures nodes that voted (notarize or nullify) before crashing
        // contribute their votes to certificate building. Without this, nodes
        // with Phase::Voted cannot nullify via timeout (safety constraint) and
        // would be stuck if other nodes didn't receive their original vote.
        if let Some(vote) = state.our_vote_for_current_view() {
            match vote {
                Vote::Notarize(n) => {
                    debug!(view = %n.view(), "re-broadcasting notarize after recovery");
                    egress.broadcast_notarize(n).await;
                }
                Vote::Nullify(n) => {
                    debug!(view = %n.view(), "re-broadcasting nullify after recovery");
                    egress.broadcast_nullify(n).await;
                }
            }
        }

        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping voter");
                // Sync and close journal before shutdown
                if let Some(journal) = self.journal.take() {
                    journal.sync_all().await.expect("unable to sync journal");
                }
            },
            // Handle timeout
            _ = self.context.sleep_until(timeout_deadline) => {
                trace!(view = %state.view(), "timeout expired");
                let result = state.handle_timeout();

                // Handle nullify vote
                if let Some(nullify) = result.nullify {
                    if !result.is_retry {
                        // First timeout: journal, sync, send to batcher
                        self.append_journal(nullify.view(), Artifact::Nullify(nullify.clone()))
                            .await;
                        self.sync_journal(nullify.view()).await;
                        self.reporter
                            .report(Activity::Nullify(nullify.clone()))
                            .await;
                        batcher
                            .constructed(Vote::Nullify(nullify.clone()))
                            .await;

                        // Update skipped_views metric (view skipped due to timeout/nullification)
                        self.skipped_views.inc();
                    }
                    // Always broadcast (both first and retry)
                    debug!(view = %nullify.view(), retry = result.is_retry, "broadcasting nullify");
                    egress.broadcast_nullify(nullify).await;
                }

                // On retry, broadcast entry certificate to help lagging nodes
                if let Some(certificate) = result.entry_certificate {
                    debug!(view = %certificate.view(), "broadcasting entry certificate");
                    egress.broadcast_certificate(certificate).await;
                }

                // Reset timeout for retry
                timeout_deadline = self.context.current() + self.nullify_retry;
            },
            // Handle messages from batcher and resolver
            message = self.receiver.recv() => {
                let Some(message) = message else {
                    break;
                };

                let actions = match message {
                    Message::VerifiedNotarize(notarize) => {
                        // Time certificate construction (only record if certificate is built)
                        let mut timer = self.recover_latency.timer();
                        let actions = state.receive_verified_notarize(notarize, &self.strategy);
                        let has_certificate = actions.iter().any(|a| {
                            matches!(a, Action::BroadcastCertificate(_) | Action::Finalized(_))
                        });
                        if has_certificate {
                            timer.observe();
                        } else {
                            timer.cancel();
                        }
                        actions
                    }
                    Message::VerifiedNullify(nullify) => {
                        // Time certificate construction (only record if certificate is built)
                        let mut timer = self.recover_latency.timer();
                        let actions = state.receive_verified_nullify(nullify, &self.strategy);
                        let has_certificate = actions.iter().any(|a| {
                            matches!(a, Action::BroadcastCertificate(_))
                        });
                        if has_certificate {
                            timer.observe();
                        } else {
                            timer.cancel();
                        }
                        actions
                    }
                    Message::VerifiedCertificate(certificate) => {
                        state.receive_certificate(certificate)
                    }
                    Message::Proposal(proposal) => {
                        // Leader's proposal from batcher - request verification
                        let leader = state.leader(proposal.view(), None);
                        state.receive_proposal(leader, proposal)
                    }
                    Message::ResolvedCertificate(certificate) => {
                        state.receive_certificate(certificate)
                    }
                };

                for action in actions {
                    self.execute_action(action, &mut state, &mut egress, &mut batcher, &mut resolver)
                        .await;
                }
            },
            on_end => {
                // Check for view advancement
                let new_view = state.view();
                if new_view > current_view {
                    info!(old = %current_view, new = %new_view, "view advanced");
                    current_view = new_view;

                    // Update current_view metric
                    let _ = self.current_view.try_set(new_view.get());

                    // Update batcher with new view
                    let leader = state.leader(new_view, None);
                    let finalized = state.last_finalized();
                    let is_active = batcher.update(new_view, leader, finalized).await;

                    // Prune journal to keep only views within activity_timeout
                    let prune_floor = finalized.saturating_sub(self.activity_timeout);
                    self.prune_journal(prune_floor).await;

                    // Clean up old proposal start times
                    self.proposal_starts.retain(|v, _| *v >= prune_floor);

                    // Reset timeout based on leader activity
                    timeout_deadline = self.next_timeout_deadline(is_active);

                    // Try to propose if we're leader of the new view
                    if let Some(action) = state.try_propose() {
                        self.execute_action(
                            action,
                            &mut state,
                            &mut egress,
                            &mut batcher,
                            &mut resolver,
                        )
                        .await;
                    }
                }
            },
        }
    }

    /// Execute an action emitted by the state machine.
    async fn execute_action<V: Sender, C: Sender>(
        &mut self,
        action: Action<S, D>,
        state: &mut State<S, D, L::Elector>,
        egress: &mut Egress<S, D, V, C>,
        batcher: &mut batcher::Mailbox<S, D>,
        resolver: &mut resolver::Mailbox<S, D>,
    ) {
        match action {
            Action::Propose { context, view } => {
                debug!(%view, "requesting proposal from automaton");
                // Record proposal start time for latency measurement (we are the leader)
                self.proposal_starts.insert(view, self.context.current());
                let receiver = self.automaton.propose(context.clone()).await;
                // Wait for proposal (with timeout handled by automaton)
                if let Ok(payload) = receiver.await {
                    let proposal =
                        Proposal::new(context.round, context.parent.0, context.parent.1, payload);
                    let actions = state.proposed(proposal.clone());

                    // Only broadcast if we actually voted (view hasn't advanced)
                    // This avoids leaking stale proposals if the view changed while
                    // waiting for the automaton
                    if !actions.is_empty() {
                        self.relay.broadcast(proposal.payload).await;
                    }

                    for action in actions {
                        Box::pin(self.execute_action(action, state, egress, batcher, resolver))
                            .await;
                    }
                }
            }
            Action::VerifyProposal(proposal) => {
                debug!(view = %proposal.view(), "requesting proposal verification");
                // Build context for verification using the proposal's claimed parent
                let leader = state.leader(proposal.view(), None);
                let leader_key = state
                    .scheme()
                    .participants()
                    .get(leader.into())
                    .expect("leader must exist")
                    .clone();
                // Look up the parent payload based on the proposal's claimed parent view
                let parent = match state.parent_payload(&proposal) {
                    Some(p) => p,
                    None => {
                        // Invalid ancestry - reject the proposal
                        let actions = state.proposal_verified(proposal, false);
                        for action in actions {
                            Box::pin(self.execute_action(action, state, egress, batcher, resolver))
                                .await;
                        }
                        return;
                    }
                };
                let context = Context {
                    round: proposal.round,
                    leader: leader_key,
                    parent,
                };
                let receiver = self.automaton.verify(context, proposal.payload).await;
                // Wait for verification result
                if let Ok(valid) = receiver.await {
                    let actions = state.proposal_verified(proposal, valid);
                    for action in actions {
                        Box::pin(self.execute_action(action, state, egress, batcher, resolver))
                            .await;
                    }
                }
            }
            Action::BroadcastNotarize(notarize) => {
                debug!(view = %notarize.view(), "broadcasting notarize");
                // Persist to journal for crash recovery (before broadcast)
                self.append_journal(notarize.view(), Artifact::Notarize(notarize.clone()))
                    .await;
                self.sync_journal(notarize.view()).await;
                self.reporter
                    .report(Activity::Notarize(notarize.clone()))
                    .await;
                // Add to batcher for tracking
                batcher.constructed(Vote::Notarize(notarize.clone())).await;
                egress.broadcast_notarize(notarize).await;
            }
            Action::BroadcastNullify(nullify) => {
                debug!(view = %nullify.view(), "broadcasting nullify");
                // Persist to journal for crash recovery (before broadcast)
                self.append_journal(nullify.view(), Artifact::Nullify(nullify.clone()))
                    .await;
                self.sync_journal(nullify.view()).await;
                self.reporter
                    .report(Activity::Nullify(nullify.clone()))
                    .await;
                // Add to batcher for tracking
                batcher.constructed(Vote::Nullify(nullify.clone())).await;
                egress.broadcast_nullify(nullify).await;
            }
            Action::BroadcastCertificate(certificate) => {
                debug!(view = %certificate.view(), "broadcasting certificate");
                // Persist certificate to journal for crash recovery (before broadcast)
                let view = certificate.view();
                let artifact = match &certificate {
                    Certificate::MNotarization(m) => {
                        // Only the leader sees an unbiased latency sample, so record it now.
                        if let Some(elapsed) = self.leader_elapsed(view) {
                            self.m_notarization_latency.observe(elapsed);
                        }
                        self.reporter
                            .report(Activity::MNotarization(m.clone()))
                            .await;
                        // Notify batcher that M-quorum was reached for this view.
                        // This allows batching toward L-quorum.
                        batcher.m_notarization_exists(view).await;
                        Artifact::MNotarization(m.clone())
                    }
                    Certificate::Nullification(n) => {
                        self.reporter
                            .report(Activity::Nullification(n.clone()))
                            .await;
                        Artifact::Nullification(n.clone())
                    }
                    Certificate::Finalization(f) => {
                        // Only the leader sees an unbiased latency sample, so record it now.
                        if let Some(elapsed) = self.leader_elapsed(view) {
                            self.finalization_latency.observe(elapsed);
                        }
                        self.reporter
                            .report(Activity::Finalization(f.clone()))
                            .await;
                        Artifact::Finalization(f.clone())
                    }
                };
                self.append_journal(view, artifact).await;
                self.sync_journal(view).await;
                // Notify resolver of new certificate
                resolver.updated(certificate.clone()).await;
                egress.broadcast_certificate(certificate).await;
            }
            Action::Finalized(finalization) => {
                let view = finalization.view();
                info!(%view, "finalized");
                // Only the leader sees an unbiased latency sample, so record it now.
                if let Some(elapsed) = self.leader_elapsed(view) {
                    self.finalization_latency.observe(elapsed);
                }
                self.reporter
                    .report(Activity::Finalization(finalization.clone()))
                    .await;
                // Notify resolver so it can serve finalizations for catch-up.
                // Note: we don't broadcast finalizations (per the paper), but the resolver
                // needs to know about them to help lagging nodes.
                resolver
                    .updated(Certificate::Finalization(finalization))
                    .await;
            }
            Action::Advanced(view) => {
                trace!(%view, "view advanced (handled in main loop)");
                // View advancement is handled in the main loop
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{batcher, resolver, Actor, Config};
    use crate::{
        elector::RoundRobin,
        minimmit::{
            mocks::{application, reporter},
            scheme::ed25519,
            types::{Artifact, Certificate, MNotarization, Notarize, Proposal},
        },
        mocks::relay,
        types::{Epoch, Round, View, ViewDelta},
    };
    use bytes::Bytes;
    use commonware_codec::Read;
    use commonware_cryptography::{
        certificate::{mocks::Fixture, Scheme as CertificateScheme},
        ed25519::PublicKey as Ed25519PublicKey,
        sha256::Digest as Sha256Digest,
        PublicKey, Sha256,
    };
    use commonware_p2p::{Blocker, CheckedSender, LimitedSender, Recipients};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock, IoBufMut, Metrics, Runner, Spawner,
    };
    use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
    use commonware_utils::{channel::mpsc, test_rng, NZUsize, Participant, NZU16};
    use std::{
        convert::Infallible,
        marker::PhantomData,
        num::{NonZeroU16, NonZeroUsize},
        sync::{Arc, Mutex},
        time::{Duration, SystemTime},
    };

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    #[derive(Clone, Default)]
    struct NoopBlocker;

    impl Blocker for NoopBlocker {
        type PublicKey = Ed25519PublicKey;

        async fn block(&mut self, _peer: Self::PublicKey) {}
    }

    #[derive(Clone)]
    struct TestSender<P: PublicKey> {
        messages: Arc<Mutex<Vec<Vec<u8>>>>,
        _marker: PhantomData<P>,
    }

    impl<P: PublicKey> Default for TestSender<P> {
        fn default() -> Self {
            Self {
                messages: Arc::new(Mutex::new(Vec::new())),
                _marker: PhantomData,
            }
        }
    }

    impl<P: PublicKey> TestSender<P> {
        fn len(&self) -> usize {
            self.messages.lock().unwrap().len()
        }

        fn take(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.messages.lock().unwrap())
        }
    }

    struct TestChecked<P: PublicKey> {
        messages: Arc<Mutex<Vec<Vec<u8>>>>,
        _marker: PhantomData<P>,
    }

    impl<P: PublicKey> CheckedSender for TestChecked<P> {
        type PublicKey = P;
        type Error = Infallible;

        async fn send(
            self,
            message: impl Into<IoBufMut> + Send,
            _: bool,
        ) -> Result<Vec<P>, Infallible> {
            self.messages
                .lock()
                .unwrap()
                .push(message.into().as_ref().to_vec());
            Ok(Vec::new())
        }
    }

    impl<P: PublicKey> LimitedSender for TestSender<P> {
        type PublicKey = P;
        type Checked<'a>
            = TestChecked<P>
        where
            Self: 'a;

        async fn check<'a>(
            &'a mut self,
            _: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'a>, SystemTime> {
            Ok(TestChecked {
                messages: self.messages.clone(),
                _marker: PhantomData,
            })
        }
    }

    #[test]
    fn leader_timeout_used_when_inactive() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let mut rng = test_rng();
            let Fixture { schemes, .. } = ed25519::fixture(&mut rng, b"minimmit-timeout", 6);
            let scheme = schemes[0].clone();
            let participants = scheme.participants().clone();
            let me = participants
                .get(Participant::new(0).into())
                .expect("participant")
                .clone();

            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = reporter::Config {
                participants,
                scheme: scheme.clone(),
                elector: elector.clone(),
            };
            let reporter = reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            let relay = Arc::new(relay::Relay::new());
            let application_cfg = application::Config {
                hasher: Sha256::default(),
                relay,
                me,
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: application::Certifier::Always,
            };
            let (app_actor, application) =
                application::Application::new(context.with_label("app"), application_cfg);
            let _app_handle = app_actor.start();

            let leader_timeout = Duration::from_secs(3);
            let notarization_timeout = Duration::from_secs(5);
            let cfg = Config {
                scheme,
                elector,
                blocker: NoopBlocker,
                automaton: application.clone(),
                relay: application,
                reporter,
                strategy: Sequential,
                partition: "voter_timeout".to_string(),
                epoch: Epoch::new(1),
                mailbox_size: 16,
                leader_timeout,
                notarization_timeout,
                nullify_retry: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(3),
                replay_buffer: NZUsize!(1024),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            let actor_context = context.with_label("voter");
            let start = actor_context.current();
            let (actor, _mailbox) = Actor::new(actor_context, cfg);

            let inactive_deadline = actor.next_timeout_deadline(false);
            let active_deadline = actor.next_timeout_deadline(true);
            assert_eq!(
                inactive_deadline.duration_since(start).unwrap(),
                leader_timeout
            );
            assert_eq!(
                active_deadline.duration_since(start).unwrap(),
                notarization_timeout
            );
        });
    }

    #[test]
    fn rebroadcasts_replayed_certificates() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let mut rng = test_rng();
            let Fixture { schemes, .. } = ed25519::fixture(&mut rng, b"minimmit-rebroadcast", 6);
            let scheme = schemes[0].clone();
            let participants = scheme.participants().clone();
            let me = participants
                .get(Participant::new(0).into())
                .expect("participant")
                .clone();

            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = reporter::Config {
                participants: participants.clone(),
                scheme: scheme.clone(),
                elector: elector.clone(),
            };
            let reporter = reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            let relay = Arc::new(relay::Relay::new());
            let application_cfg = application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: application::Certifier::Always,
            };
            let (app_actor, application) =
                application::Application::new(context.with_label("app"), application_cfg);
            let _app_handle = app_actor.start();

            let partition = "voter_rebroadcast".to_string();
            let mut journal = Journal::<_, Artifact<ed25519::Scheme, Sha256Digest>>::init(
                context.with_label("journal"),
                JConfig {
                    partition: partition.clone(),
                    compression: None,
                    codec_config: scheme.certificate_codec_config(),
                    page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    write_buffer: NZUsize!(1024 * 1024),
                },
            )
            .await
            .expect("journal init");

            let view = View::new(1);
            let proposal = Proposal::new(
                Round::new(Epoch::new(1), view),
                View::zero(),
                Sha256Digest::from([0u8; 32]),
                Sha256Digest::from([1u8; 32]),
            );
            let votes: Vec<_> = schemes
                .iter()
                .take(3)
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
                .collect();
            let m_notarization = MNotarization::from_notarizes(&scheme, votes.iter(), &Sequential)
                .expect("m-notarization");
            journal
                .append(view.get(), Artifact::MNotarization(m_notarization.clone()))
                .await
                .expect("append");
            journal.sync_all().await.expect("sync");
            drop(journal);

            let cfg = Config {
                scheme: scheme.clone(),
                elector,
                blocker: NoopBlocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                strategy: Sequential,
                partition,
                epoch: Epoch::new(1),
                mailbox_size: 16,
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(3),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            let (actor, _mailbox) = Actor::new(context.with_label("voter"), cfg);
            let (batcher_sender, _batcher_receiver) = mpsc::channel(8);
            let (resolver_sender, _resolver_receiver) = mpsc::channel(8);
            let vote_sender = TestSender::<Ed25519PublicKey>::default();
            let certificate_sender = TestSender::<Ed25519PublicKey>::default();

            actor.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                certificate_sender.clone(),
            );

            for _ in 0..5 {
                if certificate_sender.len() > 0 {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            let messages = certificate_sender.take();
            assert!(
                !messages.is_empty(),
                "expected replayed certificate broadcast"
            );

            let mut buf = Bytes::from(messages[0].clone());
            let decoded = Certificate::<ed25519::Scheme, Sha256Digest>::read_cfg(
                &mut buf,
                &scheme.certificate_codec_config(),
            )
            .expect("decode certificate");
            match decoded {
                Certificate::MNotarization(m_not) => {
                    assert_eq!(m_not.proposal.payload, proposal.payload);
                }
                _ => panic!("expected m-notarization"),
            }

            context.stop(0, None).await.expect("stop");
        });
    }
}
