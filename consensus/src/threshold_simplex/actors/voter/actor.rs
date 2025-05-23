use super::{Config, Mailbox, Message};
use crate::{
    threshold_simplex::{
        actors::{batcher, resolver},
        interesting,
        metrics::{self, Inbound, Outbound},
        min_active,
        types::{
            Activity, Attributable, Context, Finalization, Finalize, Notarization, Notarize,
            Nullification, Nullify, Proposal, View, Viewable, Voter,
        },
    },
    Automaton, Relay, Reporter, ThresholdSupervisor, LATENCY,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops::{threshold_signature_recover, threshold_signature_recover_pair},
        variant::Variant,
    },
    Digest, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    telemetry::metrics::histogram::{self, Buckets},
    Clock, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::variable::{Config as JConfig, Journal};
use commonware_utils::quorum;
use core::panic;
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    pin_mut, StreamExt,
};
use prometheus_client::metrics::{
    counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
};
use rand::Rng;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};
use std::{
    sync::{atomic::AtomicI64, Arc},
    time::Instant,
};
use tracing::{debug, info, trace, warn};

const GENESIS_VIEW: View = 0;

/// Compute the quorum for a given polynomial.
fn polynomial_quorum<P>(polynomial: &[P]) -> u32 {
    let n = polynomial.len() as u32;
    quorum(n)
}

/// Action to take after processing a message.
enum Action {
    /// Skip processing the message.
    Skip,
    /// Block the peer from sending any more messages.
    Block,
    /// Process the message.
    Process,
}

struct Round<
    E: Clock,
    C: Scheme,
    V: Variant,
    D: Digest,
    S: ThresholdSupervisor<
        Index = View,
        PublicKey = C::PublicKey,
        Identity = V::Public,
        Seed = V::Signature,
        Share = group::Share,
    >,
> {
    start: SystemTime,
    supervisor: S,

    view: View,
    quorum: u32,

    // Leader is set as soon as we know the seed for the view.
    leader: Option<(C::PublicKey, u32)>,

    // We explicitly distinguish between the proposal being verified (we checked it)
    // and the proposal being recovered (network has determined its validity). As a sanity
    // check, we'll never notarize or finalize a proposal that we did not verify.
    //
    // We will, however, construct a notarization or finalization (if we have enough partial
    // signatures of either) even if we did not verify the proposal.
    requested_proposal_build: bool,
    requested_proposal_verify: bool,
    verified_proposal: bool,

    proposal: Option<Proposal<D>>,

    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,

    // We only receive verified notarizes for the leader's proposal, so we don't
    // need to track multiple proposals here.
    notarizes: Vec<Notarize<V, D>>,
    notarization: Option<Notarization<V, D>>,
    broadcast_notarize: bool,
    broadcast_notarization: bool,

    // Track nullifies (ensuring any participant only has one recorded nullify)
    nullifies: Vec<Nullify<V>>,
    nullification: Option<Nullification<V>>,
    broadcast_nullify: bool,
    broadcast_nullification: bool,

    // We only receive verified finalizes for the leader's proposal, so we don't
    // need to track multiple proposals here.
    finalizes: Vec<Finalize<V, D>>,
    finalization: Option<Finalization<V, D>>,
    broadcast_finalize: bool,
    broadcast_finalization: bool,

    recover_latency: histogram::Timed<E>,
}

impl<
        E: Clock,
        C: Scheme,
        V: Variant,
        D: Digest,
        S: ThresholdSupervisor<
            Seed = V::Signature,
            Index = View,
            Share = group::Share,
            PublicKey = C::PublicKey,
            Identity = V::Public,
        >,
    > Round<E, C, V, D, S>
{
    pub fn new(
        context: &E,
        supervisor: S,
        recover_latency: histogram::Timed<E>,
        view: View,
    ) -> Self {
        let participants = supervisor.participants(view).unwrap().len();
        let quorum = quorum(participants as u32);
        Self {
            start: context.current(),
            supervisor,

            view,
            quorum,

            leader: None,

            requested_proposal_build: false,
            requested_proposal_verify: false,
            verified_proposal: false,

            proposal: None,

            leader_deadline: None,
            advance_deadline: None,
            nullify_retry: None,

            notarizes: Vec::with_capacity(participants),
            notarization: None,
            broadcast_notarize: false,
            broadcast_notarization: false,

            nullifies: Vec::with_capacity(participants),
            nullification: None,
            broadcast_nullify: false,
            broadcast_nullification: false,

            finalizes: Vec::with_capacity(participants),
            finalization: None,
            broadcast_finalize: false,
            broadcast_finalization: false,

            recover_latency,
        }
    }

    pub fn set_leader(&mut self, seed: V::Signature) {
        let leader = ThresholdSupervisor::leader(&self.supervisor, self.view, seed).unwrap();
        let leader_index = self.supervisor.is_participant(self.view, &leader).unwrap();
        self.leader = Some((leader, leader_index));
    }

    fn add_recovered_proposal(&mut self, proposal: Proposal<D>) {
        if self.proposal.is_none() {
            debug!(?proposal, "setting verified proposal");
            self.proposal = Some(proposal);
        } else if let Some(previous) = &self.proposal {
            assert_eq!(proposal, *previous);
        }
    }

    async fn add_verified_notarize(&mut self, notarize: Notarize<V, D>) {
        if self.proposal.is_none() {
            self.proposal = Some(notarize.proposal.clone());
        }
        self.notarizes.push(notarize);
    }

    async fn add_verified_nullify(&mut self, nullify: Nullify<V>) {
        // We don't consider a nullify vote as being active.
        self.nullifies.push(nullify);
    }

    async fn add_verified_finalize(&mut self, finalize: Finalize<V, D>) {
        if self.proposal.is_none() {
            self.proposal = Some(finalize.proposal.clone());
        }
        self.finalizes.push(finalize);
    }

    fn add_verified_notarization(&mut self, notarization: Notarization<V, D>) -> bool {
        // If already have notarization, ignore
        if self.notarization.is_some() {
            return false;
        }

        // Clear leader and advance deadlines (if they exist)
        self.leader_deadline = None;
        self.advance_deadline = None;

        // If proposal is missing, set it
        self.add_recovered_proposal(notarization.proposal.clone());

        // Store the notarization
        self.notarization = Some(notarization);
        true
    }

    fn add_verified_nullification(&mut self, nullification: Nullification<V>) -> bool {
        // If already have nullification, ignore
        if self.nullification.is_some() {
            return false;
        }

        // Clear leader and advance deadlines (if they exist)
        self.leader_deadline = None;
        self.advance_deadline = None;

        // Store the nullification
        self.nullification = Some(nullification);
        true
    }

    fn add_verified_finalization(&mut self, finalization: Finalization<V, D>) -> bool {
        // If already have finalization, ignore
        if self.finalization.is_some() {
            return false;
        }

        // Clear leader and advance deadlines (if they exist)
        self.leader_deadline = None;
        self.advance_deadline = None;

        // If proposal is missing, set it
        self.add_recovered_proposal(finalization.proposal.clone());

        // Store the finalization
        self.finalization = Some(finalization);
        true
    }

    async fn notarizable(&mut self, threshold: u32, force: bool) -> Option<Notarization<V, D>> {
        // Ensure we haven't already broadcast
        if !force && (self.broadcast_notarization || self.broadcast_nullification) {
            // We want to broadcast a notarization, even if we haven't yet verified a proposal.
            return None;
        }

        // If already constructed, return
        if let Some(notarization) = &self.notarization {
            self.broadcast_notarization = true;
            return Some(notarization.clone());
        }

        // Attempt to construct notarization
        if self.notarizes.len() < threshold as usize {
            return None;
        }
        let proposal = self.proposal.as_ref().unwrap().clone();
        debug!(
            ?proposal,
            verified = self.verified_proposal,
            "broadcasting notarization"
        );

        // Recover threshold signature
        let mut timer = self.recover_latency.timer();
        let (proposals, seeds): (Vec<_>, Vec<_>) = self
            .notarizes
            .iter()
            .map(|notarize| (&notarize.proposal_signature, &notarize.seed_signature))
            .unzip();
        let (proposal_signature, seed_signature) =
            threshold_signature_recover_pair::<V, _>(threshold, proposals, seeds)
                .expect("failed to recover threshold signature");
        timer.observe();

        // Construct notarization
        let notarization = Notarization::new(proposal, proposal_signature, seed_signature);
        self.broadcast_notarization = true;
        Some(notarization)
    }

    async fn nullifiable(&mut self, threshold: u32, force: bool) -> Option<Nullification<V>> {
        // Ensure we haven't already broadcast
        if !force && (self.broadcast_nullification || self.broadcast_notarization) {
            return None;
        }

        // If already constructed, return
        if let Some(nullification) = &self.nullification {
            self.broadcast_nullification = true;
            return Some(nullification.clone());
        }

        // Attempt to construct nullification
        if self.nullifies.len() < threshold as usize {
            return None;
        }
        debug!(view = self.view, "broadcasting nullification");

        // Recover threshold signature
        let mut timer = self.recover_latency.timer();
        let (views, seeds): (Vec<_>, Vec<_>) = self
            .nullifies
            .iter()
            .map(|nullify| (&nullify.view_signature, &nullify.seed_signature))
            .unzip();
        let (view_signature, seed_signature) =
            threshold_signature_recover_pair::<V, _>(threshold, views, seeds)
                .expect("failed to recover threshold signature");
        timer.observe();

        // Construct nullification
        let nullification = Nullification::new(self.view, view_signature, seed_signature);
        self.broadcast_nullification = true;
        Some(nullification)
    }

    async fn finalizable(&mut self, threshold: u32, force: bool) -> Option<Finalization<V, D>> {
        // Ensure we haven't already broadcast
        if !force && self.broadcast_finalization {
            // We want to broadcast a finalization, even if we haven't yet verified a proposal.
            return None;
        }

        // If already constructed, return
        if let Some(finalization) = &self.finalization {
            self.broadcast_finalization = true;
            return Some(finalization.clone());
        }

        // Attempt to construct finalization
        if self.finalizes.len() < threshold as usize {
            return None;
        }
        let proposal = self.proposal.as_ref().unwrap().clone();

        // Ensure we have a notarization
        let Some(notarization) = &self.notarization else {
            return None;
        };
        let seed_signature = notarization.seed_signature;

        // Check notarization and finalization proposal match
        if notarization.proposal != proposal {
            warn!(
                ?proposal,
                ?notarization.proposal,
                "finalization proposal does not match notarization"
            );
        }

        // There should never exist enough finalizes for multiple proposals, so it doesn't
        // matter which one we choose.
        debug!(
            ?proposal,
            verified = self.verified_proposal,
            "broadcasting finalization"
        );

        // Only select verified finalizes
        let proposals = self
            .finalizes
            .iter()
            .map(|finalize| &finalize.proposal_signature);

        // Recover threshold signature
        let mut timer = self.recover_latency.timer();
        let proposal_signature = threshold_signature_recover::<V, _>(threshold, proposals)
            .expect("failed to recover threshold signature");
        timer.observe();

        // Construct finalization
        let finalization = Finalization::new(proposal.clone(), proposal_signature, seed_signature);
        self.broadcast_finalization = true;
        Some(finalization)
    }

    /// Returns whether at least one honest participant has notarized a proposal.
    pub fn at_least_one_honest(&self) -> Option<View> {
        let at_least_one_honest = (self.quorum - 1) / 2 + 1;
        if self.notarizes.len() < at_least_one_honest as usize {
            return None;
        }
        let proposal = self.proposal.as_ref().unwrap().clone();
        Some(proposal.parent)
    }
}

pub struct Actor<
    E: Clock + Rng + Spawner + Storage + Metrics,
    C: Scheme,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    D: Digest,
    A: Automaton<Digest = D, Context = Context<D>>,
    R: Relay,
    F: Reporter<Activity = Activity<V, D>>,
    S: ThresholdSupervisor<
        Index = View,
        PublicKey = C::PublicKey,
        Identity = V::Public,
        Seed = V::Signature,
        Polynomial = Vec<V::Public>,
        Share = group::Share,
    >,
> {
    context: E,
    crypto: C,
    blocker: B,
    automaton: A,
    relay: R,
    reporter: F,
    supervisor: S,

    partition: String,
    compression: Option<u8>,
    replay_concurrency: usize,
    replay_buffer: usize,
    write_buffer: usize,
    journal: Option<Journal<E, Voter<V, D>>>,

    genesis: Option<D>,

    namespace: Vec<u8>,

    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    activity_timeout: View,

    mailbox_receiver: mpsc::Receiver<Message<V, D>>,

    view: View,
    views: BTreeMap<View, Round<E, C, V, D, S>>,
    last_finalized: View,

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
        E: Clock + Rng + Spawner + Storage + Metrics,
        C: Scheme,
        B: Blocker<PublicKey = C::PublicKey>,
        V: Variant,
        D: Digest,
        A: Automaton<Digest = D, Context = Context<D>>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<V, D>>,
        S: ThresholdSupervisor<
            Index = View,
            PublicKey = C::PublicKey,
            Identity = V::Public,
            Seed = V::Signature,
            Polynomial = Vec<V::Public>,
            Share = group::Share,
        >,
    > Actor<E, C, B, V, D, A, R, F, S>
{
    pub fn new(context: E, cfg: Config<C, B, V, D, A, R, F, S>) -> (Self, Mailbox<V, D>) {
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
            "threshold signature recover latency",
            recover_latency.clone(),
        );

        // Initialize store
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        (
            Self {
                context: context.clone(),
                crypto: cfg.crypto,
                blocker: cfg.blocker,
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,
                supervisor: cfg.supervisor,

                partition: cfg.partition,
                compression: cfg.compression,
                replay_concurrency: cfg.replay_concurrency,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                journal: None,

                genesis: None,

                namespace: cfg.namespace,

                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,

                activity_timeout: cfg.activity_timeout,

                mailbox_receiver,

                last_finalized: 0,
                view: 0,
                views: BTreeMap::new(),

                current_view,
                tracked_views,
                skipped_views,
                inbound_messages,
                outbound_messages,
                notarization_latency,
                finalization_latency,
                recover_latency: histogram::Timed::new(recover_latency, Arc::new(context)),
            },
            mailbox,
        )
    }

    fn is_notarized(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(notarization) = &round.notarization {
            return Some(&notarization.proposal.payload);
        }
        let proposal = round.proposal.as_ref()?;
        let polynomial = self.supervisor.polynomial(view)?;
        let threshold = polynomial_quorum(polynomial);
        if round.notarizes.len() >= threshold as usize {
            return Some(&proposal.payload);
        }
        None
    }

    fn is_nullified(&self, view: View) -> bool {
        let round = match self.views.get(&view) {
            Some(round) => round,
            None => return false,
        };
        let polynomial = match self.supervisor.polynomial(view) {
            Some(polynomial) => polynomial,
            None => return false,
        };
        let threshold = polynomial_quorum(polynomial);
        round.nullification.is_some() || round.nullifies.len() >= threshold as usize
    }

    fn is_finalized(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(finalization) = &round.finalization {
            return Some(&finalization.proposal.payload);
        }
        let proposal = round.proposal.as_ref()?;
        let polynomial = self.supervisor.polynomial(view)?;
        let threshold = polynomial_quorum(polynomial);
        if round.finalizes.len() >= threshold as usize {
            return Some(&proposal.payload);
        }
        None
    }

    fn find_parent(&self) -> Result<(View, D), View> {
        let mut cursor = self.view - 1; // self.view always at least 1
        loop {
            if cursor == 0 {
                return Ok((GENESIS_VIEW, *self.genesis.as_ref().unwrap()));
            }

            // If have notarization, return
            let parent = self.is_notarized(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, *parent));
            }

            // If have finalization, return
            //
            // We never want to build on some view less than finalized and this prevents that
            let parent = self.is_finalized(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, *parent));
            }

            // If have nullification, continue
            if self.is_nullified(cursor) {
                cursor -= 1;
                continue;
            }

            // We can't find a valid parent, return
            return Err(cursor);
        }
    }

    fn missing_nullifications(&self, parent: View) -> Vec<View> {
        let mut missing = Vec::new();
        for view in (parent + 1)..self.view {
            if !self.is_nullified(view) {
                missing.push(view);
            }
        }
        missing
    }

    #[allow(clippy::question_mark)]
    async fn propose(
        &mut self,
        resolver: &mut resolver::Mailbox<V, D>,
    ) -> Option<(Context<D>, oneshot::Receiver<D>)> {
        // Check if we are leader
        {
            let round = self.views.get_mut(&self.view).unwrap();
            let Some((leader, _)) = &round.leader else {
                return None;
            };
            if *leader != self.crypto.public_key() {
                return None;
            }

            // Check if we have already requested a proposal
            if round.requested_proposal_build {
                return None;
            }

            // Check if we have already proposed
            if round.proposal.is_some() {
                return None;
            }

            // Set that we requested a proposal even if we don't end up finding a parent
            // to prevent frequent scans.
            round.requested_proposal_build = true;
        }

        // Find best parent
        let (parent_view, parent_payload) = match self.find_parent() {
            Ok(parent) => parent,
            Err(view) => {
                debug!(
                    view = self.view,
                    missing = view,
                    "skipping proposal opportunity"
                );
                resolver.fetch(vec![view], vec![view]).await;
                return None;
            }
        };

        // Request proposal from application
        debug!(view = self.view, "requested proposal from automaton");
        let context = Context {
            view: self.view,
            parent: (parent_view, parent_payload),
        };
        Some((context.clone(), self.automaton.propose(context).await))
    }

    fn timeout_deadline(&mut self) -> SystemTime {
        // Return the earliest deadline
        let view = self.views.get_mut(&self.view).unwrap();
        if let Some(deadline) = view.leader_deadline {
            return deadline;
        }
        if let Some(deadline) = view.advance_deadline {
            return deadline;
        }

        // If no deadlines are still set (waiting for nullify),
        // return next try for nullify.
        if let Some(deadline) = view.nullify_retry {
            return deadline;
        }

        // Set nullify retry, if none already set
        let null_retry = self.context.current() + self.nullify_retry;
        view.nullify_retry = Some(null_retry);
        null_retry
    }

    async fn timeout<Sp: Sender, Sr: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<C::PublicKey, V, D>,
        pending_sender: &mut WrappedSender<Sp, Voter<V, D>>,
        recovered_sender: &mut WrappedSender<Sr, Voter<V, D>>,
    ) {
        // Set timeout fired
        let round = self.views.get_mut(&self.view).unwrap();
        let mut retry = false;
        if round.broadcast_nullify {
            retry = true;
        }
        round.broadcast_nullify = true;

        // Remove deadlines
        round.leader_deadline = None;
        round.advance_deadline = None;
        round.nullify_retry = None;

        // If retry, broadcast notarization that led us to enter this view
        let past_view = self.view - 1;
        if retry && past_view > 0 {
            if let Some(notarization) = self.construct_notarization(past_view, true).await {
                self.outbound_messages
                    .get_or_create(&metrics::NOTARIZATION)
                    .inc();
                let msg = Voter::Notarization(notarization);
                recovered_sender
                    .send(Recipients::All, msg, true)
                    .await
                    .unwrap();
                debug!(view = past_view, "rebroadcast entry notarization");
            } else if let Some(nullification) = self.construct_nullification(past_view, true).await
            {
                self.outbound_messages
                    .get_or_create(&metrics::NULLIFICATION)
                    .inc();
                let msg = Voter::Nullification(nullification);
                recovered_sender
                    .send(Recipients::All, msg, true)
                    .await
                    .unwrap();
                debug!(view = past_view, "rebroadcast entry nullification");
            } else {
                warn!(
                    view = past_view,
                    "unable to rebroadcast entry notarization/nullification"
                );
            }
        }

        // Construct nullify
        let share = self.supervisor.share(self.view).unwrap();
        let nullify = Nullify::sign(&self.namespace, share, self.view);

        // Handle the nullify
        if !retry {
            batcher.constructed(Voter::Nullify(nullify.clone())).await;
            self.handle_nullify(nullify.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(self.view)
                .await
                .expect("unable to sync journal");
        }

        // Broadcast nullify
        self.outbound_messages
            .get_or_create(&metrics::NULLIFY)
            .inc();
        let msg = Voter::Nullify(nullify);
        pending_sender
            .send(Recipients::All, msg, true)
            .await
            .unwrap();
        debug!(view = self.view, "broadcasted nullify");
    }

    async fn handle_nullify(&mut self, nullify: Nullify<V>) {
        // Check to see if nullify is for proposal in view
        let view = nullify.view;
        let round = self.views.entry(view).or_insert(Round::new(
            &self.context,
            self.supervisor.clone(),
            self.recover_latency.clone(),
            view,
        ));

        // Handle nullify
        if self.journal.is_some() {
            let msg = Voter::Nullify(nullify.clone());
            self.journal
                .as_mut()
                .unwrap()
                .append(view, msg)
                .await
                .expect("unable to append nullify");
        }
        round.add_verified_nullify(nullify).await
    }

    async fn our_proposal(&mut self, proposal: Proposal<D>) -> bool {
        // Store the proposal
        let round = self.views.get_mut(&proposal.view).expect("view missing");

        // Check if view timed out
        if round.broadcast_nullify {
            debug!(
                ?proposal,
                reason = "view timed out",
                "dropping our proposal"
            );
            return false;
        }

        // Store the proposal
        debug!(?proposal, "generated proposal");
        assert!(round.proposal.is_none());
        round.proposal = Some(proposal);
        round.requested_proposal_verify = true;
        round.verified_proposal = true;
        round.leader_deadline = None;
        true
    }

    // Attempt to set proposal from each message received over the wire
    #[allow(clippy::question_mark)]
    async fn peer_proposal(&mut self) -> Option<(Context<D>, oneshot::Receiver<bool>)> {
        // Get round
        let proposal = {
            // Get view or exit
            let round = self.views.get(&self.view)?;

            // If we are the leader, drop peer proposals
            let Some((leader, _)) = &round.leader else {
                debug!(
                    view = self.view,
                    "dropping peer proposal because leader is not set"
                );
                return None;
            };
            if *leader == self.crypto.public_key() {
                return None;
            }

            // If we already broadcast nullify or set proposal, do nothing
            if round.broadcast_nullify {
                return None;
            }
            if round.requested_proposal_verify {
                return None;
            }

            // Check if leader has signed a digest
            let Some(ref proposal) = round.proposal else {
                return None;
            };

            // Check parent validity
            if proposal.view <= proposal.parent {
                debug!(
                    view = proposal.view,
                    parent = proposal.parent,
                    "dropping peer proposal because parent is invalid"
                );
                return None;
            }
            if proposal.parent < self.last_finalized {
                debug!(
                    view = proposal.view,
                    parent = proposal.parent,
                    last_finalized = self.last_finalized,
                    "dropping peer proposal because parent is less than last finalized"
                );
                return None;
            }
            proposal
        };

        // Ensure we have required notarizations
        let mut cursor = match self.view {
            0 => {
                return None;
            }
            _ => self.view - 1,
        };
        let parent_payload = loop {
            if cursor == proposal.parent {
                // Check if first block
                if proposal.parent == GENESIS_VIEW {
                    break self.genesis.as_ref().unwrap();
                }

                // Check notarization exists
                let parent_proposal = match self.is_notarized(cursor) {
                    Some(parent) => parent,
                    None => {
                        debug!(view = cursor, "parent proposal is not notarized");
                        return None;
                    }
                };

                // Peer proposal references a valid parent
                break parent_proposal;
            }

            // Check nullification exists in gap
            if !self.is_nullified(cursor) {
                debug!(
                    view = cursor,
                    "missing nullification during proposal verification"
                );
                return None;
            }
            cursor -= 1;
        };

        // Request verification
        debug!(?proposal, "requested proposal verification",);
        let context = Context {
            view: proposal.view,
            parent: (proposal.parent, *parent_payload),
        };
        let proposal = proposal.clone();
        let payload = proposal.payload;
        let round = self.views.get_mut(&context.view).unwrap();
        round.requested_proposal_verify = true;
        Some((
            context.clone(),
            self.automaton.verify(context, payload).await,
        ))
    }

    async fn verified(&mut self, view: View) -> bool {
        // Check if view still relevant
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                debug!(view, reason = "view missing", "dropping verified proposal");
                return false;
            }
        };

        // Ensure we haven't timed out
        if round.broadcast_nullify {
            debug!(
                view,
                reason = "view timed out",
                "dropping verified proposal"
            );
            return false;
        }

        // Mark proposal as verified
        round.leader_deadline = None;
        round.verified_proposal = true;

        // Indicate that verification is done
        debug!(view, "verified proposal");
        true
    }

    fn since_view_start(&self, view: u64) -> Option<(bool, f64)> {
        let round = self.views.get(&view)?;
        let (leader, _) = round.leader.as_ref()?;
        let Ok(elapsed) = self.context.current().duration_since(round.start) else {
            return None;
        };
        Some((*leader == self.crypto.public_key(), elapsed.as_secs_f64()))
    }

    fn enter_view(&mut self, view: u64, seed: V::Signature) {
        // Ensure view is valid
        if view <= self.view {
            trace!(
                view = view,
                our_view = self.view,
                "skipping useless view change"
            );
            return;
        }

        // Setup new view
        let round = self.views.entry(view).or_insert(Round::new(
            &self.context,
            self.supervisor.clone(),
            self.recover_latency.clone(),
            view,
        ));
        round.leader_deadline = Some(self.context.current() + self.leader_timeout);
        round.advance_deadline = Some(self.context.current() + self.notarization_timeout);
        round.set_leader(seed);
        self.view = view;

        // Update metrics
        self.current_view.set(view as i64);
    }

    async fn prune_views(&mut self) {
        // Get last min
        let min = min_active(self.activity_timeout, self.last_finalized);
        let mut pruned = false;
        loop {
            // Get next key
            let next = match self.views.keys().next() {
                Some(next) => *next,
                None => return,
            };

            // If less than min, prune
            if next >= min {
                break;
            }
            self.views.remove(&next);
            debug!(
                view = next,
                last_finalized = self.last_finalized,
                "pruned view"
            );
            pruned = true;
        }

        // Prune journal up to min
        if pruned {
            self.journal
                .as_mut()
                .unwrap()
                .prune(min)
                .await
                .expect("unable to prune journal");
        }

        // Update metrics
        self.tracked_views.set(self.views.len() as i64);
    }

    async fn handle_notarize(&mut self, notarize: Notarize<V, D>) {
        // Check to see if notarize is for proposal in view
        let view = notarize.view();
        let round = self.views.entry(view).or_insert(Round::new(
            &self.context,
            self.supervisor.clone(),
            self.recover_latency.clone(),
            view,
        ));

        // Handle notarize
        if self.journal.is_some() {
            let msg = Voter::Notarize(notarize.clone());
            self.journal
                .as_mut()
                .unwrap()
                .append(view, msg)
                .await
                .expect("unable to append to journal");
        }
        round.add_verified_notarize(notarize).await;
    }

    async fn notarization(&mut self, notarization: Notarization<V, D>) -> Action {
        // Check if we are still in a view where this notarization could help
        let view = notarization.view();
        if !interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            view,
            true,
        ) {
            return Action::Skip;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&view) {
            if round.broadcast_notarization {
                return Action::Skip;
            }
        }

        // Verify notarization
        let identity = self.supervisor.identity();
        if !notarization.verify(&self.namespace, identity) {
            return Action::Block;
        }

        // Handle notarization
        self.handle_notarization(notarization).await;
        Action::Process
    }

    async fn handle_notarization(&mut self, notarization: Notarization<V, D>) {
        // Create round (if it doesn't exist)
        let view = notarization.view();
        let round = self.views.entry(view).or_insert(Round::new(
            &self.context,
            self.supervisor.clone(),
            self.recover_latency.clone(),
            view,
        ));

        // Store notarization
        let msg = Voter::Notarization(notarization.clone());
        let seed = notarization.seed_signature;
        if round.add_verified_notarization(notarization) && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, msg)
                .await
                .expect("unable to append to journal");
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn nullification(&mut self, nullification: Nullification<V>) -> Action {
        // Check if we are still in a view where this notarization could help
        if !interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            nullification.view,
            true,
        ) {
            return Action::Skip;
        }

        // Determine if we already broadcast nullification for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&nullification.view) {
            if round.broadcast_nullification {
                return Action::Skip;
            }
        }

        // Verify nullification
        let identity = self.supervisor.identity();
        if !nullification.verify(&self.namespace, identity) {
            return Action::Block;
        }

        // Handle notarization
        self.handle_nullification(nullification).await;
        Action::Process
    }

    async fn handle_nullification(&mut self, nullification: Nullification<V>) {
        // Create round (if it doesn't exist)
        let view = nullification.view;
        let round = self.views.entry(view).or_insert(Round::new(
            &self.context,
            self.supervisor.clone(),
            self.recover_latency.clone(),
            nullification.view,
        ));

        // Store nullification
        let msg = Voter::Nullification(nullification.clone());
        let seed = nullification.seed_signature;
        if round.add_verified_nullification(nullification) && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, msg)
                .await
                .expect("unable to append to journal");
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn handle_finalize(&mut self, finalize: Finalize<V, D>) {
        // Get view for finalize
        let view = finalize.view();
        let round = self.views.entry(view).or_insert(Round::new(
            &self.context,
            self.supervisor.clone(),
            self.recover_latency.clone(),
            view,
        ));

        // Handle finalize
        if self.journal.is_some() {
            let msg = Voter::Finalize(finalize.clone());
            self.journal
                .as_mut()
                .unwrap()
                .append(view, msg)
                .await
                .expect("unable to append to journal");
        }
        round.add_verified_finalize(finalize).await
    }

    async fn finalization(&mut self, finalization: Finalization<V, D>) -> Action {
        // Check if we are still in a view where this finalization could help
        let view = finalization.view();
        if !interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            view,
            true,
        ) {
            return Action::Skip;
        }

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&view) {
            if round.broadcast_finalization {
                return Action::Skip;
            }
        }

        // Verify finalization
        let identity = self.supervisor.identity();
        if !finalization.verify(&self.namespace, identity) {
            return Action::Block;
        }

        // Process finalization
        self.handle_finalization(finalization).await;
        Action::Process
    }

    async fn handle_finalization(&mut self, finalization: Finalization<V, D>) {
        // Create round (if it doesn't exist)
        let view = finalization.view();
        let round = self.views.entry(view).or_insert(Round::new(
            &self.context,
            self.supervisor.clone(),
            self.recover_latency.clone(),
            view,
        ));

        // Store finalization
        let msg = Voter::Finalization(finalization.clone());
        let seed = finalization.seed_signature;
        if round.add_verified_finalization(finalization) && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, msg)
                .await
                .expect("unable to append to journal");
        }

        // Track view finalized
        if view > self.last_finalized {
            self.last_finalized = view;
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    fn construct_notarize(&mut self, view: u64) -> Option<Notarize<V, D>> {
        // Determine if it makes sense to broadcast a notarize
        let round = self.views.get_mut(&view)?;
        if round.broadcast_notarize {
            return None;
        }
        if round.broadcast_nullify {
            return None;
        }
        if !round.verified_proposal {
            return None;
        }
        round.broadcast_notarize = true;

        // Construct notarize
        let share = self.supervisor.share(view).unwrap();
        let proposal = round.proposal.as_ref().unwrap();
        Some(Notarize::sign(&self.namespace, share, proposal.clone()))
    }

    async fn construct_notarization(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Notarization<V, D>> {
        // Get requested view
        let round = self.views.get_mut(&view)?;

        // Attempt to construct notarization
        let polynomial = self.supervisor.polynomial(view)?;
        let threshold = polynomial_quorum(polynomial);
        round.notarizable(threshold, force).await
    }

    async fn construct_nullification(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Nullification<V>> {
        // Get requested view
        let round = self.views.get_mut(&view)?;

        // Attempt to construct nullification
        let polynomial = self.supervisor.polynomial(view)?;
        let threshold = polynomial_quorum(polynomial);
        round.nullifiable(threshold, force).await
    }

    fn construct_finalize(&mut self, view: u64) -> Option<Finalize<V, D>> {
        // Determine if it makes sense to broadcast a finalize
        let round = self.views.get_mut(&view)?;
        if round.broadcast_nullify {
            return None;
        }
        if !round.broadcast_notarize {
            // Ensure we notarize before we finalize
            return None;
        }
        if !round.broadcast_notarization {
            // Ensure we broadcast notarization before we finalize
            return None;
        }
        if round.broadcast_finalize {
            return None;
        }
        round.broadcast_finalize = true;
        let share = self.supervisor.share(view).unwrap();
        let Some(proposal) = &round.proposal else {
            return None;
        };
        Some(Finalize::sign(&self.namespace, share, proposal.clone()))
    }

    async fn construct_finalization(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Finalization<V, D>> {
        let round = self.views.get_mut(&view)?;

        // Attempt to construct finalization
        let polynomial = self.supervisor.polynomial(view)?;
        let threshold = polynomial_quorum(polynomial);
        round.finalizable(threshold, force).await
    }

    async fn notify<Sp: Sender, Sr: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<C::PublicKey, V, D>,
        resolver: &mut resolver::Mailbox<V, D>,
        pending_sender: &mut WrappedSender<Sp, Voter<V, D>>,
        recovered_sender: &mut WrappedSender<Sr, Voter<V, D>>,
        view: u64,
    ) {
        // Attempt to notarize
        if let Some(notarize) = self.construct_notarize(view) {
            // Handle the notarize
            self.outbound_messages
                .get_or_create(&metrics::NOTARIZE)
                .inc();
            batcher.constructed(Voter::Notarize(notarize.clone())).await;
            self.handle_notarize(notarize.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the notarize
            let msg = Voter::Notarize(notarize);
            pending_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();
        };

        // Attempt to notarization
        if let Some(notarization) = self.construct_notarization(view, false).await {
            // Record latency if we are the leader (only way to get unbiased observation)
            if let Some((leader, elapsed)) = self.since_view_start(view) {
                if leader {
                    self.notarization_latency.observe(elapsed);
                }
            }

            // Update resolver
            resolver.notarized(notarization.clone()).await;

            // Handle the notarization
            self.outbound_messages
                .get_or_create(&metrics::NOTARIZATION)
                .inc();
            self.handle_notarization(notarization.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Alert application
            self.reporter
                .report(Activity::Notarization(notarization.clone()))
                .await;

            // Broadcast the notarization
            let msg = Voter::Notarization(notarization.clone());
            recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();
        };

        // Attempt to nullification
        //
        // We handle broadcast of nullify in `timeout`.
        if let Some(nullification) = self.construct_nullification(view, false).await {
            // Update resolver
            resolver.nullified(nullification.clone()).await;

            // Handle the nullification
            self.outbound_messages
                .get_or_create(&metrics::NULLIFICATION)
                .inc();
            self.handle_nullification(nullification.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Alert application
            self.reporter
                .report(Activity::Nullification(nullification.clone()))
                .await;

            // Broadcast the nullification
            let msg = Voter::Nullification(nullification.clone());
            recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();

            // If `>= f+1` notarized a given proposal, then we should backfill missing
            // notarizations
            let round = self.views.get(&view).expect("missing round");
            if let Some(parent) = round.at_least_one_honest() {
                if parent >= self.last_finalized {
                    // Compute missing nullifications
                    let mut missing_notarizations = Vec::new();
                    if parent != GENESIS_VIEW && self.is_notarized(parent).is_none() {
                        missing_notarizations.push(parent);
                    }
                    let missing_nullifications = self.missing_nullifications(parent);

                    // Fetch any missing
                    if !missing_notarizations.is_empty() || !missing_nullifications.is_empty() {
                        warn!(
                            proposal_view = view,
                            parent,
                            ?missing_notarizations,
                            ?missing_nullifications,
                            ">= 1 honest notarize for nullified parent"
                        );
                        resolver
                            .fetch(missing_notarizations, missing_nullifications)
                            .await;
                    }
                } else {
                    // Broadcast last finalized
                    debug!(
                    parent,
                    last_finalized = self.last_finalized,
                    "not backfilling because parent is behind finalized tip, broadcasting finalized"
                );
                    if let Some(finalization) =
                        self.construct_finalization(self.last_finalized, true).await
                    {
                        let msg = Voter::Finalization(finalization.clone());
                        recovered_sender
                            .send(Recipients::All, msg, true)
                            .await
                            .expect("unable to broadcast finalization");
                    } else {
                        warn!(
                            last_finalized = self.last_finalized,
                            "unable to construct last finalization"
                        );
                    }
                }
            }
        }

        // Attempt to finalize
        if let Some(finalize) = self.construct_finalize(view) {
            // Handle the finalize
            self.outbound_messages
                .get_or_create(&metrics::FINALIZE)
                .inc();
            batcher.constructed(Voter::Finalize(finalize.clone())).await;
            self.handle_finalize(finalize.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the finalize
            let msg = Voter::Finalize(finalize.clone());
            pending_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();
        };

        // Attempt to finalization
        if let Some(finalization) = self.construct_finalization(view, false).await {
            // Record latency if we are the leader (only way to get unbiased observation)
            if let Some((leader, elapsed)) = self.since_view_start(view) {
                if leader {
                    self.finalization_latency.observe(elapsed);
                }
            }

            // Update resolver
            resolver.finalized(view).await;

            // Handle the finalization
            self.outbound_messages
                .get_or_create(&metrics::FINALIZATION)
                .inc();
            self.handle_finalization(finalization.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Alert application
            self.reporter
                .report(Activity::Finalization(finalization.clone()))
                .await;

            // Broadcast the finalization
            let msg = Voter::Finalization(finalization.clone());
            recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();
        };
    }

    pub fn start(
        mut self,
        batcher: batcher::Mailbox<C::PublicKey, V, D>,
        resolver: resolver::Mailbox<V, D>,
        pending_sender: impl Sender<PublicKey = C::PublicKey>,
        recovered_sender: impl Sender<PublicKey = C::PublicKey>,
        recovered_receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(
            batcher,
            resolver,
            pending_sender,
            recovered_sender,
            recovered_receiver,
        ))
    }

    async fn run(
        mut self,
        mut batcher: batcher::Mailbox<C::PublicKey, V, D>,
        mut resolver: resolver::Mailbox<V, D>,
        pending_sender: impl Sender<PublicKey = C::PublicKey>,
        recovered_sender: impl Sender<PublicKey = C::PublicKey>,
        recovered_receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) {
        // Wrap channel
        let mut pending_sender = WrappedSender::new(pending_sender);
        let (mut recovered_sender, mut recovered_receiver) =
            wrap::<_, _, Voter<V, D>>((), recovered_sender, recovered_receiver);

        // Compute genesis
        let genesis = self.automaton.genesis().await;
        self.genesis = Some(genesis);

        // Add initial view
        //
        // We start on view 1 because the genesis container occupies view 0/height 0.
        self.enter_view(1, V::Signature::zero());

        // Initialize journal
        let journal = Journal::<_, Voter<V, D>>::init(
            self.context.with_label("journal"),
            JConfig {
                partition: self.partition.clone(),
                compression: self.compression,
                codec_config: (),
                write_buffer: self.write_buffer,
            },
        )
        .await
        .expect("unable to open journal");

        // Rebuild from journal
        let start = Instant::now();
        {
            let stream = journal
                .replay(self.replay_concurrency, self.replay_buffer)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);
            while let Some(msg) = stream.next().await {
                let (_, _, _, msg) = msg.expect("unable to replay journal");
                let view = msg.view();
                match msg {
                    Voter::Notarize(notarize) => {
                        // Handle notarize
                        let public_key_index = notarize.signer();
                        let me = self.supervisor.participants(view).unwrap()
                            [public_key_index as usize]
                            == self.crypto.public_key();
                        let proposal = notarize.proposal.clone();
                        self.handle_notarize(notarize).await;

                        // Update round info
                        if me {
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.proposal = Some(proposal);
                            round.requested_proposal_build = true;
                            round.requested_proposal_verify = true;
                            round.verified_proposal = true;
                            round.broadcast_notarize = true;
                        }
                    }
                    Voter::Notarization(notarization) => {
                        // Handle notarization
                        self.handle_notarization(notarization).await;

                        // Update round info
                        let round = self.views.get_mut(&view).expect("missing round");
                        round.broadcast_notarization = true;
                    }
                    Voter::Nullify(nullify) => {
                        // Handle nullify
                        let public_key_index = nullify.signer();
                        let me = self.supervisor.participants(view).unwrap()
                            [public_key_index as usize]
                            == self.crypto.public_key();
                        self.handle_nullify(nullify).await;

                        // Update round info
                        if me {
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_nullify = true;
                        }
                    }
                    Voter::Nullification(nullification) => {
                        // Handle nullification
                        self.handle_nullification(nullification).await;

                        // Update round info
                        let round = self.views.get_mut(&view).expect("missing round");
                        round.broadcast_nullification = true;
                    }
                    Voter::Finalize(finalize) => {
                        // Handle finalize
                        let public_key_index = finalize.signer();
                        let me = self.supervisor.participants(view).unwrap()
                            [public_key_index as usize]
                            == self.crypto.public_key();
                        self.handle_finalize(finalize).await;

                        // Update round info
                        //
                        // If we are sending a finalize message, we must be in the next view
                        if me {
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_finalize = true;
                        }
                    }
                    Voter::Finalization(finalization) => {
                        // Handle finalization
                        self.handle_finalization(finalization).await;

                        // Update round info
                        let round = self.views.get_mut(&view).expect("missing round");
                        round.broadcast_finalization = true;
                    }
                }
            }
        }
        self.journal = Some(journal);

        // Update current view and immediately move to timeout (very unlikely we restarted and still within timeout)
        let observed_view = self.view;
        info!(current_view = observed_view, elapsed = ?start.elapsed(), "consensus initialized");
        {
            let round = self.views.get_mut(&observed_view).expect("missing round");
            round.leader_deadline = Some(self.context.current());
            round.advance_deadline = Some(self.context.current());
        }
        self.current_view.set(observed_view as i64);
        self.tracked_views.set(self.views.len() as i64);

        // Initialize verifier with leader
        let round = self.views.get_mut(&observed_view).expect("missing round");
        let (leader, _) = round.leader.as_ref().unwrap();
        batcher
            .update(observed_view, leader.clone(), self.last_finalized)
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
                if view != self.view {
                    pending_set = None;
                    pending_propose_context = None;
                    pending_propose = None;
                    pending_verify_context = None;
                    pending_verify = None;
                }
            }

            // Attempt to propose a container
            if let Some((context, new_propose)) = self.propose(&mut resolver).await {
                pending_set = Some(self.view);
                pending_propose_context = Some(context);
                pending_propose = Some(new_propose);
            }
            let propose_wait = match &mut pending_propose {
                Some(propose) => Either::Left(propose),
                None => Either::Right(futures::future::pending()),
            };

            // Attempt to verify current view
            if let Some((context, new_verify)) = self.peer_proposal().await {
                pending_set = Some(self.view);
                pending_verify_context = Some(context);
                pending_verify = Some(new_verify);
            }
            let verify_wait = match &mut pending_verify {
                Some(verify) => Either::Left(verify),
                None => Either::Right(futures::future::pending()),
            };

            // Wait for a timeout to fire or for a message to arrive
            let timeout = self.timeout_deadline();
            let start = self.view;
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
                    view = self.view;
                },
                proposed = propose_wait => {
                    // Clear propose waiter
                    let context = pending_propose_context.take().unwrap();
                    pending_propose = None;

                    // Try to use result
                    let proposed = match proposed {
                        Ok(proposed) => proposed,
                        Err(err) => {
                            debug!(?err, view = context.view, "failed to propose container");
                            continue;
                        }
                    };

                    // If we have already moved to another view, drop the response as we will
                    // not broadcast it
                    if self.view != context.view {
                        debug!(view = context.view, our_view = self.view, reason = "no longer in required view", "dropping requested proposal");
                        continue;
                    }

                    // Construct proposal
                    let proposal = Proposal::new(
                        context.view,
                        context.parent.0,
                        proposed,
                    );
                    if !self.our_proposal(proposal).await {
                        warn!(view = context.view, "failed to record our container");
                        continue;
                    }
                    view = self.view;

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
                                debug!(view = context.view, "proposal failed verification");
                                continue;
                            }
                        },
                        Err(err) => {
                            debug!(?err, view = context.view, "failed to verify proposal");
                            continue;
                        }
                    };

                    // Handle verified proposal
                    view = context.view;
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
                    if !interesting(
                        self.activity_timeout,
                        self.last_finalized,
                        self.view,
                        view,
                        false,
                    ) {
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
                    let Ok((s, msg)) = msg else {
                        break;
                    };

                    // Skip if there is a decoding error
                    let Ok(msg) = msg else {
                        warn!(sender = ?s, "blocking peer");
                        self.blocker.block(s).await;
                        continue;
                    };

                    // Process message
                    //
                    // We opt to not filter by `interesting()` here because each message type has a different
                    // configuration for handling `future` messages.
                    view = msg.view();
                    let action = match msg {
                        Voter::Notarization(notarization) => {
                            self.inbound_messages
                                .get_or_create(&Inbound::notarization(&s))
                                .inc();
                            self.notarization(notarization).await
                        }
                        Voter::Nullification(nullification) => {
                            self.inbound_messages
                                .get_or_create(&Inbound::nullification(&s))
                                .inc();
                            self.nullification(nullification).await
                        }
                        Voter::Finalization(finalization) => {
                            self.inbound_messages
                                .get_or_create(&Inbound::finalization(&s))
                                .inc();
                            self.finalization(finalization).await
                        }
                        Voter::Notarize(_) | Voter::Nullify(_) | Voter::Finalize(_) => {
                            warn!(sender=?s, "blocking peer");
                            self.blocker.block(s).await;
                            continue;
                        }
                    };
                    match action {
                        Action::Process => {}
                        Action::Skip => {
                            trace!(sender=?s, view, "dropped useless");
                            continue;
                        }
                        Action::Block => {
                            warn!(sender=?s, view, "blocking peer");
                            self.blocker.block(s).await;
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
            if self.view > start {
                let round = self.views.get_mut(&self.view).expect("missing round");
                let (leader, _) = round.leader.as_ref().unwrap();
                let is_active = batcher
                    .update(self.view, leader.clone(), self.last_finalized)
                    .await;

                // If the leader is not active (and not us), we should reduce leader timeout to now
                if !is_active && leader != &self.crypto.public_key() {
                    debug!(view, ?leader, "skipping leader timeout due to inactivity");
                    self.skipped_views.inc();
                    round.leader_deadline = Some(self.context.current());
                }
            }
        }
    }
}
