use super::{Config, Mailbox, Message};
use crate::{
    threshold_simplex::{
        actors::resolver,
        metrics,
        types::{
            Activity, Attributable, ConflictingFinalize, ConflictingNotarize, Context,
            Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
            NullifyFinalize, Proposal, View, Viewable, Voter,
        },
    },
    Automaton, Relay, Reporter, ThresholdSupervisor, LATENCY,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops::threshold_signature_recover,
        poly,
    },
    Digest, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::journal::variable::Journal;
use commonware_utils::quorum;
use futures::{
    channel::{mpsc, oneshot},
    future::{join, Either},
    pin_mut, StreamExt,
};
use prometheus_client::metrics::{
    counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
};
use rand::Rng;
use std::{
    collections::hash_map::Entry,
    sync::{atomic::AtomicI64, Arc},
};
use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, SystemTime},
};
use tracing::{debug, trace, warn};

const GENESIS_VIEW: View = 0;

struct Round<
    C: Scheme,
    D: Digest,
    E: Spawner + Metrics + Clock,
    R: Reporter<Activity = Activity<D>>,
    S: ThresholdSupervisor<
        Seed = group::Signature,
        Index = View,
        Share = group::Share,
        PublicKey = C::PublicKey,
    >,
> {
    start: SystemTime,
    context: E,
    reporter: R,
    supervisor: S,

    view: View,
    participants: usize,

    leader: Option<C::PublicKey>,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,

    // Track one proposal per view (only matters prior to notarization)
    proposal: Option<Proposal<D>>,
    requested_proposal: bool,
    verified_proposal: bool,

    // Track notarizes for all proposals (ensuring any participant only has one recorded notarize)
    notarized_proposals: HashMap<Proposal<D>, Vec<u32>>,
    notarizes: Arc<Vec<Option<Notarize<D>>>>,
    notarization: Option<Notarization<D>>,
    broadcast_notarize: bool,
    broadcast_notarization: bool,

    // Track nullifies (ensuring any participant only has one recorded nullify)
    nullifies: Arc<HashMap<u32, Nullify>>,
    nullification: Option<Nullification>,
    broadcast_nullify: bool,
    broadcast_nullification: bool,

    // Track finalizes for all proposals (ensuring any participant only has one recorded finalize)
    finalized_proposals: HashMap<Proposal<D>, Vec<u32>>,
    finalizes: Arc<Vec<Option<Finalize<D>>>>,
    finalization: Option<Finalization<D>>,
    broadcast_finalize: bool,
    broadcast_finalization: bool,
}

impl<
        C: Scheme,
        D: Digest,
        E: Spawner + Metrics + Clock,
        R: Reporter<Activity = Activity<D>>,
        S: ThresholdSupervisor<
            Seed = group::Signature,
            Index = View,
            Share = group::Share,
            PublicKey = C::PublicKey,
        >,
    > Round<C, D, E, R, S>
{
    pub fn new(ctx: E, reporter: R, supervisor: S, view: View) -> Self {
        let participants = supervisor.participants(view).unwrap().len();
        Self {
            start: ctx.current(),
            context: ctx,
            reporter,
            supervisor,

            view,
            participants,

            leader: None,
            leader_deadline: None,
            advance_deadline: None,
            nullify_retry: None,

            requested_proposal: false,
            proposal: None,
            verified_proposal: false,

            notarized_proposals: HashMap::new(),
            notarizes: Arc::new(vec![None; participants]),
            notarization: None,
            broadcast_notarize: false,
            broadcast_notarization: false,

            nullifies: Arc::new(HashMap::new()),
            nullification: None,
            broadcast_nullify: false,
            broadcast_nullification: false,

            finalized_proposals: HashMap::new(),
            finalizes: Arc::new(vec![None; participants]),
            finalization: None,
            broadcast_finalize: false,
            broadcast_finalization: false,
        }
    }

    pub fn set_leader(&mut self, seed: group::Signature) {
        let leader = ThresholdSupervisor::leader(&self.supervisor, self.view, seed).unwrap();
        self.leader = Some(leader);
    }

    fn add_verified_proposal(&mut self, proposal: Proposal<D>) {
        if self.proposal.is_none() {
            debug!(?proposal, "setting unverified proposal in notarization");
            self.proposal = Some(proposal);
        } else if let Some(previous) = &self.proposal {
            if proposal != *previous {
                warn!(
                    ?proposal,
                    ?previous,
                    "proposal in notarization does not match stored proposal"
                );
            }
        }
    }

    async fn add_verified_notarize(
        &mut self,
        public_key_index: u32,
        notarize: Notarize<D>,
    ) -> bool {
        // Check if already notarized
        if let Some(previous) = self.notarizes[public_key_index as usize].as_ref() {
            if previous == &notarize {
                trace!(?notarize, ?previous, "already notarized");
                return false;
            }

            // Create fault
            let activity = ConflictingNotarize::new(previous.clone(), notarize);
            self.reporter
                .report(Activity::ConflictingNotarize(activity))
                .await;
            warn!(
                view = self.view,
                signer = public_key_index,
                "recorded fault"
            );
            return false;
        }

        // Store the notarize
        if let Some(vec) = self.notarized_proposals.get_mut(&notarize.proposal) {
            vec.push(public_key_index);
        } else {
            self.notarized_proposals
                .insert(notarize.proposal.clone(), vec![public_key_index]);
        }
        Arc::get_mut(&mut self.notarizes).unwrap()[public_key_index as usize] =
            Some(notarize.clone());
        self.reporter.report(Activity::Notarize(notarize)).await;
        true
    }

    async fn add_verified_nullify(&mut self, public_key_index: u32, nullify: Nullify) -> bool {
        // Check if already issued finalize
        let Some(finalize) = self.finalizes[public_key_index as usize].as_ref() else {
            // Store the nullify
            let item = Arc::get_mut(&mut self.nullifies)
                .unwrap()
                .entry(public_key_index);
            return match item {
                Entry::Occupied(_) => false,
                Entry::Vacant(v) => {
                    v.insert(nullify.clone());
                    self.reporter.report(Activity::Nullify(nullify)).await;
                    true
                }
            };
        };

        // Create fault
        let activity = NullifyFinalize::new(nullify, finalize.clone());
        self.reporter
            .report(Activity::NullifyFinalize(activity))
            .await;
        warn!(
            view = self.view,
            signer = public_key_index,
            "recorded fault"
        );
        false
    }

    async fn add_verified_finalize(
        &mut self,
        public_key_index: u32,
        finalize: Finalize<D>,
    ) -> bool {
        // Check if also issued nullify
        if let Some(previous) = self.nullifies.get(&public_key_index) {
            // Create fault
            let activity = NullifyFinalize::new(previous.clone(), finalize);
            self.reporter
                .report(Activity::NullifyFinalize(activity))
                .await;
            warn!(
                view = self.view,
                signer = public_key_index,
                "recorded fault"
            );
            return false;
        }

        // Check if already finalized
        if let Some(previous) = self.finalizes[public_key_index as usize].as_ref() {
            if previous == &finalize {
                trace!(?finalize, ?previous, "already finalize");
                return false;
            }

            // Create fault
            let activity = ConflictingFinalize::new(previous.clone(), finalize);
            self.reporter
                .report(Activity::ConflictingFinalize(activity))
                .await;
            warn!(
                view = self.view,
                signer = public_key_index,
                "recorded fault"
            );
            return false;
        }

        // Store the finalize
        if let Some(vec) = self.finalized_proposals.get_mut(&finalize.proposal) {
            vec.push(public_key_index);
        } else {
            self.finalized_proposals
                .insert(finalize.proposal.clone(), vec![public_key_index]);
        }
        Arc::get_mut(&mut self.finalizes).unwrap()[public_key_index as usize] =
            Some(finalize.clone());
        self.reporter.report(Activity::Finalize(finalize)).await;
        true
    }

    fn add_verified_notarization(&mut self, notarization: Notarization<D>) -> bool {
        // If already have notarization, ignore
        if self.notarization.is_some() {
            return false;
        }

        // Clear leader and advance deadlines (if they exist)
        self.leader_deadline = None;
        self.advance_deadline = None;

        // If proposal is missing, set it
        self.add_verified_proposal(notarization.proposal.clone());

        // Store the notarization
        self.notarization = Some(notarization);
        true
    }

    fn add_verified_nullification(&mut self, nullification: Nullification) -> bool {
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

    fn add_verified_finalization(&mut self, finalization: Finalization<D>) -> bool {
        // If already have finalization, ignore
        if self.finalization.is_some() {
            return false;
        }

        // Clear leader and advance deadlines (if they exist)
        self.leader_deadline = None;
        self.advance_deadline = None;

        // If proposal is missing, set it
        self.add_verified_proposal(finalization.proposal.clone());

        // Store the finalization
        self.finalization = Some(finalization);
        true
    }

    async fn notarizable(&mut self, threshold: u32, force: bool) -> Option<Notarization<D>> {
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
        for (proposal, notarizes) in self.notarized_proposals.iter() {
            if (notarizes.len() as u32) < threshold {
                continue;
            }

            // There should never exist enough notarizes for multiple proposals, so it doesn't
            // matter which one we choose.
            debug!(
                ?proposal,
                verified = self.verified_proposal,
                "broadcasting notarization"
            );

            // Recover threshold signature
            let proposal_signature = self
                .context
                .with_label("notarization_recovery")
                .spawn_blocking({
                    let notarizes = self.notarizes.clone();
                    move || {
                        let proposals = notarizes
                            .iter()
                            .filter_map(|x| x.as_ref())
                            .map(|x| &x.proposal_signature);
                        threshold_signature_recover(threshold, proposals).unwrap()
                    }
                });
            let seed_signature = self.context.with_label("seed_recovery").spawn_blocking({
                let notarizes = self.notarizes.clone();
                move || {
                    let seeds = notarizes
                        .iter()
                        .filter_map(|x| x.as_ref())
                        .map(|x| &x.seed_signature);
                    threshold_signature_recover(threshold, seeds).unwrap()
                }
            });
            let (proposal_signature, seed_signature) =
                join(proposal_signature, seed_signature).await;

            // Construct notarization
            let notarization = Notarization::new(
                proposal.clone(),
                proposal_signature.unwrap(),
                seed_signature.unwrap(),
            );
            self.broadcast_notarization = true;
            return Some(notarization);
        }
        None
    }

    async fn nullifiable(&mut self, threshold: u32, force: bool) -> Option<Nullification> {
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
        if (self.nullifies.len() as u32) < threshold {
            return None;
        }
        debug!(view = self.view, "broadcasting nullification");

        // Recover threshold signature
        let view_signature = self
            .context
            .with_label("nullification_recovery")
            .spawn_blocking({
                let nullifies = self.nullifies.clone();
                move || {
                    let views = nullifies.values().map(|x| &x.view_signature);
                    threshold_signature_recover(threshold, views).unwrap()
                }
            });
        let seed_signature = self.context.with_label("seed_recovery").spawn_blocking({
            let nullifies = self.nullifies.clone();
            move || {
                let seeds = nullifies.values().map(|x| &x.seed_signature);
                threshold_signature_recover(threshold, seeds).unwrap()
            }
        });
        let (view_signature, seed_signature) = join(view_signature, seed_signature).await;

        // Construct nullification
        let nullification =
            Nullification::new(self.view, view_signature.unwrap(), seed_signature.unwrap());
        self.broadcast_nullification = true;
        Some(nullification)
    }

    async fn finalizable(&mut self, threshold: u32, force: bool) -> Option<Finalization<D>> {
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
        for (proposal, finalizes) in self.finalized_proposals.iter() {
            if (finalizes.len() as u32) < threshold {
                continue;
            }

            // Ensure we have a notarization
            let Some(notarization) = &self.notarization else {
                continue;
            };
            let seed_signature = notarization.seed_signature;

            // Check notarization and finalization proposal match
            if notarization.proposal != *proposal {
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

            // Recover threshold signature
            let proposal_signature = self
                .context
                .with_label("finalization_recovery")
                .spawn_blocking({
                    let finalizes = self.finalizes.clone();
                    move || {
                        let proposals = finalizes
                            .iter()
                            .filter_map(|x| x.as_ref())
                            .map(|x| &x.proposal_signature);
                        threshold_signature_recover(threshold, proposals).unwrap()
                    }
                })
                .await;

            // Construct finalization
            let finalization = Finalization::new(
                proposal.clone(),
                proposal_signature.unwrap(),
                seed_signature,
            );
            self.broadcast_finalization = true;
            return Some(finalization);
        }
        None
    }

    /// Returns whether at least one honest participant has notarized a proposal.
    pub fn at_least_one_honest(&self) -> Option<View> {
        let threshold = quorum(self.participants as u32);
        let at_least_one_honest = (threshold - 1) / 2 + 1;
        for (proposal, notarizes) in self.notarized_proposals.iter() {
            if notarizes.len() < at_least_one_honest as usize {
                continue;
            }
            return Some(proposal.parent);
        }
        None
    }
}

pub struct Actor<
    E: Clock + Rng + Spawner + Storage + Metrics,
    C: Scheme,
    D: Digest,
    A: Automaton<Digest = D, Context = Context<D>>,
    R: Relay,
    F: Reporter<Activity = Activity<D>>,
    S: ThresholdSupervisor<
        Identity = poly::Poly<group::Public>,
        Seed = group::Signature,
        Index = View,
        Share = group::Share,
        PublicKey = C::PublicKey,
    >,
> {
    context: E,
    crypto: C,
    automaton: A,
    relay: R,
    reporter: F,
    supervisor: S,

    replay_concurrency: usize,
    journal: Option<Journal<E>>,

    genesis: Option<D>,

    namespace: Vec<u8>,

    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    activity_timeout: View,
    skip_timeout: View,

    mailbox_receiver: mpsc::Receiver<Message<D>>,

    last_finalized: View,
    view: View,
    views: BTreeMap<View, Round<C, D, E, F, S>>,

    current_view: Gauge,
    tracked_views: Gauge,
    skipped_views: Counter,
    received_messages: Family<metrics::PeerMessage, Counter>,
    broadcast_messages: Family<metrics::Message, Counter>,
    notarization_latency: Histogram,
    finalization_latency: Histogram,
}

impl<
        E: Clock + Rng + Spawner + Storage + Metrics,
        C: Scheme,
        D: Digest,
        A: Automaton<Digest = D, Context = Context<D>>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<D>>,
        S: ThresholdSupervisor<
            Identity = poly::Poly<group::Public>,
            Seed = group::Signature,
            Index = View,
            Share = group::Share,
            PublicKey = C::PublicKey,
        >,
    > Actor<E, C, D, A, R, F, S>
{
    pub fn new(
        context: E,
        journal: Journal<E>,
        cfg: Config<C, D, A, R, F, S>,
    ) -> (Self, Mailbox<D>) {
        // Assert correctness of timeouts
        if cfg.leader_timeout > cfg.notarization_timeout {
            panic!("leader timeout must be less than or equal to notarization timeout");
        }

        // Initialize metrics
        let current_view = Gauge::<i64, AtomicI64>::default();
        let tracked_views = Gauge::<i64, AtomicI64>::default();
        let skipped_views = Counter::default();
        let received_messages = Family::<metrics::PeerMessage, Counter>::default();
        let broadcast_messages = Family::<metrics::Message, Counter>::default();
        let notarization_latency = Histogram::new(LATENCY.into_iter());
        let finalization_latency = Histogram::new(LATENCY.into_iter());
        context.register("current_view", "current view", current_view.clone());
        context.register("tracked_views", "tracked views", tracked_views.clone());
        context.register("skipped_views", "skipped views", skipped_views.clone());
        context.register(
            "received_messages",
            "received messages",
            received_messages.clone(),
        );
        context.register(
            "broadcast_messages",
            "broadcast messages",
            broadcast_messages.clone(),
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
        (
            Self {
                context,
                crypto: cfg.crypto,
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,
                supervisor: cfg.supervisor,

                replay_concurrency: cfg.replay_concurrency,
                journal: Some(journal),

                genesis: None,

                namespace: cfg.namespace,

                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,

                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,

                mailbox_receiver,

                last_finalized: 0,
                view: 0,
                views: BTreeMap::new(),

                current_view,
                tracked_views,
                skipped_views,
                received_messages,
                broadcast_messages,
                notarization_latency,
                finalization_latency,
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
        let notarizes = round.notarized_proposals.get(proposal)?;
        let identity = self.supervisor.identity(view)?;
        let threshold = identity.required();
        if notarizes.len() >= threshold as usize {
            return Some(&proposal.payload);
        }
        None
    }

    fn is_nullified(&self, view: View) -> bool {
        let round = match self.views.get(&view) {
            Some(round) => round,
            None => return false,
        };
        let identity = match self.supervisor.identity(view) {
            Some(identity) => identity,
            None => return false,
        };
        let threshold = identity.required();
        round.nullification.is_some() || round.nullifies.len() >= threshold as usize
    }

    fn is_finalized(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(finalization) = &round.finalization {
            return Some(&finalization.proposal.payload);
        }
        let proposal = round.proposal.as_ref()?;
        let finalizes = round.finalized_proposals.get(proposal)?;
        let identity = self.supervisor.identity(view)?;
        let threshold = identity.required();
        if finalizes.len() >= threshold as usize {
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
        backfiller: &mut resolver::Mailbox<D>,
    ) -> Option<(Context<D>, oneshot::Receiver<D>)> {
        // Check if we are leader
        {
            let round = self.views.get_mut(&self.view).unwrap();
            let Some(leader) = &round.leader else {
                return None;
            };
            if *leader != self.crypto.public_key() {
                return None;
            }

            // Check if we have already requested a proposal
            if round.requested_proposal {
                return None;
            }

            // Check if we have already proposed
            if round.proposal.is_some() {
                return None;
            }

            // Set that we requested a proposal even if we don't end up finding a parent
            // to prevent frequent scans.
            round.requested_proposal = true;
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
                backfiller.fetch(vec![view], vec![view]).await;
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

    async fn timeout(&mut self, sender: &mut impl Sender) {
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
                let msg = Voter::Notarization(notarization).encode().into();
                sender.send(Recipients::All, msg, true).await.unwrap();
                self.broadcast_messages
                    .get_or_create(&metrics::NOTARIZATION)
                    .inc();
                debug!(view = past_view, "rebroadcast entry notarization");
            } else if let Some(nullification) = self.construct_nullification(past_view, true).await
            {
                let msg = Voter::<D>::Nullification(nullification).encode().into();
                sender.send(Recipients::All, msg, true).await.unwrap();
                self.broadcast_messages
                    .get_or_create(&metrics::NULLIFICATION)
                    .inc();
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
        self.handle_nullify(share.index, nullify.clone()).await;

        // Sync the journal
        self.journal
            .as_mut()
            .unwrap()
            .sync(self.view)
            .await
            .expect("unable to sync journal");

        // Broadcast nullify
        let msg = Voter::<D>::Nullify(nullify).encode().into();
        sender.send(Recipients::All, msg, true).await.unwrap();
        self.broadcast_messages
            .get_or_create(&metrics::NULLIFY)
            .inc();
        debug!(view = self.view, "broadcasted nullify");
    }

    async fn nullify(&mut self, sender: &C::PublicKey, nullify: Nullify) -> bool {
        // Ensure we are in the right view to process this message
        if !self.interesting(nullify.view, false) {
            return false;
        }

        // Verify that signer is a validator
        let Some(public_key_index) = self.supervisor.is_participant(nullify.view, sender) else {
            return false;
        };
        let Some(identity) = self.supervisor.identity(nullify.view) else {
            return false;
        };

        // Verify signatures
        if !nullify.verify(&self.namespace, identity, Some(public_key_index)) {
            return false;
        }

        // Handle nullify
        self.handle_nullify(public_key_index, nullify).await;
        true
    }

    async fn handle_nullify(&mut self, public_key_index: u32, nullify: Nullify) {
        // Check to see if nullify is for proposal in view
        let view = nullify.view;
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.with_label("round"),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });

        // Handle nullify
        let nullify_bytes = Voter::<D>::Nullify(nullify.clone()).encode().into();
        if round.add_verified_nullify(public_key_index, nullify).await && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, nullify_bytes)
                .await
                .expect("unable to append nullify");
        }
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
        round.proposal = Some(proposal);
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
            let Some(leader) = &round.leader else {
                debug!(
                    view = self.view,
                    "dropping peer proposal because leader is not set"
                );
                return None;
            };
            if *leader == self.crypto.public_key() {
                return None;
            }
            let leader_index = self.supervisor.is_participant(self.view, leader)?;

            // If we already broadcast nullify or set proposal, do nothing
            if round.broadcast_nullify {
                return None;
            }
            if round.proposal.is_some() {
                return None;
            }

            // Check if leader has signed a digest
            let notarize = round.notarizes[leader_index as usize].as_ref()?;
            let proposal = &notarize.proposal;

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
        round.proposal = Some(proposal);
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
        let leader = round.leader.as_ref()?;
        let Ok(elapsed) = self.context.current().duration_since(round.start) else {
            return None;
        };
        Some((*leader == self.crypto.public_key(), elapsed.as_secs_f64()))
    }

    fn enter_view(&mut self, view: u64, seed: group::Signature) {
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
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.with_label("round"),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });
        round.leader_deadline = Some(self.context.current() + self.leader_timeout);
        round.advance_deadline = Some(self.context.current() + self.notarization_timeout);
        round.set_leader(seed);
        self.view = view;

        // Update metrics
        self.current_view.set(view as i64);

        // If we are backfilling, exit early
        if self.journal.is_none() {
            return;
        }

        // Check if we should skip this view
        let leader = round.leader.as_ref().unwrap().clone();
        if view < self.skip_timeout || leader == self.crypto.public_key() {
            // Don't skip the view
            return;
        }
        let mut next = view - 1;
        while next > view - self.skip_timeout {
            let leader_index = match self.supervisor.is_participant(next, &leader) {
                Some(index) => index,
                None => {
                    // Don't punish a participant if they weren't online at any point during
                    // the lookback window.
                    return;
                }
            };
            let round = match self.views.get(&next) {
                Some(round) => round,
                None => {
                    return;
                }
            };
            if round.notarizes[leader_index as usize].is_some()
                || round.nullifies.contains_key(&leader_index)
            {
                return;
            }
            next -= 1;
        }

        // Reduce leader deadline to now
        debug!(view, ?leader, "skipping leader timeout due to inactivity");
        self.skipped_views.inc();
        self.views.get_mut(&view).unwrap().leader_deadline = Some(self.context.current());
    }

    fn interesting(&self, view: View, allow_future: bool) -> bool {
        if view + self.activity_timeout < self.last_finalized {
            return false;
        }
        if !allow_future && view > self.view + 1 {
            return false;
        }
        true
    }

    async fn prune_views(&mut self) {
        // Get last min
        let mut pruned = false;
        let min = loop {
            // Get next key
            let next = match self.views.keys().next() {
                Some(next) => *next,
                None => return,
            };

            // Compare to last finalized
            if !self.interesting(next, false) {
                self.views.remove(&next);
                debug!(
                    view = next,
                    last_finalized = self.last_finalized,
                    "pruned view"
                );
                pruned = true;
            } else {
                break next;
            }
        };

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

    async fn notarize(&mut self, sender: &C::PublicKey, notarize: Notarize<D>) -> bool {
        // Ensure we are in the right view to process this message
        let view = notarize.view();
        if !self.interesting(view, false) {
            return false;
        }

        // Verify that signer is a validator
        let Some(public_key_index) = self.supervisor.is_participant(view, sender) else {
            return false;
        };
        let Some(identity) = self.supervisor.identity(view) else {
            return false;
        };

        // Verify signatures
        if !notarize.verify(&self.namespace, identity, Some(public_key_index)) {
            return false;
        }

        // Handle notarize
        self.handle_notarize(public_key_index, notarize).await;
        true
    }

    async fn handle_notarize(&mut self, public_key_index: u32, notarize: Notarize<D>) {
        // Check to see if notarize is for proposal in view
        let view = notarize.view();
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.with_label("round"),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });

        // Handle notarize
        let notarize_bytes = Voter::Notarize(notarize.clone()).encode().into();
        if round
            .add_verified_notarize(public_key_index, notarize)
            .await
            && self.journal.is_some()
        {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, notarize_bytes)
                .await
                .expect("unable to append to journal");
        }
    }

    async fn notarization(&mut self, notarization: Notarization<D>) -> bool {
        // Check if we are still in a view where this notarization could help
        let view = notarization.view();
        if !self.interesting(view, true) {
            return false;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&view) {
            if round.broadcast_notarization {
                return false;
            }
        }

        // Verify notarization
        let Some(identity) = self.supervisor.identity(view) else {
            return false;
        };
        let public_key = poly::public(identity);
        if !notarization.verify(&self.namespace, public_key) {
            return false;
        }

        // Handle notarization
        self.handle_notarization(notarization).await;
        true
    }

    async fn handle_notarization(&mut self, notarization: Notarization<D>) {
        // Create round (if it doesn't exist)
        let view = notarization.view();
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.with_label("round"),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });

        // Store notarization
        let notarization_bytes = Voter::Notarization(notarization.clone()).encode().into();
        let seed = notarization.seed_signature;
        if round.add_verified_notarization(notarization) && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, notarization_bytes)
                .await
                .expect("unable to append to journal");
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn nullification(&mut self, nullification: Nullification) -> bool {
        // Check if we are still in a view where this notarization could help
        if !self.interesting(nullification.view, true) {
            return false;
        }

        // Determine if we already broadcast nullification for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&nullification.view) {
            if round.broadcast_nullification {
                return false;
            }
        }

        // Verify nullification
        let Some(identity) = self.supervisor.identity(nullification.view) else {
            return false;
        };
        let public_key = poly::public(identity);
        if !nullification.verify(&self.namespace, public_key) {
            return false;
        }

        // Handle notarization
        self.handle_nullification(nullification).await;
        true
    }

    async fn handle_nullification(&mut self, nullification: Nullification) {
        // Create round (if it doesn't exist)
        let view = nullification.view;
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.with_label("round"),
                self.reporter.clone(),
                self.supervisor.clone(),
                nullification.view,
            )
        });

        // Store nullification
        let nullification_bytes = Voter::<D>::Nullification(nullification.clone())
            .encode()
            .into();
        let seed = nullification.seed_signature;
        if round.add_verified_nullification(nullification) && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, nullification_bytes)
                .await
                .expect("unable to append to journal");
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn finalize(&mut self, sender: &C::PublicKey, finalize: Finalize<D>) -> bool {
        // Ensure we are in the right view to process this message
        let view = finalize.view();
        if !self.interesting(view, false) {
            return false;
        }

        // Verify that signer is a validator
        let Some(public_key_index) = self.supervisor.is_participant(view, sender) else {
            return false;
        };
        let Some(identity) = self.supervisor.identity(view) else {
            return false;
        };

        // Verify signature
        if !finalize.verify(&self.namespace, identity, Some(public_key_index)) {
            return false;
        }

        // Handle finalize
        self.handle_finalize(public_key_index, finalize).await;
        true
    }

    async fn handle_finalize(&mut self, public_key_index: u32, finalize: Finalize<D>) {
        // Get view for finalize
        let view = finalize.view();
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.with_label("round"),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });

        // Handle finalize
        let finalize_bytes = Voter::Finalize(finalize.clone()).encode().into();
        if round
            .add_verified_finalize(public_key_index, finalize)
            .await
            && self.journal.is_some()
        {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, finalize_bytes)
                .await
                .expect("unable to append to journal");
        }
    }

    async fn finalization(&mut self, finalization: Finalization<D>) -> bool {
        // Check if we are still in a view where this finalization could help
        let view = finalization.view();
        if !self.interesting(view, true) {
            return false;
        }

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&view) {
            if round.broadcast_finalization {
                return false;
            }
        }

        // Verify finalization
        let Some(identity) = self.supervisor.identity(view) else {
            return false;
        };
        let public_key = poly::public(identity);
        if !finalization.verify(&self.namespace, public_key) {
            return false;
        }

        // Process finalization
        self.handle_finalization(finalization).await;
        true
    }

    async fn handle_finalization(&mut self, finalization: Finalization<D>) {
        // Create round (if it doesn't exist)
        let view = finalization.view();
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.with_label("round"),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });

        // Store finalization
        let finalization_bytes = Voter::Finalization(finalization.clone()).encode().into();
        let seed = finalization.seed_signature;
        if round.add_verified_finalization(finalization) && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, finalization_bytes)
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

    fn construct_notarize(&mut self, view: u64) -> Option<Notarize<D>> {
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

    async fn construct_notarization(&mut self, view: u64, force: bool) -> Option<Notarization<D>> {
        // Get requested view
        let round = self.views.get_mut(&view)?;

        // Attempt to construct notarization
        let identity = self.supervisor.identity(view)?;
        let threshold = identity.required();
        round.notarizable(threshold, force).await
    }

    async fn construct_nullification(&mut self, view: u64, force: bool) -> Option<Nullification> {
        // Get requested view
        let round = self.views.get_mut(&view)?;

        // Attempt to construct nullification
        let identity = self.supervisor.identity(view)?;
        let threshold = identity.required();
        round.nullifiable(threshold, force).await
    }

    fn construct_finalize(&mut self, view: u64) -> Option<Finalize<D>> {
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

    async fn construct_finalization(&mut self, view: u64, force: bool) -> Option<Finalization<D>> {
        let round = self.views.get_mut(&view)?;

        // Attempt to construct finalization
        let identity = self.supervisor.identity(view)?;
        let threshold = identity.required();
        round.finalizable(threshold, force).await
    }

    async fn notify(
        &mut self,
        backfiller: &mut resolver::Mailbox<D>,
        sender: &mut impl Sender,
        view: u64,
    ) {
        // Get public key index
        let public_key_index = self.supervisor.share(view).unwrap().index;

        // Attempt to notarize
        if let Some(notarize) = self.construct_notarize(view) {
            // Handle the notarize
            self.handle_notarize(public_key_index, notarize.clone())
                .await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the notarize
            let msg = Voter::Notarize(notarize.clone()).encode().into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::NOTARIZE)
                .inc();
        };

        // Attempt to notarization
        if let Some(notarization) = self.construct_notarization(view, false).await {
            // Record latency if we are the leader (only way to get unbiased observation)
            if let Some((leader, elapsed)) = self.since_view_start(view) {
                if leader {
                    self.notarization_latency.observe(elapsed);
                }
            }

            // Update backfiller
            backfiller.notarized(notarization.clone()).await;

            // Handle the notarization
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
            let msg = Voter::Notarization(notarization.clone()).encode().into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::NOTARIZATION)
                .inc();
        };

        // Attempt to nullification
        //
        // We handle broadcast of nullify in `timeout`.
        if let Some(nullification) = self.construct_nullification(view, false).await {
            // Update backfiller
            backfiller.nullified(nullification.clone()).await;

            // Handle the nullification
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
            let msg = Voter::<D>::Nullification(nullification.clone())
                .encode()
                .into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::NULLIFICATION)
                .inc();

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
                        backfiller
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
                        let msg = Voter::Finalization(finalization.clone()).encode().into();
                        sender
                            .send(Recipients::All, msg, true)
                            .await
                            .expect("unable to broadcast finalization");
                        self.broadcast_messages
                            .get_or_create(&metrics::FINALIZATION)
                            .inc();
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
            self.handle_finalize(public_key_index, finalize.clone())
                .await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the finalize
            let msg = Voter::Finalize(finalize.clone()).encode().into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::FINALIZE)
                .inc();
        };

        // Attempt to finalization
        if let Some(finalization) = self.construct_finalization(view, false).await {
            // Record latency if we are the leader (only way to get unbiased observation)
            if let Some((leader, elapsed)) = self.since_view_start(view) {
                if leader {
                    self.finalization_latency.observe(elapsed);
                }
            }

            // Update backfiller
            backfiller.finalized(view).await;

            // Handle the finalization
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
            let msg = Voter::Finalization(finalization.clone()).encode().into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::FINALIZATION)
                .inc();
        };
    }

    pub fn start(
        self,
        backfiller: resolver::Mailbox<D>,
        sender: impl Sender<PublicKey = C::PublicKey>,
        receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) -> Handle<()> {
        self.context
            .clone()
            .spawn(|_| self.run(backfiller, sender, receiver))
    }

    async fn run(
        mut self,
        mut backfiller: resolver::Mailbox<D>,
        mut sender: impl Sender<PublicKey = C::PublicKey>,
        mut receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) {
        // Compute genesis
        let genesis = self.automaton.genesis().await;
        self.genesis = Some(genesis);

        // Add initial view
        //
        // We start on view 1 because the genesis container occupies view 0/height 0.
        self.enter_view(1, group::Signature::zero());

        // Rebuild from journal
        let mut journal = self.journal.take().expect("missing journal");
        {
            let stream = journal
                .replay(self.replay_concurrency, None)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);
            while let Some(msg) = stream.next().await {
                let (_, _, _, msg) = msg.expect("unable to decode journal message");
                // We must wrap the message in Voter so we decode the right type of message (otherwise,
                // we can parse a finalize as a notarize)
                let msg = Voter::decode(msg).expect("journal message is unexpected format");
                let view = msg.view();
                match msg {
                    Voter::Notarize(notarize) => {
                        // Handle notarize
                        let public_key_index = notarize.signer();
                        let me = self.supervisor.participants(view).unwrap()
                            [public_key_index as usize]
                            == self.crypto.public_key();
                        let proposal = notarize.proposal.clone();
                        self.handle_notarize(public_key_index, notarize).await;

                        // Update round info
                        if me {
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.proposal = Some(proposal);
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
                        self.handle_nullify(public_key_index, nullify).await;

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
                        self.handle_finalize(public_key_index, finalize).await;

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
        debug!(current_view = observed_view, "replayed journal");
        {
            let round = self.views.get_mut(&observed_view).expect("missing round");
            round.leader_deadline = Some(self.context.current());
            round.advance_deadline = Some(self.context.current());
        }
        self.current_view.set(observed_view as i64);
        self.tracked_views.set(self.views.len() as i64);

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
            if let Some((context, new_propose)) = self.propose(&mut backfiller).await {
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
                    self.timeout(&mut sender).await;
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
                    // Ensure view is still useful
                    //
                    // It is possible that we make a request to the backfiller and prune the view
                    // before we receive the response. In this case, we should ignore the response (not
                    // doing so may result in attempting to store before the prune boundary).
                    let msg = mailbox.unwrap();
                    view = msg.view();
                    if !self.interesting(view, false) {
                        debug!(view, "backfilled message is not interesting");
                        continue;
                    }

                    // Handle backfill
                    match msg {
                        Message::Notarization(notarization)  => {
                            debug!(view, "received notarization from backfiller");
                            self.handle_notarization(notarization).await;
                        },
                        Message::Nullification(nullification) => {
                            debug!(view, "received nullification from backfiller");
                            self.handle_nullification(nullification).await;
                        },
                    }
                },
                msg = receiver.recv() => {
                    // Parse message
                    let Ok((s, msg)) = msg else {
                        break;
                    };
                    let Ok(msg) = Voter::decode(msg) else {
                        continue;
                    };

                    // Process message
                    //
                    // We opt to not filter by `interesting()` here because each message type has a different
                    // configuration for handling `future` messages.
                    view = msg.view();
                    let interesting = match msg {
                        Voter::Notarize(notarize) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::notarize(&s)).inc();
                            self.notarize(&s, notarize).await
                        }
                        Voter::Notarization(notarization) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::notarization(&s)).inc();
                            self.notarization(notarization).await
                        }
                        Voter::Nullify(nullify) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::nullify(&s)).inc();
                            self.nullify(&s, nullify).await
                        }
                        Voter::Nullification(nullification) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::nullification(&s)).inc();
                            self.nullification(nullification).await
                        }
                        Voter::Finalize(finalize) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::finalize(&s)).inc();
                            self.finalize(&s, finalize).await
                        }
                        Voter::Finalization(finalization) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::finalization(&s)).inc();
                            self.finalization(finalization).await
                        }
                    };
                    if !interesting {
                        trace!(sender=?s, view, "dropped message");
                        continue;
                    }
                },
            };

            // Attempt to send any new view messages
            self.notify(&mut backfiller, &mut sender, view).await;

            // After sending all required messages, prune any views
            // we no longer need
            self.prune_views().await;
        }
    }
}
