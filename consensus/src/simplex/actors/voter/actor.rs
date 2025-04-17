use super::{Config, Mailbox, Message};
use crate::{
    simplex::{
        actors::resolver,
        metrics,
        types::{
            finalize_namespace, notarize_namespace, nullify_namespace, threshold, Activity,
            Attributable, ConflictingFinalize, ConflictingNotarize, Context, Finalization,
            Finalize, Notarization, Notarize, Nullification, Nullify, NullifyFinalize, Proposal,
            View, Viewable, Voter,
        },
    },
    Automaton, Relay, Reporter, Supervisor, LATENCY,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Digest, Scheme};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Blob, Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::journal::variable::Journal;
use commonware_utils::quorum;
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    pin_mut, StreamExt,
};
use prometheus_client::metrics::{
    counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
};
use rand::Rng;
use std::sync::atomic::AtomicI64;
use std::{
    cmp::max,
    collections::{btree_map::Entry, BTreeMap, HashMap},
    time::{Duration, SystemTime},
};
use tracing::{debug, trace, warn};

type Notarizable<'a, V, D> = Option<(Proposal<D>, &'a Vec<u32>, &'a Vec<Option<Notarize<V, D>>>)>;
type Nullifiable<'a, V> = Option<(View, &'a BTreeMap<u32, Nullify<V>>)>;
type Finalizable<'a, V, D> = Option<(Proposal<D>, &'a Vec<u32>, &'a Vec<Option<Finalize<V, D>>>)>;

const GENESIS_VIEW: View = 0;

struct Round<
    C: Scheme,
    D: Digest,
    R: Reporter<Activity = Activity<C::Signature, D>>,
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
> {
    start: SystemTime,
    supervisor: S,
    reporter: R,

    view: View,
    leader: C::PublicKey,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,

    // Track one proposal per view
    proposal: Option<Proposal<D>>,
    requested_proposal: bool,
    verified_proposal: bool,

    // Track notarizes for all proposals (ensuring any participant only has one recorded notarize)
    notarized_proposals: HashMap<Proposal<D>, Vec<u32>>,
    notarizes: Vec<Option<Notarize<C::Signature, D>>>,
    broadcast_notarize: bool,
    broadcast_notarization: bool,

    // Track nullifies (ensuring any participant only has one recorded nullify)
    nullifies: BTreeMap<u32, Nullify<C::Signature>>, // we use BTreeMap for deterministic ordering
    broadcast_nullify: bool,
    broadcast_nullification: bool,

    // Track finalizes for all proposals (ensuring any participant only has one recorded finalize)
    finalized_proposals: HashMap<Proposal<D>, Vec<u32>>,
    finalizes: Vec<Option<Finalize<C::Signature, D>>>,
    broadcast_finalize: bool,
    broadcast_finalization: bool,
}

impl<
        C: Scheme,
        D: Digest,
        R: Reporter<Activity = Activity<C::Signature, D>>,
        S: Supervisor<Index = View, PublicKey = C::PublicKey>,
    > Round<C, D, R, S>
{
    pub fn new(current: SystemTime, reporter: R, supervisor: S, view: View) -> Self {
        let leader = supervisor.leader(view).expect("unable to compute leader");
        let participants = supervisor.participants(view).unwrap().len();
        Self {
            start: current,
            supervisor,
            reporter,

            view,
            leader,
            leader_deadline: None,
            advance_deadline: None,
            nullify_retry: None,

            requested_proposal: false,
            proposal: None,
            verified_proposal: false,

            notarized_proposals: HashMap::new(),
            notarizes: vec![None; participants],
            broadcast_notarize: false,
            broadcast_notarization: false,

            nullifies: BTreeMap::new(),
            broadcast_nullify: false,
            broadcast_nullification: false,

            finalized_proposals: HashMap::new(),
            finalizes: vec![None; participants],
            broadcast_finalize: false,
            broadcast_finalization: false,
        }
    }

    async fn add_verified_notarize(&mut self, notarize: Notarize<C::Signature, D>) -> bool {
        // Check if already notarized
        let public_key_index = notarize.signer();
        if let Some(previous_notarize) = self.notarizes[public_key_index as usize].as_ref() {
            if previous_notarize == &notarize {
                trace!(
                    view = self.view,
                    signer = ?notarize.signer(),
                    "already notarized"
                );
                return false;
            }

            // Create fault
            let fault = ConflictingNotarize::new(previous_notarize.clone(), notarize);
            self.reporter
                .report(Activity::ConflictingNotarize(fault))
                .await;
            warn!(view = self.view, signer = ?previous_notarize.signer(), "recorded fault");
            return false;
        }

        // Store the notarize
        if let Some(vec) = self.notarized_proposals.get_mut(&notarize.proposal) {
            vec.push(public_key_index);
        } else {
            self.notarized_proposals
                .insert(notarize.proposal.clone(), vec![public_key_index]);
        }
        self.notarizes[public_key_index as usize] = Some(notarize.clone());
        self.reporter.report(Activity::Notarize(notarize)).await;
        true
    }

    async fn add_verified_nullify(&mut self, nullify: Nullify<C::Signature>) -> bool {
        // Check if already issued finalize
        let public_key_index = nullify.signer();
        let Some(finalize) = self.finalizes[public_key_index as usize].as_ref() else {
            // Store the nullify
            let item = self.nullifies.entry(public_key_index);
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
        let fault = NullifyFinalize::new(nullify, finalize.clone());
        self.reporter.report(Activity::NullifyFinalize(fault)).await;
        warn!(
            view = self.view,
            signer = ?finalize.signer(),
            "recorded fault"
        );
        false
    }

    fn notarizable(&mut self, threshold: u32, force: bool) -> Notarizable<C::Signature, D> {
        if !force && (self.broadcast_notarization || self.broadcast_nullification) {
            // We want to broadcast a notarization, even if we haven't yet verified a proposal.
            return None;
        }
        for (proposal, notarizes) in self.notarized_proposals.iter() {
            if (notarizes.len() as u32) < threshold {
                continue;
            }

            // There should never exist enough notarizes for multiple proposals, so it doesn't
            // matter which one we choose.
            debug!(
                view = self.view,
                proposal = ?proposal,
                verified = self.verified_proposal,
                "broadcasting notarization"
            );
            self.broadcast_notarization = true;
            return Some((proposal.clone(), notarizes, &self.notarizes));
        }
        None
    }

    fn nullifiable(&mut self, threshold: u32, force: bool) -> Nullifiable<C::Signature> {
        if !force && (self.broadcast_nullification || self.broadcast_notarization) {
            return None;
        }
        if (self.nullifies.len() as u32) < threshold {
            return None;
        }
        self.broadcast_nullification = true;
        Some((self.view, &self.nullifies))
    }

    async fn add_verified_finalize(&mut self, finalize: Finalize<C::Signature, D>) -> bool {
        // Check if also issued nullify
        let public_key_index = finalize.signer();
        if let Some(nullify) = self.nullifies.get(&public_key_index) {
            // Create fault
            let fault = NullifyFinalize::new(nullify.clone(), finalize);
            self.reporter.report(Activity::NullifyFinalize(fault)).await;
            warn!(view = self.view, signer=?nullify.signer(), "recorded fault");
            return false;
        }

        // Check if already finalized
        if let Some(previous) = self.finalizes[public_key_index as usize].as_ref() {
            if previous == &finalize {
                trace!(view = ?self.view, signer = ?previous.signer(), "already finalized");
                return false;
            }

            // Create fault
            let fault = ConflictingFinalize::new(previous.clone(), finalize);
            self.reporter
                .report(Activity::ConflictingFinalize(fault))
                .await;
            warn!(view = self.view, signer=?previous.signer(), "recorded fault");
            return false;
        }

        // Store the finalize
        if let Some(vec) = self.finalized_proposals.get_mut(&finalize.proposal) {
            vec.push(public_key_index);
        } else {
            self.finalized_proposals
                .insert(finalize.proposal.clone(), vec![public_key_index]);
        }
        self.finalizes[public_key_index as usize] = Some(finalize.clone());
        self.reporter.report(Activity::Finalize(finalize)).await;
        true
    }

    fn finalizable(&mut self, threshold: u32, force: bool) -> Finalizable<C::Signature, D> {
        if !force && self.broadcast_finalization {
            // We want to broadcast a finalization, even if we haven't yet verified a proposal.
            return None;
        }
        for (proposal, finalizes) in self.finalized_proposals.iter() {
            if (finalizes.len() as u32) < threshold {
                continue;
            }

            // There should never exist enough finalizes for multiple proposals, so it doesn't
            // matter which one we choose.
            debug!(
                view = self.view,
                proposal = ?proposal,
                verified = self.verified_proposal,
                "broadcasting finalization"
            );
            self.broadcast_finalization = true;
            return Some((proposal.clone(), finalizes, &self.finalizes));
        }
        None
    }

    pub fn at_least_one_honest(&self) -> Option<View> {
        let participants = self.supervisor.participants(self.view)?;
        let threshold = quorum(participants.len() as u32)?;
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
    B: Blob,
    E: Clock + Rng + Spawner + Storage<B> + Metrics,
    C: Scheme,
    D: Digest,
    A: Automaton<Context = Context<D>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<C::Signature, D>>,
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
> {
    context: E,
    crypto: C,
    automaton: A,
    relay: R,
    reporter: F,
    supervisor: S,

    replay_concurrency: usize,
    journal: Option<Journal<B, E>>,

    genesis: Option<D>,

    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    activity_timeout: View,
    skip_timeout: View,
    max_participants: usize,

    mailbox_receiver: mpsc::Receiver<Message<C::Signature, D>>,

    last_finalized: View,
    view: View,
    views: BTreeMap<View, Round<C, D, F, S>>,

    current_view: Gauge,
    tracked_views: Gauge,
    skipped_views: Counter,
    received_messages: Family<metrics::PeerMessage, Counter>,
    broadcast_messages: Family<metrics::Message, Counter>,
    notarization_latency: Histogram,
    finalization_latency: Histogram,
}

impl<
        B: Blob,
        E: Clock + Rng + Spawner + Storage<B> + Metrics,
        C: Scheme,
        D: Digest,
        A: Automaton<Context = Context<D>, Digest = D>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<C::Signature, D>>,
        S: Supervisor<Index = View, PublicKey = C::PublicKey>,
    > Actor<B, E, C, D, A, R, F, S>
{
    pub fn new(
        context: E,
        journal: Journal<B, E>,
        cfg: Config<C, D, A, R, F, S>,
    ) -> (Self, Mailbox<C::Signature, D>) {
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

                notarize_namespace: notarize_namespace(&cfg.namespace),
                nullify_namespace: nullify_namespace(&cfg.namespace),
                finalize_namespace: finalize_namespace(&cfg.namespace),

                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,

                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
                max_participants: cfg.max_participants,

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

    fn is_notarized(&self, view: View) -> Option<&Proposal<D>> {
        let round = self.views.get(&view)?;
        let proposal = round.proposal.as_ref()?;
        let notarizes = round.notarized_proposals.get(proposal)?;
        let validators = self.supervisor.participants(view)?;
        let (threshold, _) = threshold(validators);
        if notarizes.len() < threshold as usize {
            return None;
        }
        Some(proposal)
    }

    fn is_nullified(&self, view: View) -> bool {
        let round = match self.views.get(&view) {
            Some(round) => round,
            None => return false,
        };
        let validators = match self.supervisor.participants(view) {
            Some(validators) => validators,
            None => return false,
        };
        let (threshold, _) = threshold(validators);
        round.nullifies.len() >= threshold as usize
    }

    fn is_finalized(&self, view: View) -> Option<&Proposal<D>> {
        let round = self.views.get(&view)?;
        let proposal = round.proposal.as_ref()?;
        let finalizes = round.finalized_proposals.get(proposal)?;
        let validators = self.supervisor.participants(view)?;
        let (threshold, _) = threshold(validators);
        if finalizes.len() < threshold as usize {
            return None;
        }
        Some(proposal)
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
                return Ok((cursor, parent.payload));
            }

            // If have finalization, return
            //
            // We never want to build on some view less than finalized and this prevents that
            let parent = self.is_finalized(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, parent.payload));
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

    async fn propose(
        &mut self,
        backfiller: &mut resolver::Mailbox<C::Signature, D>,
    ) -> Option<(Context<D>, oneshot::Receiver<D>)> {
        // Check if we are leader
        {
            let round = self.views.get_mut(&self.view).unwrap();
            if round.leader != self.crypto.public_key() {
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
            if let Some(notarization) = self.construct_notarization(past_view, true) {
                let msg = Voter::Notarization(notarization).encode().into();
                sender.send(Recipients::All, msg, true).await.unwrap();
                self.broadcast_messages
                    .get_or_create(&metrics::NOTARIZATION)
                    .inc();
                debug!(view = past_view, "rebroadcast entry notarization");
            } else if let Some(nullification) = self.construct_nullification(past_view, true) {
                let msg = Voter::Nullification::<C::Signature, D>(nullification)
                    .encode()
                    .into();
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
        let public_key_index = self
            .supervisor
            .is_participant(self.view, &self.crypto.public_key())
            .unwrap();
        let nullify = Nullify::sign(
            &mut self.crypto,
            public_key_index,
            self.view,
            &self.nullify_namespace,
        );

        // Handle the nullify
        self.handle_nullify(nullify.clone()).await;

        // Sync the journal
        self.journal
            .as_mut()
            .unwrap()
            .sync(self.view)
            .await
            .expect("unable to sync journal");

        // Broadcast nullify
        let msg = Voter::Nullify::<C::Signature, D>(nullify).encode().into();
        sender.send(Recipients::All, msg, true).await.unwrap();
        self.broadcast_messages
            .get_or_create(&metrics::NULLIFY)
            .inc();
        debug!(view = self.view, "broadcasted nullify");
    }

    async fn nullify(&mut self, nullify: Nullify<C::Signature>) -> bool {
        // Ensure we are in the right view to process this message
        if !self.interesting(nullify.view, false) {
            return false;
        }

        // Verify that signer is a validator
        let Some(participants) = self.supervisor.participants(nullify.view) else {
            return false;
        };
        let Some(public_key) = participants.get(nullify.signer() as usize) else {
            return false;
        };

        // Verify the signature
        if !nullify.verify::<C::PublicKey, C>(public_key, &self.nullify_namespace) {
            return false;
        }

        // Handle nullify
        self.handle_nullify(nullify).await;
        true
    }

    async fn handle_nullify(&mut self, nullify: Nullify<C::Signature>) {
        // Check to see if nullify is for proposal in view
        let view = nullify.view();
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.current(),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });

        // Handle nullify
        let msg = Voter::Nullify::<C::Signature, D>(nullify.clone())
            .encode()
            .into();
        if round.add_verified_nullify(nullify).await && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, msg)
                .await
                .expect("unable to append nullify");
        }
    }

    async fn our_proposal(&mut self, proposal: Proposal<D>) -> bool {
        // Store the proposal
        let round = self.views.get_mut(&proposal.view()).expect("view missing");

        // Check if view timed out
        if round.broadcast_nullify {
            debug!(
                view = proposal.view(),
                reason = "view timed out",
                "dropping our proposal"
            );
            return false;
        }

        // Store the proposal
        debug!(view = proposal.view(), "generated proposal");
        round.proposal = Some(proposal);
        round.verified_proposal = true;
        round.leader_deadline = None;
        true
    }

    // Attempt to set proposal from each message received over the wire
    async fn peer_proposal(&mut self) -> Option<(Context<D>, oneshot::Receiver<bool>)> {
        // Get round
        let proposal = {
            // Get view or exit
            let round = self.views.get(&self.view)?;

            // If we are the leader, drop peer proposals
            if round.leader == self.crypto.public_key() {
                return None;
            }
            let leader_index = self.supervisor.is_participant(self.view, &round.leader)?;

            // If we already broadcast nullify or set proposal, do nothing
            if round.broadcast_nullify {
                return None;
            }
            if round.proposal.is_some() {
                return None;
            }

            // Check if leader has signed a digest
            let proposal = round.notarizes[leader_index as usize]
                .as_ref()?
                .proposal
                .clone();

            // Check parent validity
            if proposal.view <= proposal.parent {
                return None;
            }
            if proposal.parent < self.last_finalized {
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
                    break *self.genesis.as_ref().unwrap();
                }

                // Check notarization exists
                let parent_proposal = match self.is_notarized(cursor) {
                    Some(parent) => parent,
                    None => {
                        trace!(view = cursor, "parent proposal is not notarized");
                        return None;
                    }
                };

                // Peer proposal references a valid parent
                break parent_proposal.payload;
            }

            // Check nullification exists in gap
            if !self.is_nullified(cursor) {
                trace!(
                    view = cursor,
                    "missing nullification during proposal verification"
                );
                return None;
            }
            cursor -= 1;
        };

        // Request verification
        debug!(view = proposal.view, "requested proposal verification",);
        let context = Context {
            view: proposal.view,
            parent: (proposal.parent, parent_payload),
        };
        let payload = proposal.payload;
        let round_proposal = Some(proposal);
        let round = self.views.get_mut(&context.view).unwrap();
        round.proposal = round_proposal;
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
        let leader = &round.leader;
        let Ok(elapsed) = self.context.current().duration_since(round.start) else {
            return None;
        };
        Some((*leader == self.crypto.public_key(), elapsed.as_secs_f64()))
    }

    fn enter_view(&mut self, view: u64) {
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
                self.context.current(),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });
        round.leader_deadline = Some(self.context.current() + self.leader_timeout);
        round.advance_deadline = Some(self.context.current() + self.notarization_timeout);
        self.view = view;

        // Update metrics
        self.current_view.set(view as i64);

        // Check if we should skip this view
        let leader = round.leader.clone();
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

    async fn notarize(&mut self, notarize: Notarize<C::Signature, D>) -> bool {
        // Ensure we are in the right view to process this message
        let view = notarize.view();
        if !self.interesting(view, false) {
            return false;
        }

        // Verify that signer is a validator
        let Some(participants) = self.supervisor.participants(view) else {
            return false;
        };
        let Some(public_key) = participants.get(notarize.signer() as usize) else {
            return false;
        };

        // Verify the signature
        if !notarize.verify::<C::PublicKey, C>(public_key, &self.notarize_namespace) {
            return false;
        }

        // Handle notarize
        self.handle_notarize(notarize).await;
        true
    }

    async fn handle_notarize(&mut self, notarize: Notarize<C::Signature, D>) {
        // Check to see if notarize is for proposal in view
        let view = notarize.view();
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.current(),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });

        // Handle notarize
        let msg = Voter::Notarize::<C::Signature, D>(notarize.clone())
            .encode()
            .into();
        if round.add_verified_notarize(notarize).await && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, msg)
                .await
                .expect("unable to append to journal");
        }
    }

    async fn notarization(&mut self, notarization: Notarization<C::Signature, D>) -> bool {
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
        let Some(participants) = self.supervisor.participants(view) else {
            return false;
        };
        if !notarization.verify::<S::PublicKey, C>(participants, &self.notarize_namespace) {
            return false;
        }

        // Handle notarization
        self.handle_notarization(&notarization).await;
        true
    }

    async fn handle_notarization(&mut self, notarization: &Notarization<C::Signature, D>) {
        // Add signatures to view (needed to broadcast notarization if we get proposal)
        let view = notarization.view();
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.current(),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });
        for signature in &notarization.signatures {
            let notarize = Notarize::new(notarization.proposal.clone(), signature.clone());
            let msg = Voter::Notarize::<C::Signature, D>(notarize.clone())
                .encode()
                .into();
            if round.add_verified_notarize(notarize).await && self.journal.is_some() {
                self.journal
                    .as_mut()
                    .unwrap()
                    .append(view, msg)
                    .await
                    .expect("unable to append to journal");
            }
        }

        // Clear leader and advance deadlines (if they exist)
        round.leader_deadline = None;
        round.advance_deadline = None;

        // If proposal is missing, set it
        if round.proposal.is_none() {
            let proposal = notarization.proposal.clone();
            debug!(
                view = proposal.view,
                "setting unverified proposal in notarization"
            );
            round.proposal = Some(proposal);
        }

        // Enter next view
        self.enter_view(view + 1);
    }

    async fn nullification(&mut self, nullification: Nullification<C::Signature>) -> bool {
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
        let Some(participants) = self.supervisor.participants(nullification.view) else {
            return false;
        };
        if !nullification.verify::<S::PublicKey, C>(participants, &self.nullify_namespace) {
            return false;
        }

        // Handle notarization
        self.handle_nullification(&nullification).await;
        true
    }

    async fn handle_nullification(&mut self, nullification: &Nullification<C::Signature>) {
        // Add signatures to view (needed to broadcast notarization if we get proposal)
        let view = nullification.view();
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.current(),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });
        for signature in &nullification.signatures {
            let nullify = Nullify::new(view, signature.clone());
            let msg = Voter::Nullify::<C::Signature, D>(nullify.clone())
                .encode()
                .into();
            if round.add_verified_nullify(nullify).await && self.journal.is_some() {
                self.journal
                    .as_mut()
                    .unwrap()
                    .append(nullification.view, msg)
                    .await
                    .expect("unable to append to journal");
            }
        }

        // Clear leader and advance deadlines (if they exist)
        round.leader_deadline = None;
        round.advance_deadline = None;

        // Enter next view
        self.enter_view(nullification.view + 1);
    }

    async fn finalize(&mut self, finalize: Finalize<C::Signature, D>) -> bool {
        // Ensure we are in the right view to process this message
        let view = finalize.view();
        if !self.interesting(view, false) {
            return false;
        }

        // Verify that signer is a validator
        let Some(participants) = self.supervisor.participants(view) else {
            return false;
        };
        let Some(public_key) = participants.get(finalize.signer() as usize) else {
            return false;
        };

        // Verify the signature
        if !finalize.verify::<C::PublicKey, C>(public_key, &self.finalize_namespace) {
            return false;
        }

        // Handle finalize
        self.handle_finalize(finalize).await;
        true
    }

    async fn handle_finalize(&mut self, finalize: Finalize<C::Signature, D>) {
        // Get view for finalize
        let view = finalize.view();
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.current(),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });

        // Handle finalize
        let msg = Voter::Finalize::<C::Signature, D>(finalize.clone())
            .encode()
            .into();
        if round.add_verified_finalize(finalize).await && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, msg)
                .await
                .expect("unable to append to journal");
        }
    }

    async fn finalization(&mut self, finalization: Finalization<C::Signature, D>) -> bool {
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
        let Some(participants) = self.supervisor.participants(view) else {
            return false;
        };
        if !finalization.verify::<S::PublicKey, C>(participants, &self.finalize_namespace) {
            return false;
        }

        // Process finalization
        self.handle_finalization(&finalization).await;
        true
    }

    async fn handle_finalization(&mut self, finalization: &Finalization<C::Signature, D>) {
        // Add signatures to view (needed to broadcast finalization if we get proposal)
        let view = finalization.view();
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.current(),
                self.reporter.clone(),
                self.supervisor.clone(),
                view,
            )
        });
        for signature in &finalization.signatures {
            let finalize = Finalize::new(finalization.proposal.clone(), signature.clone());
            let msg = Voter::Finalize::<C::Signature, D>(finalize.clone())
                .encode()
                .into();
            if round.add_verified_finalize(finalize).await && self.journal.is_some() {
                self.journal
                    .as_mut()
                    .unwrap()
                    .append(view, msg)
                    .await
                    .expect("unable to append to journal");
            }
        }

        // If proposal is missing, set it
        if round.proposal.is_none() {
            let proposal = finalization.proposal.clone();
            debug!(
                view = proposal.view,
                "setting unverified proposal in finalization"
            );
            round.proposal = Some(proposal);
        }

        // Track view finalized
        if view > self.last_finalized {
            self.last_finalized = view;
        }

        // Enter next view
        self.enter_view(view + 1);
    }

    fn construct_notarize(&mut self, view: u64) -> Option<Notarize<C::Signature, D>> {
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };
        if round.broadcast_notarize {
            return None;
        }
        if round.broadcast_nullify {
            return None;
        }
        if !round.verified_proposal {
            return None;
        }
        let public_key_index = self
            .supervisor
            .is_participant(view, &self.crypto.public_key())?;
        round.broadcast_notarize = true;
        Some(Notarize::sign(
            &mut self.crypto,
            public_key_index,
            round.proposal.as_ref().unwrap().clone(),
            &self.notarize_namespace,
        ))
    }

    fn construct_notarization(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Notarization<C::Signature, D>> {
        // Get requested view
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct notarization
        let validators = match self.supervisor.participants(view) {
            Some(validators) => validators,
            None => {
                return None;
            }
        };
        let threshold =
            quorum(validators.len() as u32).expect("not enough validators for a quorum");
        let (proposal, proposal_notarizes, notarizes) = round.notarizable(threshold, force)?;

        // Construct notarization
        let mut signatures = Vec::new();
        for notarize in proposal_notarizes {
            signatures.push(
                notarizes[*notarize as usize]
                    .as_ref()
                    .unwrap()
                    .signature
                    .clone(),
            );
        }
        Some(Notarization::new(proposal, signatures))
    }

    fn construct_nullification(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Nullification<C::Signature>> {
        // Get requested view
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct notarization
        let validators = match self.supervisor.participants(view) {
            Some(validators) => validators,
            None => {
                return None;
            }
        };
        let threshold =
            quorum(validators.len() as u32).expect("not enough validators for a quorum");
        let (_, nullifies) = round.nullifiable(threshold, force)?;

        // Construct nullification
        let signatures = nullifies
            .values()
            .map(|n| n.signature.clone())
            .collect::<Vec<_>>();
        Some(Nullification::new(view, signatures))
    }

    fn construct_finalize(&mut self, view: u64) -> Option<Finalize<C::Signature, D>> {
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };
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
        let public_key_index = self
            .supervisor
            .is_participant(view, &self.crypto.public_key())?;
        round.broadcast_finalize = true;
        Some(Finalize::sign(
            &mut self.crypto,
            public_key_index,
            round.proposal.as_ref().unwrap().clone(),
            &self.finalize_namespace,
        ))
    }

    fn construct_finalization(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Finalization<C::Signature, D>> {
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct finalization
        let validators = match self.supervisor.participants(view) {
            Some(validators) => validators,
            None => {
                return None;
            }
        };
        let threshold =
            quorum(validators.len() as u32).expect("not enough validators for a quorum");
        let (proposal, proposal_finalizes, finalizes) = round.finalizable(threshold, force)?;

        // Construct finalization
        let mut signatures = Vec::new();
        for finalize in proposal_finalizes {
            signatures.push(
                finalizes[*finalize as usize]
                    .as_ref()
                    .unwrap()
                    .signature
                    .clone(),
            );
        }
        Some(Finalization::new(proposal, signatures))
    }

    async fn notify(
        &mut self,
        backfiller: &mut resolver::Mailbox<C::Signature, D>,
        sender: &mut impl Sender,
        view: u64,
    ) {
        // Attempt to notarize
        if let Some(notarize) = self.construct_notarize(view) {
            // Handle the notarize
            self.handle_notarize(notarize.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the notarize
            let msg = Voter::Notarize(notarize).encode().into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::NOTARIZE)
                .inc();
        };

        // Attempt to notarization
        if let Some(notarization) = self.construct_notarization(view, false) {
            // Record latency if we are the leader (only way to get unbiased observation)
            if let Some((leader, elapsed)) = self.since_view_start(view) {
                if leader {
                    self.notarization_latency.observe(elapsed);
                }
            }

            // Update backfiller
            backfiller.notarized(notarization.clone()).await;

            // Handle the notarization
            self.handle_notarization(&notarization).await;

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
            let msg = Voter::Notarization(notarization).encode().into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::NOTARIZATION)
                .inc();
        };

        // Attempt to nullification
        //
        // We handle broadcast of nullify in `timeout`.
        if let Some(nullification) = self.construct_nullification(view, false) {
            // Update backfiller
            backfiller.nullified(nullification.clone()).await;

            // Handle the nullification
            self.handle_nullification(&nullification).await;

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
            let msg = Voter::Nullification::<C::Signature, D>(nullification)
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
                    let finalization = self.construct_finalization(self.last_finalized, true);
                    if let Some(finalization) = finalization {
                        let msg = Voter::Finalization(finalization).encode().into();
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
            self.handle_finalize(finalize.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the finalize
            let msg = Voter::Finalize(finalize).encode().into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::FINALIZE)
                .inc();
        };

        // Attempt to finalization
        if let Some(finalization) = self.construct_finalization(view, false) {
            // Record latency if we are the leader (only way to get unbiased observation)
            if let Some((leader, elapsed)) = self.since_view_start(view) {
                if leader {
                    self.finalization_latency.observe(elapsed);
                }
            }

            // Update backfiller
            backfiller.finalized(view).await;

            // Handle the finalization
            self.handle_finalization(&finalization).await;

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
            let msg = Voter::Finalization(finalization).encode().into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::FINALIZATION)
                .inc();
        };
    }

    pub fn start(
        mut self,
        backfiller: resolver::Mailbox<C::Signature, D>,
        sender: impl Sender,
        receiver: impl Receiver,
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(backfiller, sender, receiver))
    }

    async fn run(
        mut self,
        mut backfiller: resolver::Mailbox<C::Signature, D>,
        mut sender: impl Sender,
        mut receiver: impl Receiver,
    ) {
        // Compute genesis
        let genesis = self.automaton.genesis().await;
        self.genesis = Some(genesis);

        // Add initial view
        //
        // We start on view 1 because the genesis container occupies view 0/height 0.
        self.enter_view(1);

        // Rebuild from journal
        let mut observed_view = 1;
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
                let msg = Voter::decode_cfg(msg, &self.max_participants)
                    .expect("journal message is unexpected format");
                let view = msg.view();
                let public_key_index = self
                    .supervisor
                    .is_participant(view, &self.crypto.public_key());
                match msg {
                    Voter::Notarize(notarize) => {
                        // Handle notarize
                        self.handle_notarize(notarize.clone()).await;

                        // Update round info
                        let Some(public_key_index) = public_key_index else {
                            continue;
                        };
                        if notarize.signer() == public_key_index {
                            observed_view = max(observed_view, view);
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.proposal = Some(notarize.proposal);
                            round.verified_proposal = true;
                            round.broadcast_notarize = true;
                        }
                    }
                    Voter::Nullify(nullify) => {
                        // Handle nullify
                        self.handle_nullify(nullify.clone()).await;

                        // Update round info
                        let Some(public_key_index) = public_key_index else {
                            continue;
                        };
                        if nullify.signer() == public_key_index {
                            observed_view = max(observed_view, view);
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_nullify = true;
                        }
                    }
                    Voter::Finalize(finalize) => {
                        // Handle finalize
                        self.handle_finalize(finalize.clone()).await;

                        // Update round info
                        //
                        // If we are sending a finalize message, we must be in the next view
                        let Some(public_key_index) = public_key_index else {
                            continue;
                        };
                        if finalize.signer() == public_key_index {
                            observed_view = max(observed_view, view + 1);
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_notarization = true;
                            round.broadcast_finalize = true;
                        }
                    }
                    _ => panic!("unexpected message in journal"),
                }
            }
        }
        self.journal = Some(journal);

        // Update current view and immediately move to timeout (very unlikely we restarted and still within timeout)
        debug!(current_view = observed_view, "replayed journal");
        self.enter_view(observed_view);
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
                    let proposal = Proposal::new(context.view, context.parent.0, proposed);
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
                    match msg {
                        Message::Notarization(notarization)  => {
                            debug!(view, "received notarization from backfiller");
                            self.handle_notarization(&notarization).await;
                        },
                        Message::Nullification(nullification) => {
                            debug!(view, "received nullification from backfiller");
                            self.handle_nullification(&nullification).await;
                        },
                    }
                },
                msg = receiver.recv() => {
                    // Parse message
                    let Ok((s, msg)) = msg else {
                        break;
                    };
                    let Ok(msg) = Voter::decode_cfg(msg, &self.max_participants) else {
                        continue;
                    };

                    // Process message
                    view = msg.view();
                    let interesting = match msg {
                        Voter::Notarize(notarize) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::notarize(&s)).inc();
                            self.notarize(notarize).await
                        }
                        Voter::Notarization(notarization) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::notarization(&s)).inc();
                            self.notarization(notarization).await
                        }
                        Voter::Nullify(nullify) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::nullify(&s)).inc();
                            self.nullify(nullify).await
                        }
                        Voter::Nullification(nullification) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::nullification(&s)).inc();
                            self.nullification(nullification).await
                        }
                        Voter::Finalize(finalize) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::finalize(&s)).inc();
                            self.finalize(finalize).await
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
