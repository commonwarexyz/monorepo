use super::{Config, Mailbox, Message};
use crate::{
    simplex::{
        actors::resolver,
        encoder::{
            finalize_namespace, notarize_namespace, nullify_message, nullify_namespace,
            proposal_message,
        },
        metrics,
        prover::Prover,
        verifier::{threshold, verify_finalization, verify_notarization, verify_nullification},
        wire, Context, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE, NOTARIZE,
        NULLIFY_AND_FINALIZE,
    },
    Automaton, Committer, Parsed, Relay, Supervisor, LATENCY,
};
use commonware_cryptography::{sha256::hash, sha256::Digest as Sha256Digest, Scheme};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Blob, Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::journal::variable::Journal;
use commonware_utils::{quorum, Array};
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    pin_mut, StreamExt,
};
use prometheus_client::metrics::{
    counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
};
use prost::Message as _;
use rand::Rng;
use std::sync::atomic::AtomicI64;
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
    time::{Duration, SystemTime},
};
use tracing::{debug, info, trace, warn};

type Notarizable<'a, D> = Option<(wire::Proposal, &'a HashMap<u32, Parsed<wire::Notarize, D>>)>;
type Nullifiable<'a> = Option<(View, &'a HashMap<u32, wire::Nullify>)>;
type Finalizable<'a, D> = Option<(wire::Proposal, &'a HashMap<u32, Parsed<wire::Finalize, D>>)>;

const GENESIS_VIEW: View = 0;

struct Round<C: Scheme, D: Array, S: Supervisor<Index = View>> {
    start: SystemTime,
    supervisor: S,

    view: View,
    leader: C::PublicKey,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,

    // Track one proposal per view
    proposal: Option<(Sha256Digest /* proposal */, Parsed<wire::Proposal, D>)>,
    requested_proposal: bool,
    verified_proposal: bool,

    // Track notarizes for all proposals (ensuring any participant only has one recorded notarize)
    notaries: HashMap<u32, Sha256Digest>,
    notarizes: HashMap<Sha256Digest, HashMap<u32, Parsed<wire::Notarize, D>>>,
    broadcast_notarize: bool,
    broadcast_notarization: bool,

    // Track nullifies (ensuring any participant only has one recorded nullify)
    nullifies: HashMap<u32, wire::Nullify>,
    broadcast_nullify: bool,
    broadcast_nullification: bool,

    // Track finalizes for all proposals (ensuring any participant only has one recorded finalize)
    finalizers: HashMap<u32, Sha256Digest>,
    finalizes: HashMap<Sha256Digest, HashMap<u32, Parsed<wire::Finalize, D>>>,
    broadcast_finalize: bool,
    broadcast_finalization: bool,
}

impl<C: Scheme, D: Array, S: Supervisor<Index = View, PublicKey = C::PublicKey>> Round<C, D, S> {
    pub fn new(start: SystemTime, supervisor: S, view: View) -> Self {
        let leader = supervisor.leader(view).expect("unable to compute leader");
        Self {
            start,
            supervisor,

            view,
            leader,
            leader_deadline: None,
            advance_deadline: None,
            nullify_retry: None,

            requested_proposal: false,
            proposal: None,
            verified_proposal: false,

            notaries: HashMap::new(),
            notarizes: HashMap::new(),
            broadcast_notarize: false,
            broadcast_notarization: false,

            nullifies: HashMap::new(),
            broadcast_nullify: false,
            broadcast_nullification: false,

            finalizers: HashMap::new(),
            finalizes: HashMap::new(),
            broadcast_finalize: false,
            broadcast_finalization: false,
        }
    }

    async fn add_verified_notarize(
        &mut self,
        public_key: &C::PublicKey,
        notarize: Parsed<wire::Notarize, D>,
    ) -> bool {
        // Get proposal
        let proposal = notarize.message.proposal.as_ref().unwrap();

        // Compute proposal digest
        let message = proposal_message(proposal.view, proposal.parent, &notarize.digest);
        let proposal_digest = hash(&message);

        // Get Signature
        let Ok(notarize_signature) =
            C::Signature::try_from(&notarize.message.signature.as_ref().unwrap().signature)
        else {
            return false;
        };

        // Check if already notarized
        let public_key_index = notarize.message.signature.as_ref().unwrap().public_key;
        if let Some(previous_notarize) = self.notaries.get(&public_key_index) {
            if previous_notarize == &proposal_digest {
                trace!(
                    view = self.view,
                    signer = ?public_key,
                    previous_notarize = ?previous_notarize,
                    "already notarized"
                );
                return false;
            }

            // Create fault
            let previous_notarize = self
                .notarizes
                .get(previous_notarize)
                .unwrap()
                .get(&public_key_index)
                .unwrap();
            let previous_proposal = previous_notarize.message.proposal.as_ref().unwrap();
            let Ok(previous_notarize_signature) = C::Signature::try_from(
                &previous_notarize
                    .message
                    .signature
                    .as_ref()
                    .unwrap()
                    .signature,
            ) else {
                return false;
            };

            let proof = Prover::<C, D>::serialize_conflicting_notarize(
                self.view,
                public_key,
                previous_proposal.parent,
                &previous_notarize.digest,
                &previous_notarize_signature,
                proposal.parent,
                &notarize.digest,
                &notarize_signature,
            );
            self.supervisor.report(CONFLICTING_NOTARIZE, proof).await;
            warn!(
                view = self.view,
                signer = ?public_key,
                activity = CONFLICTING_NOTARIZE,
                "recorded fault"
            );
            return false;
        }

        // Store the notarize
        if self
            .notaries
            .insert(public_key_index, proposal_digest.clone())
            .is_some()
        {
            return false;
        }
        let entry = self.notarizes.entry(proposal_digest).or_default();
        let proof = Prover::<C, D>::serialize_proposal(proposal, public_key, &notarize_signature);
        entry.insert(public_key_index, notarize);
        self.supervisor.report(NOTARIZE, proof).await;
        true
    }

    async fn add_verified_nullify(
        &mut self,
        public_key: &C::PublicKey,
        nullify: wire::Nullify,
    ) -> bool {
        // Check if already issued finalize
        let public_key_index = nullify.signature.as_ref().unwrap().public_key;
        let finalize = self.finalizers.get(&public_key_index);
        if finalize.is_none() {
            // Store the nullify
            return self.nullifies.insert(public_key_index, nullify).is_none();
        }
        let finalize = finalize.unwrap();

        // Create fault
        let finalize = self
            .finalizes
            .get(finalize)
            .unwrap()
            .get(&public_key_index)
            .unwrap();
        let Ok(finalize_signature) =
            C::Signature::try_from(&finalize.message.signature.as_ref().unwrap().signature)
        else {
            return false;
        };
        let Ok(nullify_signature) =
            C::Signature::try_from(&nullify.signature.as_ref().unwrap().signature)
        else {
            return false;
        };
        let finalize_proposal = finalize.message.proposal.as_ref().unwrap();
        let proof = Prover::<C, D>::serialize_nullify_finalize(
            self.view,
            public_key,
            finalize_proposal.parent,
            &finalize.digest,
            &finalize_signature,
            &nullify_signature,
        );
        self.supervisor.report(NULLIFY_AND_FINALIZE, proof).await;
        warn!(
            view = self.view,
            signer = ?public_key,
            activity = NULLIFY_AND_FINALIZE,
            "recorded fault"
        );
        false
    }

    fn notarizable(&mut self, threshold: u32, force: bool) -> Notarizable<D> {
        if !force && (self.broadcast_notarization || self.broadcast_nullification) {
            // We want to broadcast a notarization, even if we haven't yet verified a proposal.
            return None;
        }
        for (proposal, notarizes) in self.notarizes.iter() {
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

            // Grab the proposal
            let proposal = notarizes
                .values()
                .next()
                .unwrap()
                .message
                .proposal
                .as_ref()
                .unwrap();
            return Some((proposal.clone(), notarizes));
        }
        None
    }

    fn nullifiable(&mut self, threshold: u32, force: bool) -> Nullifiable {
        if !force && (self.broadcast_nullification || self.broadcast_notarization) {
            return None;
        }
        if (self.nullifies.len() as u32) < threshold {
            return None;
        }
        self.broadcast_nullification = true;
        Some((self.view, &self.nullifies))
    }

    async fn add_verified_finalize(
        &mut self,
        public_key: &C::PublicKey,
        finalize: Parsed<wire::Finalize, D>,
    ) -> bool {
        // Check if also issued nullify
        let proposal = finalize.message.proposal.as_ref().unwrap();
        let public_key_index = finalize.message.signature.as_ref().unwrap().public_key;
        let Ok(finalize_signature) =
            C::Signature::try_from(&finalize.message.signature.as_ref().unwrap().signature)
        else {
            return false;
        };
        let null = self.nullifies.get(&public_key_index);
        if let Some(null) = null {
            // Create fault
            let Ok(null_signature) =
                C::Signature::try_from(&null.signature.as_ref().unwrap().signature)
            else {
                return false;
            };
            let proof = Prover::<C, D>::serialize_nullify_finalize(
                self.view,
                public_key,
                proposal.parent,
                &finalize.digest,
                &finalize_signature,
                &null_signature,
            );
            self.supervisor.report(NULLIFY_AND_FINALIZE, proof).await;
            warn!(
                view = self.view,
                signer = ?public_key,
                activity = NULLIFY_AND_FINALIZE,
                "recorded fault"
            );
            return false;
        }

        // Compute proposal digest
        let message = proposal_message(proposal.view, proposal.parent, &finalize.digest);
        let proposal_digest = hash(&message);

        // Check if already finalized
        if let Some(previous_finalize) = self.finalizers.get(&public_key_index) {
            if previous_finalize == &proposal_digest {
                trace!(
                    view = self.view,
                    signer = ?public_key,
                    ?previous_finalize,
                    "already finalize"
                );
                return false;
            }

            // Create fault
            let previous_finalize = self
                .finalizes
                .get(previous_finalize)
                .unwrap()
                .get(&public_key_index)
                .unwrap();
            let previous_proposal = previous_finalize.message.proposal.as_ref().unwrap();
            let Ok(previous_finalize_signature) = C::Signature::try_from(
                &previous_finalize
                    .message
                    .signature
                    .as_ref()
                    .unwrap()
                    .signature,
            ) else {
                return false;
            };
            let proof = Prover::<C, D>::serialize_conflicting_finalize(
                self.view,
                public_key,
                previous_proposal.parent,
                &previous_finalize.digest,
                &previous_finalize_signature,
                proposal.parent,
                &finalize.digest,
                &finalize_signature,
            );
            self.supervisor.report(CONFLICTING_FINALIZE, proof).await;
            warn!(
                view = self.view,
                signer = ?public_key,
                activity = CONFLICTING_FINALIZE,
                "recorded fault"
            );
            return false;
        }

        // Store the finalize
        if self
            .finalizers
            .insert(public_key_index, proposal_digest.clone())
            .is_some()
        {
            return false;
        }
        let entry = self.finalizes.entry(proposal_digest).or_default();
        let proof = Prover::<C, D>::serialize_proposal(proposal, public_key, &finalize_signature);
        entry.insert(public_key_index, finalize);
        self.supervisor.report(FINALIZE, proof).await;
        true
    }

    fn finalizable(&mut self, threshold: u32, force: bool) -> Finalizable<D> {
        if !force && self.broadcast_finalization {
            // We want to broadcast a finalization, even if we haven't yet verified a proposal.
            return None;
        }
        for (proposal, finalizes) in self.finalizes.iter() {
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

            // Grab the proposal
            let proposal = finalizes
                .values()
                .next()
                .unwrap()
                .message
                .proposal
                .as_ref()
                .unwrap()
                .clone();
            return Some((proposal, finalizes));
        }
        None
    }

    pub fn at_least_one_honest(&self) -> Option<View> {
        let participants = self.supervisor.participants(self.view)?;
        let threshold = quorum(participants.len() as u32)?;
        let at_least_one_honest = (threshold - 1) / 2 + 1;
        for (_, notarizes) in self.notarizes.iter() {
            if notarizes.len() < at_least_one_honest as usize {
                continue;
            }
            let parent = notarizes
                .values()
                .next()
                .unwrap()
                .message
                .proposal
                .as_ref()
                .unwrap()
                .parent;
            return Some(parent);
        }
        None
    }
}

pub struct Actor<
    B: Blob,
    E: Clock + Rng + Spawner + Storage<B> + Metrics,
    C: Scheme,
    D: Array,
    A: Automaton<Context = Context<D>, Digest = D>,
    R: Relay<Digest = D>,
    F: Committer<Digest = D>,
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
> {
    context: E,
    crypto: C,
    automaton: A,
    relay: R,
    committer: F,
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

    mailbox_receiver: mpsc::Receiver<Message<D>>,

    last_finalized: View,
    view: View,
    views: BTreeMap<View, Round<C, D, S>>,

    current_view: Gauge,
    tracked_views: Gauge,
    received_messages: Family<metrics::PeerMessage, Counter>,
    broadcast_messages: Family<metrics::Message, Counter>,
    notarization_latency: Histogram,
    finalization_latency: Histogram,
}

impl<
        B: Blob,
        E: Clock + Rng + Spawner + Storage<B> + Metrics,
        C: Scheme,
        D: Array,
        A: Automaton<Context = Context<D>, Digest = D>,
        R: Relay<Digest = D>,
        F: Committer<Digest = D>,
        S: Supervisor<Index = View, PublicKey = C::PublicKey>,
    > Actor<B, E, C, D, A, R, F, S>
{
    pub fn new(
        context: E,
        journal: Journal<B, E>,
        cfg: Config<C, D, A, R, F, S>,
    ) -> (Self, Mailbox<D>) {
        // Assert correctness of timeouts
        if cfg.leader_timeout > cfg.notarization_timeout {
            panic!("leader timeout must be less than or equal to notarization timeout");
        }

        // Initialize metrics
        let current_view = Gauge::<i64, AtomicI64>::default();
        let tracked_views = Gauge::<i64, AtomicI64>::default();
        let received_messages = Family::<metrics::PeerMessage, Counter>::default();
        let broadcast_messages = Family::<metrics::Message, Counter>::default();
        let notarization_latency = Histogram::new(LATENCY.into_iter());
        let finalization_latency = Histogram::new(LATENCY.into_iter());
        context.register("current_view", "current view", current_view.clone());
        context.register("tracked_views", "tracked views", tracked_views.clone());
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
                committer: cfg.committer,
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

                mailbox_receiver,

                last_finalized: 0,
                view: 0,
                views: BTreeMap::new(),

                current_view,
                tracked_views,
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
        let (digest, proposal) = round.proposal.as_ref()?;
        let notarizes = round.notarizes.get(digest)?;
        let validators = self.supervisor.participants(view)?;
        let (threshold, _) = threshold(validators)?;
        if notarizes.len() < threshold as usize {
            return None;
        }
        Some(&proposal.digest)
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
        let (threshold, _) = match threshold(validators) {
            Some(threshold) => threshold,
            None => return false,
        };
        round.nullifies.len() >= threshold as usize
    }

    fn is_finalized(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        let (digest, proposal) = round.proposal.as_ref()?;
        let finalizes = round.finalizes.get(digest)?;
        let validators = self.supervisor.participants(view)?;
        let (threshold, _) = threshold(validators)?;
        if finalizes.len() < threshold as usize {
            return None;
        }
        Some(&proposal.digest)
    }

    fn find_parent(&self) -> Result<(View, D), View> {
        let mut cursor = self.view - 1; // self.view always at least 1
        loop {
            if cursor == 0 {
                return Ok((GENESIS_VIEW, self.genesis.as_ref().unwrap().clone()));
            }

            // If have notarization, return
            let parent = self.is_notarized(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, parent.clone()));
            }

            // If have finalization, return
            //
            // We never want to build on some view less than finalized and this prevents that
            let parent = self.is_finalized(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, parent.clone()));
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
        backfiller: &mut resolver::Mailbox,
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
                let msg = wire::Voter {
                    payload: Some(wire::voter::Payload::Notarization(notarization.message)),
                }
                .encode_to_vec()
                .into();
                sender.send(Recipients::All, msg, true).await.unwrap();
                self.broadcast_messages
                    .get_or_create(&metrics::NOTARIZATION)
                    .inc();
                debug!(view = past_view, "rebroadcast entry notarization");
            } else if let Some(nullification) = self.construct_nullification(past_view, true) {
                let msg = wire::Voter {
                    payload: Some(wire::voter::Payload::Nullification(nullification)),
                }
                .encode_to_vec()
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
        let public_key = &self.crypto.public_key();
        let public_key_index = self
            .supervisor
            .is_participant(self.view, &self.crypto.public_key())
            .unwrap();
        let message = nullify_message(self.view);
        let null = wire::Nullify {
            view: self.view,
            signature: Some(wire::Signature {
                public_key: public_key_index,
                signature: self
                    .crypto
                    .sign(Some(&self.nullify_namespace), &message)
                    .to_vec(),
            }),
        };

        // Handle the nullify
        self.handle_nullify(public_key, null.clone()).await;

        // Sync the journal
        self.journal
            .as_mut()
            .unwrap()
            .sync(self.view)
            .await
            .expect("unable to sync journal");

        // Broadcast nullify
        let msg = wire::Voter {
            payload: Some(wire::voter::Payload::Nullify(null)),
        }
        .encode_to_vec()
        .into();
        sender.send(Recipients::All, msg, true).await.unwrap();
        self.broadcast_messages
            .get_or_create(&metrics::NULLIFY)
            .inc();
        debug!(view = self.view, "broadcasted nullify");
    }

    async fn nullify(&mut self, nullify: wire::Nullify) {
        // Ensure we are in the right view to process this message
        if !self.interesting(nullify.view, false) {
            return;
        }

        // Parse signature
        let Some(signature) = nullify.signature.as_ref() else {
            return;
        };

        // Verify that signer is a validator
        let Some(participants) = self.supervisor.participants(nullify.view) else {
            return;
        };
        let Ok(public_key_index) = usize::try_from(signature.public_key) else {
            return;
        };
        let Some(public_key) = participants.get(public_key_index).cloned() else {
            return;
        };

        // Verify the signature
        let nullify_message = nullify_message(nullify.view);
        let Ok(signature) = C::Signature::try_from(&signature.signature) else {
            return;
        };
        if !C::verify(
            Some(&self.nullify_namespace),
            &nullify_message,
            &public_key,
            &signature,
        ) {
            return;
        }

        // Handle nullify
        self.handle_nullify(&public_key, nullify).await;
    }

    async fn handle_nullify(&mut self, public_key: &C::PublicKey, nullify: wire::Nullify) {
        // Check to see if nullify is for proposal in view
        let view = nullify.view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));

        // Handle nullify
        let nullify_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Nullify(nullify.clone())),
        }
        .encode_to_vec()
        .into();
        if round.add_verified_nullify(public_key, nullify).await && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, nullify_bytes)
                .await
                .expect("unable to append nullify");
        }
    }

    async fn our_proposal(
        &mut self,
        proposal_digest: Sha256Digest,
        proposal: Parsed<wire::Proposal, D>,
    ) -> bool {
        // Store the proposal
        let round = self
            .views
            .get_mut(&proposal.message.view)
            .expect("view missing");

        // Check if view timed out
        if round.broadcast_nullify {
            debug!(
                view = proposal.message.view,
                reason = "view timed out",
                "dropping our proposal"
            );
            return false;
        }

        // Store the proposal
        debug!(
            view = proposal.message.view,
            parent = proposal.message.parent,
            digest = ?proposal_digest,
            "generated proposal"
        );
        round.proposal = Some((proposal_digest, proposal));
        round.verified_proposal = true;
        round.leader_deadline = None;
        true
    }

    // Attempt to set proposal from each message received over the wire
    async fn peer_proposal(&mut self) -> Option<(Context<D>, oneshot::Receiver<bool>)> {
        // Get round
        let (proposal_digest, proposal) = {
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
            let proposal_digest = round.notaries.get(&leader_index)?;
            let notarize = round.notarizes.get(proposal_digest)?.get(&leader_index)?;
            let proposal = notarize.message.proposal.as_ref()?;

            // Check parent validity
            if proposal.view <= proposal.parent {
                return None;
            }
            if proposal.parent < self.last_finalized {
                return None;
            }
            (
                proposal_digest,
                Parsed {
                    message: proposal.clone(),
                    digest: notarize.digest.clone(),
                },
            )
        };

        // Ensure we have required notarizations
        let mut cursor = match self.view {
            0 => {
                return None;
            }
            _ => self.view - 1,
        };
        let parent_payload = loop {
            if cursor == proposal.message.parent {
                // Check if first block
                if proposal.message.parent == GENESIS_VIEW {
                    break self.genesis.as_ref().unwrap().clone();
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
                break parent_proposal.clone();
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
        debug!(
            view = proposal.message.view,
            digest = ?proposal_digest,
            payload = ?proposal.digest,
            "requested proposal verification",
        );
        let context = Context {
            view: proposal.message.view,
            parent: (proposal.message.parent, parent_payload),
        };
        let payload = proposal.digest.clone();
        let round_proposal = Some((proposal_digest.clone(), proposal));
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
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));
        round.leader_deadline = Some(self.context.current() + self.leader_timeout);
        round.advance_deadline = Some(self.context.current() + self.notarization_timeout);
        self.view = view;
        info!(view, "entered view");

        // Check if we should fast exit this view
        let leader = round.leader.clone();
        if view < self.activity_timeout || leader == self.crypto.public_key() {
            // Don't fast exit the view
            return;
        }
        let mut next = view - 1;
        while next > view - self.activity_timeout {
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
            if round.notaries.contains_key(&leader_index)
                || round.nullifies.contains_key(&leader_index)
            {
                return;
            }
            next -= 1;
        }

        // Reduce leader deadline to now
        debug!(view, ?leader, "skipping leader timeout due to inactivity");
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
    }

    async fn notarize(&mut self, notarize: wire::Notarize) {
        // Extract proposal
        let Some(proposal) = notarize.proposal.as_ref() else {
            return;
        };

        // Ensure we are in the right view to process this message
        if !self.interesting(proposal.view, false) {
            return;
        }

        // Ensure digest is well-formed
        let Ok(payload) = D::try_from(&proposal.payload) else {
            return;
        };

        // Parse signature
        let Some(signature) = notarize.signature.as_ref() else {
            return;
        };

        // Verify that signer is a validator
        let Some(participants) = self.supervisor.participants(proposal.view) else {
            return;
        };
        let Ok(public_key_index) = usize::try_from(signature.public_key) else {
            return;
        };
        let Some(public_key) = participants.get(public_key_index).cloned() else {
            return;
        };

        // Verify the signature
        let Ok(signature) = C::Signature::try_from(&signature.signature) else {
            return;
        };
        let notarize_message = proposal_message(proposal.view, proposal.parent, &payload);
        if !C::verify(
            Some(&self.notarize_namespace),
            &notarize_message,
            &public_key,
            &signature,
        ) {
            return;
        }

        // Handle notarize
        self.handle_notarize(
            &public_key,
            Parsed {
                message: notarize,
                digest: payload,
            },
        )
        .await;
    }

    async fn handle_notarize(
        &mut self,
        public_key: &C::PublicKey,
        notarize: Parsed<wire::Notarize, D>,
    ) {
        // Check to see if notarize is for proposal in view
        let view = notarize.message.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));

        // Handle notarize
        let notarize_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Notarize(notarize.message.clone())),
        }
        .encode_to_vec()
        .into();
        if round.add_verified_notarize(public_key, notarize).await && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, notarize_bytes)
                .await
                .expect("unable to append to journal");
        }
    }

    async fn notarization(&mut self, notarization: wire::Notarization) {
        // Extract proposal
        let Some(proposal) = &notarization.proposal else {
            return;
        };

        // Check if we are still in a view where this notarization could help
        if !self.interesting(proposal.view, true) {
            return;
        }

        // Ensure digest is well-formed
        let Ok(payload) = D::try_from(&proposal.payload) else {
            return;
        };

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&proposal.view) {
            if round.broadcast_notarization {
                return;
            }
        }

        // Verify notarization
        if !verify_notarization::<S, C, D>(
            &self.supervisor,
            &self.notarize_namespace,
            &notarization,
        ) {
            return;
        }

        // Handle notarization
        self.handle_notarization(Parsed {
            message: notarization,
            digest: payload,
        })
        .await;
    }

    async fn handle_notarization(&mut self, notarization: Parsed<wire::Notarization, D>) {
        // Add signatures to view (needed to broadcast notarization if we get proposal)
        let view = notarization.message.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));
        let validators = self.supervisor.participants(view).unwrap();
        for signature in &notarization.message.signatures {
            let notarize = wire::Notarize {
                proposal: Some(notarization.message.proposal.as_ref().unwrap().clone()),
                signature: Some(signature.clone()),
            };
            let notarize_bytes = wire::Voter {
                payload: Some(wire::voter::Payload::Notarize(notarize.clone())),
            }
            .encode_to_vec()
            .into();
            let public_key = validators.get(signature.public_key as usize).unwrap();
            if round
                .add_verified_notarize(
                    public_key,
                    Parsed {
                        message: notarize,
                        digest: notarization.digest.clone(),
                    },
                )
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

        // Clear leader and advance deadlines (if they exist)
        round.leader_deadline = None;
        round.advance_deadline = None;

        // If proposal is missing, set it
        if round.proposal.is_none() {
            let proposal = notarization.message.proposal.unwrap();
            let message = proposal_message(proposal.view, proposal.parent, &notarization.digest);
            let proposal_digest = hash(&message);
            debug!(
                view = proposal.view,
                digest = ?proposal_digest,
                payload = ?notarization.digest,
                "setting unverified proposal in notarization"
            );
            round.proposal = Some((
                proposal_digest,
                Parsed {
                    message: proposal,
                    digest: notarization.digest,
                },
            ));
        }

        // Enter next view
        self.enter_view(view + 1);
    }

    async fn nullification(&mut self, nullification: wire::Nullification) {
        // Check if we are still in a view where this notarization could help
        if !self.interesting(nullification.view, true) {
            return;
        }

        // Determine if we already broadcast nullification for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&nullification.view) {
            if round.broadcast_nullification {
                return;
            }
        }

        // Verify nullification
        if !verify_nullification::<S, C>(&self.supervisor, &self.nullify_namespace, &nullification)
        {
            return;
        }

        // Handle notarization
        self.handle_nullification(nullification).await;
    }

    async fn handle_nullification(&mut self, nullification: wire::Nullification) {
        // Add signatures to view (needed to broadcast notarization if we get proposal)
        let round = self.views.entry(nullification.view).or_insert_with(|| {
            Round::new(
                self.context.current(),
                self.supervisor.clone(),
                nullification.view,
            )
        });
        let validators = self.supervisor.participants(nullification.view).unwrap();
        for signature in &nullification.signatures {
            let nullify = wire::Nullify {
                view: nullification.view,
                signature: Some(signature.clone()),
            };
            let nullify_bytes = wire::Voter {
                payload: Some(wire::voter::Payload::Nullify(nullify.clone())),
            }
            .encode_to_vec()
            .into();
            let public_key = validators.get(signature.public_key as usize).unwrap();
            if round.add_verified_nullify(public_key, nullify).await && self.journal.is_some() {
                self.journal
                    .as_mut()
                    .unwrap()
                    .append(nullification.view, nullify_bytes)
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

    async fn finalize(&mut self, finalize: wire::Finalize) {
        // Extract proposal
        let Some(proposal) = finalize.proposal.as_ref() else {
            return;
        };

        // Ensure we are in the right view to process this message
        if !self.interesting(proposal.view, false) {
            return;
        }

        // Ensure digest is well-formed
        let Ok(payload) = D::try_from(&proposal.payload) else {
            return;
        };

        // Parse signature
        let Some(signature) = finalize.signature.as_ref() else {
            return;
        };

        // Verify that signer is a validator
        let Some(participants) = self.supervisor.participants(proposal.view) else {
            return;
        };
        let Ok(public_key_index) = usize::try_from(signature.public_key) else {
            return;
        };
        let Some(public_key) = participants.get(public_key_index).cloned() else {
            return;
        };

        // Verify the signature
        let Ok(signature) = C::Signature::try_from(&signature.signature) else {
            return;
        };
        let finalize_message = proposal_message(proposal.view, proposal.parent, &payload);
        if !C::verify(
            Some(&self.finalize_namespace),
            &finalize_message,
            &public_key,
            &signature,
        ) {
            return;
        }

        // Handle finalize
        self.handle_finalize(
            &public_key,
            Parsed {
                message: finalize,
                digest: payload,
            },
        )
        .await;
    }

    async fn handle_finalize(
        &mut self,
        public_key: &C::PublicKey,
        finalize: Parsed<wire::Finalize, D>,
    ) {
        // Get view for finalize
        let view = finalize.message.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));

        // Handle finalize
        let finalize_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Finalize(finalize.message.clone())),
        }
        .encode_to_vec()
        .into();
        if round.add_verified_finalize(public_key, finalize).await && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, finalize_bytes)
                .await
                .expect("unable to append to journal");
        }
    }

    async fn finalization(&mut self, finalization: wire::Finalization) {
        // Extract proposal
        let Some(proposal) = &finalization.proposal else {
            return;
        };

        // Check if we are still in a view where this finalization could help
        if !self.interesting(proposal.view, true) {
            return;
        }

        // Ensure digest is well-formed
        let Ok(payload) = D::try_from(&proposal.payload) else {
            return;
        };

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&proposal.view) {
            if round.broadcast_finalization {
                return;
            }
        }

        // Verify finalization
        if !verify_finalization::<S, C, D>(
            &self.supervisor,
            &self.finalize_namespace,
            &finalization,
        ) {
            return;
        }

        // Process finalization
        self.handle_finalization(Parsed {
            message: finalization,
            digest: payload,
        })
        .await;
    }

    async fn handle_finalization(&mut self, finalization: Parsed<wire::Finalization, D>) {
        // Add signatures to view (needed to broadcast finalization if we get proposal)
        let view = finalization.message.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));
        let validators = self.supervisor.participants(view).unwrap();
        for signature in finalization.message.signatures.iter() {
            let finalize = wire::Finalize {
                proposal: Some(finalization.message.proposal.as_ref().unwrap().clone()),
                signature: Some(signature.clone()),
            };
            let finalize_bytes = wire::Voter {
                payload: Some(wire::voter::Payload::Finalize(finalize.clone())),
            }
            .encode_to_vec()
            .into();
            let public_key = validators.get(signature.public_key as usize).unwrap();
            if round
                .add_verified_finalize(
                    public_key,
                    Parsed {
                        message: finalize,
                        digest: finalization.digest.clone(),
                    },
                )
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

        // If proposal is missing, set it
        if round.proposal.is_none() {
            let proposal = finalization.message.proposal.unwrap();
            let message = proposal_message(proposal.view, proposal.parent, &finalization.digest);
            let proposal_digest = hash(&message);
            debug!(
                view = proposal.view,
                digest = ?proposal_digest,
                payload = ?finalization.digest,
                "setting unverified proposal in finalization"
            );
            round.proposal = Some((
                proposal_digest,
                Parsed {
                    message: proposal,
                    digest: finalization.digest,
                },
            ));
        }

        // Track view finalized
        if view > self.last_finalized {
            self.last_finalized = view;
        }

        // Enter next view
        self.enter_view(view + 1);
    }

    fn construct_notarize(&mut self, view: u64) -> Option<Parsed<wire::Notarize, D>> {
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
        let public_key = self
            .supervisor
            .is_participant(view, &self.crypto.public_key())?;
        let proposal = &round.proposal.as_ref().unwrap().1;
        let message = proposal_message(
            proposal.message.view,
            proposal.message.parent,
            &proposal.digest,
        );
        round.broadcast_notarize = true;
        Some(Parsed {
            message: wire::Notarize {
                proposal: Some(proposal.message.clone()),
                signature: Some(wire::Signature {
                    public_key,
                    signature: self
                        .crypto
                        .sign(Some(&self.notarize_namespace), &message)
                        .to_vec(),
                }),
            },
            digest: proposal.digest.clone(),
        })
    }

    fn construct_notarization(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Parsed<wire::Notarization, D>> {
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
        let (proposal, notarizes) = round.notarizable(threshold, force)?;

        // Construct notarization
        let mut payload = None;
        let mut signatures = Vec::new();
        for validator in 0..(validators.len() as u32) {
            if let Some(notarize) = notarizes.get(&validator) {
                payload = Some(notarize.digest.clone());
                signatures.push(notarize.message.signature.clone().unwrap());
            }
        }
        let notarization = wire::Notarization {
            proposal: Some(proposal),
            signatures,
        };
        Some(Parsed {
            message: notarization,
            digest: payload.unwrap(),
        })
    }

    fn construct_nullification(&mut self, view: u64, force: bool) -> Option<wire::Nullification> {
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
        let mut signatures = Vec::new();
        for validator in 0..(validators.len() as u32) {
            if let Some(nullify) = nullifies.get(&validator) {
                signatures.push(nullify.signature.clone().unwrap());
            }
        }
        Some(wire::Nullification { view, signatures })
    }

    fn construct_finalize(&mut self, view: u64) -> Option<Parsed<wire::Finalize, D>> {
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
        let proposal = match &round.proposal {
            Some((_, proposal)) => proposal,
            None => {
                return None;
            }
        };
        let public_key = self
            .supervisor
            .is_participant(view, &self.crypto.public_key())?;
        let message = proposal_message(view, proposal.message.parent, &proposal.digest);
        round.broadcast_finalize = true;
        Some(Parsed {
            message: wire::Finalize {
                proposal: Some(proposal.message.clone()),
                signature: Some(wire::Signature {
                    public_key,
                    signature: self
                        .crypto
                        .sign(Some(&self.finalize_namespace), &message)
                        .to_vec(),
                }),
            },
            digest: proposal.digest.clone(),
        })
    }

    fn construct_finalization(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Parsed<wire::Finalization, D>> {
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
        let (proposal, finalizes) = round.finalizable(threshold, force)?;

        // Construct finalization
        let mut payload = None;
        let mut signatures = Vec::new();
        for validator in 0..(validators.len() as u32) {
            if let Some(finalize) = finalizes.get(&validator) {
                payload = Some(finalize.digest.clone());
                signatures.push(finalize.message.signature.clone().unwrap());
            }
        }
        let finalization = wire::Finalization {
            proposal: Some(proposal),
            signatures,
        };
        Some(Parsed {
            message: finalization,
            digest: payload.unwrap(),
        })
    }

    async fn notify(
        &mut self,
        backfiller: &mut resolver::Mailbox,
        sender: &mut impl Sender,
        view: u64,
    ) {
        // Attempt to notarize
        if let Some(notarize) = self.construct_notarize(view) {
            // Handle the notarize
            self.handle_notarize(&self.crypto.public_key(), notarize.clone())
                .await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the notarize
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Notarize(notarize.message)),
            }
            .encode_to_vec()
            .into();
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
            backfiller.notarized(notarization.message.clone()).await;

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
            let validators = self.supervisor.participants(view).unwrap();
            let proposal = notarization.message.proposal.as_ref().unwrap();
            let mut signatures = Vec::with_capacity(notarization.message.signatures.len());
            for signature in &notarization.message.signatures {
                let public_key = validators.get(signature.public_key as usize).unwrap();
                let signature = C::Signature::try_from(&signature.signature).unwrap();
                signatures.push((public_key, signature));
            }
            let proof = Prover::<C, D>::serialize_aggregation(proposal, signatures);
            self.committer.prepared(proof, notarization.digest).await;

            // Broadcast the notarization
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Notarization(notarization.message)),
            }
            .encode_to_vec()
            .into();
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
            self.handle_nullification(nullification.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the nullification
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Nullification(nullification)),
            }
            .encode_to_vec()
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
                        let msg = wire::Voter {
                            payload: Some(wire::voter::Payload::Finalization(finalization.message)),
                        }
                        .encode_to_vec()
                        .into();
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
            self.handle_finalize(&self.crypto.public_key(), finalize.clone())
                .await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the finalize
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Finalize(finalize.message)),
            }
            .encode_to_vec()
            .into();
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
            self.handle_finalization(finalization.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Alert application
            let validators = self.supervisor.participants(view).unwrap();
            let proposal = finalization.message.proposal.as_ref().unwrap();
            let mut signatures = Vec::with_capacity(finalization.message.signatures.len());
            for signature in &finalization.message.signatures {
                let public_key = validators.get(signature.public_key as usize).unwrap();
                let signature = C::Signature::try_from(&signature.signature).unwrap();
                signatures.push((public_key, signature));
            }
            let proof = Prover::<C, D>::serialize_aggregation(proposal, signatures);
            self.committer.finalized(proof, finalization.digest).await;

            // Broadcast the finalization
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Finalization(finalization.message)),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::FINALIZATION)
                .inc();
        };
    }

    pub fn start(
        self,
        backfiller: resolver::Mailbox,
        sender: impl Sender,
        receiver: impl Receiver,
    ) -> Handle<()> {
        self.context
            .clone()
            .spawn(|_| self.run(backfiller, sender, receiver))
    }

    async fn run(
        mut self,
        mut backfiller: resolver::Mailbox,
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
                let msg = wire::Voter::decode(msg).expect("journal message is unexpected format");
                let msg = msg.payload.expect("missing payload");
                match msg {
                    wire::voter::Payload::Notarize(notarize) => {
                        // Handle notarize
                        let proposal = notarize.proposal.as_ref().unwrap().clone();
                        let payload = D::try_from(&proposal.payload).unwrap();
                        let public_key = notarize.signature.as_ref().unwrap().public_key;
                        let public_key = self
                            .supervisor
                            .participants(proposal.view)
                            .unwrap()
                            .get(public_key as usize)
                            .unwrap()
                            .clone();
                        self.handle_notarize(
                            &public_key,
                            Parsed {
                                message: notarize,
                                digest: payload.clone(),
                            },
                        )
                        .await;

                        // Update round info
                        if public_key == self.crypto.public_key() {
                            observed_view = max(observed_view, proposal.view);
                            let round = self.views.get_mut(&proposal.view).expect("missing round");
                            let proposal_message =
                                proposal_message(proposal.view, proposal.parent, &payload);
                            let proposal_digest = hash(&proposal_message);
                            round.proposal = Some((
                                proposal_digest,
                                Parsed {
                                    message: proposal,
                                    digest: payload,
                                },
                            ));
                            round.verified_proposal = true;
                            round.broadcast_notarize = true;
                        }
                    }
                    wire::voter::Payload::Nullify(nullify) => {
                        // Handle nullify
                        let view = nullify.view;
                        let public_key = nullify.signature.as_ref().unwrap().public_key;
                        let public_key = self
                            .supervisor
                            .participants(view)
                            .unwrap()
                            .get(public_key as usize)
                            .unwrap()
                            .clone();
                        self.handle_nullify(&public_key, nullify).await;

                        // Update round info
                        if public_key == self.crypto.public_key() {
                            observed_view = max(observed_view, view);
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_nullify = true;
                        }
                    }
                    wire::voter::Payload::Finalize(finalize) => {
                        // Handle finalize
                        let proposal = finalize.proposal.as_ref().unwrap();
                        let view = proposal.view;
                        let payload = D::try_from(&proposal.payload).unwrap();
                        let public_key = finalize.signature.as_ref().unwrap().public_key;
                        let public_key = self
                            .supervisor
                            .participants(view)
                            .unwrap()
                            .get(public_key as usize)
                            .unwrap()
                            .clone();
                        self.handle_finalize(
                            &public_key,
                            Parsed {
                                message: finalize,
                                digest: payload,
                            },
                        )
                        .await;

                        // Update round info
                        //
                        // If we are sending a finalize message, we must be in the next view
                        if public_key == self.crypto.public_key() {
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
                    let message = proposal_message(context.view, context.parent.0, &proposed);
                    let proposal_digest = hash(&message);
                    let proposal = wire::Proposal {
                        view: context.view,
                        parent: context.parent.0,
                        payload: proposed.to_vec(),
                    };
                    if !self.our_proposal(proposal_digest, Parsed{
                        message: proposal.clone(),
                        digest: proposed.clone(),
                    }).await {
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
                    let msg = mailbox.unwrap();
                    match msg {
                        Message::Notarization{ notarization }  => {
                            view = notarization.message.proposal.as_ref().unwrap().view;
                            self.handle_notarization(notarization).await;
                        },
                        Message::Nullification { nullification } => {
                            view = nullification.view;
                            self.handle_nullification(nullification).await;
                        },
                    }
                },
                msg = receiver.recv() => {
                    // Parse message
                    let Ok((s, msg)) = msg else {
                        break;
                    };
                    let Ok(msg) = wire::Voter::decode(msg) else {
                        continue;
                    };
                    let Some(payload) = msg.payload else {
                        continue;
                    };

                    // Process message
                    match payload {
                        wire::voter::Payload::Notarize(notarize) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::notarize(&s)).inc();
                            view = match &notarize.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    continue;
                                }
                            };
                            self.notarize(notarize).await;
                        }
                        wire::voter::Payload::Notarization(notarization) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::notarization(&s)).inc();
                            view = match &notarization.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    continue;
                                }
                            };
                            self.notarization(notarization).await;
                        }
                        wire::voter::Payload::Nullify(nullify) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::nullify(&s)).inc();
                            view = nullify.view;
                            self.nullify(nullify).await;
                        }
                        wire::voter::Payload::Nullification(nullification) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::nullification(&s)).inc();
                            view = nullification.view;
                            self.nullification(nullification).await;
                        }
                        wire::voter::Payload::Finalize(finalize) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::finalize(&s)).inc();
                            view = match &finalize.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    continue;
                                }
                            };
                            self.finalize(finalize).await;
                        }
                        wire::voter::Payload::Finalization(finalization) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::finalization(&s)).inc();
                            view = match &finalization.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    continue;
                                }
                            };
                            self.finalization(finalization).await;
                        }
                    };
                },
            };

            // Attempt to send any new view messages
            self.notify(&mut backfiller, &mut sender, view).await;

            // After sending all required messages, prune any views
            // we no longer need
            self.prune_views().await;

            // Update metrics
            self.current_view.set(view as i64);
            self.tracked_views.set(self.views.len() as i64);
        }
    }
}
