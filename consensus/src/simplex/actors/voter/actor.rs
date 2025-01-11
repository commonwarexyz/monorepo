use super::{Config, Mailbox, Message};
use crate::{
    simplex::{
        actors::resolver,
        encoder::{
            finalize_namespace, notarize_namespace, nullify_message, nullify_namespace,
            proposal_message, seed_message, seed_namespace,
        },
        metrics,
        prover::Prover,
        verifier::{threshold, verify_finalization, verify_notarization, verify_nullification},
        wire, Context, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE, NOTARIZE,
        NULLIFY_AND_FINALIZE,
    },
    Automaton, Committer, Relay, ThresholdSupervisor,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops,
        poly::{self, Eval},
    },
    Digest, Hasher, PublicKey, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Blob, Clock, Spawner, Storage};
use commonware_storage::journal::Journal;
use commonware_utils::{hex, quorum};
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    pin_mut, StreamExt,
};
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};
use prost::Message as _;
use rand::Rng;
use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, SystemTime},
};
use std::{marker::PhantomData, sync::atomic::AtomicI64};
use tracing::{debug, info, trace, warn};

const GENESIS_VIEW: View = 0;

struct Round<
    C: Scheme,
    H: Hasher,
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    hasher: H,
    supervisor: S,
    _crypto: PhantomData<C>,

    leader: Option<PublicKey>,

    view: View,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,

    // Track one proposal per view
    proposal: Option<(Digest /* proposal */, wire::Proposal)>,
    requested_proposal: bool,
    verified_proposal: bool,

    // Track notarizes for all proposals (ensuring any participant only has one recorded notarize)
    notaries: HashMap<u32, Digest>,
    notarizes: HashMap<Digest, HashMap<u32, wire::Notarize>>,
    notarization: Option<wire::Notarization>,
    broadcast_notarize: bool,
    broadcast_notarization: bool,

    nullifies: HashMap<u32, wire::Nullify>,
    nullification: Option<wire::Nullification>,
    broadcast_nullify: bool,
    broadcast_nullification: bool,

    // Track finalizes for all proposals (ensuring any participant only has one recorded finalize)
    finalizers: HashMap<u32, Digest>,
    finalizes: HashMap<Digest, HashMap<u32, wire::Finalize>>,
    finalization: Option<wire::Finalization>,
    broadcast_finalize: bool,
    broadcast_finalization: bool,
}

impl<
        C: Scheme,
        H: Hasher,
        S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
    > Round<C, H, S>
{
    pub fn new(hasher: H, supervisor: S, view: View) -> Self {
        Self {
            hasher,
            supervisor,
            _crypto: PhantomData,

            view,
            leader: None,
            leader_deadline: None,
            advance_deadline: None,
            nullify_retry: None,

            requested_proposal: false,
            proposal: None,
            verified_proposal: false,

            notaries: HashMap::new(),
            notarizes: HashMap::new(),
            notarization: None,
            broadcast_notarize: false,
            broadcast_notarization: false,

            nullifies: HashMap::new(),
            nullification: None,
            broadcast_nullify: false,
            broadcast_nullification: false,

            finalizers: HashMap::new(),
            finalizes: HashMap::new(),
            finalization: None,
            broadcast_finalize: false,
            broadcast_finalization: false,
        }
    }

    pub fn set_leader(&mut self, seed: group::Signature) {
        let leader = ThresholdSupervisor::leader(&self.supervisor, seed, self.view).unwrap();
        self.leader = Some(leader);
    }

    async fn add_verified_notarize(
        &mut self,
        public_key_index: u32,
        notarize: wire::Notarize,
    ) -> bool {
        // Get proposal
        let proposal = notarize.proposal.as_ref().unwrap();

        // Compute proposal digest
        let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
        self.hasher.update(&message);
        let digest = self.hasher.finalize();

        // Check if already notarized
        if let Some(previous_notarize) = self.notaries.get(&public_key_index) {
            if previous_notarize == &digest {
                trace!(
                    view = self.view,
                    signer = public_key_index,
                    previous_notarize = hex(previous_notarize),
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
            let previous_proposal = previous_notarize.proposal.as_ref().unwrap();
            let proof = Prover::<H>::serialize_conflicting_notarize(
                self.view,
                previous_proposal.parent,
                &previous_proposal.payload,
                &previous_notarize.signature,
                proposal.parent,
                &proposal.payload,
                &notarize.signature,
            );
            self.supervisor.report(CONFLICTING_NOTARIZE, proof).await;
            warn!(
                view = self.view,
                signer = public_key_index,
                activity = CONFLICTING_NOTARIZE,
                "recorded fault"
            );
            return false;
        }

        // Store the notarize
        if self
            .notaries
            .insert(public_key_index, digest.clone())
            .is_some()
        {
            return false;
        }
        let entry = self.notarizes.entry(digest).or_default();
        let proof = Prover::<H>::serialize_proposal(proposal, &notarize.signature);
        entry.insert(public_key_index, notarize);
        self.supervisor.report(NOTARIZE, proof).await;
        true
    }

    async fn add_verified_nullify(
        &mut self,
        public_key_index: u32,
        nullify: wire::Nullify,
    ) -> bool {
        // Check if already issued finalize
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
        let finalize_proposal = finalize.proposal.as_ref().unwrap();
        let proof = Prover::<H>::serialize_nullify_finalize(
            self.view,
            finalize_proposal.parent,
            &finalize_proposal.payload,
            &finalize.signature,
            &nullify.signature,
        );
        self.supervisor.report(NULLIFY_AND_FINALIZE, proof).await;
        warn!(
            view = self.view,
            signer = public_key_index,
            activity = NULLIFY_AND_FINALIZE,
            "recorded fault"
        );
        false
    }

    fn notarizable(&mut self, threshold: u32, force: bool) -> Option<wire::Notarization> {
        if !force && (self.broadcast_notarization || self.broadcast_nullification) {
            // We want to broadcast a notarization, even if we haven't yet verified a proposal.
            return None;
        }
        if let Some(notarization) = &self.notarization {
            self.broadcast_notarization = true;
            return Some(notarization.clone());
        }
        for (proposal, notarizes) in self.notarizes.iter() {
            if (notarizes.len() as u32) < threshold {
                continue;
            }

            // There should never exist enough notarizes for multiple proposals, so it doesn't
            // matter which one we choose.
            debug!(
                view = self.view,
                proposal = hex(proposal),
                verified = self.verified_proposal,
                "broadcasting notarization"
            );

            // Grab the proposal
            let proposal = notarizes
                .values()
                .next()
                .unwrap()
                .proposal
                .as_ref()
                .unwrap()
                .clone();

            // Recover threshold signature
            let mut notarization = Vec::new();
            let mut seed = Vec::new();
            for notarize in notarizes.values() {
                let eval = Eval::deserialize(&notarize.signature).unwrap();
                notarization.push(eval);
                let eval = Eval::deserialize(&notarize.seed).unwrap();
                seed.push(eval);
            }
            let signature = ops::threshold_signature_recover(threshold, notarization).unwrap();
            let signature = signature.serialize();
            let seed = ops::threshold_signature_recover(threshold, seed).unwrap();
            let seed = seed.serialize();

            // Construct notarization
            let notarization = wire::Notarization {
                proposal: Some(proposal.clone()),
                signature: signature.into(),
                seed: seed.into(),
            };
            self.notarization = Some(notarization.clone());
            self.broadcast_notarization = true;
            return Some(notarization);
        }
        None
    }

    fn nullifiable(&mut self, threshold: u32, force: bool) -> Option<wire::Nullification> {
        if !force && (self.broadcast_nullification || self.broadcast_notarization) {
            return None;
        }
        if let Some(nullification) = &self.nullification {
            self.broadcast_nullification = true;
            return Some(nullification.clone());
        }
        if (self.nullifies.len() as u32) < threshold {
            return None;
        }

        debug!(view = self.view, "broadcasting nullification");

        // Recover threshold signature
        let mut nullification = Vec::new();
        let mut seed = Vec::new();
        for nullify in self.nullifies.values() {
            let eval = Eval::deserialize(&nullify.signature).unwrap();
            nullification.push(eval);
            let eval = Eval::deserialize(&nullify.seed).unwrap();
            seed.push(eval);
        }
        let signature = ops::threshold_signature_recover(threshold, nullification).unwrap();
        let signature = signature.serialize();
        let seed = ops::threshold_signature_recover(threshold, seed).unwrap();
        let seed = seed.serialize();

        // Construct nullification
        let nullification = wire::Nullification {
            view: self.view,
            signature: signature.into(),
            seed: seed.into(),
        };
        self.nullification = Some(nullification.clone());
        self.broadcast_nullification = true;
        Some(nullification)
    }

    async fn add_verified_finalize(
        &mut self,
        public_key_index: u32,
        finalize: wire::Finalize,
    ) -> bool {
        // Check if also issued nullify
        let proposal = finalize.proposal.as_ref().unwrap();
        let null = self.nullifies.get(&public_key_index);
        if let Some(null) = null {
            // Create fault
            let proof = Prover::<H>::serialize_nullify_finalize(
                self.view,
                proposal.parent,
                &proposal.payload,
                &finalize.signature,
                &null.signature,
            );
            self.supervisor.report(NULLIFY_AND_FINALIZE, proof).await;
            warn!(
                view = self.view,
                signer = public_key_index,
                activity = NULLIFY_AND_FINALIZE,
                "recorded fault"
            );
            return false;
        }
        // Compute proposal digest
        let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
        self.hasher.update(&message);
        let digest = self.hasher.finalize();

        // Check if already finalized
        if let Some(previous_finalize) = self.finalizers.get(&public_key_index) {
            if previous_finalize == &digest {
                trace!(
                    view = self.view,
                    signer = public_key_index,
                    previous_finalize = hex(previous_finalize),
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
            let previous_proposal = previous_finalize.proposal.as_ref().unwrap();
            let proof = Prover::<H>::serialize_conflicting_finalize(
                self.view,
                previous_proposal.parent,
                &previous_proposal.payload,
                &previous_finalize.signature,
                proposal.parent,
                &proposal.payload,
                &finalize.signature,
            );
            self.supervisor.report(CONFLICTING_FINALIZE, proof).await;
            warn!(
                view = self.view,
                signer = public_key_index,
                activity = CONFLICTING_FINALIZE,
                "recorded fault"
            );
            return false;
        }

        // Store the finalize
        if self
            .finalizers
            .insert(public_key_index, digest.clone())
            .is_some()
        {
            return false;
        }
        let entry = self.finalizes.entry(digest).or_default();
        let signature = &finalize.signature;
        let proof = Prover::<H>::serialize_proposal(proposal, signature);
        entry.insert(public_key_index, finalize);
        self.supervisor.report(FINALIZE, proof).await;
        true
    }

    fn finalizable(&mut self, threshold: u32, force: bool) -> Option<wire::Finalization> {
        if !force && self.broadcast_finalization {
            // We want to broadcast a finalization, even if we haven't yet verified a proposal.
            return None;
        }
        if let Some(finalization) = &self.finalization {
            self.broadcast_finalization = true;
            return Some(finalization.clone());
        }
        for (proposal, finalizes) in self.finalizes.iter() {
            if (finalizes.len() as u32) < threshold {
                continue;
            }

            // Ensure we have a notarization
            let Some(notarization) = &self.notarization else {
                continue;
            };
            let seed = notarization.seed.clone();

            // There should never exist enough finalizes for multiple proposals, so it doesn't
            // matter which one we choose.
            debug!(
                view = self.view,
                proposal = hex(proposal),
                verified = self.verified_proposal,
                "broadcasting finalization"
            );

            // Grab the proposal
            let proposal = finalizes
                .values()
                .next()
                .unwrap()
                .proposal
                .as_ref()
                .unwrap()
                .clone();

            // Recover threshold signature
            let mut finalization = Vec::new();
            for finalize in finalizes.values() {
                let eval = Eval::deserialize(&finalize.signature).unwrap();
                finalization.push(eval);
            }
            let signature = ops::threshold_signature_recover(threshold, finalization).unwrap();
            let signature = signature.serialize();

            // Construct finalization
            let finalization = wire::Finalization {
                proposal: Some(proposal.clone()),
                signature: signature.into(),
                seed,
            };
            self.finalization = Some(finalization.clone());
            self.broadcast_finalization = true;
            return Some(finalization);
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
    E: Clock + Rng + Spawner + Storage<B>,
    C: Scheme,
    H: Hasher,
    A: Automaton<Context = Context>,
    R: Relay,
    F: Committer,
    S: ThresholdSupervisor<
        Identity = poly::Poly<group::Public>,
        Seed = group::Signature,
        Index = View,
        Share = group::Share,
    >,
> {
    runtime: E,
    crypto: C,
    hasher: H,
    automaton: A,
    relay: R,
    committer: F,
    supervisor: S,

    replay_concurrency: usize,
    journal: Option<Journal<B, E>>,

    genesis: Option<Digest>,

    seed_namespace: Vec<u8>,
    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    activity_timeout: View,

    mailbox_receiver: mpsc::Receiver<Message>,

    last_finalized: View,
    view: View,
    views: BTreeMap<View, Round<C, H, S>>,

    current_view: Gauge,
    tracked_views: Gauge,
    received_messages: Family<metrics::PeerMessage, Counter>,
    broadcast_messages: Family<metrics::Message, Counter>,
}

impl<
        B: Blob,
        E: Clock + Rng + Spawner + Storage<B>,
        C: Scheme, // TODO: changing share over time (no longer a fixed value) -> need to determine which index we are in the identity
        H: Hasher,
        A: Automaton<Context = Context>,
        R: Relay,
        F: Committer,
        S: ThresholdSupervisor<
            Identity = poly::Poly<group::Public>,
            Seed = group::Signature,
            Index = View,
            Share = group::Share,
        >,
        // TODO: can use participants to perform basic check + verify index associated with right participant before verification + track invalid signatures using partial and group polynomial (only way to verify correct signature) + Seed will just be seed signature (separate from notarization/finalization) + need polynomial threshold
    > Actor<B, E, C, H, A, R, F, S>
{
    pub fn new(
        runtime: E,
        journal: Journal<B, E>,
        cfg: Config<C, H, A, R, F, S>,
    ) -> (Self, Mailbox) {
        // Assert correctness of timeouts
        if cfg.leader_timeout > cfg.notarization_timeout {
            panic!("leader timeout must be less than or equal to notarization timeout");
        }

        // Initialize metrics
        let current_view = Gauge::<i64, AtomicI64>::default();
        let tracked_views = Gauge::<i64, AtomicI64>::default();
        let received_messages = Family::<metrics::PeerMessage, Counter>::default();
        let broadcast_messages = Family::<metrics::Message, Counter>::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register("current_view", "current view", current_view.clone());
            registry.register("tracked_views", "tracked views", tracked_views.clone());
            registry.register(
                "received_messages",
                "received messages",
                received_messages.clone(),
            );
            registry.register(
                "broadcast_messages",
                "broadcast messages",
                broadcast_messages.clone(),
            );
        }

        // Initialize store
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        (
            Self {
                runtime,
                crypto: cfg.crypto,
                hasher: cfg.hasher,
                automaton: cfg.automaton,
                relay: cfg.relay,
                committer: cfg.committer,
                supervisor: cfg.supervisor,

                replay_concurrency: cfg.replay_concurrency,
                journal: Some(journal),

                genesis: None,

                seed_namespace: seed_namespace(&cfg.namespace),
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
            },
            mailbox,
        )
    }

    fn is_notarized(&self, view: View) -> Option<&wire::Proposal> {
        let round = self.views.get(&view)?;
        let (digest, proposal) = round.proposal.as_ref()?;
        let notarizes = round.notarizes.get(digest)?;
        let validators = self.supervisor.participants(view)?;
        let (threshold, _) = threshold(validators)?;
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
        let (threshold, _) = match threshold(validators) {
            Some(threshold) => threshold,
            None => return false,
        };
        round.nullifies.len() >= threshold as usize
    }

    fn is_finalized(&self, view: View) -> Option<&wire::Proposal> {
        let round = self.views.get(&view)?;
        let (digest, proposal) = round.proposal.as_ref()?;
        let finalizes = round.finalizes.get(digest)?;
        let validators = self.supervisor.participants(view)?;
        let (threshold, _) = threshold(validators)?;
        if finalizes.len() < threshold as usize {
            return None;
        }
        Some(proposal)
    }

    fn find_parent(&self) -> Result<(View, Digest), View> {
        let mut cursor = self.view - 1; // self.view always at least 1
        loop {
            if cursor == 0 {
                return Ok((GENESIS_VIEW, self.genesis.as_ref().unwrap().clone()));
            }

            // If have notarization, return
            let parent = self.is_notarized(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, parent.payload.clone()));
            }

            // If have finalization, return
            //
            // We never want to build on some view less than finalized and this prevents that
            let parent = self.is_finalized(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, parent.payload.clone()));
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
        backfiller: &mut resolver::Mailbox,
    ) -> Option<(Context, oneshot::Receiver<Digest>)> {
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
        let null_retry = self.runtime.current() + self.nullify_retry;
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
                    payload: Some(wire::voter::Payload::Notarization(notarization)),
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
        let share = self.supervisor.share(self.view).unwrap();
        let message = nullify_message(self.view);
        let signature = ops::partial_sign_message(&share, Some(&self.nullify_namespace), &message);
        let signature = signature.serialize();
        let message = seed_message(self.view);
        let seed = ops::partial_sign_message(&share, Some(&self.seed_namespace), &message);
        let seed = seed.serialize();
        let null = wire::Nullify {
            view: self.view,
            signature: signature.into(),
            seed: seed.into(),
        };

        // Handle the nullify
        self.handle_nullify(share.index, null.clone()).await;

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

    async fn nullify(&mut self, sender: &PublicKey, nullify: wire::Nullify) {
        // Ensure we are in the right view to process this message
        if !self.interesting(nullify.view, false) {
            return;
        }

        // Verify that signer is a validator
        let Some(public_key_index) = self.supervisor.is_participant(nullify.view, sender) else {
            return;
        };
        let Some((identity, _)) = self.supervisor.identity(nullify.view) else {
            return;
        };

        // Verify signature
        let Some(signature) = Eval::deserialize(&nullify.signature) else {
            return;
        };
        if signature.index != public_key_index {
            return;
        }
        let nullify_message = nullify_message(nullify.view);
        if ops::partial_verify_message(
            identity,
            Some(&self.nullify_namespace),
            &nullify_message,
            &signature,
        )
        .is_err()
        {
            return;
        }

        // Verify seed
        let Some(seed) = Eval::deserialize(&nullify.seed) else {
            return;
        };
        if seed.index != public_key_index {
            return;
        }
        let seed_message = seed_message(nullify.view);
        if ops::partial_verify_message(identity, Some(&self.seed_namespace), &seed_message, &seed)
            .is_err()
        {
            return;
        }

        // Handle nullify
        self.handle_nullify(public_key_index, nullify).await;
    }

    async fn handle_nullify(&mut self, public_key_index: u32, nullify: wire::Nullify) {
        // Check to see if nullify is for proposal in view
        let view = nullify.view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.hasher.clone(), self.supervisor.clone(), view));

        // Handle nullify
        let nullify_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Nullify(nullify.clone())),
        }
        .encode_to_vec()
        .into();
        if round.add_verified_nullify(public_key_index, nullify).await && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, nullify_bytes)
                .await
                .expect("unable to append nullify");
        }
    }

    async fn our_proposal(&mut self, digest: Digest, proposal: wire::Proposal) -> bool {
        // Store the proposal
        let round = self.views.get_mut(&proposal.view).expect("view missing");

        // Check if view timed out
        if round.broadcast_nullify {
            debug!(
                view = proposal.view,
                reason = "view timed out",
                "dropping our proposal"
            );
            return false;
        }

        // Store the proposal
        debug!(
            view = proposal.view,
            parent = proposal.parent,
            digest = hex(&digest),
            "generated proposal"
        );
        round.proposal = Some((digest, proposal));
        round.verified_proposal = true;
        round.leader_deadline = None;
        true
    }

    // Attempt to set proposal from each message received over the wire
    #[allow(clippy::question_mark)]
    async fn peer_proposal(&mut self) -> Option<(Context, oneshot::Receiver<bool>)> {
        // Get round
        let (proposal_digest, proposal) = {
            // Get view or exit
            let round = self.views.get(&self.view)?;

            // If we are the leader, drop peer proposals
            let Some(leader) = &round.leader else {
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
            let proposal_digest = round.notaries.get(&leader_index)?;
            let proposal = round
                .notarizes
                .get(proposal_digest)?
                .get(&leader_index)?
                .proposal
                .as_ref()?;

            // Check parent validity
            if proposal.view <= proposal.parent {
                return None;
            }
            if proposal.parent < self.last_finalized {
                return None;
            }
            (proposal_digest, proposal)
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
                break parent_proposal.payload.clone();
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
        let payload = proposal.payload.clone();
        debug!(
            view = proposal.view,
            digest = hex(proposal_digest),
            payload = hex(&payload),
            "requested proposal verification",
        );
        let context = Context {
            view: proposal.view,
            parent: (proposal.parent, parent_payload),
        };
        let proposal = Some((proposal_digest.clone(), proposal.clone()));
        let round = self.views.get_mut(&context.view).unwrap();
        round.proposal = proposal;
        Some((
            context.clone(),
            self.automaton.verify(context, payload.clone()).await,
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
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.hasher.clone(), self.supervisor.clone(), view));
        round.leader_deadline = Some(self.runtime.current() + self.leader_timeout);
        round.advance_deadline = Some(self.runtime.current() + self.notarization_timeout);
        round.set_leader(seed);
        self.view = view;
        info!(view, "entered view");

        // Check if we should fast exit this view
        let leader = round.leader.as_ref().unwrap().clone();
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
        debug!(
            view,
            leader = hex(&leader),
            "skipping leader timeout due to inactivity"
        );
        self.views.get_mut(&view).unwrap().leader_deadline = Some(self.runtime.current());
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

    async fn notarize(&mut self, sender: &PublicKey, notarize: wire::Notarize) {
        // Extract proposal
        let Some(proposal) = notarize.proposal.as_ref() else {
            return;
        };

        // Ensure we are in the right view to process this message
        if !self.interesting(proposal.view, false) {
            return;
        }

        // Verify that signer is a validator
        let Some(public_key_index) = self.supervisor.is_participant(proposal.view, sender) else {
            return;
        };
        let Some((identity, _)) = self.supervisor.identity(proposal.view) else {
            return;
        };

        // Verify signature
        let Some(signature) = Eval::deserialize(&notarize.signature) else {
            return;
        };
        if signature.index != public_key_index {
            return;
        }
        let notarize_message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
        if ops::partial_verify_message(
            identity,
            Some(&self.notarize_namespace),
            &notarize_message,
            &signature,
        )
        .is_err()
        {
            return;
        }

        // Verify seed
        let Some(seed) = Eval::deserialize(&notarize.seed) else {
            return;
        };
        if seed.index != public_key_index {
            return;
        }
        let seed_message = seed_message(proposal.view);
        if ops::partial_verify_message(identity, Some(&self.seed_namespace), &seed_message, &seed)
            .is_err()
        {
            return;
        }

        // Handle notarize
        self.handle_notarize(public_key_index, notarize).await;
    }

    async fn handle_notarize(&mut self, public_key_index: u32, notarize: wire::Notarize) {
        // Check to see if notarize is for proposal in view
        let view = notarize.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.hasher.clone(), self.supervisor.clone(), view));

        // Handle notarize
        let notarize_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Notarize(notarize.clone())),
        }
        .encode_to_vec()
        .into();
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

    async fn notarization(&mut self, notarization: wire::Notarization) {
        // Extract proposal
        let Some(proposal) = &notarization.proposal else {
            return;
        };

        // Check if we are still in a view where this notarization could help
        if !self.interesting(proposal.view, true) {
            return;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&proposal.view) {
            if round.broadcast_notarization {
                return;
            }
        }

        // Verify notarization
        if !verify_notarization::<S>(
            &self.supervisor,
            &self.notarize_namespace,
            &self.seed_namespace,
            &notarization,
        ) {
            return;
        }

        // Handle notarization
        self.handle_notarization(notarization).await;
    }

    async fn handle_notarization(&mut self, notarization: wire::Notarization) {
        // Create round (if it doesn't exist)
        let view = notarization.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.hasher.clone(), self.supervisor.clone(), view));

        // If already have notarization, ignore
        if round.notarization.is_some() {
            return;
        }

        // Clear leader and advance deadlines (if they exist)
        round.leader_deadline = None;
        round.advance_deadline = None;

        // If proposal is missing, set it
        if round.proposal.is_none() {
            let proposal = notarization.proposal.as_ref().unwrap().clone();
            let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
            self.hasher.update(&message);
            let digest = self.hasher.finalize();
            debug!(
                view = proposal.view,
                digest = hex(&digest),
                "setting unverified proposal in notarization"
            );
            round.proposal = Some((digest, proposal));
        }

        // Put notarization in journal
        if self.journal.is_some() {
            let notarization_bytes = wire::Voter {
                payload: Some(wire::voter::Payload::Notarization(notarization.clone())),
            }
            .encode_to_vec()
            .into();
            self.journal
                .as_mut()
                .unwrap()
                .append(view, notarization_bytes)
                .await
                .expect("unable to append to journal");
        }

        // Get seed
        let seed = group::Signature::deserialize(&notarization.seed).unwrap();

        // Store notarization
        round.notarization = Some(notarization);

        // Enter next view
        self.enter_view(view + 1, seed);
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
        if !verify_nullification::<S>(
            &self.supervisor,
            &self.nullify_namespace,
            &self.seed_namespace,
            &nullification,
        ) {
            return;
        }

        // Handle notarization
        self.handle_nullification(nullification).await;
    }

    async fn handle_nullification(&mut self, nullification: wire::Nullification) {
        // Create round (if it doesn't exist)
        let view = nullification.view;
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.hasher.clone(),
                self.supervisor.clone(),
                nullification.view,
            )
        });

        // Clear leader and advance deadlines (if they exist)
        round.leader_deadline = None;
        round.advance_deadline = None;

        // Put nullification in journal
        if self.journal.is_some() {
            let nullification_bytes = wire::Voter {
                payload: Some(wire::voter::Payload::Nullification(nullification.clone())),
            }
            .encode_to_vec()
            .into();
            self.journal
                .as_mut()
                .unwrap()
                .append(view, nullification_bytes)
                .await
                .expect("unable to append to journal");
        }

        // Get seed
        let seed = group::Signature::deserialize(&nullification.seed).unwrap();

        // Store nullification
        round.nullification = Some(nullification);

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn finalize(&mut self, sender: &PublicKey, finalize: wire::Finalize) {
        // Extract proposal
        let Some(proposal) = finalize.proposal.as_ref() else {
            return;
        };

        // Ensure we are in the right view to process this message
        if !self.interesting(proposal.view, false) {
            return;
        }

        // Verify that signer is a validator
        let Some(public_key_index) = self.supervisor.is_participant(proposal.view, sender) else {
            return;
        };
        let Some((identity, _)) = self.supervisor.identity(proposal.view) else {
            return;
        };

        // Verify signature
        let Some(signature) = Eval::deserialize(&finalize.signature) else {
            return;
        };
        if signature.index != public_key_index {
            return;
        }
        let finalize_message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
        if ops::partial_verify_message(
            identity,
            Some(&self.finalize_namespace),
            &finalize_message,
            &signature,
        )
        .is_err()
        {
            return;
        }

        // Handle finalize
        self.handle_finalize(public_key_index, finalize).await;
    }

    async fn handle_finalize(&mut self, public_key_index: u32, finalize: wire::Finalize) {
        // Get view for finalize
        let view = finalize.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.hasher.clone(), self.supervisor.clone(), view));

        // Handle finalize
        let finalize_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Finalize(finalize.clone())),
        }
        .encode_to_vec()
        .into();
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

    async fn finalization(&mut self, finalization: wire::Finalization) {
        // Extract proposal
        let Some(proposal) = &finalization.proposal else {
            return;
        };

        // Check if we are still in a view where this finalization could help
        if !self.interesting(proposal.view, true) {
            return;
        }

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&proposal.view) {
            if round.broadcast_finalization {
                return;
            }
        }

        // Verify finalization
        if !verify_finalization::<S>(
            &self.supervisor,
            &self.finalize_namespace,
            &self.seed_namespace,
            &finalization,
        ) {
            return;
        }

        // Process finalization
        self.handle_finalization(finalization).await;
    }

    async fn handle_finalization(&mut self, finalization: wire::Finalization) {
        // Create round (if it doesn't exist)
        let view = finalization.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.hasher.clone(), self.supervisor.clone(), view));

        // Clear leader and advance deadlines (if they exist)
        round.leader_deadline = None;
        round.advance_deadline = None;

        // If proposal is missing, set it
        if round.proposal.is_none() {
            let proposal = finalization.proposal.as_ref().unwrap().clone();
            let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
            self.hasher.update(&message);
            let digest = self.hasher.finalize();
            debug!(
                view = proposal.view,
                digest = hex(&digest),
                "setting unverified proposal in finalization"
            );
            round.proposal = Some((digest, proposal));
        }

        // Put finalization in journal
        if self.journal.is_some() {
            let finalization_bytes = wire::Voter {
                payload: Some(wire::voter::Payload::Finalization(finalization.clone())),
            }
            .encode_to_vec()
            .into();
            self.journal
                .as_mut()
                .unwrap()
                .append(view, finalization_bytes)
                .await
                .expect("unable to append to journal");
        }

        // Get seed
        let seed = group::Signature::deserialize(&finalization.seed).unwrap();

        // Store finalization
        round.finalization = Some(finalization);

        // Track view finalized
        if view > self.last_finalized {
            self.last_finalized = view;
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    fn construct_notarize(&mut self, view: u64) -> Option<wire::Notarize> {
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
        let share = self.supervisor.share(view).unwrap();
        let proposal = &round.proposal.as_ref().unwrap().1;
        let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
        let signature = ops::partial_sign_message(&share, Some(&self.notarize_namespace), &message);
        let signature = signature.serialize();
        let message = seed_message(view);
        let seed = ops::partial_sign_message(&share, Some(&self.seed_namespace), &message);
        let seed = seed.serialize();
        round.broadcast_notarize = true;
        Some(wire::Notarize {
            proposal: Some(proposal.clone()),
            signature: signature.into(),
            seed: seed.into(),
        })
    }

    fn construct_notarization(&mut self, view: u64, force: bool) -> Option<wire::Notarization> {
        // Get requested view
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct notarization
        let (_, threshold) = self.supervisor.identity(view)?;
        round.notarizable(threshold, force)
    }

    fn construct_nullification(&mut self, view: u64, force: bool) -> Option<wire::Nullification> {
        // Get requested view
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct nullification
        let (_, threshold) = self.supervisor.identity(view)?;
        round.nullifiable(threshold, force)
    }

    fn construct_finalize(&mut self, view: u64) -> Option<wire::Finalize> {
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
        let share = self.supervisor.share(view).unwrap();
        let proposal = match &round.proposal {
            Some((_, proposal)) => proposal,
            None => {
                return None;
            }
        };
        let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
        let signature = ops::partial_sign_message(&share, Some(&self.finalize_namespace), &message);
        let signature = signature.serialize();
        round.broadcast_finalize = true;
        Some(wire::Finalize {
            proposal: Some(proposal.clone()),
            signature: signature.into(),
        })
    }

    fn construct_finalization(&mut self, view: u64, force: bool) -> Option<wire::Finalization> {
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct finalization
        let (_, threshold) = self.supervisor.identity(view)?;
        round.finalizable(threshold, force)
    }

    async fn notify(
        &mut self,
        backfiller: &mut resolver::Mailbox,
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
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Notarize(notarize)),
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
            let proposal = notarization.proposal.as_ref().unwrap();
            let proof = Prover::<H>::serialize_threshold(
                proposal,
                &notarization.signature,
                &notarization.seed,
            );
            self.committer
                .prepared(
                    proof,
                    notarization.proposal.as_ref().unwrap().payload.clone(),
                )
                .await;

            // Broadcast the notarization
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Notarization(notarization)),
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
                    if self.is_notarized(parent).is_none() {
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
                            payload: Some(wire::voter::Payload::Finalization(finalization)),
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
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Finalize(finalize)),
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
            let proposal = finalization.proposal.as_ref().unwrap();
            let proof = Prover::<H>::serialize_threshold(
                proposal,
                &finalization.signature,
                &finalization.seed,
            );
            self.committer
                .finalized(
                    proof,
                    finalization.proposal.as_ref().unwrap().payload.clone(),
                )
                .await;

            // Broadcast the finalization
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Finalization(finalization)),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::FINALIZATION)
                .inc();
        };
    }

    pub async fn run(
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
                let msg = wire::Voter::decode(msg).expect("journal message is unexpected format");
                let msg = msg.payload.expect("missing payload");
                match msg {
                    wire::voter::Payload::Notarize(notarize) => {
                        // Handle notarize
                        let proposal = notarize.proposal.as_ref().unwrap().clone();
                        let signature: Eval<group::Signature> =
                            Eval::deserialize(&notarize.signature).unwrap();
                        let public_key_index = signature.index;
                        let public_key = self
                            .supervisor
                            .participants(proposal.view)
                            .unwrap()
                            .get(public_key_index as usize)
                            .unwrap()
                            .clone();
                        self.handle_notarize(public_key_index, notarize).await;

                        // Update round info
                        if public_key == self.crypto.public_key() {
                            let round = self.views.get_mut(&proposal.view).expect("missing round");
                            let proposal_message =
                                proposal_message(proposal.view, proposal.parent, &proposal.payload);
                            self.hasher.update(&proposal_message);
                            let proposal_digest = self.hasher.finalize();
                            round.proposal = Some((proposal_digest, proposal));
                            round.verified_proposal = true;
                            round.broadcast_notarize = true;
                        }
                    }
                    wire::voter::Payload::Notarization(notarization) => {
                        // Handle notarization
                        let proposal = notarization.proposal.as_ref().unwrap().clone();
                        self.handle_notarization(notarization).await;

                        // Update round info
                        let round = self.views.get_mut(&proposal.view).expect("missing round");
                        round.broadcast_notarization = true;
                    }
                    wire::voter::Payload::Nullify(nullify) => {
                        // Handle nullify
                        let view = nullify.view;
                        let signature: Eval<group::Signature> =
                            Eval::deserialize(&nullify.signature).unwrap();
                        let public_key_index = signature.index;
                        let public_key = self
                            .supervisor
                            .participants(view)
                            .unwrap()
                            .get(public_key_index as usize)
                            .unwrap()
                            .clone();
                        self.handle_nullify(public_key_index, nullify).await;

                        // Update round info
                        if public_key == self.crypto.public_key() {
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_nullify = true;
                        }
                    }
                    wire::voter::Payload::Nullification(nullification) => {
                        // Handle nullification
                        let view = nullification.view;
                        self.handle_nullification(nullification).await;

                        // Update round info
                        let round = self.views.get_mut(&view).expect("missing round");
                        round.broadcast_nullification = true;
                    }
                    wire::voter::Payload::Finalize(finalize) => {
                        // Handle finalize
                        let view = finalize.proposal.as_ref().unwrap().view;
                        let signature: Eval<group::Signature> =
                            Eval::deserialize(&finalize.signature).unwrap();
                        let public_key_index = signature.index;
                        let public_key = self
                            .supervisor
                            .participants(view)
                            .unwrap()
                            .get(public_key_index as usize)
                            .unwrap()
                            .clone();
                        self.handle_finalize(public_key_index, finalize).await;

                        // Update round info
                        //
                        // If we are sending a finalize message, we must be in the next view
                        if public_key == self.crypto.public_key() {
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_notarization = true;
                            round.broadcast_finalize = true;
                        }
                    }
                    wire::voter::Payload::Finalization(finalization) => {
                        // Handle finalization
                        let view = finalization.proposal.as_ref().unwrap().view;
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
            round.leader_deadline = Some(self.runtime.current());
            round.advance_deadline = Some(self.runtime.current());
        }
        self.current_view.set(observed_view as i64);
        self.tracked_views.set(self.views.len() as i64);

        // Create shutdown tracker
        let mut shutdown = self.runtime.stopped();

        // Process messages
        let mut pending_propose_context = None;
        let mut pending_propose = None;
        let mut pending_verify_context = None;
        let mut pending_verify = None;
        loop {
            // Attempt to propose a container
            if let Some((context, new_propose)) = self.propose(&mut backfiller).await {
                pending_propose_context = Some(context);
                pending_propose = Some(new_propose);
            }
            let propose_wait = match &mut pending_propose {
                Some(propose) => Either::Left(propose),
                None => Either::Right(futures::future::pending()),
            };

            // Attempt to verify current view
            if let Some((context, new_verify)) = self.peer_proposal().await {
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
                _ = self.runtime.sleep_until(timeout) => {
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
                    self.hasher.update(&message);
                    let proposal_digest = self.hasher.finalize();
                    let proposal = wire::Proposal {
                        view: context.view,
                        parent: context.parent.0,
                        payload: proposed.clone(),
                    };
                    if !self.our_proposal(proposal_digest, proposal.clone()).await {
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
                            view = notarization.proposal.as_ref().unwrap().view;
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
                            self.notarize(&s, notarize).await;
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
                            self.nullify(&s, nullify).await;
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
                            self.finalize(&s, finalize).await;
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
