use super::{Config, Mailbox, Message};
use crate::{
    authority::{
        encoder::{
            finalize_namespace, notarize_namespace, nullify_message, nullify_namespace,
            proposal_message,
        },
        prover::Prover,
        wire, Context, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE, NOTARIZE,
        NULLIFY_AND_FINALIZE,
    },
    Automaton, Finalizer, Relay, Supervisor,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Blob, Clock, Spawner, Storage};
use commonware_storage::journal::Journal;
use commonware_utils::{hex, quorum};
use core::panic;
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    pin_mut, StreamExt,
};
use prometheus_client::metrics::gauge::Gauge;
use prost::Message as _;
use rand::Rng;
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap, HashSet},
    pin,
    time::{Duration, SystemTime},
};
use std::{marker::PhantomData, sync::atomic::AtomicI64};
use tracing::{debug, info, trace, warn};

type Notarizable<'a> = Option<(wire::Proposal, &'a HashMap<PublicKey, wire::Notarize>)>;
type Nullifiable<'a> = Option<(View, &'a HashMap<PublicKey, wire::Nullify>)>;
type Finalizable<'a> = Option<(wire::Proposal, &'a HashMap<PublicKey, wire::Finalize>)>;

const GENESIS_VIEW: View = 0;

struct Round<C: Scheme, H: Hasher, S: Supervisor<Index = View>> {
    hasher: H,
    supervisor: S,
    _crypto: PhantomData<C>,

    view: View,
    leader: PublicKey,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,

    // Track one proposal per view
    proposal: Option<(Digest /* proposal */, wire::Proposal)>,
    requested_proposal: bool,
    verified_proposal: bool,

    // Track votes for all proposals (ensuring any participant only has one recorded vote)
    notaries: HashMap<PublicKey, Digest>,
    notarizes: HashMap<Digest, HashMap<PublicKey, wire::Notarize>>,
    broadcast_notarize: bool,
    broadcast_notarization: bool,

    nullifies: HashMap<PublicKey, wire::Nullify>,
    broadcast_nullify: bool,
    broadcast_nullification: bool,

    // Track finalizes for all proposals (ensuring any participant only has one recorded finalize)
    finalizers: HashMap<PublicKey, Digest>,
    finalizes: HashMap<Digest, HashMap<PublicKey, wire::Finalize>>,
    broadcast_finalize: bool,
    broadcast_finalization: bool,
}

impl<C: Scheme, H: Hasher, S: Supervisor<Index = View>> Round<C, H, S> {
    pub fn new(
        hasher: H,
        supervisor: S,
        view: View,
        leader: PublicKey,
        leader_deadline: Option<SystemTime>,
        advance_deadline: Option<SystemTime>,
    ) -> Self {
        Self {
            hasher,
            supervisor,
            _crypto: PhantomData,

            view,
            leader,
            leader_deadline,
            advance_deadline,
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

    async fn add_verified_notarize(&mut self, notarize: wire::Notarize) -> bool {
        // Get proposal
        let proposal = notarize.proposal.as_ref().unwrap();

        // Compute proposal digest
        let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
        self.hasher.update(&message);
        let digest = self.hasher.finalize();

        // Check if already voted
        let public_key = &notarize.signature.as_ref().unwrap().public_key;
        if let Some(previous_notarize) = self.notaries.get(public_key) {
            if previous_notarize == &digest {
                trace!(
                    view = self.view,
                    signer = hex(public_key),
                    previous_vote = hex(previous_notarize),
                    "already voted"
                );
                return false;
            }

            // Create fault
            let previous_vote = self
                .notarizes
                .get(previous_notarize)
                .unwrap()
                .get(public_key)
                .unwrap();
            let previous_proposal = previous_vote.proposal.as_ref().unwrap();
            let proof = Prover::<C, H>::serialize_conflicting_notarize(
                previous_proposal.view,
                previous_proposal.parent,
                &previous_proposal.payload,
                &previous_vote.signature.as_ref().unwrap(),
                proposal.view,
                proposal.parent,
                &proposal.payload,
                &notarize.signature.as_ref().unwrap(),
            );
            self.supervisor.report(CONFLICTING_NOTARIZE, proof).await;
            warn!(
                view = self.view,
                signer = hex(public_key),
                activity = CONFLICTING_NOTARIZE,
                "recorded fault"
            );
            return false;
        }

        // Store the vote
        if self
            .notaries
            .insert(public_key.clone(), digest.clone())
            .is_some()
        {
            return false;
        }
        let entry = self.notarizes.entry(digest).or_default();
        let proof = Prover::<C, H>::serialize_notarize(&notarize);
        entry.insert(public_key.clone(), notarize);
        self.supervisor.report(NOTARIZE, proof).await;
        true
    }

    async fn add_verified_nullify(&mut self, nullify: wire::Nullify) -> bool {
        // Check if already issued finalize
        let public_key = &nullify.signature.as_ref().unwrap().public_key;
        let finalize = self.finalizers.get(public_key);
        if finalize.is_none() {
            // Store the null vote
            return self.nullifies.insert(public_key.clone(), nullify).is_none();
        }
        let finalize = finalize.unwrap();

        // Create fault
        let finalize = self
            .finalizes
            .get(finalize)
            .unwrap()
            .get(public_key)
            .unwrap();
        let finalize_proposal = finalize.proposal.as_ref().unwrap();
        let proof = Prover::<C, H>::serialize_nullify_finalize(
            finalize_proposal.view,
            finalize_proposal.parent,
            &finalize_proposal.payload,
            &finalize.signature.as_ref().unwrap(),
            &nullify.signature.as_ref().unwrap(),
        );
        self.supervisor.report(NULLIFY_AND_FINALIZE, proof).await;
        warn!(
            view = self.view,
            signer = hex(public_key),
            activity = NULLIFY_AND_FINALIZE,
            "recorded fault"
        );
        false
    }

    fn notarizable(&mut self, threshold: u32, force: bool) -> Notarizable {
        if !force
            && (self.broadcast_notarization
                || self.broadcast_nullification
                || !self.verified_proposal)
        {
            // We only want to broadcast a notarization if we have verified some proposal at
            // this point.
            return None;
        }
        for (proposal, notarizes) in self.notarizes.iter() {
            if (notarizes.len() as u32) < threshold {
                continue;
            }

            // Ensure we have the proposal we are going to broadcast a notarization for
            let proposal = match &self.proposal {
                Some((digest, pro)) => {
                    if digest != proposal {
                        debug!(
                            view = self.view,
                            proposal = hex(proposal),
                            reason = "proposal mismatch",
                            "skipping notarization broadcast"
                        );
                        continue;
                    }
                    debug!(
                        view = self.view,
                        proposal = hex(proposal),
                        "broadcasting notarization"
                    );
                    pro
                }
                None => {
                    continue;
                }
            };

            // There should never exist enough votes for multiple proposals, so it doesn't
            // matter which one we choose.
            self.broadcast_notarization = true;
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
        self.broadcast_notarization = true;
        Some((self.view, &self.nullifies))
    }

    async fn add_verified_finalize(&mut self, finalize: wire::Finalize) -> bool {
        // Check if also issued null vote
        let proposal = finalize.proposal.as_ref().unwrap();
        let public_key = &finalize.signature.as_ref().unwrap().public_key;
        let null = self.nullifies.get(public_key);
        if let Some(null) = null {
            // Create fault
            let proof = Prover::<C, H>::serialize_nullify_finalize(
                proposal.view,
                proposal.parent,
                &proposal.payload,
                &finalize.signature.as_ref().unwrap(),
                &null.signature.as_ref().unwrap(),
            );
            self.supervisor.report(NULLIFY_AND_FINALIZE, proof).await;
            warn!(
                view = self.view,
                signer = hex(public_key),
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
        if let Some(previous_finalize) = self.finalizers.get(public_key) {
            if previous_finalize == &digest {
                trace!(
                    view = self.view,
                    signer = hex(public_key),
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
                .get(public_key)
                .unwrap();
            let previous_proposal = previous_finalize.proposal.as_ref().unwrap();
            let proof = Prover::<C, H>::serialize_conflicting_finalize(
                previous_proposal.view,
                previous_proposal.parent,
                &previous_proposal.payload,
                &previous_finalize.signature.as_ref().unwrap(),
                proposal.view,
                proposal.parent,
                &proposal.payload,
                &finalize.signature.as_ref().unwrap(),
            );
            self.supervisor.report(CONFLICTING_FINALIZE, proof).await;
            warn!(
                view = self.view,
                signer = hex(public_key),
                activity = CONFLICTING_FINALIZE,
                "recorded fault"
            );
            return false;
        }

        // Store the finalize
        if self
            .finalizers
            .insert(public_key.clone(), digest.clone())
            .is_some()
        {
            return false;
        }
        let entry = self.finalizes.entry(digest).or_default();
        let proof = Prover::<C, H>::serialize_finalize(&finalize);
        entry.insert(public_key.clone(), finalize);
        self.supervisor.report(FINALIZE, proof).await;
        true
    }

    fn finalizable_proposal(&mut self, threshold: u32, force: bool) -> Finalizable {
        if !force && (self.broadcast_finalization || !self.verified_proposal) {
            // We only want to broadcast a finalization if we have verified some proposal at
            // this point.
            return None;
        }
        for (proposal, finalizes) in self.finalizes.iter() {
            if (finalizes.len() as u32) < threshold {
                continue;
            }

            // Ensure we have the proposal we are going to broadcast a finalization for
            let proposal = match &self.proposal {
                Some((digest, pro)) => {
                    if digest != proposal {
                        debug!(
                            proposal = hex(proposal),
                            digest = hex(digest),
                            reason = "proposal mismatch",
                            "skipping finalization broadcast"
                        );
                        continue;
                    }
                    pro
                }
                None => {
                    continue;
                }
            };

            // There should never exist enough finalizes for multiple proposals, so it doesn't
            // matter which one we choose.
            self.broadcast_finalization = true;
            return Some((proposal.clone(), finalizes));
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
    A: Automaton<Context = Context> + Relay + Finalizer,
    S: Supervisor<Index = View>,
> {
    runtime: E,
    crypto: C,
    hasher: H,
    application: A,
    supervisor: S,

    replay_concurrency: usize,
    journal: Option<Journal<B, E>>,

    genesis: Option<Digest>,

    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    activity_timeout: View,

    mailbox_sender: Mailbox,
    mailbox_receiver: mpsc::Receiver<Message>,

    last_finalized: View,
    view: View,
    views: BTreeMap<View, Round<C, H, S>>,

    current_view: Gauge,
    tracked_views: Gauge,
}

impl<
        B: Blob,
        E: Clock + Rng + Spawner + Storage<B>,
        C: Scheme,
        H: Hasher,
        A: Automaton<Context = Context> + Relay + Finalizer,
        S: Supervisor<Seed = (), Index = View>,
    > Actor<B, E, C, H, A, S>
{
    pub fn new(runtime: E, journal: Journal<B, E>, mut cfg: Config<C, H, A, S>) -> (Self, Mailbox) {
        // Assert correctness of timeouts
        if cfg.leader_timeout > cfg.notarization_timeout {
            panic!("leader timeout must be less than or equal to notarization timeout");
        }

        // Initialize metrics
        let current_view = Gauge::<i64, AtomicI64>::default();
        let tracked_views = Gauge::<i64, AtomicI64>::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register("current_view", "current view", current_view.clone());
            registry.register("tracked_views", "tracked views", tracked_views.clone());
        }

        // Initialize store
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(1024);
        let mailbox = Mailbox::new(mailbox_sender);
        (
            Self {
                runtime,
                crypto: cfg.crypto,
                hasher: cfg.hasher,
                application: cfg.application,
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

                mailbox_sender: mailbox.clone(),
                mailbox_receiver,

                last_finalized: 0,
                view: 0,
                views: BTreeMap::new(),

                current_view,
                tracked_views,
            },
            mailbox,
        )
    }

    fn is_notarized(&self, view: View) -> Option<&wire::Proposal> {
        let round = self.views.get(&view)?;
        let (digest, proposal) = round.proposal.as_ref()?;
        let notarizes = round.notarizes.get(digest)?;
        let (threshold, _) = self.threshold(view)?;
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
        let (threshold, _) = match self.threshold(view) {
            Some(threshold) => threshold,
            None => return false,
        };
        round.nullifies.len() >= threshold as usize
    }

    fn find_parent(&self) -> Option<(View, Digest)> {
        let mut cursor = self.view - 1; // self.view always at least 1
        loop {
            if cursor == 0 {
                return Some((GENESIS_VIEW, self.genesis.as_ref().unwrap().clone()));
            }

            // If have notarization, return
            let parent = self.is_notarized(cursor);
            if let Some(parent) = parent {
                return Some((cursor, parent.payload.clone()));
            }

            // If have nullification, continue
            if self.is_nullified(cursor) {
                cursor -= 1;
                continue;
            }

            // We can't find a valid parent, return
            return None;
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

    async fn propose(&mut self) -> Option<(Context, oneshot::Receiver<Digest>)> {
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
            Some(parent) => parent,
            None => {
                debug!(
                    view = self.view,
                    reason = "no parent",
                    "skipping proposal opportunity"
                );
                return None;
            }
        };

        // Request proposal from application
        debug!(view = self.view, "requested proposal");
        let context = Context {
            view: self.view,
            parent: (parent_view, parent_payload),
        };
        Some((context.clone(), self.application.propose(context).await))
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

        // If no deadlines are still set (waiting for null votes),
        // return next try for null container vote
        if let Some(deadline) = view.nullify_retry {
            return deadline;
        }

        // Set null vote retry, if none already set
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
                debug!(view = past_view, "rebroadcast entry notarization");
            } else if let Some(nullification) = self.construct_nullification(past_view, true) {
                let msg = wire::Voter {
                    payload: Some(wire::voter::Payload::Nullification(nullification)),
                }
                .encode_to_vec()
                .into();
                sender.send(Recipients::All, msg, true).await.unwrap();
                debug!(view = past_view, "rebroadcast entry nullification");
            } else {
                warn!(
                    view = past_view,
                    "unable to rebroadcast entry notarization/nullification"
                );
            }
        }

        // Construct nullify
        let message = nullify_message(self.view);
        let null = wire::Nullify {
            view: self.view,
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(&self.nullify_namespace, &message),
            }),
        };

        // Handle the nullify
        self.handle_nullify(null.clone()).await;

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
        debug!(view = self.view, "broadcasted nullify");
    }

    async fn nullify(&mut self, nullify: wire::Nullify) {
        // Ensure we are in the right view to process this message
        if !self.interesting(nullify.view, false) {
            debug!(
                nullify_view = nullify.view,
                our_view = self.view,
                "dropping vote"
            );
            return;
        }

        // Parse signature
        let signature = match &nullify.signature {
            Some(signature) => signature,
            _ => {
                debug!(reason = "missing signature", "dropping vote");
                return;
            }
        };
        if !C::validate(&signature.public_key) {
            debug!(reason = "invalid signature", "dropping vote");
            return;
        }

        // Verify that signer is a validator
        let is_participant = match self
            .supervisor
            .is_participant(nullify.view, &signature.public_key)
        {
            Some(is) => is,
            None => {
                debug!(
                    view = nullify.view,
                    our_view = self.view,
                    signer = hex(&signature.public_key),
                    reason = "unable to compute participants for view",
                    "dropping vote"
                );
                return;
            }
        };
        if !is_participant {
            debug!(
                signer = hex(&signature.public_key),
                reason = "invalid validator",
                "dropping vote"
            );
            return;
        }

        // Verify the signature
        let message = nullify_message(nullify.view);
        if !C::verify(
            &self.nullify_namespace,
            &message,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping vote");
            return;
        }

        // Handle nullify
        self.handle_nullify(nullify).await;
    }

    async fn handle_nullify(&mut self, nullify: wire::Nullify) {
        // Check to see if vote is for proposal in view
        let view = nullify.view;
        let leader = match self.supervisor.leader(view, ()) {
            Some(leader) => leader,
            None => {
                debug!(
                    view = nullify.view,
                    reason = "unable to compute leader",
                    "dropping null"
                );
                return;
            }
        };
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.hasher.clone(),
                self.supervisor.clone(),
                view,
                leader,
                None,
                None,
            )
        });

        // Handle nullify
        let nullify_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Nullify(nullify.clone())),
        }
        .encode_to_vec()
        .into();
        if round.add_verified_nullify(nullify).await && self.journal.is_some() {
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
    async fn peer_proposal(&mut self) -> Option<(Context, oneshot::Receiver<bool>)> {
        // Get round
        let (proposal_digest, proposal) = {
            // Get view or exit
            let round = self.views.get(&self.view)?;

            // If we are the leader, drop peer proposals
            if round.leader == self.crypto.public_key() {
                return None;
            }

            // If we already broadcast nullify or set proposal, do nothing
            if round.broadcast_nullify {
                return None;
            }
            if round.proposal.is_some() {
                return None;
            }

            // Check if leader has signed a digest
            let proposal_digest = round.notaries.get(&round.leader)?;
            let proposal = round
                .notarizes
                .get(proposal_digest)?
                .get(&round.leader)?
                .proposal
                .as_ref()?;

            // Check parent validity
            if proposal.view <= proposal.parent {
                debug!(
                    view = proposal.view,
                    parent = proposal.parent,
                    reason = "invalid parent",
                    "dropping proposal"
                );
                return None;
            }
            if proposal.parent < self.last_finalized {
                debug!(
                    view = proposal.view,
                    parent = proposal.parent,
                    last_finalized = self.last_finalized,
                    reason = "parent behind finalized tip",
                    "dropping proposal"
                );
                return None;
            }
            (proposal_digest, proposal)
        };

        // Ensure we have required notarizations
        let mut cursor = match self.view {
            0 => {
                debug!(self.view, reason = "invalid view", "dropping proposal");
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
                        trace!(
                            view = cursor,
                            reason = "missing notarization",
                            "skipping verify"
                        );
                        return None;
                    }
                };

                // Peer proposal references a valid parent
                break parent_proposal.payload.clone();
            }

            // Check nullification exists in gap
            if !self.is_nullified(cursor) {
                debug!(view = cursor, "missing nullification");
                return None;
            }
            cursor -= 1;
        };

        // Request verification
        let payload = proposal.payload.clone();
        debug!(
            view = proposal.view,
            digest = hex(&proposal_digest),
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
            self.application.verify(context, payload.clone()).await,
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
        let leader = self
            .supervisor
            .leader(view, ())
            .expect("unable to get leader");
        let entry = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.hasher.clone(),
                self.supervisor.clone(),
                view,
                leader.clone(),
                None,
                None,
            )
        });
        entry.leader_deadline = Some(self.runtime.current() + self.leader_timeout);
        entry.advance_deadline = Some(self.runtime.current() + self.notarization_timeout);
        self.view = view;
        info!(view, "entered view");

        // TODO: alert backfiller we've entered a new view

        // Check if we should fast exit this view
        if view < self.activity_timeout || leader == self.crypto.public_key() {
            // Don't fast exit the view
            return;
        }
        let mut next = view - 1;
        while next > view - self.activity_timeout {
            if !self.supervisor.is_participant(next, &leader).unwrap() {
                // Don't punish a participant if they weren't online at any point during
                // the lookback window.
                return;
            }
            let round = match self.views.get(&next) {
                Some(round) => round,
                None => {
                    return;
                }
            };
            if round.notaries.contains_key(&leader) || round.nullifies.contains_key(&leader) {
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

    fn threshold(&self, view: View) -> Option<(u32, u32)> {
        let validators = match self.supervisor.participants(view) {
            Some(validators) => validators,
            None => return None,
        };
        let len = validators.len() as u32;
        let threshold = quorum(len).expect("not enough validators for a quorum");
        Some((threshold, len))
    }

    async fn notarize(&mut self, notarize: wire::Notarize) {
        // Extract proposal
        let proposal = match &notarize.proposal {
            Some(proposal) => proposal,
            _ => {
                debug!(reason = "missing proposal", "dropping finalize");
                return;
            }
        };

        // Ensure we are in the right view to process this message
        if !self.interesting(proposal.view, false) {
            debug!(
                notarize_view = proposal.view,
                our_view = self.view,
                "dropping vote"
            );
            return;
        }

        // Parse signature
        let signature = match &notarize.signature {
            Some(signature) => signature,
            _ => {
                debug!(reason = "missing signature", "dropping vote");
                return;
            }
        };
        if !C::validate(&signature.public_key) {
            debug!(reason = "invalid signature", "dropping vote");
            return;
        }

        // Verify that signer is a validator
        let is_participant = match self
            .supervisor
            .is_participant(proposal.view, &signature.public_key)
        {
            Some(is) => is,
            None => {
                debug!(
                    view = proposal.view,
                    our_view = self.view,
                    signer = hex(&signature.public_key),
                    reason = "unable to compute participants for view",
                    "dropping vote"
                );
                return;
            }
        };
        if !is_participant {
            debug!(
                signer = hex(&signature.public_key),
                reason = "invalid validator",
                "dropping vote"
            );
            return;
        }

        // Verify the signature
        let notarize_message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
        if !C::verify(
            &self.notarize_namespace,
            &notarize_message,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping vote");
            return;
        }

        // Handle notarize
        self.handle_notarize(notarize).await;
    }

    async fn handle_notarize(&mut self, notarize: wire::Notarize) {
        // Check to see if vote is for proposal in view
        let view = notarize.proposal.as_ref().unwrap().view;
        let leader = self
            .supervisor
            .leader(view, ())
            .expect("unable to get leader");
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.hasher.clone(),
                self.supervisor.clone(),
                view,
                leader,
                None,
                None,
            )
        });

        // Handle vote
        let notarize_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Notarize(notarize.clone())),
        }
        .encode_to_vec()
        .into();
        if round.add_verified_notarize(notarize).await && self.journal.is_some() {
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
        let proposal = match &notarization.proposal {
            Some(proposal) => proposal,
            _ => {
                debug!(reason = "missing proposal", "dropping finalize");
                return;
            }
        };

        // Check if we are still in a view where this notarization could help
        if !self.interesting(proposal.view, true) {
            trace!(
                notarization_view = proposal.view,
                our_view = self.view,
                reason = "outdated notarization",
                "dropping notarization"
            );
            return;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        let round = self.views.get_mut(&proposal.view);
        if let Some(ref round) = round {
            if round.broadcast_notarization {
                trace!(
                    view = proposal.view,
                    reason = "already broadcast notarization",
                    "dropping notarization"
                );
                return;
            }
        }

        // Ensure notarization has valid number of signatures
        let (threshold, count) = match self.threshold(proposal.view) {
            Some(participation) => participation,
            None => {
                debug!(
                    view = proposal.view,
                    reason = "unable to compute participants for view",
                    "dropping notarization"
                );
                return;
            }
        };
        if notarization.signatures.len() < threshold as usize {
            debug!(
                threshold,
                signatures = notarization.signatures.len(),
                reason = "insufficient signatures",
                "dropping notarization"
            );
            return;
        }
        if notarization.signatures.len() > count as usize {
            debug!(
                threshold,
                signatures = notarization.signatures.len(),
                reason = "too many signatures",
                "dropping notarization"
            );
            return;
        }

        // Verify threshold notarization
        let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
        let mut seen = HashSet::new();
        for signature in notarization.signatures.iter() {
            // Verify signature
            if !C::validate(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "invalid validator",
                    "dropping notarization"
                );
                return;
            }

            // Ensure we haven't seen this signature before
            if seen.contains(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "duplicate signature",
                    "dropping notarization"
                );
                return;
            }
            seen.insert(signature.public_key.clone());

            // Verify signature
            if !C::verify(
                &self.notarize_namespace,
                &message,
                &signature.public_key,
                &signature.signature,
            ) {
                debug!(reason = "invalid signature", "dropping notarization");
                return;
            }
        }
        debug!(view = proposal.view, "notarization verified");

        // Handle notarization
        self.handle_notarization(notarization).await;
    }

    async fn handle_notarization(&mut self, notarization: wire::Notarization) {
        // Add signatures to view (needed to broadcast notarization if we get proposal)
        let view = notarization.proposal.as_ref().unwrap().view;
        let leader = self
            .supervisor
            .leader(view, ())
            .expect("unable to get leader");
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.hasher.clone(),
                self.supervisor.clone(),
                view,
                leader,
                None,
                None,
            )
        });
        for signature in &notarization.signatures {
            let notarize = wire::Notarize {
                proposal: Some(notarization.proposal.as_ref().unwrap().clone()),
                signature: Some(signature.clone()),
            };
            let notarize_bytes = wire::Voter {
                payload: Some(wire::voter::Payload::Notarize(notarize.clone())),
            }
            .encode_to_vec()
            .into();
            if round.add_verified_notarize(notarize).await && self.journal.is_some() {
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
            let proposal = notarization.proposal.unwrap();
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

        // Enter next view
        self.enter_view(view + 1);
    }

    async fn nullification(&mut self, nullification: wire::Nullification) {
        // Check if we are still in a view where this notarization could help
        if !self.interesting(nullification.view, true) {
            trace!(
                nullification_view = nullification.view,
                our_view = self.view,
                reason = "outdated",
                "dropping nullification"
            );
            return;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        let round = self.views.get_mut(&nullification.view);
        if let Some(ref round) = round {
            if round.broadcast_notarization {
                trace!(
                    view = nullification.view,
                    reason = "already broadcast notarization",
                    "dropping notarization"
                );
                return;
            }
        }

        // Ensure notarization has valid number of signatures
        let (threshold, count) = match self.threshold(nullification.view) {
            Some(participation) => participation,
            None => {
                debug!(
                    view = nullification.view,
                    reason = "unable to compute participants for view",
                    "dropping notarization"
                );
                return;
            }
        };
        if nullification.signatures.len() < threshold as usize {
            debug!(
                threshold,
                signatures = nullification.signatures.len(),
                reason = "insufficient signatures",
                "dropping nullification"
            );
            return;
        }
        if nullification.signatures.len() > count as usize {
            debug!(
                threshold,
                signatures = nullification.signatures.len(),
                reason = "too many signatures",
                "dropping nullification"
            );
            return;
        }

        // Verify threshold notarization
        let message = nullify_message(nullification.view);
        let mut seen = HashSet::new();
        for signature in nullification.signatures.iter() {
            // Verify signature
            if !C::validate(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "invalid validator",
                    "dropping notarization"
                );
                return;
            }

            // Ensure we haven't seen this signature before
            if seen.contains(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "duplicate signature",
                    "dropping notarization"
                );
                return;
            }
            seen.insert(signature.public_key.clone());

            // Verify signature
            if !C::verify(
                &self.nullify_namespace,
                &message,
                &signature.public_key,
                &signature.signature,
            ) {
                debug!(reason = "invalid signature", "dropping notarization");
                return;
            }
        }
        debug!(view = nullification.view, "nullification verified");

        // Handle notarization
        self.handle_nullification(nullification).await;
    }

    async fn handle_nullification(&mut self, nullification: wire::Nullification) {
        // Add signatures to view (needed to broadcast notarization if we get proposal)
        let leader = self
            .supervisor
            .leader(nullification.view, ())
            .expect("unable to get leader");
        let round = self.views.entry(nullification.view).or_insert_with(|| {
            Round::new(
                self.hasher.clone(),
                self.supervisor.clone(),
                nullification.view,
                leader,
                None,
                None,
            )
        });
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
            if round.add_verified_nullify(nullify).await && self.journal.is_some() {
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
        let proposal = match &finalize.proposal {
            Some(proposal) => proposal,
            _ => {
                debug!(reason = "missing proposal", "dropping finalize");
                return;
            }
        };

        // Ensure we are in the right view to process this message
        if !self.interesting(proposal.view, false) {
            debug!(
                finalize_view = proposal.view,
                our_view = self.view,
                reason = "incorrect view",
                "dropping finalize"
            );
            return;
        }

        // Parse signature
        let signature = match &finalize.signature {
            Some(signature) => signature,
            _ => {
                debug!(reason = "missing signature", "dropping finalize");
                return;
            }
        };
        if !C::validate(&signature.public_key) {
            debug!(reason = "invalid public key", "dropping finalize");
            return;
        }

        // Verify that signer is a validator
        let is_participant = match self
            .supervisor
            .is_participant(proposal.view, &signature.public_key)
        {
            Some(is) => is,
            None => {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "unable to compute participants for view",
                    "dropping vote"
                );
                return;
            }
        };
        if !is_participant {
            debug!(
                signer = hex(&signature.public_key),
                reason = "invalid validator",
                "dropping finalize"
            );
            return;
        }

        // Verify the signature
        let finalize_message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
        if !C::verify(
            &self.finalize_namespace,
            &finalize_message,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(
                signer = hex(&signature.public_key),
                digest = hex(&finalize_message),
                reason = "invalid signature",
                "dropping finalize"
            );
            return;
        }

        // Handle finalize
        self.handle_finalize(finalize).await;
    }

    async fn handle_finalize(&mut self, finalize: wire::Finalize) {
        // Get view for finalize
        let view = finalize.proposal.as_ref().unwrap().view;
        let leader = self
            .supervisor
            .leader(view, ())
            .expect("unable to get leader");
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.hasher.clone(),
                self.supervisor.clone(),
                view,
                leader,
                None,
                None,
            )
        });

        // Handle finalize
        let finalize_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Finalize(finalize.clone())),
        }
        .encode_to_vec()
        .into();
        if round.add_verified_finalize(finalize).await && self.journal.is_some() {
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
        let proposal = match &finalization.proposal {
            Some(proposal) => proposal,
            _ => {
                debug!(reason = "missing proposal", "dropping finalize");
                return;
            }
        };

        // Check if we are still in a view where this finalization could help
        if !self.interesting(proposal.view, true) {
            trace!(
                finalization_view = proposal.view,
                our_view = self.view,
                reason = "outdated finalization",
                "dropping finalization"
            );
            return;
        }

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        let round = self.views.get_mut(&proposal.view);
        if let Some(ref round) = round {
            if round.broadcast_finalization {
                trace!(
                    view = proposal.view,
                    reason = "already broadcast finalization",
                    "dropping finalization"
                );
                return;
            }
        }

        // Ensure finalization has valid number of signatures
        let (threshold, count) = match self.threshold(proposal.view) {
            Some(participation) => participation,
            None => {
                debug!(
                    view = proposal.view,
                    reason = "unable to compute participants for view",
                    "dropping finalization"
                );
                return;
            }
        };
        if finalization.signatures.len() < threshold as usize {
            debug!(
                threshold,
                signatures = finalization.signatures.len(),
                reason = "insufficient signatures",
                "dropping finalization"
            );
            return;
        }
        if finalization.signatures.len() > count as usize {
            debug!(
                threshold,
                signatures = finalization.signatures.len(),
                reason = "too many signatures",
                "dropping finalization"
            );
            return;
        }

        // Verify threshold finalization
        let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
        let mut seen = HashSet::new();
        for signature in finalization.signatures.iter() {
            // Verify signature
            if !C::validate(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "invalid validator",
                    "dropping finalization"
                );
                return;
            }

            // Ensure we haven't seen this signature before
            if seen.contains(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "duplicate signature",
                    "dropping finalization"
                );
                return;
            }
            seen.insert(signature.public_key.clone());

            // Verify signature
            if !C::verify(
                &self.finalize_namespace,
                &message,
                &signature.public_key,
                &signature.signature,
            ) {
                debug!(reason = "invalid signature", "dropping finalization");
                return;
            }
        }
        debug!(view = proposal.view, "finalization verified");

        // Process finalization
        self.handle_finalization(finalization).await;
    }

    async fn handle_finalization(&mut self, finalization: wire::Finalization) {
        // Add signatures to view (needed to broadcast finalization if we get proposal)
        let view = finalization.proposal.as_ref().unwrap().view;
        let leader = self
            .supervisor
            .leader(view, ())
            .expect("unable to get leader");
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.hasher.clone(),
                self.supervisor.clone(),
                view,
                leader,
                None,
                None,
            )
        });
        for signature in finalization.signatures.iter() {
            let finalize = wire::Finalize {
                proposal: Some(finalization.proposal.as_ref().unwrap().clone()),
                signature: Some(signature.clone()),
            };
            let finalize_bytes = wire::Voter {
                payload: Some(wire::voter::Payload::Finalize(finalize.clone())),
            }
            .encode_to_vec()
            .into();
            if round.add_verified_finalize(finalize).await && self.journal.is_some() {
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
            let proposal = finalization.proposal.unwrap();
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

        // Track view finalized
        if view > self.last_finalized {
            self.last_finalized = view;
        }

        // Enter next view
        self.enter_view(view + 1);
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
        let proposal = &round.proposal.as_ref().unwrap().1;
        round.broadcast_notarize = true;
        Some(wire::Notarize {
            proposal: Some(proposal.clone()),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(
                    &self.notarize_namespace,
                    &proposal_message(proposal.view, proposal.parent, &proposal.payload),
                ),
            }),
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
        let validators = match self.supervisor.participants(view) {
            Some(validators) => validators,
            None => {
                return None;
            }
        };
        let threshold =
            quorum(validators.len() as u32).expect("not enough validators for a quorum");
        let (proposal, votes) = round.notarizable(threshold, force)?;

        // Construct notarization
        let mut signatures = Vec::new();
        for validator in validators.iter() {
            if let Some(vote) = votes.get(validator) {
                signatures.push(vote.signature.clone().unwrap());
            }
        }
        let notarization = wire::Notarization {
            proposal: Some(proposal),
            signatures,
        };
        Some(notarization)
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
        for validator in validators.iter() {
            if let Some(nullify) = nullifies.get(validator) {
                signatures.push(nullify.signature.clone().unwrap());
            }
        }
        Some(wire::Nullification { view, signatures })
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
            // Ensure we vote before we finalize
            return None;
        }
        if !round.broadcast_notarization {
            // Ensure we notarize before we finalize
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
        round.broadcast_finalize = true;
        Some(wire::Finalize {
            proposal: Some(proposal.clone()),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(
                    &self.finalize_namespace,
                    &proposal_message(proposal.view, proposal.parent, &proposal.payload),
                ),
            }),
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
        let validators = match self.supervisor.participants(view) {
            Some(validators) => validators,
            None => {
                return None;
            }
        };
        let threshold =
            quorum(validators.len() as u32).expect("not enough validators for a quorum");
        let (proposal, finalizes) = round.finalizable_proposal(threshold, force)?;

        // Construct finalization
        let mut signatures = Vec::new();
        for validator in validators.iter() {
            if let Some(finalize) = finalizes.get(validator) {
                signatures.push(finalize.signature.clone().unwrap());
            }
        }
        let finalization = wire::Finalization {
            proposal: Some(proposal),
            signatures,
        };
        Some(finalization)
    }

    async fn broadcast(&mut self, sender: &mut impl Sender, view: u64) {
        // Attempt to notarize
        if let Some(notarize) = self.construct_notarize(view) {
            // Handle the vote
            self.handle_notarize(notarize.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the vote
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Notarize(notarize)),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();
        };

        // Attempt to notarization
        if let Some(notarization) = self.construct_notarization(view, false) {
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
            let proof = Prover::<C, H>::serialize_notarization(&notarization);
            self.application
                .notarized(
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
        };

        // Attempt to nullification
        //
        // We handle broadcast of nullify in `timeout`.
        if let Some(nullification) = self.construct_nullification(view, false) {
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

            // If `> f` notarized a given proposal, then we should backfill missing
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

                    // Enqueue missing
                    warn!(
                        proposal_view = view,
                        parent,
                        ?missing_notarizations,
                        ?missing_nullifications,
                        "at least one honest voter for parent"
                    );
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
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Finalize(finalize)),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();
        };

        // Attempt to finalization
        if let Some(finalization) = self.construct_finalization(view, false) {
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
            let proof = Prover::<C, H>::serialize_finalization(&finalization);
            self.application
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
        };
    }

    pub async fn run(mut self, mut sender: impl Sender, mut receiver: impl Receiver) {
        // Compute genesis
        let genesis = self.application.genesis().await;
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
                let msg = wire::Voter::decode(msg).expect("unable to decode voter message");
                let msg = msg.payload.expect("missing payload");
                match msg {
                    wire::voter::Payload::Notarize(notarize) => {
                        // Handle notarize
                        let proposal = notarize.proposal.as_ref().unwrap().clone();
                        let me = notarize.signature.as_ref().unwrap().public_key
                            == self.crypto.public_key();
                        self.handle_notarize(notarize).await;

                        // Update round info
                        if me {
                            observed_view = max(observed_view, proposal.view);
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
                    wire::voter::Payload::Nullify(nullify) => {
                        // Handle nullify
                        let view = nullify.view;
                        let me = nullify.signature.as_ref().unwrap().public_key
                            == self.crypto.public_key();
                        self.handle_nullify(nullify).await;

                        // Update round info
                        if me {
                            observed_view = max(observed_view, view);
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_nullify = true;
                        }
                    }
                    wire::voter::Payload::Finalize(finalize) => {
                        // Handle finalize
                        let view = finalize.proposal.as_ref().unwrap().view;
                        let me = finalize.signature.as_ref().unwrap().public_key
                            == self.crypto.public_key();
                        self.handle_finalize(finalize).await;

                        // Update round info
                        //
                        // If we are sending a finalize message, we must be in the next view
                        if me {
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
            if let Some((context, new_propose)) = self.propose().await {
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
                        debug!(view = context.view, "failed to propose container");
                        continue;
                    }
                    view = self.view;

                    // Notify application of proposal
                    self.application.broadcast(proposed).await;
                },
                verified = verify_wait => {
                    // Clear verify waiter
                    let context = pending_verify_context.take().unwrap();
                    pending_verify = None;

                    // Try to use result
                    let verified = match verified {
                        Ok(verified) => verified,
                        Err(err) => {
                            debug!(?err, view = context.view, "failed to verify proposal");
                            continue;
                        }
                    };

                    // Digest should never be verified again
                    if !verified {
                        debug!(view = context.view, "proposal failed verification");
                        continue;
                    }

                    // Handle verified proposal
                    view = context.view;
                    if !self.verified(view).await {
                        continue;
                    }
                },
                mailbox = self.mailbox_receiver.next() => {
                    // TODO: store notarizations we've backfilled (verified in backfiller to avoid using compute in this loop)
                    unimplemented!()
                },
                msg = receiver.recv() => {
                    // Parse message
                    let (s, msg) = msg.unwrap();
                    let msg = match wire::Voter::decode(msg) {
                        Ok(msg) => msg,
                        Err(err) => {
                            debug!(?err, sender = hex(&s), "failed to decode message");
                            continue;
                        }
                    };
                    let payload = match msg.payload {
                        Some(payload) => payload,
                        None => {
                            debug!(sender = hex(&s), "message missing payload");
                            continue;
                        }
                    };

                    // Process message
                    //
                    // All messages are semantically verified before being passed to the `voter`.
                    match payload {
                        wire::voter::Payload::Notarize(notarize) => {
                            view = match &notarize.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    debug!(sender = hex(&s), "missing proposal in notarize");
                                    continue;
                                }
                            };
                            self.notarize(notarize).await;
                        }
                        wire::voter::Payload::Notarization(notarization) => {
                            view = match &notarization.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    debug!(sender = hex(&s), "missing proposal in notarization");
                                    continue;
                                }
                            };
                            self.notarization(notarization).await;
                        }
                        wire::voter::Payload::Nullify(nullify) => {
                            view = nullify.view;
                            self.nullify(nullify).await;
                        }
                        wire::voter::Payload::Nullification(nullification) => {
                            view = nullification.view;
                            self.nullification(nullification).await;
                        }
                        wire::voter::Payload::Finalize(finalize) => {
                            view = match &finalize.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    debug!(sender = hex(&s), "missing proposal in finalize");
                                    continue;
                                }
                            };
                            self.finalize(finalize).await;
                        }
                        wire::voter::Payload::Finalization(finalization) => {
                            view = match &finalization.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    debug!(sender = hex(&s), "missing proposal in finalization");
                                    continue;
                                }
                            };
                            self.finalization(finalization).await;
                        }
                    };
                },
            };

            // Attempt to send any new view messages
            self.broadcast(&mut sender, view).await;

            // After sending all required messages, prune any views
            // we no longer need
            self.prune_views().await;

            // Update metrics
            self.current_view.set(view as i64);
            self.tracked_views.set(self.views.len() as i64);
        }
    }
}
