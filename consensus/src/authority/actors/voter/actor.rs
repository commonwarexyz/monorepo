use super::{
    ingress::{Application, ApplicationMessage},
    Config, Mailbox, Message,
};
use crate::{
    authority::{
        encoder::{
            finalize_namespace, notarize_namespace, nullify_message, nullify_namespace,
            proposal_message,
        },
        prover::Prover,
        wire, Context, Height, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE,
        NOTARIZE, NULLIFY_AND_FINALIZE,
    },
    Automaton, Supervisor,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::{hex, quorum};
use core::panic;
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::gauge::Gauge;
use prost::Message as _;
use rand::Rng;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::{Duration, SystemTime},
};
use std::{marker::PhantomData, sync::atomic::AtomicI64};
use tracing::{debug, info, trace, warn};

type Notarizable<'a> = Option<(wire::Proposal, &'a HashMap<PublicKey, wire::Notarize>)>;
type Nullifiable<'a> = Option<(View, &'a HashMap<PublicKey, wire::Nullify>)>;
type Finalizable<'a> = Option<(wire::Proposal, &'a HashMap<PublicKey, wire::Finalize>)>;

const GENESIS_VIEW: View = 0;
const GENESIS_HEIGHT: Height = 0;

struct Round<C: Scheme, H: Hasher, S: Supervisor> {
    hasher: H,
    supervisor: S,
    _crypto: PhantomData<C>,

    view: View,
    leader: PublicKey,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,

    // Track one proposal per view
    requested_proposal: bool,
    proposal: Option<(Digest /* proposal */, wire::Proposal)>,
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

impl<C: Scheme, H: Hasher, S: Supervisor> Round<C, H, S> {
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

    async fn add_verified_notarize(&mut self, notarize: wire::Notarize) {
        // Get proposal
        let proposal = notarize.proposal.as_ref().unwrap();

        // Compute proposal digest
        let message = proposal_message(
            proposal.index.as_ref().expect("missing index"),
            proposal.parent.as_ref().expect("missing parent"),
            &proposal.payload,
        );
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
                return;
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
                &previous_proposal.index.unwrap(),
                &previous_proposal.parent.as_ref().unwrap(),
                &previous_proposal.payload,
                &previous_vote.signature.as_ref().unwrap(),
                &proposal.index.unwrap(),
                &proposal.parent.as_ref().unwrap(),
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
            return;
        }

        // Generate vote report
        let proof = Prover::<C, H>::serialize_notarize(&notarize);

        // Store the vote
        self.notaries.insert(public_key.clone(), digest.clone());
        let entry = self.notarizes.entry(digest).or_default();
        entry.insert(public_key.clone(), notarize);

        // Report vote
        self.supervisor.report(NOTARIZE, proof).await;
    }

    async fn add_verified_nullify(&mut self, nullify: wire::Nullify) {
        // Check if already issued finalize
        let public_key = &nullify.signature.as_ref().unwrap().public_key;
        let finalize = self.finalizers.get(public_key);
        if finalize.is_none() {
            // Store the null vote
            self.nullifies.insert(public_key.clone(), nullify);
            return;
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
            &finalize_proposal.index.as_ref().unwrap(),
            &finalize_proposal.parent.as_ref().unwrap(),
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

    async fn add_verified_finalize(&mut self, finalize: wire::Finalize) {
        // Check if also issued null vote
        let proposal = finalize.proposal.as_ref().unwrap();
        let public_key = &finalize.signature.as_ref().unwrap().public_key;
        let null = self.nullifies.get(public_key);
        if let Some(null) = null {
            // Create fault
            let proof = Prover::<C, H>::serialize_nullify_finalize(
                &proposal.index.as_ref().unwrap(),
                &proposal.parent.as_ref().unwrap(),
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
            return;
        }
        // Compute proposal digest
        let message = proposal_message(
            proposal.index.as_ref().expect("missing index"),
            proposal.parent.as_ref().expect("missing parent"),
            &proposal.payload,
        );
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
                return;
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
                &previous_proposal.index.as_ref().unwrap(),
                &previous_proposal.parent.as_ref().unwrap(),
                &previous_proposal.payload,
                &previous_finalize.signature.as_ref().unwrap(),
                &proposal.index.as_ref().unwrap(),
                &proposal.parent.as_ref().unwrap(),
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
            return;
        }

        // Generate finalize report
        let proof = Prover::<C, H>::serialize_finalize(&finalize);

        // Store the finalize
        self.finalizers.insert(public_key.clone(), digest.clone());
        let entry = self.finalizes.entry(digest).or_default();
        entry.insert(public_key.clone(), finalize);

        // Report the finalize
        self.supervisor.report(FINALIZE, proof).await;
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
}

fn proposal_view(proposal: &Option<wire::Proposal>) -> Option<View> {
    proposal.as_ref().and_then(|proposal| {
        proposal
            .index
            .as_ref()
            .map(|index| index.view)
            .or_else(|| None)
    })
}

pub struct Actor<
    E: Clock + Rng,
    C: Scheme,
    H: Hasher,
    A: Automaton<Context = Context>,
    S: Supervisor<Index = View>,
> {
    runtime: E,
    crypto: C,
    hasher: H,
    application: Option<A>,
    supervisor: S,

    genesis: Digest,

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
        E: Clock + Rng + Spawner,
        C: Scheme,
        H: Hasher,
        A: Automaton<Context = Context>,
        S: Supervisor<Seed = (), Index = View>,
    > Actor<E, C, H, A, S>
{
    pub fn new(runtime: E, mut cfg: Config<C, H, A, S>) -> (Self, Mailbox) {
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

        // Get genesis
        let genesis = cfg.application.genesis();

        // Initialize store
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(1024);
        let mailbox = Mailbox::new(mailbox_sender);
        (
            Self {
                runtime,
                crypto: cfg.crypto,
                hasher: cfg.hasher,
                application: Some(cfg.application),
                supervisor: cfg.supervisor,

                genesis,

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

    fn is_notarized(&self, view: View) -> Option<&(Digest, wire::Proposal)> {
        let round = self.views.get(&view)?;
        let proposal = round.proposal.as_ref()?;
        let notarizes = round.notarizes.get(&proposal.0)?;
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

    fn find_parent(&self) -> Option<(wire::Parent, Height)> {
        let mut cursor = self.view - 1; // self.view always at least 1
        loop {
            if cursor == 0 {
                return Some((
                    wire::Parent {
                        view: GENESIS_VIEW,
                        digest: self.genesis.clone(),
                    },
                    GENESIS_HEIGHT,
                ));
            }

            // If have notarization, return
            let parent = self.is_notarized(cursor);
            if let Some(parent) = parent {
                return Some((
                    wire::Parent {
                        view: cursor,
                        digest: parent.0.clone(),
                    },
                    parent.1.index.unwrap().height,
                ));
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

    async fn propose(&mut self, mailbox: &mut Application) {
        // Check if we are leader
        {
            let round = self.views.get_mut(&self.view).unwrap();
            if round.leader != self.crypto.public_key() {
                return;
            }

            // Check if we have already requested a proposal
            if round.requested_proposal {
                return;
            }

            // Check if we have already proposed
            if round.proposal.is_some() {
                return;
            }

            // Consider proposal requested, even if parent doesn't exist to prevent
            // frequent parent searches
            round.requested_proposal = true;
        }

        // Find best parent
        let (parent, parent_height) = match self.find_parent() {
            Some(parent) => parent,
            None => return,
        };

        // Request proposal from application
        mailbox
            .propose(Context {
                index: (self.view, parent_height + 1),
                parent: (parent.view, parent.digest),
            })
            .await;
        debug!(view = self.view, "requested proposal");
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
            match self.construct_notarization(past_view, true) {
                Some(notarization) => {
                    let msg = wire::Voter {
                        payload: Some(wire::voter::Payload::Notarization(notarization)),
                    }
                    .encode_to_vec()
                    .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                    debug!(view = past_view, "rebroadcast entry notarization");
                }
                None => {
                    warn!(view = past_view, "no notarization to rebroadcast");
                }
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
        let msg = wire::Voter {
            payload: Some(wire::voter::Payload::Nullify(null.clone())),
        }
        .encode_to_vec()
        .into();
        sender.send(Recipients::All, msg, true).await.unwrap();

        // Handle the nullify
        debug!(view = self.view, "broadcasted nullify");
        self.handle_nullify(null).await;
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
        let leader = match self.supervisor.leader(nullify.view, ()) {
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
        let round = self.views.entry(nullify.view).or_insert_with(|| {
            Round::new(
                self.hasher.clone(),
                self.supervisor.clone(),
                nullify.view,
                leader,
                None,
                None,
            )
        });

        // Handle nullify
        round.add_verified_nullify(nullify).await;
    }

    async fn our_proposal(&mut self, digest: Digest, proposal: wire::Proposal) -> bool {
        // Store the proposal
        let index = proposal.index.unwrap();
        let round = self.views.get_mut(&index.view).expect("view missing");

        // Check if view timed out
        if round.broadcast_nullify {
            debug!(
                view = index.view,
                reason = "view timed out",
                "dropping our proposal"
            );
            return false;
        }

        // Store the proposal
        debug!(
            view = index.view,
            height = index.height,
            digest = hex(&digest),
            "generated proposal"
        );
        round.proposal = Some((digest, proposal));
        round.verified_proposal = true;
        round.leader_deadline = None;
        true
    }

    // Attempt to set proposal from each message received over the wire
    async fn peer_proposal(
        &mut self,
        proposal: &wire::Proposal,
        sender: &PublicKey,
        mailbox: &mut Application,
    ) {
        // Determine if proposal from leader
        let index = proposal.index.as_ref().unwrap();
        let expected_leader = match self.supervisor.leader(index.view, ()) {
            Some(leader) => leader,
            None => {
                debug!(
                    sender = hex(&sender),
                    reason = "unable to compute leader",
                    "dropping proposal"
                );
                return;
            }
        };
        if expected_leader != sender {
            trace!(
                sender = hex(&sender),
                view_leader = hex(&expected_leader),
                reason = "not leader",
                "dropping proposal"
            );
            return;
        }

        // Compute digest
        let proposal_message =
            proposal_message(index, proposal.parent.as_ref().unwrap(), &proposal.payload);
        self.hasher.update(&proposal_message);
        let proposal_digest = self.hasher.finalize();

        // Check if duplicate or conflicting
        if let Some(round) = self.views.get_mut(&index.view) {
            if round.broadcast_nullify {
                warn!(
                    leader = hex(&expected_leader),
                    view = round.view,
                    reason = "view already timed out",
                    "dropping proposal"
                );
                return;
            }
            if round.proposal.is_some() {
                let round_digest = &round.proposal.as_ref().unwrap().0;
                if *round_digest == proposal_digest {
                    debug!(
                        leader = hex(&expected_leader),
                        view = round.view,
                        reason = "already received proposal",
                        "dropping proposal"
                    );
                    return;
                } else {
                    // This will be handled as a conflicting vote.
                    warn!(
                        leader = hex(&expected_leader),
                        view = round.view,
                        round_digest = hex(round_digest),
                        proposal_digest = hex(&proposal_digest),
                        "conflicting proposal"
                    );
                    return;
                }
            }
        }

        // Check parent validity
        let parent = proposal.parent.as_ref().unwrap();
        if index.view <= parent.view {
            debug!(
                view = index.view,
                parent = parent.view,
                reason = "invalid parent",
                "dropping proposal"
            );
            return;
        }
        if parent.view < self.last_finalized {
            debug!(
                view = index.view,
                parent = parent.view,
                last_finalized = self.last_finalized,
                reason = "parent behind finalized tip",
                "dropping proposal"
            );
            return;
        }

        // Ensure we have required notarizations
        let mut cursor = match index.view {
            0 => {
                debug!(
                    view = index.view,
                    reason = "invalid view",
                    "dropping proposal"
                );
                return;
            }
            _ => index.view - 1,
        };
        loop {
            if cursor == parent.view {
                // Check if first block
                if parent.view == GENESIS_VIEW {
                    if parent.digest != self.genesis {
                        debug!(
                            view = cursor,
                            proposal = hex(&parent.digest),
                            genesis = hex(&self.genesis),
                            reason = "invalid genesis",
                            "dropping proposal"
                        );
                        return;
                    }
                    if index.height != GENESIS_HEIGHT + 1 {
                        debug!(
                            view = cursor,
                            height = index.height,
                            reason = "invalid height",
                            "dropping proposal"
                        );
                        return;
                    }
                    break;
                }

                // Check notarization exists
                let (parent_digest, parent_proposal) = match self.is_notarized(cursor) {
                    Some(parent) => parent,
                    None => {
                        debug!(
                            view = cursor,
                            reason = "missing notarization",
                            "dropping proposal"
                        );
                        return;
                    }
                };
                if parent_digest != &parent.digest {
                    debug!(
                        view = cursor,
                        parent = hex(&parent.digest),
                        proposal = hex(&parent_digest),
                        reason = "invalid parent",
                        "dropping proposal"
                    );
                    return;
                }
                if parent_proposal.index.unwrap().height + 1 != index.height {
                    debug!(
                        view = cursor,
                        parent = hex(&parent.digest),
                        proposal = hex(&parent_digest),
                        height = index.height,
                        reason = "invalid height",
                        "dropping proposal"
                    );
                    return;
                }

                // Peer proposal references a valid parent
                break;
            }

            // Check nullification exists in gap
            if !self.is_nullified(cursor) {
                debug!(view = cursor, "missing nullification");
                return;
            }
            cursor -= 1;
        }

        // Verify the proposal
        let round = self.views.entry(index.view).or_insert_with(|| {
            Round::new(
                self.hasher.clone(),
                self.supervisor.clone(),
                index.view,
                expected_leader,
                None,
                None,
            )
        });
        round.proposal = Some((proposal_digest.clone(), proposal.clone()));
        mailbox
            .verify(
                Context {
                    index: (index.view, index.height),
                    parent: (parent.view, parent.digest.clone()),
                },
                proposal.payload.clone(),
            )
            .await;
        debug!(
            view = index.view,
            height = index.height,
            digest = hex(&proposal_digest),
            payload = hex(&proposal.payload),
            "requested proposal verification",
        );
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

    fn prune_views(&mut self) {
        loop {
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
            } else {
                return;
            }
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

    async fn notarize(&mut self, notarize: wire::Notarize, mailbox: &mut Application) {
        // Extract proposal
        let proposal = match &notarize.proposal {
            Some(proposal) => proposal,
            _ => {
                debug!(reason = "missing proposal", "dropping finalize");
                return;
            }
        };
        let proposal_index = match &proposal.index {
            Some(index) => index,
            _ => {
                debug!(reason = "missing index", "dropping finalize");
                return;
            }
        };
        let proposal_parent = match &proposal.parent {
            Some(parent) => parent,
            _ => {
                debug!(reason = "missing parent", "dropping finalize");
                return;
            }
        };

        // Ensure we are in the right view to process this message
        if !self.interesting(proposal_index.view, false) {
            debug!(
                vote_view = proposal_index.view,
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
            .is_participant(proposal_index.view, &signature.public_key)
        {
            Some(is) => is,
            None => {
                debug!(
                    view = proposal_index.view,
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
        let notarize_message = proposal_message(proposal_index, proposal_parent, &proposal.payload);
        if !C::verify(
            &self.notarize_namespace,
            &notarize_message,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping vote");
            return;
        }

        // Handle peer proposal
        self.peer_proposal(proposal, &signature.public_key, mailbox)
            .await;

        // Handle notarize
        self.handle_notarize(notarize).await;
    }

    async fn handle_notarize(&mut self, notarize: wire::Notarize) {
        // Check to see if vote is for proposal in view
        let view = notarize.proposal.as_ref().unwrap().index.unwrap().view;
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
        round.add_verified_notarize(notarize).await;
    }

    async fn notarization(&mut self, notarization: wire::Notarization, mailbox: &mut Application) {
        // Extract proposal
        let proposal = match &notarization.proposal {
            Some(proposal) => proposal,
            _ => {
                debug!(reason = "missing proposal", "dropping finalize");
                return;
            }
        };
        let proposal_index = match &proposal.index {
            Some(index) => index,
            _ => {
                debug!(reason = "missing index", "dropping finalize");
                return;
            }
        };
        let proposal_parent = match &proposal.parent {
            Some(parent) => parent,
            _ => {
                debug!(reason = "missing parent", "dropping finalize");
                return;
            }
        };

        // Check if we are still in a view where this notarization could help
        if !self.interesting(proposal_index.view, true) {
            trace!(
                notarization_view = proposal_index.view,
                our_view = self.view,
                reason = "outdated notarization",
                "dropping notarization"
            );
            return;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        let round = self.views.get_mut(&proposal_index.view);
        if let Some(ref round) = round {
            if round.broadcast_notarization {
                trace!(
                    view = proposal_index.view,
                    reason = "already broadcast notarization",
                    "dropping notarization"
                );
                return;
            }
        }

        // Ensure notarization has valid number of signatures
        let (threshold, count) = match self.threshold(proposal_index.view) {
            Some(participation) => participation,
            None => {
                debug!(
                    view = proposal_index.view,
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
        let message = proposal_message(proposal_index, proposal_parent, &proposal.payload);
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

            // Handle peer proposal
            self.peer_proposal(proposal, &signature.public_key, mailbox)
                .await;
        }
        debug!(view = proposal_index.view, "notarization verified");

        // Handle notarization
        self.handle_notarization(notarization).await;
    }

    async fn handle_notarization(&mut self, notarization: wire::Notarization) {
        // Add signatures to view (needed to broadcast notarization if we get proposal)
        let view = notarization.proposal.as_ref().unwrap().index.unwrap().view;
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
            round.add_verified_notarize(notarize).await
        }

        // Clear leader and advance deadlines (if they exist)
        round.leader_deadline = None;
        round.advance_deadline = None;

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
            round.add_verified_nullify(nullify).await
        }

        // Clear leader and advance deadlines (if they exist)
        round.leader_deadline = None;
        round.advance_deadline = None;

        // TODO: If `> f` notarized a given proposal, then we should backfill...

        // Enter next view
        self.enter_view(nullification.view + 1);
    }

    async fn finalize(&mut self, finalize: wire::Finalize, mailbox: &mut Application) {
        // Extract proposal
        let proposal = match &finalize.proposal {
            Some(proposal) => proposal,
            _ => {
                debug!(reason = "missing proposal", "dropping finalize");
                return;
            }
        };
        let proposal_index = match &proposal.index {
            Some(index) => index,
            _ => {
                debug!(reason = "missing index", "dropping finalize");
                return;
            }
        };
        let proposal_parent = match &proposal.parent {
            Some(parent) => parent,
            _ => {
                debug!(reason = "missing parent", "dropping finalize");
                return;
            }
        };

        // Ensure we are in the right view to process this message
        if !self.interesting(proposal_index.view, false) {
            debug!(
                finalize_view = proposal_index.view,
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
            .is_participant(proposal_index.view, &signature.public_key)
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
        let finalize_message = proposal_message(proposal_index, proposal_parent, &proposal.payload);
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

        // Handle peer proposal
        self.peer_proposal(proposal, &signature.public_key, mailbox)
            .await;

        // Handle finalize
        self.handle_finalize(finalize).await;
    }

    async fn handle_finalize(&mut self, finalize: wire::Finalize) {
        // Get view for finalize
        let view = finalize.proposal.as_ref().unwrap().index.unwrap().view;
        let leader = self
            .supervisor
            .leader(view, ())
            .expect("unable to get leader");
        let view = self.views.entry(view).or_insert_with(|| {
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
        view.add_verified_finalize(finalize).await;
    }

    async fn finalization(&mut self, finalization: wire::Finalization, mailbox: &mut Application) {
        // Extract proposal
        let proposal = match &finalization.proposal {
            Some(proposal) => proposal,
            _ => {
                debug!(reason = "missing proposal", "dropping finalize");
                return;
            }
        };
        let proposal_index = match &proposal.index {
            Some(index) => index,
            _ => {
                debug!(reason = "missing index", "dropping finalize");
                return;
            }
        };
        let proposal_parent = match &proposal.parent {
            Some(parent) => parent,
            _ => {
                debug!(reason = "missing parent", "dropping finalize");
                return;
            }
        };

        // Check if we are still in a view where this finalization could help
        if !self.interesting(proposal_index.view, true) {
            trace!(
                finalization_view = proposal_index.view,
                our_view = self.view,
                reason = "outdated finalization",
                "dropping finalization"
            );
            return;
        }

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        let round = self.views.get_mut(&proposal_index.view);
        if let Some(ref round) = round {
            if round.broadcast_finalization {
                trace!(
                    view = proposal_index.view,
                    height = proposal_index.height,
                    reason = "already broadcast finalization",
                    "dropping finalization"
                );
                return;
            }
        }

        // Ensure finalization has valid number of signatures
        let (threshold, count) = match self.threshold(proposal_index.view) {
            Some(participation) => participation,
            None => {
                debug!(
                    view = proposal_index.view,
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
        let message = proposal_message(proposal_index, proposal_parent, &proposal.payload);
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

            // Handle peer proposal
            self.peer_proposal(proposal, &signature.public_key, mailbox)
                .await;
        }
        debug!(view = proposal_index.view, "finalization verified");

        // Process finalization
        self.handle_finalization(finalization).await;
    }

    async fn handle_finalization(&mut self, finalization: wire::Finalization) {
        // Add signatures to view (needed to broadcast finalization if we get proposal)
        let view = finalization.proposal.as_ref().unwrap().index.unwrap().view;
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
            round.add_verified_finalize(finalize).await;
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
                    &proposal_message(
                        proposal.index.as_ref().unwrap(),
                        proposal.parent.as_ref().unwrap(),
                        &proposal.payload,
                    ),
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
                    &proposal_message(
                        proposal.index.as_ref().unwrap(),
                        proposal.parent.as_ref().unwrap(),
                        &proposal.payload,
                    ),
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
            // Broadcast the vote
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Notarize(notarize.clone())),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();

            // Handle the vote
            self.handle_notarize(notarize).await;
        };

        // Attempt to notarization
        if let Some(notarization) = self.construct_notarization(view, false) {
            // Broadcast the notarization
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Notarization(notarization.clone())),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();

            // Handle the notarization
            self.handle_notarization(notarization).await;
        };

        // Attempt to nullification
        //
        // We handle broadcast of nullify in `timeout`.
        if let Some(nullification) = self.construct_nullification(view, false) {
            // Broadcast the nullification
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Nullification(nullification.clone())),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();

            // Handle the nullification
            self.handle_nullification(nullification).await;
        }

        // Attempt to finalize
        if let Some(finalize) = self.construct_finalize(view) {
            // Broadcast the finalize
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Finalize(finalize.clone())),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();

            // Handle the finalize
            self.handle_finalize(finalize).await;
        };

        // Attempt to finalization
        if let Some(finalization) = self.construct_finalization(view, false) {
            // Broadcast the finalization
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Finalization(finalization.clone())),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();

            // Handle the finalization
            self.handle_finalization(finalization).await;
        };
    }

    pub async fn run(mut self, mut sender: impl Sender, mut receiver: impl Receiver) {
        // Spawn async application processor
        //
        // TODO: clean up these abstractions
        // TODO: use automaton rather than application
        let (application_sender, mut application_receiver) = mpsc::channel(1024);
        let mut application_mailbox = Application::new(application_sender);
        self.runtime.spawn("application", {
            let mut application = self.application.take().unwrap();
            let mut mailbox = self.mailbox_sender.clone();
            async move {
                // TODO: should we handle these messages concurrently?
                while let Some(msg) = application_receiver.next().await {
                    match msg {
                        ApplicationMessage::Propose { context } => {
                            let payload = match application.propose(context.clone()).await {
                                Some(payload) => payload,
                                None => continue,
                            };
                            mailbox.proposed(context, payload).await;
                        }
                        ApplicationMessage::Verify { context, payload } => {
                            let result = match application.verify(context.clone(), payload).await {
                                Some(verified) => verified,
                                None => continue, // means that can't be verified (not sure if valid or not)
                            };
                            mailbox.verified(context, result).await;
                        }
                        ApplicationMessage::Broadcast {
                            context,
                            header,
                            payload,
                        } => {
                            application.broadcast(context, header, payload).await;
                        }
                    }
                }
            }
        });

        // Add initial view
        //
        // We start on view 1 because the genesis container occupies view 0/height 0.
        self.enter_view(1);
        self.current_view.set(1);
        self.tracked_views.set(1);

        // TODO: rebuild from journal

        // Process messages
        loop {
            // Attempt to propose a container
            self.propose(&mut application_mailbox).await;

            // Wait for a timeout to fire or for a message to arrive
            let timeout = self.timeout_deadline();
            let view;
            select! {
                _ = self.runtime.sleep_until(timeout) => {
                    // Trigger the timeout
                    self.timeout(&mut sender).await;
                    view = self.view;
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = mailbox.unwrap();
                    match msg {
                        Message::Proposed{ context, payload } => {
                            // If we have already moved to another view, drop the response as we will
                            // not broadcast it
                            if self.view != context.index.0 {
                                debug!(view = context.index.0, our_view = self.view, reason = "no longer in required view", "dropping requested proposal");
                                continue;
                            }

                            // Construct proposal
                            let index = wire::Index {
                                view: context.index.0,
                                height: context.index.1,
                            };
                            let parent = wire::Parent {
                                view: context.parent.0,
                                digest: context.parent.1.clone(),
                            };
                            let message = proposal_message(&index, &parent, &payload);
                            self.hasher.update(&message);
                            let proposal_digest = self.hasher.finalize();
                            let proposal = wire::Proposal {
                                index: Some(index),
                                parent: Some(parent),
                                payload: payload.clone(),
                            };
                            if !self.our_proposal(proposal_digest, proposal.clone()).await {
                                continue;
                            }
                            view = self.view;

                            // Construct header
                            //
                            // TODO: refactor to only sign once
                            let notarize = wire::Notarize {
                                proposal: Some(proposal),
                                signature: Some(wire::Signature {
                                    public_key: self.crypto.public_key(),
                                    signature: self.crypto.sign(&self.notarize_namespace, &message),
                                }),
                            };
                            let header = Prover::<C, H>::serialize_notarize(&notarize);

                            // Notify application of proposal
                            application_mailbox.broadcast(context, header, payload).await;
                        },
                        Message::Verified { context, result } => {
                            // TODO: prevent future verification/penalize?
                            if !result {
                                debug!(view = context.index.0, "proposal failed verification");
                                continue;
                            }

                            // Handle verified proposal
                            view = context.index.0;
                            if !self.verified(view).await {
                                continue;
                            }

                            // TODO: Have resolver hold on to verified proposals in case they become notarized or if they are notarized
                            // but learned about later.
                        },
                        Message::Backfilled { notarizations: _ } => {
                            // TODO: store notarizations we've backfilled (verified in backfiller to avoid using compute in this loop)
                            unimplemented!()
                        },
                    }
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
                            view = match proposal_view(&notarize.proposal) {
                                Some(view) => view,
                                None => {
                                    debug!(sender = hex(&s), "missing view in notarize");
                                    continue;
                                }
                            };
                            self.notarize(notarize, &mut application_mailbox).await;
                        }
                        wire::voter::Payload::Notarization(notarization) => {
                            view = match proposal_view(&notarization.proposal) {
                                Some(view) => view,
                                None => {
                                    debug!(sender = hex(&s), "missing view in notarization");
                                    continue;
                                }
                            };
                            self.notarization(notarization, &mut application_mailbox).await;
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
                            view = match proposal_view(&finalize.proposal) {
                                Some(view) => view,
                                None => {
                                    debug!(sender = hex(&s), "missing view in finalize");
                                    continue;
                                }
                            };
                            self.finalize(finalize, &mut application_mailbox).await;
                        }
                        wire::voter::Payload::Finalization(finalization) => {
                            view = match proposal_view(&finalization.proposal) {
                                Some(view) => view,
                                None => {
                                    debug!(sender = hex(&s), "missing view in finalization");
                                    continue;
                                }
                            };
                            self.finalization(finalization, &mut application_mailbox).await;
                        }
                    };
                },
            };

            // Attempt to send any new view messages
            self.broadcast(&mut sender, view).await;

            // After sending all required messages, prune any views
            // we no longer need
            self.prune_views();

            // TODO: update backfiller if we've gone to a new view
            // TODO: we need to provide each view, not just latest (maybe ok)?

            // Update metrics
            self.current_view.set(view as i64);
            self.tracked_views.set(self.views.len() as i64);
        }
    }
}
