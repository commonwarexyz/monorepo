use super::{Config, Mailbox, Message};
use crate::{
    authority::{
        actors::{resolver, Proposal},
        encoder::{
            finalize_digest, finalize_namespace, proposal_digest, proposal_namespace, vote_digest,
            vote_namespace,
        },
        wire, Context, Height, Prover, View, CONFLICTING_FINALIZE, CONFLICTING_PROPOSAL,
        CONFLICTING_VOTE, FINALIZE, NULL_AND_FINALIZE, PROPOSAL, VOTE,
    },
    Automaton, Finalizer, Supervisor,
};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::Clock;
use commonware_utils::{hex, quorum};
use futures::{channel::mpsc, future::Either, StreamExt};
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore,
    RateLimiter,
};
use prometheus_client::metrics::gauge::Gauge;
use prost::Message as _;
use rand::prelude::SliceRandom;
use rand::Rng;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::{Duration, SystemTime},
};
use std::{marker::PhantomData, sync::atomic::AtomicI64};
use tracing::{debug, info, trace, warn};

type Notarizable<'a> = Option<(
    Option<Digest>,
    Option<Height>,
    &'a HashMap<PublicKey, wire::Vote>,
)>;

struct Round<C: Scheme, H: Hasher, A: Supervisor> {
    application: A,
    _crypto: PhantomData<C>,
    _hasher: PhantomData<H>,

    leader: PublicKey,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    null_vote_retry: Option<SystemTime>,

    // Track one proposal per view
    next_proposal_request: Option<SystemTime>,
    requested_proposal: bool,
    proposal: Option<(
        Digest, /* proposal */
        Digest, /* payload */
        wire::Proposal,
    )>,
    verified_proposal: bool,

    // Track broadcast
    broadcast_vote: bool,
    broadcast_finalize: bool,

    // Track votes for all proposals (ensuring any participant only has one recorded vote)
    proposal_voters: HashMap<PublicKey, Digest>,
    proposal_votes: HashMap<Digest, HashMap<PublicKey, wire::Vote>>,
    broadcast_proposal_notarization: bool,

    timeout_fired: bool,
    null_votes: HashMap<PublicKey, wire::Vote>,
    broadcast_null_notarization: bool,

    // Track finalizes for all proposals (ensuring any participant only has one recorded finalize)
    finalizers: HashMap<PublicKey, Digest>,
    finalizes: HashMap<Digest, HashMap<PublicKey, wire::Finalize>>,
    broadcast_finalization: bool,
}

impl<C: Scheme, H: Hasher, A: Supervisor> Round<C, H, A> {
    pub fn new(
        application: A,
        leader: PublicKey,
        leader_deadline: Option<SystemTime>,
        advance_deadline: Option<SystemTime>,
    ) -> Self {
        Self {
            application,
            _crypto: PhantomData,
            _hasher: PhantomData,

            leader,
            leader_deadline,
            advance_deadline,
            null_vote_retry: None,

            next_proposal_request: None,
            requested_proposal: false,
            proposal: None,
            verified_proposal: false,

            broadcast_vote: false,
            broadcast_finalize: false,

            proposal_voters: HashMap::new(),
            proposal_votes: HashMap::new(),
            broadcast_proposal_notarization: false,

            timeout_fired: false,
            null_votes: HashMap::new(),
            broadcast_null_notarization: false,

            finalizers: HashMap::new(),
            finalizes: HashMap::new(),
            broadcast_finalization: false,
        }
    }

    async fn add_verified_vote(&mut self, vote: wire::Vote) {
        // Determine whether or not this is a null vote
        let public_key = &vote.signature.as_ref().unwrap().public_key;
        if vote.digest.is_none() {
            // Check if already issued finalize
            let finalize = self.finalizers.get(public_key);
            if finalize.is_none() {
                // Store the null vote
                self.null_votes.insert(public_key.clone(), vote);
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
            let proof = Prover::<C, H>::serialize_null_finalize(
                vote.view,
                finalize.height,
                finalize.digest.clone(),
                finalize.signature.clone().unwrap(),
                vote.signature.clone().unwrap(),
            );
            self.application.report(NULL_AND_FINALIZE, proof).await;
            warn!(
                view = vote.view,
                signer = hex(public_key),
                activity = NULL_AND_FINALIZE,
                "recorded fault"
            );
            return;
        }
        let digest = vote.digest.clone().unwrap();

        // Check if already voted
        if let Some(previous_vote) = self.proposal_voters.get(public_key) {
            if previous_vote == &digest {
                trace!(
                    view = vote.view,
                    signer = hex(public_key),
                    previous_vote = hex(previous_vote),
                    "already voted"
                );
                return;
            }

            // Create fault
            let previous_vote = self
                .proposal_votes
                .get(previous_vote)
                .unwrap()
                .get(public_key)
                .unwrap();
            let proof = Prover::<C, H>::serialize_conflicting_vote(
                vote.view,
                previous_vote.height.unwrap(),
                previous_vote.digest.clone().unwrap(),
                previous_vote.signature.clone().unwrap(),
                vote.height.unwrap(),
                digest.clone(),
                vote.signature.clone().unwrap(),
            );
            self.application.report(CONFLICTING_VOTE, proof).await;
            warn!(
                view = vote.view,
                signer = hex(public_key),
                activity = CONFLICTING_VOTE,
                "recorded fault"
            );
            return;
        }

        // Store the vote
        self.proposal_voters
            .insert(public_key.clone(), digest.clone());
        let entry = self.proposal_votes.entry(digest).or_default();
        entry.insert(public_key.clone(), vote.clone());

        // Report the vote
        let proof = Prover::<C, H>::serialize_vote(vote);
        self.application.report(VOTE, proof).await;
    }

    fn notarizable_proposal(&mut self, threshold: u32, force: bool) -> Notarizable {
        if !force
            && (self.broadcast_proposal_notarization
                || self.broadcast_null_notarization
                || !self.verified_proposal)
        {
            // We only want to broadcast a notarization if we have verified some proposal at
            // this point.
            return None;
        }
        for (proposal, votes) in self.proposal_votes.iter() {
            if (votes.len() as u32) < threshold {
                continue;
            }

            // Ensure we have the proposal we are going to broadcast a notarization for
            let height = match &self.proposal {
                Some((digest, _, pro)) => {
                    if digest != proposal {
                        debug!(
                            view = pro.view,
                            proposal = hex(proposal),
                            reason = "proposal mismatch",
                            "skipping notarization broadcast"
                        );
                        continue;
                    }
                    debug!(
                        view = pro.view,
                        height = pro.height,
                        proposal = hex(proposal),
                        "broadcasting notarization"
                    );
                    pro.height
                }
                None => {
                    continue;
                }
            };

            // There should never exist enough votes for multiple proposals, so it doesn't
            // matter which one we choose.
            self.broadcast_proposal_notarization = true;
            return Some((Some(proposal.clone()), Some(height), votes));
        }
        None
    }

    fn notarizable_null(&mut self, threshold: u32, force: bool) -> Notarizable {
        if !force && (self.broadcast_null_notarization || self.broadcast_proposal_notarization) {
            return None;
        }
        if (self.null_votes.len() as u32) < threshold {
            return None;
        }
        self.broadcast_null_notarization = true;
        Some((None, None, &self.null_votes))
    }

    async fn add_verified_finalize(&mut self, finalize: wire::Finalize) {
        // Check if also issued null vote
        let public_key = &finalize.signature.as_ref().unwrap().public_key;
        let null_vote = self.null_votes.get(public_key);
        if let Some(null_vote) = null_vote {
            // Create fault
            let proof = Prover::<C, H>::serialize_null_finalize(
                finalize.view,
                finalize.height,
                finalize.digest.clone(),
                finalize.signature.clone().unwrap(),
                null_vote.signature.clone().unwrap(),
            );
            self.application.report(NULL_AND_FINALIZE, proof).await;
            warn!(
                view = finalize.view,
                signer = hex(public_key),
                activity = NULL_AND_FINALIZE,
                "recorded fault"
            );
            return;
        }

        // Check if already finalized
        if let Some(previous_finalize) = self.finalizers.get(public_key) {
            if previous_finalize == &finalize.digest {
                trace!(
                    view = finalize.view,
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
            let proof = Prover::<C, H>::serialize_conflicting_finalize(
                finalize.view,
                previous_finalize.height,
                previous_finalize.digest.clone(),
                previous_finalize.signature.clone().unwrap(),
                finalize.height,
                finalize.digest.clone(),
                finalize.signature.clone().unwrap(),
            );
            self.application.report(CONFLICTING_FINALIZE, proof).await;
            warn!(
                view = finalize.view,
                signer = hex(public_key),
                activity = CONFLICTING_FINALIZE,
                "recorded fault"
            );
            return;
        }

        // Store the finalize
        self.finalizers
            .insert(public_key.clone(), finalize.digest.clone());
        let entry = self.finalizes.entry(finalize.digest.clone()).or_default();
        entry.insert(public_key.clone(), finalize.clone());

        // Report the finalize
        let proof = Prover::<C, H>::serialize_finalize(finalize);
        self.application.report(FINALIZE, proof).await;
    }

    fn finalizable_proposal(
        &mut self,
        threshold: u32,
        force: bool,
    ) -> Option<(Digest, Height, &HashMap<PublicKey, wire::Finalize>)> {
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
            let height = match &self.proposal {
                Some((digest, _, pro)) => {
                    if digest != proposal {
                        debug!(
                            proposal = hex(proposal),
                            digest = hex(digest),
                            reason = "proposal mismatch",
                            "skipping finalization broadcast"
                        );
                        continue;
                    }
                    pro.height
                }
                None => {
                    continue;
                }
            };

            // There should never exist enough finalizes for multiple proposals, so it doesn't
            // matter which one we choose.
            self.broadcast_finalization = true;
            return Some((proposal.clone(), height, finalizes));
        }
        None
    }
}

pub struct Actor<
    E: Clock + Rng + GClock,
    C: Scheme,
    H: Hasher,
    A: Automaton<Context = Context> + Supervisor<Index = View> + Finalizer,
> {
    runtime: E,
    crypto: C,
    hasher: H,
    application: A,

    proposal_namespace: Vec<u8>,
    vote_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    leader_timeout: Duration,
    notarization_timeout: Duration,
    null_vote_retry: Duration,
    proposal_retry: Duration,
    activity_timeout: View,
    fetch_timeout: Duration,
    max_fetch_count: u64,
    max_fetch_size: usize,
    fetch_rate_limiter:
        RateLimiter<PublicKey, HashMapStateStore<PublicKey>, E, NoOpMiddleware<E::Instant>>,

    mailbox_receiver: mpsc::Receiver<Message>,

    last_finalized: View,
    view: View,
    views: BTreeMap<View, Round<C, H, A>>,

    current_view: Gauge,
    tracked_views: Gauge,
}

impl<
        E: Clock + Rng + GClock,
        C: Scheme,
        H: Hasher,
        A: Automaton<Context = Context> + Supervisor<Index = View> + Finalizer,
    > Actor<E, C, H, A>
{
    pub fn new(runtime: E, cfg: Config<C, H, A>) -> (Self, Mailbox) {
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

        // Initialize rate limiter
        let fetch_rate_limiter = RateLimiter::hashmap_with_clock(cfg.fetch_rate_per_peer, &runtime);

        // Initialize store
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(1024);
        (
            Self {
                runtime,
                crypto: cfg.crypto,
                hasher: cfg.hasher,
                application: cfg.application,

                proposal_namespace: proposal_namespace(&cfg.namespace),
                vote_namespace: vote_namespace(&cfg.namespace),
                finalize_namespace: finalize_namespace(&cfg.namespace),

                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                null_vote_retry: cfg.null_vote_retry,
                proposal_retry: cfg.proposal_retry,
                fetch_timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
                max_fetch_size: cfg.max_fetch_size,
                fetch_rate_limiter,

                activity_timeout: cfg.activity_timeout,

                mailbox_receiver,

                last_finalized: 0,
                view: 0,
                views: BTreeMap::new(),

                current_view,
                tracked_views,
            },
            Mailbox::new(mailbox_sender),
        )
    }

    fn leader(&self, view: View) -> Option<PublicKey> {
        let validators = match self.application.participants(view) {
            Some(validators) => validators,
            None => return None,
        };
        Some(validators[view as usize % validators.len()].clone())
    }

    async fn propose(&mut self, resolver: &mut resolver::Mailbox) -> Option<SystemTime> {
        // Check if we are leader
        let view = self.views.get_mut(&self.view).unwrap();
        if view.leader != self.crypto.public_key() {
            return None;
        }

        // Check if we need to wait to propose
        if let Some(next_proposal_request) = view.next_proposal_request {
            if next_proposal_request > self.runtime.current() {
                return Some(next_proposal_request);
            }
        }

        // Check if we have already requested a proposal
        if view.requested_proposal {
            return None;
        }

        // Check if we have already proposed
        if view.proposal.is_some() {
            return None;
        }

        // Request proposal from resolver
        view.requested_proposal = true;
        resolver.propose(self.view, self.crypto.public_key()).await;
        debug!(view = self.view, "requested proposal");
        None
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
        if let Some(deadline) = view.null_vote_retry {
            return deadline;
        }

        // Set null vote retry, if none already set
        let null_vote_retry = self.runtime.current() + self.null_vote_retry;
        view.null_vote_retry = Some(null_vote_retry);
        null_vote_retry
    }

    async fn timeout(&mut self, sender: &mut impl Sender) {
        // Set timeout fired
        let view = self.views.get_mut(&self.view).unwrap();
        let mut retry = false;
        if view.timeout_fired {
            retry = true;
        }
        view.timeout_fired = true;

        // Remove deadlines
        view.leader_deadline = None;
        view.advance_deadline = None;
        view.null_vote_retry = None;

        // Broadcast notarization that led to entrance to this view
        let past_view = self.view - 1;
        if retry && past_view > 0 {
            match self.construct_notarization(past_view, true) {
                Some(notarization) => {
                    debug!(view = past_view, "rebroadcasting notarization");
                    let msg = wire::Consensus {
                        payload: Some(wire::consensus::Payload::Notarization(notarization)),
                    }
                    .encode_to_vec()
                    .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                None => {
                    warn!(view = past_view, "no notarization to rebroadcast");
                }
            }
        }

        // Construct null vote
        let digest = vote_digest(self.view, None, None);
        let vote = wire::Vote {
            view: self.view,
            height: None,
            digest: None,
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(&self.vote_namespace, &digest),
            }),
        };
        let msg = wire::Consensus {
            payload: Some(wire::consensus::Payload::Vote(vote.clone())),
        }
        .encode_to_vec()
        .into();
        sender.send(Recipients::All, msg, true).await.unwrap();

        // Handle the vote
        debug!(view = self.view, "broadcasted null vote");
        self.handle_vote(vote).await;
    }

    async fn our_proposal(
        &mut self,
        proposal_hash: Digest,
        payload_hash: Digest,
        proposal: wire::Proposal,
    ) -> bool {
        // Store the proposal
        let view = self.views.get_mut(&proposal.view).expect("view missing");

        // Check if view timed out
        if view.timeout_fired {
            debug!(
                view = proposal.view,
                reason = "view timed out",
                "dropping our proposal"
            );
            return false;
        }

        // Store the proposal
        let proposal_view = proposal.view;
        let proposal_height = proposal.height;
        let proposal_parent = proposal.parent.clone();
        let proposal_signature = proposal.signature.clone().unwrap();
        debug!(
            view = proposal_view,
            height = proposal_height,
            digest = hex(&proposal_hash),
            retried = view.next_proposal_request.is_some(),
            "generated proposal"
        );
        view.proposal = Some((proposal_hash, payload_hash.clone(), proposal));
        view.verified_proposal = true;
        view.leader_deadline = None;

        // Report the proposal
        let proof = Prover::<C, H>::serialize_proposal(
            proposal_view,
            proposal_height,
            proposal_parent,
            payload_hash,
            proposal_signature,
        );
        self.application.report(PROPOSAL, proof).await;
        true
    }

    async fn peer_proposal(&mut self, resolver: &mut resolver::Mailbox, proposal: wire::Proposal) {
        // Parse signature
        let signature = match &proposal.signature {
            Some(signature) => signature,
            _ => {
                debug!(reason = "missing signature", "dropping proposal");
                return;
            }
        };

        // Ensure we are in the right view to process this message
        if proposal.view != self.view && proposal.view != self.view + 1 {
            debug!(
                proposal_view = proposal.view,
                our_view = self.view,
                reason = "incorrect view",
                "dropping proposal"
            );
            return;
        }

        // Check expected leader
        if !C::validate(&signature.public_key) {
            debug!(reason = "invalid signature", "dropping proposal");
            return;
        }
        let expected_leader = match self.leader(proposal.view) {
            Some(leader) => leader,
            None => {
                debug!(
                    proposal_leader = hex(&signature.public_key),
                    reason = "unable to compute leader",
                    "dropping proposal"
                );
                return;
            }
        };
        if expected_leader != signature.public_key {
            debug!(
                proposal_leader = hex(&signature.public_key),
                view_leader = hex(&expected_leader),
                reason = "leader mismatch",
                "dropping proposal"
            );
            return;
        }

        // Compute digest
        let payload_hash = match self.application.parse(proposal.payload.clone()).await {
            Some(digest) => digest,
            None => {
                debug!(reason = "invalid payload", "dropping proposal");
                return;
            }
        };
        let proposal_digest = proposal_digest(
            proposal.view,
            proposal.height,
            &proposal.parent,
            &payload_hash,
        );
        self.hasher.update(&proposal_digest);
        let proposal_hash = self.hasher.finalize();

        // Check if duplicate or conflicting
        let mut previous = None;
        if let Some(view) = self.views.get_mut(&proposal.view) {
            if view.timeout_fired {
                warn!(
                    leader = hex(&expected_leader),
                    view = proposal.view,
                    reason = "view already timed out",
                    "dropping proposal"
                );
                return;
            }
            if view.proposal.is_some() {
                let incoming_hash = &view.proposal.as_ref().unwrap().0;
                if *incoming_hash == proposal_hash {
                    debug!(
                        leader = hex(&expected_leader),
                        view = proposal.view,
                        reason = "already received proposal",
                        "dropping proposal"
                    );
                    return;
                }
                previous = view.proposal.as_ref();
            }
        }

        // Verify the signature
        let public_key = &signature.public_key;
        if !C::verify(
            &self.proposal_namespace,
            &proposal_digest,
            public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping proposal");
            return;
        }

        // Collect fault for leader
        if let Some(previous) = previous {
            // Record fault
            let signature_1 = previous.2.signature.clone().unwrap();
            let signature_2 = proposal.signature.clone().unwrap();
            let proof = Prover::<C, H>::serialize_conflicting_proposal(
                proposal.view,
                previous.2.height,
                previous.2.parent.clone(),
                previous.1.clone(),
                signature_1,
                proposal.height,
                proposal.parent.clone(),
                payload_hash.clone(),
                signature_2,
            );
            self.application.report(CONFLICTING_PROPOSAL, proof).await;
            warn!(
                leader = hex(&expected_leader),
                view = proposal.view,
                activity = CONFLICTING_PROPOSAL,
                "recorded fault"
            );
            return;
        }

        // Verify the proposal
        //
        // This will fail if we haven't notified the application of this parent.
        let view = self
            .views
            .entry(proposal.view)
            .or_insert_with(|| Round::new(self.application.clone(), expected_leader, None, None));
        view.proposal = Some((
            proposal_hash.clone(),
            payload_hash.clone(),
            proposal.clone(),
        ));
        resolver
            .verify(proposal_hash.clone(), proposal.clone())
            .await;
        trace!(
            view = proposal.view,
            height = proposal.height,
            digest = hex(&proposal_hash),
            "requested proposal verification",
        );
    }

    async fn verified(&mut self, view: View) -> bool {
        // Check if view still relevant
        let view_obj = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                debug!(view, reason = "view missing", "dropping verified proposal");
                return false;
            }
        };

        // Ensure we haven't timed out
        if view_obj.timeout_fired {
            debug!(
                view,
                reason = "view timed out",
                "dropping verified proposal"
            );
            return false;
        }

        // Mark proposal as verified
        view_obj.leader_deadline = None;
        view_obj.verified_proposal = true;

        // Report the proposal
        let proposal = view_obj.proposal.as_ref().unwrap();
        let proof = Prover::<C, H>::serialize_proposal(
            view,
            proposal.2.height,
            proposal.2.parent.clone(),
            proposal.1.clone(),
            proposal.2.signature.clone().unwrap(),
        );
        self.application.report(PROPOSAL, proof).await;

        // Indicate that verification is done
        debug!(view, height = proposal.2.height, "verified proposal");
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
        let leader = self.leader(view).expect("unable to get leader");
        let entry = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.application.clone(), leader.clone(), None, None));
        entry.leader_deadline = Some(self.runtime.current() + self.leader_timeout);
        entry.advance_deadline = Some(self.runtime.current() + self.notarization_timeout);
        self.view = view;
        info!(view, "entered view");

        // Check if we should fast exit this view
        if view < self.activity_timeout || leader == self.crypto.public_key() {
            return;
        }
        let mut next = view - 1;
        while next > view - self.activity_timeout {
            if !self.application.is_participant(next, &leader).unwrap() {
                // Don't punish a participant if they weren't online at any point during
                // the lookback window.
                return;
            }
            let view_obj = match self.views.get(&next) {
                Some(view_obj) => view_obj,
                None => {
                    return;
                }
            };
            if view_obj.proposal_voters.contains_key(&leader)
                || view_obj.null_votes.contains_key(&leader)
            {
                return;
            }
            next -= 1;
        }

        // Reduce leader deadline to now
        debug!(view, "skipping leader timeout");
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
        let validators = match self.application.participants(view) {
            Some(validators) => validators,
            None => return None,
        };
        let len = validators.len() as u32;
        let threshold = quorum(len).expect("not enough validators for a quorum");
        Some((threshold, len))
    }

    async fn vote(&mut self, vote: wire::Vote) {
        // Ensure we are in the right view to process this message
        if !self.interesting(vote.view, false) {
            debug!(vote_view = vote.view, our_view = self.view, "dropping vote");
            return;
        }

        // Parse signature
        let signature = match &vote.signature {
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
            .application
            .is_participant(vote.view, &signature.public_key)
        {
            Some(is) => is,
            None => {
                debug!(
                    view = vote.view,
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
        let vote_digest = vote_digest(vote.view, vote.height, vote.digest.as_ref());
        if !C::verify(
            &self.vote_namespace,
            &vote_digest,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping vote");
            return;
        }

        // Handle vote
        self.handle_vote(vote).await;
    }

    async fn handle_vote(&mut self, vote: wire::Vote) {
        // Check to see if vote is for proposal in view
        let leader = match self.leader(vote.view) {
            Some(leader) => leader,
            None => {
                debug!(
                    view = vote.view,
                    reason = "unable to compute leader",
                    "dropping vote"
                );
                return;
            }
        };
        let view = self
            .views
            .entry(vote.view)
            .or_insert_with(|| Round::new(self.application.clone(), leader, None, None));

        // Handle vote
        view.add_verified_vote(vote).await;
    }

    async fn notarization(
        &mut self,
        resolver: &mut resolver::Mailbox,
        notarization: wire::Notarization,
    ) {
        // Check if we are still in a view where this notarization could help
        if !self.interesting(notarization.view, true) {
            trace!(
                notarization_view = notarization.view,
                our_view = self.view,
                reason = "outdated notarization",
                "dropping notarization"
            );
            return;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        let view = self.views.get_mut(&notarization.view);
        if let Some(ref view) = view {
            if notarization.digest.is_some() && view.broadcast_proposal_notarization {
                trace!(
                    view = notarization.view,
                    reason = "already broadcast notarization",
                    "dropping notarization"
                );
                return;
            }
            if notarization.digest.is_none() && view.broadcast_null_notarization {
                trace!(
                    view = notarization.view,
                    reason = "already broadcast null notarization",
                    "dropping notarization"
                );
                return;
            }
        }

        // Ensure notarization has valid number of signatures
        let (threshold, count) = match self.threshold(notarization.view) {
            Some(participation) => participation,
            None => {
                debug!(
                    view = notarization.view,
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
                &self.vote_namespace,
                &vote_digest(
                    notarization.view,
                    notarization.height,
                    notarization.digest.as_ref(),
                ),
                &signature.public_key,
                &signature.signature,
            ) {
                debug!(reason = "invalid signature", "dropping notarization");
                return;
            }
        }
        debug!(view = notarization.view, "notarization verified");

        // Handle notarization
        self.handle_notarization(resolver, notarization).await;
    }

    async fn handle_notarization(
        &mut self,
        resolver: &mut resolver::Mailbox,
        notarization: wire::Notarization,
    ) {
        // Add signatures to view (needed to broadcast notarization if we get proposal)
        let leader = self
            .leader(notarization.view)
            .expect("unable to get leader");
        let view = self
            .views
            .entry(notarization.view)
            .or_insert_with(|| Round::new(self.application.clone(), leader, None, None));
        for signature in notarization.signatures {
            let vote = wire::Vote {
                view: notarization.view,
                height: notarization.height,
                digest: notarization.digest.clone(),
                signature: Some(signature),
            };
            view.add_verified_vote(vote).await
        }

        // Clear leader and advance deadlines (if they exist)
        view.leader_deadline = None;
        view.advance_deadline = None;

        // Notify resolver of notarization
        let proposal = if let Some(notarization_hash) = notarization.digest {
            match view.proposal.as_ref() {
                Some((digest, _, proposal)) => {
                    Proposal::Populated(digest.clone(), proposal.clone())
                }
                None => Proposal::Reference(
                    notarization.view,
                    notarization.height.unwrap(),
                    notarization_hash,
                ),
            }
        } else {
            Proposal::Null(notarization.view)
        };
        resolver.notarized(proposal).await;

        // Enter next view
        self.enter_view(notarization.view + 1);
    }

    async fn finalize(&mut self, finalize: wire::Finalize) {
        // Ensure we are in the right view to process this message
        if !self.interesting(finalize.view, false) {
            debug!(
                finalize_view = finalize.view,
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
            .application
            .is_participant(finalize.view, &signature.public_key)
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
        let finalize_digest = finalize_digest(finalize.view, finalize.height, &finalize.digest);
        if !C::verify(
            &self.finalize_namespace,
            &finalize_digest,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(
                signer = hex(&signature.public_key),
                digest = hex(&finalize_digest),
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
        let leader = self.leader(finalize.view).expect("unable to get leader");
        let view = self
            .views
            .entry(finalize.view)
            .or_insert_with(|| Round::new(self.application.clone(), leader, None, None));

        // Handle finalize
        view.add_verified_finalize(finalize).await;
    }

    async fn finalization(
        &mut self,
        resolver: &mut resolver::Mailbox,
        finalization: wire::Finalization,
    ) {
        // Check if we are still in a view where this finalization could help
        if !self.interesting(finalization.view, true) {
            trace!(
                finalization_view = finalization.view,
                our_view = self.view,
                reason = "outdated finalization",
                "dropping finalization"
            );
            return;
        }

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        let view = self.views.get_mut(&finalization.view);
        if let Some(ref view) = view {
            if view.broadcast_finalization {
                trace!(
                    view = finalization.view,
                    height = finalization.height,
                    reason = "already broadcast finalization",
                    "dropping finalization"
                );
                return;
            }
        }

        // Ensure finalization has valid number of signatures
        let (threshold, count) = match self.threshold(finalization.view) {
            Some(participation) => participation,
            None => {
                debug!(
                    view = finalization.view,
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
                &finalize_digest(finalization.view, finalization.height, &finalization.digest),
                &signature.public_key,
                &signature.signature,
            ) {
                debug!(reason = "invalid signature", "dropping finalization");
                return;
            }
        }
        debug!(view = finalization.view, "finalization verified");

        // Process finalization
        self.handle_finalization(resolver, finalization).await;
    }

    async fn handle_finalization(
        &mut self,
        resolver: &mut resolver::Mailbox,
        finalization: wire::Finalization,
    ) {
        // Add signatures to view (needed to broadcast finalization if we get proposal)
        let leader = self
            .leader(finalization.view)
            .expect("unable to get leader");
        let view = self
            .views
            .entry(finalization.view)
            .or_insert_with(|| Round::new(self.application.clone(), leader, None, None));
        for signature in finalization.signatures.iter() {
            let finalize = wire::Finalize {
                view: finalization.view,
                height: finalization.height,
                digest: finalization.digest.clone(),
                signature: Some(signature.clone()),
            };
            view.add_verified_finalize(finalize).await;
        }

        // Track view finalized
        if finalization.view > self.last_finalized {
            self.last_finalized = finalization.view;
        }

        // Inform resolver of finalization
        let proposal = match view.proposal.as_ref() {
            Some((digest, _, proposal)) => Proposal::Populated(digest.clone(), proposal.clone()),
            None => Proposal::Reference(
                finalization.view,
                finalization.height,
                finalization.digest.clone(),
            ),
        };
        resolver.finalized(proposal).await;

        // Enter next view
        self.enter_view(finalization.view + 1);
    }

    fn construct_proposal_vote(&mut self, view: u64) -> Option<wire::Vote> {
        let view_obj = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };
        if view_obj.broadcast_vote {
            return None;
        }
        if view_obj.timeout_fired {
            return None;
        }
        if !view_obj.verified_proposal {
            return None;
        }
        let (digest, proposal) = match &view_obj.proposal {
            Some((digest, _, proposal)) => (digest, proposal),
            None => {
                return None;
            }
        };
        view_obj.broadcast_vote = true;
        Some(wire::Vote {
            view,
            height: Some(proposal.height),
            digest: Some(digest.clone()),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(
                    &self.vote_namespace,
                    &vote_digest(view, Some(proposal.height), Some(digest)),
                ),
            }),
        })
    }

    fn construct_notarization(&mut self, view: u64, force: bool) -> Option<wire::Notarization> {
        // Get requested view
        let view_obj = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct notarization
        let validators = match self.application.participants(view) {
            Some(validators) => validators,
            None => {
                return None;
            }
        };
        let threshold =
            quorum(validators.len() as u32).expect("not enough validators for a quorum");
        let mut result = view_obj.notarizable_proposal(threshold, force);
        if result.is_none() {
            result = view_obj.notarizable_null(threshold, force);
        }
        let (digest, height, votes) = result?;

        // Construct notarization
        let mut signatures = Vec::new();
        for validator in validators.iter() {
            if let Some(vote) = votes.get(validator) {
                signatures.push(vote.signature.clone().unwrap());
            }
        }
        let notarization = wire::Notarization {
            view,
            height,
            digest,
            signatures,
        };
        Some(notarization)
    }

    fn construct_finalize(&mut self, view: u64) -> Option<wire::Finalize> {
        let view_obj = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };
        if view_obj.timeout_fired {
            return None;
        }
        if !view_obj.broadcast_vote {
            // Ensure we vote before we finalize
            return None;
        }
        if !view_obj.broadcast_proposal_notarization {
            // Ensure we notarize before we finalize
            return None;
        }
        if view_obj.broadcast_finalize {
            return None;
        }
        let (digest, proposal) = match &view_obj.proposal {
            Some((digest, _, proposal)) => (digest, proposal),
            None => {
                return None;
            }
        };
        view_obj.broadcast_finalize = true;
        Some(wire::Finalize {
            view,
            height: proposal.height,
            digest: digest.clone(),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(
                    &self.finalize_namespace,
                    &finalize_digest(view, proposal.height, digest),
                ),
            }),
        })
    }

    fn construct_finalization(&mut self, view: u64, force: bool) -> Option<wire::Finalization> {
        let view_obj = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct finalization
        let validators = match self.application.participants(view) {
            Some(validators) => validators,
            None => {
                return None;
            }
        };
        let threshold =
            quorum(validators.len() as u32).expect("not enough validators for a quorum");
        let (digest, height, finalizes) = view_obj.finalizable_proposal(threshold, force)?;

        // Construct finalization
        let mut signatures = Vec::new();
        for validator in validators.iter() {
            if let Some(finalize) = finalizes.get(validator) {
                signatures.push(finalize.signature.clone().unwrap());
            }
        }
        let finalization = wire::Finalization {
            view,
            height,
            digest,
            signatures,
        };
        Some(finalization)
    }

    async fn broadcast(
        &mut self,
        resolver: &mut resolver::Mailbox,
        sender: &mut impl Sender,
        view: u64,
    ) {
        // Attempt to vote
        if let Some(vote) = self.construct_proposal_vote(view) {
            // Broadcast the vote
            let msg = wire::Consensus {
                payload: Some(wire::consensus::Payload::Vote(vote.clone())),
            }
            .encode_to_vec();
            sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the vote
            let digest = vote.digest.clone().unwrap();
            debug!(view = vote.view, digest = hex(&digest), "broadcast vote");
            self.handle_vote(vote).await;
        };

        // Attempt to notarize
        if let Some(notarization) = self.construct_notarization(view, false) {
            // Broadcast the notarization
            let msg = wire::Consensus {
                payload: Some(wire::consensus::Payload::Notarization(notarization.clone())),
            }
            .encode_to_vec();
            sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the notarization
            let null_broadcast = notarization.digest.is_none();
            debug!(
                view = notarization.view,
                null = null_broadcast,
                "broadcast notarization"
            );
            self.handle_notarization(resolver, notarization).await;

            // If we built the proposal and are broadcasting null, also broadcast most recent finalization
            //
            // In cases like this, it is possible that other peers cannot verify the proposal because they do not
            // have the latest finalization and null notarizations.
            let view_obj = self.views.get(&view).expect("view missing");
            if null_broadcast
                && view_obj.leader == self.crypto.public_key()
                && view_obj.verified_proposal
            {
                match self.construct_finalization(self.last_finalized, true) {
                    Some(finalization) => {
                        let msg = wire::Consensus {
                            payload: Some(wire::consensus::Payload::Finalization(
                                finalization.clone(),
                            )),
                        }
                        .encode_to_vec();
                        sender
                            .send(Recipients::All, msg.into(), true)
                            .await
                            .unwrap();
                        debug!(
                            finalized_view = finalization.view,
                            finalized_height = finalization.height,
                            current_view = view,
                            "broadcast last finalized after null notarization on our proposal"
                        );
                    }
                    None => {
                        debug!(
                            finalized_view = self.last_finalized,
                            current_view = view,
                            "missing last finalized view, unable to broadcast finalization"
                        );
                    }
                }
            }
        };

        // Attempt to finalize
        if let Some(finalize) = self.construct_finalize(view) {
            // Broadcast the finalize
            let msg = wire::Consensus {
                payload: Some(wire::consensus::Payload::Finalize(finalize.clone())),
            };
            let msg = msg.encode_to_vec();
            sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the finalize
            debug!(
                view = finalize.view,
                height = finalize.height,
                "broadcast finalize"
            );
            self.handle_finalize(finalize).await;
        };

        // Attempt to finalization
        if let Some(finalization) = self.construct_finalization(view, false) {
            // Broadcast the finalization
            let msg = wire::Consensus {
                payload: Some(wire::consensus::Payload::Finalization(finalization.clone())),
            };
            let msg = msg.encode_to_vec();
            sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the finalization
            debug!(
                view = finalization.view,
                height = finalization.height,
                "broadcast finalization"
            );
            self.handle_finalization(resolver, finalization).await;
        };
    }

    fn notarization_observed(&self, view: View) -> bool {
        if let Some(view_obj) = self.views.get(&view) {
            if view_obj.broadcast_proposal_notarization {
                return true;
            }
            if view_obj.broadcast_null_notarization {
                return true;
            }
        }
        false
    }

    fn get_next_missing(&self) -> Option<(View, View)> {
        let mut base = None;
        let mut next = self.last_finalized + 1;
        while next < self.view {
            if self.notarization_observed(next) {
                break;
            }
            if base.is_none() {
                base = Some(next);
            }
            next += 1;
        }
        base.map(|base| (base, next - base - 1))
    }

    async fn send_request(
        &mut self,
        base: View,
        children: View,
        sender: &mut impl Sender,
    ) -> PublicKey {
        // Send the request
        let msg: Bytes = wire::Consensus {
            payload: Some(wire::consensus::Payload::NotarizationRequest(
                wire::NotarizationRequest {
                    view: base,
                    children,
                },
            )),
        }
        .encode_to_vec()
        .into();

        // Get validators from highest view we know about
        let validators = self.application.participants(self.view).unwrap();

        // Generate a shuffle
        let mut validator_indices = (0..validators.len()).collect::<Vec<_>>();
        validator_indices.shuffle(&mut self.runtime);

        // Minimize footprint of rate limiter
        self.fetch_rate_limiter.shrink_to_fit();

        // Loop until we send a message
        let mut index = 0;
        loop {
            // Check if we have exhausted all validators
            if index == validators.len() {
                warn!(
                    base,
                    view = self.view,
                    "failed to send request to any validator"
                );

                // Avoid busy looping when disconnected
                self.runtime.sleep(self.fetch_timeout).await;
                index = 0;
            }

            // Select random validator to fetch from
            let validator = validators[validator_indices[index]].clone();
            if validator == self.crypto.public_key() {
                index += 1;
                continue;
            }

            // Check if rate limit is exceeded
            if self.fetch_rate_limiter.check_key(&validator).is_err() {
                debug!(
                    base,
                    view = self.view,
                    peer = hex(&validator),
                    "skipping request because rate limited"
                );
                index += 1;
                continue;
            }

            // Send message
            if !sender
                .send(Recipients::One(validator.clone()), msg.clone(), true)
                .await
                .unwrap()
                .is_empty()
            {
                debug!(
                    base,
                    view = self.view,
                    peer = hex(&validator),
                    "requested missing notarizations"
                );
                return validator;
            }

            // Try again
            debug!(
                base,
                view = self.view,
                peer = hex(&validator),
                "failed to send backfill request"
            );
            index += 1;
        }
    }

    pub async fn run(
        mut self,
        resolver: &mut resolver::Mailbox,
        mut sender: impl Sender,
        mut receiver: impl Receiver,
    ) {
        // Add initial view
        //
        // We start on view 1 because the genesis container occupies view 0/height 0.
        self.enter_view(1);
        self.current_view.set(1);
        self.tracked_views.set(1);

        // Process messages
        let mut outstanding_task = None;
        loop {
            // Ensure task has not been resolved
            if let Some((_, ref base, _, _)) = outstanding_task {
                if self.notarization_observed(*base) {
                    outstanding_task = None;
                }
            }

            // Look for next task if nothing
            if outstanding_task.is_none() {
                if let Some((base, children)) = self.get_next_missing() {
                    let validator = self.send_request(base, children, &mut sender).await;
                    outstanding_task = Some((
                        validator,
                        base,
                        children,
                        self.runtime.current() + self.fetch_timeout,
                    ));
                }
            }

            // Create fetch timeout
            let fetch_timeout = if let Some((_, _, _, ref deadline)) = outstanding_task {
                Either::Left(self.runtime.sleep_until(*deadline))
            } else {
                Either::Right(futures::future::pending())
            };

            // Attempt to propose a container
            let propose_retry = match self.propose(resolver).await {
                Some(retry) => Either::Left(self.runtime.sleep_until(retry)),
                None => Either::Right(futures::future::pending()),
            };

            // Wait for a timeout to fire or for a message to arrive
            let null_timeout = self.timeout_deadline();
            let view;
            select! {
                _ = self.runtime.sleep_until(null_timeout) => {
                    // Trigger the timeout
                    self.timeout(&mut sender).await;
                    view = self.view;
                },
                _ = propose_retry => {
                    debug!(view = self.view, "proposal retry timeout fired");
                    continue;
                },
                _ = fetch_timeout => {
                    // Send request again
                    let (_, base, children, _) = outstanding_task.unwrap();
                    let validator = self.send_request(base, children, &mut sender).await;

                    // Reset timeout
                    let deadline = self.runtime.current() + self.fetch_timeout;
                    outstanding_task = Some((validator, base, children, deadline));
                    continue;
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = mailbox.unwrap();
                    match msg {
                        Message::Proposal{ view: proposal_view, parent, height, payload, payload_hash} => {
                            // If we have already moved to another view, drop the response as we will
                            // not broadcast it
                            if self.view != proposal_view {
                                debug!(view = proposal_view, our_view = self.view, reason = "no longer in required view", "dropping requested proposal");
                                continue;
                            }

                            // Construct proposal
                            let proposal_digest = proposal_digest(self.view, height, &parent, &payload_hash);
                            let proposal = wire::Proposal {
                                view: self.view,
                                height,
                                parent,
                                payload,
                                signature: Some(wire::Signature {
                                    public_key: self.crypto.public_key(),
                                    signature: self.crypto.sign(&self.proposal_namespace, &proposal_digest),
                                }),
                            };

                            // Handle our proposal
                            self.hasher.update(&proposal_digest);
                            let proposal_hash = self.hasher.finalize();
                            if !self.our_proposal(proposal_hash, payload_hash, proposal.clone()).await {
                                continue;
                            }
                            view = proposal_view;

                            // Broadcast the proposal
                            let msg = wire::Consensus {
                                payload: Some(wire::consensus::Payload::Proposal(proposal.clone())),
                            }.encode_to_vec();
                            sender
                                .send(Recipients::All, msg.into(), true)
                                .await
                                .unwrap();
                        },
                        Message::ProposalFailed {view} => {
                            if self.view != view {
                                debug!(view = view, our_view = self.view, reason = "no longer in required view", "dropping proposal failure");
                                continue;
                            }

                            // Handle proposal failure
                            let view_obj = self.views.get_mut(&view).expect("view missing");
                            view_obj.requested_proposal = false;
                            view_obj.next_proposal_request = Some(self.runtime.current() + self.proposal_retry);
                            debug!(view = view, "proposal failed");
                            continue;
                        }
                        Message::Verified { view: verified_view } => {
                            // Handle verified proposal
                            if !self.verified(verified_view).await {
                                continue;
                            }
                            view = verified_view;
                        },
                    }
                },
                msg = receiver.recv() => {
                    // Parse message
                    let (s, msg) = msg.unwrap();
                    let msg = match wire::Consensus::decode(msg) {
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
                        wire::consensus::Payload::Proposal(proposal) => {
                            if !H::validate(&proposal.parent) {
                                debug!(sender = hex(&s), "invalid proposal parent digest size");
                                continue;
                            }
                            view = proposal.view;
                            self.peer_proposal(resolver, proposal).await;
                        }
                        wire::consensus::Payload::Vote(vote) => {
                            if let Some(vote_hash) = vote.digest.as_ref() {
                                if !H::validate(vote_hash) {
                                    debug!(sender = hex(&s), "invalid vote digest size");
                                    continue;
                                }
                                if vote.height.is_none() {
                                    debug!(sender = hex(&s), "missing vote height");
                                    continue;
                                }
                            } else if vote.height.is_some() {
                                debug!(sender = hex(&s), "invalid vote height for null container");
                                continue;
                            }
                            view = vote.view;
                            self.vote(vote).await;
                        }
                        wire::consensus::Payload::Notarization(notarization) => {
                            if let Some(notarization_hash) = notarization.digest.as_ref() {
                                if !H::validate(notarization_hash) {
                                    debug!(sender = hex(&s), "invalid notarization digest size");
                                    continue;
                                }
                                if notarization.height.is_none() {
                                    debug!(sender = hex(&s), "missing notarization height");
                                    continue;
                                }
                            } else if notarization.height.is_some() {
                                debug!(sender = hex(&s), "invalid notarization height for null container");
                                continue;
                            }
                            view = notarization.view;
                            self.notarization(resolver, notarization).await;
                        }
                        wire::consensus::Payload::Finalize(finalize) => {
                            if !H::validate(&finalize.digest) {
                                debug!(sender = hex(&s), "invalid finalize digest size");
                                continue;
                            }
                            view = finalize.view;
                            self.finalize(finalize).await;
                        }
                        wire::consensus::Payload::Finalization(finalization) => {
                            if !H::validate(&finalization.digest) {
                                debug!(sender = hex(&s), "invalid finalization digest size");
                                continue;
                            }
                            view = finalization.view;
                            self.finalization(resolver, finalization).await;
                        }
                        wire::consensus::Payload::NotarizationRequest(request) => {
                            // Populate as many notarizations as we can
                            let mut notarization_bytes = 0; // TODO: add a buffer
                            let mut notarizations = Vec::new();
                            let mut cursor = request.view;
                            loop {
                                // Attempt to construct notarization
                                let notarization = match self.construct_notarization(cursor, true) {
                                    Some(notarization) => notarization,
                                    None => break,
                                };

                                // If we don't have any more space, stop
                                notarization_bytes += notarization.encoded_len();
                                if notarization_bytes > self.max_fetch_size{
                                    debug!(
                                        requested = request.children + 1,
                                        fetched = notarizations.len(),
                                        peer = hex(&s),
                                        "reached max fetch size"
                                    );
                                    break;
                                }
                                notarizations.push(notarization);

                                // If we have all children or we hit our limit, stop
                                let fetched = notarizations.len() as u64;
                                if fetched == request.children +1 || fetched == self.max_fetch_count {
                                    break;
                                }
                                cursor +=1;
                            }

                            // Send back notarizations
                            debug!(view = cursor, fetched = notarizations.len(), peer = hex(&s), "responding to notarization request");
                            let msg = wire::Consensus {
                                payload: Some(wire::consensus::Payload::BatchedNotarizations(
                                    wire::BatchedNotarizations {
                                        notarizations,
                                    },
                                )),
                            }.encode_to_vec();
                            sender
                                .send(Recipients::One(s), msg.into(), false)
                                .await
                                .unwrap();
                            continue;
                        }
                        wire::consensus::Payload::BatchedNotarizations(response) => {
                            // Drop anything from someone we don't expect
                            if let Some((ref sender, _, _, _)) = outstanding_task {
                                if sender != &s {
                                    continue
                                }
                                outstanding_task = None;
                            }
                            for notarization in response.notarizations {
                                if let Some(notarization_hash) = notarization.digest.as_ref() {
                                    if !H::validate(notarization_hash) {
                                        debug!(sender = hex(&s), "invalid notarization digest size");
                                        continue;
                                    }
                                    if notarization.height.is_none() {
                                        debug!(sender = hex(&s), "missing notarization height");
                                        continue;
                                    }
                                } else if notarization.height.is_some() {
                                    debug!(sender = hex(&s), "invalid notarization height for null container");
                                    continue;
                                }
                                debug!(view = notarization.view, "received batch notarization");
                                self.notarization(resolver, notarization).await;
                            }
                            continue;
                        }
                    };
                },
            };

            // Attempt to send any new view messages
            self.broadcast(resolver, &mut sender, view).await;

            // After sending all required messages, prune any views
            // we no longer need
            self.prune_views();

            // Update metrics
            self.current_view.set(view as i64);
            self.tracked_views.set(self.views.len() as i64);
        }
    }
}
