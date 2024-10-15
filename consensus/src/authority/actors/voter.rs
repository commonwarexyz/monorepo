use super::orchestrator::{Mailbox, Proposal};
use crate::{
    authenticated::{
        encoding::{
            finalize_digest, proposal_digest, vote_digest, FINALIZE_SUFFIX, PROPOSAL_SUFFIX,
            VOTE_SUFFIX,
        },
        wire,
    },
    Application, Hash, Hasher, Height, View,
};
use bytes::Bytes;
use commonware_cryptography::{PublicKey, Scheme};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::Clock;
use commonware_utils::{hex, quorum, union};
use futures::{channel::mpsc, SinkExt, StreamExt};
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use prost::Message;
use rand::Rng;
use std::sync::atomic::AtomicI64;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tracing::{debug, info, trace, warn};

// TODO: change name
// If either of these requests fails, it will not send a reply.
pub enum VoterMessage {
    Proposal {
        view: View,
        parent: Hash,
        height: Height,
        payload: Bytes,
        payload_hash: Hash,
    },
    Verified {
        view: View,
    },
}

// TODO: improve name here
#[derive(Clone)]
pub struct VoterMailbox {
    sender: mpsc::Sender<VoterMessage>,
}

impl VoterMailbox {
    pub(super) fn new(sender: mpsc::Sender<VoterMessage>) -> Self {
        Self { sender }
    }

    pub async fn proposal(
        &mut self,
        view: View,
        parent: Hash,
        height: Height,
        payload: Bytes,
        payload_hash: Hash,
    ) {
        self.sender
            .send(VoterMessage::Proposal {
                view,
                parent,
                height,
                payload,
                payload_hash,
            })
            .await
            .unwrap();
    }

    pub async fn verified(&mut self, view: View) {
        self.sender
            .send(VoterMessage::Verified { view })
            .await
            .unwrap();
    }
}

struct Record {
    leader: PublicKey,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    null_vote_retry: Option<SystemTime>,

    // Track one proposal per view
    requested_proposal: bool,
    proposal: Option<(Hash /* proposal */, wire::Proposal)>,
    verified_proposal: bool,
    broadcast_vote: bool,
    broadcast_finalize: bool,

    // Track votes for all proposals (ensuring any participant only has one recorded vote)
    proposal_voters: HashMap<PublicKey, Hash>,
    proposal_votes: HashMap<Hash, HashMap<PublicKey, wire::Vote>>,
    broadcast_proposal_notarization: bool,

    timeout_fired: bool,
    null_votes: HashMap<PublicKey, wire::Vote>,
    broadcast_null_notarization: bool,

    // Track finalizes for all proposals (ensuring any participant only has one recorded finalize)
    finalizers: HashMap<PublicKey, Hash>,
    finalizes: HashMap<Hash, HashMap<PublicKey, wire::Finalize>>,
    broadcast_finalization: bool,
}

impl Record {
    pub fn new(
        leader: PublicKey,
        leader_deadline: Option<SystemTime>,
        advance_deadline: Option<SystemTime>,
    ) -> Self {
        Self {
            leader,
            leader_deadline,
            advance_deadline,
            null_vote_retry: None,

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

    fn add_verified_vote(&mut self, skip_invalid: bool, vote: wire::Vote) {
        // Determine whether or not this is a null vote
        let public_key = &vote.signature.as_ref().unwrap().public_key;
        if vote.hash.is_none() {
            // Check if already issued finalize
            if self.finalizers.contains_key(public_key) && !skip_invalid {
                warn!(
                    view = vote.view,
                    signer = hex(public_key),
                    "already voted finalize",
                );
                return;
            }

            // Store the null vote
            self.null_votes.insert(public_key.clone(), vote);
            return;
        }
        let hash = vote.hash.clone().unwrap();

        // Check if already voted
        if !skip_invalid {
            if let Some(previous_vote) = self.proposal_voters.get(public_key) {
                warn!(
                    view = vote.view,
                    signer = hex(public_key),
                    previous_vote = hex(previous_vote),
                    "already voted"
                );
                return;
            }
        }

        // Store the vote
        self.proposal_voters
            .insert(public_key.clone(), hash.clone());
        let entry = self.proposal_votes.entry(hash).or_default();
        entry.insert(public_key.clone(), vote);
    }

    fn notarizable_proposal(
        &mut self,
        threshold: u32,
        force: bool,
    ) -> Option<(Option<Hash>, Height, &HashMap<PublicKey, wire::Vote>)> {
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
                Some((hash, pro)) => {
                    if hash != proposal {
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
            return Some((Some(proposal.clone()), height, votes));
        }
        None
    }

    fn notarizable_null(
        &mut self,
        threshold: u32,
        force: bool,
    ) -> Option<(Option<Hash>, Height, &HashMap<PublicKey, wire::Vote>)> {
        if !force && (self.broadcast_null_notarization || self.broadcast_proposal_notarization) {
            return None;
        }
        if (self.null_votes.len() as u32) < threshold {
            return None;
        }
        self.broadcast_null_notarization = true;
        Some((None, 0, &self.null_votes))
    }

    fn add_verified_finalize(&mut self, skip_invalid: bool, finalize: wire::Finalize) {
        // Check if also issued null vote
        let public_key = &finalize.signature.as_ref().unwrap().public_key;
        if self.null_votes.contains_key(public_key) && !skip_invalid {
            warn!(
                view = finalize.view,
                signer = hex(public_key),
                "already voted null",
            );
            return;
        }

        // Check if already finalized
        if !skip_invalid {
            if let Some(previous_finalize) = self.finalizers.get(public_key) {
                warn!(
                    view = finalize.view,
                    signer = hex(public_key),
                    previous_finalize = hex(previous_finalize),
                    "already voted finalize"
                );
                return;
            }
        }

        // Store the finalize
        self.finalizers
            .insert(public_key.clone(), finalize.hash.clone());
        let entry = self.finalizes.entry(finalize.hash.clone()).or_default();
        entry.insert(public_key.clone(), finalize);
    }

    fn finalizable_proposal(
        &mut self,
        threshold: u32,
    ) -> Option<(Hash, Height, &HashMap<PublicKey, wire::Finalize>)> {
        if self.broadcast_finalization || !self.verified_proposal {
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
                Some((hash, pro)) => {
                    if hash != proposal {
                        debug!(
                            proposal = hex(proposal),
                            hash = hex(hash),
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

pub struct Config {
    pub registry: Arc<Mutex<Registry>>,
    pub namespace: Bytes,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub null_vote_retry: Duration,
}

pub struct Voter<E: Clock + Rng, C: Scheme, H: Hasher, A: Application> {
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

    mailbox_receiver: mpsc::Receiver<VoterMessage>,

    last_finalized: View,
    view: View,
    views: BTreeMap<View, Record>,

    current_view: Gauge,
    tracked_views: Gauge,
}

impl<E: Clock + Rng, C: Scheme, H: Hasher, A: Application> Voter<E, C, H, A> {
    pub fn new(
        runtime: E,
        crypto: C,
        hasher: H,
        application: A,
        cfg: Config,
    ) -> (Self, VoterMailbox) {
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
        (
            Self {
                runtime,
                crypto,
                hasher,
                application,

                proposal_namespace: union(&cfg.namespace, PROPOSAL_SUFFIX),
                vote_namespace: union(&cfg.namespace, VOTE_SUFFIX),
                finalize_namespace: union(&cfg.namespace, FINALIZE_SUFFIX),

                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                null_vote_retry: cfg.null_vote_retry,

                mailbox_receiver,

                last_finalized: 0,
                view: 1,
                views: BTreeMap::new(),

                current_view,
                tracked_views,
            },
            VoterMailbox::new(mailbox_sender),
        )
    }

    fn leader(&self, view: View) -> Option<PublicKey> {
        let validators = match self.application.participants(view) {
            Some(validators) => validators,
            None => return None,
        };
        Some(validators[view as usize % validators.len()].clone())
    }

    async fn propose(&mut self, orchestrator: &mut Mailbox) -> bool {
        // Check if we are leader
        let view = self.views.get_mut(&self.view).unwrap();
        if view.leader != self.crypto.public_key() {
            return false;
        }

        // Check if we have already requested a proposal
        if view.requested_proposal {
            return false;
        }

        // Check if we have already proposed
        if view.proposal.is_some() {
            return false;
        }

        // Request proposal from orchestrator
        view.requested_proposal = true;
        orchestrator
            .propose(self.view, self.crypto.public_key())
            .await;
        true
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
        // return next try for null block vote
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
        let digest = vote_digest(self.view, 0, None);
        let vote = wire::Vote {
            view: self.view,
            height: 0,
            hash: None,
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
        self.handle_vote(vote);
    }

    async fn our_proposal(&mut self, payload_hash: Hash, proposal: wire::Proposal) -> bool {
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

        // Construct hash
        let proposal_digest = proposal_digest(
            proposal.view,
            proposal.height,
            &proposal.parent,
            &payload_hash,
        );
        let proposal_hash = self.hasher.hash(&proposal_digest);

        // Store the proposal
        let proposal_view = proposal.view;
        let proposal_height = proposal.height;
        view.proposal = Some((proposal_hash.clone(), proposal));
        view.verified_proposal = true;
        view.leader_deadline = None;
        debug!(
            view = proposal_view,
            height = proposal_height,
            hash = hex(&proposal_hash),
            "stored our proposal"
        );
        true
    }

    async fn peer_proposal(&mut self, orchestrator: &mut Mailbox, proposal: wire::Proposal) {
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

        // Check to see if we have already received a proposal for this view (if exists)
        if let Some(view) = self.views.get_mut(&proposal.view) {
            if view.proposal.is_some() {
                warn!(
                    leader = hex(&expected_leader),
                    view = proposal.view,
                    reason = "already received proposal",
                    "dropping proposal"
                );
                return;
            }
            if view.timeout_fired {
                warn!(
                    leader = hex(&expected_leader),
                    view = proposal.view,
                    reason = "view already timed out",
                    "dropping proposal"
                );
                return;
            }
        }

        // Verify the signature
        let payload_hash = match self.application.parse(proposal.payload.clone()).await {
            Some(hash) => hash,
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
        if !C::verify(
            &self.proposal_namespace,
            &proposal_digest,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping proposal");
            return;
        }
        let proposal_hash = self.hasher.hash(&proposal_digest);

        // Verify the proposal
        //
        // This will fail if we haven't notified the application of this parent.
        let view = self
            .views
            .entry(proposal.view)
            .or_insert_with(|| Record::new(expected_leader, None, None));
        view.proposal = Some((proposal_hash.clone(), proposal.clone()));
        orchestrator
            .verify(proposal_hash.clone(), proposal.clone())
            .await;
        debug!(
            view = proposal.view,
            height = proposal.height,
            hash = hex(&proposal_hash),
            "requested proposal verification",
        );
    }

    fn verified(&mut self, view: View) -> bool {
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
        debug!(view, "verified peer proposal");
        true
    }

    fn enter_view(&mut self, view: u64) {
        // Ensure view is valid
        if view <= self.view {
            debug!(
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
            .or_insert_with(|| Record::new(leader, None, None));
        entry.leader_deadline = Some(self.runtime.current() + self.leader_timeout);
        entry.advance_deadline = Some(self.runtime.current() + self.notarization_timeout);
        self.view = view;
        info!(view, "entered view");
    }

    fn prune_views(&mut self) {
        loop {
            // Get next key
            let next = match self.views.keys().next() {
                Some(next) => *next,
                None => return,
            };

            // Compare to last finalized
            if next < self.last_finalized {
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

    fn vote(&mut self, vote: wire::Vote) {
        // Ensure we are in the right view to process this message
        if vote.view != self.view && vote.view != self.view + 1 {
            debug!(
                vote_view = vote.view,
                our_view = self.view,
                reason = "incorrect view",
                "dropping vote"
            );
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
        let vote_digest = vote_digest(vote.view, vote.height, vote.hash.clone());
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
        self.handle_vote(vote);
    }

    fn handle_vote(&mut self, vote: wire::Vote) {
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
            .or_insert_with(|| Record::new(leader, None, None));

        // Handle vote
        view.add_verified_vote(false, vote);
    }

    async fn notarization(&mut self, orchestrator: &mut Mailbox, notarization: wire::Notarization) {
        // Check if we are still in a view where this notarization could help
        if notarization.view <= self.last_finalized {
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
            if notarization.hash.is_some() && view.broadcast_proposal_notarization {
                debug!(
                    view = notarization.view,
                    reason = "already broadcast notarization",
                    "dropping notarization"
                );
                return;
            }
            if notarization.hash.is_none() && view.broadcast_null_notarization {
                debug!(
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
                    notarization.hash.clone(),
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
        self.handle_notarization(orchestrator, notarization).await;
    }

    async fn handle_notarization(
        &mut self,
        orchestrator: &mut Mailbox,
        notarization: wire::Notarization,
    ) {
        // Add signatures to view (needed to broadcast notarization if we get proposal)
        let leader = self
            .leader(notarization.view)
            .expect("unable to get leader");
        let view = self
            .views
            .entry(notarization.view)
            .or_insert_with(|| Record::new(leader, None, None));
        for signature in notarization.signatures {
            let vote = wire::Vote {
                view: notarization.view,
                height: notarization.height,
                hash: notarization.hash.clone(),
                signature: Some(signature),
            };
            view.add_verified_vote(true, vote);
        }

        // Clear leader and advance deadlines (if they exist)
        view.leader_deadline = None;
        view.advance_deadline = None;

        // Inform orchestrator of notarization if not null vote
        if let Some(notarization_hash) = notarization.hash {
            let proposal = match view.proposal.as_ref() {
                Some((hash, proposal)) => Proposal::Populated(hash.clone(), proposal.clone()),
                None => {
                    Proposal::Reference(notarization.view, notarization.height, notarization_hash)
                }
            };
            orchestrator.notarized(proposal).await;
        } else {
            orchestrator.null_notarized(notarization.view).await;
        }

        // Enter next view
        self.enter_view(notarization.view + 1);
    }

    fn finalize(&mut self, finalize: wire::Finalize) {
        // Ensure we are in the right view to process this message
        if finalize.view <= self.last_finalized || finalize.view > self.view + 1 {
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
        let finalize_digest = finalize_digest(finalize.view, finalize.height, &finalize.hash);
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
        self.handle_finalize(finalize);
    }

    fn handle_finalize(&mut self, finalize: wire::Finalize) {
        // Get view for finalize
        let leader = self.leader(finalize.view).expect("unable to get leader");
        let view = self
            .views
            .entry(finalize.view)
            .or_insert_with(|| Record::new(leader, None, None));

        // Handle finalize
        view.add_verified_finalize(false, finalize);
    }

    async fn finalization(&mut self, orchestrator: &mut Mailbox, finalization: wire::Finalization) {
        // Check if we are still in a view where this finalization could help
        if finalization.view <= self.last_finalized {
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
                debug!(
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
                &finalize_digest(finalization.view, finalization.height, &finalization.hash),
                &signature.public_key,
                &signature.signature,
            ) {
                debug!(reason = "invalid signature", "dropping finalization");
                return;
            }
        }
        debug!(view = finalization.view, "finalization verified");

        // Process finalization
        self.handle_finalization(orchestrator, finalization).await;
    }

    async fn handle_finalization(
        &mut self,
        orchestrator: &mut Mailbox,
        finalization: wire::Finalization,
    ) {
        // Add signatures to view (needed to broadcast finalization if we get proposal)
        let leader = self
            .leader(finalization.view)
            .expect("unable to get leader");
        let view = self
            .views
            .entry(finalization.view)
            .or_insert_with(|| Record::new(leader, None, None));
        for signature in finalization.signatures.iter() {
            let finalize = wire::Finalize {
                view: finalization.view,
                height: finalization.height,
                hash: finalization.hash.clone(),
                signature: Some(signature.clone()),
            };
            view.add_verified_finalize(true, finalize);
        }

        // Track view finalized
        if finalization.view > self.last_finalized {
            self.last_finalized = finalization.view;
        }

        // Inform orchestrator of finalization
        let proposal = match view.proposal.as_ref() {
            Some((hash, proposal)) => Proposal::Populated(hash.clone(), proposal.clone()),
            None => Proposal::Reference(
                finalization.view,
                finalization.height,
                finalization.hash.clone(),
            ),
        };
        orchestrator.finalized(proposal).await;

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
        let (hash, proposal) = match &view_obj.proposal {
            Some((hash, proposal)) => (hash, proposal),
            None => {
                return None;
            }
        };
        view_obj.broadcast_vote = true;
        Some(wire::Vote {
            view,
            height: proposal.height,
            hash: Some(hash.clone()),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(
                    &self.vote_namespace,
                    &vote_digest(view, proposal.height, Some(hash.clone())),
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
        let (hash, height, votes) = result?;

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
            hash,
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
        let (hash, proposal) = match &view_obj.proposal {
            Some((hash, proposal)) => (hash, proposal),
            None => {
                return None;
            }
        };
        view_obj.broadcast_finalize = true;
        Some(wire::Finalize {
            view,
            height: proposal.height,
            hash: hash.clone(),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(
                    &self.finalize_namespace,
                    &finalize_digest(view, proposal.height, hash),
                ),
            }),
        })
    }

    fn construct_finalization(&mut self, view: u64) -> Option<wire::Finalization> {
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
        let (hash, height, finalizes) = view_obj.finalizable_proposal(threshold)?;

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
            hash,
            signatures,
        };
        Some(finalization)
    }

    async fn broadcast(&mut self, orchestrator: &mut Mailbox, sender: &mut impl Sender, view: u64) {
        // Attempt to vote
        if let Some(vote) = self.construct_proposal_vote(view) {
            // Broadcast the vote
            let msg = wire::Consensus {
                payload: Some(wire::consensus::Payload::Vote(vote.clone())),
            };
            let msg = msg.encode_to_vec();
            sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the vote
            let hash = vote.hash.clone().unwrap();
            debug!(view = vote.view, hash = hex(&hash), "broadcast vote");
            self.handle_vote(vote);
        };

        // Attempt to notarize
        if let Some(notarization) = self.construct_notarization(view, false) {
            // Broadcast the notarization
            let msg = wire::Consensus {
                payload: Some(wire::consensus::Payload::Notarization(notarization.clone())),
            };
            let msg = msg.encode_to_vec();
            sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the notarization
            debug!(
                view = notarization.view,
                null = notarization.hash.is_none(),
                "broadcast notarization"
            );
            self.handle_notarization(orchestrator, notarization).await;
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
            self.handle_finalize(finalize);
        };

        // Attempt to finalization
        if let Some(finalization) = self.construct_finalization(view) {
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
            self.handle_finalization(orchestrator, finalization).await;
        };
    }

    pub async fn run(
        mut self,
        orchestrator: &mut Mailbox,
        mut sender: impl Sender,
        mut receiver: impl Receiver,
    ) {
        // Add initial view
        //
        // We start on view 1 because the genesis block occupies view 0/height 0.
        self.enter_view(1);
        self.current_view.set(1);
        self.tracked_views.set(1);

        // Process messages
        loop {
            // Attempt to propose a block
            if self.propose(orchestrator).await {
                debug!(view = self.view, "requested proposal");
            }

            // Wait for a timeout to fire or for a message to arrive
            let null_timeout = self.timeout_deadline();
            let view;
            select! {
                _ = self.runtime.sleep_until(null_timeout) => {
                    // Trigger the timeout
                    self.timeout(&mut sender).await;
                    view = self.view;
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = mailbox.unwrap();
                    match msg {
                        VoterMessage::Proposal{ view: proposal_view, parent, height, payload, payload_hash} => {
                            debug!(view = proposal_view, our_view = self.view, "received proposal");

                            // If we have already moved to another view, drop the response as we will
                            // not broadcast it
                            if self.view != proposal_view {
                                debug!(view = proposal_view, our_view = self.view, reason = "no longer in required view", "dropping requested proposal");
                                continue;
                            }

                            // Construct proposal
                            let digest = proposal_digest(self.view, height, &parent, &payload_hash);
                            let proposal = wire::Proposal {
                                view: self.view,
                                height,
                                parent,
                                payload,
                                signature: Some(wire::Signature {
                                    public_key: self.crypto.public_key(),
                                    signature: self.crypto.sign(&self.proposal_namespace, &digest),
                                }),
                            };

                            // Handle our proposal
                            if !self.our_proposal(payload_hash, proposal.clone()).await {
                                continue;
                            }
                            view = proposal_view;

                            // Broadcast the proposal
                            let msg = wire::Consensus {
                                payload: Some(wire::consensus::Payload::Proposal(proposal.clone())),
                            };
                            let msg = msg.encode_to_vec();
                            sender
                                .send(Recipients::All, msg.into(), true)
                                .await
                                .unwrap();
                        },
                        VoterMessage::Verified { view: verified_view } => {
                            debug!(view = verified_view, "received verified proposal");

                            // Handle verified proposal
                            if !self.verified(verified_view) {
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
                                debug!(sender = hex(&s), "invalid proposal parent hash size");
                                continue;
                            }
                            view = proposal.view;
                            self.peer_proposal(orchestrator, proposal).await;
                        }
                        wire::consensus::Payload::Vote(vote) => {
                            if vote.hash.is_none() && vote.height != 0 {
                                debug!(sender = hex(&s), "invalid vote height for null block");
                                continue;
                            }
                            if vote.hash.is_some() && !H::validate(vote.hash.as_ref().unwrap()) {
                                debug!(sender = hex(&s), "invalid vote hash size");
                                continue;
                            }
                            view = vote.view;
                            self.vote(vote);
                        }
                        wire::consensus::Payload::Notarization(notarization) => {
                            if notarization.hash.is_none() && notarization.height != 0 {
                                debug!(sender = hex(&s), "invalid notarization height for null block");
                                continue;
                            }
                            if notarization.hash.is_some() && !H::validate(notarization.hash.as_ref().unwrap()) {
                                debug!(sender = hex(&s), "invalid notarization hash size");
                                continue;
                            }
                            view = notarization.view;
                            self.notarization(orchestrator, notarization).await;
                        }
                        wire::consensus::Payload::Finalize(finalize) => {
                            if !H::validate(&finalize.hash) {
                                debug!(sender = hex(&s), "invalid finalize hash size");
                                continue;
                            }
                            view = finalize.view;
                            self.finalize(finalize);
                        }
                        wire::consensus::Payload::Finalization(finalization) => {
                            if !H::validate(&finalization.hash) {
                                debug!(sender = hex(&s), "invalid finalization hash size");
                                continue;
                            }
                            view = finalization.view;
                            self.finalization(orchestrator, finalization).await;
                        }
                    };
                },
            };

            // Attempt to send any new view messages
            self.broadcast(orchestrator, &mut sender, view).await;

            // After sending all required messages, prune any views
            // we no longer need
            self.prune_views();

            // Update metrics
            self.current_view.set(view as i64);
            self.tracked_views.set(self.views.len() as i64);
        }
    }
}
