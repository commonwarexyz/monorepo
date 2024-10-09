//! TODO: change name to voter

use super::{
    orchestrator::{Mailbox, Proposal},
    wire,
};
use crate::{Hash, Height, HASH_LENGTH};
use bytes::Bytes;
use commonware_cryptography::{bls12381::dkg::utils::threshold, utils::hex, PublicKey, Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Clock};
use prost::Message;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::{Duration, SystemTime},
};
use tracing::{debug, info, trace, warn};

// TODO: move to config
const PROPOSAL_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_PROPOSAL_";
const VOTE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_VOTE_";
const FINALIZE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_FINALIZE_";

pub fn proposal_digest(
    view: crate::View,
    height: Height,
    parent: &Hash,
    payload_hash: &Hash,
) -> Bytes {
    let mut msg = Vec::new();
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(&parent);
    msg.extend_from_slice(&payload_hash);
    msg.into()
}

fn vote_digest(view: crate::View, height: Height, proposal_hash: Option<Hash>) -> Bytes {
    let mut msg = Vec::new();
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    if let Some(hash) = proposal_hash {
        msg.extend_from_slice(&hash);
    }
    msg.into()
}

fn finalize_digest(view: crate::View, height: Height, proposal_hash: &Hash) -> Bytes {
    let mut msg = Vec::new();
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(&proposal_hash);
    msg.into()
}

pub fn hash(digest: &Bytes) -> Bytes {
    let mut hasher = Sha256::new();
    hasher.update(digest);
    hasher.finalize().to_vec().into()
}

pub struct View {
    leader: PublicKey,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    null_vote_retry: Option<SystemTime>,

    // Track one proposal per view
    proposal: Option<(Hash /* proposal */, wire::Proposal)>,
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

impl View {
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

            proposal: None,
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
            if self.finalizers.contains_key(public_key) {
                warn!(
                    view = vote.view,
                    signer = hex(public_key),
                    "already voted finalize",
                );
                if skip_invalid {
                    return;
                }
            }

            // Store the null vote
            self.null_votes.insert(public_key.clone(), vote);
            return;
        }
        let hash = vote.hash.clone().unwrap();

        // Check if already voted
        if let Some(previous_vote) = self.proposal_voters.get(public_key) {
            warn!(
                view = vote.view,
                signer = hex(public_key),
                previous_vote = hex(previous_vote),
                "already voted"
            );
            if skip_invalid {
                return;
            }
        }

        // Store the vote
        self.proposal_voters
            .insert(public_key.clone(), hash.clone());
        let entry = self.proposal_votes.entry(hash).or_insert_with(HashMap::new);
        entry.insert(public_key.clone(), vote);
    }

    fn notarizable_proposal(
        &mut self,
        threshold: u32,
    ) -> Option<(Option<Hash>, Height, &HashMap<PublicKey, wire::Vote>)> {
        if self.broadcast_proposal_notarization || self.broadcast_null_notarization {
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
                            proposal = hex(&proposal),
                            hash = hex(&hash),
                            reason = "proposal mismatch",
                            "skipping notarization broadcast"
                        );
                        continue;
                    }
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
    ) -> Option<(Option<Hash>, Height, &HashMap<PublicKey, wire::Vote>)> {
        if self.broadcast_null_notarization || self.broadcast_proposal_notarization {
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
        if self.null_votes.contains_key(public_key) {
            warn!(
                view = finalize.view,
                signer = hex(public_key),
                "already voted null",
            );
            if skip_invalid {
                return;
            }
        }

        // Check if already finalized
        if let Some(previous_finalize) = self.finalizers.get(public_key) {
            warn!(
                view = finalize.view,
                signer = hex(public_key),
                previous_finalize = hex(previous_finalize),
                "already voted finalize"
            );
            if skip_invalid {
                return;
            }
        }

        // Store the finalize
        self.finalizers
            .insert(public_key.clone(), finalize.hash.clone());
        let entry = self
            .finalizes
            .entry(finalize.hash.clone())
            .or_insert_with(HashMap::new);
        entry.insert(public_key.clone(), finalize);
    }

    fn finalizable_proposal(
        &mut self,
        threshold: u32,
    ) -> Option<(Hash, Height, &HashMap<PublicKey, wire::Finalize>)> {
        if self.broadcast_finalization {
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
                            proposal = hex(&proposal),
                            hash = hex(&hash),
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

// TODO: create fault tracker that can be configured by developer to do something

pub struct Voter<E: Clock + Rng, C: Scheme> {
    runtime: E,
    crypto: C,

    orchestrator: Mailbox,

    threshold: u32,
    validators: Vec<PublicKey>,
    validators_ordered: HashMap<PublicKey, u32>,

    last_finalized: u64,
    view: u64,
    views: BTreeMap<u64, View>,
}

impl<E: Clock + Rng, C: Scheme> Voter<E, C> {
    pub fn new(
        runtime: E,
        crypto: C,
        orchestrator: Mailbox,
        mut validators: Vec<PublicKey>,
    ) -> Self {
        // Initialize ordered validators
        validators.sort();
        let mut validators_ordered = HashMap::new();
        for (i, validator) in validators.iter().enumerate() {
            validators_ordered.insert(validator.clone(), i as u32);
        }

        // Add first view
        //
        // We start on view 1 because the genesis block occupies view 0/height 0.
        let mut views = BTreeMap::new();
        views.insert(
            1,
            View::new(
                validators[1].clone(),
                Some(runtime.current() + Duration::from_secs(1)),
                Some(runtime.current() + Duration::from_secs(2)),
            ),
        );

        // Initialize store
        Self {
            runtime,
            crypto,

            orchestrator,

            // TODO: move this helper
            threshold: threshold(validators.len() as u32)
                .expect("not possible to satisfy 2f+1 threshold"),
            validators,
            validators_ordered,

            last_finalized: 0,
            view: 1,
            views,
        }
    }

    pub async fn propose(&mut self) -> Option<wire::Proposal> {
        // Check if we are leader
        let view = self.views.get(&self.view).unwrap();
        if view.leader != self.crypto.public_key() {
            return None;
        }

        // Check if we have already proposed
        if view.proposal.is_some() {
            return None;
        }

        // Select parent block
        let (parent, height, payload_hash, payload) = match self.orchestrator.propose().await {
            Some(proposal) => proposal,
            None => {
                debug!(reason = "no available parent", "dropping proposal");
                return None;
            }
        };

        // Construct proposal
        let digest = proposal_digest(self.view, height, &parent, &payload_hash);
        let proposal = wire::Proposal {
            view: self.view,
            height,
            parent,
            payload,
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(PROPOSAL_NAMESPACE, &digest),
            }),
        };
        Some(proposal)
    }

    pub fn timeout_deadline(&mut self) -> SystemTime {
        // Return the earliest deadline
        // TODO: if no view exists, this will panic
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
        let null_vote_retry = self.runtime.current() + Duration::from_secs(30);
        view.null_vote_retry = Some(null_vote_retry);
        null_vote_retry
    }

    fn leader(&self, view: crate::View) -> PublicKey {
        self.validators[view as usize % self.validators.len()].clone()
    }

    pub fn timeout(&mut self) -> wire::Vote {
        // Set timeout fired
        let view = self.views.get_mut(&self.view).unwrap();
        view.timeout_fired = true;

        // Remove deadlines
        view.leader_deadline = None;
        view.advance_deadline = None;
        view.null_vote_retry = None;

        // Construct null vote
        let digest = vote_digest(self.view, 0, None);
        wire::Vote {
            view: self.view,
            height: 0,
            hash: None,
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(VOTE_NAMESPACE, &digest),
            }),
        }
    }

    pub async fn proposal(&mut self, proposal: wire::Proposal) {
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
        let expected_leader = self.leader(proposal.view);
        if !C::validate(&signature.public_key) {
            debug!(reason = "invalid signature", "dropping proposal");
            return;
        }
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
        if let Some(view) = self.views.get(&proposal.view) {
            if view.proposal.is_some() {
                debug!(view = proposal.view, "proposal already exists");
                // TODO: check if different signed proposal and post fault
                return;
            }
        }

        // Verify the signature
        let payload_hash = match self
            .orchestrator
            .parse(
                proposal.parent.clone(),
                proposal.height,
                proposal.payload.clone(),
            )
            .await
        {
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
            PROPOSAL_NAMESPACE,
            &proposal_digest,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping proposal");
            return;
        }

        // Verify the proposal
        //
        // This will fail if we haven't notified the application of this parent.
        if !self.orchestrator.verify(proposal.clone()).await {
            debug!(reason = "invalid payload", "dropping proposal");
            return;
        };

        // Store the proposal
        let proposal_view = proposal.view;
        let proposal_height = proposal.height;
        let view = self
            .views
            .entry(proposal.view)
            .or_insert_with(|| View::new(expected_leader, None, None));
        let proposal_hash = hash(&proposal_digest);
        view.proposal = Some((proposal_hash.clone(), proposal));
        view.leader_deadline = None;
        debug!(
            view = proposal_view,
            height = proposal_height,
            hash = hex(&proposal_hash),
            "stored proposal"
        );
    }

    fn enter_view(&mut self, view: u64) {
        // Ensure view is valid
        if view <= self.view {
            panic!("cannot enter previous or current view");
        }

        // Setup new view
        let entry = self.views.entry(view).or_insert_with(|| {
            View::new(
                self.validators[view as usize % self.validators.len()].clone(),
                None,
                None,
            )
        });
        entry.leader_deadline = Some(self.runtime.current() + Duration::from_secs(1));
        entry.advance_deadline = Some(self.runtime.current() + Duration::from_secs(2));

        info!(view, "entered view");
        self.view = view;
    }

    fn prune_views(&mut self) {
        loop {
            // Get next key
            let next = match self.views.keys().next() {
                Some(next) => *next,
                None => return,
            };

            // Compare to last finalized
            if next <= self.last_finalized {
                self.views.remove(&next);
                debug!(view = next, "pruned view");
            } else {
                return;
            }
        }
    }

    pub fn vote(&mut self, vote: wire::Vote) {
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
        if !self.validators_ordered.contains_key(&signature.public_key) {
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
            VOTE_NAMESPACE,
            &vote_digest,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping vote");
            return;
        }

        // Check to see if vote is for proposal in view
        let view = self.views.entry(vote.view).or_insert_with(|| {
            View::new(
                self.validators[vote.view as usize % self.validators.len()].clone(),
                None,
                None,
            )
        });

        // Handle vote
        view.add_verified_vote(true, vote);
    }

    pub async fn notarization(&mut self, notarization: wire::Notarization) {
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
        if notarization.signatures.len() < self.threshold as usize {
            debug!(
                threshold = self.threshold,
                signatures = notarization.signatures.len(),
                reason = "insufficient signatures",
                "dropping notarization"
            );
            return;
        }
        if notarization.signatures.len() > self.validators.len() {
            debug!(
                threshold = self.threshold,
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
                VOTE_NAMESPACE,
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

        // Add signatures to view (needed to broadcast notarization if we get proposal)
        let view = self.views.entry(notarization.view).or_insert_with(|| {
            View::new(
                self.validators[notarization.view as usize % self.validators.len()].clone(),
                None,
                None,
            )
        });
        for signature in notarization.signatures {
            let vote = wire::Vote {
                view: notarization.view,
                height: notarization.height,
                hash: notarization.hash.clone(),
                signature: Some(signature),
            };
            view.add_verified_vote(false, vote);
        }

        // Inform orchestrator of notarization if not null vote
        if let Some(notarization_hash) = notarization.hash {
            let proposal = match view.proposal.as_ref() {
                Some((hash, proposal)) => Proposal::Populated(hash.clone(), proposal.clone()),
                None => {
                    Proposal::Reference(notarization.view, notarization.height, notarization_hash)
                }
            };
            self.orchestrator.notarized(proposal).await;
        }

        // Enter next view
        self.enter_view(notarization.view + 1);
    }

    pub fn finalize(&mut self, finalize: wire::Finalize) {
        // Ensure we are in the right view to process this message
        if finalize.view != self.view && finalize.view != self.view + 1 {
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
        if !self.validators_ordered.contains_key(&signature.public_key) {
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
            FINALIZE_NAMESPACE,
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

        // Get view for finalize
        let view = self.views.entry(finalize.view).or_insert_with(|| {
            View::new(
                self.validators[finalize.view as usize % self.validators.len()].clone(),
                None,
                None,
            )
        });

        // Handle finalize
        view.add_verified_finalize(true, finalize);
    }

    pub async fn finalization(&mut self, finalization: wire::Finalization) {
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
                    reason = "already broadcast finalization",
                    "dropping finalization"
                );
                return;
            }
        }

        // Ensure finalization has valid number of signatures
        if finalization.signatures.len() < self.threshold as usize {
            debug!(
                threshold = self.threshold,
                signatures = finalization.signatures.len(),
                reason = "insufficient signatures",
                "dropping finalization"
            );
            return;
        }
        if finalization.signatures.len() > self.validators.len() {
            debug!(
                threshold = self.threshold,
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
                FINALIZE_NAMESPACE,
                &finalize_digest(finalization.view, finalization.height, &finalization.hash),
                &signature.public_key,
                &signature.signature,
            ) {
                debug!(reason = "invalid signature", "dropping finalization");
                return;
            }
        }
        debug!(view = finalization.view, "finalization verified");

        // Add signatures to view (needed to broadcast finalization if we get proposal)
        let view = self.views.entry(finalization.view).or_insert_with(|| {
            View::new(
                self.validators[finalization.view as usize % self.validators.len()].clone(),
                None,
                None,
            )
        });
        for signature in finalization.signatures {
            let finalize = wire::Finalize {
                view: finalization.view,
                height: finalization.height,
                hash: finalization.hash.clone(),
                signature: Some(signature),
            };
            view.add_verified_finalize(false, finalize);
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
        self.orchestrator.finalized(proposal).await;

        // Enter next view (if applicable)
        if finalization.view >= self.view {
            self.enter_view(finalization.view + 1);
        }

        // Prune any old views
        self.prune_views();
    }

    pub fn construct_vote(&mut self, view: u64) -> Option<wire::Vote> {
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
                    VOTE_NAMESPACE,
                    &vote_digest(view, proposal.height, Some(hash.clone())),
                ),
            }),
        })
    }

    pub fn construct_notarization(&mut self, view: u64) -> Option<wire::Notarization> {
        // Get requested view
        let view_obj = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct notarization
        let mut result = view_obj.notarizable_proposal(self.threshold);
        if result.is_none() {
            result = view_obj.notarizable_null(self.threshold);
        }
        let (hash, height, votes) = result?;

        // Construct notarization
        let mut signatures = Vec::new();
        for validator in self.validators.iter() {
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

    pub fn construct_finalize(&mut self, view: u64) -> Option<wire::Finalize> {
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
                    FINALIZE_NAMESPACE,
                    &finalize_digest(view, proposal.height, hash),
                ),
            }),
        })
    }

    pub fn construct_finalization(&mut self, view: u64) -> Option<wire::Finalization> {
        let view_obj = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Check if we have enough finalizes
        let (hash, height, finalizes) = view_obj.finalizable_proposal(self.threshold)?;

        // Construct finalization
        let mut signatures = Vec::new();
        for validator in self.validators.iter() {
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

    async fn send_view_messages(&mut self, sender: &mut impl Sender, view: u64) {
        // Attempt to vote
        if let Some(vote) = self.construct_vote(view) {
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
            self.vote(vote);
        };

        // Attempt to notarize
        if let Some(notarization) = self.construct_notarization(view) {
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
            self.notarization(notarization);
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
            self.finalize(finalize);
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
            self.finalization(finalization);
        };
    }

    pub async fn run(mut self, mut sender: impl Sender, mut receiver: impl Receiver) {
        // Process messages
        loop {
            // Attempt to propose a block
            if let Some(proposal) = self.propose().await {
                // Broadcast the proposal
                let msg = wire::Consensus {
                    payload: Some(wire::consensus::Payload::Proposal(proposal.clone())),
                };
                let msg = msg.encode_to_vec();
                sender
                    .send(Recipients::All, msg.into(), true)
                    .await
                    .unwrap();

                // Handle the proposal
                let proposal_view = proposal.view;
                self.proposal(proposal).await;
                self.send_view_messages(&mut sender, proposal_view).await;
            }

            // Wait for a timeout to fire or for a message to arrive
            let null_timeout = self.timeout_deadline();
            select! {
                _timeout = self.runtime.sleep_until(null_timeout) => {
                    // Trigger the timeout
                    let vote = self.timeout();

                    // Broadcast the vote
                    let msg = wire::Consensus{
                        payload: Some(wire::consensus::Payload::Vote(vote.clone())),
                    };
                    let msg = msg.encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();

                    // Handle the vote
                    let vote_view = vote.view;
                    self.vote(vote);
                    self.send_view_messages(&mut sender, vote_view).await;
                },
                result = receiver.recv() => {
                    // Parse message
                    let (s, msg) = result.unwrap();
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
                    let view;
                    match payload {
                        wire::consensus::Payload::Proposal(proposal) => {
                            if proposal.parent.len() != HASH_LENGTH {
                                debug!(sender = hex(&s), "invalid proposal parent hash size");
                                continue;
                            }
                            view = proposal.view;
                            self.proposal(proposal).await;
                        }
                        wire::consensus::Payload::Vote(vote) => {
                            if vote.hash.is_none() && vote.height != 0 {
                                debug!(sender = hex(&s), "invalid vote height for null block");
                                continue;
                            }
                            if vote.hash.is_some() && vote.hash.as_ref().unwrap().len() != HASH_LENGTH {
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
                            if notarization.hash.is_some() && notarization.hash.as_ref().unwrap().len() != HASH_LENGTH {
                                debug!(sender = hex(&s), "invalid notarization hash size");
                                continue;
                            }
                            view = notarization.view;
                            self.notarization(notarization).await;
                        }
                        wire::consensus::Payload::Finalize(finalize) => {
                            if finalize.hash.len() != HASH_LENGTH {
                                debug!(sender = hex(&s), "invalid finalize hash size");
                                continue;
                            }
                            view = finalize.view;
                            self.finalize(finalize);
                        }
                        wire::consensus::Payload::Finalization(finalization) => {
                            if finalization.hash.len() != HASH_LENGTH {
                                debug!(sender = hex(&s), "invalid finalization hash size");
                                continue;
                            }
                            view = finalization.view;
                            self.finalization(finalization).await;
                        }
                    };

                    // Attempt to send any new view messages
                    self.send_view_messages(&mut sender, view).await;
                },
            };
        }
    }
}
