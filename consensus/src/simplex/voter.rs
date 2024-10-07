//! TODO: change name to voter

use super::{orchestrator::Orchestrator, wire};
use crate::{Application, Hash};
use bytes::Bytes;
use commonware_cryptography::{bls12381::dkg::utils::threshold, utils::hex, PublicKey, Scheme};
use commonware_runtime::Clock;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime},
};
use tracing::{debug, trace, warn};

// TODO: move to config
const PROPOSAL_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_PROPOSAL_";
const VOTE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_VOTE_";
const FINALIZE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_FINALIZE_";

// TODO: move to shared location
pub fn proposal_digest(view: u64, height: u64, parent: Bytes, payload_hash: Bytes) -> Bytes {
    let mut hash = Vec::new();
    hash.extend_from_slice(&view.to_be_bytes());
    hash.extend_from_slice(&height.to_be_bytes());
    hash.extend_from_slice(&parent);
    hash.extend_from_slice(&payload_hash);
    hash.into()
}

pub fn hash(bytes: Bytes) -> Bytes {
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().to_vec().into()
}

fn vote_digest(view: u64, proposal_hash: Bytes) -> Bytes {
    let mut hash = Vec::new();
    hash.extend_from_slice(&view.to_be_bytes());
    hash.extend_from_slice(&proposal_hash);
    hash.into()
}

fn finalize_digest(view: u64, proposal_hash: Bytes) -> Bytes {
    let mut hash = Vec::new();
    hash.extend_from_slice(&view.to_be_bytes());
    hash.extend_from_slice(&proposal_hash);
    hash.into()
}

pub struct View {
    idx: u64,

    leader: PublicKey,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    null_vote_retry: Option<SystemTime>,

    // Track one proposal per view
    proposal: Option<(
        Hash, /* proposal */
        Hash, /* payload */
        wire::Proposal,
    )>,

    // Track votes for all proposals (ensuring any participant only has one recorded vote)
    proposal_voters: HashSet<PublicKey>,
    proposal_votes: HashMap<Hash, HashMap<PublicKey, wire::Vote>>,
    broadcast_proposal_notarization: bool,

    timeout_fired: bool,
    null_votes: HashMap<PublicKey, wire::Vote>,
    broadcast_null_notarization: bool,

    // Track finalizes for all proposals (ensuring any participant only has one recorded finalize)
    finalizers: HashSet<PublicKey>,
    finalizes: HashMap<Hash, HashMap<PublicKey, wire::Finalize>>,
    broadcast_finalization: bool,
}

impl View {
    pub fn new(
        idx: u64,
        leader: PublicKey,
        leader_deadline: Option<SystemTime>,
        advance_deadline: Option<SystemTime>,
    ) -> Self {
        Self {
            idx,

            leader,
            leader_deadline,
            advance_deadline,
            null_vote_retry: None,

            proposal: None,

            proposal_voters: HashSet::new(),
            proposal_votes: HashMap::new(),
            broadcast_proposal_notarization: false,

            timeout_fired: false,
            null_votes: HashMap::new(),
            broadcast_null_notarization: false,

            finalizers: HashSet::new(),
            finalizes: HashMap::new(),
            broadcast_finalization: false,
        }
    }

    fn notarizable_proposal(
        &mut self,
        threshold: u32,
    ) -> Option<(Hash, &HashMap<PublicKey, wire::Vote>)> {
        if self.broadcast_proposal_notarization {
            return None;
        }
        for (proposal, votes) in self.proposal_votes.iter() {
            if (votes.len() as u32) < threshold {
                continue;
            }

            // Ensure we have the proposal we are going to broadcast a notarization for
            match &self.proposal {
                Some((hash, _, _)) => {
                    if hash != proposal {
                        debug!(
                            proposal = hex(&proposal),
                            hash = hex(&hash),
                            reason = "proposal mismatch",
                            "skipping notarization broadcast"
                        );
                        continue;
                    }
                }
                None => {
                    continue;
                }
            }

            // There should never exist enough votes for multiple proposals, so it doesn't
            // matter which one we choose.
            self.broadcast_proposal_notarization = true;
            return Some((proposal.clone(), votes));
        }
        None
    }

    fn notarizable_null(
        &mut self,
        threshold: u32,
    ) -> Option<(Hash, &HashMap<PublicKey, wire::Vote>)> {
        if self.broadcast_null_notarization {
            return None;
        }
        if (self.null_votes.len() as u32) < threshold {
            return None;
        }
        self.broadcast_null_notarization = true;
        Some((Bytes::new(), &self.null_votes))
    }

    fn finalizable_proposal(
        &mut self,
        threshold: u32,
    ) -> Option<(Hash, &HashMap<PublicKey, wire::Finalize>)> {
        if self.broadcast_finalization {
            return None;
        }
        for (proposal, finalizes) in self.finalizes.iter() {
            if (finalizes.len() as u32) < threshold {
                continue;
            }

            // Ensure we have the proposal we are going to broadcast a finalization for
            match &self.proposal {
                Some((hash, _, _)) => {
                    if hash != proposal {
                        debug!(
                            proposal = hex(&proposal),
                            hash = hex(&hash),
                            reason = "proposal mismatch",
                            "skipping finalization broadcast"
                        );
                        continue;
                    }
                }
                None => {
                    continue;
                }
            }

            // There should never exist enough finalizes for multiple proposals, so it doesn't
            // matter which one we choose.
            self.broadcast_finalization = true;
            return Some((proposal.clone(), finalizes));
        }
        None
    }
}

// TODO: create fault tracker that can be configured by developer to do something

// TODO: handle messages from current view and next view
pub struct Voter<E: Clock + Rng, C: Scheme, A: Application> {
    runtime: E,
    crypto: C,

    orchestrator: Orchestrator<E, A>,

    threshold: u32,
    validators: Vec<PublicKey>,
    validators_ordered: HashMap<PublicKey, u32>,

    view: u64,
    views: HashMap<u64, View>,
}

impl<E: Clock + Rng, C: Scheme, A: Application> Voter<E, C, A> {
    pub fn new(
        runtime: E,
        crypto: C,
        orchestrator: Orchestrator<E, A>,
        mut validators: Vec<PublicKey>,
    ) -> Self {
        // Initialize ordered validators
        validators.sort();
        let mut validators_ordered = HashMap::new();
        for (i, validator) in validators.iter().enumerate() {
            validators_ordered.insert(validator.clone(), i as u32);
        }

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

            view: 0,
            views: HashMap::new(),
        }
    }

    pub fn propose(&mut self) -> Option<wire::Proposal> {
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
        let (parent, payload) = match self.orchestrator.propose() {
            Some((parent, payload)) => (parent, payload),
            None => {
                debug!(reason = "no available parent", "dropping proposal");
                return None;
            }
        };
        let height = parent.1.height + 1;

        // Get payload hash
        let payload_hash = match self.orchestrator.parse(payload.clone()) {
            Some(hash) => hash,
            None => {
                warn!(
                    reason = "invalid payload produced by self",
                    "dropping proposal"
                );
                return None;
            }
        };

        // Construct proposal
        let digest = proposal_digest(self.view, height, parent.0.clone(), payload_hash.clone());
        let proposal = wire::Proposal {
            view: self.view,
            height,
            parent: parent.0,
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

    pub fn timeout(&mut self) -> wire::Vote {
        // Set timeout fired
        let view = self.views.get_mut(&self.view).unwrap();
        view.timeout_fired = true;

        // Remove deadlines
        view.leader_deadline = None;
        view.advance_deadline = None;
        view.null_vote_retry = None;

        // Construct null vote
        let blk = Bytes::new();
        wire::Vote {
            view: self.view,
            block: blk.clone(),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(VOTE_NAMESPACE, &blk),
            }),
        }
    }

    pub fn proposal(&mut self, proposal: wire::Proposal) -> Option<wire::Vote> {
        // Parse signature
        let signature = match &proposal.signature {
            Some(signature) => signature,
            _ => {
                debug!(reason = "missing signature", "dropping proposal");
                return None;
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
            return None;
        }

        // Check expected leader
        let expected_leader =
            self.validators[proposal.view as usize % self.validators.len()].clone();
        if !C::validate(&signature.public_key) {
            debug!(reason = "invalid signature", "dropping proposal");
            return None;
        }
        if expected_leader != signature.public_key {
            debug!(
                proposal_leader = hex(&signature.public_key),
                view_leader = hex(&expected_leader),
                reason = "leader mismatch",
                "dropping proposal"
            );
            return None;
        }

        // Check to see if we have already received a proposal for this view (if exists)
        if let Some(view) = self.views.get(&proposal.view) {
            if view.proposal.is_some() {
                debug!(view = proposal.view, "proposal already exists");
                // TODO: check if different signed proposal and post fault
                return None;
            }
        }

        // Verify the signature
        let payload_hash = match self.orchestrator.parse(proposal.payload.clone()) {
            Some(hash) => hash,
            None => {
                debug!(reason = "invalid payload", "dropping proposal");
                return None;
            }
        };
        let proposal_digest = proposal_digest(
            proposal.view,
            proposal.height,
            proposal.parent.clone(),
            payload_hash.clone(),
        );
        if !C::verify(
            PROPOSAL_NAMESPACE,
            &proposal_digest,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping proposal");
            return None;
        }

        // Verify the proposal
        if !self.orchestrator.verify(proposal.clone()) {
            debug!(reason = "invalid payload", "dropping proposal");
            return None;
        };

        // Store the proposal
        let view = self
            .views
            .entry(proposal.view)
            .or_insert_with(|| View::new(proposal.view, expected_leader, None, None));
        let proposal_hash = hash(proposal_digest);
        let proposal_view = proposal.view;
        view.proposal = Some((proposal_hash.clone(), payload_hash, proposal));
        view.leader_deadline = None;

        // Check to see if we are past the leader deadline
        if view.timeout_fired {
            debug!(view = proposal_view, "leader deadline passed");
            return None;
        }

        // Construct vote
        if proposal_view != self.view {
            // TODO: when moving into next view, we should broadcast vote
            return None;
        }
        Some(wire::Vote {
            view: self.view,
            block: proposal_hash.clone(),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(VOTE_NAMESPACE, &proposal_hash),
            }),
        })
    }

    fn construct_notarization(
        validators: &Vec<PublicKey>,
        threshold: u32,
        view: &mut View,
        last_vote_null: bool,
    ) -> Option<wire::Notarization> {
        // Determine which votes to use
        let (proposal_hash, votes) = match last_vote_null {
            true => view.notarizable_null(threshold)?,
            false => view.notarizable_proposal(threshold)?,
        };

        // Construct notarization
        let mut signatures = Vec::new();
        for validator in validators.iter() {
            if let Some(vote) = votes.get(validator) {
                signatures.push(vote.signature.clone().unwrap());
            }
        }
        let notarization = wire::Notarization {
            view: view.idx,
            block: proposal_hash,
            signatures,
        };
        Some(notarization)
    }

    fn enter_view(
        &mut self,
        view: u64,
    ) -> (
        Option<wire::Vote>,
        Option<wire::Notarization>,
        Option<wire::Finalize>,
        Option<wire::Finalization>,
    ) {
        // Ensure view is valid
        if view <= self.view {
            panic!("cannot enter previous or current view");
        }

        // Prune old views
        while self.view < view {
            if let Some(record) = self.views.remove(&self.view) {
                // TODO: send proposals to orchestrator to reduce backfill needs?
                debug!(view = record.idx, "pruned view");
            }
            self.view += 1;
        }

        // Setup new view
        let entry = self.views.entry(view).or_insert_with(|| {
            View::new(
                view,
                self.validators[view as usize % self.validators.len()].clone(),
                None,
                None,
            )
        });
        entry.leader_deadline = Some(self.runtime.current() + Duration::from_secs(1));
        entry.advance_deadline = Some(self.runtime.current() + Duration::from_secs(2));

        // TODO: If we have already seen a proposal, construct useful network messages
    }

    pub fn vote(&mut self, vote: wire::Vote) -> Option<wire::Notarization> {
        // Ensure we are in the right view to process this message
        if vote.view != self.view && vote.view != self.view + 1 {
            debug!(
                vote_view = vote.view,
                our_view = self.view,
                reason = "incorrect view",
                "dropping vote"
            );
            return None;
        }

        // Parse signature
        let signature = match &vote.signature {
            Some(signature) => signature,
            _ => {
                debug!(reason = "missing signature", "dropping vote");
                return None;
            }
        };
        if !C::validate(&signature.public_key) {
            debug!(reason = "invalid signature", "dropping vote");
            return None;
        }

        // Verify that signer is a validator
        if !self.validators_ordered.contains_key(&signature.public_key) {
            debug!(
                signer = hex(&signature.public_key),
                reason = "invalid validator",
                "dropping vote"
            );
            return None;
        }

        // Verify the signature
        let vote_digest = vote_digest(vote.view, vote.block.clone());
        if !C::verify(
            VOTE_NAMESPACE,
            &vote_digest,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping vote");
            return None;
        }

        // Check to see if vote is for proposal in view
        let view = self.views.entry(vote.view).or_insert_with(|| {
            View::new(
                vote.view,
                self.validators[vote.view as usize % self.validators.len()].clone(),
                None,
                None,
            )
        });

        // Handle vote
        let last_vote_null = vote.block.len() == 0;
        if vote.block.len() == 0 {
            view.null_votes
                .insert(signature.public_key.clone(), vote.clone());
        } else {
            let proposal_hash = match &view.proposal {
                Some((hash, _, _)) => hash,
                None => {
                    debug!(reason = "missing proposal", "dropping vote");
                    return None;
                }
            };
            if proposal_hash != &vote.block {
                debug!(
                    vote_block = hex(&vote.block),
                    proposal_block = hex(&proposal_hash),
                    reason = "block mismatch",
                    "dropping vote"
                );
                return None;
            }

            // Record the vote
            view.proposal_votes
                .insert(signature.public_key.clone(), vote.clone());
        }

        // Construct notarization
        if self.view != vote.view {
            return None;
        }
        Self::construct_notarization(&self.validators, self.threshold, view, last_vote_null)
    }

    pub fn notarization(
        &mut self,
        notarization: wire::Notarization,
    ) -> (Option<wire::Notarization>, Option<wire::Finalize>) {
        // Verify threshold notarization
        //
        // TODO: conditionally verify signatures based on our view
        let mut added = 0;
        let mut seen = HashSet::new();
        for signature in notarization.signatures {
            // Verify signature
            if !C::validate(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "invalid validator",
                    "dropping notarization"
                );
                return (None, None);
            }

            // Ensure we haven't seen this signature before
            if seen.contains(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "duplicate signature",
                    "dropping notarization"
                );
                return (None, None);
            }
            seen.insert(signature.public_key.clone());

            // Verify signature
            if !C::verify(
                VOTE_NAMESPACE,
                &vote_digest(notarization.view, notarization.block.clone()),
                &signature.public_key,
                &signature.signature,
            ) {
                debug!(reason = "invalid signature", "dropping notarization");
                return (None, None);
            }

            // TODO: If we are tracking this view, add any new signatures
            added += 1;
        }
        if added <= self.threshold {
            debug!(
                threshold = self.threshold,
                signatures = added,
                reason = "insufficient signatures",
                "dropping notarization"
            );
            return (None, None);
        }
        debug!(view = notarization.view, added, "notarization verified");

        // TODO: If new view, immediately jump ahead

        // TODO: if old view, add any missing signatures

        // TODO: check that notarization has threshold signatures and then move forward to that view,
        // if already tracking view can add missing signatures but we should not check that view already exists

        // Store any signatures we have yet to see on current or previous view
        let view = match self.views.get_mut(&notarization.view) {
            Some(view) => view,
            None => {
                debug!(
                    view = notarization.view,
                    reason = "unknown view",
                    "dropping notarization"
                );
                return (None, None);
            }
        };

        // Get votes
        let (proposal_hash, votes) = match notarization.block.len() {
            0 => (Bytes::new(), &mut view.null_votes),
            _ => {
                // Get proposal
                let proposal_hash = match &view.proposal {
                    Some((hash, _, _)) => hash,
                    None => {
                        // TODO: this will require us to fetch the proposal, but should never drop notarization
                        debug!(reason = "missing proposal", "dropping notarization");
                        return (None, None);
                    }
                };

                // If notarization is not for proposal, drop
                if proposal_hash != &notarization.block {
                    // TODO: this will require us to fetch the proposal and drop ours (Fault)
                    debug!(
                        notarization_block = hex(&notarization.block),
                        proposal_block = hex(&proposal_hash),
                        reason = "block mismatch",
                        "dropping notarization"
                    );
                    return (None, None);
                }
                (proposal_hash.clone(), &mut view.proposal_votes)
            }
        };

        // Verify signature info
        if notarization.signatures.len() < self.threshold as usize {
            debug!(
                threshold = self.threshold,
                signatures = notarization.signatures.len(),
                reason = "insufficient signatures",
                "dropping notarization"
            );
            return (None, None);
        }

        // Verify and store missing signatures
        let mut added = 0;
        let mut seen = HashSet::new();
        for signature in notarization.signatures {
            // Verify signature
            if !C::validate(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "invalid validator",
                    "dropping notarization"
                );
                return (None, None);
            }

            // Ensure we haven't seen this signature before
            if seen.contains(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "duplicate signature",
                    "dropping notarization"
                );
                return (None, None);
            }
            seen.insert(signature.public_key.clone());

            // If we already have this, skip verification
            if votes.contains_key(&signature.public_key) {
                trace!(
                    signer = hex(&signature.public_key),
                    reason = "already voted",
                    "skipping notarization vote"
                );
                continue;
            }
            if !C::verify(
                VOTE_NAMESPACE,
                &vote_digest(notarization.view, proposal_hash.clone()),
                &signature.public_key,
                &signature.signature,
            ) {
                debug!(reason = "invalid signature", "dropping notarization");
                return (None, None);
            }

            // Store the vote
            votes.insert(
                signature.public_key.clone(),
                wire::Vote {
                    view: notarization.view,
                    block: proposal_hash.clone(),
                    signature: Some(signature),
                },
            );
            added += 1;
        }
        debug!(added, "notarization verified");

        // Construct notarization
        let notarization = Self::construct_notarization(
            &self.validators,
            self.threshold,
            view,
            proposal_hash.is_empty(),
        );

        // Notify application
        if notarization.is_some() && !proposal_hash.is_empty() {
            let payload = view.proposal.as_ref().unwrap().2.payload.clone();
            self.last_notarized = Some(proposal_hash.clone());
            self.application.notarized(payload);
        }

        // Increment view
        let timeout_fired = view.timeout_fired;
        self.view += 1;
        self.views.insert(
            self.view,
            View::new(
                self.view,
                self.validators[self.view as usize % self.validators.len()].clone(),
                self.runtime.current() + Duration::from_secs(2),
                self.runtime.current() + Duration::from_secs(3),
            ),
        );

        // If this is a dummy block notarization or we've timed out, don't broadcast a finalize message.
        if proposal_hash.is_empty() || timeout_fired {
            return (notarization, None);
        }

        // Construct finalize
        let finalize = wire::Finalize {
            view: self.view,
            block: proposal_hash.clone(),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(FINALIZE_NAMESPACE, &proposal_hash),
            }),
        };
        (notarization, Some(finalize))
    }

    fn construct_finalization(
        validators: &Vec<PublicKey>,
        threshold: u32,
        view: &mut View,
    ) -> Option<wire::Finalization> {
        // Check if we have enough finalizes
        let (proposal_hash, finalizes) = view.finalizable_proposal(threshold)?;

        // Construct finalization
        let mut signatures = Vec::new();
        for validator in validators.iter() {
            if let Some(finalize) = finalizes.get(validator) {
                signatures.push(finalize.signature.clone().unwrap());
            }
        }
        let finalization = wire::Finalization {
            view: view.idx,
            block: proposal_hash,
            signatures,
        };
        Some(finalization)
    }

    pub fn finalize(&mut self, finalize: wire::Finalize) -> Option<wire::Finalization> {
        // Ensure we are in the right view to process this message
        if finalize.view != self.view && finalize.view != self.view + 1 {
            debug!(
                finalize_view = finalize.view,
                our_view = self.view,
                reason = "incorrect view",
                "dropping finalize"
            );
            return None;
        }

        // Parse signature
        let signature = match &finalize.signature {
            Some(signature) => signature,
            _ => {
                debug!(reason = "missing signature", "dropping finalize");
                return None;
            }
        };
        if !C::validate(&signature.public_key) {
            debug!(reason = "invalid signature", "dropping finalize");
            return None;
        }

        // Verify that signer is a validator
        if !self.validators_ordered.contains_key(&signature.public_key) {
            debug!(
                signer = hex(&signature.public_key),
                reason = "invalid validator",
                "dropping finalize"
            );
            return None;
        }

        // Verify the signature
        let finalize_digest = finalize_digest(finalize.view, finalize.block.clone());
        if !C::verify(
            VOTE_NAMESPACE,
            &finalize_digest,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping vote");
            return None;
        }

        // Get view for finalize
        let view = self.views.entry(finalize.view).or_insert_with(|| {
            View::new(
                finalize.view,
                self.validators[finalize.view as usize % self.validators.len()].clone(),
                None,
                None,
            )
        });

        // Check if finalize vote is for a block (Fault)
        if finalize.block.len() == 0 {
            // TODO: record fault
            debug!(reason = "finalize for null block", "dropping finalize");
            return None;
        }
        let proposal_hash = match &view.proposal {
            Some((hash, _, _)) => hash,
            None => {
                debug!(reason = "missing proposal", "dropping finalize");
                return None;
            }
        };
        if finalize.block != proposal_hash {
            debug!(
                finalize_block = hex(&finalize.block),
                proposal_block = hex(&view.proposal.as_ref().unwrap().0),
                reason = "block mismatch",
                "dropping finalize"
            );
            return None;
        }

        // Record the finalize
        view.finalizes
            .insert(signature.public_key.clone(), finalize.clone());

        // Construct finalization
        if finalize.view != self.view {
            return None;
        }
        Self::construct_finalization(&self.validators, self.threshold, view)
    }

    pub fn finalization(&mut self, finalization: wire::Finalization) -> Option<wire::Finalization> {
        // Ensure not for null
        if finalization.block.len() == 0 {
            debug!(reason = "finalize for null block", "dropping finalization");
            // TODO: record faults
            return None;
        }

        // Verify threshold finalization
        //
        // TODO: conditionally verify signatures based on our view
        let mut added = 0;
        let mut seen = HashSet::new();
        for signature in finalization.signatures {
            // Verify signature
            if !C::validate(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "invalid validator",
                    "dropping finalization"
                );
                return None;
            }

            // Ensure we haven't seen this signature before
            if seen.contains(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "duplicate signature",
                    "dropping finalization"
                );
                return None;
            }
            seen.insert(signature.public_key.clone());

            // Verify signature
            if !C::verify(
                FINALIZE_NAMESPACE,
                &finalize_digest(finalization.view, finalization.block.clone()),
                &signature.public_key,
                &signature.signature,
            ) {
                debug!(reason = "invalid signature", "dropping finalization");
                return None;
            }

            // TODO: If we are tracking this view, add any new signatures
            added += 1;
        }
        debug!(view = finalization.view, added, "finalization verified");

        // TODO: jump ahead if greater than our view (and prune in-memory after notifying orchestrator of what we have)

        // TODO: if old view, store finalizations

        // Store any signatures we have yet to see on current or previous view
        let view = match self.views.get_mut(&finalization.view) {
            Some(view) => view,
            None => {
                // TODO: shouldn't drop this
                debug!(
                    view = finalization.view,
                    reason = "unknown view",
                    "dropping finalization"
                );
                return None;
            }
        };

        // Verify signature info
        if finalization.signatures.len() < self.threshold as usize {
            debug!(
                threshold = self.threshold,
                signatures = finalization.signatures.len(),
                reason = "insufficient signatures",
                "dropping finalization"
            );
            return None;
        }

        // Verify and store missing signatures
        let mut added = 0;
        let mut seen = HashSet::new();
        for signature in finalization.signatures {
            // Verify signature
            if !C::validate(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "invalid validator",
                    "dropping finalization"
                );
                return None;
            }

            // Ensure we haven't seen this signature before
            if seen.contains(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "duplicate signature",
                    "dropping finalization"
                );
                return None;
            }
            seen.insert(signature.public_key.clone());

            // If we already have this, skip verification
            if view.finalizes.contains_key(&signature.public_key) {
                trace!(
                    signer = hex(&signature.public_key),
                    reason = "already recorded finalize",
                    "skipping finalization"
                );
                continue;
            }
            if !C::verify(
                FINALIZE_NAMESPACE,
                &finalize_digest(finalization.view, finalization.block.clone()),
                &signature.public_key,
                &signature.signature,
            ) {
                debug!(reason = "invalid signature", "dropping finalization");
                return None;
            }

            // Store the finalize
            view.finalizes.insert(
                signature.public_key.clone(),
                wire::Finalize {
                    view: finalization.view,
                    block: finalization.block.clone(),
                    signature: Some(signature),
                },
            );
            added += 1;
        }
        debug!(added, "finalization verified");

        // Construct finalization
        let finalization = Self::construct_finalization(&self.validators, self.threshold, view);
        if finalization.is_none() {
            return None;
        }

        // Notify application
        let payload = view.proposal.as_ref().unwrap().2.payload.clone();
        self.application.finalized(payload);
        finalization
    }
}
