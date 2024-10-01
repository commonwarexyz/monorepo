use super::wire;
use crate::Application;
use bytes::Bytes;
use commonware_cryptography::{
    bls12381::dkg::utils::threshold, utils::hex, PublicKey, Scheme, Signature,
};
use commonware_runtime::Clock;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};
use tracing::{debug, trace};

// TODO: move to config
const PROPOSAL_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_PROPOSAL_";
const VOTE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_VOTE_";
const FINALIZE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_FINALIZE_";

fn proposal_digest(view: u64, height: u64, parent: Bytes, payload: Bytes) -> Bytes {
    let mut hash = Vec::new();
    hash.extend_from_slice(&view.to_be_bytes());
    hash.extend_from_slice(&height.to_be_bytes());
    hash.extend_from_slice(&parent);
    hash.extend_from_slice(&payload);
    hash.into()
}

fn hash(bytes: Bytes) -> Bytes {
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

pub struct View {
    idx: u64,

    leader: PublicKey,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    null_vote_retry: Option<SystemTime>,

    proposal: Option<(Bytes, wire::Proposal)>,

    proposal_votes: HashMap<PublicKey, wire::Vote>,
    broadcast_proposal_notarization: bool,

    timeout_fired: bool,
    null_votes: HashMap<PublicKey, wire::Vote>,
    broadcast_null_notarization: bool,

    finalizes: HashMap<PublicKey, wire::Finalize>,
    broadcast_finalization: bool,
}

impl View {
    pub fn new(
        idx: u64,
        leader: PublicKey,
        leader_deadline: SystemTime,
        advance_deadline: SystemTime,
    ) -> Self {
        Self {
            idx,

            leader,
            leader_deadline: Some(leader_deadline),
            advance_deadline: Some(advance_deadline),
            null_vote_retry: None,

            proposal: None,

            proposal_votes: HashMap::new(),
            broadcast_proposal_notarization: false,

            timeout_fired: false,
            null_votes: HashMap::new(),
            broadcast_null_notarization: false,

            finalizes: HashMap::new(),
            broadcast_finalization: false,
        }
    }
}

pub struct Store<E: Clock, C: Scheme, A: Application> {
    runtime: E,
    crypto: C,
    application: A,

    threshold: u32,
    validators: Vec<PublicKey>,
    validators_ordered: HashMap<PublicKey, u32>,

    view: u64,
    views: HashMap<u64, View>,
    notarized_blocks: HashMap<Bytes, (u64, u64)>, // block hash -> (view, height)
}

impl<E: Clock, C: Scheme, A: Application> Store<E, C, A> {
    pub fn new(runtime: E, crypto: C, application: A, mut validators: Vec<PublicKey>) -> Self {
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
            application,

            // TODO: move this helper
            threshold: threshold(validators.len() as u32)
                .expect("not possible to satisfy 2f+1 threshold"),
            validators,
            validators_ordered,

            view: 0,
            views: HashMap::new(),
            notarized_blocks: HashMap::new(),
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

        // Construct proposal
        let (payload_hash, payload) = self.application.propose();
        let proposal = wire::Proposal {
            view: self.view,
            height: 0,
            parent: Bytes::new(),
            payload,
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(
                    PROPOSAL_NAMESPACE,
                    &proposal_digest(self.view, 0, Bytes::new(), payload_hash),
                ),
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
        wire::Vote {
            view: self.view,
            block: Bytes::new(),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(VOTE_NAMESPACE, &Bytes::new()),
            }),
        }
    }

    pub fn proposal(&mut self, proposal: wire::Proposal) -> Option<wire::Vote> {
        // Ensure we are in the right view to process this message
        // TODO: consider storing the proposal if one ahead of our current view
        if proposal.view != self.view {
            debug!(
                proposal_view = proposal.view,
                our_view = self.view,
                reason = "incorrect view",
                "dropping proposal"
            );
            return None;
        }

        // Parse signature
        let signature = match &proposal.signature {
            Some(signature) => signature,
            _ => {
                debug!(reason = "missing signature", "dropping proposal");
                return None;
            }
        };

        // Check to see if we have already received a proposal for this view
        let view = self.views.get_mut(&proposal.view).unwrap();
        if view.proposal.is_some() {
            debug!(view = proposal.view, "proposal already exists");
            // TODO: check if different signed proposal and post fault
            return None;
        }

        // Check to see if leader is correct
        if !C::validate(&signature.public_key) {
            debug!(reason = "invalid signature", "dropping proposal");
            return None;
        }
        if view.leader != signature.public_key {
            debug!(
                proposal_leader = hex(&signature.public_key),
                view_leader = hex(&view.leader),
                reason = "leader mismatch",
                "dropping proposal"
            );
            return None;
        }

        // Verify the payload and get its hash
        let payload_hash = match self.application.verify(proposal.payload.clone()) {
            Some(hash) => hash,
            None => {
                debug!(reason = "invalid payload", "dropping proposal");
                return None;
            }
        };

        // Verify the signature
        let proposal_digest = proposal_digest(
            proposal.view,
            proposal.height,
            proposal.parent.clone(),
            payload_hash,
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

        // Check to see if compatible with notarized tip
        let (_, parent_height) = match self.notarized_blocks.get(&proposal.parent) {
            Some(view) => view,
            None => {
                debug!(reason = "unknown parent", "dropping proposal");
                return None;
            }
        };
        if parent_height + 1 != proposal.height {
            debug!(
                parent_height = parent_height,
                proposal_height = proposal.height,
                reason = "invalid height",
                "dropping proposal"
            );
            return None;
        }

        // Store the proposal
        let proposal_hash = hash(proposal_digest);
        let proposal_view = proposal.view;
        view.proposal = Some((proposal_hash.clone(), proposal));
        view.leader_deadline = None;

        // Check to see if we are past the leader deadline
        if view.timeout_fired {
            debug!(view = proposal_view, "leader deadline passed");
            return None;
        }

        // Construct vote
        let vote = wire::Vote {
            view: self.view,
            block: proposal_hash.clone(),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(VOTE_NAMESPACE, &proposal_hash),
            }),
        };

        // Return the vote for broadcast
        Some(vote)
    }

    fn construct_notarization(
        validators: &Vec<PublicKey>,
        threshold: u32,
        view: &mut View,
        last_vote_null: bool,
    ) -> Option<wire::Notarization> {
        // Determine which votes to use
        let (proposal_hash, votes) = match last_vote_null {
            true => {
                if (view.null_votes.len() as u32) < threshold || view.broadcast_null_notarization {
                    return None;
                }
                view.broadcast_null_notarization = true;
                (Bytes::new(), &view.null_votes)
            }
            false => {
                if (view.proposal_votes.len() as u32) < threshold
                    || view.broadcast_proposal_notarization
                {
                    return None;
                }
                view.broadcast_proposal_notarization = true;
                (
                    view.proposal.as_ref().unwrap().0.clone(),
                    &view.proposal_votes,
                )
            }
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

    pub fn vote(&mut self, vote: wire::Vote) -> Option<wire::Notarization> {
        // Ensure we are in the right view to process this message
        // TODO: consider storing the vote if one ahead of our current view
        if vote.view != self.view {
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
                debug!(reason = "missing signature", "dropping proposal");
                return None;
            }
        };
        if !C::validate(&signature.public_key) {
            debug!(reason = "invalid signature", "dropping proposal");
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
        let view = self.views.get_mut(&vote.view).unwrap();

        // Handle vote
        let last_vote_null = vote.block.len() == 0;
        if vote.block.len() == 0 {
            view.null_votes
                .insert(signature.public_key.clone(), vote.clone());
        } else {
            let proposal_hash = match &view.proposal {
                Some((hash, _)) => hash,
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
        Self::construct_notarization(&self.validators, self.threshold, view, last_vote_null)
    }

    pub fn advance(&mut self) -> Option<wire::Notarization> {
        // Return if we don't have threshold votes and or have already broadcast notarization
        // TODO: also handle threshold null votes
        if (view.proposal_votes.len() as u32) < self.threshold
            || view.broadcast_proposal_notarization
        {
            return None;
        }

        // Construct notarization
        let mut signatures = Vec::new();
        for validator in self.validators.iter() {
            if let Some(vote) = view.proposal_votes.get(validator) {
                signatures.push(vote.signature.clone().unwrap());
            }
        }
        let notarization = wire::Notarization {
            view: self.view,
            block: proposal_hash.clone(),
            signatures,
        };
        view.broadcast_proposal_notarization = true;
        self.blocks.insert(
            proposal_hash.clone(),
            (self.view, view.proposal.as_ref().unwrap().1.height),
        );

        // Increment view
        // TODO: put this logic in a helper
        self.view += 1;
        self.views.insert(
            self.view,
            View::new(
                self.validators[self.view as usize % self.validators.len()].clone(),
                self.runtime.current() + Duration::from_secs(2),
                self.runtime.current() + Duration::from_secs(3),
            ),
        );

        // TODO: if leader, ask for block after sending notarization

        // Return the notarization
        Some(notarization)

        // TODO: send finalize message
    }

    pub fn notarization(
        &mut self,
        notarization: wire::Notarization,
    ) -> (Option<wire::Notarization>, Option<wire::Finalize>) {
        // Store any signatures we have yet to see on current or previous view
        let view = match self.views.get_mut(&notarization.view) {
            Some(view) => view,
            None => {
                debug!(
                    view = notarization.view,
                    reason = "unknown view",
                    "dropping notarization"
                );
                return None;
            }
        };

        // Get proposal
        let proposal_hash = match &view.proposal {
            Some((hash, _)) => hash,
            None => {
                debug!(reason = "missing proposal", "dropping notarization");
                return None;
            }
        };

        // If notarization is not for proposal, drop
        if proposal_hash != &notarization.block {
            debug!(
                notarization_block = hex(&notarization.block),
                proposal_block = hex(&proposal_hash),
                reason = "block mismatch",
                "dropping notarization"
            );
            return None;

            // TODO: drop proposal block we were given and fetch correct block
        }

        // Verify and store missing signatures
        //
        // TODO: verify that well-formed notarization (has threshold signatures)?
        // TODO: limit length of signatures
        for signature in notarization.signatures {
            if !C::validate(&signature.public_key) {
                debug!(
                    signer = hex(&signature.public_key),
                    reason = "invalid validator",
                    "dropping notarization"
                );
                return None;
            }
            if view.proposal_votes.contains_key(&signature.public_key) {
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
                return None;
            }
            view.proposal_votes.insert(
                signature.public_key.clone(),
                wire::Vote {
                    view: notarization.view,
                    block: proposal_hash.clone(),
                    signature: Some(signature),
                },
            );
        }

        // Return if we don't have threshold votes and or have already broadcast notarization
        if (view.proposal_votes.len() as u32) < self.threshold
            || view.broadcast_proposal_notarization
        {
            return None;
        }

        // Construct notarization
        let mut signatures = Vec::new();
        for validator in self.validators.iter() {
            if let Some(vote) = view.proposal_votes.get(validator) {
                signatures.push(vote.signature.clone().unwrap());
            }
        }
        let notarization = wire::Notarization {
            view: self.view,
            block: proposal_hash.clone(),
            signatures,
        };
        view.broadcast_proposal_notarization = true;
        self.blocks.insert(
            proposal_hash.clone(),
            (self.view, view.proposal.as_ref().unwrap().1.height),
        );

        // Increment view
        // TODO: put this logic in a helper
        self.view += 1;
        self.views.insert(
            self.view,
            View::new(
                self.validators[self.view as usize % self.validators.len()].clone(),
                self.runtime.current() + Duration::from_secs(2),
                self.runtime.current() + Duration::from_secs(3),
            ),
        );

        // Return the notarization
        Some(notarization)
    }

    pub fn finalize(&mut self, finalize: wire::Finalize) -> Option<wire::Finalization> {
        None
    }

    pub fn finalization(&mut self, finalization: wire::Finalization) -> Option<wire::Finalization> {
        None
    }
}
