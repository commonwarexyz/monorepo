use super::wire;
use bytes::Bytes;
use commonware_cryptography::{utils::hex, PublicKey, Scheme, Signature};
use commonware_runtime::Clock;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, time::SystemTime};
use tracing::debug;

// TODO: move to config
const PROPOSAL_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_PROPOSAL_";
const VOTE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_VOTE_";
const FINALIZE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_FINALIZE_";

// TODO: get payload as hash
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
    leader: PublicKey,

    leader_deadline: Option<SystemTime>,
    notarization_deadline: Option<SystemTime>,

    proposal: Option<(Bytes, wire::Proposal)>,

    proposal_votes: HashMap<PublicKey, wire::Vote>,
    proposal_notarization: Option<wire::Notarization>,

    null_votes: HashMap<PublicKey, wire::Vote>,
    null_notarization: Option<wire::Notarization>,

    finalizes: HashMap<PublicKey, wire::Finalize>,
    finalization: Option<wire::Finalization>,
}

impl View {
    pub fn new(
        leader: PublicKey,
        leader_deadline: SystemTime,
        notarization_deadline: SystemTime,
    ) -> Self {
        Self {
            leader,

            leader_deadline: Some(leader_deadline),
            notarization_deadline: Some(notarization_deadline),

            proposal: None,

            proposal_votes: HashMap::new(),
            proposal_notarization: None,

            null_votes: HashMap::new(),
            null_notarization: None,

            finalizes: HashMap::new(),
            finalization: None,
        }
    }
}

pub struct Store<E: Clock, C: Scheme> {
    runtime: E,
    crypto: C,

    validators: Vec<PublicKey>,
    validators_ordered: HashMap<PublicKey, u32>,

    view: u64,
    views: HashMap<u64, View>,
    blocks: HashMap<Bytes, (u64, u64)>, // block hash -> (view, height)
}

impl<E: Clock, C: Scheme> Store<E, C> {
    pub fn new(runtime: E, crypto: C, mut validators: Vec<PublicKey>) -> Self {
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

            validators,
            validators_ordered,

            view: 0,
            views: HashMap::new(),
            blocks: HashMap::new(),
        }
    }

    pub fn propose(&mut self, proposal: wire::Proposal) -> Option<wire::Vote> {
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

        // Verify the signature
        // TODO: get payload hash from function (passed as trait)
        let proposal_digest = proposal_digest(
            proposal.view,
            proposal.height,
            proposal.parent.clone(),
            proposal.payload.clone(),
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

        // Check to see if we are past the leader deadline
        let deadline = view.leader_deadline.unwrap();
        let current = self.runtime.current();
        if deadline < current {
            debug!(
                view = proposal.view,
                ?deadline,
                ?current,
                "leader deadline passed"
            );
            return None;
        }

        // Check to see if compatible with notarized tip
        let (_, parent_height) = match self.blocks.get(&proposal.parent) {
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

        // TODO: verify the proposal

        // Store the proposal
        let proposal_hash = hash(proposal_digest);
        view.proposal = Some((proposal_hash.clone(), proposal));
        view.leader_deadline = None;

        // Construct vote
        let vote = wire::Vote {
            view: self.view,
            block: proposal_hash.clone(),
            signature: Some(wire::Signature {
                public_key: self.crypto.public_key(),
                signature: self.crypto.sign(VOTE_NAMESPACE, &proposal_hash),
            }),
        };

        // Store the vote
        view.proposal_votes
            .insert(self.crypto.public_key(), vote.clone());

        // Return the vote for broadcast
        Some(vote)
    }

    pub fn vote(&mut self, vote: wire::Vote) -> Option<wire::Notarization> {
        // Ensure we are in the right view to process this message
        if vote.view != self.view {
            debug!(
                vote_view = vote.view,
                our_view = self.view,
                reason = "incorrect view",
                "dropping vote"
            );
            return None;
        }
        None
    }

    pub fn notarization(&self, notarization: wire::Notarization) -> Option<wire::Notarization> {
        None
    }

    pub fn finalize(finalize: wire::Finalize) -> Option<wire::Finalization> {
        None
    }

    pub fn finalization(finalization: wire::Finalization) -> Option<wire::Finalization> {
        None
    }
}
