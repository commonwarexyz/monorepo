use super::wire;
use bytes::Bytes;
use commonware_cryptography::{utils::hex, PublicKey, Scheme, Signature};
use commonware_runtime::Clock;
use std::{collections::HashMap, time::SystemTime};
use tracing::debug;

// TODO: move to config
const PROPOSAL_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_PROPOSAL_";
const VOTE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_VOTE_";
const FINALIZE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_FINALIZE_";

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
        }
    }

    pub fn propose(&mut self, proposal: wire::Proposal) -> Option<wire::Vote> {
        // Ensure we are in the right view to process this message
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
        let signature = match proposal.signature {
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
        if !C::verify(
            PROPOSAL_NAMESPACE,
            &Vec::new(),
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

        // TODO: Check to see if compatible with notarized tip

        // TODO: verify the proposal

        None
    }

    pub fn vote(vote: wire::Vote) -> Option<wire::Notarization> {
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
