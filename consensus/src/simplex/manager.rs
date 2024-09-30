use super::wire;
use bytes::Bytes;
use commonware_cryptography::{PublicKey, Signature};
use commonware_runtime::Clock;
use std::{collections::HashMap, time::SystemTime};
use tracing::debug;

pub struct View {
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
    pub fn new(leader_deadline: SystemTime, notarization_deadline: SystemTime) -> Self {
        Self {
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

pub struct Store<E: Clock> {
    runtime: E,

    validators: Vec<PublicKey>,
    validators_ordered: HashMap<PublicKey, u32>,

    view: u64,
    views: HashMap<u64, View>,
}

impl<E: Clock> Store<E> {
    pub fn new(runtime: E, mut validators: Vec<PublicKey>) -> Self {
        // Initialize ordered validators
        validators.sort();
        let mut validators_ordered = HashMap::new();
        for (i, validator) in validators.iter().enumerate() {
            validators_ordered.insert(validator.clone(), i as u32);
        }

        // Initialize store
        Self {
            runtime,

            validators,
            validators_ordered,

            view: 0,
            views: HashMap::new(),
        }
    }

    pub fn propose(&self, proposal: wire::Proposal) -> Option<wire::Vote> {
        if proposal.view > self.view {
            debug!(view = proposal.view, "dropping proposal");
            return None;
        }
        None
    }

    pub fn vote(vote: wire::Vote) -> Option<wire::Notarization> {
        None
    }

    pub fn notarization(notarization: wire::Notarization) -> Option<wire::Notarization> {
        None
    }

    pub fn finalize(finalize: wire::Finalize) -> Option<wire::Finalization> {
        None
    }

    pub fn finalization(finalization: wire::Finalization) -> Option<wire::Finalization> {
        None
    }
}
