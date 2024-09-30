use super::wire;
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use std::{collections::HashMap, time::SystemTime};

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

pub struct Store {
    pub view: u64,
    pub views: HashMap<u64, View>,
}

impl Store {
    pub fn new() -> Self {
        Self {
            view: 0,
            views: HashMap::new(),
        }
    }

    pub fn 
}
