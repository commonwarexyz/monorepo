use super::{config::Config, wire};
use bytes::Bytes;
use commonware_cryptography::{PublicKey, Signature};
use commonware_runtime::Clock;
use std::{collections::HashMap, time::SystemTime};

type View = (u64, u64);

struct Info {
    leader_deadline: SystemTime,
    advance_deadline: SystemTime,

    proposal: Option<(Bytes, wire::Proposal)>,
    // other_proposals: HashMap<Bytes, wire::Proposal>, // Faults (TODO: this is an OOM if we aren't careful -> should just store info needed to post a complaint)
    proposal_votes: HashMap<PublicKey, Signature>,
    // other_votes: HashMap<PublicKey, Signature>, // Faults
    proposal_notarization: Option<Bytes>,

    null_votes: HashMap<PublicKey, Signature>,
    null_notarization: Option<Bytes>,

    seeds: HashMap<PublicKey, Signature>,
    beacon: Option<Bytes>,

    finalizes: HashMap<PublicKey, Signature>,
    finalization: Option<Bytes>,
}

impl Info {
    fn new(leader_deadline: SystemTime, advance_deadline: SystemTime) -> Self {
        Self {
            leader_deadline,
            advance_deadline,

            proposal: None,
            proposal_votes: HashMap::new(),
            proposal_notarization: None,

            null_votes: HashMap::new(),
            null_notarization: None,

            seeds: HashMap::new(),
            beacon: None,

            finalizes: HashMap::new(),
            finalization: None,
        }
    }
}

pub struct Manager<E: Clock> {
    cfg: Config,
    runtime: E,
    rounds: HashMap<View, Info>,
}

impl<E: Clock> Manager<E> {
    pub fn init(cfg: Config, runtime: E) -> Self {
        Self {
            cfg,
            runtime,
            rounds: HashMap::new(),
        }
    }

    pub fn start_epoch(&mut self, participants: Vec<PublicKey>) {
        // TODO: create a Resharing arbiter to handle key management (wait for
        // commitments up to some view, acks to some view, etc)
    }

    pub fn start_view(&mut self, epoch: u64, view: u64) {
        let now = self.runtime.current();
        let leader_deadline = now + self.cfg.leader_timeout;
        let advance_deadline = now + self.cfg.advance_timeout;
        let view = (epoch, view);
        self.rounds
            .insert(view, Info::new(leader_deadline, advance_deadline));
    }

    pub fn vote(
        &mut self,
        epoch: u64,
        view: u64,
        block: Bytes, // hash
        public_key: PublicKey,
        signature: Signature,
    ) -> Option<Bytes> {
        // Get view info
        let view = (epoch, view);
        let info = match self.rounds.get_mut(&view) {
            Some(info) => info,
            None => {
                // If we have yet to start a given view, ignore the vote.
                //
                // If we tried to track arbitrary future votes, it would
                // be trivial for a peer to OOM us.
                //
                // TODO: consider being a bit more flexible here and allow
                // vote collection for next view.
                return None;
            }
        };

        // Get proposal info
        let (hash, proposal) = match &info.proposal {
            Some(proposal) => proposal,
            None => {
                // If we have yet to receive a proposal, ignore the vote.
                return None;
            }
        };

        // If vote is for the proposal, store it.
        if hash == &block {
            info.proposal_votes.insert(public_key, signature);
        } else if block.len() == 0 {
            info.null_votes.insert(public_key, signature);
        } else {
            // This vote is for a different proposal than what we have,
            // this means either the proposer sent conflicting blocks
            // or the voter is malicious.
            return None;
        }

        // If we already have a notarization, we are done.
        if info.proposal_notarization.is_some() || info.null_notarization.is_some() {
            return None;
        }

        // If we have threshold votes, generate notarization and return.
        if info.proposal_votes.len() >= self.cfg.threshold {
        } else if info.null_votes.len() >= self.cfg.threshold {
        }

        // Maybe next time
        None
    }

    pub fn seed(
        &mut self,
        epoch: u64,
        view: u64,
        public_key: PublicKey,
        signature: Signature,
    ) -> Option<Bytes> {
        // Get view info
        let view = (epoch, view);
        let info = match self.rounds.get_mut(&view) {
            Some(info) => info,
            None => return None,
        };

        // Store seed
        info.seeds.insert(public_key, signature);

        // If we have already generated a beacon, we are done.
        if info.beacon.is_some() {
            return None;
        }

        // If we have threshold seeds, generate beacon and return.
        if info.seeds.len() >= self.cfg.threshold {}

        // Maybe next time
        None
    }

    pub fn finalize(
        &mut self,
        epoch: u64,
        view: u64,
        public_key: PublicKey,
        signature: Signature,
    ) -> Option<Bytes> {
        // Get view info
        let view = (epoch, view);
        let info = match self.rounds.get_mut(&view) {
            Some(info) => info,
            None => return None,
        };

        // Store finalization
        info.finalizes.insert(public_key, signature);

        // If we have already generated a finalization, we are done.
        if info.finalization.is_some() {
            return None;
        }

        // If we have threshold finalizations, generate finalization and return.
        if info.finalizes.len() >= self.cfg.threshold {
            // TODO: apply DKG/Resharing from ancestry to arbiter
            // TODO: fetch missing blocks from ancestry
        }

        // Maybe next time
        None
    }
}
