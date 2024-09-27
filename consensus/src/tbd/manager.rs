use super::{config::Config, wire};
use bytes::Bytes;
use commonware_cryptography::{PublicKey, Signature};
use commonware_runtime::Clock;
use std::{collections::HashMap, time::SystemTime};

type View = (u64, u64);

struct Info {
    leader_deadline: SystemTime,
    advance_deadline: SystemTime,

    proposal: Option<wire::Proposal>,
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

    pub fn start(&mut self, epoch: u64, view: u64) {
        let now = self.runtime.current();
        let leader_deadline = now + self.cfg.leader_timeout;
        let advance_deadline = now + self.cfg.advance_timeout;
        let view = (epoch, view);
        self.rounds.insert(
            view,
            Info {
                leader_deadline,
                advance_deadline,
            },
        );
    }
    pub fn vote(&mut self, epoch: u64, view: u64, public_key: PublicKey, signature: Signature) {}
}
