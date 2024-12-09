use commonware_consensus::{
    simplex::{
        Prover, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE, NOTARIZE,
        NULLIFY_AND_FINALIZE,
    },
    Activity, Proof, Supervisor as Su,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use std::collections::{HashMap, HashSet};
use tracing::debug;

pub struct Config<C: Scheme, H: Hasher> {
    pub prover: Prover<C, H>,
    pub participants: Vec<PublicKey>,
}

type Participation = HashMap<View, HashMap<Digest, HashSet<PublicKey>>>;
type Faults = HashMap<PublicKey, HashMap<View, HashSet<Activity>>>;

#[derive(Clone)]
pub struct Supervisor<C: Scheme, H: Hasher> {
    participants: Vec<PublicKey>,
    participants_map: HashMap<PublicKey, u32>,

    prover: Prover<C, H>,
}

impl<C: Scheme, H: Hasher> Supervisor<C, H> {
    pub fn new(mut cfg: Config<C, H>) -> Self {
        // Setup participants
        cfg.participants.sort();
        let mut participants_map = HashMap::new();
        for (index, validator) in cfg.participants.iter().enumerate() {
            participants_map.insert(validator.clone(), index as u32);
        }

        // Return supervisor
        Self {
            participants: cfg.participants,
            participants_map,
            prover: cfg.prover,
        }
    }
}

impl<C: Scheme, H: Hasher> Su for Supervisor<C, H> {
    type Index = View;
    type Seed = ();

    fn leader(&self, index: Self::Index, _: Self::Seed) -> Option<PublicKey> {
        Some(self.participants[index as usize % self.participants.len()].clone())
    }

    fn participants(&self, _: Self::Index) -> Option<&Vec<PublicKey>> {
        Some(&self.participants)
    }

    fn is_participant(&self, _: Self::Index, candidate: &PublicKey) -> Option<u32> {
        self.participants_map.get(candidate).cloned()
    }

    async fn report(&self, activity: Activity, proof: Proof) {
        match activity {
            NOTARIZE => {
                let (view, _, payload, public_key) =
                    self.prover.deserialize_notarize(proof, false).unwrap();
                debug!(view, "notarize");
            }
            FINALIZE => {
                let (view, _, payload, public_key) =
                    self.prover.deserialize_finalize(proof, false).unwrap();
                debug!(view, "finalize");
            }
            CONFLICTING_NOTARIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_conflicting_notarize(proof, false)
                    .unwrap();
                debug!(view, "conflicting notarize");
            }
            CONFLICTING_FINALIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_conflicting_finalize(proof, false)
                    .unwrap();
                debug!(view, "conflicting finalize");
            }
            NULLIFY_AND_FINALIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_nullify_finalize(proof, false)
                    .unwrap();
                debug!(view, "nullify and finalize");
            }
            unexpected => {
                panic!("unexpected activity: {}", unexpected);
            }
        }
    }
}
