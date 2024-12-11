use crate::{
    simplex::{
        prover::Prover, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE, NOTARIZE,
        NULLIFY_AND_FINALIZE,
    },
    Activity, Proof, Supervisor as Su,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};

pub struct Config<C: Scheme, H: Hasher> {
    pub prover: Prover<C, H>,
    pub participants: BTreeMap<View, Vec<PublicKey>>,
}

type Participation = HashMap<View, HashMap<Digest, HashSet<PublicKey>>>;
type Faults = HashMap<PublicKey, HashMap<View, HashSet<Activity>>>;

#[derive(Clone)]
pub struct Supervisor<C: Scheme, H: Hasher> {
    participants: BTreeMap<View, (HashMap<PublicKey, u32>, Vec<PublicKey>)>,

    prover: Prover<C, H>,

    pub notarizes: Arc<Mutex<Participation>>,
    pub finalizes: Arc<Mutex<Participation>>,
    pub faults: Arc<Mutex<Faults>>,
}

impl<C: Scheme, H: Hasher> Supervisor<C, H> {
    pub fn new(cfg: Config<C, H>) -> Self {
        let mut parsed_participants = BTreeMap::new();
        for (view, mut validators) in cfg.participants.into_iter() {
            let mut map = HashMap::new();
            for (index, validator) in validators.iter().enumerate() {
                map.insert(validator.clone(), index as u32);
            }
            validators.sort();
            parsed_participants.insert(view, (map, validators));
        }
        Self {
            participants: parsed_participants,
            prover: cfg.prover,
            notarizes: Arc::new(Mutex::new(HashMap::new())),
            finalizes: Arc::new(Mutex::new(HashMap::new())),
            faults: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<C: Scheme, H: Hasher> Su for Supervisor<C, H> {
    type Index = View;
    type Seed = ();

    fn leader(&self, index: Self::Index, _seed: Self::Seed) -> Option<PublicKey> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, p)) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(closest.1[index as usize % closest.1.len()].clone())
    }

    fn participants(&self, index: Self::Index) -> Option<&Vec<PublicKey>> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, p)) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(&closest.1)
    }

    fn is_participant(&self, index: Self::Index, candidate: &PublicKey) -> Option<u32> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, p)) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        closest.0.get(candidate).cloned()
    }

    async fn report(&self, activity: Activity, proof: Proof) {
        // We check signatures for all messages to ensure that the prover is working correctly
        // but in production this isn't necessary (as signatures are already verified in
        // consensus).
        match activity {
            NOTARIZE => {
                let (view, _, payload, public_key) =
                    self.prover.deserialize_notarize(proof, true).unwrap();
                self.notarizes
                    .lock()
                    .unwrap()
                    .entry(view)
                    .or_default()
                    .entry(payload)
                    .or_default()
                    .insert(public_key);
            }
            FINALIZE => {
                let (view, _, payload, public_key) =
                    self.prover.deserialize_finalize(proof, true).unwrap();
                self.finalizes
                    .lock()
                    .unwrap()
                    .entry(view)
                    .or_default()
                    .entry(payload)
                    .or_default()
                    .insert(public_key);
            }
            CONFLICTING_NOTARIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_conflicting_notarize(proof, true)
                    .unwrap();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(CONFLICTING_NOTARIZE);
            }
            CONFLICTING_FINALIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_conflicting_finalize(proof, true)
                    .unwrap();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(CONFLICTING_FINALIZE);
            }
            NULLIFY_AND_FINALIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_nullify_finalize(proof, true)
                    .unwrap();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(NULLIFY_AND_FINALIZE);
            }
            unexpected => {
                panic!("unexpected activity: {}", unexpected);
            }
        }
    }
}
