use crate::{
    simplex::{
        Prover, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE, NOTARIZE,
        NULLIFY_AND_FINALIZE,
    },
    Activity, Proof, Supervisor as Su, ThresholdSupervisor as TSu,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        poly,
    },
    Digest, Hasher, PublicKey,
};
use commonware_utils::modulo;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};

type ViewInfo = (
    poly::Poly<group::Public>,
    HashMap<PublicKey, u32>,
    Vec<PublicKey>,
    group::Share,
);

pub struct Config<H: Hasher> {
    pub prover: Prover<H>,
    pub participants: BTreeMap<View, (poly::Poly<group::Public>, Vec<PublicKey>, group::Share)>,
}

type Participation = HashMap<View, HashMap<Digest, HashSet<PublicKey>>>;
type Faults = HashMap<PublicKey, HashMap<View, HashSet<Activity>>>;

#[derive(Clone)]
pub struct Supervisor<H: Hasher> {
    prover: Prover<H>,
    participants: BTreeMap<View, ViewInfo>,

    pub notarizes: Arc<Mutex<Participation>>,
    pub finalizes: Arc<Mutex<Participation>>,
    pub faults: Arc<Mutex<Faults>>,
}

impl<H: Hasher> Supervisor<H> {
    pub fn new(cfg: Config<H>) -> Self {
        let mut parsed_participants = BTreeMap::new();
        for (view, (identity, mut validators, share)) in cfg.participants.into_iter() {
            let mut map = HashMap::new();
            for (index, validator) in validators.iter().enumerate() {
                map.insert(validator.clone(), index as u32);
            }
            validators.sort();
            parsed_participants.insert(view, (identity, map, validators, share));
        }
        Self {
            prover: cfg.prover,
            participants: parsed_participants,
            notarizes: Arc::new(Mutex::new(HashMap::new())),
            finalizes: Arc::new(Mutex::new(HashMap::new())),
            faults: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<H: Hasher> Su for Supervisor<H> {
    type Index = View;

    fn leader(&self, _: Self::Index) -> Option<PublicKey> {
        unimplemented!("only defined in supertrait")
    }

    fn participants(&self, index: Self::Index) -> Option<&Vec<PublicKey>> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (_, _, p, _))) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(closest)
    }

    fn is_participant(&self, index: Self::Index, candidate: &PublicKey) -> Option<u32> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (_, p, _, _))) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        closest.get(candidate).cloned()
    }

    async fn report(&self, activity: Activity, proof: Proof) {
        // We check signatures for all messages to ensure that the prover is working correctly
        // but in production this isn't necessary (as signatures are already verified in
        // consensus).
        match activity {
            NOTARIZE => {
                let (view, _, payload, verifier) = self.prover.deserialize_notarize(proof).unwrap();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                let public_key_index = verifier.verify(identity).unwrap();
                let public_key = validators[public_key_index as usize].clone();
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
                let (view, _, payload, verifier) = self.prover.deserialize_finalize(proof).unwrap();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                let public_key_index = verifier.verify(identity).unwrap();
                let public_key = validators[public_key_index as usize].clone();
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
                let (view, verifier) = self.prover.deserialize_conflicting_notarize(proof).unwrap();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                let public_key_index = verifier.verify(identity).unwrap();
                let public_key = validators[public_key_index as usize].clone();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
            CONFLICTING_FINALIZE => {
                let (view, verifier) = self.prover.deserialize_conflicting_finalize(proof).unwrap();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                let public_key_index = verifier.verify(identity).unwrap();
                let public_key = validators[public_key_index as usize].clone();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
            NULLIFY_AND_FINALIZE => {
                let (view, verifier) = self.prover.deserialize_nullify_finalize(proof).unwrap();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                let public_key_index = verifier.verify(identity).unwrap();
                let public_key = validators[public_key_index as usize].clone();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
            unexpected => {
                panic!("unexpected activity: {}", unexpected);
            }
        }
    }
}

impl<H: Hasher> TSu for Supervisor<H> {
    type Seed = group::Signature;
    type Identity = poly::Public;
    type Share = group::Share;

    fn leader(&self, seed: Self::Seed, index: Self::Index) -> Option<PublicKey> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (_, _, p, _))) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        let seed = seed.serialize();
        let index = modulo(&seed, closest.len() as u64);
        Some(closest[index as usize].clone())
    }

    fn identity(&self, index: Self::Index) -> Option<&Self::Identity> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (p, _, _, _))) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(closest)
    }

    fn share(&self, index: Self::Index) -> Option<&Self::Share> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (_, _, _, s))) => s,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(closest)
    }
}
