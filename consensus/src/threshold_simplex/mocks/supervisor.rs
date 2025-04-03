use crate::{
    threshold_simplex::types::{Activity, View},
    Reporter, Supervisor as Su, ThresholdSupervisor as TSu,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        poly,
    },
    Digest,
};
use commonware_utils::{modulo, Array};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};

type ViewInfo<P> = (
    poly::Poly<group::Public>,
    HashMap<P, u32>,
    Vec<P>,
    group::Share,
);

pub struct Config<P: Array, D: Digest> {
    pub participants: BTreeMap<View, (poly::Poly<group::Public>, Vec<P>, group::Share)>,
}

type Participation<D, P> = HashMap<View, HashMap<D, HashSet<P>>>;
type Faults<D, P> = HashMap<P, HashMap<View, HashSet<Activity<D>>>>;

#[derive(Clone)]
pub struct Supervisor<P: Array, D: Digest> {
    participants: BTreeMap<View, ViewInfo<P>>,

    pub notarizes: Arc<Mutex<Participation<D, P>>>,
    pub finalizes: Arc<Mutex<Participation<D, P>>>,
    pub faults: Arc<Mutex<Faults<D, P>>>,
}

impl<P: Array, D: Digest> Supervisor<P, D> {
    pub fn new(cfg: Config<P, D>) -> Self {
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
            participants: parsed_participants,
            notarizes: Arc::new(Mutex::new(HashMap::new())),
            finalizes: Arc::new(Mutex::new(HashMap::new())),
            faults: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<P: Array, D: Digest> Su for Supervisor<P, D> {
    type Index = View;
    type PublicKey = P;

    fn leader(&self, _: Self::Index) -> Option<Self::PublicKey> {
        unimplemented!("only defined in supertrait")
    }

    fn participants(&self, index: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (_, _, p, _))) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(closest)
    }

    fn is_participant(&self, index: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (_, p, _, _))) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        closest.get(candidate).cloned()
    }
}

impl<P: Array, D: Digest> TSu for Supervisor<P, D> {
    type Seed = group::Signature;
    type Identity = poly::Public;
    type Share = group::Share;

    fn leader(&self, index: Self::Index, seed: Self::Seed) -> Option<Self::PublicKey> {
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

impl<D: Digest> Reporter for Supervisor<group::Public, D> {
    type Activity = Activity<D>;

    async fn report(&self, activity: Self::Activity) {
        // We check signatures for all messages to ensure that the prover is working correctly
        // but in production this isn't necessary (as signatures are already verified in
        // consensus).
        match activity {
            Activity::Notarize(notarize) => {
                let (identity, validators) =
                    match self.participants.range(..=notarize.view).next_back() {
                        Some((_, (p, _, v, _))) => (p, v),
                        None => {
                            panic!("no participants in required range");
                        }
                    };
                let public_key = validators[notarize.signer() as usize].clone();
                self.notarizes
                    .lock()
                    .unwrap()
                    .entry(notarize.view)
                    .or_default()
                    .entry(notarize.proposal.payload)
                    .or_default()
                    .insert(public_key);
            }
            Activity::Finalize(finalize) => {
                let (identity, validators) =
                    match self.participants.range(..=finalize.view).next_back() {
                        Some((_, (p, _, v, _))) => (p, v),
                        None => {
                            panic!("no participants in required range");
                        }
                    };
                let public_key = validators[finalize.signer() as usize].clone();
                self.finalizes
                    .lock()
                    .unwrap()
                    .entry(finalize.view)
                    .or_default()
                    .entry(finalize.payload)
                    .or_default()
                    .insert(public_key);
            }
            Activity::ConflictingNotarize(conflicting) => {
                let (identity, validators) =
                    match self.participants.range(..=conflicting.view).next_back() {
                        Some((_, (p, _, v, _))) => (p, v),
                        None => {
                            panic!("no participants in required range");
                        }
                    };
                let public_key = validators[conflicting.signer() as usize].clone();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(conflicting.view)
                    .or_default()
                    .insert(activity);
            }
            Activity::ConflictingFinalize(conflicting) => {
                let (identity, validators) =
                    match self.participants.range(..=conflicting.view).next_back() {
                        Some((_, (p, _, v, _))) => (p, v),
                        None => {
                            panic!("no participants in required range");
                        }
                    };
                let public_key = validators[conflicting.signer() as usize].clone();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(conflicting.view())
                    .or_default()
                    .insert(activity);
            }
            Activity::NullifyFinalize(double) => {
                let (identity, validators) =
                    match self.participants.range(..=double.view()).next_back() {
                        Some((_, (p, _, v, _))) => (p, v),
                        None => {
                            panic!("no participants in required range");
                        }
                    };
                let public_key = validators[double.signer() as usize].clone();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(double.view())
                    .or_default()
                    .insert(activity);
            }
            unexpected => {
                panic!("unexpected activity: {}", unexpected);
            }
        }
    }
}
