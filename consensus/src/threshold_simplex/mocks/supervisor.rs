use crate::{
    threshold_simplex::types::{
        finalize_namespace, notarize_namespace, nullify_namespace, seed_namespace, Activity, View,
    },
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

pub struct Config<P: Array> {
    pub namespace: Vec<u8>,
    pub participants: BTreeMap<View, (poly::Poly<group::Public>, Vec<P>, group::Share)>,
}

type Participation<D, P> = HashMap<View, HashMap<D, HashSet<P>>>;
type Faults<D, P> = HashMap<P, HashMap<View, HashSet<Activity<D>>>>;

#[derive(Clone)]
pub struct Supervisor<P: Array, D: Digest> {
    participants: BTreeMap<View, ViewInfo<P>>,

    seed_namespace: Vec<u8>,
    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    pub notarizes: Arc<Mutex<Participation<D, P>>>,
    pub finalizes: Arc<Mutex<Participation<D, P>>>,
    pub faults: Arc<Mutex<Faults<D, P>>>,
}

impl<P: Array, D: Digest> Supervisor<P, D> {
    pub fn new(cfg: Config<P>) -> Self {
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
            seed_namespace: seed_namespace(&cfg.namespace),
            notarize_namespace: notarize_namespace(&cfg.namespace),
            nullify_namespace: nullify_namespace(&cfg.namespace),
            finalize_namespace: finalize_namespace(&cfg.namespace),
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

impl<P: Array, D: Digest> Reporter for Supervisor<P, D> {
    type Activity = Activity<D>;

    async fn report(&self, activity: Self::Activity) {
        // TODO: restore comment about verifying signatures
        match activity {
            Activity::Notarize(notarize) => {
                let view = notarize.view();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                if !notarize.verify(
                    identity,
                    None,
                    &self.notarize_namespace,
                    &self.seed_namespace,
                ) {
                    panic!("signature verification failed");
                }
                let public_key = validators[notarize.signer() as usize].clone();
                self.notarizes
                    .lock()
                    .unwrap()
                    .entry(view)
                    .or_default()
                    .entry(notarize.proposal.payload)
                    .or_default()
                    .insert(public_key);
            }
            Activity::Finalize(finalize) => {
                let view = finalize.view();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                if !finalize.verify(identity, None, &self.finalize_namespace) {
                    panic!("signature verification failed");
                }
                let public_key = validators[finalize.signer() as usize].clone();
                self.finalizes
                    .lock()
                    .unwrap()
                    .entry(view)
                    .or_default()
                    .entry(finalize.proposal.payload)
                    .or_default()
                    .insert(public_key);
            }
            Activity::ConflictingNotarize(ref conflicting) => {
                let view = conflicting.view();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                if !conflicting.verify(identity, None, &self.notarize_namespace) {
                    panic!("signature verification failed");
                }
                let public_key = validators[conflicting.signer() as usize].clone();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
            Activity::ConflictingFinalize(ref conflicting) => {
                let view = conflicting.view();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                if !conflicting.verify(identity, None, &self.finalize_namespace) {
                    panic!("signature verification failed");
                }
                let public_key = validators[conflicting.signer() as usize].clone();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
            Activity::NullifyFinalize(ref nullify_finalize) => {
                let view = nullify_finalize.view();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                if !nullify_finalize.verify(
                    identity,
                    None,
                    &self.nullify_namespace,
                    &self.finalize_namespace,
                ) {
                    panic!("signature verification failed");
                }
                let public_key = validators[nullify_finalize.signer() as usize].clone();
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
                panic!("unexpected activity: {:?}", unexpected);
            }
        }
    }
}
