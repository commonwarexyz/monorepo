use crate::{
    threshold_simplex::types::{
        Activity, Attributable, ConflictingFinalize, ConflictingNotarize, Finalization, Finalize,
        Notarization, Notarize, Nullification, Nullify, NullifyFinalize, Seed, Seedable, View,
        Viewable,
    },
    Monitor, Reporter, Supervisor as Su, ThresholdSupervisor as TSu,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    bls12381::primitives::{
        group,
        poly::{self, public},
    },
    Digest,
};
use commonware_utils::{modulo, Array};
use futures::channel::mpsc::{Receiver, Sender};
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

    namespace: Vec<u8>,

    pub leaders: Arc<Mutex<HashMap<View, P>>>,
    pub seeds: Arc<Mutex<HashMap<View, Seed>>>,
    pub notarizes: Arc<Mutex<Participation<D, P>>>,
    pub notarizations: Arc<Mutex<HashMap<View, Notarization<D>>>>,
    pub nullifies: Arc<Mutex<HashMap<View, HashSet<P>>>>,
    pub nullifications: Arc<Mutex<HashMap<View, Nullification>>>,
    pub finalizes: Arc<Mutex<Participation<D, P>>>,
    pub finalizations: Arc<Mutex<HashMap<View, Finalization<D>>>>,
    pub faults: Arc<Mutex<Faults<D, P>>>,

    latest: Arc<Mutex<View>>,
    subscribers: Arc<Mutex<Vec<Sender<View>>>>,
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
            namespace: cfg.namespace,
            leaders: Arc::new(Mutex::new(HashMap::new())),
            seeds: Arc::new(Mutex::new(HashMap::new())),
            notarizes: Arc::new(Mutex::new(HashMap::new())),
            notarizations: Arc::new(Mutex::new(HashMap::new())),
            nullifies: Arc::new(Mutex::new(HashMap::new())),
            nullifications: Arc::new(Mutex::new(HashMap::new())),
            finalizes: Arc::new(Mutex::new(HashMap::new())),
            finalizations: Arc::new(Mutex::new(HashMap::new())),
            faults: Arc::new(Mutex::new(HashMap::new())),
            latest: Arc::new(Mutex::new(0)),
            subscribers: Arc::new(Mutex::new(Vec::new())),
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
        let seed = seed.encode();
        let leader_index = modulo(&seed, closest.len() as u64);
        let leader = closest[leader_index as usize].clone();
        self.leaders
            .lock()
            .unwrap()
            .entry(index)
            .or_insert(leader.clone());
        Some(leader)
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

    async fn report(&mut self, activity: Self::Activity) {
        // We check signatures for all messages to ensure that the prover is working correctly
        // but in production this isn't necessary (as signatures are already verified in
        // consensus).
        match activity {
            Activity::Notarize(notarize) => {
                let view = notarize.view();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                if !notarize.verify(&self.namespace, identity) {
                    panic!("signature verification failed");
                }
                let encoded = notarize.encode();
                Notarize::<D>::decode(encoded).unwrap();
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
            Activity::Notarization(notarization) => {
                let view = notarization.view();
                let (identity, _) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                let public = public(identity);

                // Verify notarization
                let seed = notarization.seed();
                if !notarization.verify(&self.namespace, public) {
                    panic!("signature verification failed");
                }
                let encoded = notarization.encode();
                Notarization::<D>::decode(encoded).unwrap();
                self.notarizations
                    .lock()
                    .unwrap()
                    .insert(view, notarization);

                // Verify seed
                if !seed.verify(&self.namespace, public) {
                    panic!("signature verification failed");
                }
                let encoded = seed.encode();
                Seed::decode(encoded).unwrap();
                self.seeds.lock().unwrap().insert(view, seed);
            }
            Activity::Nullify(nullify) => {
                let view = nullify.view();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                if !nullify.verify(&self.namespace, identity) {
                    panic!("signature verification failed");
                }
                let encoded = nullify.encode();
                Nullify::decode(encoded).unwrap();
                let public_key = validators[nullify.signer() as usize].clone();
                self.nullifies
                    .lock()
                    .unwrap()
                    .entry(view)
                    .or_default()
                    .insert(public_key);
            }
            Activity::Nullification(nullification) => {
                let view = nullification.view();
                let (identity, _) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                let public = public(identity);

                // Verify nullification
                let seed = nullification.seed();
                if !nullification.verify(&self.namespace, public) {
                    panic!("signature verification failed");
                }
                let encoded = nullification.encode();
                Nullification::decode(encoded).unwrap();
                self.nullifications
                    .lock()
                    .unwrap()
                    .insert(view, nullification);

                // Verify seed
                if !seed.verify(&self.namespace, public) {
                    panic!("signature verification failed");
                }
                let encoded = seed.encode();
                Seed::decode(encoded).unwrap();
                self.seeds.lock().unwrap().insert(view, seed);
            }
            Activity::Finalize(finalize) => {
                let view = finalize.view();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                if !finalize.verify(&self.namespace, identity) {
                    panic!("signature verification failed");
                }
                let encoded = finalize.encode();
                Finalize::<D>::decode(encoded).unwrap();
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
            Activity::Finalization(ref finalization) => {
                let view = finalization.view();
                let (identity, _) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                let public = public(identity);

                // Verify finalization
                let seed = finalization.seed();
                if !finalization.verify(&self.namespace, public) {
                    panic!("signature verification failed");
                }
                let encoded = finalization.encode();
                Finalization::<D>::decode(encoded).unwrap();
                self.finalizations
                    .lock()
                    .unwrap()
                    .insert(view, finalization.clone());

                // Verify seed
                if !seed.verify(&self.namespace, public) {
                    panic!("signature verification failed");
                }
                let encoded = seed.encode();
                Seed::decode(encoded).unwrap();
                self.seeds.lock().unwrap().insert(view, seed);

                // Send message to subscribers
                *self.latest.lock().unwrap() = finalization.view();
                let mut subscribers = self.subscribers.lock().unwrap();
                for subscriber in subscribers.iter_mut() {
                    let _ = subscriber.try_send(finalization.view());
                }
            }
            Activity::ConflictingNotarize(ref conflicting) => {
                let view = conflicting.view();
                let (identity, validators) = match self.participants.range(..=view).next_back() {
                    Some((_, (p, _, v, _))) => (p, v),
                    None => {
                        panic!("no participants in required range");
                    }
                };
                if !conflicting.verify(&self.namespace, identity) {
                    panic!("signature verification failed");
                }
                let encoded = conflicting.encode();
                ConflictingNotarize::<D>::decode(encoded).unwrap();
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
                if !conflicting.verify(&self.namespace, identity) {
                    panic!("signature verification failed");
                }
                let encoded = conflicting.encode();
                ConflictingFinalize::<D>::decode(encoded).unwrap();
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
                if !nullify_finalize.verify(&self.namespace, identity) {
                    panic!("signature verification failed");
                }
                let encoded = nullify_finalize.encode();
                NullifyFinalize::<D>::decode(encoded).unwrap();
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
        }
    }
}

impl<P: Array, D: Digest> Monitor for Supervisor<P, D> {
    type Index = View;
    async fn subscribe(&mut self) -> (Self::Index, Receiver<Self::Index>) {
        let (tx, rx) = futures::channel::mpsc::channel(128);
        self.subscribers.lock().unwrap().push(tx);
        let latest = *self.latest.lock().unwrap();
        (latest, rx)
    }
}
