use crate::{
    simplex::types::{
        finalize_namespace, notarize_namespace, nullify_namespace, Activity, Attributable,
        Finalization, Notarization, Nullification, View, Viewable,
    },
    Monitor, Reporter, Supervisor as Su,
};
use commonware_cryptography::{Digest, Verifier};
use futures::channel::mpsc::{Receiver, Sender};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};

pub struct Config<C: Verifier> {
    pub namespace: Vec<u8>,
    pub participants: BTreeMap<View, Vec<C::PublicKey>>,
}

type Participation<P, D> = HashMap<View, HashMap<D, HashSet<P>>>;
type Faults<P, S, D> = HashMap<P, HashMap<View, HashSet<Activity<S, D>>>>;
type Participants<P> = BTreeMap<View, (HashMap<P, u32>, Vec<P>)>;

#[derive(Clone)]
pub struct Supervisor<C: Verifier, D: Digest> {
    participants: Participants<C::PublicKey>,

    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    pub notarizes: Arc<Mutex<Participation<C::PublicKey, D>>>,
    pub notarizations: Arc<Mutex<HashMap<View, Notarization<C::Signature, D>>>>,
    pub nullifies: Arc<Mutex<HashMap<View, HashSet<C::PublicKey>>>>,
    pub nullifications: Arc<Mutex<HashMap<View, Nullification<C::Signature>>>>,
    pub finalizes: Arc<Mutex<Participation<C::PublicKey,D >>>,
    pub finalizations: Arc<Mutex<HashMap<View, Finalization<C::Signature, D>>>>,
    pub faults: Arc<Mutex<Faults<C::PublicKey, C::Signature, D>>>,

    latest: Arc<Mutex<View>>,
    subscribers: Arc<Mutex<Vec<Sender<View>>>>,
}

impl<C: Verifier, D: Digest> Supervisor<C, D> {
    pub fn new(cfg: Config<C>) -> Self {
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
            notarize_namespace: notarize_namespace(&cfg.namespace),
            nullify_namespace: nullify_namespace(&cfg.namespace),
            finalize_namespace: finalize_namespace(&cfg.namespace),
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

impl<C: Verifier, D: Digest> Su for Supervisor<C, D> {
    type Index = View;
    type PublicKey = C::PublicKey;

    fn leader(&self, index: Self::Index) -> Option<Self::PublicKey> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, p)) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(closest.1[index as usize % closest.1.len()].clone())
    }

    fn participants(&self, index: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, p)) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(&closest.1)
    }

    fn is_participant(&self, index: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, p)) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        closest.0.get(candidate).cloned()
    }
}

impl<C: Verifier, D: Digest> Reporter for Supervisor<C, D> {
    type Activity = Activity<C::Signature, D>;

    async fn report(&mut self, activity: Activity<C::Signature, D>) {
        // We check signatures for all messages to ensure that the prover is working correctly
        // but in production this isn't necessary (as signatures are already verified in
        // consensus).
        match activity {
            Activity::Notarize(notarize) => {
                let view = notarize.view();
                let participants = self.participants(view).unwrap();
                let public_key = participants[notarize.signer() as usize].clone();
                if !notarize.verify::<C::PublicKey, C>(&public_key, &self.notarize_namespace) {
                    panic!("signature verification failed");
                }
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
                if !notarization.verify::<_, C>(self, &self.notarize_namespace) {
                    panic!("signature verification failed");
                }
                let participants = self.participants(view).unwrap();
                let mut notarizes = self.notarizes.lock().unwrap();
                let notarizes = notarizes
                    .entry(view)
                    .or_default()
                    .entry(notarization.proposal.payload)
                    .or_default();
                for signature in &notarization.signatures {
                    let public_key_index = signature.signer() as usize;
                    let public_key = participants[public_key_index].clone();
                    notarizes.insert(public_key);
                }
                self.notarizations
                    .lock()
                    .unwrap()
                    .insert(view, notarization);
            }
            Activity::Nullify(nullify) => {
                let view = nullify.view();
                let participants = self.participants(view).unwrap();
                let public_key = participants[nullify.signer() as usize].clone();
                if !nullify.verify::<C::PublicKey, C>(&public_key, &self.nullify_namespace) {
                    panic!("signature verification failed");
                }
                self.nullifies
                    .lock()
                    .unwrap()
                    .entry(view)
                    .or_default()
                    .insert(public_key);
            }
            Activity::Nullification(nullification) => {
                let view = nullification.view();
                if !nullification.verify::<_, C>(self, &self.nullify_namespace) {
                    panic!("signature verification failed");
                }
                let participants = self.participants(view).unwrap();
                let mut nullifies = self.nullifies.lock().unwrap();
                let nullifies = nullifies.entry(view).or_default();
                for signature in &nullification.signatures {
                    let public_key_index = signature.signer() as usize;
                    let public_key = participants[public_key_index].clone();
                    nullifies.insert(public_key);
                }
                self.nullifications
                    .lock()
                    .unwrap()
                    .insert(view, nullification);
            }
            Activity::Finalize(finalize) => {
                let view = finalize.view();
                let participants = self.participants(view).unwrap();
                let public_key = participants[finalize.signer() as usize].clone();
                if !finalize.verify::<C::PublicKey, C>(&public_key, &self.finalize_namespace) {
                    panic!("signature verification failed");
                }
                self.finalizes
                    .lock()
                    .unwrap()
                    .entry(view)
                    .or_default()
                    .entry(finalize.proposal.payload)
                    .or_default()
                    .insert(public_key);
            }
            Activity::Finalization(finalization) => {
                let view = finalization.view();
                if !finalization.verify::<_, C>(self, &self.finalize_namespace) {
                    panic!("signature verification failed");
                }
                let participants = self.participants(view).unwrap();
                let mut finalizes = self.finalizes.lock().unwrap();
                let finalizes = finalizes
                    .entry(view)
                    .or_default()
                    .entry(finalization.proposal.payload)
                    .or_default();
                for signature in &finalization.signatures {
                    let public_key_index = signature.signer() as usize;
                    let public_key = participants[public_key_index].clone();
                    finalizes.insert(public_key);
                }
                self.finalizations
                    .lock()
                    .unwrap()
                    .insert(view, finalization);
            }
            Activity::ConflictingNotarize(ref conflicting) => {
                let view = conflicting.view();
                let participants = self.participants(view).unwrap();
                let public_key = participants[conflicting.signer() as usize].clone();
                if !conflicting.verify::<C::PublicKey, C>(&public_key, &self.notarize_namespace) {
                    panic!("signature verification failed");
                }
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
                let participants = self.participants(view).unwrap();
                let public_key = participants[conflicting.signer() as usize].clone();
                if !conflicting.verify::<C::PublicKey, C>(&public_key, &self.finalize_namespace) {
                    panic!("signature verification failed");
                }
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
            Activity::NullifyFinalize(ref conflicting) => {
                let view = conflicting.view();
                let participants = self.participants(view).unwrap();
                let public_key = participants[conflicting.signer() as usize].clone();
                if !conflicting.verify::<C::PublicKey, C>(
                    &public_key,
                    &self.nullify_namespace,
                    &self.finalize_namespace,
                ) {
                    panic!("signature verification failed");
                }
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

impl<C: Verifier, D: Digest> Monitor for Supervisor<C, D> {
    type Index = View;
    async fn subscribe(&mut self) -> (Self::Index, Receiver<Self::Index>) {
        let (sender, receiver) = futures::channel::mpsc::channel(128);
        self.subscribers.lock().unwrap().push(sender);
        let latest = *self.latest.lock().unwrap();
        (latest, receiver)
    }
}
