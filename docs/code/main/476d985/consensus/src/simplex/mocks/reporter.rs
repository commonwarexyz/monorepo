//! Mock `Reporter` for tests: tracks participants/leaders, verifies activities,
//! records votes/faults, and exposes a simple subscription.
use crate::{
    simplex::{
        elector::{Config as ElectorConfig, Elector},
        scheme,
        types::{
            Activity, Attributable, ConflictingFinalize, ConflictingNotarize, Finalization,
            Finalize, Notarization, Notarize, Nullification, Nullify, NullifyFinalize, Subject,
        },
    },
    types::{Round, View},
    Monitor, Viewable,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_utils::ordered::{Quorum, Set};
use futures::channel::mpsc::{Receiver, Sender};
use rand::{CryptoRng, Rng};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::{Arc, Mutex},
};

// Records which validators have participated in a given view/payload pair.
type Participation<P, D> = HashMap<View, HashMap<D, HashSet<P>>>;
type Faults<S, D> = HashMap<<S as Scheme>::PublicKey, HashMap<View, HashSet<Activity<S, D>>>>;

/// Reporter configuration used in tests.
#[derive(Clone, Debug)]
pub struct Config<S: Scheme, L: ElectorConfig<S>> {
    pub namespace: Vec<u8>,
    pub participants: Set<S::PublicKey>,
    pub scheme: S,
    pub elector: L,
}

#[derive(Clone)]
pub struct Reporter<E: Rng + CryptoRng, S: Scheme, L: ElectorConfig<S>, D: Digest> {
    context: E,
    pub participants: Set<S::PublicKey>,
    scheme: S,
    elector: L::Elector,

    namespace: Vec<u8>,

    pub leaders: Arc<Mutex<HashMap<View, S::PublicKey>>>,
    pub certified: Arc<Mutex<HashSet<View>>>,
    pub notarizes: Arc<Mutex<Participation<S::PublicKey, D>>>,
    pub notarizations: Arc<Mutex<HashMap<View, Notarization<S, D>>>>,
    pub nullifies: Arc<Mutex<HashMap<View, HashSet<S::PublicKey>>>>,
    pub nullifications: Arc<Mutex<HashMap<View, Nullification<S>>>>,
    pub finalizes: Arc<Mutex<Participation<S::PublicKey, D>>>,
    pub finalizations: Arc<Mutex<HashMap<View, Finalization<S, D>>>>,
    pub faults: Arc<Mutex<Faults<S, D>>>,
    pub invalid: Arc<Mutex<usize>>,

    latest: Arc<Mutex<View>>,
    subscribers: Arc<Mutex<Vec<Sender<View>>>>,
}

impl<E, S, L, D> Reporter<E, S, L, D>
where
    E: Rng + CryptoRng,
    S: Scheme,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
{
    pub fn new(context: E, cfg: Config<S, L>) -> Self {
        // Build elector with participants
        let elector = cfg.elector.build(&cfg.participants);

        Self {
            context,
            namespace: cfg.namespace,
            participants: cfg.participants,
            scheme: cfg.scheme,
            elector,
            leaders: Arc::new(Mutex::new(HashMap::new())),
            certified: Arc::new(Mutex::new(HashSet::new())),
            notarizes: Arc::new(Mutex::new(HashMap::new())),
            notarizations: Arc::new(Mutex::new(HashMap::new())),
            nullifies: Arc::new(Mutex::new(HashMap::new())),
            nullifications: Arc::new(Mutex::new(HashMap::new())),
            finalizes: Arc::new(Mutex::new(HashMap::new())),
            finalizations: Arc::new(Mutex::new(HashMap::new())),
            faults: Arc::new(Mutex::new(HashMap::new())),
            invalid: Arc::new(Mutex::new(0)),
            latest: Arc::new(Mutex::new(View::zero())),
            subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn certified(&self, round: Round, certificate: &S::Certificate) {
        // Record that this view has a certificate
        self.certified.lock().unwrap().insert(round.view());

        // We use the certificate from view N to determine the leader for view N+1.
        let next_round = Round::new(round.epoch(), round.view().next());
        let mut leaders = self.leaders.lock().unwrap();
        leaders.entry(next_round.view()).or_insert_with(|| {
            let leader = self.elector.elect(next_round, Some(certificate));
            self.participants.key(leader).cloned().unwrap()
        });
    }
}

impl<E, S, L, D> crate::Reporter for Reporter<E, S, L, D>
where
    E: Clone + Rng + CryptoRng + Send + Sync + 'static,
    S: scheme::Scheme<D>,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
{
    type Activity = Activity<S, D>;

    async fn report(&mut self, activity: Self::Activity) {
        // We check signatures for all messages to ensure that the prover is working correctly
        // but in production this isn't necessary (as signatures are already verified in
        // consensus).
        let verified = activity.verified();
        match &activity {
            Activity::Notarize(notarize) => {
                if !notarize.verify(&self.scheme, &self.namespace) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = notarize.encode();
                Notarize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants[notarize.signer() as usize].clone();
                self.notarizes
                    .lock()
                    .unwrap()
                    .entry(notarize.view())
                    .or_default()
                    .entry(notarize.proposal.payload)
                    .or_default()
                    .insert(public_key);
            }
            Activity::Notarization(notarization) | Activity::Certification(notarization) => {
                // Verify notarization
                let view = notarization.view();
                if !self.scheme.verify_certificate::<_, D>(
                    &mut self.context,
                    &self.namespace,
                    Subject::Notarize {
                        proposal: &notarization.proposal,
                    },
                    &notarization.certificate,
                ) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = notarization.encode();
                Notarization::<S, D>::decode_cfg(encoded, &self.scheme.certificate_codec_config())
                    .unwrap();
                self.notarizations
                    .lock()
                    .unwrap()
                    .insert(view, notarization.clone());
                self.certified(notarization.round(), &notarization.certificate);
            }
            Activity::Nullify(nullify) => {
                if !nullify.verify(&self.scheme, &self.namespace) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = nullify.encode();
                Nullify::<S>::decode(encoded).unwrap();
                let public_key = self.participants[nullify.signer() as usize].clone();
                self.nullifies
                    .lock()
                    .unwrap()
                    .entry(nullify.view())
                    .or_default()
                    .insert(public_key);
            }
            Activity::Nullification(nullification) => {
                // Verify nullification
                let view = nullification.view();
                if !self.scheme.verify_certificate::<_, D>(
                    &mut self.context,
                    &self.namespace,
                    Subject::Nullify {
                        round: nullification.round,
                    },
                    &nullification.certificate,
                ) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = nullification.encode();
                Nullification::<S>::decode_cfg(encoded, &self.scheme.certificate_codec_config())
                    .unwrap();
                self.nullifications
                    .lock()
                    .unwrap()
                    .insert(view, nullification.clone());
                self.certified(nullification.round, &nullification.certificate);
            }
            Activity::Finalize(finalize) => {
                if !finalize.verify(&self.scheme, &self.namespace) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = finalize.encode();
                Finalize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants[finalize.signer() as usize].clone();
                self.finalizes
                    .lock()
                    .unwrap()
                    .entry(finalize.view())
                    .or_default()
                    .entry(finalize.proposal.payload)
                    .or_default()
                    .insert(public_key);
            }
            Activity::Finalization(finalization) => {
                // Verify finalization
                let view = finalization.view();
                if !self.scheme.verify_certificate::<_, D>(
                    &mut self.context,
                    &self.namespace,
                    Subject::Finalize {
                        proposal: &finalization.proposal,
                    },
                    &finalization.certificate,
                ) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = finalization.encode();
                Finalization::<S, D>::decode_cfg(encoded, &self.scheme.certificate_codec_config())
                    .unwrap();
                self.finalizations
                    .lock()
                    .unwrap()
                    .insert(view, finalization.clone());
                self.certified(finalization.round(), &finalization.certificate);

                // Send message to subscribers
                *self.latest.lock().unwrap() = finalization.view();
                let mut subscribers = self.subscribers.lock().unwrap();
                for subscriber in subscribers.iter_mut() {
                    let _ = subscriber.try_send(finalization.view());
                }
            }
            Activity::ConflictingNotarize(conflicting) => {
                let view = conflicting.view();
                if !conflicting.verify(&self.scheme, &self.namespace) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = conflicting.encode();
                ConflictingNotarize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants[conflicting.signer() as usize].clone();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
            Activity::ConflictingFinalize(conflicting) => {
                let view = conflicting.view();
                if !conflicting.verify(&self.scheme, &self.namespace) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = conflicting.encode();
                ConflictingFinalize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants[conflicting.signer() as usize].clone();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
            Activity::NullifyFinalize(conflicting) => {
                let view = conflicting.view();
                if !conflicting.verify(&self.scheme, &self.namespace) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = conflicting.encode();
                NullifyFinalize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants[conflicting.signer() as usize].clone();
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

impl<E, S, L, D> Monitor for Reporter<E, S, L, D>
where
    E: Clone + Rng + CryptoRng + Send + Sync + 'static,
    S: Scheme,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
{
    type Index = View;

    async fn subscribe(&mut self) -> (Self::Index, Receiver<Self::Index>) {
        let (tx, rx) = futures::channel::mpsc::channel(128);
        self.subscribers.lock().unwrap().push(tx);
        let latest = *self.latest.lock().unwrap();
        (latest, rx)
    }
}
