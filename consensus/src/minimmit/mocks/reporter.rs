//! Mock `Reporter` for tests: tracks participants/leaders, verifies activities,
//! records votes/faults, and exposes a simple subscription.

use crate::{
    minimmit::{
        elector::{Config as ElectorConfig, Elector},
        scheme,
        types::{
            Activity, Attributable, ConflictingNotarize, Notarization, Notarize, Nullification,
            Nullify, NullifyNotarize,
        },
    },
    types::{Round, View},
    Monitor, Viewable,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::ordered::{Quorum, Set};
use futures::channel::mpsc::{Receiver, Sender};
use rand_core::CryptoRngCore;
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
pub struct Config<S: Scheme, L: ElectorConfig<S>, T: Strategy = Sequential> {
    pub namespace: Vec<u8>,
    pub participants: Set<S::PublicKey>,
    pub scheme: S,
    pub elector: L,
    pub strategy: T,
}

#[derive(Clone)]
pub struct Reporter<E: CryptoRngCore, S: Scheme, L: ElectorConfig<S>, D: Digest, T: Strategy = Sequential> {
    context: E,
    namespace: Vec<u8>,
    pub participants: Set<S::PublicKey>,
    scheme: S,
    elector: L::Elector,
    strategy: T,

    pub leaders: Arc<Mutex<HashMap<View, S::PublicKey>>>,
    pub notarizes: Arc<Mutex<Participation<S::PublicKey, D>>>,
    pub notarizations: Arc<Mutex<HashMap<View, Notarization<S, D>>>>,
    pub nullifies: Arc<Mutex<HashMap<View, HashSet<S::PublicKey>>>>,
    pub nullifications: Arc<Mutex<HashMap<View, Nullification<S>>>>,
    pub faults: Arc<Mutex<Faults<S, D>>>,
    pub invalid: Arc<Mutex<usize>>,

    /// Tracks the highest finalized view (at L notarizes).
    latest: Arc<Mutex<View>>,
    subscribers: Arc<Mutex<Vec<Sender<View>>>>,
}

impl<E, S, L, D, T> Reporter<E, S, L, D, T>
where
    E: CryptoRngCore,
    S: Scheme,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
    T: Strategy,
{
    pub fn new(context: E, cfg: Config<S, L, T>) -> Self {
        // Build elector with participants
        let elector = cfg.elector.build(&cfg.participants);

        Self {
            context,
            namespace: cfg.namespace,
            participants: cfg.participants,
            scheme: cfg.scheme,
            elector,
            strategy: cfg.strategy,
            leaders: Arc::new(Mutex::new(HashMap::new())),
            notarizes: Arc::new(Mutex::new(HashMap::new())),
            notarizations: Arc::new(Mutex::new(HashMap::new())),
            nullifies: Arc::new(Mutex::new(HashMap::new())),
            nullifications: Arc::new(Mutex::new(HashMap::new())),
            faults: Arc::new(Mutex::new(HashMap::new())),
            invalid: Arc::new(Mutex::new(0)),
            latest: Arc::new(Mutex::new(View::zero())),
            subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn notarized(&self, round: Round, certificate: &S::Certificate) {
        // We use the certificate from view N to determine the leader for view N+1.
        let next_round = Round::new(round.epoch(), round.view().next());
        let mut leaders = self.leaders.lock().expect("leaders lock poisoned");
        leaders.entry(next_round.view()).or_insert_with(|| {
            let leader = self.elector.elect(next_round, Some(certificate));
            self.participants
                .key(commonware_utils::Participant::new(leader))
                .cloned()
                .expect("leader not found in participants")
        });
    }
}

impl<E, S, L, D, T> crate::Reporter for Reporter<E, S, L, D, T>
where
    E: Clone + CryptoRngCore + Send + Sync + 'static,
    S: scheme::Scheme<D>,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
    T: Strategy,
{
    type Activity = Activity<S, D>;

    async fn report(&mut self, activity: Self::Activity) {
        // We check signatures for all messages to ensure that the prover is working correctly
        // but in production this isn't necessary (as signatures are already verified in
        // consensus).
        let verified = activity.verified();
        match &activity {
            Activity::Notarize(notarize) => {
                if !notarize.verify(&mut self.context, &self.scheme, &self.strategy) {
                    assert!(!verified);
                    *self.invalid.lock().expect("invalid lock poisoned") += 1;
                    return;
                }
                let encoded = notarize.encode();
                Notarize::<S, D>::decode(encoded).expect("notarize decode failed");
                let public_key = self.participants[notarize.signer() as usize].clone();
                self.notarizes
                    .lock()
                    .expect("notarizes lock poisoned")
                    .entry(notarize.view())
                    .or_default()
                    .entry(notarize.proposal.payload)
                    .or_default()
                    .insert(public_key);
            }
            Activity::Notarization(notarization) => {
                // Verify notarization
                let view = notarization.view();
                if !notarization.verify(&mut self.context, &self.scheme, &self.strategy) {
                    assert!(!verified);
                    *self.invalid.lock().expect("invalid lock poisoned") += 1;
                    return;
                }
                let encoded = notarization.encode();
                Notarization::<S, D>::decode_cfg(encoded, &self.scheme.certificate_codec_config())
                    .expect("notarization decode failed");
                self.notarizations
                    .lock()
                    .expect("notarizations lock poisoned")
                    .insert(view, notarization.clone());
                self.notarized(notarization.round(), &notarization.certificate);

                // In minimmit, finalization happens at L notarizes (handled by consensus).
                // We update latest when we see a notarization to track progress.
                let latest = *self.latest.lock().expect("latest lock poisoned");
                if view > latest {
                    *self.latest.lock().expect("latest lock poisoned") = view;
                    let mut subscribers =
                        self.subscribers.lock().expect("subscribers lock poisoned");
                    for subscriber in subscribers.iter_mut() {
                        let _ = subscriber.try_send(view);
                    }
                }
            }
            Activity::Nullify(nullify) => {
                if !nullify.verify::<_, D>(&mut self.context, &self.scheme, &self.strategy) {
                    assert!(!verified);
                    *self.invalid.lock().expect("invalid lock poisoned") += 1;
                    return;
                }
                let encoded = nullify.encode();
                Nullify::<S>::decode(encoded).expect("nullify decode failed");
                let public_key = self.participants[nullify.signer() as usize].clone();
                self.nullifies
                    .lock()
                    .expect("nullifies lock poisoned")
                    .entry(nullify.view())
                    .or_default()
                    .insert(public_key);
            }
            Activity::Nullification(nullification) => {
                // Verify nullification
                let view = nullification.view();
                if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.strategy) {
                    assert!(!verified);
                    *self.invalid.lock().expect("invalid lock poisoned") += 1;
                    return;
                }
                let encoded = nullification.encode();
                Nullification::<S>::decode_cfg(encoded, &self.scheme.certificate_codec_config())
                    .expect("nullification decode failed");
                self.nullifications
                    .lock()
                    .expect("nullifications lock poisoned")
                    .insert(view, nullification.clone());
                self.notarized(nullification.round, &nullification.certificate);
            }
            Activity::ConflictingNotarize(conflicting) => {
                let view = conflicting.view();
                if !conflicting.verify(&mut self.context, &self.scheme, &self.strategy) {
                    assert!(!verified);
                    *self.invalid.lock().expect("invalid lock poisoned") += 1;
                    return;
                }
                let encoded = conflicting.encode();
                ConflictingNotarize::<S, D>::decode(encoded)
                    .expect("conflicting notarize decode failed");
                let public_key = self.participants[conflicting.signer() as usize].clone();
                self.faults
                    .lock()
                    .expect("faults lock poisoned")
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
            Activity::NullifyNotarize(conflicting) => {
                let view = conflicting.view();
                if !conflicting.verify(&mut self.context, &self.scheme, &self.strategy) {
                    assert!(!verified);
                    *self.invalid.lock().expect("invalid lock poisoned") += 1;
                    return;
                }
                let encoded = conflicting.encode();
                NullifyNotarize::<S, D>::decode(encoded).expect("nullify notarize decode failed");
                let public_key = self.participants[conflicting.notarize.signer() as usize].clone();
                self.faults
                    .lock()
                    .expect("faults lock poisoned")
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
        }
    }
}

impl<E, S, L, D, T> Monitor for Reporter<E, S, L, D, T>
where
    E: Clone + CryptoRngCore + Send + Sync + 'static,
    S: Scheme,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
    T: Strategy,
{
    type Index = View;

    async fn subscribe(&mut self) -> (Self::Index, Receiver<Self::Index>) {
        let (tx, rx) = futures::channel::mpsc::channel(128);
        self.subscribers
            .lock()
            .expect("subscribers lock poisoned")
            .push(tx);
        let latest = *self.latest.lock().expect("latest lock poisoned");
        (latest, rx)
    }
}
