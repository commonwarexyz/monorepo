//! Mock `Reporter` for tests: tracks participants/leaders, verifies activities,
//! records votes/faults, and exposes a simple subscription.

use crate::{
    elector::{Config as ElectorConfig, Elector},
    minimmit::{
        scheme::Scheme,
        types::{
            Activity, Attributable, ConflictingNotarize, Finalization, MNotarization, Notarize,
            Nullification, Nullify, Subject,
        },
    },
    types::{Round, View},
    Monitor, Viewable,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::{certificate::Scheme as CertScheme, Digest};
use commonware_parallel::Sequential;
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc},
    ordered::{Quorum, Set},
    M5f1, N5f1,
};
use rand_core::CryptoRngCore;
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::{Arc, Mutex},
};

// Records which validators have participated in a given view/payload pair.
type Participation<P, D> = HashMap<View, HashMap<D, HashSet<P>>>;
type Faults<S, D> = HashMap<<S as CertScheme>::PublicKey, HashMap<View, HashSet<Activity<S, D>>>>;

/// Reporter configuration used in tests.
#[derive(Clone, Debug)]
pub struct Config<S: CertScheme, L: ElectorConfig<S>> {
    pub participants: Set<S::PublicKey>,
    pub scheme: S,
    pub elector: L,
}

#[derive(Clone)]
pub struct Reporter<E: CryptoRngCore, S: CertScheme, L: ElectorConfig<S>, D: Digest> {
    context: E,
    pub participants: Set<S::PublicKey>,
    scheme: S,
    elector: L::Elector,

    pub leaders: Arc<Mutex<HashMap<View, S::PublicKey>>>,
    pub certified: Arc<Mutex<HashSet<View>>>,
    pub notarizes: Arc<Mutex<Participation<S::PublicKey, D>>>,
    pub m_notarizations: Arc<Mutex<HashMap<View, MNotarization<S, D>>>>,
    pub nullifies: Arc<Mutex<HashMap<View, HashSet<S::PublicKey>>>>,
    pub nullifications: Arc<Mutex<HashMap<View, Nullification<S>>>>,
    pub finalizations: Arc<Mutex<HashMap<View, Finalization<S, D>>>>,
    pub faults: Arc<Mutex<Faults<S, D>>>,
    pub invalid: Arc<Mutex<usize>>,

    latest: Arc<Mutex<View>>,
    subscribers: Arc<Mutex<Vec<mpsc::Sender<View>>>>,
}

impl<E, S, L, D> Reporter<E, S, L, D>
where
    E: CryptoRngCore,
    S: CertScheme,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
{
    pub fn new(context: E, cfg: Config<S, L>) -> Self {
        // Build elector with participants
        let elector = cfg.elector.build(&cfg.participants);

        Self {
            context,
            participants: cfg.participants,
            scheme: cfg.scheme,
            elector,
            leaders: Arc::new(Mutex::new(HashMap::new())),
            certified: Arc::new(Mutex::new(HashSet::new())),
            notarizes: Arc::new(Mutex::new(HashMap::new())),
            m_notarizations: Arc::new(Mutex::new(HashMap::new())),
            nullifies: Arc::new(Mutex::new(HashMap::new())),
            nullifications: Arc::new(Mutex::new(HashMap::new())),
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
    E: Clone + CryptoRngCore + Send + Sync + 'static,
    S: Scheme<D>,
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
                if !notarize.verify(&mut self.context, &self.scheme, &Sequential) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = notarize.encode();
                Notarize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants.key(notarize.signer()).unwrap().clone();
                self.notarizes
                    .lock()
                    .unwrap()
                    .entry(notarize.view())
                    .or_default()
                    .entry(notarize.proposal.payload)
                    .or_default()
                    .insert(public_key);
            }
            Activity::MNotarization(m_notarization) => {
                // Verify M-notarization
                let view = m_notarization.view();
                if !self.scheme.verify_certificate::<_, D, M5f1>(
                    &mut self.context,
                    Subject::Notarize {
                        proposal: &m_notarization.proposal,
                    },
                    &m_notarization.certificate,
                    &Sequential,
                ) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = m_notarization.encode();
                MNotarization::<S, D>::decode_cfg(encoded, &self.scheme.certificate_codec_config())
                    .unwrap();
                self.m_notarizations
                    .lock()
                    .unwrap()
                    .insert(view, m_notarization.clone());
                self.certified(m_notarization.round(), &m_notarization.certificate);
            }
            Activity::Nullify(nullify) => {
                if !nullify.verify(&mut self.context, &self.scheme, &Sequential) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = nullify.encode();
                Nullify::<S>::decode(encoded).unwrap();
                let public_key = self.participants.key(nullify.signer()).unwrap().clone();
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
                if !self.scheme.verify_certificate::<_, D, M5f1>(
                    &mut self.context,
                    Subject::Nullify {
                        round: nullification.round,
                    },
                    &nullification.certificate,
                    &Sequential,
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
            Activity::Finalization(finalization) => {
                // Verify finalization
                let view = finalization.view();
                if !self.scheme.verify_certificate::<_, D, N5f1>(
                    &mut self.context,
                    Subject::Notarize {
                        proposal: &finalization.proposal,
                    },
                    &finalization.certificate,
                    &Sequential,
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
                    subscriber.try_send_lossy(finalization.view());
                }
            }
            Activity::ConflictingNotarize(conflicting) => {
                let view = conflicting.view();
                if !conflicting.verify(&mut self.context, &self.scheme, &Sequential) {
                    assert!(!verified);
                    *self.invalid.lock().unwrap() += 1;
                    return;
                }
                let encoded = conflicting.encode();
                ConflictingNotarize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants.key(conflicting.signer()).unwrap().clone();
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
    E: Clone + CryptoRngCore + Send + Sync + 'static,
    S: CertScheme,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
{
    type Index = View;

    async fn subscribe(&mut self) -> (Self::Index, mpsc::Receiver<Self::Index>) {
        let (tx, rx) = mpsc::channel(128);
        self.subscribers.lock().unwrap().push(tx);
        let latest = *self.latest.lock().unwrap();
        (latest, rx)
    }
}
