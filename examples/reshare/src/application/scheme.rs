//! (Simplex)[commonware_consensus::simplex] signing scheme and
//! [commonware_consensus::marshal::SchemeProvider] implementation.

use crate::orchestrator::EpochTransition;
use commonware_consensus::{
    marshal,
    simplex::signing_scheme::{self, Scheme},
    types::Epoch,
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    ed25519, PublicKey, Signer,
};
use commonware_resolver::p2p;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// The BLS12-381 threshold signing scheme used in simplex.
pub type ThresholdScheme<V> = signing_scheme::bls12381_threshold::Scheme<V>;

/// The ED25519 signing scheme used in simplex.
pub type EdScheme = signing_scheme::ed25519::Scheme;

/// Provides signing schemes for different epochs.
#[derive(Clone)]
pub struct SchemeProvider<S: Scheme, C: Signer> {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<S>>>>,
    signer: C,
}

impl<S: Scheme, C: Signer> SchemeProvider<S, C> {
    pub fn new(signer: C) -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
            signer,
        }
    }
}

impl<S: Scheme, C: Signer> SchemeProvider<S, C> {
    /// Registers a new signing scheme for the given epoch.
    ///
    /// Returns `false` if a scheme was already registered for the epoch.
    pub fn register(&self, epoch: Epoch, scheme: S) -> bool {
        let mut schemes = self.schemes.lock().unwrap();
        schemes.insert(epoch, Arc::new(scheme)).is_none()
    }

    /// Unregisters the signing scheme for the given epoch.
    ///
    /// Returns `false` if no scheme was registered for the epoch.
    pub fn unregister(&self, epoch: &Epoch) -> bool {
        let mut schemes = self.schemes.lock().unwrap();
        schemes.remove(epoch).is_some()
    }
}

impl<S: Scheme, C: Signer> marshal::SchemeProvider for SchemeProvider<S, C> {
    type Scheme = S;

    fn scheme(&self, epoch: Epoch) -> Option<Arc<S>> {
        let schemes = self.schemes.lock().unwrap();
        schemes.get(&epoch).cloned()
    }
}

pub trait EpochSchemeProvider {
    type Variant: Variant;
    type PublicKey: PublicKey;
    type Scheme: Scheme;

    /// Returns a [Scheme] for the given [EpochTransition].
    fn scheme_for_epoch(
        &self,
        transition: &EpochTransition<Self::Variant, Self::PublicKey>,
    ) -> Self::Scheme;
}

impl<V: Variant, C: Signer> EpochSchemeProvider for SchemeProvider<ThresholdScheme<V>, C> {
    type Variant = V;
    type PublicKey = C::PublicKey;
    type Scheme = ThresholdScheme<V>;

    fn scheme_for_epoch(
        &self,
        transition: &EpochTransition<Self::Variant, Self::PublicKey>,
    ) -> Self::Scheme {
        if let Some(share) = transition.share.as_ref() {
            ThresholdScheme::<V>::new(
                transition.participants.as_ref(),
                transition
                    .poly
                    .as_ref()
                    .expect("group polynomial must exist"),
                share.clone(),
            )
        } else {
            ThresholdScheme::<V>::verifier(
                transition.participants.as_ref(),
                transition
                    .poly
                    .as_ref()
                    .expect("group polynomial must exist"),
            )
        }
    }
}

impl EpochSchemeProvider for SchemeProvider<EdScheme, ed25519::PrivateKey> {
    type Variant = MinSig;
    type PublicKey = ed25519::PublicKey;
    type Scheme = EdScheme;

    fn scheme_for_epoch(
        &self,
        transition: &EpochTransition<Self::Variant, Self::PublicKey>,
    ) -> Self::Scheme {
        EdScheme::new(transition.participants.clone(), self.signer.clone())
    }
}

#[derive(Clone)]
pub struct Coordinator<P> {
    pub participants: Vec<P>,
}

impl<P> Coordinator<P> {
    pub fn new(participants: Vec<P>) -> Self {
        Self { participants }
    }
}

impl<P: PublicKey> p2p::Coordinator for Coordinator<P> {
    type PublicKey = P;

    fn peers(&self) -> &[Self::PublicKey] {
        self.participants.as_ref()
    }

    fn peer_set_id(&self) -> u64 {
        // In this example, we only have one static peer set.
        0
    }
}
