//! (Simplex)[commonware_consensus::simplex] signing scheme and
//! [commonware_consensus::marshal::SchemeProvider] implementation.

use commonware_consensus::{marshal, simplex::signing_scheme, types::Epoch};
use commonware_cryptography::{bls12381::primitives::variant::Variant, PublicKey};
use commonware_resolver::p2p;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// The BLS12-381 threshold signing scheme used in simplex.
pub type Scheme<V> = signing_scheme::bls12381_threshold::Scheme<V>;

/// Provides signing schemes for different epochs.
#[derive(Clone)]
pub struct SchemeProvider<V: Variant> {
    schemes: Arc<Mutex<HashMap<Epoch, Scheme<V>>>>,
}

impl<V: Variant> Default for SchemeProvider<V> {
    fn default() -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<V: Variant> SchemeProvider<V> {
    /// Registers a new signing scheme for the given epoch.
    ///
    /// Returns `false` if a scheme was already registered for the epoch.
    pub fn register(&self, epoch: Epoch, scheme: Scheme<V>) -> bool {
        let mut schemes = self.schemes.lock().unwrap();
        schemes.insert(epoch, scheme).is_none()
    }

    /// Unregisters the signing scheme for the given epoch.
    ///
    /// Returns `false` if no scheme was registered for the epoch.
    pub fn unregister(&self, epoch: &Epoch) -> bool {
        let mut schemes = self.schemes.lock().unwrap();
        schemes.remove(epoch).is_some()
    }
}

impl<V: Variant> marshal::SchemeProvider for SchemeProvider<V> {
    type Scheme = Scheme<V>;

    fn scheme(&self, epoch: Epoch) -> Option<Scheme<V>> {
        let schemes = self.schemes.lock().unwrap();
        schemes.get(&epoch).cloned()
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
