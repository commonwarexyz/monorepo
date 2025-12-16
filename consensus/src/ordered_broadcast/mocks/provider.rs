use crate::types::Epoch;
use commonware_cryptography::certificate;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// A mock [`certificate::Provider`] that allows registering different schemes per epoch.
///
/// Unlike [`certificate::ConstantProvider`] which returns the same scheme for all scopes,
/// this mock supports epoch-specific schemes for multi-epoch testing scenarios.
#[derive(Clone)]
pub struct Provider<S: certificate::Scheme> {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<S>>>>,
}

impl<S: certificate::Scheme> Provider<S> {
    pub fn new() -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Registers a new signing scheme for the given epoch.
    ///
    /// Returns `false` if a scheme was already registered for the epoch.
    pub fn register(&self, epoch: Epoch, scheme: S) -> bool {
        let mut schemes = self.schemes.lock().unwrap();
        schemes.insert(epoch, Arc::new(scheme)).is_none()
    }
}

impl<S: certificate::Scheme> Default for Provider<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: certificate::Scheme> certificate::Provider for Provider<S> {
    type Scope = Epoch;
    type Scheme = S;

    fn scoped(&self, epoch: Epoch) -> Option<Arc<Self::Scheme>> {
        let schemes = self.schemes.lock().unwrap();
        schemes.get(&epoch).cloned()
    }
}
