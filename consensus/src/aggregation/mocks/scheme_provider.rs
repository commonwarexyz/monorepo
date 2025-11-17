use crate::{
    signing_scheme::{self, Scheme},
    types::Epoch,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Provides signing schemes for different epochs.
#[derive(Clone)]
pub struct SchemeProvider<S: Scheme> {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<S>>>>,
}

impl<S: Scheme> SchemeProvider<S> {
    pub fn new() -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S: Scheme> SchemeProvider<S> {
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

impl<S: Scheme> signing_scheme::SchemeProvider for SchemeProvider<S> {
    type Scheme = S;

    fn scheme(&self, epoch: Epoch) -> Option<Arc<S>> {
        let schemes = self.schemes.lock().unwrap();
        schemes.get(&epoch).cloned()
    }
}
