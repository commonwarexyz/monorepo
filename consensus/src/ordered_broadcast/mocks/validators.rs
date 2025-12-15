use crate::types::Epoch;
use commonware_cryptography::{
    certificate::{Provider, Scheme},
    PublicKey,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct Validators<P: PublicKey, S: Scheme> {
    _validators: Vec<P>,
    schemes: Arc<Mutex<HashMap<Epoch, Arc<S>>>>,
}

impl<P: PublicKey, S: Scheme> Validators<P, S> {
    pub fn new(mut validators: Vec<P>) -> Self {
        validators.sort();
        Self {
            _validators: validators,
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

impl<P: PublicKey, S: Scheme> Provider<Epoch> for Validators<P, S> {
    type Scheme = S;

    fn scheme(&self, epoch: Epoch) -> Option<Arc<Self::Scheme>> {
        let schemes = self.schemes.lock().unwrap();
        schemes.get(&epoch).cloned()
    }
}
