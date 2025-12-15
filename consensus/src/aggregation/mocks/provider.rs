//! Mock provider for testing aggregation.
//!
//! This module provides a simple [`MockProvider`] implementation that can be
//! used in tests. It allows registering signing schemes for specific epochs
//! and retrieving them later.

use crate::types::Epoch;
use commonware_cryptography::certificate::{Provider, Scheme};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Provides signing schemes for different epochs.
#[derive(Clone)]
pub struct MockProvider<S: Scheme> {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<S>>>>,
}

impl<S: Scheme> Default for MockProvider<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Scheme> MockProvider<S> {
    pub fn new() -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S: Scheme> MockProvider<S> {
    /// Registers a new signing scheme for the given epoch.
    ///
    /// Returns `false` if a scheme was already registered for the epoch.
    pub fn register(&self, epoch: Epoch, scheme: S) -> bool {
        let mut schemes = self.schemes.lock().unwrap();
        schemes.insert(epoch, Arc::new(scheme)).is_none()
    }
}

impl<S: Scheme> Provider for MockProvider<S> {
    type Key = Epoch;
    type Scheme = S;

    fn keyed(&self, epoch: Epoch) -> Option<Arc<S>> {
        let schemes = self.schemes.lock().unwrap();
        schemes.get(&epoch).cloned()
    }
}
