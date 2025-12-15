//! Test fixtures for certificate signing schemes.

use crate::{certificate::Scheme, ed25519};
use std::sync::Arc;

/// A deterministic test fixture containing identities, identity private keys, per-participant
/// signing schemes, and a single verifier scheme.
#[derive(Clone, Debug)]
pub struct Fixture<S> {
    /// A sorted vector of participant public identity keys.
    pub participants: Vec<ed25519::PublicKey>,
    /// A sorted vector of participant private identity keys (matching order with `participants`).
    pub private_keys: Vec<ed25519::PrivateKey>,
    /// A vector of per-participant scheme instances (matching order with `participants`).
    pub schemes: Vec<S>,
    /// A single scheme verifier.
    pub verifier: S,
}

/// A scheme provider that always returns the same scheme regardless of epoch.
///
/// Useful for unit tests that don't need to test epoch transitions.
#[derive(Clone, Debug)]
pub struct ConstantProvider<S: Scheme> {
    scheme: Arc<S>,
}

impl<S: Scheme> ConstantProvider<S> {
    /// Creates a new provider that always returns the given scheme.
    pub fn new(scheme: S) -> Self {
        Self {
            scheme: Arc::new(scheme),
        }
    }
}

impl<S: Scheme, E> crate::certificate::Provider<E> for ConstantProvider<S> {
    type Scheme = S;

    fn scheme(&self, _epoch: E) -> Option<Arc<S>> {
        Some(self.scheme.clone())
    }

    fn certificate_verifier(&self) -> Option<Arc<Self::Scheme>> {
        Some(self.scheme.clone())
    }
}

/// A provider that allows dynamically setting the returned scheme.
///
/// Useful for tests that need to modify the scheme during execution (e.g., to simulate
/// epoch transitions or scheme failures).
#[derive(Clone, Debug)]
pub struct MockProvider<S: Scheme> {
    scheme: Arc<std::sync::RwLock<Option<Arc<S>>>>,
}

impl<S: Scheme> Default for MockProvider<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Scheme> MockProvider<S> {
    /// Creates a new mock provider with no scheme set.
    pub fn new() -> Self {
        Self {
            scheme: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Creates a new mock provider with the given scheme.
    pub fn with_scheme(scheme: S) -> Self {
        Self {
            scheme: Arc::new(std::sync::RwLock::new(Some(Arc::new(scheme)))),
        }
    }

    /// Sets the scheme to return.
    pub fn set(&self, scheme: Option<S>) {
        *self.scheme.write().unwrap() = scheme.map(Arc::new);
    }
}

impl<S: Scheme, E> crate::certificate::Provider<E> for MockProvider<S> {
    type Scheme = S;

    fn scheme(&self, _epoch: E) -> Option<Arc<S>> {
        self.scheme.read().unwrap().clone()
    }
}
