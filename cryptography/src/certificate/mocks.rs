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

/// A scheme provider that always returns the same scheme regardless of key.
///
/// Useful for unit tests that don't need to test key transitions.
#[derive(Clone, Debug)]
pub struct ConstantProvider<S: Scheme, K = ()> {
    scheme: Arc<S>,
    _key: core::marker::PhantomData<K>,
}

impl<S: Scheme, K> ConstantProvider<S, K> {
    /// Creates a new provider that always returns the given scheme.
    pub fn new(scheme: S) -> Self {
        Self {
            scheme: Arc::new(scheme),
            _key: core::marker::PhantomData,
        }
    }
}

impl<S: Scheme, K: Clone + Send + Sync + 'static> crate::certificate::Provider
    for ConstantProvider<S, K>
{
    type Key = K;
    type Scheme = S;

    fn keyed(&self, _: K) -> Option<Arc<S>> {
        Some(self.scheme.clone())
    }

    fn all(&self) -> Option<Arc<Self::Scheme>> {
        Some(self.scheme.clone())
    }
}

/// A provider that allows dynamically setting the returned scheme.
///
/// Useful for tests that need to modify the scheme during execution (e.g., to simulate
/// key transitions or scheme failures).
#[derive(Clone, Debug)]
pub struct MockProvider<S: Scheme, K = ()> {
    scheme: Arc<std::sync::RwLock<Option<Arc<S>>>>,
    _key: core::marker::PhantomData<K>,
}

impl<S: Scheme, K> Default for MockProvider<S, K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Scheme, K> MockProvider<S, K> {
    /// Creates a new mock provider with no scheme set.
    pub fn new() -> Self {
        Self {
            scheme: Arc::new(std::sync::RwLock::new(None)),
            _key: core::marker::PhantomData,
        }
    }

    /// Creates a new mock provider with the given scheme.
    pub fn with_scheme(scheme: S) -> Self {
        Self {
            scheme: Arc::new(std::sync::RwLock::new(Some(Arc::new(scheme)))),
            _key: core::marker::PhantomData,
        }
    }

    /// Sets the scheme to return.
    pub fn set(&self, scheme: Option<S>) {
        *self.scheme.write().unwrap() = scheme.map(Arc::new);
    }
}

impl<S: Scheme, K: Clone + Send + Sync + 'static> crate::certificate::Provider
    for MockProvider<S, K>
{
    type Key = K;
    type Scheme = S;

    fn keyed(&self, _: K) -> Option<Arc<S>> {
        self.scheme.read().unwrap().clone()
    }
}
