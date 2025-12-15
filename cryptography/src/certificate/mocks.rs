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

/// A scheme provider that always returns the same scheme regardless of scope.
///
/// Useful for unit tests that don't need to test scope transitions.
#[derive(Clone, Debug)]
pub struct ConstantProvider<S: Scheme, Sc = ()> {
    scheme: Arc<S>,
    _scope: core::marker::PhantomData<Sc>,
}

impl<S: Scheme, Sc> ConstantProvider<S, Sc> {
    /// Creates a new provider that always returns the given scheme.
    pub fn new(scheme: S) -> Self {
        Self {
            scheme: Arc::new(scheme),
            _scope: core::marker::PhantomData,
        }
    }
}

impl<S: Scheme, Sc: Clone + Send + Sync + 'static> crate::certificate::Provider
    for ConstantProvider<S, Sc>
{
    type Scope = Sc;
    type Scheme = S;

    fn scoped(&self, _: Sc) -> Option<Arc<S>> {
        Some(self.scheme.clone())
    }

    fn all(&self) -> Option<Arc<Self::Scheme>> {
        Some(self.scheme.clone())
    }
}

/// A provider that allows dynamically setting the returned scheme.
///
/// Useful for tests that need to modify the scheme during execution (e.g., to simulate
/// scope transitions or scheme failures).
#[derive(Clone, Debug)]
pub struct MockProvider<S: Scheme, Sc = ()> {
    scheme: Arc<std::sync::RwLock<Option<Arc<S>>>>,
    _scope: core::marker::PhantomData<Sc>,
}

impl<S: Scheme, Sc> Default for MockProvider<S, Sc> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Scheme, Sc> MockProvider<S, Sc> {
    /// Creates a new mock provider with no scheme set.
    pub fn new() -> Self {
        Self {
            scheme: Arc::new(std::sync::RwLock::new(None)),
            _scope: core::marker::PhantomData,
        }
    }

    /// Creates a new mock provider with the given scheme.
    pub fn with_scheme(scheme: S) -> Self {
        Self {
            scheme: Arc::new(std::sync::RwLock::new(Some(Arc::new(scheme)))),
            _scope: core::marker::PhantomData,
        }
    }

    /// Sets the scheme to return.
    pub fn set(&self, scheme: Option<S>) {
        *self.scheme.write().unwrap() = scheme.map(Arc::new);
    }
}

impl<S: Scheme, Sc: Clone + Send + Sync + 'static> crate::certificate::Provider
    for MockProvider<S, Sc>
{
    type Scope = Sc;
    type Scheme = S;

    fn scoped(&self, _: Sc) -> Option<Arc<S>> {
        self.scheme.read().unwrap().clone()
    }
}
