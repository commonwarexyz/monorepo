//! Certificate-scheme providers shared by DKG bootstrap and runtime actors.

use commonware_cryptography::certificate::{Provider, Scoped};
use std::sync::Arc;

/// A [`Provider`] that answers unregistered scopes with a constant all-scope
/// verifier.
///
/// Registered scopes resolve exactly as `inner` provides them. An unregistered
/// scope is answered with a verify-only handle built from the fallback scheme,
/// keeping certificates judgeable for scopes the node has not learned yet, such
/// as epochs beyond a state-sync anchor. The fallback is sound only for schemes
/// whose certificates verify under scope-independent state, such as a threshold
/// scheme whose group key survives resharing.
///
/// Signing scheme lookup never falls back: [`Provider::scheme`] delegates to
/// `inner` alone, so signing, participant enumeration, and membership checks
/// are unaffected.
///
/// State-sync compositions that allow the probe floor to cross an epoch
/// boundary MUST wrap the provider handed to marshal and the probe in this
/// type. Marshal panics when installing a floor for an epoch its provider
/// cannot verify.
#[derive(Clone)]
pub struct FallbackProvider<P: Provider> {
    inner: P,
    fallback: Arc<P::Scheme>,
}

impl<P: Provider> FallbackProvider<P> {
    /// Wraps `inner`, answering unregistered scopes with a verify-only handle
    /// built from `fallback`.
    pub fn new(inner: P, fallback: P::Scheme) -> Self {
        Self {
            inner,
            fallback: Arc::new(fallback),
        }
    }
}

impl<P: Provider> Provider for FallbackProvider<P> {
    type Scope = P::Scope;
    type Scheme = P::Scheme;

    fn scoped(&self, scope: Self::Scope) -> Option<Scoped<Self::Scheme>> {
        self.inner
            .scoped(scope)
            .or_else(|| Some(Scoped::verifier(self.fallback.clone())))
    }

    fn scheme(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        self.inner.scheme(scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::tests::mocks;
    use commonware_consensus::types::Epoch;
    use commonware_runtime::{Runner as _, deterministic};

    #[derive(Clone)]
    struct SingleEpoch {
        epoch: Epoch,
        scheme: Arc<mocks::TestScheme>,
    }

    impl Provider for SingleEpoch {
        type Scope = Epoch;
        type Scheme = mocks::TestScheme;

        fn scoped(&self, scope: Epoch) -> Option<Scoped<Self::Scheme>> {
            (scope == self.epoch).then(|| Scoped::scheme(self.scheme.clone()))
        }

        fn scheme(&self, scope: Epoch) -> Option<Arc<Self::Scheme>> {
            (scope == self.epoch).then(|| self.scheme.clone())
        }
    }

    #[test]
    fn registered_scope_uses_inner_scheme() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let inner = SingleEpoch {
                epoch: Epoch::new(1),
                scheme: Arc::new(fixture.schemes[0].clone()),
            };
            let provider = FallbackProvider::new(inner, fixture.schemes[1].clone());

            let scoped = provider.scoped(Epoch::new(1)).expect("registered scope");
            assert!(scoped.into_scheme().is_some());
            assert!(provider.scheme(Epoch::new(1)).is_some());
        });
    }

    #[test]
    fn unregistered_scope_falls_back_to_verifier_only() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let inner = SingleEpoch {
                epoch: Epoch::new(1),
                scheme: Arc::new(fixture.schemes[0].clone()),
            };
            let provider = FallbackProvider::new(inner, fixture.schemes[1].clone());

            let scoped = provider.scoped(Epoch::new(7)).expect("fallback scope");
            assert!(scoped.into_scheme().is_none());
            assert!(provider.scheme(Epoch::new(7)).is_none());
        });
    }
}
