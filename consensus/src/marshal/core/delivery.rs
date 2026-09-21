use super::{Variant, actor::ResolverVerdict};
use crate::simplex::{
    scheme::Scheme,
    types::{Finalization, Notarization},
};
use commonware_cryptography::certificate::{Scheme as CertificateScheme, Scoped};

/// A parsed-but-unverified resolver delivery awaiting batch certificate verification.
///
/// Each item carries the scope it was admitted under so verification does not
/// depend on the provider still serving that epoch.
pub(super) enum PendingVerification<S: CertificateScheme, V: Variant>
where
    S: Scheme<V::Commitment>,
{
    Notarized {
        scoped: Scoped<S>,
        notarization: Notarization<S, V::Commitment>,
        block: V::Block,
        verdict: ResolverVerdict<V>,
    },
    Finalized {
        scoped: Scoped<S>,
        finalization: Finalization<S, V::Commitment>,
        block: V::ApplicationBlock,
        verdict: ResolverVerdict<V>,
    },
}

impl<S: CertificateScheme, V: Variant> PendingVerification<S, V>
where
    S: Scheme<V::Commitment>,
{
    /// Returns the scope the delivery was admitted under.
    pub(super) const fn scoped(&self) -> &Scoped<S> {
        match self {
            Self::Notarized { scoped, .. } | Self::Finalized { scoped, .. } => scoped,
        }
    }

    pub(super) fn response_closed(&self) -> bool {
        match self {
            Self::Notarized { verdict, .. } | Self::Finalized { verdict, .. } => {
                verdict.response_closed()
            }
        }
    }
}
