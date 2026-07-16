use super::Variant;
use crate::simplex::{
    scheme::Scheme,
    types::{Finalization, Notarization},
};
use commonware_cryptography::certificate::Scheme as CertificateScheme;
use commonware_utils::channel::oneshot;

/// A resolver block decoded according to the request's trust level.
pub(super) enum DecodedBlock<V: Variant> {
    Certified(V::ApplicationBlock),
    Untrusted(V::Block),
}

impl<V: Variant> DecodedBlock<V> {
    pub(super) fn into_block(self, commitment: V::Commitment) -> V::Block {
        match self {
            Self::Certified(block) => V::from_application_block(block, commitment),
            Self::Untrusted(block) => block,
        }
    }
}

/// A parsed-but-unverified resolver delivery awaiting batch certificate verification.
pub(super) enum PendingVerification<S: CertificateScheme, V: Variant>
where
    S: Scheme<V::Commitment>,
{
    Notarized {
        notarization: Notarization<S, V::Commitment>,
        block: DecodedBlock<V>,
        response: oneshot::Sender<bool>,
    },
    Finalized {
        finalization: Finalization<S, V::Commitment>,
        block: V::ApplicationBlock,
        response: oneshot::Sender<bool>,
    },
}

impl<S: CertificateScheme, V: Variant> PendingVerification<S, V>
where
    S: Scheme<V::Commitment>,
{
    pub(super) fn response_closed(&self) -> bool {
        match self {
            Self::Notarized { response, .. } | Self::Finalized { response, .. } => {
                response.is_closed()
            }
        }
    }
}
