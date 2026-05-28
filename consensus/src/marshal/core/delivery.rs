use super::Variant;
use crate::{
    simplex::{
        scheme::Scheme,
        types::{Finalization, Notarization, Subject},
    },
    types::Epoch, Epochable,
};
use commonware_cryptography::certificate::Scheme as CertificateScheme;
use commonware_utils::channel::oneshot;

/// A parsed-but-unverified resolver delivery awaiting batch certificate verification.
pub(super) enum PendingVerification<S: CertificateScheme, V: Variant>
where
    S: Scheme<V::Commitment>,
{
    Notarized {
        notarization: Notarization<S, V::Commitment>,
        block: V::Block,
        response: oneshot::Sender<bool>,
    },
    Finalized {
        finalization: Finalization<S, V::Commitment>,
        block: V::Block,
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

    pub(super) fn epoch(&self) -> Epoch {
        match self {
            Self::Notarized { notarization, .. } => notarization.epoch(),
            Self::Finalized { finalization, .. } => finalization.epoch(),
        }
    }

    pub(super) const fn as_subject_and_certificate(
        &self,
    ) -> (Subject<'_, V::Commitment>, &S::Certificate) {
        match self {
            Self::Notarized { notarization, .. } => (
                Subject::Notarize {
                    proposal: &notarization.proposal,
                },
                &notarization.certificate,
            ),
            Self::Finalized { finalization, .. } => (
                Subject::Finalize {
                    proposal: &finalization.proposal,
                },
                &finalization.certificate,
            ),
        }
    }
}
