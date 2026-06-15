use crate::types::View;

/// Why a resolver fetch was requested.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum FetchReason {
    MissingNullification,
    CertificationFailed,
    SatisfiedByFailedNotarization,
}

impl FetchReason {
    /// Returns the stable trace field value for this reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingNullification => "missing_nullification",
            Self::CertificationFailed => "certification_failed",
            Self::SatisfiedByFailedNotarization => "satisfied_by_failed_notarization",
        }
    }
}

/// Local request metadata carried through the resolver subscriber.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct FetchRequest {
    /// Unique id that distinguishes repeated requests with the same metadata.
    pub(crate) id: u64,
    /// The view to fetch.
    pub(crate) view: View,
    /// The view whose processing caused this fetch.
    pub(crate) cause: View,
    /// Why the fetch is needed.
    pub(crate) reason: FetchReason,
}

impl FetchRequest {
    pub(crate) const fn new(id: u64, view: View, cause: View, reason: FetchReason) -> Self {
        Self {
            id,
            view,
            cause,
            reason,
        }
    }
}
