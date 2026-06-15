/// Why a resolver fetch was requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
