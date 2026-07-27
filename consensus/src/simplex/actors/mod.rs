mod span;

pub mod batcher;
pub mod resolver;
pub mod voter;

/// Why a certificate is being fetched.
///
/// This is local resolver bookkeeping and is never encoded on the wire.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Purpose {
    /// Background repair between the local floor and current view.
    Backfill,
    /// A nullification covering the requested view.
    Nullification,
    /// A certified notarization or finalization for the named parent.
    Parent,
}

impl Purpose {
    /// Returns whether this fetch came from proposal ancestry repair.
    pub const fn is_targeted(self) -> bool {
        !matches!(self, Self::Backfill)
    }

    /// Returns whether `resolved` makes this fetch unnecessary.
    ///
    /// This controls only local retention. The wire key remains kindless, and
    /// any certificate valid for that key completes its delivery.
    pub const fn is_retired_by(self, resolved: Self) -> bool {
        matches!(
            (self, resolved),
            (Self::Backfill | Self::Nullification, Self::Nullification)
                | (Self::Parent, Self::Parent)
        )
    }

    /// Returns the stable trace field value for this purpose.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Backfill => "backfill",
            Self::Nullification => "nullification",
            Self::Parent => "parent",
        }
    }
}
