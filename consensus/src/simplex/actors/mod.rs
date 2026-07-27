mod span;

pub mod batcher;
pub mod resolver;
pub mod voter;

/// Proposal ancestry evidence a targeted resolver request must obtain.
///
/// This is local subscriber bookkeeping and is never encoded on the wire.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum AncestryRequirement {
    /// A nullification covering the requested view.
    Nullification,
    /// A certified notarization or finalization for the named parent.
    Parent,
}

impl AncestryRequirement {
    /// Returns the stable trace field value for this requirement.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nullification => "nullification",
            Self::Parent => "parent",
        }
    }
}
