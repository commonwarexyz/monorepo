//! Journal positions and stable identifiers for effects and barriers.

/// The last acknowledged journal position.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cursor(pub(super) u64);

impl Cursor {
    /// Returns the empty-journal cursor.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Returns the journal position.
    pub const fn get(self) -> u64 {
        self.0
    }

    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Stable idempotency identifier for one durable external action.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EffectId(pub(super) u64);

impl EffectId {
    pub(crate) const fn from_cursor(cursor: Cursor) -> Self {
        Self(cursor.0)
    }

    /// Returns the stable epoch-local sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Identifies one persistence batch within a process generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BatchId(u64);

impl BatchId {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the generation-local sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}
