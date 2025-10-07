use super::location::Location;
use core::{
    fmt,
    ops::{Add, AddAssign, Deref, Sub, SubAssign},
};

/// A [Position] is an index into an MMR's nodes.
/// This is in contrast to a [Location], which is an index into an MMR's _leaves_.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug)]
pub struct Position(u64);

impl Position {
    /// Return a new [Position] from a raw `u64`.
    #[inline]
    pub const fn new(pos: u64) -> Self {
        Self(pos)
    }

    /// Attempts to convert a [Location] to a [Position], returning `None` if overflow would occur.
    ///
    /// This is a checked alternative to [Position::from] which panics on overflow.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_storage::mmr::{Location, Position, MAX_LOCATION};
    ///
    /// let valid_loc = Location::new(100);
    /// assert!(Position::checked_from_location(valid_loc).is_some());
    ///
    /// let invalid_loc = Location::new(MAX_LOCATION + 1);
    /// assert!(Position::checked_from_location(invalid_loc).is_none());
    /// ```
    #[inline]
    pub fn checked_from_location(loc: Location) -> Option<Self> {
        let loc_val = *loc;
        let doubled = loc_val.checked_mul(2)?;
        Some(Self(doubled - loc_val.count_ones() as u64))
    }

    /// Return the underlying `u64` value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Return `self + rhs` returning `None` on overflow.
    #[inline]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return `self - rhs` returning `None` on underflow.
    #[inline]
    pub const fn checked_sub(self, rhs: u64) -> Option<Self> {
        match self.0.checked_sub(rhs) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return `self + rhs` saturating at `u64::MAX`.
    #[inline]
    pub const fn saturating_add(self, rhs: u64) -> Self {
        Self(self.0.saturating_add(rhs))
    }

    /// Return `self - rhs` saturating at zero.
    #[inline]
    pub const fn saturating_sub(self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Position({})", self.0)
    }
}

impl Deref for Position {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<u64> for Position {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

impl From<u64> for Position {
    #[inline]
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<usize> for Position {
    #[inline]
    fn from(value: usize) -> Self {
        Self::new(value as u64)
    }
}

impl From<Position> for u64 {
    #[inline]
    fn from(position: Position) -> Self {
        *position
    }
}

/// Returns the position of the leaf at the given location in an MMR.
///
/// # Panics
///
/// Panics if `loc > MAX_LOCATION`. Use [Position::checked_from_location] if you need to handle
/// this case without panicking.
///
/// # Examples
///
/// ```
/// use commonware_storage::mmr::{Location, Position};
///
/// let loc = Location::new(5);
/// let pos = Position::from(loc);
/// assert_eq!(pos, Position::new(8));
/// ```
impl From<Location> for Position {
    #[inline]
    fn from(loc: Location) -> Self {
        // This will never underflow since 2*n >= count_ones(n).
        let loc = *loc;
        Self(loc.checked_mul(2).expect("leaf_loc overflow") - loc.count_ones() as u64)
    }
}

/// Add two positions together.
///
/// # Panics
///
/// Panics if the result overflows.
impl Add for Position {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

/// Add a position and a `u64`.
///
/// # Panics
///
/// Panics if the result overflows.
impl Add<u64> for Position {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

/// Subtract two positions.
///
/// # Panics
///
/// Panics if the result underflows.
impl Sub for Position {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

/// Subtract a `u64` from a position.
///
/// # Panics
///
/// Panics if the result underflows.
impl Sub<u64> for Position {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl PartialEq<u64> for Position {
    #[inline]
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u64> for Position {
    #[inline]
    fn partial_cmp(&self, other: &u64) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

// Allow u64 to be compared with Position too
impl PartialEq<Position> for u64 {
    #[inline]
    fn eq(&self, other: &Position) -> bool {
        *self == other.0
    }
}

impl PartialOrd<Position> for u64 {
    #[inline]
    fn partial_cmp(&self, other: &Position) -> Option<core::cmp::Ordering> {
        self.partial_cmp(&other.0)
    }
}

/// Add a `u64` to a position.
///
/// # Panics
///
/// Panics if the result overflows.
impl AddAssign<u64> for Position {
    #[inline]
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

/// Subtract a `u64` from a position.
///
/// # Panics
///
/// Panics if the result underflows.
impl SubAssign<u64> for Position {
    #[inline]
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::{Location, Position};

    // Test that the [Position::from] function returns the correct position for leaf locations.
    #[test]
    fn test_from_location() {
        const CASES: &[(Location, Position)] = &[
            (Location::new(0), Position::new(0)),
            (Location::new(1), Position::new(1)),
            (Location::new(2), Position::new(3)),
            (Location::new(3), Position::new(4)),
            (Location::new(4), Position::new(7)),
            (Location::new(5), Position::new(8)),
            (Location::new(6), Position::new(10)),
            (Location::new(7), Position::new(11)),
            (Location::new(8), Position::new(15)),
            (Location::new(9), Position::new(16)),
            (Location::new(10), Position::new(18)),
            (Location::new(11), Position::new(19)),
            (Location::new(12), Position::new(22)),
            (Location::new(13), Position::new(23)),
            (Location::new(14), Position::new(25)),
            (Location::new(15), Position::new(26)),
        ];
        for (loc, expected_pos) in CASES {
            let pos = Position::from(*loc);
            assert_eq!(pos, *expected_pos);
        }
    }

    #[test]
    fn test_checked_add() {
        let pos = Position::new(10);
        assert_eq!(pos.checked_add(5).unwrap(), 15);
        assert!(Position::new(u64::MAX).checked_add(1).is_none());
    }

    #[test]
    fn test_checked_sub() {
        let pos = Position::new(10);
        assert_eq!(pos.checked_sub(5).unwrap(), 5);
        assert!(pos.checked_sub(11).is_none());
    }

    #[test]
    fn test_saturating_add() {
        let pos = Position::new(10);
        assert_eq!(pos.saturating_add(5), 15);
        assert_eq!(Position::new(u64::MAX).saturating_add(1), u64::MAX);
    }

    #[test]
    fn test_saturating_sub() {
        let pos = Position::new(10);
        assert_eq!(pos.saturating_sub(5), 5);
        assert_eq!(Position::new(0).saturating_sub(1), 0);
    }

    #[test]
    fn test_display() {
        let position = Position::new(42);
        assert_eq!(position.to_string(), "Position(42)");
    }

    #[test]
    fn test_add() {
        let pos1 = Position::new(10);
        let pos2 = Position::new(5);
        assert_eq!((pos1 + pos2), 15);
    }

    #[test]
    fn test_sub() {
        let pos1 = Position::new(10);
        let pos2 = Position::new(3);
        assert_eq!((pos1 - pos2), 7);
    }

    #[test]
    fn test_comparison_with_u64() {
        let pos = Position::new(42);

        // Test equality
        assert_eq!(pos, 42u64);
        assert_eq!(42u64, pos);
        assert_ne!(pos, 43u64);
        assert_ne!(43u64, pos);

        // Test ordering
        assert!(pos < 43u64);
        assert!(43u64 > pos);
        assert!(pos > 41u64);
        assert!(41u64 < pos);
        assert!(pos <= 42u64);
        assert!(42u64 >= pos);
    }

    #[test]
    fn test_assignment_with_u64() {
        let mut pos = Position::new(10);

        // Test add assignment
        pos += 5;
        assert_eq!(pos, 15u64);

        // Test sub assignment
        pos -= 3;
        assert_eq!(pos, 12u64);
    }

    #[test]
    fn test_checked_from_location_success() {
        use super::{super::location::MAX_LOCATION, Location};

        // Normal conversions should work
        let cases = vec![
            (Location::new(0), Position::new(0)),
            (Location::new(1), Position::new(1)),
            (Location::new(100), Position::from(Location::new(100))),
        ];

        for (loc, expected) in cases {
            let pos = Position::checked_from_location(loc).expect("should succeed");
            assert_eq!(pos, expected);
        }

        // MAX_LOCATION should work
        let max_loc = Location::new(MAX_LOCATION);
        let pos = Position::checked_from_location(max_loc).expect("MAX_LOCATION should convert");
        // For MAX_LOCATION = 2^63 - 1, popcount = 63
        // Position = 2 * (2^63 - 1) - 63 = u64::MAX - 64
        assert_eq!(*pos, u64::MAX - 64);
    }

    #[test]
    fn test_checked_from_location_overflow() {
        use super::{super::location::MAX_LOCATION, Location};

        // MAX_LOCATION + 1 should fail
        let over_loc = Location::new(MAX_LOCATION + 1);
        assert!(Position::checked_from_location(over_loc).is_none());

        // u64::MAX should fail
        let max_loc = Location::new(u64::MAX);
        assert!(Position::checked_from_location(max_loc).is_none());
    }
}
