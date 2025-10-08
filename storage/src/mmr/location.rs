use super::position::Position;
use core::{
    convert::TryFrom,
    fmt,
    ops::{Add, AddAssign, Deref, Range, Sub, SubAssign},
};
use thiserror::Error;

/// Maximum valid [Location] value that can be safely converted to a [Position].
///
/// This limit exists because converting `Location` to `Position` requires multiplying by 2,
/// which would overflow for values larger than this. The formula `Position = 2L - popcount(L)`
/// means the maximum safe location is the largest value where `2L` fits in a u64.
///
/// For `Location = 2^63 - 1 = 0x7FFF_FFFF_FFFF_FFFF`:
/// - `2 * Location = 2^64 - 2 = u64::MAX - 1` ✓ (fits in u64)
/// - `popcount = 63`
/// - `Position = (2^64 - 2) - 63 = u64::MAX - 64`
///
/// For `Location = 2^63 = 0x8000_0000_0000_0000`:
/// - `2 * Location = 2^64` ✗ (overflow)
pub const MAX_LOCATION: u64 = 0x7FFF_FFFF_FFFF_FFFF; // 2^63 - 1

/// A [Location] is an index into an MMR's _leaves_.
/// This is in contrast to a [Position], which is an index into an MMR's _nodes_.
///
/// # Limits
///
/// While [Location] can technically hold any `u64` value, only values up to [`MAX_LOCATION`]
/// can be safely converted to [Position]. Values exceeding this limit will cause the
/// conversion to panic due to overflow in the underlying arithmetic.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug)]
pub struct Location(u64);

impl Location {
    /// Create a new [Location] from a raw `u64` without validation.
    ///
    /// This is an internal constructor that assumes the value is valid. For creating
    /// locations from external or untrusted sources, use [Location::new_checked].
    ///
    /// # Panics (debug builds only)
    ///
    /// In non-test debug builds, panics if `loc > MAX_LOCATION`. This helps catch bugs
    /// during development. Tests are allowed to create invalid locations for testing purposes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use commonware_storage::mmr::Location;
    /// // Internal code with known-valid values
    /// let loc = Location::new(42);
    /// assert_eq!(*loc, 42);
    /// ```
    #[inline]
    pub(crate) const fn new_unchecked(loc: u64) -> Self {
        debug_assert!(loc <= MAX_LOCATION);
        Self(loc)
    }

    /// Create a new [Location] from a raw `u64`, validating it does not exceed [`MAX_LOCATION`].
    ///
    /// Returns `None` if `loc > MAX_LOCATION`. Locations exceeding [`MAX_LOCATION`] cannot be
    /// safely converted to [Position] and will cause panics in MMR operations.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_storage::mmr::{Location, MAX_LOCATION};
    ///
    /// let loc = Location::new_checked(100).unwrap();
    /// assert_eq!(*loc, 100);
    ///
    /// // Values at MAX_LOCATION are valid
    /// assert!(Location::new_checked(MAX_LOCATION).is_some());
    ///
    /// // Values exceeding MAX_LOCATION return None
    /// assert!(Location::new_checked(MAX_LOCATION + 1).is_none());
    /// assert!(Location::new_checked(u64::MAX).is_none());
    /// ```
    #[inline]
    pub const fn new(loc: u64) -> Option<Self> {
        if loc > MAX_LOCATION {
            None
        } else {
            Some(Self(loc))
        }
    }

    /// Return the underlying `u64` value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns `true` if this location can be safely converted to a [Position].
    ///
    /// Returns `false` if this location exceeds [`MAX_LOCATION`], which would cause
    /// [Position::from] to panic due to overflowing u64.
    #[inline]
    pub const fn is_valid(self) -> bool {
        self.0 <= MAX_LOCATION
    }

    /// Return `self + rhs` returning `None` on overflow or if result exceeds [`MAX_LOCATION`].
    #[inline]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(value) => {
                if value <= MAX_LOCATION {
                    Some(Self(value))
                } else {
                    None
                }
            }
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

    /// Return `self + rhs` saturating at [`MAX_LOCATION`].
    #[inline]
    pub const fn saturating_add(self, rhs: u64) -> Self {
        let result = self.0.saturating_add(rhs);
        if result > MAX_LOCATION {
            Self(MAX_LOCATION)
        } else {
            Self(result)
        }
    }

    /// Return `self - rhs` saturating at zero.
    #[inline]
    pub const fn saturating_sub(self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Location({})", self.0)
    }
}

impl From<u64> for Location {
    #[inline]
    fn from(value: u64) -> Self {
        Self::new_unchecked(value)
    }
}

impl From<usize> for Location {
    #[inline]
    fn from(value: usize) -> Self {
        Self::new_unchecked(value as u64)
    }
}

impl Deref for Location {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Location> for u64 {
    #[inline]
    fn from(loc: Location) -> Self {
        *loc
    }
}

/// Add two locations together.
///
/// # Panics
///
/// Panics if the result overflows.
impl Add for Location {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

/// Add a location and a `u64`.
///
/// # Panics
///
/// Panics if the result overflows.
impl Add<u64> for Location {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

/// Subtract two locations.
///
/// # Panics
///
/// Panics if the result underflows.
impl Sub for Location {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

/// Subtract a `u64` from a location.
///
/// # Panics
///
/// Panics if the result underflows.
impl Sub<u64> for Location {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl PartialEq<u64> for Location {
    #[inline]
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u64> for Location {
    #[inline]
    fn partial_cmp(&self, other: &u64) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

// Allow u64 to be compared with Location too
impl PartialEq<Location> for u64 {
    #[inline]
    fn eq(&self, other: &Location) -> bool {
        *self == other.0
    }
}

impl PartialOrd<Location> for u64 {
    #[inline]
    fn partial_cmp(&self, other: &Location) -> Option<core::cmp::Ordering> {
        self.partial_cmp(&other.0)
    }
}

/// Add a `u64` to a location.
///
/// # Panics
///
/// Panics if the result overflows.
impl AddAssign<u64> for Location {
    #[inline]
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

/// Subtract a `u64` from a location.
///
/// # Panics
///
/// Panics if the result underflows.
impl SubAssign<u64> for Location {
    #[inline]
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

impl TryFrom<Position> for Location {
    type Error = NonLeafPositionError;

    /// Attempt to derive the [Location] of a given node [Position].
    ///
    /// Returns an error if the position does not correspond to an MMR leaf.
    ///
    /// This computation is O(log2(n)) in the given position.
    ///
    /// # Panics
    ///
    /// Panics if `pos` is too large (top 2 bits should be 0).
    #[inline]
    fn try_from(pos: Position) -> Result<Self, Self::Error> {
        if *pos == 0 {
            return Ok(Self(0));
        }

        let start = u64::MAX >> (*pos.checked_add(1).expect("leaf pos overflow")).leading_zeros();
        let height = start.trailing_ones();
        assert!(height > 1, "leaf pos overflow");
        let mut two_h = 1 << (height - 1);
        let mut cur_node = start - 1;
        let mut leaf_loc_floor = 0u64;

        while two_h > 1 {
            if cur_node == *pos {
                return Err(NonLeafPositionError { pos });
            }
            let left_pos = cur_node - two_h;
            two_h >>= 1;
            if *pos > left_pos {
                // The leaf is in the right subtree, so we must account for the leaves in the left
                // subtree all of which precede it.
                leaf_loc_floor += two_h;
                cur_node -= 1; // move to the right child
            } else {
                // The node is in the left subtree
                cur_node = left_pos;
            }
        }

        Ok(Self(leaf_loc_floor))
    }
}

/// Error returned when attempting to interpret a non-leaf position as a [Location].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
#[error("Position({}) is not a leaf", *pos)]
pub struct NonLeafPositionError {
    pos: Position,
}

impl NonLeafPositionError {
    /// The offending position.
    #[inline]
    pub const fn position(self) -> Position {
        self.pos
    }
}

/// Extension trait for converting `Range<Location>` into other range types.
pub trait LocationRangeExt {
    /// Convert a `Range<Location>` to a `Range<usize>` suitable for slice indexing.
    fn to_usize_range(&self) -> Range<usize>;
}

impl LocationRangeExt for Range<Location> {
    #[inline]
    fn to_usize_range(&self) -> Range<usize> {
        *self.start as usize..*self.end as usize
    }
}

#[cfg(test)]
mod tests {
    use super::{Location, MAX_LOCATION};
    use crate::mmr::position::Position;

    // Test that the [Location::try_from] function returns the correct location for leaf positions.
    #[test]
    fn test_try_from_position() {
        const CASES: &[(Position, Location)] = &[
            (Position::new(0), Location::new_unchecked(0)),
            (Position::new(1), Location::new_unchecked(1)),
            (Position::new(3), Location::new_unchecked(2)),
            (Position::new(4), Location::new_unchecked(3)),
            (Position::new(7), Location::new_unchecked(4)),
            (Position::new(8), Location::new_unchecked(5)),
            (Position::new(10), Location::new_unchecked(6)),
            (Position::new(11), Location::new_unchecked(7)),
            (Position::new(15), Location::new_unchecked(8)),
            (Position::new(16), Location::new_unchecked(9)),
            (Position::new(18), Location::new_unchecked(10)),
            (Position::new(19), Location::new_unchecked(11)),
            (Position::new(22), Location::new_unchecked(12)),
            (Position::new(23), Location::new_unchecked(13)),
            (Position::new(25), Location::new_unchecked(14)),
            (Position::new(26), Location::new_unchecked(15)),
        ];
        for (pos, expected_loc) in CASES {
            let loc = Location::try_from(*pos).expect("should map to a leaf location");
            assert_eq!(loc, *expected_loc);
        }
    }

    // Test that the [Location::try_from] function returns an error for non-leaf positions.
    #[test]
    fn test_try_from_position_error() {
        const CASES: &[Position] = &[
            Position::new(2),
            Position::new(5),
            Position::new(6),
            Position::new(9),
            Position::new(12),
            Position::new(13),
            Position::new(14),
            Position::new(17),
            Position::new(20),
            Position::new(21),
            Position::new(24),
            Position::new(27),
            Position::new(28),
            Position::new(29),
            Position::new(30),
        ];
        for &pos in CASES {
            let err = Location::try_from(pos).expect_err("position is not a leaf");
            assert_eq!(err.position(), pos);
        }
    }

    #[test]
    fn test_checked_add() {
        let loc = Location::new_unchecked(10);
        assert_eq!(loc.checked_add(5).unwrap(), 15);

        // Overflow returns None
        assert!(Location::new_unchecked(u64::MAX).checked_add(1).is_none());

        // Exceeding MAX_LOCATION returns None
        assert!(Location::new_unchecked(MAX_LOCATION)
            .checked_add(1)
            .is_none());

        // At MAX_LOCATION is OK
        let loc = Location::new_unchecked(MAX_LOCATION - 10);
        assert_eq!(loc.checked_add(10).unwrap(), MAX_LOCATION);
    }

    #[test]
    fn test_checked_sub() {
        let loc = Location::new_unchecked(10);
        assert_eq!(loc.checked_sub(5).unwrap(), 5);
        assert!(loc.checked_sub(11).is_none());
    }

    #[test]
    fn test_saturating_add() {
        let loc = Location::new_unchecked(10);
        assert_eq!(loc.saturating_add(5), 15);

        // Saturates at MAX_LOCATION, not u64::MAX
        assert_eq!(
            Location::new_unchecked(u64::MAX).saturating_add(1),
            MAX_LOCATION
        );
        assert_eq!(
            Location::new_unchecked(MAX_LOCATION).saturating_add(1),
            MAX_LOCATION
        );
        assert_eq!(
            Location::new_unchecked(MAX_LOCATION).saturating_add(1000),
            MAX_LOCATION
        );
    }

    #[test]
    fn test_saturating_sub() {
        let loc = Location::new_unchecked(10);
        assert_eq!(loc.saturating_sub(5), 5);
        assert_eq!(Location::new_unchecked(0).saturating_sub(1), 0);
    }

    #[test]
    fn test_display() {
        let location = Location::new_unchecked(42);
        assert_eq!(location.to_string(), "Location(42)");
    }

    #[test]
    fn test_add() {
        let loc1 = Location::new_unchecked(10);
        let loc2 = Location::new_unchecked(5);
        assert_eq!((loc1 + loc2), 15);
    }

    #[test]
    fn test_sub() {
        let loc1 = Location::new_unchecked(10);
        let loc2 = Location::new_unchecked(3);
        assert_eq!((loc1 - loc2), 7);
    }

    #[test]
    fn test_comparison_with_u64() {
        let loc = Location::new_unchecked(42);

        // Test equality
        assert_eq!(loc, 42u64);
        assert_eq!(42u64, loc);
        assert_ne!(loc, 43u64);
        assert_ne!(43u64, loc);

        // Test ordering
        assert!(loc < 43u64);
        assert!(43u64 > loc);
        assert!(loc > 41u64);
        assert!(41u64 < loc);
        assert!(loc <= 42u64);
        assert!(42u64 >= loc);
    }

    #[test]
    fn test_assignment_with_u64() {
        let mut loc = Location::new_unchecked(10);

        // Test add assignment
        loc += 5;
        assert_eq!(loc, 15u64);

        // Test sub assignment
        loc -= 3;
        assert_eq!(loc, 12u64);
    }

    #[test]
    fn test_new_checked() {
        // Valid locations
        assert!(Location::new(0).is_some());
        assert!(Location::new(1000).is_some());
        assert!(Location::new(MAX_LOCATION).is_some());

        // Invalid locations (too large)
        assert!(Location::new(MAX_LOCATION + 1).is_none());
        assert!(Location::new(u64::MAX).is_none());
    }

    #[test]
    fn test_is_valid_for_position() {
        assert!(Location::new_unchecked(0).is_valid());
        assert!(Location::new_unchecked(1000).is_valid());
        assert!(Location::new_unchecked(MAX_LOCATION).is_valid());
        assert!(!Location::new_unchecked(MAX_LOCATION + 1).is_valid());
        assert!(!Location::new_unchecked(u64::MAX).is_valid());
    }

    #[test]
    fn test_max_location_boundary() {
        // MAX_LOCATION should convert successfully
        let max_loc = Location::new_unchecked(MAX_LOCATION);
        assert!(max_loc.is_valid());
        let pos = Position::from(max_loc);
        // Verify the position value
        // For MAX_LOCATION = 2^63 - 1, popcount = 63
        // Position = 2 * (2^63 - 1) - 63 = 2^64 - 2 - 63 = u64::MAX - 64
        let expected = u64::MAX - 64;
        assert_eq!(*pos, expected);
    }

    #[test]
    #[should_panic(expected = "location overflow: exceeds MAX_LOCATION")]
    fn test_overflow_location_panics() {
        use super::Position;

        // MAX_LOCATION + 1 should panic
        let over_loc = Location::new_unchecked(MAX_LOCATION + 1);
        let _ = Position::from(over_loc);
    }

    #[test]
    fn test_checked_from_location() {
        use super::Position;

        // Valid conversion
        let valid_loc = Location::new_unchecked(1000);
        assert!(Position::checked_from_location(valid_loc).is_some());

        // MAX_LOCATION should succeed
        let max_loc = Location::new_unchecked(MAX_LOCATION);
        assert!(Position::checked_from_location(max_loc).is_some());

        // Over MAX_LOCATION should fail
        let over_loc = Location::new_unchecked(MAX_LOCATION + 1);
        assert!(Position::checked_from_location(over_loc).is_none());

        // u64::MAX should fail
        let max_u64_loc = Location::new_unchecked(u64::MAX);
        assert!(Position::checked_from_location(max_u64_loc).is_none());
    }
}
