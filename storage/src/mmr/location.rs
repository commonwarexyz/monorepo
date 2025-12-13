use super::position::Position;
use crate::mmr::MAX_POSITION;
use core::{
    convert::TryFrom,
    fmt,
    ops::{Add, AddAssign, Deref, Range, Sub, SubAssign},
};
use thiserror::Error;

/// Maximum valid [Location] value that can exist in a valid MMR.
///
/// This limit exists because the total MMR size (number of nodes) must be representable in a u64
/// with at least one leading zero bit for validity checking. The MMR size for N leaves is:
///
/// ```text
/// MMR_size = 2*N - popcount(N)
/// ```
///
/// where `popcount(N)` is the number of set bits in N (the number of binary trees in the MMR forest).
///
/// The worst case occurs when N is a power of 2 (popcount = 1), giving `MMR_size = 2*N - 1`.
///
/// For validity, we require `MMR_size < 2^63` (top bit clear), which gives us:
///
/// ```text
/// 2*N - 1 < 2^63
/// 2*N < 2^63 + 1
/// N ≤ 2^62
/// ```
///
/// Therefore, the maximum number of leaves is `2^62`, and the maximum location (0-indexed) is `2^62 - 1`.
///
/// ## Verification
///
/// For `N = 2^62` leaves (worst case):
/// - `MMR_size = 2 * 2^62 - 1 = 2^63 - 1 = 0x7FFF_FFFF_FFFF_FFFF` ✓
/// - Leading zeros: 1 ✓
///
/// For `N = 2^62 + 1` leaves:
/// - `2 * N = 2^63 + 2` ✗ (exceeds maximum valid MMR size)
pub const MAX_LOCATION: u64 = 0x3FFF_FFFF_FFFF_FFFF; // 2^62 - 1

/// A [Location] is an index into an MMR's _leaves_.
/// This is in contrast to a [Position], which is an index into an MMR's _nodes_.
///
/// # Limits
///
/// While [Location] can technically hold any `u64` value, only values up to [MAX_LOCATION]
/// can be safely converted to [Position]. Values beyond this are considered invalid.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug)]
pub struct Location(u64);

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Location {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let value = u.int_in_range(0..=MAX_LOCATION)?;
        Ok(Self(value))
    }
}

impl Location {
    /// Create a new [Location] from a raw `u64` without validation.
    ///
    /// This is an internal constructor that assumes the value is valid. For creating
    /// locations from external or untrusted sources, use [Location::new].
    #[inline]
    pub(crate) const fn new_unchecked(loc: u64) -> Self {
        Self(loc)
    }

    /// Create a new [Location] from a raw `u64`, validating it does not exceed [MAX_LOCATION].
    ///
    /// Returns `None` if `loc > MAX_LOCATION`.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_storage::mmr::{Location, MAX_LOCATION};
    ///
    /// let loc = Location::new(100).unwrap();
    /// assert_eq!(*loc, 100);
    ///
    /// // Values at MAX_LOCATION are valid
    /// assert!(Location::new(MAX_LOCATION).is_some());
    ///
    /// // Values exceeding MAX_LOCATION return None
    /// assert!(Location::new(MAX_LOCATION + 1).is_none());
    /// assert!(Location::new(u64::MAX).is_none());
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

    /// Returns `true` iff this location can be safely converted to a [Position].
    #[inline]
    pub const fn is_valid(self) -> bool {
        self.0 <= MAX_LOCATION
    }

    /// Return `self + rhs` returning `None` on overflow or if result exceeds [MAX_LOCATION].
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

    /// Return `self + rhs` saturating at [MAX_LOCATION].
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
    type Error = LocationError;

    /// Attempt to derive the [Location] of a given node [Position].
    ///
    /// Returns an error if the position does not correspond to an MMR leaf or if position
    /// overflow occurs.
    ///
    /// This computation is O(log2(n)) in the given position.
    #[inline]
    fn try_from(pos: Position) -> Result<Self, Self::Error> {
        // Reject positions beyond the valid MMR range. This ensures `pos + 1` won't overflow below.
        if *pos > MAX_POSITION {
            return Err(LocationError::Overflow(pos));
        }
        // Position 0 is always the first leaf at location 0.
        if *pos == 0 {
            return Ok(Self(0));
        }

        // Find the height of the perfect binary tree containing this position.
        // Safe: pos + 1 cannot overflow since pos <= MAX_POSITION (checked above).
        let start = u64::MAX >> (pos + 1).leading_zeros();
        let height = start.trailing_ones();
        // Height 0 means this position is a peak (not a leaf in a tree).
        if height == 0 {
            return Err(LocationError::NonLeaf(pos));
        }
        let mut two_h = 1 << (height - 1);
        let mut cur_node = start - 1;
        let mut leaf_loc_floor = 0u64;

        while two_h > 1 {
            if cur_node == *pos {
                return Err(LocationError::NonLeaf(pos));
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

/// Error returned when attempting to convert a [Position] to a [Location].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum LocationError {
    #[error("{0} is not a leaf")]
    NonLeaf(Position),

    #[error("{0} > MAX_LOCATION")]
    Overflow(Position),
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
    use crate::mmr::{position::Position, LocationError, MAX_POSITION};

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
            assert_eq!(err, LocationError::NonLeaf(pos));
        }
    }

    #[test]
    fn test_try_from_position_error_overflow() {
        let overflow_pos = Position::new(u64::MAX);
        let err = Location::try_from(overflow_pos).expect_err("should overflow");
        assert_eq!(err, LocationError::Overflow(overflow_pos));

        // MAX_POSITION doesn't overflow and isn't a leaf
        let result = Location::try_from(MAX_POSITION);
        assert_eq!(result, Err(LocationError::NonLeaf(MAX_POSITION)));

        let overflow_pos = MAX_POSITION + 1;
        let err = Location::try_from(overflow_pos).expect_err("should overflow");
        assert_eq!(err, LocationError::Overflow(overflow_pos));
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
    fn test_new() {
        // Valid locations
        assert!(Location::new(0).is_some());
        assert!(Location::new(1000).is_some());
        assert!(Location::new(MAX_LOCATION).is_some());

        // Invalid locations (too large)
        assert!(Location::new(MAX_LOCATION + 1).is_none());
        assert!(Location::new(u64::MAX).is_none());
    }

    #[test]
    fn test_is_valid() {
        assert!(Location::new_unchecked(0).is_valid());
        assert!(Location::new_unchecked(1000).is_valid());
        assert!(Location::new_unchecked(MAX_LOCATION).is_valid());
        assert!(Location::new_unchecked(MAX_LOCATION).is_valid());
        assert!(!Location::new_unchecked(u64::MAX).is_valid());
    }

    #[test]
    fn test_max_location_boundary() {
        // MAX_LOCATION should convert successfully
        let max_loc = Location::new_unchecked(MAX_LOCATION);
        assert!(max_loc.is_valid());
        let pos = Position::try_from(max_loc).unwrap();
        // Verify the position value
        // For MAX_LOCATION = 2^62 - 1 = 0x3FFFFFFFFFFFFFFF, popcount = 62
        // Position = 2 * (2^62 - 1) - 62 = 2^63 - 2 - 62 = 2^63 - 64
        let expected = (1u64 << 63) - 64;
        assert_eq!(*pos, expected);
    }

    #[test]
    fn test_overflow_location_returns_error() {
        // MAX_LOCATION + 1 should return error
        let over_loc = Location::new_unchecked(MAX_LOCATION + 1);
        assert!(Position::try_from(over_loc).is_err());

        // Verify the error message
        match Position::try_from(over_loc) {
            Err(crate::mmr::Error::LocationOverflow(loc)) => {
                assert_eq!(loc, over_loc);
            }
            _ => panic!("expected LocationOverflow error"),
        }
    }
}
