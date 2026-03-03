use super::position::Position;
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Read, ReadExt};
use core::{
    convert::TryFrom,
    fmt,
    ops::{Add, AddAssign, Deref, Range, Sub, SubAssign},
};
use thiserror::Error;

/// Maximum valid [Location] value: the largest leaf count an MMR can hold.
///
/// An MMR with N leaves has `2*N - popcount(N)` nodes. We require `size < 2^63` (top bit clear).
/// The worst case is `N = 2^62` (a power of two, `popcount = 1`):
///
/// ```text
/// 2*N - 1 < 2^63  =>  N <= 2^62
/// ```
///
/// Therefore the maximum leaf count is `2^62` and `MAX_LOCATION = 2^62`.
///
/// Leaf indices are 0-based, so valid indices satisfy `loc < MAX_LOCATION` (i.e., `0..=2^62 - 1`).
/// Leaf counts and exclusive range-ends satisfy `loc <= MAX_LOCATION`.
pub const MAX_LOCATION: Location = Location(0x4000_0000_0000_0000); // 2^62

/// A [Location] is a leaf index or leaf count in an MMR.
/// This is in contrast to a [Position], which is a node index or node count.
///
/// # Limits
///
/// Values up to [MAX_LOCATION] are valid (see [Location::is_valid]). As a 0-based leaf index,
/// valid indices are `0..MAX_LOCATION - 1`. As a leaf count or exclusive range-end, the maximum
/// is `MAX_LOCATION` itself.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug)]
pub struct Location(u64);

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Location {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let value = u.int_in_range(0..=*MAX_LOCATION)?;
        Ok(Self(value))
    }
}

impl Location {
    /// Return a new [Location] from a raw `u64`.
    #[inline]
    pub const fn new(loc: u64) -> Self {
        Self(loc)
    }

    /// Return the underlying `u64` value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns `true` iff this value is within the valid range (`<= MAX_LOCATION`).
    /// This covers both leaf indices (`< MAX_LOCATION`) and leaf counts (`<= MAX_LOCATION`).
    #[inline]
    pub const fn is_valid(self) -> bool {
        self.0 <= MAX_LOCATION.0
    }

    /// Return `self + rhs` returning `None` on overflow or if result exceeds [MAX_LOCATION].
    #[inline]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(value) => {
                if value <= MAX_LOCATION.0 {
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
        if result > MAX_LOCATION.0 {
            MAX_LOCATION
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
        Self::new(value)
    }
}

impl From<usize> for Location {
    #[inline]
    fn from(value: usize) -> Self {
        Self::new(value as u64)
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

// Codec implementations using varint encoding for efficient storage
impl commonware_codec::Write for Location {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.0).write(buf);
    }
}

impl commonware_codec::EncodeSize for Location {
    #[inline]
    fn encode_size(&self) -> usize {
        UInt(self.0).encode_size()
    }
}

impl Read for Location {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let value: u64 = UInt::read(buf)?.into();
        let loc = Self::new(value);
        if loc.is_valid() {
            Ok(loc)
        } else {
            Err(commonware_codec::Error::Invalid(
                "Location",
                "value exceeds MAX_LOCATION",
            ))
        }
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
        // Reject positions beyond the valid range.
        if !pos.is_valid() {
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
            (Position::new(0), Location::new(0)),
            (Position::new(1), Location::new(1)),
            (Position::new(3), Location::new(2)),
            (Position::new(4), Location::new(3)),
            (Position::new(7), Location::new(4)),
            (Position::new(8), Location::new(5)),
            (Position::new(10), Location::new(6)),
            (Position::new(11), Location::new(7)),
            (Position::new(15), Location::new(8)),
            (Position::new(16), Location::new(9)),
            (Position::new(18), Location::new(10)),
            (Position::new(19), Location::new(11)),
            (Position::new(22), Location::new(12)),
            (Position::new(23), Location::new(13)),
            (Position::new(25), Location::new(14)),
            (Position::new(26), Location::new(15)),
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

        // MAX_POSITION is the leaf at MAX_LOCATION
        let result = Location::try_from(MAX_POSITION);
        assert_eq!(result, Ok(MAX_LOCATION));

        let overflow_pos = MAX_POSITION + 1;
        let err = Location::try_from(overflow_pos).expect_err("should overflow");
        assert_eq!(err, LocationError::Overflow(overflow_pos));
    }

    #[test]
    fn test_checked_add() {
        let loc = Location::new(10);
        assert_eq!(loc.checked_add(5).unwrap(), 15);

        // Overflow returns None
        assert!(Location::new(u64::MAX).checked_add(1).is_none());

        // Exceeding MAX_LOCATION returns None
        assert!(MAX_LOCATION.checked_add(1).is_none());

        // At MAX_LOCATION is OK
        let loc = Location::new(*MAX_LOCATION - 10);
        assert_eq!(loc.checked_add(10).unwrap(), *MAX_LOCATION);
    }

    #[test]
    fn test_checked_sub() {
        let loc = Location::new(10);
        assert_eq!(loc.checked_sub(5).unwrap(), 5);
        assert!(loc.checked_sub(11).is_none());
    }

    #[test]
    fn test_saturating_add() {
        let loc = Location::new(10);
        assert_eq!(loc.saturating_add(5), 15);

        // Saturates at MAX_LOCATION, not u64::MAX
        assert_eq!(Location::new(u64::MAX).saturating_add(1), MAX_LOCATION);
        assert_eq!(MAX_LOCATION.saturating_add(1), MAX_LOCATION);
        assert_eq!(MAX_LOCATION.saturating_add(1000), MAX_LOCATION);
    }

    #[test]
    fn test_saturating_sub() {
        let loc = Location::new(10);
        assert_eq!(loc.saturating_sub(5), 5);
        assert_eq!(Location::new(0).saturating_sub(1), 0);
    }

    #[test]
    fn test_display() {
        let location = Location::new(42);
        assert_eq!(location.to_string(), "Location(42)");
    }

    #[test]
    fn test_add() {
        let loc1 = Location::new(10);
        let loc2 = Location::new(5);
        assert_eq!((loc1 + loc2), 15);
    }

    #[test]
    fn test_sub() {
        let loc1 = Location::new(10);
        let loc2 = Location::new(3);
        assert_eq!((loc1 - loc2), 7);
    }

    #[test]
    fn test_comparison_with_u64() {
        let loc = Location::new(42);

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
        let mut loc = Location::new(10);

        // Test add assignment
        loc += 5;
        assert_eq!(loc, 15u64);

        // Test sub assignment
        loc -= 3;
        assert_eq!(loc, 12u64);
    }

    #[test]
    fn test_is_valid() {
        assert!(Location::new(0).is_valid());
        assert!(Location::new(1000).is_valid());
        assert!(MAX_LOCATION.is_valid());
        assert!(!Location::new(u64::MAX).is_valid());
    }

    #[test]
    fn test_max_location_boundary() {
        // MAX_LOCATION (2^62) is the max leaf count. It should be valid and convert to
        // MAX_POSITION (2^63 - 1).
        assert!(MAX_LOCATION.is_valid());
        let pos = Position::try_from(MAX_LOCATION).unwrap();
        assert_eq!(pos, crate::mmr::MAX_POSITION);
        assert!(pos.is_valid());

        // MAX_POSITION converts back to MAX_LOCATION (they are the same leaf).
        let loc = Location::try_from(pos).unwrap();
        assert_eq!(loc, MAX_LOCATION);
    }

    #[test]
    fn test_overflow_location_returns_error() {
        // MAX_LOCATION + 1 exceeds the valid range
        let over_loc = Location::new(*MAX_LOCATION + 1);
        assert!(!over_loc.is_valid());
        assert!(Position::try_from(over_loc).is_err());

        match Position::try_from(over_loc) {
            Err(crate::mmr::Error::LocationOverflow(loc)) => {
                assert_eq!(loc, over_loc);
            }
            _ => panic!("expected LocationOverflow error"),
        }
    }

    #[test]
    fn test_read_cfg_valid_values() {
        use commonware_codec::{Encode, ReadExt};

        // Test zero
        let loc = Location::new(0);
        let encoded = loc.encode();
        let decoded = Location::read(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, loc);

        // Test middle value
        let loc = Location::new(12345);
        let encoded = loc.encode();
        let decoded = Location::read(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, loc);

        // Test MAX_LOCATION (boundary)
        let encoded = MAX_LOCATION.encode();
        let decoded = Location::read(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, MAX_LOCATION);
    }

    #[test]
    fn test_read_cfg_invalid_values() {
        use commonware_codec::{varint::UInt, Encode, ReadExt};

        // Encode MAX_LOCATION + 1 as a raw varint, then try to decode as Location
        let invalid_value = *MAX_LOCATION + 1;
        let encoded = UInt(invalid_value).encode();
        let result = Location::read(&mut encoded.as_ref());
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(commonware_codec::Error::Invalid("Location", _))
        ));

        // Encode u64::MAX as a raw varint
        let encoded = UInt(u64::MAX).encode();
        let result = Location::read(&mut encoded.as_ref());
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(commonware_codec::Error::Invalid("Location", _))
        ));
    }
}
