use super::position::Position;
use bytes::{Buf, BufMut};
use commonware_codec::{Read, ReadExt};
use core::{
    convert::TryFrom,
    fmt,
    ops::{Add, AddAssign, Deref, Range, Sub, SubAssign},
};

/// Maximum valid [Location] value for an MMB.
///
/// This limit exists because the total MMB size (number of nodes) must be representable in a u64
/// with at least one leading zero bit for validity checking. The MMB size for N leaves is:
///
/// ```text
/// MMB_size = 2*N - ilog2(N+1)
/// ```
///
/// The maximum N where `2*N - ilog2(N+1) < 2^63` is `N = 2^62 + 30`, which gives `MMB_size = 2^63 -
/// 2`. Therefore, the maximum location (0-indexed) is `2^62 + 29`.
pub const MAX_LOCATION: Location = Location(0x4000_0000_0000_001D); // 2^62 + 29

/// A [Location] is an index into an MMB's _leaves_. This is in contrast to a [Position], which is
/// an index into an MMB's _nodes_. A [Position] can be converted to a [Location] via
/// `Location::try_from(pos)`.
///
/// # Limits
///
/// While [Location] can technically hold any `u64` value, only values up to [MAX_LOCATION] are
/// considered valid. Values beyond this are invalid.
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
    /// Create a new [Location] from a raw `u64` without validation.
    ///
    /// This is an internal constructor that assumes the value is valid. For creating locations from
    /// external or untrusted sources, use [Location::new].
    #[inline]
    pub(crate) const fn new_unchecked(loc: u64) -> Self {
        Self(loc)
    }

    /// Create a new [Location] from a raw `u64`, validating it does not exceed [MAX_LOCATION].
    ///
    /// Returns `None` if `loc > MAX_LOCATION`.
    #[inline]
    pub const fn new(loc: u64) -> Option<Self> {
        if loc > MAX_LOCATION.0 {
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

    /// Returns `true` iff this location is within the valid range.
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

/// Convert a [Position] (node index) to its [Location] (leaf index) in any MMB containing it.
///
/// The mapping is stable across MMB sizes: a given leaf position always maps to the same location
/// regardless of how many additional leaves have been appended.
///
/// The physical index of leaf N is `2*N - ilog2(N+1)`. This function inverts that formula:
/// given `pos`, find `N` such that `2*N - ilog2(N+1) == pos`, or return [super::Error::NonLeaf]
/// if `pos` is a parent node.
///
/// Returns an error if the position is not a leaf or exceeds [super::MAX_POSITION].
impl TryFrom<Position> for Location {
    type Error = super::Error;

    fn try_from(pos: Position) -> Result<Self, Self::Error> {
        if !pos.is_valid() {
            return Err(super::Error::PosOutOfBounds(pos));
        }
        let p = *pos;

        // Solve 2*N - ilog2(N+1) = p for N.
        // Starting estimate: N ~ (p + ilog2(N+1)) / 2 ~ p/2. One refinement gives accuracy
        // within +/-1, so the loop body runs at most a few times.
        let mut n = p / 2;
        n = (p + (n + 1).ilog2() as u64) / 2;
        loop {
            let leaf_pos = 2 * n - (n + 1).ilog2() as u64;
            if leaf_pos == p {
                return Ok(Self::new_unchecked(n));
            }
            if leaf_pos > p {
                // p is not a leaf position (it falls between two leaf positions, so it's a parent).
                return Err(super::Error::NonLeaf(pos));
            }
            n += 1;
        }
    }
}

// Codec implementations using varint encoding for efficient storage
impl commonware_codec::Write for Location {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        commonware_codec::varint::UInt(self.0).write(buf);
    }
}

impl commonware_codec::EncodeSize for Location {
    #[inline]
    fn encode_size(&self) -> usize {
        commonware_codec::varint::UInt(self.0).encode_size()
    }
}

impl Read for Location {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let value: u64 = commonware_codec::varint::UInt::read(buf)?.into();
        Self::new(value).ok_or(commonware_codec::Error::Invalid(
            "Location",
            "value exceeds MAX_LOCATION",
        ))
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
    use super::{Location, Position, MAX_LOCATION};
    use crate::mmb::Error;

    #[test]
    fn test_checked_add() {
        let loc = Location::new_unchecked(10);
        assert_eq!(loc.checked_add(5).unwrap(), 15);

        // Overflow returns None
        assert!(Location::new_unchecked(u64::MAX).checked_add(1).is_none());

        // Exceeding MAX_LOCATION returns None
        assert!(MAX_LOCATION.checked_add(1).is_none());

        // At MAX_LOCATION is OK
        let loc = Location::new_unchecked(*MAX_LOCATION - 10);
        assert_eq!(loc.checked_add(10).unwrap(), *MAX_LOCATION);
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
            *MAX_LOCATION
        );
        assert_eq!(MAX_LOCATION.saturating_add(1), *MAX_LOCATION);
        assert_eq!(MAX_LOCATION.saturating_add(1000), *MAX_LOCATION);
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
        assert!(Location::new(*MAX_LOCATION).is_some());

        // Invalid locations (too large)
        assert!(Location::new(*MAX_LOCATION + 1).is_none());
        assert!(Location::new(u64::MAX).is_none());
    }

    #[test]
    fn test_is_valid() {
        assert!(Location::new_unchecked(0).is_valid());
        assert!(Location::new_unchecked(1000).is_valid());
        assert!(MAX_LOCATION.is_valid());
        assert!(!Location::new_unchecked(u64::MAX).is_valid());
    }

    #[test]
    fn test_max_location_boundary() {
        // MAX_LOCATION = 2^62 + 29 (max N - 1 where max N = 2^62 + 30)
        let max_n: u64 = (1u64 << 62) + 30;
        assert_eq!(*MAX_LOCATION, max_n - 1);
        assert_eq!(*MAX_LOCATION, 0x4000_0000_0000_001D);

        // Verify the MMB size for max N is valid
        let mmb_size = 2 * max_n - (max_n + 1).ilog2() as u64;
        assert_eq!(mmb_size, (1u64 << 63) - 2);
        assert_eq!(mmb_size.leading_zeros(), 1); // Top bit clear
    }

    #[test]
    fn test_read_cfg_valid_values() {
        use commonware_codec::{Encode, ReadExt};

        // Test zero
        let loc = Location::new(0).unwrap();
        let encoded = loc.encode();
        let decoded = Location::read(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, loc);

        // Test middle value
        let loc = Location::new(12345).unwrap();
        let encoded = loc.encode();
        let decoded = Location::read(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, loc);

        // Test MAX_LOCATION (boundary)
        let loc = Location::new(*MAX_LOCATION).unwrap();
        let encoded = loc.encode();
        let decoded = Location::read(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, loc);
    }

    #[test]
    fn test_read_cfg_invalid_values() {
        use commonware_codec::{Encode, ReadExt};

        // Encode MAX_LOCATION + 1 as a raw varint, then try to decode as Location
        let invalid_value = *MAX_LOCATION + 1;
        let encoded = commonware_codec::varint::UInt(invalid_value).encode();
        let result = Location::read(&mut encoded.as_ref());
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(commonware_codec::Error::Invalid("Location", _))
        ));

        // Encode u64::MAX as a raw varint
        let encoded = commonware_codec::varint::UInt(u64::MAX).encode();
        let result = Location::read(&mut encoded.as_ref());
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(commonware_codec::Error::Invalid("Location", _))
        ));
    }

    #[test]
    fn test_try_from_position() {
        // Leaf N has physical index 2*N - ilog2(N+1). These are the inverse mappings.
        const CASES: &[(Position, Location)] = &[
            (Position::new(0), Location::new_unchecked(0)), // leaf 0
            (Position::new(1), Location::new_unchecked(1)), // leaf 1
            (Position::new(3), Location::new_unchecked(2)), // leaf 2
            (Position::new(4), Location::new_unchecked(3)), // leaf 3
            (Position::new(6), Location::new_unchecked(4)), // leaf 4
            (Position::new(8), Location::new_unchecked(5)), // leaf 5
            (Position::new(10), Location::new_unchecked(6)), // leaf 6
            (Position::new(11), Location::new_unchecked(7)), // leaf 7
        ];
        for (pos, expected_loc) in CASES {
            let loc = Location::try_from(*pos).expect("should map to a leaf location");
            assert_eq!(loc, *expected_loc);
        }
    }

    #[test]
    fn test_try_from_position_non_leaf() {
        // Parent nodes in the N=8 MMB (size=13). Parent at step N has index 2*N+1-ilog2(N+1).
        const CASES: &[Position] = &[
            Position::new(2),  // parent at step 1: 3 - 1
            Position::new(5),  // parent at step 3: 7 - 2
            Position::new(7),  // parent at step 4: 9 - 2
            Position::new(9),  // parent at step 5: 11 - 2
            Position::new(12), // parent at step 7: 15 - 3
        ];
        for &pos in CASES {
            let err = Location::try_from(pos).expect_err("position is not a leaf");
            assert_eq!(err, Error::NonLeaf(pos));
        }
    }

    #[test]
    fn test_try_from_position_overflow() {
        use crate::mmb::position::MAX_POSITION;

        // MAX_POSITION is not a leaf but should not return an out-of-bounds error
        assert_eq!(
            Location::try_from(MAX_POSITION),
            Err(Error::NonLeaf(MAX_POSITION))
        );

        // MAX_POSITION + 1 is out of bounds
        let over = Position::new(*MAX_POSITION + 1);
        assert_eq!(Location::try_from(over), Err(Error::PosOutOfBounds(over)));

        let overflow_pos = Position::new(u64::MAX);
        assert_eq!(
            Location::try_from(overflow_pos),
            Err(Error::PosOutOfBounds(overflow_pos))
        );
    }

    #[test]
    fn test_roundtrip() {
        for n in 1u64..=200 {
            for loc in 0..n {
                let location = Location::new_unchecked(loc);
                let pos = Position::try_from(location).unwrap();
                let back = Location::try_from(pos).unwrap();
                assert_eq!(back, location, "N={n}, loc={loc}, pos={pos}");
            }
        }
    }
}
