use super::location::Location;
use bytes::{Buf, BufMut};
use commonware_codec::ReadExt;
use core::{
    fmt,
    ops::{Add, AddAssign, Deref, Sub, SubAssign},
};

/// Maximum valid [Position] value that can exist in a valid MMB.
///
/// For N leaves, the MMB size is `2*N - ilog2(N+1)`. We require the size to have
/// at least one leading zero bit (i.e. `size < 2^63`). The maximum N satisfying
/// this is `2^62 + 30`, giving `size = 2^63 - 2` and `MAX_POSITION = 2^63 - 3`.
pub const MAX_POSITION: Position = Position::new(0x7FFF_FFFF_FFFF_FFFD); // (1 << 63) - 3

/// A [Position] is an index into an MMB's nodes.
/// This is in contrast to a [Location], which is an index into an MMB's _leaves_.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug)]
pub struct Position(u64);

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Position {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let value = u.int_in_range(0..=*MAX_POSITION)?;
        Ok(Self(value))
    }
}

impl Position {
    /// Return a new [Position] from a raw `u64`.
    #[inline]
    pub const fn new(pos: u64) -> Self {
        Self(pos)
    }

    /// Return the underlying `u64` value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Return `self + rhs` returning `None` on overflow or if result exceeds [MAX_POSITION].
    #[inline]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(value) => {
                if value <= MAX_POSITION.0 {
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

    /// Return `self + rhs` saturating at [MAX_POSITION].
    #[inline]
    pub const fn saturating_add(self, rhs: u64) -> Self {
        let result = self.0.saturating_add(rhs);
        if result > MAX_POSITION.0 {
            MAX_POSITION
        } else {
            Self(result)
        }
    }

    /// Return `self - rhs` saturating at zero.
    #[inline]
    pub const fn saturating_sub(self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }

    /// Returns `true` iff this position is within the valid range.
    #[inline]
    pub const fn is_valid(self) -> bool {
        self.0 <= MAX_POSITION.0
    }

    /// Returns whether this is a valid MMB size.
    ///
    /// An MMB with N leaves has size `2*N - ilog2(N+1)`. This method checks whether the
    /// given value corresponds to such a size for some positive integer N, or is zero.
    #[inline]
    pub const fn is_mmb_size(self) -> bool {
        super::iterator::leaves_for_size(self.0).is_some()
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

/// Try to convert a [Location] to a [Position].
///
/// The mapping is stable across MMB sizes: a given location always maps to the same position
/// regardless of how many additional leaves have been appended.
///
/// The physical index of leaf N (0-indexed) is `2*N - ilog2(N+1)`.
///
/// Returns an error if `loc` > [super::MAX_LOCATION].
impl TryFrom<Location> for Position {
    type Error = super::Error;

    #[inline]
    fn try_from(loc: Location) -> Result<Self, Self::Error> {
        if !loc.is_valid() {
            return Err(super::Error::LocOutOfBounds(loc));
        }
        let n = *loc;
        Ok(Self::new(2 * n - (n + 1).ilog2() as u64))
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

// Codec implementations using varint encoding for efficient storage
impl commonware_codec::Write for Position {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        commonware_codec::varint::UInt(self.0).write(buf);
    }
}

impl commonware_codec::EncodeSize for Position {
    #[inline]
    fn encode_size(&self) -> usize {
        commonware_codec::varint::UInt(self.0).encode_size()
    }
}

impl commonware_codec::Read for Position {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let value: u64 = commonware_codec::varint::UInt::read(buf)?.into();
        if value <= *MAX_POSITION {
            Ok(Self(value))
        } else {
            Err(commonware_codec::Error::Invalid(
                "Position",
                "value exceeds MAX_POSITION",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Location, Position, MAX_POSITION};
    use crate::mmb::location::MAX_LOCATION;

    #[test]
    fn test_checked_add() {
        let pos = Position::new(10);
        assert_eq!(pos.checked_add(5).unwrap(), 15);

        // Overflow returns None
        assert!(Position::new(u64::MAX).checked_add(1).is_none());

        // Exceeding MAX_POSITION returns None
        assert!(MAX_POSITION.checked_add(1).is_none());
        assert!(Position::new(*MAX_POSITION - 5).checked_add(10).is_none());

        // At MAX_POSITION is OK
        assert_eq!(
            Position::new(*MAX_POSITION - 10).checked_add(10).unwrap(),
            MAX_POSITION
        );
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

        // Saturates at MAX_POSITION, not u64::MAX
        assert_eq!(Position::new(u64::MAX).saturating_add(1), MAX_POSITION);
        assert_eq!(MAX_POSITION.saturating_add(1), MAX_POSITION);
        assert_eq!(MAX_POSITION.saturating_add(1000), MAX_POSITION);
        assert_eq!(
            Position::new(*MAX_POSITION - 5).saturating_add(10),
            MAX_POSITION
        );
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
    fn test_max_position() {
        // For MMB: size = 2*N - ilog2(N+1), must have size < 2^63
        // Max N = 2^62 + 30, giving size = 2^63 - 2, MAX_POSITION = 2^63 - 3
        let max_n: u64 = (1u64 << 62) + 30;
        let mmb_size = 2 * max_n - (max_n + 1).ilog2() as u64;
        assert_eq!(mmb_size, (1u64 << 63) - 2);
        assert_eq!(mmb_size.leading_zeros(), 1); // Top bit clear

        let expected_max_pos = mmb_size - 1;
        assert_eq!(MAX_POSITION, expected_max_pos);
        assert_eq!(MAX_POSITION, (1u64 << 63) - 3);

        // N + 1 would overflow
        let next_n = max_n + 1;
        let next_size = 2 * next_n - (next_n + 1).ilog2() as u64;
        assert_eq!(next_size, 1u64 << 63); // Top bit set, invalid
        assert_eq!(next_size.leading_zeros(), 0);

        // Verify MAX_LOCATION is consistent: max leaf index = max_n - 1
        assert_eq!(*MAX_LOCATION, max_n - 1);
    }

    #[test]
    fn test_is_valid() {
        assert!(Position::new(0).is_valid());
        assert!(Position::new(1000).is_valid());
        assert!(MAX_POSITION.is_valid());
        assert!(!Position::new(u64::MAX).is_valid());
    }

    #[test]
    fn test_is_mmb_size() {
        // Helper: compute MMB size for N leaves
        fn mmb_size(n: u64) -> u64 {
            2 * n - (n + 1).ilog2() as u64
        }

        // Size 0 is valid (empty MMB)
        assert!(Position::new(0).is_mmb_size());

        // Check sizes for small N values
        let mut size_to_check = Position::new(1);
        for n in 1u64..=10000 {
            let s = mmb_size(n);
            while *size_to_check < s {
                assert!(
                    !size_to_check.is_mmb_size(),
                    "size {} should not be a valid MMB size (next valid is {} for N={})",
                    size_to_check,
                    s,
                    n
                );
                size_to_check += 1;
            }
            assert!(
                size_to_check.is_mmb_size(),
                "size {} should be a valid MMB size for N={}",
                s,
                n
            );
            size_to_check += 1;
        }

        // Test overflow boundaries
        assert!(!Position::new(u64::MAX).is_mmb_size());
        assert!(!Position::new((u64::MAX >> 1) + 1).is_mmb_size());

        // Max valid MMB size
        let max_n: u64 = (1u64 << 62) + 30;
        let max_size = mmb_size(max_n);
        assert!(Position::new(max_size).is_mmb_size());
        assert!(!Position::new(max_size + 1).is_mmb_size());
    }

    #[test]
    fn test_read_cfg_valid_values() {
        use commonware_codec::{Encode, ReadExt};

        // Test zero
        let pos = Position::new(0);
        let encoded = pos.encode();
        let decoded = Position::read(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, pos);

        // Test middle value
        let pos = Position::new(12345);
        let encoded = pos.encode();
        let decoded = Position::read(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, pos);

        // Test MAX_POSITION (boundary)
        let pos = MAX_POSITION;
        let encoded = pos.encode();
        let decoded = Position::read(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, pos);
    }

    #[test]
    fn test_read_cfg_invalid_values() {
        use commonware_codec::{Encode, ReadExt};

        // Encode MAX_POSITION + 1 as a raw varint, then try to decode as Position
        let invalid_value = *MAX_POSITION + 1;
        let encoded = commonware_codec::varint::UInt(invalid_value).encode();
        let result = Position::read(&mut encoded.as_ref());
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(commonware_codec::Error::Invalid("Position", _))
        ));

        // Encode u64::MAX as a raw varint
        let encoded = commonware_codec::varint::UInt(u64::MAX).encode();
        let result = Position::read(&mut encoded.as_ref());
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(commonware_codec::Error::Invalid("Position", _))
        ));
    }

    #[test]
    fn test_try_from_location() {
        // Test vectors: leaf N has physical index 2*N - ilog2(N+1).
        const CASES: &[(Location, Position)] = &[
            (Location::new_unchecked(0), Position::new(0)), // 0 - 0
            (Location::new_unchecked(1), Position::new(1)), // 2 - 1
            (Location::new_unchecked(2), Position::new(3)), // 4 - 1
            (Location::new_unchecked(3), Position::new(4)), // 6 - 2
            (Location::new_unchecked(4), Position::new(6)), // 8 - 2
            (Location::new_unchecked(5), Position::new(8)), // 10 - 2
            (Location::new_unchecked(6), Position::new(10)), // 12 - 2
            (Location::new_unchecked(7), Position::new(11)), // 14 - 3
        ];
        for (loc, expected_pos) in CASES {
            let pos = Position::try_from(*loc).unwrap();
            assert_eq!(pos, *expected_pos);
        }

        // MAX_LOCATION is valid
        assert!(Position::try_from(MAX_LOCATION).is_ok());
    }

    #[test]
    fn test_try_from_location_invalid() {
        use crate::mmb::Error;

        // MAX_LOCATION + 1 is invalid
        let over = Location::new_unchecked(*MAX_LOCATION + 1);
        assert_eq!(Position::try_from(over), Err(Error::LocOutOfBounds(over)));

        let overflow_loc = Location::new_unchecked(u64::MAX);
        assert_eq!(
            Position::try_from(overflow_loc),
            Err(Error::LocOutOfBounds(overflow_loc))
        );
    }
}
