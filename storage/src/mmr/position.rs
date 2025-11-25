use super::location::Location;
use core::{
    fmt,
    ops::{Add, AddAssign, Deref, Sub, SubAssign},
};

/// Maximum valid [Position] value that can exist in a valid MMR.
///
/// This value corresponds to the last node in an MMR with the maximum number of leaves.
pub const MAX_POSITION: Position = Position::new(0x7FFFFFFFFFFFFFFE); // (1 << 63) - 2

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

    /// Returns whether this is a valid MMR size.
    ///
    /// The implementation verifies that (1) the size won't result in overflow and (2) peaks in the
    /// MMR of the given size have strictly decreasing height, which is a necessary condition for
    /// MMR validity.
    #[inline]
    pub const fn is_mmr_size(self) -> bool {
        if self.0 == 0 {
            return true;
        }
        let leading_zeros = self.0.leading_zeros();
        if leading_zeros == 0 {
            // size overflow
            return false;
        }
        let start = u64::MAX >> leading_zeros;
        let mut two_h = 1 << start.trailing_ones();
        let mut node_pos = start.checked_sub(1).expect("start > 0 because size != 0");
        while two_h > 1 {
            if node_pos < self.0 {
                if two_h == 2 {
                    // If this peak is a leaf yet there are more nodes remaining, then this MMR is
                    // invalid.
                    return node_pos == self.0 - 1;
                }
                // move to the right sibling
                node_pos += two_h - 1;
                if node_pos < self.0 {
                    // If the right sibling is in the MMR, then it is invalid.
                    return false;
                }
                continue;
            }
            // descend to the left child
            two_h >>= 1;
            node_pos -= two_h;
        }
        true
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
/// Returns an error if `loc` > [super::MAX_LOCATION].
///
/// # Examples
///
/// ```
/// use commonware_storage::mmr::{Location, Position, MAX_LOCATION};
/// use core::convert::TryFrom;
///
/// let loc = Location::new(5).unwrap();
/// let pos = Position::try_from(loc).unwrap();
/// assert_eq!(pos, Position::new(8));
///
/// // Invalid locations return error  
/// assert!(Location::new(MAX_LOCATION + 1).is_none());
/// ```
impl TryFrom<Location> for Position {
    type Error = super::Error;

    #[inline]
    fn try_from(loc: Location) -> Result<Self, Self::Error> {
        if !loc.is_valid() {
            return Err(super::Error::LocationOverflow(loc));
        }
        // This will never underflow since 2*n >= count_ones(n).
        let loc_val = *loc;
        Ok(Self(
            loc_val
                .checked_mul(2)
                .expect("should not overflow for valid location")
                - loc_val.count_ones() as u64,
        ))
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
    use crate::mmr::{mem::CleanMmr, StandardHasher as Standard, MAX_LOCATION, MAX_POSITION};
    use commonware_cryptography::Sha256;

    // Test that the [Position::from] function returns the correct position for leaf locations.
    #[test]
    fn test_from_location() {
        const CASES: &[(Location, Position)] = &[
            (Location::new_unchecked(0), Position::new(0)),
            (Location::new_unchecked(1), Position::new(1)),
            (Location::new_unchecked(2), Position::new(3)),
            (Location::new_unchecked(3), Position::new(4)),
            (Location::new_unchecked(4), Position::new(7)),
            (Location::new_unchecked(5), Position::new(8)),
            (Location::new_unchecked(6), Position::new(10)),
            (Location::new_unchecked(7), Position::new(11)),
            (Location::new_unchecked(8), Position::new(15)),
            (Location::new_unchecked(9), Position::new(16)),
            (Location::new_unchecked(10), Position::new(18)),
            (Location::new_unchecked(11), Position::new(19)),
            (Location::new_unchecked(12), Position::new(22)),
            (Location::new_unchecked(13), Position::new(23)),
            (Location::new_unchecked(14), Position::new(25)),
            (Location::new_unchecked(15), Position::new(26)),
        ];
        for (loc, expected_pos) in CASES {
            let pos = Position::try_from(*loc).unwrap();
            assert_eq!(pos, *expected_pos);
        }
    }

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
        // The constraint is: MMR_size must have top bit clear (< 2^63)
        // For N leaves: MMR_size = 2*N - popcount(N)
        // Worst case (maximum size) is when N is a power of 2: MMR_size = 2*N - 1

        // Maximum N where 2*N - 1 < 2^63:
        //   2*N - 1 < 2^63
        //   2*N < 2^63 + 1
        //   N <= 2^62
        let max_leaves = 1u64 << 62;

        // For N = 2^62 leaves:
        // MMR_size = 2 * 2^62 - 1 = 2^63 - 1
        let mmr_size_at_max = 2 * max_leaves - 1;
        assert_eq!(mmr_size_at_max, (1u64 << 63) - 1);
        assert_eq!(mmr_size_at_max.leading_zeros(), 1); // Top bit clear ✓

        // Last position (0-indexed) = MMR_size - 1 = 2^63 - 2
        let expected_max_pos = mmr_size_at_max - 1;
        assert_eq!(MAX_POSITION, expected_max_pos);
        assert_eq!(MAX_POSITION, (1u64 << 63) - 2);

        // Verify the constraint: a position at MAX_POSITION + 1 would require
        // an MMR_size >= 2^63, which violates the "top bit clear" requirement
        let hypothetical_mmr_size = MAX_POSITION + 2; // Would need this many nodes
        assert_eq!(hypothetical_mmr_size, 1u64 << 63);
        assert_eq!(hypothetical_mmr_size.leading_zeros(), 0); // Top bit NOT clear ✗

        // Verify relationship with MAX_LOCATION
        // Converting MAX_LOCATION to position should give a value < MAX_POSITION
        let max_loc = Location::new_unchecked(MAX_LOCATION);
        let last_leaf_pos = Position::try_from(max_loc).unwrap();
        assert!(*last_leaf_pos < MAX_POSITION);
    }

    #[test]
    fn test_is_mmr_size() {
        // Build an MMR one node at a time and check that the validity check is correct for all
        // sizes up to the current size.
        let mut size_to_check = Position::new(0);
        let mut hasher = Standard::<Sha256>::new();
        let mut mmr = CleanMmr::new(&mut hasher);
        let digest = [1u8; 32];
        for _i in 0..10000 {
            while size_to_check != mmr.size() {
                assert!(
                    !size_to_check.is_mmr_size(),
                    "size_to_check: {} {}",
                    size_to_check,
                    mmr.size()
                );
                size_to_check += 1;
            }
            assert!(size_to_check.is_mmr_size());
            mmr.add(&mut hasher, &digest);
            size_to_check += 1;
        }

        // Test overflow boundaries.
        assert!(!Position::new(u64::MAX).is_mmr_size());
        assert!(Position::new(u64::MAX >> 1).is_mmr_size());
        assert!(!Position::new((u64::MAX >> 1) + 1).is_mmr_size());
        assert!(!MAX_POSITION.is_mmr_size());
    }
}
