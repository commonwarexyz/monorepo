use super::{location::Location, Family};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, ReadExt};
use core::{
    fmt,
    marker::PhantomData,
    ops::{Add, AddAssign, Deref, Sub, SubAssign},
};

/// A [Position] is an index into a Merkle structure's nodes.
/// This is in contrast to a [Location], which is an index into the structure's _leaves_.
pub struct Position<F: Family>(u64, PhantomData<F>);

#[cfg(feature = "arbitrary")]
impl<F: Family> arbitrary::Arbitrary<'_> for Position<F> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let value = u.int_in_range(0..=F::MAX_POSITION.as_u64())?;
        Ok(Self::new(value))
    }
}

impl<F: Family> Position<F> {
    /// Return a new [Position] from a raw `u64`.
    #[inline]
    pub const fn new(pos: u64) -> Self {
        Self(pos, PhantomData)
    }

    /// Return the underlying `u64` value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns `true` iff this value is within the valid range (`<= MAX`).
    /// This covers both node indices (`< MAX`) and node counts (`<= MAX`).
    #[inline]
    pub const fn is_valid(self) -> bool {
        self.0 <= F::MAX_POSITION.as_u64()
    }

    /// Return `self + rhs` returning `None` on overflow or if result exceeds the maximum.
    #[inline]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(value) => {
                if value <= F::MAX_POSITION.as_u64() {
                    Some(Self::new(value))
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
            Some(value) => Some(Self::new(value)),
            None => None,
        }
    }

    /// Return `self + rhs` saturating at the maximum.
    #[inline]
    pub const fn saturating_add(self, rhs: u64) -> Self {
        let result = self.0.saturating_add(rhs);
        if result > F::MAX_POSITION.as_u64() {
            F::MAX_POSITION
        } else {
            Self::new(result)
        }
    }

    /// Return `self - rhs` saturating at zero.
    #[inline]
    pub const fn saturating_sub(self, rhs: u64) -> Self {
        Self::new(self.0.saturating_sub(rhs))
    }

    /// Returns whether this is a valid size for this Merkle structure.
    #[inline]
    pub fn is_valid_size(self) -> bool {
        F::is_valid_size(self)
    }
}

// --- Manual trait implementations (to avoid unnecessary bounds on F) ---

impl<F: Family> Copy for Position<F> {}

impl<F: Family> Clone for Position<F> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: Family> PartialEq for Position<F> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<F: Family> Eq for Position<F> {}

impl<F: Family> PartialOrd for Position<F> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: Family> Ord for Position<F> {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<F: Family> core::hash::Hash for Position<F> {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<F: Family> Default for Position<F> {
    #[inline]
    fn default() -> Self {
        Self::new(0)
    }
}

impl<F: Family> fmt::Debug for Position<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Position").field(&self.0).finish()
    }
}

impl<F: Family> fmt::Display for Position<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Position({})", self.0)
    }
}

impl<F: Family> Deref for Position<F> {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: Family> AsRef<u64> for Position<F> {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

impl<F: Family> From<u64> for Position<F> {
    #[inline]
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl<F: Family> From<usize> for Position<F> {
    #[inline]
    fn from(value: usize) -> Self {
        Self::new(value as u64)
    }
}

impl<F: Family> From<Position<F>> for u64 {
    #[inline]
    fn from(position: Position<F>) -> Self {
        *position
    }
}

/// Try to convert a leaf [Location] to its node [Position].
///
/// Returns [`super::Error::LocationOverflow`] if `!loc.is_valid()`.
impl<F: Family> TryFrom<Location<F>> for Position<F> {
    type Error = super::Error<F>;

    #[inline]
    fn try_from(loc: Location<F>) -> Result<Self, Self::Error> {
        if !loc.is_valid() {
            return Err(super::Error::LocationOverflow(loc));
        }
        Ok(F::location_to_position(loc))
    }
}

// --- Arithmetic operators ---

/// Add two positions together.
///
/// # Panics
///
/// Panics if the result overflows.
impl<F: Family> Add for Position<F> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self::new(self.0 + rhs.0)
    }
}

/// Add a position and a `u64`.
///
/// # Panics
///
/// Panics if the result overflows.
impl<F: Family> Add<u64> for Position<F> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u64) -> Self::Output {
        Self::new(self.0 + rhs)
    }
}

/// Subtract two positions.
///
/// # Panics
///
/// Panics if the result underflows.
impl<F: Family> Sub for Position<F> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self::new(self.0 - rhs.0)
    }
}

/// Subtract a `u64` from a position.
///
/// # Panics
///
/// Panics if the result underflows.
impl<F: Family> Sub<u64> for Position<F> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: u64) -> Self::Output {
        Self::new(*self - rhs)
    }
}

impl<F: Family> PartialEq<u64> for Position<F> {
    #[inline]
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl<F: Family> PartialOrd<u64> for Position<F> {
    #[inline]
    fn partial_cmp(&self, other: &u64) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl<F: Family> PartialEq<Position<F>> for u64 {
    #[inline]
    fn eq(&self, other: &Position<F>) -> bool {
        *self == other.0
    }
}

impl<F: Family> PartialOrd<Position<F>> for u64 {
    #[inline]
    fn partial_cmp(&self, other: &Position<F>) -> Option<core::cmp::Ordering> {
        self.partial_cmp(&other.0)
    }
}

/// Add a `u64` to a position.
///
/// # Panics
///
/// Panics if the result overflows.
impl<F: Family> AddAssign<u64> for Position<F> {
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
impl<F: Family> SubAssign<u64> for Position<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

// --- Codec implementations using varint encoding ---

impl<F: Family> commonware_codec::Write for Position<F> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.0).write(buf);
    }
}

impl<F: Family> commonware_codec::EncodeSize for Position<F> {
    #[inline]
    fn encode_size(&self) -> usize {
        UInt(self.0).encode_size()
    }
}

impl<F: Family> commonware_codec::Read for Position<F> {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let pos = Self::new(UInt::read(buf)?.into());
        if pos.is_valid() {
            Ok(pos)
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
    use super::{Location as GenericLocation, Position as GenericPosition};
    use crate::{
        merkle::Family as _,
        mmr::{mem::Mmr, Family as MmrFamily, StandardHasher as Standard},
    };
    use commonware_cryptography::Sha256;

    type Location = GenericLocation<MmrFamily>;
    type Position = GenericPosition<MmrFamily>;

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
        assert!(MmrFamily::MAX_POSITION.checked_add(1).is_none());
        assert!(Position::new(*MmrFamily::MAX_POSITION - 5)
            .checked_add(10)
            .is_none());

        // At MAX_POSITION is OK
        assert_eq!(
            Position::new(*MmrFamily::MAX_POSITION - 10)
                .checked_add(10)
                .unwrap(),
            MmrFamily::MAX_POSITION
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
        assert_eq!(
            Position::new(u64::MAX).saturating_add(1),
            MmrFamily::MAX_POSITION
        );
        assert_eq!(
            MmrFamily::MAX_POSITION.saturating_add(1),
            MmrFamily::MAX_POSITION
        );
        assert_eq!(
            MmrFamily::MAX_POSITION.saturating_add(1000),
            MmrFamily::MAX_POSITION
        );
        assert_eq!(
            Position::new(*MmrFamily::MAX_POSITION - 5).saturating_add(10),
            MmrFamily::MAX_POSITION
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
        // MAX_POSITION = max MMR size = 2^63 - 1 (for 2^62 leaves).
        let max_leaves = 1u64 << 62;
        let max_size = 2 * max_leaves - 1; // 2^63 - 1
        assert_eq!(*MmrFamily::MAX_POSITION, max_size);
        assert_eq!(*MmrFamily::MAX_POSITION, (1u64 << 63) - 1);
        assert_eq!(max_size.leading_zeros(), 1); // top bit clear

        // One more leaf would overflow: size = 2^63, top bit set.
        let overflow_size = 2 * (max_leaves + 1) - 1;
        assert_eq!(overflow_size.leading_zeros(), 0);

        // MAX_LOCATION converts to MAX_POSITION.
        let pos = Position::try_from(MmrFamily::MAX_LOCATION).unwrap();
        assert_eq!(pos, MmrFamily::MAX_POSITION);
        assert!(pos.is_valid());
    }

    #[test]
    fn test_is_valid_size() {
        // Build an MMR one node at a time and check that the validity check is correct for all
        // sizes up to the current size.
        let mut size_to_check = Position::new(0);
        let mut hasher = Standard::<Sha256>::new();
        let mut mmr = Mmr::new(&mut hasher);
        let digest = [1u8; 32];
        for _i in 0..10000 {
            while size_to_check != mmr.size() {
                assert!(
                    !size_to_check.is_valid_size(),
                    "size_to_check: {} {}",
                    size_to_check,
                    mmr.size()
                );
                size_to_check += 1;
            }
            assert!(size_to_check.is_valid_size());
            let changeset = mmr
                .new_batch()
                .add(&mut hasher, &digest)
                .merkleize(&mut hasher)
                .finalize();
            mmr.apply(changeset).unwrap();
            size_to_check += 1;
        }

        // Test overflow boundaries.
        assert!(!Position::new(u64::MAX).is_valid_size());
        assert!(Position::new(u64::MAX >> 1).is_valid_size()); // 2^63 - 1 = MAX_POSITION
        assert!(!Position::new((u64::MAX >> 1) + 1).is_valid_size());
        assert!(MmrFamily::MAX_POSITION.is_valid_size()); // MAX_POSITION is the largest valid MMR size
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
        let pos = MmrFamily::MAX_POSITION;
        let encoded = pos.encode();
        let decoded = Position::read(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, pos);
    }

    #[test]
    fn test_read_cfg_invalid_values() {
        use commonware_codec::{varint::UInt, Encode, ReadExt};

        // Encode MAX_POSITION + 1 as a raw varint, then try to decode as Position
        let invalid_value = *MmrFamily::MAX_POSITION + 1;
        let encoded = UInt(invalid_value).encode();
        let result = Position::read(&mut encoded.as_ref());
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(commonware_codec::Error::Invalid("Position", _))
        ));

        // Encode u64::MAX as a raw varint
        let encoded = UInt(u64::MAX).encode();
        let result = Position::read(&mut encoded.as_ref());
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(commonware_codec::Error::Invalid("Position", _))
        ));
    }
}
