use super::{location::Location, LocationConversionError, MerkleFamily};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, ReadExt};
use core::{
    fmt,
    marker::PhantomData,
    ops::{Add, AddAssign, Deref, Sub, SubAssign},
};

/// A [Position] is an index into a Merkle structure's nodes.
/// This is in contrast to a [Location], which is an index into the structure's _leaves_.
pub struct Position<F: MerkleFamily>(u64, PhantomData<F>);

#[cfg(feature = "arbitrary")]
impl<F: MerkleFamily> arbitrary::Arbitrary<'_> for Position<F> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let value = u.int_in_range(0..=F::MAX_POSITION)?;
        Ok(Self(value, PhantomData))
    }
}

impl<F: MerkleFamily> Position<F> {
    /// The maximum valid [Position] for this Merkle family.
    pub const MAX: Self = Self(F::MAX_POSITION, PhantomData);

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
        self.0 <= F::MAX_POSITION
    }

    /// Return `self + rhs` returning `None` on overflow or if result exceeds the maximum.
    #[inline]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(value) => {
                if value <= F::MAX_POSITION {
                    Some(Self(value, PhantomData))
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
            Some(value) => Some(Self(value, PhantomData)),
            None => None,
        }
    }

    /// Return `self + rhs` saturating at the maximum.
    #[inline]
    pub const fn saturating_add(self, rhs: u64) -> Self {
        let result = self.0.saturating_add(rhs);
        if result > F::MAX_POSITION {
            Self::MAX
        } else {
            Self(result, PhantomData)
        }
    }

    /// Return `self - rhs` saturating at zero.
    #[inline]
    pub const fn saturating_sub(self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs), PhantomData)
    }

    /// Returns whether this is a valid size for this Merkle structure.
    #[inline]
    pub fn is_valid_size(self) -> bool {
        F::is_valid_size(self.0)
    }
}

// --- Manual trait implementations (to avoid unnecessary bounds on F) ---

impl<F: MerkleFamily> Copy for Position<F> {}

impl<F: MerkleFamily> Clone for Position<F> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: MerkleFamily> PartialEq for Position<F> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<F: MerkleFamily> Eq for Position<F> {}

impl<F: MerkleFamily> PartialOrd for Position<F> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: MerkleFamily> Ord for Position<F> {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<F: MerkleFamily> core::hash::Hash for Position<F> {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<F: MerkleFamily> Default for Position<F> {
    #[inline]
    fn default() -> Self {
        Self(0, PhantomData)
    }
}

impl<F: MerkleFamily> fmt::Debug for Position<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Position").field(&self.0).finish()
    }
}

impl<F: MerkleFamily> fmt::Display for Position<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Position({})", self.0)
    }
}

impl<F: MerkleFamily> Deref for Position<F> {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: MerkleFamily> AsRef<u64> for Position<F> {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

impl<F: MerkleFamily> From<u64> for Position<F> {
    #[inline]
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl<F: MerkleFamily> From<usize> for Position<F> {
    #[inline]
    fn from(value: usize) -> Self {
        Self::new(value as u64)
    }
}

impl<F: MerkleFamily> From<Position<F>> for u64 {
    #[inline]
    fn from(position: Position<F>) -> Self {
        *position
    }
}

/// Try to convert a leaf [Location] to its node [Position].
///
/// Returns [`LocationConversionError::Overflow`] if `!loc.is_valid()`.
impl<F: MerkleFamily> TryFrom<Location<F>> for Position<F> {
    type Error = LocationConversionError<F>;

    #[inline]
    fn try_from(loc: Location<F>) -> Result<Self, Self::Error> {
        if !loc.is_valid() {
            return Err(LocationConversionError::Overflow(loc));
        }
        Ok(Self(F::location_to_position(*loc), PhantomData))
    }
}

// --- Arithmetic operators ---

/// Add two positions together.
///
/// # Panics
///
/// Panics if the result overflows.
impl<F: MerkleFamily> Add for Position<F> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0, PhantomData)
    }
}

/// Add a position and a `u64`.
///
/// # Panics
///
/// Panics if the result overflows.
impl<F: MerkleFamily> Add<u64> for Position<F> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs, PhantomData)
    }
}

/// Subtract two positions.
///
/// # Panics
///
/// Panics if the result underflows.
impl<F: MerkleFamily> Sub for Position<F> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0, PhantomData)
    }
}

/// Subtract a `u64` from a position.
///
/// # Panics
///
/// Panics if the result underflows.
impl<F: MerkleFamily> Sub<u64> for Position<F> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs, PhantomData)
    }
}

impl<F: MerkleFamily> PartialEq<u64> for Position<F> {
    #[inline]
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl<F: MerkleFamily> PartialOrd<u64> for Position<F> {
    #[inline]
    fn partial_cmp(&self, other: &u64) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl<F: MerkleFamily> PartialEq<Position<F>> for u64 {
    #[inline]
    fn eq(&self, other: &Position<F>) -> bool {
        *self == other.0
    }
}

impl<F: MerkleFamily> PartialOrd<Position<F>> for u64 {
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
impl<F: MerkleFamily> AddAssign<u64> for Position<F> {
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
impl<F: MerkleFamily> SubAssign<u64> for Position<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

// --- Codec implementations using varint encoding ---

impl<F: MerkleFamily> commonware_codec::Write for Position<F> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.0).write(buf);
    }
}

impl<F: MerkleFamily> commonware_codec::EncodeSize for Position<F> {
    #[inline]
    fn encode_size(&self) -> usize {
        UInt(self.0).encode_size()
    }
}

impl<F: MerkleFamily> commonware_codec::Read for Position<F> {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let pos = Self(UInt::read(buf)?.into(), PhantomData);
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
