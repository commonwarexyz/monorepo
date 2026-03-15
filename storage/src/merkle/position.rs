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
