use super::{position::Position, MerkleFamily, PositionConversionError};
use bytes::{Buf, BufMut};
use commonware_codec::ReadExt;
use core::{
    convert::TryFrom,
    fmt,
    marker::PhantomData,
    ops::{Add, AddAssign, Deref, Range, Sub, SubAssign},
};

/// A [Location] is a leaf index or leaf count in a Merkle structure.
/// This is in contrast to a [Position], which is a node index or node count.
///
/// # Limits
///
/// Values up to the family's maximum are valid (see [Location::is_valid]). As a 0-based leaf
/// index, valid indices are `0..MAX - 1`. As a leaf count or exclusive range-end, the maximum
/// is `MAX` itself.
pub struct Location<F: MerkleFamily>(u64, PhantomData<F>);

#[cfg(feature = "arbitrary")]
impl<F: MerkleFamily> arbitrary::Arbitrary<'_> for Location<F> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let value = u.int_in_range(0..=F::MAX_LOCATION)?;
        Ok(Self(value, PhantomData))
    }
}

impl<F: MerkleFamily> Location<F> {
    /// The maximum valid [Location] for this Merkle family.
    pub const MAX: Self = Self(F::MAX_LOCATION, PhantomData);

    /// Return a new [Location] from a raw `u64`.
    #[inline]
    pub const fn new(loc: u64) -> Self {
        Self(loc, PhantomData)
    }

    /// Return the underlying `u64` value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns `true` iff this value is within the valid range (`<= MAX`).
    /// This covers both leaf indices (`< MAX`) and leaf counts (`<= MAX`).
    #[inline]
    pub const fn is_valid(self) -> bool {
        self.0 <= F::MAX_LOCATION
    }

    /// Return `self + rhs` returning `None` on overflow or if result exceeds the maximum.
    #[inline]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(value) => {
                if value <= F::MAX_LOCATION {
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
        if result > F::MAX_LOCATION {
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
}

// --- Manual trait implementations (to avoid unnecessary bounds on F) ---

impl<F: MerkleFamily> Copy for Location<F> {}

impl<F: MerkleFamily> Clone for Location<F> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: MerkleFamily> PartialEq for Location<F> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<F: MerkleFamily> Eq for Location<F> {}

impl<F: MerkleFamily> PartialOrd for Location<F> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: MerkleFamily> Ord for Location<F> {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<F: MerkleFamily> core::hash::Hash for Location<F> {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<F: MerkleFamily> Default for Location<F> {
    #[inline]
    fn default() -> Self {
        Self(0, PhantomData)
    }
}

impl<F: MerkleFamily> fmt::Debug for Location<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Location").field(&self.0).finish()
    }
}

impl<F: MerkleFamily> fmt::Display for Location<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Location({})", self.0)
    }
}

impl<F: MerkleFamily> Deref for Location<F> {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: MerkleFamily> From<u64> for Location<F> {
    #[inline]
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl<F: MerkleFamily> From<usize> for Location<F> {
    #[inline]
    fn from(value: usize) -> Self {
        Self::new(value as u64)
    }
}

impl<F: MerkleFamily> From<Location<F>> for u64 {
    #[inline]
    fn from(loc: Location<F>) -> Self {
        *loc
    }
}

// --- Codec implementations using varint encoding ---

impl<F: MerkleFamily> commonware_codec::Write for Location<F> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        commonware_codec::varint::UInt(self.0).write(buf);
    }
}

impl<F: MerkleFamily> commonware_codec::EncodeSize for Location<F> {
    #[inline]
    fn encode_size(&self) -> usize {
        commonware_codec::varint::UInt(self.0).encode_size()
    }
}

impl<F: MerkleFamily> commonware_codec::Read for Location<F> {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let loc = Self::new(commonware_codec::varint::UInt::read(buf)?.into());
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

/// Attempt to derive the [Location] of a given node [Position].
///
/// Returns an error if the position does not correspond to a leaf or if position
/// overflow occurs.
impl<F: MerkleFamily> TryFrom<Position<F>> for Location<F> {
    type Error = PositionConversionError<F>;

    #[inline]
    fn try_from(pos: Position<F>) -> Result<Self, Self::Error> {
        if !pos.is_valid() {
            return Err(PositionConversionError::Overflow(pos));
        }
        F::position_to_location(*pos)
            .map(|loc| Self(loc, PhantomData))
            .ok_or(PositionConversionError::NonLeaf(pos))
    }
}

// --- Arithmetic operators ---

/// Add two locations together.
///
/// # Panics
///
/// Panics if the result overflows.
impl<F: MerkleFamily> Add for Location<F> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0, PhantomData)
    }
}

/// Add a location and a `u64`.
///
/// # Panics
///
/// Panics if the result overflows.
impl<F: MerkleFamily> Add<u64> for Location<F> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs, PhantomData)
    }
}

/// Subtract two locations.
///
/// # Panics
///
/// Panics if the result underflows.
impl<F: MerkleFamily> Sub for Location<F> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0, PhantomData)
    }
}

/// Subtract a `u64` from a location.
///
/// # Panics
///
/// Panics if the result underflows.
impl<F: MerkleFamily> Sub<u64> for Location<F> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs, PhantomData)
    }
}

impl<F: MerkleFamily> PartialEq<u64> for Location<F> {
    #[inline]
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl<F: MerkleFamily> PartialOrd<u64> for Location<F> {
    #[inline]
    fn partial_cmp(&self, other: &u64) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl<F: MerkleFamily> PartialEq<Location<F>> for u64 {
    #[inline]
    fn eq(&self, other: &Location<F>) -> bool {
        *self == other.0
    }
}

impl<F: MerkleFamily> PartialOrd<Location<F>> for u64 {
    #[inline]
    fn partial_cmp(&self, other: &Location<F>) -> Option<core::cmp::Ordering> {
        self.partial_cmp(&other.0)
    }
}

/// Add a `u64` to a location.
///
/// # Panics
///
/// Panics if the result overflows.
impl<F: MerkleFamily> AddAssign<u64> for Location<F> {
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
impl<F: MerkleFamily> SubAssign<u64> for Location<F> {
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

impl<F: MerkleFamily> LocationRangeExt for Range<Location<F>> {
    #[inline]
    fn to_usize_range(&self) -> Range<usize> {
        *self.start as usize..*self.end as usize
    }
}
