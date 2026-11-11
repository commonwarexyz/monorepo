//! Fixed-size encodings of validated values.

use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write};
use commonware_formatting::Hex;
use commonware_utils::{Array, Span};
use core::{
    cmp::Ordering,
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::Deref,
};

/// The `N`-byte encoding of a `T`, as carried on the wire.
///
/// Decoding copies the bytes and checks nothing else, so an encoding is cheap to read at any
/// rate and proves nothing about its contents. A validated `T` is built from it through
/// [TryFrom] and converts back through [Into]. Equality, ordering, and hashing follow the
/// bytes.
#[derive(FixedArray)]
#[fixed_array(infallible, bytes([u8; N]))]
#[repr(transparent)]
pub struct Encoding<T, const N: usize> {
    bytes: [u8; N],
    _marker: PhantomData<fn() -> T>,
}

impl<T, const N: usize> Encoding<T, N> {
    /// Wraps the bytes of an encoding.
    pub const fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }

    /// Returns the bytes of the encoding.
    pub const fn as_array(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<T, const N: usize> Clone for Encoding<T, N> {
    fn clone(&self) -> Self {
        Self::new(self.bytes)
    }
}

impl<T, const N: usize> PartialEq for Encoding<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<T, const N: usize> Eq for Encoding<T, N> {}

impl<T, const N: usize> PartialOrd for Encoding<T, N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T, const N: usize> Ord for Encoding<T, N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<T, const N: usize> Hash for Encoding<T, N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<T, const N: usize> Debug for Encoding<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
}

impl<T, const N: usize> Display for Encoding<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
}

impl<T, const N: usize> Write for Encoding<T, N> {
    fn write(&self, buf: &mut impl BufMut) {
        self.bytes.write(buf);
    }
}

impl<T, const N: usize> Read for Encoding<T, N> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self::new(<[u8; N]>::read(buf)?))
    }
}

impl<T, const N: usize> FixedSize for Encoding<T, N> {
    const SIZE: usize = N;
}

impl<T: 'static, const N: usize> Span for Encoding<T, N> {}

impl<T: 'static, const N: usize> Array for Encoding<T, N> {}

impl<T, const N: usize> AsRef<[u8]> for Encoding<T, N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<T, const N: usize> Deref for Encoding<T, N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(feature = "arbitrary")]
impl<T, const N: usize> arbitrary::Arbitrary<'_> for Encoding<T, N> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Copying, DecodeExt, Encode};

    struct Marker;

    #[test]
    fn codec_round_trip() {
        let encoding = Encoding::<Marker, 4>::new([1, 2, 3, 4]);
        let encoded = encoding.encode();
        assert_eq!(encoded.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(Encoding::<Marker, 4>::decode(encoded).unwrap(), encoding);
        assert!(Encoding::<Marker, 4>::decode(Copying(&[1, 2, 3])).is_err());
        assert!(Encoding::<Marker, 4>::decode(Copying(&[1, 2, 3, 4, 5])).is_err());
    }

    #[test]
    fn identity_follows_bytes() {
        let low = Encoding::<Marker, 2>::new([0, 1]);
        let high = Encoding::<Marker, 2>::new([1, 0]);
        assert!(low < high);
        assert_eq!(low, low.clone());
        assert_ne!(low, high);
        assert_eq!(format!("{low}"), "0001");
        assert_eq!(<[u8; 2]>::from(high), [1, 0]);
    }
}
