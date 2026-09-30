use crate::{Array, Span};
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write};
use commonware_formatting::Hex;
use core::{
    cmp::{Ord, Ordering, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use thiserror::Error;
use zeroize::Zeroize;

/// Errors returned by `Bytes` functions.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength,
}

/// An `Array` implementation for fixed-length byte arrays.
#[derive(Clone, Eq, PartialEq, Hash, Debug, FixedArray)]
#[fixed_array(infallible, bytes([u8; N]))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(transparent)]
pub struct FixedBytes<const N: usize>([u8; N]);

impl<const N: usize> FixedBytes<N> {
    /// Creates a new `FixedBytes` instance from an array of length `N`.
    pub const fn new(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> Ord for FixedBytes<N> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        let (a, b) = (&self.0, &other.0);
        // Up to 16 bytes the derived compare is already inlined; past 64 unrolling bloats call sites.
        if N <= 16 || N > 64 {
            return a.cmp(b);
        }
        let (a_words, _) = a.as_chunks::<8>();
        let (b_words, _) = b.as_chunks::<8>();
        for (a, b) in a_words.iter().zip(b_words) {
            let (a, b) = (u64::from_be_bytes(*a), u64::from_be_bytes(*b));
            if a != b {
                return a.cmp(&b);
            }
        }
        if N.is_multiple_of(8) {
            return Ordering::Equal;
        }
        // Every earlier byte is equal, so the last 8 bytes (overlapping the last whole word) decide.
        let last = |x: &[u8; N]| u64::from_be_bytes(*x.last_chunk::<8>().expect("N > 16"));
        last(a).cmp(&last(b))
    }
}

impl<const N: usize> PartialOrd for FixedBytes<N> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> Write for FixedBytes<N> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<const N: usize> Read for FixedBytes<N> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self(<[u8; N]>::read(buf)?))
    }
}

impl<const N: usize> FixedSize for FixedBytes<N> {
    const SIZE: usize = N;
}

impl<const N: usize> Span for FixedBytes<N> {}

impl<const N: usize> Array for FixedBytes<N> {}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Deref for FixedBytes<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Display for FixedBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.0))
    }
}

impl<const N: usize> Zeroize for FixedBytes<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fixed_bytes, test_rng};
    use bytes::{Buf as _, BytesMut};
    use commonware_codec::{Copying, DecodeExt, Encode};
    use rand::RngExt as _;

    #[test]
    fn test_codec() {
        let original = FixedBytes::new([1, 2, 3, 4]);
        let encoded = original.encode();
        assert_eq!(encoded.len(), original.len());
        let decoded = FixedBytes::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_bytes_creation_and_conversion() {
        let value = [1, 2, 3, 4];
        let bytes = FixedBytes::new(value);
        assert_eq!(bytes.as_ref(), &value);

        let bytes_into = value.into();
        assert_eq!(bytes, bytes_into);

        let slice = [1, 2, 3, 4];
        let bytes_from_slice = FixedBytes::decode(Copying(&slice)).unwrap();
        assert_eq!(bytes_from_slice, bytes);

        let vec = vec![1, 2, 3, 4];
        let bytes_from_vec = FixedBytes::decode(vec).unwrap();
        assert_eq!(bytes_from_vec, bytes);

        // Test with incorrect length
        let slice_too_short = [1, 2, 3];
        assert!(matches!(
            FixedBytes::<4>::decode(Copying(&slice_too_short)),
            Err(CodecError::EndOfBuffer)
        ));

        let vec_too_long = vec![1, 2, 3, 4, 5];
        assert!(matches!(
            FixedBytes::<4>::decode(vec_too_long),
            Err(CodecError::ExtraData(1))
        ));
    }

    #[test]
    fn test_read() {
        let mut buf = BytesMut::from(&[1, 2, 3, 4][..]);
        let bytes = FixedBytes::<4>::read(&mut buf).unwrap();
        assert_eq!(bytes.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(buf.remaining(), 0);

        let mut buf = BytesMut::from(&[1, 2, 3][..]);
        let result = FixedBytes::<4>::read(&mut buf);
        assert!(matches!(result, Err(CodecError::EndOfBuffer)));

        let mut buf = BytesMut::from(&[1, 2, 3, 4, 5][..]);
        let bytes = FixedBytes::<4>::read(&mut buf).unwrap();
        assert_eq!(bytes.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(buf.remaining(), 1);
        assert_eq!(buf[0], 5);
    }

    #[test]
    fn test_display() {
        let bytes = fixed_bytes!("0x01020304");
        assert_eq!(format!("{bytes}"), "01020304");
    }

    #[test]
    fn test_ord_and_eq() {
        let a = FixedBytes::new([1, 2, 3, 4]);
        let b = FixedBytes::new([1, 2, 3, 5]);
        assert!(a < b);
        assert_ne!(a, b);

        let c = FixedBytes::new([1, 2, 3, 4]);
        assert_eq!(a, c);
    }

    fn assert_matches<const N: usize>(a: &[u8; N], b: &[u8; N]) {
        let (left, right) = (FixedBytes::new(*a), FixedBytes::new(*b));
        assert_eq!(left.cmp(&right), a.cmp(b));
        assert_eq!(right.cmp(&left), b.cmp(a));
        assert_eq!(left.partial_cmp(&right), Some(a.cmp(b)));
    }

    fn check<const N: usize>() {
        const BOUNDARIES: [u8; 4] = [0x00, 0x7f, 0x80, 0xff];
        let mut rng = test_rng();
        for _ in 0..8 {
            let a: [u8; N] = rng.random();
            assert_matches(&a, &a);
            // Make every position the first difference.
            for k in 0..N {
                let mut b = a;
                b[k] = a[k] ^ rng.random_range(1..=u8::MAX);
                for byte in &mut b[k + 1..] {
                    *byte = rng.random();
                }
                assert_matches(&a, &b);

                // Boundary bytes at `k`, with suffixes that order the other way for some pairs.
                for x in BOUNDARIES {
                    for y in BOUNDARIES {
                        let (mut a, mut b) = (a, a);
                        a[k] = x;
                        b[k] = y;
                        a[k + 1..].fill(0xff);
                        b[k + 1..].fill(0x00);
                        assert_matches(&a, &b);
                    }
                }
            }
        }
    }

    #[test]
    fn test_ord_matches_byte_order() {
        check::<0>();
        check::<5>();
        check::<16>();
        check::<17>();
        check::<18>();
        check::<19>();
        check::<20>();
        check::<21>();
        check::<22>();
        check::<23>();
        check::<24>();
        check::<31>();
        check::<32>();
        check::<33>();
        check::<40>();
        check::<63>();
        check::<64>();
        check::<65>();
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<FixedBytes<16>>,
        }
    }
}
