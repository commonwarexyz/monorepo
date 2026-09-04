//! Implementation of [Zeroed], a fixed-count run of zero bytes.

use crate::{BufsMut, EncodeSize, Error, Read, Write, util::ensure_zeros};
use bytes::{Buf, BufMut};

/// A value representing exactly `n` zeroed bytes.
///
/// Useful for padding or reserving space in an encoding without storing an
/// explicit `[0; N]` buffer. Decoding rejects any input where one of the `n`
/// bytes is non-zero, so `Zeroed` also acts as an assertion that a reserved
/// region was actually left untouched.
///
/// `n` is not stored on the wire; the reader must already know it (supplied
/// via [Read::Cfg]), the same way a fixed-length array's length is part of
/// its type rather than its encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Zeroed {
    n: usize,
}

impl Zeroed {
    /// Creates a [Zeroed] representing `n` zero bytes.
    pub const fn new(n: usize) -> Self {
        Self { n }
    }

    /// Returns the number of zero bytes this value represents.
    pub const fn len(&self) -> usize {
        self.n
    }

    /// Returns `true` if this represents zero bytes (i.e. `n == 0`).
    pub const fn is_empty(&self) -> bool {
        self.n == 0
    }
}

impl Write for Zeroed {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        // `BufMut` has no "write n zero bytes" primitive, so put_bytes (a
        // memset under the hood, not n individual calls) is the cheapest
        // portable way to do this without allocating a temporary buffer.
        buf.put_bytes(0, self.n);
    }

    #[inline]
    fn write_bufs(&self, buf: &mut impl BufsMut) {
        buf.push(vec![0u8; self.n]);
    }
}

impl EncodeSize for Zeroed {
    #[inline]
    fn encode_size(&self) -> usize {
        self.n
    }

    #[inline]
    fn encode_inline_size(&self) -> usize {
        // write_bufs pushes the zero region as a separate chunk via
        // `BufsMut::push` rather than writing it into the inline buffer, so
        // pooled encoding shouldn't reserve inline space for it too.
        0
    }
}

impl Read for Zeroed {
    type Cfg = usize;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, n: &Self::Cfg) -> Result<Self, Error> {
        ensure_zeros(buf, *n)?;
        Ok(Self { n: *n })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decode, Encode};

    #[test]
    fn test_zeroed_round_trip() {
        for n in [0, 1, 8, 300] {
            let value = Zeroed::new(n);
            let encoded = value.encode();
            assert_eq!(encoded.len(), n);
            assert!(encoded.iter().all(|&b| b == 0));

            let decoded = Zeroed::decode_cfg(encoded, &n).unwrap();
            assert_eq!(value, decoded);
            assert_eq!(decoded.len(), n);
        }
    }

    #[test]
    fn test_zeroed_write_bufs_matches_write() {
        use crate::types::tests::TrackingWriteBuf;

        for n in [0, 1, 8, 300] {
            let value = Zeroed::new(n);

            let direct = value.encode();

            let mut pooled = TrackingWriteBuf::new();
            value.write_bufs(&mut pooled);
            let via_pool = pooled.freeze();

            assert_eq!(
                direct.as_ref(),
                via_pool.as_ref(),
                "write_bufs output must be byte-identical to write for n={n}"
            );
        }
    }

    #[test]
    fn test_zeroed_rejects_non_zero_byte() {
        let mut bytes = vec![0u8; 8];
        bytes[5] = 1;
        assert!(matches!(
            Zeroed::decode_cfg(bytes.as_slice(), &8),
            Err(Error::Invalid("codec", _))
        ));
    }

    #[test]
    fn test_zeroed_rejects_short_buffer() {
        let bytes = vec![0u8; 4];
        assert!(matches!(
            Zeroed::decode_cfg(bytes.as_slice(), &8),
            Err(Error::EndOfBuffer)
        ));
    }

    #[test]
    fn test_zeroed_is_empty() {
        assert!(Zeroed::new(0).is_empty());
        assert!(!Zeroed::new(1).is_empty());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::conformance::CodecConformance;
        use arbitrary::Arbitrary;

        /// Newtype wrapper implementing [Arbitrary] for [super::Zeroed].
        ///
        /// Wraps a small, arbitrary-length `n` rather than deriving `Zeroed`
        /// directly, since [Read::Cfg] (the byte count) must be known
        /// separately from the encoded value itself, same as [super::Bytes]'s
        /// conformance wrapper carries its own length.
        #[derive(Debug)]
        struct Zeroed(super::Zeroed);

        impl Write for Zeroed {
            fn write(&self, buf: &mut impl BufMut) {
                self.0.write(buf);
            }
        }

        impl EncodeSize for Zeroed {
            fn encode_size(&self) -> usize {
                self.0.encode_size()
            }
        }

        impl Read for Zeroed {
            type Cfg = usize;

            fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
                Ok(Self(super::Zeroed::read_cfg(buf, cfg)?))
            }
        }

        impl Arbitrary<'_> for Zeroed {
            fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
                let n = u.arbitrary::<u8>()?;
                Ok(Self(super::Zeroed::new(n as usize)))
            }
        }

        commonware_conformance::conformance_tests! {
            CodecConformance<Zeroed>
        }
    }
}
