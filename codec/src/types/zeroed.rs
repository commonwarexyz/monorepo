//! Zero-filled padding for fixed-width encodings.
//!
//! # Status
//!
//! This type is **BETA**.
//!
//! # Examples
//!
//! ```
//! use commonware_codec::{Decode, Encode, types::zeroed::Zeroed};
//!
//! let padding = Zeroed::new(4);
//! assert_eq!(padding.encode().as_ref(), &[0u8; 4]);
//! assert_eq!(Zeroed::decode_cfg(&[0u8; 4][..], &4).unwrap(), padding);
//! ```

use crate::{EncodeSize, Error, Read, Write, util::ensure_zeros};
use bytes::{Buf, BufMut};

/// A runtime-sized sequence of zero bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Zeroed(usize);

impl Zeroed {
    /// Creates zero-filled padding of `len` bytes.
    pub const fn new(len: usize) -> Self {
        Self(len)
    }
}

impl Write for Zeroed {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_bytes(0, self.0);
    }
}

impl EncodeSize for Zeroed {
    #[inline]
    fn encode_size(&self) -> usize {
        self.0
    }
}

impl Read for Zeroed {
    type Cfg = usize;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, len: &Self::Cfg) -> Result<Self, Error> {
        ensure_zeros(buf, *len)?;
        Ok(Self::new(*len))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Zeroed {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.int_in_range(0..=1024u16)?.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decode, Encode, Error, Read};
    use bytes::Buf;

    #[test]
    fn test_codec() {
        for len in [0, 1, 64, 255, 256] {
            let zeroed = Zeroed::new(len);
            let encoded = zeroed.encode();

            assert_eq!(encoded.len(), len);
            assert!(encoded.iter().all(|byte| *byte == 0));
            assert_eq!(Zeroed::decode_cfg(encoded, &len).unwrap(), zeroed);
        }
    }

    #[test]
    fn test_read_validation() {
        let mut valid = &[0, 0, 7][..];
        assert_eq!(Zeroed::read_cfg(&mut valid, &2).unwrap(), Zeroed::new(2));
        assert_eq!(valid.remaining(), 1);

        assert!(matches!(
            Zeroed::decode_cfg(&[0][..], &2),
            Err(Error::EndOfBuffer)
        ));
        assert!(matches!(
            Zeroed::decode_cfg(&[0, 1][..], &2),
            Err(Error::Invalid("codec", "non-zero bytes"))
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Zeroed>
        }
    }
}
