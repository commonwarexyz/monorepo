//! Zero-padded data codec implementation.

use crate::{error::Error, util::at_least, EncodeSize, Read, Write};
use bytes::{Buf, BufMut};

/// A codec for zero-padded data of a specified length.
///
/// When decoding, it validates that all bytes in the specified range are zero,
/// returning an error if any non-zero bytes are found.
#[derive(Debug, Clone, PartialEq)]
pub struct Zeroed {
    n: usize,
}

impl Zeroed {
    /// Creates a new `Zeroed` instance for `n` bytes.
    pub fn new(n: usize) -> Self {
        Self { n }
    }
}

impl Read for Zeroed {
    type Cfg = usize;

    /// Reads and validates zero-padded data from the buffer.
    ///
    /// The configuration specifies the expected number of zero bytes to read.
    /// This method validates that all bytes in the specified range are zero,
    /// returning an error if any non-zero bytes are encountered.
    ///
    /// ```rust
    /// use commonware_codec::{Read, EncodeSize};
    /// use commonware_codec::types::zeroed::Zeroed;
    ///
    /// let mut buf = &[0u8, 0u8, 0u8, 0u8][..];
    /// let zeroed = Zeroed::read_cfg(&mut buf, &4).unwrap();
    /// assert_eq!(zeroed.encode_size(), 4);
    /// ```
    fn read_cfg(buf: &mut impl Buf, n: &Self::Cfg) -> Result<Self, Error> {
        at_least(buf, *n)?;

        let mut remaining = *n;
        while remaining > 0 {
            let chunk = buf.chunk();
            let len: usize = chunk.len().min(remaining);
            if chunk[..len].iter().any(|&b| b != 0) {
                return Err(Error::Invalid("Zeroed", "bytes are not zero"));
            }
            buf.advance(len);
            remaining -= len;
        }

        Ok(Self { n: *n })
    }
}

impl Write for Zeroed {
    /// Writes zero bytes to the buffer.
    ///
    /// This method writes exactly `n` zero bytes to the provided buffer
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_bytes(0, self.n);
    }
}

impl EncodeSize for Zeroed {
    /// Returns the encoded size of the zero-padded data.
    fn encode_size(&self) -> usize {
        self.n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Encode;
    use bytes::BytesMut;

    #[test]
    fn test_zeroed() {
        let zeroed = Zeroed::new(4);
        let encoded = zeroed.encode();
        assert_eq!(encoded.len(), 4);
    }

    #[test]
    fn test_read() {
        let mut buf = &[0u8, 0u8, 0u8, 0u8][..];
        let zeroed = Zeroed::read_cfg(&mut buf, &4).unwrap();
        assert_eq!(zeroed.encode_size(), 4);
    }

    #[test]
    fn test_faulty_read_not_zero() {
        let mut buf = &[0u8, 0u8, 0u8, 1u8][..];
        assert!(matches!(
            Zeroed::read_cfg(&mut buf, &4),
            Err(Error::Invalid("Zeroed", "bytes are not zero"))
        ));
    }

    #[test]
    fn test_faulty_read_too_short() {
        let mut buf = &[0u8, 0u8, 0u8][..];
        assert!(matches!(
            Zeroed::read_cfg(&mut buf, &4),
            Err(Error::EndOfBuffer)
        ));
    }

    #[test]
    fn test_write() {
        let zeroed = Zeroed::new(4);
        let mut buf = BytesMut::new();
        zeroed.write(&mut buf);
        assert_eq!(buf.len(), 4);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encode_size() {
        let zeroed = Zeroed::new(4);
        assert_eq!(zeroed.encode_size(), 4);
    }
}
