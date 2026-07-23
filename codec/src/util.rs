//! Codec utility functions

use crate::Error;
use bytes::Buf;

/// Checks if the buffer has at least `len` bytes remaining. Returns an [Error::EndOfBuffer] if not.
#[inline]
pub fn at_least<B: Buf>(buf: &mut B, len: usize) -> Result<(), Error> {
    let rem = buf.remaining();
    if rem < len {
        return Err(Error::EndOfBuffer);
    }
    Ok(())
}

/// Ensures the next `size` bytes are all zeroes in the provided buffer, returning an [Error]
/// otherwise.
#[inline]
pub fn ensure_zeros<B: Buf>(buf: &mut B, size: usize) -> Result<(), Error> {
    at_least(buf, size)?;
    let mut remaining = size;
    while remaining > 0 {
        // Compare (and advance) a chunk at a time rather than a byte at a time. Padding regularly
        // spans dozens of bytes, and a slice comparison vectorizes.
        let chunk = buf.chunk();
        let len = chunk.len().min(remaining);
        if chunk[..len].iter().any(|&b| b != 0) {
            return Err(Error::Invalid("codec", "non-zero bytes"));
        }
        buf.advance(len);
        remaining -= len;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_zeros() {
        // Consumes exactly `size` bytes of an all-zero region.
        let mut buf = &[0u8, 0, 0, 0, 7][..];
        ensure_zeros(&mut buf, 4).unwrap();
        assert_eq!(buf.remaining(), 1);

        // A zero-length check consumes nothing, even on an empty buffer.
        let mut buf = &[][..];
        ensure_zeros(&mut buf, 0).unwrap();

        // A short buffer fails without panicking.
        let mut buf = &[0u8, 0][..];
        assert!(matches!(ensure_zeros(&mut buf, 3), Err(Error::EndOfBuffer)));

        // A non-zero byte anywhere in the region fails.
        for i in 0..4 {
            let mut bytes = [0u8; 4];
            bytes[i] = 1;
            let mut buf = &bytes[..];
            assert!(matches!(
                ensure_zeros(&mut buf, 4),
                Err(Error::Invalid(_, _))
            ));
        }
    }

    #[test]
    fn test_ensure_zeros_across_chunks() {
        // A chained buffer exposes the region as multiple chunks, exercising the chunk loop.
        let mut buf = (&[0u8, 0][..]).chain(&[0u8, 0, 0][..]);
        ensure_zeros(&mut buf, 5).unwrap();
        assert_eq!(buf.remaining(), 0);

        // A non-zero byte in the second chunk still fails.
        let mut buf = (&[0u8, 0][..]).chain(&[0u8, 2][..]);
        assert!(matches!(
            ensure_zeros(&mut buf, 4),
            Err(Error::Invalid(_, _))
        ));
    }
}
