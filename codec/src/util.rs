//! Codec utility functions

use crate::{Error, FixedSize, Read};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::Buf;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Checks if the buffer has at least `len` bytes remaining. Returns an [Error::EndOfBuffer] if not.
#[inline]
pub fn at_least<B: Buf>(buf: &mut B, len: usize) -> Result<(), Error> {
    let rem = buf.remaining();
    if rem < len {
        return Err(Error::EndOfBuffer);
    }
    Ok(())
}

/// Checks if the buffer has at least `len * item_size` bytes remaining, treating multiplication
/// overflow as insufficient. Returns an [Error::EndOfBuffer] if not.
#[inline]
pub fn at_least_items<B: Buf>(buf: &mut B, len: usize, item_size: usize) -> Result<(), Error> {
    at_least(buf, len.checked_mul(item_size).ok_or(Error::EndOfBuffer)?)
}

/// Reads `len` values of a [FixedSize] type from the buffer into a vector.
///
/// Checks that the buffer contains all `len * SIZE` bytes before allocating or decoding, so a
/// maliciously large `len` fails fast with [Error::EndOfBuffer]. Intended as a `Read::read_vec`
/// override for [FixedSize] element types.
#[inline]
pub fn read_fixed_vec<T: Read + FixedSize>(
    buf: &mut impl Buf,
    len: usize,
    cfg: &T::Cfg,
) -> Result<Vec<T>, Error> {
    at_least_items(buf, len, T::SIZE)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(T::read_cfg(buf, cfg)?);
    }
    Ok(values)
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
