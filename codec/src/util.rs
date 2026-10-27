//! Helpers for reading, validating, and sizing encoded values.

use crate::{Buf, EncodeSize, Error, FixedSize, Read, varint::UInt};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
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

/// Returns the largest encoded size of a `Vec` or other length-prefixed sequence of `len` items
/// that each encode to at most `item` bytes, or `None` if `len` exceeds `u32::MAX` or the size
/// overflows `usize`.
#[inline]
pub fn max_items_size(len: usize, item: usize) -> Option<usize> {
    let count = u32::try_from(len).ok()?;
    len.checked_mul(item)?
        .checked_add(UInt(count).encode_size())
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
    use crate::{Copying, varint::MAX_U32_VARINT_SIZE};
    use bytes::Buf as _;

    #[test]
    fn test_max_items_size() {
        // The size matches an encoded vector of 4-byte items on both sides of the one-byte length
        // prefix boundary.
        for len in [0, 1, 127, 128] {
            let items = vec![[0u8; 4]; len];
            assert_eq!(max_items_size(len, 4), Some(items.encode_size()));
        }

        // Up to `u32::MAX` items fit the length prefix. More items or a size that overflows
        // `usize` return `None`.
        const LARGEST: usize = u32::MAX as usize;
        assert_eq!(
            max_items_size(LARGEST, 1),
            Some(LARGEST + MAX_U32_VARINT_SIZE)
        );
        assert_eq!(max_items_size(LARGEST + 1, 0), None);
        assert_eq!(max_items_size(2, usize::MAX), None);
    }

    #[test]
    fn test_ensure_zeros() {
        // Consumes exactly `size` bytes of an all-zero region.
        let mut buf = Copying(&[0u8, 0, 0, 0, 7]);
        ensure_zeros(&mut buf, 4).unwrap();
        assert_eq!(buf.remaining(), 1);

        // A zero-length check consumes nothing, even on an empty buffer.
        let mut buf = Copying(&[]);
        ensure_zeros(&mut buf, 0).unwrap();

        // A short buffer fails without panicking.
        let mut buf = Copying(&[0u8, 0]);
        assert!(matches!(ensure_zeros(&mut buf, 3), Err(Error::EndOfBuffer)));

        // A non-zero byte anywhere in the region fails.
        for i in 0..4 {
            let mut bytes = [0u8; 4];
            bytes[i] = 1;
            let mut buf = Copying(&bytes);
            assert!(matches!(
                ensure_zeros(&mut buf, 4),
                Err(Error::Invalid(_, _))
            ));
        }
    }

    #[test]
    fn test_ensure_zeros_across_chunks() {
        // A chained buffer exposes the region as multiple chunks, exercising the chunk loop.
        let mut buf = Copying(&[0u8, 0]).chain(Copying(&[0u8, 0, 0]));
        ensure_zeros(&mut buf, 5).unwrap();
        assert_eq!(buf.remaining(), 0);

        // A non-zero byte in the second chunk still fails.
        let mut buf = Copying(&[0u8, 0]).chain(Copying(&[0u8, 2]));
        assert!(matches!(
            ensure_zeros(&mut buf, 4),
            Err(Error::Invalid(_, _))
        ));
    }
}
