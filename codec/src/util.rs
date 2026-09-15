//! Helpers for reading and validating encoded values.

use crate::{Buf, Error, FixedSize, Read};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Read a fixed-width value directly from the current chunk when it fits.
#[inline]
pub(crate) fn read_fixed<const N: usize>(buf: &mut impl Buf) -> Result<[u8; N], Error> {
    if let Some(bytes) = buf.chunk().first_chunk::<N>() {
        let bytes = *bytes;
        buf.advance(N);
        return Ok(bytes);
    }

    let mut bytes = [0; N];
    buf.try_copy_to_slice(&mut bytes)
        .map_err(|_| Error::EndOfBuffer)?;
    Ok(bytes)
}

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
    use crate::{Copying, ReadExt, varint::UInt};
    use bytes::{Buf as _, Bytes};
    use core::cell::Cell;

    struct CountRemaining<B> {
        inner: B,
        calls: Cell<usize>,
    }

    impl<B> CountRemaining<B> {
        fn new(inner: B) -> Self {
            Self {
                inner,
                calls: Cell::new(0),
            }
        }
    }

    impl<B: Buf> Buf for CountRemaining<B> {}

    impl<B: Buf> bytes::Buf for CountRemaining<B> {
        fn remaining(&self) -> usize {
            self.calls.set(self.calls.get() + 1);
            self.inner.remaining()
        }

        fn chunk(&self) -> &[u8] {
            self.inner.chunk()
        }

        fn advance(&mut self, count: usize) {
            self.inner.advance(count);
        }

        fn copy_to_bytes(&mut self, count: usize) -> Bytes {
            self.inner.copy_to_bytes(count)
        }
    }

    #[test]
    fn test_numeric_reads_only_query_total_length_for_bounds() {
        let bytes = Bytes::from_static(&[0, 0, 0, 1, 0, 0, 0, 2]);
        let source = || bytes.clone().chain(Bytes::from_static(&[9]));

        let mut scalar = CountRemaining::new(source());
        assert_eq!(u32::read(&mut scalar).unwrap(), 1);
        assert_eq!(u32::read(&mut scalar).unwrap(), 2);
        assert_eq!(scalar.calls.get(), 0);

        let mut vector = CountRemaining::new(source());
        assert_eq!(u32::read_vec(&mut vector, 2, &()).unwrap(), [1, 2]);
        assert_eq!(vector.calls.get(), 1);

        let mut array = CountRemaining::new(source());
        assert_eq!(u32::read_array::<2>(&mut array, &()).unwrap(), [1, 2]);
        assert_eq!(array.calls.get(), 1);

        // Even a cross-chunk varint needs no total-length query for its individual bytes.
        let mut varint = CountRemaining::new(
            Bytes::from_static(&[0xAC]).chain(Bytes::from_static(&[0x02, 0x7F])),
        );
        assert_eq!(UInt::<u32>::read(&mut varint).unwrap().0, 300);
        assert_eq!(u8::read(&mut varint).unwrap(), 127);
        assert_eq!(varint.calls.get(), 0);
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
