//! Codec utility functions

use crate::{extensions::ReadExt as _, Error, FixedSize, Read};
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
    for _ in 0..size {
        if u8::read(buf)? != 0 {
            return Err(Error::Invalid("codec", "non-zero bytes"));
        }
    }
    Ok(())
}
