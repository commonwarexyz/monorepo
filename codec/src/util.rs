//! Codec utility functions

use crate::{extensions::ReadExt as _, Error};
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
    for _ in 0..size {
        if u8::read(buf)? != 0 {
            return Err(Error::Invalid("codec", "non-zero bytes"));
        }
    }
    Ok(())
}
