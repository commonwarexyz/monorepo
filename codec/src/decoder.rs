//! A unified decoder for both owned and zero-copy decoding.
//!
//! The [`Decoder`] struct wraps a byte slice and provides methods for reading data.
//! It implements the [`bytes::Buf`] trait for compatibility with the existing [`Read`]
//! trait, while also providing zero-copy access via [`Decoder::slice`].
//!
//! # Example
//!
//! ```
//! use commonware_codec::{Decoder, ReadExt, FixedSize};
//!
//! let data = &[0x00, 0x00, 0x00, 0x2A, 3, 1, 2, 3][..];
//! let mut decoder = Decoder::new(data);
//!
//! // Read an owned u32 (uses Buf trait)
//! let value: u32 = u32::read(&mut decoder).unwrap();
//! assert_eq!(value, 42);
//!
//! // Zero-copy: get a slice borrowing from original data
//! let len = decoder.read_usize(..=10).unwrap();
//! let slice = decoder.slice(len).unwrap();
//! assert_eq!(slice, &[1, 2, 3]);
//! ```

use crate::{Error, RangeCfg};
use bytes::{Buf, Bytes};
use core::ops::RangeBounds;

/// A decoder that wraps a byte slice for zero-copy decoding.
///
/// `Decoder` provides two ways to read data:
/// 1. **Owned decoding**: Implements [`Buf`] trait, so it works with existing [`Read`] impls
/// 2. **Zero-copy decoding**: Use [`slice`](Decoder::slice) to get references to the original buffer
///
/// The decoder tracks position and advances through the buffer as data is read.
#[derive(Debug)]
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Creates a new decoder wrapping the given byte slice.
    #[inline]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns a slice of `len` bytes from the current position (zero-copy).
    ///
    /// Advances the decoder by `len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EndOfBuffer`] if fewer than `len` bytes remain.
    #[inline]
    pub fn slice(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if self.remaining() < len {
            return Err(Error::EndOfBuffer);
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Returns the remaining bytes without advancing (zero-copy).
    #[inline]
    pub fn remaining_slice(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Returns the number of bytes remaining.
    #[inline]
    pub const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Returns true if there are no more bytes to read.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Reads a varint-encoded length with range validation.
    ///
    /// This is a convenience method for reading length-prefixed data.
    pub fn read_usize(&mut self, range: impl RangeBounds<usize>) -> Result<usize, Error> {
        let cfg = RangeCfg::new(range);
        usize::read_ref(self, &cfg)
    }

    /// Ensures all bytes have been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ExtraData`] if there are remaining bytes.
    #[inline]
    pub const fn finish(self) -> Result<(), Error> {
        if !self.is_empty() {
            return Err(Error::ExtraData(self.remaining()));
        }
        Ok(())
    }
}

/// A decoder that wraps owned [`Bytes`] for zero-copy decoding.
///
/// Unlike [`Decoder`] which borrows a slice, `ZeroBuf` owns its data. However, it still
/// provides zero-copy semantics because [`Bytes::slice`] creates a new `Bytes` that shares
/// the same underlying memory without copying.
///
/// This is useful when you have owned `Bytes` (e.g., from a network buffer) and want to
/// decode it without copying the byte data.
///
/// # Example
///
/// ```
/// use commonware_codec::{ZeroBuf, ReadExt, FixedSize};
/// use bytes::Bytes;
///
/// let data = Bytes::from_static(&[0x00, 0x00, 0x00, 0x2A, 3, 1, 2, 3]);
/// let mut decoder = ZeroBuf::new(data);
///
/// // Read an owned u32 (uses Buf trait)
/// let value: u32 = u32::read(&mut decoder).unwrap();
/// assert_eq!(value, 42);
///
/// // Zero-copy: get a Bytes that shares the same underlying memory
/// let len = decoder.read_usize(..=10).unwrap();
/// let slice = decoder.slice(len).unwrap();
/// assert_eq!(&slice[..], &[1, 2, 3]);
/// ```
#[derive(Debug, Clone)]
pub struct ZeroBuf {
    data: Bytes,
    pos: usize,
}

impl ZeroBuf {
    /// Creates a new decoder wrapping the given [`Bytes`].
    #[inline]
    pub const fn new(data: Bytes) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns a [`Bytes`] slice of `len` bytes from the current position (zero-copy).
    ///
    /// This is zero-copy because `Bytes::slice()` shares the underlying memory.
    /// Advances the decoder by `len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EndOfBuffer`] if fewer than `len` bytes remain.
    #[inline]
    pub fn slice(&mut self, len: usize) -> Result<Bytes, Error> {
        if self.remaining() < len {
            return Err(Error::EndOfBuffer);
        }
        let slice = self.data.slice(self.pos..self.pos + len);
        self.pos += len;
        Ok(slice)
    }

    /// Returns the remaining bytes as a [`Bytes`] without advancing (zero-copy).
    #[inline]
    pub fn remaining_bytes(&self) -> Bytes {
        self.data.slice(self.pos..)
    }

    /// Returns the remaining bytes as a slice without advancing.
    #[inline]
    pub fn remaining_slice(&self) -> &[u8] {
        &self.data[self.pos..]
    }

    /// Returns the number of bytes remaining.
    #[inline]
    pub const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Returns true if there are no more bytes to read.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Reads a varint-encoded length with range validation.
    ///
    /// This is a convenience method for reading length-prefixed data.
    pub fn read_usize(&mut self, range: impl RangeBounds<usize>) -> Result<usize, Error> {
        let cfg = RangeCfg::new(range);
        // Use Buf trait to read varint
        crate::Read::read_cfg(self, &cfg)
    }

    /// Ensures all bytes have been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ExtraData`] if there are remaining bytes.
    #[inline]
    pub fn finish(self) -> Result<(), Error> {
        if !self.is_empty() {
            return Err(Error::ExtraData(self.remaining()));
        }
        Ok(())
    }
}

// Implement Buf trait for ZeroBuf for compatibility with existing Read impls
impl Buf for ZeroBuf {
    #[inline]
    fn remaining(&self) -> usize {
        self.remaining()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.remaining_slice()
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(
            cnt <= self.remaining(),
            "cannot advance past end of buffer"
        );
        self.pos += cnt;
    }
}

/// Helper trait for reading from a Decoder with zero-copy support.
trait ReadFromDecoder<'a>: Sized {
    type Cfg;
    fn read_ref(decoder: &mut Decoder<'a>, cfg: &Self::Cfg) -> Result<Self, Error>;
}

// Implement for usize (varint)
impl<'a> ReadFromDecoder<'a> for usize {
    type Cfg = RangeCfg<Self>;

    fn read_ref(decoder: &mut Decoder<'a>, range: &Self::Cfg) -> Result<Self, Error> {
        use crate::varint::Decoder as VarintDecoder;

        let mut varint = VarintDecoder::<u32>::new();
        loop {
            if decoder.is_empty() {
                return Err(Error::EndOfBuffer);
            }
            let byte = decoder.data[decoder.pos];
            decoder.pos += 1;
            if let Some(value) = varint.feed(byte)? {
                let result = value as Self;
                if !range.contains(&result) {
                    return Err(Error::InvalidLength(result));
                }
                return Ok(result);
            }
        }
    }
}

// Implement Buf trait for compatibility with existing Read impls
impl Buf for Decoder<'_> {
    #[inline]
    fn remaining(&self) -> usize {
        self.remaining()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.remaining_slice()
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(
            cnt <= self.remaining(),
            "cannot advance past end of buffer"
        );
        self.pos += cnt;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Encode, ReadExt};

    #[test]
    fn test_decoder_buf_trait() {
        let data = &[0x00, 0x00, 0x00, 0x2A][..]; // 42 as big-endian u32
        let mut decoder = Decoder::new(data);

        // Use existing Read impl via Buf trait
        let value: u32 = u32::read(&mut decoder).unwrap();
        assert_eq!(value, 42);
        assert!(decoder.is_empty());
    }

    #[test]
    fn test_decoder_slice_zero_copy() {
        let data = &[1, 2, 3, 4, 5][..];
        let mut decoder = Decoder::new(data);

        // Get zero-copy slice
        let slice = decoder.slice(3).unwrap();
        assert_eq!(slice, &[1, 2, 3]);
        assert_eq!(decoder.remaining(), 2);

        // Verify it's actually pointing to original data
        assert_eq!(slice.as_ptr(), unsafe { data.as_ptr().add(0) });
    }

    #[test]
    fn test_decoder_read_usize() {
        let data = &[0x96, 0x01][..]; // varint for 150
        let mut decoder = Decoder::new(data);

        let len = decoder.read_usize(..=200).unwrap();
        assert_eq!(len, 150);
        assert!(decoder.is_empty());
    }

    #[test]
    fn test_decoder_length_prefixed_slice() {
        // Length-prefixed data: length=3, data=[1,2,3]
        let data = &[3, 1, 2, 3][..];
        let mut decoder = Decoder::new(data);

        let len = decoder.read_usize(..=10).unwrap();
        let slice = decoder.slice(len).unwrap();

        assert_eq!(slice, &[1, 2, 3]);
        assert!(decoder.is_empty());
    }

    #[test]
    fn test_decoder_mixed_owned_and_borrowed() {
        // u32 (4 bytes) + length-prefixed bytes
        let mut buf = 42u32.encode().to_vec();
        buf.extend_from_slice(&[3, 0xAA, 0xBB, 0xCC]);
        let data = buf.as_slice();

        let mut decoder = Decoder::new(data);

        // Read owned u32
        let value: u32 = u32::read(&mut decoder).unwrap();
        assert_eq!(value, 42);

        // Read zero-copy slice
        let len = decoder.read_usize(..=10).unwrap();
        let slice = decoder.slice(len).unwrap();
        assert_eq!(slice, &[0xAA, 0xBB, 0xCC]);

        decoder.finish().unwrap();
    }

    #[test]
    fn test_decoder_errors() {
        let data = &[1, 2][..];
        let mut decoder = Decoder::new(data);

        // Try to read more than available
        assert!(matches!(decoder.slice(3), Err(Error::EndOfBuffer)));

        // Read what's available
        let _ = decoder.slice(2).unwrap();

        // Extra data check
        let decoder = Decoder::new(&[1, 2, 3][..]);
        assert!(matches!(decoder.finish(), Err(Error::ExtraData(3))));
    }

    #[test]
    fn test_decoder_range_validation() {
        let data = &[10][..]; // varint for 10
        let mut decoder = Decoder::new(data);

        // Should fail: 10 > 5
        assert!(matches!(
            decoder.read_usize(..=5),
            Err(Error::InvalidLength(10))
        ));
    }

    // ZeroBuf tests

    #[test]
    fn test_zerobuf_buf_trait() {
        let data = Bytes::from_static(&[0x00, 0x00, 0x00, 0x2A]); // 42 as big-endian u32
        let mut decoder = ZeroBuf::new(data);

        // Use existing Read impl via Buf trait
        let value: u32 = u32::read(&mut decoder).unwrap();
        assert_eq!(value, 42);
        assert!(decoder.is_empty());
    }

    #[test]
    fn test_zerobuf_slice_zero_copy() {
        let data = Bytes::from_static(&[1, 2, 3, 4, 5]);
        let mut decoder = ZeroBuf::new(data.clone());

        // Get zero-copy Bytes slice
        let slice = decoder.slice(3).unwrap();
        assert_eq!(&slice[..], &[1, 2, 3]);
        assert_eq!(decoder.remaining(), 2);

        // Verify it's sharing the same underlying memory (Bytes::slice is zero-copy)
        assert_eq!(slice.as_ptr(), data.as_ptr());
    }

    #[test]
    fn test_zerobuf_read_usize() {
        let data = Bytes::from_static(&[0x96, 0x01]); // varint for 150
        let mut decoder = ZeroBuf::new(data);

        let len = decoder.read_usize(..=200).unwrap();
        assert_eq!(len, 150);
        assert!(decoder.is_empty());
    }

    #[test]
    fn test_zerobuf_length_prefixed_slice() {
        // Length-prefixed data: length=3, data=[1,2,3]
        let data = Bytes::from_static(&[3, 1, 2, 3]);
        let mut decoder = ZeroBuf::new(data);

        let len = decoder.read_usize(..=10).unwrap();
        let slice = decoder.slice(len).unwrap();

        assert_eq!(&slice[..], &[1, 2, 3]);
        assert!(decoder.is_empty());
    }

    #[test]
    fn test_zerobuf_mixed_owned_and_borrowed() {
        // u32 (4 bytes) + length-prefixed bytes
        let mut buf = 42u32.encode().to_vec();
        buf.extend_from_slice(&[3, 0xAA, 0xBB, 0xCC]);
        let data = Bytes::from(buf);

        let mut decoder = ZeroBuf::new(data);

        // Read owned u32
        let value: u32 = u32::read(&mut decoder).unwrap();
        assert_eq!(value, 42);

        // Read zero-copy Bytes slice
        let len = decoder.read_usize(..=10).unwrap();
        let slice = decoder.slice(len).unwrap();
        assert_eq!(&slice[..], &[0xAA, 0xBB, 0xCC]);

        decoder.finish().unwrap();
    }

    #[test]
    fn test_zerobuf_errors() {
        let data = Bytes::from_static(&[1, 2]);
        let mut decoder = ZeroBuf::new(data);

        // Try to read more than available
        assert!(matches!(decoder.slice(3), Err(Error::EndOfBuffer)));

        // Read what's available
        let _ = decoder.slice(2).unwrap();

        // Extra data check
        let decoder = ZeroBuf::new(Bytes::from_static(&[1, 2, 3]));
        assert!(matches!(decoder.finish(), Err(Error::ExtraData(3))));
    }

    #[test]
    fn test_zerobuf_remaining_bytes() {
        let data = Bytes::from_static(&[1, 2, 3, 4, 5]);
        let mut decoder = ZeroBuf::new(data.clone());

        // Get remaining as Bytes (zero-copy)
        let remaining = decoder.remaining_bytes();
        assert_eq!(&remaining[..], &[1, 2, 3, 4, 5]);
        assert_eq!(remaining.as_ptr(), data.as_ptr());

        // Advance and check remaining
        decoder.slice(2).unwrap();
        let remaining = decoder.remaining_bytes();
        assert_eq!(&remaining[..], &[3, 4, 5]);
    }

    #[test]
    fn test_zerobuf_clone() {
        let data = Bytes::from_static(&[1, 2, 3, 4, 5]);
        let mut decoder = ZeroBuf::new(data);
        decoder.slice(2).unwrap();

        // Clone preserves position
        let decoder2 = decoder.clone();
        assert_eq!(decoder2.remaining(), 3);
        assert_eq!(&decoder2.remaining_bytes()[..], &[3, 4, 5]);
    }
}
