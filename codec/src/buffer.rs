//! Buffer implementation with advanced safety features

use crate::{error::Error, varint};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// A buffer for reading codec data with safety checks
#[derive(Debug)]
pub struct ReadBuffer {
    /// The underlying bytes
    inner: Bytes,
}

impl ReadBuffer {
    /// Creates a new reader from bytes
    pub fn new(bytes: Bytes) -> Self {
        Self { inner: bytes }
    }

    /// Reads a varint-encoded unsigned integer
    #[inline]
    pub fn read_varint(&mut self) -> Result<u64, Error> {
        varint::decode_varint(&mut self.inner)
    }

    /// Gets a byte from the buffer
    #[inline]
    pub fn get_u8(&mut self) -> Result<u8, Error> {
        if !self.has_remaining() {
            return Err(Error::EndOfBuffer);
        }
        Ok(self.inner.get_u8())
    }

    /// Gets remaining bytes
    #[inline]
    pub fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    /// Checks if the buffer has any remaining bytes
    #[inline]
    pub fn has_remaining(&self) -> bool {
        self.remaining() > 0
    }

    /// Ensures the buffer has at least `size` bytes remaining
    #[inline]
    pub fn at_least(&self, size: usize) -> Result<(), Error> {
        if self.remaining() < size {
            return Err(Error::EndOfBuffer);
        }
        Ok(())
    }

    /// Advance the buffer by `cnt` bytes
    #[inline]
    pub fn advance(&mut self, cnt: usize) {
        self.inner.advance(cnt);
    }

    // Implement methods from Buf trait with safety checks
    #[inline]
    pub fn get_u16(&mut self) -> Result<u16, Error> {
        self.at_least(2)?;
        Ok(self.inner.get_u16())
    }

    #[inline]
    pub fn get_u32(&mut self) -> Result<u32, Error> {
        self.at_least(4)?;
        Ok(self.inner.get_u32())
    }

    #[inline]
    pub fn get_u64(&mut self) -> Result<u64, Error> {
        self.at_least(8)?;
        Ok(self.inner.get_u64())
    }

    #[inline]
    pub fn get_u128(&mut self) -> Result<u128, Error> {
        self.at_least(16)?;
        Ok(self.inner.get_u128())
    }

    #[inline]
    pub fn get_i8(&mut self) -> Result<i8, Error> {
        self.at_least(1)?;
        Ok(self.inner.get_i8())
    }

    #[inline]
    pub fn get_i16(&mut self) -> Result<i16, Error> {
        self.at_least(2)?;
        Ok(self.inner.get_i16())
    }

    #[inline]
    pub fn get_i32(&mut self) -> Result<i32, Error> {
        self.at_least(4)?;
        Ok(self.inner.get_i32())
    }

    #[inline]
    pub fn get_i64(&mut self) -> Result<i64, Error> {
        self.at_least(8)?;
        Ok(self.inner.get_i64())
    }

    #[inline]
    pub fn get_i128(&mut self) -> Result<i128, Error> {
        self.at_least(16)?;
        Ok(self.inner.get_i128())
    }

    #[inline]
    pub fn get_f32(&mut self) -> Result<f32, Error> {
        self.at_least(4)?;
        Ok(self.inner.get_f32())
    }

    #[inline]
    pub fn get_f64(&mut self) -> Result<f64, Error> {
        self.at_least(8)?;
        Ok(self.inner.get_f64())
    }

    #[inline]
    pub fn copy_to_slice(&mut self, dst: &mut [u8]) -> Result<(), Error> {
        self.at_least(dst.len())?;
        self.inner.copy_to_slice(dst);
        Ok(())
    }

    #[inline]
    pub fn split_to(&mut self, size: usize) -> Result<Bytes, Error> {
        self.at_least(size)?;
        Ok(self.inner.split_to(size))
    }

    /// Returns a reference to the internal buffer
    pub fn inner(&self) -> &Bytes {
        &self.inner
    }
}

/// A buffer for writing codec data
#[derive(Debug)]
pub struct WriteBuffer {
    /// The underlying buffer
    inner: BytesMut,
}

impl WriteBuffer {
    /// Creates a new write buffer
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: BytesMut::with_capacity(capacity),
        }
    }

    /// Returns the remaining capacity of the buffer
    #[inline]
    pub fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    /// Writes a varint-encoded unsigned integer
    #[inline]
    pub fn write_varint(&mut self, value: u64) {
        varint::encode_varint(value, &mut self.inner);
    }

    /// Returns the current length of the buffer
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Checks if the buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Freezes the buffer and returns the bytes
    pub fn freeze(self) -> Bytes {
        self.inner.freeze()
    }

    /// Resets the buffer
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    // Delegate to inner buffer's BufMut implementation
    #[inline]
    pub fn put_u8(&mut self, v: u8) {
        self.inner.put_u8(v);
    }

    #[inline]
    pub fn put_u16(&mut self, v: u16) {
        self.inner.put_u16(v);
    }

    #[inline]
    pub fn put_u32(&mut self, v: u32) {
        self.inner.put_u32(v);
    }

    #[inline]
    pub fn put_u64(&mut self, v: u64) {
        self.inner.put_u64(v);
    }

    #[inline]
    pub fn put_u128(&mut self, v: u128) {
        self.inner.put_u128(v);
    }

    #[inline]
    pub fn put_i8(&mut self, v: i8) {
        self.inner.put_i8(v);
    }

    #[inline]
    pub fn put_i16(&mut self, v: i16) {
        self.inner.put_i16(v);
    }

    #[inline]
    pub fn put_i32(&mut self, v: i32) {
        self.inner.put_i32(v);
    }

    #[inline]
    pub fn put_i64(&mut self, v: i64) {
        self.inner.put_i64(v);
    }

    #[inline]
    pub fn put_i128(&mut self, v: i128) {
        self.inner.put_i128(v);
    }

    #[inline]
    pub fn put_f32(&mut self, v: f32) {
        self.inner.put_f32(v);
    }

    #[inline]
    pub fn put_f64(&mut self, v: f64) {
        self.inner.put_f64(v);
    }

    #[inline]
    pub fn put_slice(&mut self, src: &[u8]) {
        self.inner.put_slice(src);
    }
}

impl From<WriteBuffer> for Vec<u8> {
    fn from(buffer: WriteBuffer) -> Self {
        buffer.inner.to_vec()
    }
}

impl From<WriteBuffer> for Bytes {
    fn from(buffer: WriteBuffer) -> Self {
        buffer.freeze()
    }
}

impl AsRef<[u8]> for WriteBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}
