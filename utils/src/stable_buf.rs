//! # Acknowledgements
//!
//! This code is inspired by [tokio-uring](https://github.com/tokio-rs/tokio-uring>) at commit 7761222.

use bytes::Bytes;
use std::ops::Index;

#[derive(Debug, Clone, PartialEq, Eq)]
/// A buffer whose memory is stable as long as its not reallocated.
pub enum StableBuf {
    Vec(Vec<u8>),
    BytesMut(bytes::BytesMut),
}

impl Default for StableBuf {
    fn default() -> Self {
        StableBuf::Vec(Vec::new())
    }
}

impl From<Vec<u8>> for StableBuf {
    fn from(v: Vec<u8>) -> Self {
        StableBuf::Vec(v)
    }
}

impl From<bytes::BytesMut> for StableBuf {
    fn from(b: bytes::BytesMut) -> Self {
        StableBuf::BytesMut(b)
    }
}

impl From<StableBuf> for Bytes {
    fn from(buf: StableBuf) -> Self {
        match buf {
            StableBuf::Vec(v) => Bytes::from(v),
            StableBuf::BytesMut(b) => b.freeze(),
        }
    }
}

impl From<StableBuf> for Vec<u8> {
    fn from(buf: StableBuf) -> Self {
        match buf {
            StableBuf::Vec(v) => v,
            StableBuf::BytesMut(b) => b.to_vec(),
        }
    }
}

impl Index<usize> for StableBuf {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            StableBuf::Vec(v) => &v[index],
            StableBuf::BytesMut(b) => &b[index],
        }
    }
}

impl StableBuf {
    /// Returns a raw pointer to this buffer.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        match self {
            StableBuf::Vec(v) => v.as_mut_ptr(),
            StableBuf::BytesMut(b) => b.as_mut_ptr(),
        }
    }

    /// Returns the length of the buffer.
    pub fn len(&self) -> usize {
        match self {
            StableBuf::Vec(v) => v.len(),
            StableBuf::BytesMut(b) => b.len(),
        }
    }

    /// Returns whether this buffer is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            StableBuf::Vec(v) => v.is_empty(),
            StableBuf::BytesMut(b) => b.is_empty(),
        }
    }

    /// Copies the given byte slice into this buffer.
    /// `src` must not overlap with this buffer.
    /// Panics if `src` exceeds this buffer's length.
    pub fn put_slice(&mut self, src: &[u8]) {
        let dst = self.as_mut_ptr();
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
    }

    /// Truncates the buffer to the specified length.
    pub fn truncate(&mut self, len: usize) {
        match self {
            StableBuf::Vec(v) => v.truncate(len),
            StableBuf::BytesMut(b) => b.truncate(len),
        }
    }

    /// Splits the buffer into two at the given index.
    ///
    /// Returns a new `StableBuf` containing the bytes from `at` to the end,
    /// while `self` retains bytes from 0 to `at`.
    ///
    /// # Panics
    ///
    /// Panics if `at > len`.
    pub fn split_off(&mut self, at: usize) -> StableBuf {
        match self {
            StableBuf::Vec(v) => StableBuf::Vec(v.split_off(at)),
            StableBuf::BytesMut(b) => StableBuf::BytesMut(b.split_off(at)),
        }
    }

    /// Absorbs a buffer that was previously split off.
    ///
    /// Appends the contents of `other` to `self`, consuming `other`.
    /// This is the inverse of `split_off`.
    ///
    /// # Performance
    ///
    /// This operation is O(1) only when both buffers are [StableBuf::BytesMut]
    /// variants that were previously split from the same buffer and haven't
    /// been mutated in a way that caused reallocation (e.g. growing beyond
    /// capacity). In all other cases it requires copying the data.
    pub fn unsplit(&mut self, other: StableBuf) {
        match (self, other) {
            (StableBuf::Vec(v), StableBuf::Vec(mut other_v)) => {
                v.append(&mut other_v);
            }
            (StableBuf::BytesMut(b), StableBuf::BytesMut(other_b)) => {
                b.unsplit(other_b);
            }
            (StableBuf::Vec(v), StableBuf::BytesMut(other_b)) => {
                v.extend_from_slice(&other_b);
            }
            (StableBuf::BytesMut(b), StableBuf::Vec(other_v)) => {
                b.extend_from_slice(&other_v);
            }
        }
    }
}

impl AsRef<[u8]> for StableBuf {
    fn as_ref(&self) -> &[u8] {
        match self {
            StableBuf::Vec(v) => v.as_ref(),
            StableBuf::BytesMut(b) => b.as_ref(),
        }
    }
}

impl AsMut<[u8]> for StableBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            StableBuf::Vec(v) => v.as_mut(),
            StableBuf::BytesMut(b) => b.as_mut(),
        }
    }
}
