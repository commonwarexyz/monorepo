//! # Acknowledgements
//!
//! This code is inspired by [tokio-uring](https://github.com/tokio-rs/tokio-uring>) at commit 7761222.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::Bytes;
use core::ops::Index;

#[derive(Debug, Clone, PartialEq, Eq)]
/// A buffer whose memory is stable as long as its not reallocated.
pub enum StableBuf {
    Vec(Vec<u8>),
    BytesMut(bytes::BytesMut),
}

impl Default for StableBuf {
    fn default() -> Self {
        Self::Vec(Vec::new())
    }
}

impl From<Vec<u8>> for StableBuf {
    fn from(v: Vec<u8>) -> Self {
        Self::Vec(v)
    }
}

impl From<bytes::BytesMut> for StableBuf {
    fn from(b: bytes::BytesMut) -> Self {
        Self::BytesMut(b)
    }
}

impl From<StableBuf> for Bytes {
    fn from(buf: StableBuf) -> Self {
        match buf {
            StableBuf::Vec(v) => Self::from(v),
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
            Self::Vec(v) => &v[index],
            Self::BytesMut(b) => &b[index],
        }
    }
}

impl StableBuf {
    /// Returns a raw pointer to this buffer.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        match self {
            Self::Vec(v) => v.as_mut_ptr(),
            Self::BytesMut(b) => b.as_mut_ptr(),
        }
    }

    /// Returns the length of the buffer.
    pub fn len(&self) -> usize {
        match self {
            Self::Vec(v) => v.len(),
            Self::BytesMut(b) => b.len(),
        }
    }

    /// Returns whether this buffer is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Vec(v) => v.is_empty(),
            Self::BytesMut(b) => b.is_empty(),
        }
    }

    /// Copies the given byte slice into this buffer.
    /// `src` must not overlap with this buffer.
    /// Panics if `src` exceeds this buffer's length.
    pub fn put_slice(&mut self, src: &[u8]) {
        let dst = self.as_mut_ptr();
        // SAFETY: Caller guarantees no overlap and sufficient length.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
    }

    /// Truncates the buffer to the specified length.
    pub fn truncate(&mut self, len: usize) {
        match self {
            Self::Vec(v) => v.truncate(len),
            Self::BytesMut(b) => b.truncate(len),
        }
    }
}

impl AsRef<[u8]> for StableBuf {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Vec(v) => v.as_ref(),
            Self::BytesMut(b) => b.as_ref(),
        }
    }
}

impl AsMut<[u8]> for StableBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Vec(v) => v.as_mut(),
            Self::BytesMut(b) => b.as_mut(),
        }
    }
}
