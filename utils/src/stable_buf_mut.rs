//! # Acknowledgements
//!
//! This code is inspired by [tokio-uring](https://github.com/tokio-rs/tokio-uring>) at commit 7761222.

use std::ops::Index;

use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StableBufMut {
    Vec(Vec<u8>),
    BytesMut(bytes::BytesMut),
}

unsafe impl Send for StableBufMut {}

impl Default for StableBufMut {
    fn default() -> Self {
        StableBufMut::Vec(Vec::new())
    }
}

impl From<Vec<u8>> for StableBufMut {
    fn from(v: Vec<u8>) -> Self {
        StableBufMut::Vec(v)
    }
}

impl From<bytes::BytesMut> for StableBufMut {
    fn from(b: bytes::BytesMut) -> Self {
        StableBufMut::BytesMut(b)
    }
}

impl From<StableBufMut> for Bytes {
    fn from(buf: StableBufMut) -> Self {
        match buf {
            StableBufMut::Vec(v) => Bytes::from(v),
            StableBufMut::BytesMut(b) => b.freeze(),
        }
    }
}

impl Index<usize> for StableBufMut {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            StableBufMut::Vec(v) => &v[index],
            StableBufMut::BytesMut(b) => &b[index],
        }
    }
}

impl StableBufMut {
    /// Returns a raw pointer to this buffer.
    pub fn stable_mut_ptr(&mut self) -> *mut u8 {
        match self {
            StableBufMut::Vec(v) => v.as_mut_ptr(),
            StableBufMut::BytesMut(b) => b.as_mut_ptr(),
        }
    }

    /// Returns the length of the buffer.
    pub fn len(&self) -> usize {
        match self {
            StableBufMut::Vec(v) => v.len(),
            StableBufMut::BytesMut(b) => b.len(),
        }
    }

    /// Returns whether this buffer is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            StableBufMut::Vec(v) => v.is_empty(),
            StableBufMut::BytesMut(b) => b.is_empty(),
        }
    }

    /// Copies the given byte slice into this buffer.
    /// `src` must not overlap with this buffer.
    /// Panics if `src` exceeds this buffer's length.
    pub fn put_slice(&mut self, src: &[u8]) {
        let dst = self.stable_mut_ptr();
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
    }

    /// Truncates the buffer to the specified length.
    pub fn truncate(&mut self, len: usize) {
        match self {
            StableBufMut::Vec(v) => v.truncate(len),
            StableBufMut::BytesMut(b) => b.truncate(len),
        }
    }
}

impl AsRef<[u8]> for StableBufMut {
    fn as_ref(&self) -> &[u8] {
        match self {
            StableBufMut::Vec(v) => v.as_ref(),
            StableBufMut::BytesMut(b) => b.as_ref(),
        }
    }
}

impl AsMut<[u8]> for StableBufMut {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            StableBufMut::Vec(v) => v.as_mut(),
            StableBufMut::BytesMut(b) => b.as_mut(),
        }
    }
}

// /// A mutable buffer with a stable memory address.
// /// # Safety
// /// The implementor must guarantee that the pointer remains valid
// /// and unchanged while the buffer is being used.
// pub unsafe trait StableBufMut: StableBuf {
//     /// Returns a raw pointer to this buffer.
//     fn stable_mut_ptr(&mut self) -> *mut u8;

//     /// Copies the given byte slice into this buffer.
//     /// `src` must not overlap with this buffer.
//     /// Panics if `src` exceeds this buffer's length.
//     fn put_slice(&mut self, src: &[u8]) {
//         let dst = self.stable_mut_ptr();
//         unsafe {
//             std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
//         }
//     }

//     /// Returns the buffer as a mutable slice.
//     fn deref_mut(&mut self) -> &mut [u8] {
//         unsafe { std::slice::from_raw_parts_mut(self.stable_mut_ptr(), self.len()) }
//     }
// }

// unsafe impl StableBufMut for Vec<u8> {
//     fn stable_mut_ptr(&mut self) -> *mut u8 {
//         self.as_mut_ptr()
//     }
// }

// unsafe impl StableBufMut for bytes::BytesMut {
//     fn stable_mut_ptr(&mut self) -> *mut u8 {
//         self.as_mut_ptr()
//     }
// }
