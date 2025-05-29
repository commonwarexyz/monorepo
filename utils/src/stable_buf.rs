//! # Acknowledgements
//!
//! This code is inspired by [tokio-uring](https://github.com/tokio-rs/tokio-uring>) at commit 7761222.

use crate::StableBufMut;

pub enum StableBuf {
    Vec(Vec<u8>),
    Bytes(bytes::Bytes),
    BytesMut(bytes::BytesMut),
    StaticStr(&'static str),
    StaticSlice(&'static [u8]),
}

impl From<StableBufMut> for StableBuf {
    fn from(buf: StableBufMut) -> Self {
        match buf {
            StableBufMut::Vec(v) => StableBuf::Vec(v),
            StableBufMut::BytesMut(b) => StableBuf::BytesMut(b),
        }
    }
}

impl From<Vec<u8>> for StableBuf {
    fn from(v: Vec<u8>) -> Self {
        StableBuf::Vec(v)
    }
}

impl From<bytes::Bytes> for StableBuf {
    fn from(b: bytes::Bytes) -> Self {
        StableBuf::Bytes(b)
    }
}

impl From<bytes::BytesMut> for StableBuf {
    fn from(b: bytes::BytesMut) -> Self {
        StableBuf::BytesMut(b)
    }
}

impl From<&'static str> for StableBuf {
    fn from(s: &'static str) -> Self {
        StableBuf::StaticStr(s)
    }
}

impl From<&'static [u8]> for StableBuf {
    fn from(s: &'static [u8]) -> Self {
        StableBuf::StaticSlice(s)
    }
}

impl StableBuf {
    /// Returns a raw pointer to this buffer.
    pub fn stable_ptr(&self) -> *const u8 {
        match self {
            StableBuf::Vec(v) => v.as_ptr(),
            StableBuf::Bytes(b) => b.as_ptr(),
            StableBuf::BytesMut(b) => b.as_ptr(),
            StableBuf::StaticStr(s) => s.as_ptr(),
            StableBuf::StaticSlice(s) => s.as_ptr(),
        }
    }

    /// Returns the length of the buffer.
    pub fn len(&self) -> usize {
        match self {
            StableBuf::Vec(v) => v.len(),
            StableBuf::Bytes(b) => b.len(),
            StableBuf::BytesMut(b) => b.len(),
            StableBuf::StaticStr(s) => s.len(),
            StableBuf::StaticSlice(s) => s.len(),
        }
    }

    /// Returns the buffer as a slice.
    pub fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.stable_ptr(), self.len()) }
    }
}

// /// A buffer with a stable memory address.
// /// # Safety
// /// The implementor must guarantee that the pointer remains valid
// /// and unchanged while the buffer is being used.
// #[allow(clippy::len_without_is_empty)]
// pub unsafe trait StableBuf: Unpin + Send + Sync + 'static {
//     /// Returns a raw pointer to this buffer.
//     fn stable_ptr(&self) -> *const u8;

//     /// Length of the buffer.
//     fn len(&self) -> usize;

//     /// Returns the buffer as a slice.
//     fn as_ref(&self) -> &[u8] {
//         unsafe { std::slice::from_raw_parts(self.stable_ptr(), self.len()) }
//     }
// }

// unsafe impl StableBuf for Vec<u8> {
//     fn stable_ptr(&self) -> *const u8 {
//         self.as_ptr()
//     }

//     fn len(&self) -> usize {
//         self.len()
//     }
// }

// unsafe impl StableBuf for &'static [u8] {
//     fn stable_ptr(&self) -> *const u8 {
//         self.as_ptr()
//     }

//     fn len(&self) -> usize {
//         <[u8]>::len(self)
//     }
// }

// unsafe impl StableBuf for &'static str {
//     fn stable_ptr(&self) -> *const u8 {
//         self.as_ptr()
//     }

//     fn len(&self) -> usize {
//         <str>::len(self)
//     }
// }

// unsafe impl StableBuf for bytes::Bytes {
//     fn stable_ptr(&self) -> *const u8 {
//         self.as_ptr()
//     }

//     fn len(&self) -> usize {
//         self.len()
//     }
// }

// unsafe impl StableBuf for bytes::BytesMut {
//     fn stable_ptr(&self) -> *const u8 {
//         self.as_ptr()
//     }

//     fn len(&self) -> usize {
//         self.len()
//     }
// }
