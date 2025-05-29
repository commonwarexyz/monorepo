//! # Acknowledgements
//!
//! This code is inspired by [tokio-uring](https://github.com/tokio-rs/tokio-uring>) at commit 7761222.

pub enum StableBuf2 {
    Vec(Vec<u8>),
    Bytes(bytes::Bytes),
    BytesMut(bytes::BytesMut),
    StaticStr(&'static str),
    StaticSlice(&'static [u8]),
}

impl StableBuf2 {
    /// Returns a raw pointer to this buffer.
    pub fn stable_ptr(&self) -> *const u8 {
        match self {
            StableBuf2::Vec(v) => v.as_ptr(),
            StableBuf2::Bytes(b) => b.as_ptr(),
            StableBuf2::BytesMut(b) => b.as_ptr(),
            StableBuf2::StaticStr(s) => s.as_ptr(),
            StableBuf2::StaticSlice(s) => s.as_ptr(),
        }
    }

    /// Returns the length of the buffer.
    pub fn len(&self) -> usize {
        match self {
            StableBuf2::Vec(v) => v.len(),
            StableBuf2::Bytes(b) => b.len(),
            StableBuf2::BytesMut(b) => b.len(),
            StableBuf2::StaticStr(s) => s.len(),
            StableBuf2::StaticSlice(s) => s.len(),
        }
    }

    /// Returns the buffer as a slice.
    pub fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.stable_ptr(), self.len()) }
    }
}

/// A buffer with a stable memory address.
/// # Safety
/// The implementor must guarantee that the pointer remains valid
/// and unchanged while the buffer is being used.
#[allow(clippy::len_without_is_empty)]
pub unsafe trait StableBuf: Unpin + Send + Sync + 'static {
    /// Returns a raw pointer to this buffer.
    fn stable_ptr(&self) -> *const u8;

    /// Length of the buffer.
    fn len(&self) -> usize;

    /// Returns the buffer as a slice.
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.stable_ptr(), self.len()) }
    }
}

unsafe impl StableBuf for Vec<u8> {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn len(&self) -> usize {
        self.len()
    }
}

unsafe impl StableBuf for &'static [u8] {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

unsafe impl StableBuf for &'static str {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn len(&self) -> usize {
        <str>::len(self)
    }
}

unsafe impl StableBuf for bytes::Bytes {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn len(&self) -> usize {
        self.len()
    }
}

unsafe impl StableBuf for bytes::BytesMut {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn len(&self) -> usize {
        self.len()
    }
}
