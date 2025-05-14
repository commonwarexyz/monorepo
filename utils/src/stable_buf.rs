//! # Acknowledgements
//!
//! This code is inspired by [tokio-uring](https://github.com/tokio-rs/tokio-uring>) at commit 7761222.

/// A buffer with a stable memory address.
/// # Safety
/// The implementor must guarantee that the pointer remains valid
/// and unchanged while the buffer is being used.
#[allow(clippy::len_without_is_empty)]
pub unsafe trait StableBuf: Unpin + Send + 'static {
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
