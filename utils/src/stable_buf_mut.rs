//! # Acknowledgements
//!
//! This code is inspired by [tokio-uring](https://github.com/tokio-rs/tokio-uring>) at commit 7761222.

use crate::stable_buf::StableBuf;

/// A mutable buffer with a stable memory address.
/// # Safety
/// The implementor must guarantee that the pointer remains valid
/// and unchanged while the buffer is being used.
pub unsafe trait StableBufMut: StableBuf {
    /// Returns a raw pointer to this buffer.
    fn stable_mut_ptr(&mut self) -> *mut u8;

    /// Copies the given byte slice into this buffer.
    /// `src` must not overlap with this buffer.
    /// Panics if `src` exceeds this buffer's length.
    fn put_slice(&mut self, src: &[u8]) {
        let dst = self.stable_mut_ptr();
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
    }

    /// Returns the buffer as a mutable slice.
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.stable_mut_ptr(), self.len()) }
    }
}

unsafe impl StableBufMut for Vec<u8> {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_ptr()
    }
}

unsafe impl StableBufMut for bytes::BytesMut {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_ptr()
    }
}
