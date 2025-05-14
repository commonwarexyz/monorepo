// The contents of this file are from based on https://github.com/tokio-rs/tokio-uring at commit 7761222.
// We don't want to depend on the whole crate, so we've copied/adapted the relevant parts.
use super::IoBuf;

/// A mutable`io-uring` compatible buffer.
///
/// The `IoBufMut` trait is implemented by buffer types that can be used with
/// io-uring operations. Users will not need to use this trait directly.
///
/// # Safety
///
/// Buffers passed to `io-uring` operations must reference a stable memory
/// region. While the runtime holds ownership to a buffer, the pointer returned
/// by `stable_mut_ptr` must remain valid even if the `IoBufMut` value is moved.
pub unsafe trait IoBufMut: IoBuf {
    /// Returns a raw mutable pointer to the vector’s buffer.
    ///
    /// This method is to be used by the runtime and it is not
    /// expected for users to call it directly.
    ///
    /// The implementation must ensure that, while the runtime
    /// owns the value, the pointer returned by `stable_mut_ptr` **does not**
    /// change.
    fn stable_mut_ptr(&mut self) -> *mut u8;

    /// Updates the number of initialized bytes.
    ///
    /// If the specified `pos` is greater than the value returned by
    /// [`IoBuf::len`], it becomes the new water mark as returned by
    /// `IoBuf::len`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that all bytes starting at `stable_mut_ptr()` up
    /// to `pos` are initialized and owned by the buffer.
    unsafe fn set_len(&mut self, pos: usize);
}

unsafe impl IoBufMut for Vec<u8> {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_ptr()
    }

    unsafe fn set_len(&mut self, init_len: usize) {
        if self.len() < init_len {
            self.set_len(init_len);
        }
    }
}

unsafe impl IoBufMut for bytes::BytesMut {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_ptr()
    }

    unsafe fn set_len(&mut self, init_len: usize) {
        if self.len() < init_len {
            self.set_len(init_len);
        }
    }
}
