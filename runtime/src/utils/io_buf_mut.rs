// The contents of this file are based on https://github.com/tokio-rs/tokio-uring at commit 7761222.
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

    /// Copies the given byte slice into this buffer.
    ///
    /// Panics if `src` exceeds this buffer's length.
    fn put_slice(&mut self, src: &[u8]) {
        let dst = self.stable_mut_ptr();

        // Safety:
        // * dst pointer validity is ensured by stable_mut_ptr;
        // * the length is checked to not exceed the buf's length;
        // * src (immutable) and dst (mutable) cannot point to overlapping memory;
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
    }

    /// Returns the buffer as a mutable slice.
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.stable_mut_ptr(), self.len()) }
    }
}

unsafe impl IoBufMut for Vec<u8> {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_ptr()
    }
}

unsafe impl IoBufMut for bytes::BytesMut {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_ptr()
    }
}
