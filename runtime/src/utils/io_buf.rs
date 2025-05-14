// The contents of this file are based on https://github.com/tokio-rs/tokio-uring at commit 7761222.
// We don't want to depend on the whole crate, so we've copied/adapted the relevant parts.

/// An `io-uring` compatible buffer.
///
/// The `IoBuf` trait is implemented by buffer types that can be used with
/// io-uring operations. Users will not need to use this trait directly.
///
/// # Safety
///
/// Buffers passed to `io-uring` operations must reference a stable memory
/// region. While the runtime holds ownership to a buffer, the pointer returned
/// by `stable_ptr` must remain valid even if the `IoBuf` value is moved.
#[allow(clippy::len_without_is_empty)]
pub unsafe trait IoBuf: Unpin + Send + 'static {
    /// Returns a raw pointer to the vector’s buffer.
    ///
    /// This method is to be used internally and it is not
    /// expected for users to call it directly.
    ///
    /// The implementation must ensure that the pointer
    /// returned by `stable_ptr` **does not** change.
    fn stable_ptr(&self) -> *const u8;

    /// Length of the buffer.
    fn len(&self) -> usize;

    /// Returns the buffer as a slice.
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.stable_ptr(), self.len()) }
    }
}

unsafe impl IoBuf for Vec<u8> {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn len(&self) -> usize {
        self.len()
    }
}

unsafe impl IoBuf for &'static [u8] {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

unsafe impl IoBuf for &'static str {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn len(&self) -> usize {
        <str>::len(self)
    }
}

unsafe impl IoBuf for bytes::Bytes {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn len(&self) -> usize {
        self.len()
    }
}

unsafe impl IoBuf for bytes::BytesMut {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn len(&self) -> usize {
        self.len()
    }
}
