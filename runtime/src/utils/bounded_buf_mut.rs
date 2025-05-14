// The contents of this file are from based on https://github.com/tokio-rs/tokio-uring at commit 7761222.
// We don't want to depend on the whole crate, so we've copied/adapted the relevant parts.
use super::{BoundedBuf, IoBufMut};

/// A possibly bounded view into an owned [`IoBufMut`] buffer.
///
/// This trait provides a generic way to use mutable buffers and `Slice` views
/// into such buffers with `io-uring` operations.
pub trait BoundedBufMut: BoundedBuf<Buf = Self::BufMut> + Send {
    /// The type of the underlying buffer.
    type BufMut: IoBufMut;

    /// Like [`IoBufMut::stable_mut_ptr`],
    /// but possibly offset to the view's starting position.
    fn stable_mut_ptr(&mut self) -> *mut u8;

    /// Like [`IoBufMut::set_len`],
    /// but the position is possibly offset to the view's starting position.
    ///
    /// # Safety
    ///
    /// The caller must ensure that all bytes starting at `stable_mut_ptr()` up
    /// to `pos` are initialized and owned by the buffer.
    unsafe fn set_len(&mut self, pos: usize);

    /// Copies the given byte slice into the buffer, starting at
    /// this view's offset.
    ///
    /// # Panics
    ///
    /// If the slice's length exceeds the destination's total capacity,
    /// this method panics.
    fn put_slice(&mut self, src: &[u8]) {
        assert!(self.capacity() >= src.len());
        let dst = self.stable_mut_ptr();

        // Safety:
        // dst pointer validity is ensured by stable_mut_ptr;
        // the length is checked to not exceed the view's total capacity;
        // src (immutable) and dst (mutable) cannot point to overlapping memory;
        // after copying the amount of bytes given by the slice, it's safe
        // to mark them as initialized in the buffer.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
            self.set_len(src.len());
        }
    }
}

impl<T: IoBufMut> BoundedBufMut for T {
    type BufMut = T;

    fn stable_mut_ptr(&mut self) -> *mut u8 {
        IoBufMut::stable_mut_ptr(self)
    }

    unsafe fn set_len(&mut self, pos: usize) {
        IoBufMut::set_len(self, pos)
    }
}
