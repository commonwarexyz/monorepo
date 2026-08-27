//! Buffer types for I/O operations.
//!
//! `IoBuf` and `IoBufMut` store readable/writable cursor state directly in the
//! public handle. Allocation ownership lives in a compact tagged owner
//! reference: runtime-owned heap buffers keep a header inside their own
//! allocation (in front of the data for low-alignment mutable buffers, at the
//! tail for high-alignment ones and adopted vecs), pooled buffers keep their
//! owner record in a per-slot side table owned by the size class,
//! caller-supplied `Vec<u8>` values converted to immutable buffers are adopted
//! into the native heap form when their spare capacity allows (mutable
//! conversions copy to preserve the caller's capacity), and caller-supplied
//! [`Bytes`] values are held zero-copy by a small external owner. This keeps
//! `bytes::Buf` and `bytes::BufMut` hot paths as simple pointer/length
//! arithmetic. `owner.rs` documents the owner model.
//!
//! Throughout this module, "native" means runtime-owned storage whose owner
//! supports zero-copy mutable recovery through [`IoBuf::try_into_mut`]: heap
//! allocations (front or tail header), pooled buffers, and adopted vecs, as
//! opposed to external `Bytes` and `'static` views.
//!
//! # Conversions
//!
//! Every `From` conversion into [`IoBuf`] or [`IoBufs`] is zero-copy: the
//! payload is never copied. Most conversions require at most one small owner
//! allocation. A `Vec<u8>` that cannot host an inline owner may require two
//! small metadata allocations: one for `bytes` shared ownership and one for
//! the external owner. Conversions into [`IoBufMut`] or [`IoBufsMut`] are
//! zero-copy where the source allocation can back a mutable handle and copy
//! otherwise. Each mutable conversion documents which one it is, and
//! conversions out of the handles document their cost on each impl.
//!
//! Because untracked heap buffers embed their owner header in the same
//! allocation, a power-of-two capacity request may land in the allocator's
//! next size bin. Pooled buffers do not pay this: their side-table record
//! keeps the data allocation exactly the class size.
//!
//! Public types:
//! - [`IoBuf`]: Immutable byte buffer
//! - [`IoBufMut`]: Mutable byte buffer
//! - [`IoBufs`]: Container for one or more immutable buffers
//! - [`IoBufsMut`]: Container for one or more mutable buffers
//! - [`BufferPool`]: Pool of reusable, aligned buffers
//! - [`Builder`]: Assembles [`IoBufs`] from inline writes and zero-copy pieces
//!
//! # Examples
//!
//! The core lifecycle: fill a fixed-capacity mutable buffer, freeze it into
//! cheaply cloneable immutable views, and recover the mutable handle (with
//! its spare capacity) once the views are gone:
//!
//! ```
//! use commonware_runtime::{Buf, BufMut, IoBuf, IoBufMut};
//!
//! let mut buf = IoBufMut::with_capacity(8);
//! buf.put_slice(b"abcdef");
//!
//! let frozen: IoBuf = buf.freeze();
//! let head = frozen.slice(..3);
//! assert_eq!(head, b"abc"[..]);
//!
//! // A live view shares the owner, so recovery declines.
//! let frozen = frozen.try_into_mut().unwrap_err();
//! drop(head);
//!
//! // Unique again: the mutable handle returns with its spare capacity.
//! let mut recovered = frozen.try_into_mut().unwrap();
//! assert_eq!(recovered.as_ref(), b"abcdef");
//! assert_eq!(recovered.capacity(), 8);
//! recovered.put_slice(b"gh");
//! ```
//!
//! [`Bytes`]: bytes::Bytes

mod buf;
mod bufs;
mod owner;
mod pool;

pub use buf::{IoBuf, IoBufMut};
pub use bufs::{Builder, EncodeExt, IoBufs, IoBufsMut};
use crossbeam_utils::CachePadded;
pub use pool::{
    BufferPool, BufferPoolClassConfig, BufferPoolConfig, BufferPoolThreadCache, PoolError,
};
use std::mem::align_of;

/// Returns the system page size.
///
/// On Unix systems, queries the actual page size via `sysconf`.
/// On WebAssembly, defaults to 4KB.
#[allow(clippy::missing_const_for_fn)]
pub fn page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: sysconf is safe to call.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size <= 0 {
            4096 // Safe fallback if sysconf fails
        } else {
            size as usize
        }
    }

    #[cfg(not(unix))]
    {
        4096
    }
}

/// Returns the cache line size for the current architecture.
pub const fn cache_line_size() -> usize {
    align_of::<CachePadded<u8>>()
}

/// Panics for cursor or write operations that run past the available region.
///
/// Outlined so the `Buf`/`BufMut` fast paths inline as a compare, a branch,
/// and a memcpy, mirroring the panic helpers in `bytes`.
#[cold]
#[inline(never)]
fn panic_advance(requested: usize, available: usize) -> ! {
    panic!("cannot advance past end of buffer: requested {requested}, available {available}");
}

/// Benchmark-only access to internal pool machinery.
///
/// Raw pooled buffers reference owner metadata stored by their freelist.
/// Taking one requires the caller to keep that freelist alive, and returning
/// one requires proof that it came from the target freelist:
///
/// ```compile_fail,E0133
/// use commonware_runtime::iobuf::bench::{Freelist, PooledBuffer};
///
/// fn return_buffer(freelist: &Freelist, buffer: PooledBuffer) {
///     freelist.put(buffer);
/// }
/// ```
#[doc(hidden)]
#[cfg(feature = "bench")]
pub mod bench {
    pub use super::owner::{PooledBuffer, PooledOwner};
    use std::{
        alloc::Layout,
        num::{NonZeroU32, NonZeroUsize},
    };

    /// Raw freelist access for benchmarks.
    ///
    /// Pooled buffers carry no type-level identity for their originating
    /// freelist, so return operations are unsafe at this public boundary.
    pub struct Freelist(super::pool::Freelist);

    impl Freelist {
        /// Creates a fixed-capacity benchmark freelist.
        pub fn new(
            capacity: NonZeroU32,
            parallelism: NonZeroUsize,
            layout: Layout,
            prefill: bool,
        ) -> Self {
            Self(super::pool::Freelist::new(
                capacity,
                parallelism,
                layout,
                prefill,
            ))
        }

        /// Returns one available pooled buffer.
        ///
        /// ```compile_fail,E0133
        /// use commonware_runtime::iobuf::bench::Freelist;
        ///
        /// fn take(freelist: &Freelist) {
        ///     let _buffer = freelist.take();
        /// }
        /// ```
        ///
        /// # Safety
        ///
        /// The returned buffer references owner metadata stored by this
        /// freelist. This freelist must remain alive until the buffer is
        /// returned here or deallocated.
        #[inline]
        pub unsafe fn take(&self) -> Option<PooledBuffer> {
            self.0.take()
        }

        /// Returns up to `max` available pooled buffers to `on_entry`.
        ///
        /// `on_entry` must not panic. A panic can strand claimed buffers
        /// outside the freelist and leak their allocations.
        ///
        /// ```compile_fail,E0133
        /// use commonware_runtime::iobuf::bench::Freelist;
        ///
        /// fn take_batch(freelist: &Freelist) {
        ///     freelist.take_batch(1, |_| {});
        /// }
        /// ```
        ///
        /// # Safety
        ///
        /// Every buffer passed to `on_entry` references owner metadata stored
        /// by this freelist. This freelist must remain alive until all such
        /// buffers are returned here or deallocated.
        #[inline]
        pub unsafe fn take_batch(&self, max: usize, on_entry: impl FnMut(PooledBuffer)) -> usize {
            self.0.take_batch(max, on_entry)
        }

        /// Returns one pooled buffer to this freelist.
        ///
        /// # Safety
        ///
        /// `buffer` must have been taken from this freelist, and its slot must
        /// not already be available here.
        #[inline]
        pub unsafe fn put(&self, buffer: PooledBuffer) {
            self.0.put(buffer);
        }

        /// Returns several pooled buffers to this freelist.
        ///
        /// If the iterator panics, buffers already accepted by this method may
        /// leak.
        ///
        /// # Safety
        ///
        /// Every buffer must have been taken from this freelist. Their slots
        /// must be unique within the batch and unavailable in the freelist.
        #[inline]
        pub unsafe fn put_batch(&self, buffers: impl IntoIterator<Item = PooledBuffer>) {
            self.0.put_batch(buffers);
        }

        /// Drops every currently available pooled buffer.
        #[inline]
        pub fn drain(&self) -> usize {
            self.0.drain()
        }
    }
}
