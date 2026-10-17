//! Buffer types for I/O operations.
//!
//! `IoBuf` and `IoBufMut` store readable/writable cursor state directly in the
//! public handle. Allocation ownership lives in a compact tagged owner
//! reference: runtime-owned heap buffers keep their owner record in a
//! separate small allocation so the data allocation is exactly the requested
//! size and alignment, caller-supplied `Vec<u8>` values are adopted into that
//! same native form without copying, and caller-supplied [`Bytes`] values
//! are held zero-copy by a small external owner. This keeps `bytes::Buf`
//! and `bytes::BufMut` hot paths as simple pointer/length arithmetic.
//! `owner.rs` documents the owner model.
//!
//! Throughout this module, "native" means runtime-owned storage whose owner
//! supports zero-copy mutable recovery through [`IoBuf::try_into_mut`]: heap
//! allocations and adopted vecs, as opposed to external `Bytes` and
//! `'static` views.
//!
//! # Conversions
//!
//! Every `From` conversion into [`IoBuf`] or [`IoBufs`] is zero-copy: the
//! payload is never copied, and each requires at most one small owner
//! allocation (the record of an adopted vec, or the external owner of a
//! `Bytes`) beyond the shared-ownership record that freezing a `BytesMut`
//! with spare capacity allocates. Conversions into [`IoBufMut`] or
//! [`IoBufsMut`] are zero-copy where the source allocation can back a
//! mutable handle and copy otherwise. Each mutable conversion documents
//! which one it is, and conversions out of the handles document their cost
//! on each impl.
//!
//! Freshly allocated native buffers request exactly the requested size and
//! alignment from the global allocator, with no ownership metadata in the
//! data allocation, so a power-of-two or page-multiple request can map to an
//! allocator's exact size class. Only the requested alignment is guaranteed;
//! use [`IoBufMut::with_alignment`] when a stronger one is needed. Such
//! buffers, and adopted vectors, pay one additional small allocation for the
//! owner record.
//!
//! Public types:
//! - [`IoBuf`]: Immutable byte buffer
//! - [`IoBufMut`]: Mutable byte buffer
//! - [`IoBufs`]: Container for one or more immutable buffers
//! - [`IoBufsMut`]: Container for one or more mutable buffers
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

pub use buf::{IoBuf, IoBufMut};
pub use bufs::{Builder, EncodeExt, IoBufs, IoBufsMut};

/// Panics for cursor or write operations that run past the available region.
///
/// Outlined so the `Buf`/`BufMut` fast paths inline as a compare, a branch,
/// and a memcpy, mirroring the panic helpers in `bytes`.
#[cold]
#[inline(never)]
fn panic_advance(requested: usize, available: usize) -> ! {
    panic!("cannot advance past end of buffer: requested {requested}, available {available}");
}
