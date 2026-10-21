//! Buffer types for I/O operations.
//!
//! `IoBuf` and `IoBufMut` store readable/writable cursor state directly in the
//! public handle, so the [`Buf`](bytes::Buf) and [`BufMut`](bytes::BufMut) hot
//! paths are simple pointer/length arithmetic. Allocation ownership lives in a
//! compact owner reference, and `owner.rs` documents the owner model.
//!
//! Runtime-owned heap buffers allocate exactly the requested size and alignment
//! ([`IoBufMut::with_capacity`] requests byte alignment), with the owner record
//! in one extra small allocation. Caller-supplied `Vec<u8>` values are adopted
//! into the same native form without copying. Caller-supplied [`Bytes`] values
//! are held zero-copy by an owner record that keeps the `Bytes` alive.
//!
//! Throughout this module, "native" means runtime-owned storage whose owner
//! supports zero-copy mutable recovery through [`IoBuf::try_into_mut`]: heap
//! allocations and adopted vecs, as opposed to external `Bytes` and
//! `'static` views.
//!
//! # Conversions
//!
//! Every `From` conversion into [`IoBuf`] or [`IoBufs`] is zero-copy and
//! allocates at most one small owner record. When a `BytesMut` still owns its
//! vector directly and has spare capacity, freezing it also allocates a
//! shared-ownership record.
//!
//! Conversions into [`IoBufMut`] or [`IoBufsMut`] reuse the source allocation
//! where it can back a mutable handle and copy into a new one otherwise.
//! Reusing a `Bytes` or `BytesMut` keeps its whole allocation as the capacity
//! and moves readable bytes that start past its beginning to the front. Each
//! mutable conversion, and each conversion out of the handles, documents its
//! cost on its impl.
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
//! // Once the view is gone, recovery returns the mutable handle with its
//! // spare capacity.
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
