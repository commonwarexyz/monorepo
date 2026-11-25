//! P4: the read cursor and the write position of `IoBufMut` through the `bytes` traits.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_p4_advance_copy_write`: for EVERY capacity up to 4, EVERY content, EVERY advance, EVERY
//! copy length and EVERY write length that the remaining bytes and capacity allow:
//!
//! - `advance(k)` drops the first `k` readable bytes and the capacity shrinks with them. The
//!   `bytes` crate (1.12.1), src/buf/buf_impl.rs, `Buf::advance` (the buffer implements this
//!   trait): "Advance the internal cursor of the Buf" and "The next call to `chunk()` will
//!   return a slice starting `cnt` bytes further into the underlying buffer.";
//!   runtime/src/iobuf/buf.rs, `IoBufMut` type docs: "`advance` moves `ptr` forward and shrinks
//!   both `len` and `cap`."
//! - `copy_to_slice` copies the next bytes and moves the cursor past them. The `bytes` crate,
//!   src/buf/buf_impl.rs, `Buf::copy_to_slice`: "Copies bytes from `self` into `dst`." and "The
//!   cursor is advanced by the number of bytes copied."
//! - a write after that appends behind the readable bytes. runtime/src/iobuf/buf.rs,
//!   `IoBufMut` type docs: "`BufMut` writes always begin at `ptr + len`."
//! - `remaining()` is the readable length after each step. The `bytes` crate,
//!   src/buf/buf_impl.rs, `Buf::remaining`: "Returns the number of bytes between the current
//!   position and the end of the buffer."
//!
//! Kani also checks the pointer arithmetic and the `unsafe` copy of `copy_to_slice` for memory
//! safety.
//!
//! # Implementation consistency
//!
//! None.
//!
//! # Bounds
//!
//! Capacity and content up to 4 bytes (`MAX`); one advance, one copy, one write, each inside
//! what the remaining bytes and capacity allow. Not covered: an advance, copy or write past
//! them, which panics (see the section Not covered of `README.md`). Loops unwound 6 times.
//! `usize` is 64 bits.

use crate::common::{MAX, same_bytes};
use bytes::{Buf as _, BufMut as _};
use commonware_runtime::IoBufMut;

#[kani::proof]
#[kani::unwind(6)]
fn kani_p4_advance_copy_write() {
    let cap: usize = kani::any();
    kani::assume(cap <= MAX);
    let n: usize = kani::any();
    kani::assume(n <= cap);
    let data: [u8; MAX] = kani::any();
    let more: [u8; MAX] = kani::any();

    let mut m = IoBufMut::with_capacity(cap);
    m.put_slice(&data[..n]);

    let k: usize = kani::any();
    kani::assume(k <= n);
    m.advance(k);
    assert_eq!(m.remaining(), n - k);
    assert_eq!(m.capacity(), cap - k);
    assert!(same_bytes(m.chunk(), &data[k..n]));

    let d: usize = kani::any();
    kani::assume(d <= n - k);
    let mut dst = [0u8; MAX];
    m.copy_to_slice(&mut dst[..d]);
    assert!(same_bytes(&dst[..d], &data[k..k + d]));
    assert_eq!(m.remaining(), n - k - d);
    let start = k + d;
    assert!(same_bytes(m.chunk(), &data[start..n]));

    let e: usize = kani::any();
    kani::assume(e <= m.capacity() - m.len());
    m.put_slice(&more[..e]);
    assert_eq!(m.len(), n - start + e);
    assert!(same_bytes(&m.as_ref()[..n - start], &data[start..n]));
    assert!(same_bytes(&m.as_ref()[n - start..], &more[..e]));

    kani::cover!(k > 0 && d > 0 && e > 0, "advance, copy and write all move");
    kani::cover!(start == n && e == 0, "everything consumed");
}
