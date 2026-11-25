//! P1: the life of one heap buffer through `IoBufMut` and `IoBuf`: write, freeze, view, share,
//! and recover the mutable handle.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_p1_lifecycle`: for EVERY capacity up to 4, EVERY written length up to the capacity,
//! EVERY content and EVERY range of the frozen view:
//!
//! - `with_capacity` gives exactly that capacity. runtime/src/iobuf/buf.rs,
//!   `IoBufMut::with_capacity`: "Create a buffer whose [capacity](Self#capacity) is exactly
//!   `capacity` bytes."
//! - the frozen buffer and a slice of it hold the written bytes. `IoBuf::slice`: "Returns a
//!   slice of self for the provided range (zero-copy)."
//! - `try_into_mut` succeeds exactly when no other handle shares the allocation: here when the
//!   buffer is empty or the slice is empty. `IoBuf::try_into_mut`: "Succeeds when this view,
//!   whole or sliced, is the only handle to a native allocation" and "Returns `self` when
//!   other handles share the allocation" and "An empty view with no owner converts to an empty
//!   [`IoBufMut`]."; `IoBuf::slice`: "An empty range returns a detached empty buffer that holds
//!   no allocation."; `IoBufMut::freeze`: "Freezing an empty buffer releases its allocation, so
//!   the result holds no memory."
//! - a recovered nonempty buffer has its full capacity back and the same bytes.
//!   `IoBuf::try_into_mut`: "The recovered capacity runs from the view's start to the end of the
//!   allocation, so spare capacity beyond the view returns with it."; the allocation is exactly
//!   the capacity, runtime/src/iobuf/mod.rs, module docs: "Runtime-owned heap buffers allocate
//!   exactly the requested size and alignment ([`IoBufMut::with_capacity`] requests byte
//!   alignment)."
//! - once the slice is dropped, the recovery succeeds (the same quotes).
//!
//! `kani_p1_clone_shares`: for EVERY content of 1 to 4 bytes copied with `copy_from_slice`, a
//! clone holds the same bytes, `try_into_mut` fails while the clone lives and succeeds after
//! it is dropped. runtime/src/iobuf/buf.rs, `IoBuf::copy_from_slice`: "Create a buffer by
//! copying data from a slice." and "The copy lands in a native heap allocation, so the result
//! supports zero-copy [`IoBuf::try_into_mut`]."; `IoBuf` type docs: "Cloning and slicing are
//! zero-copy" (so the clone views the same bytes of the same allocation, which therefore has
//! another handle); the `try_into_mut` quotes above.
//!
//! In every harness Kani also checks each pointer use, allocation and free inside the
//! runtime for memory safety (no out-of-bounds access, no use after free, no double free).
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - after `copy_from_slice` of `n` bytes, the recovered buffer has capacity exactly `n` (the
//!   docs do not give the capacity of a copy).
//!
//! # Bounds
//!
//! Capacity and content up to 4 bytes (`MAX`); one slice; one clone. Loops unwound 6 times.
//! Native heap storage only: `Bytes`-backed and `'static` buffers are not covered. `usize` is
//! 64 bits.

use crate::common::{MAX, any_range, consistency, same_bytes};
use bytes::BufMut as _;
use commonware_runtime::{IoBuf, IoBufMut};

#[kani::proof]
#[kani::unwind(6)]
fn kani_p1_lifecycle() {
    let cap: usize = kani::any();
    kani::assume(cap <= MAX);
    let n: usize = kani::any();
    kani::assume(n <= cap);
    let data: [u8; MAX] = kani::any();

    let mut m = IoBufMut::with_capacity(cap);
    assert_eq!(m.capacity(), cap);
    m.put_slice(&data[..n]);
    assert!(same_bytes(m.as_ref(), &data[..n]));

    let frozen: IoBuf = m.freeze();
    assert!(same_bytes(frozen.as_ref(), &data[..n]));

    let (a, b) = any_range(n);
    let view = frozen.slice(a..b);
    assert!(same_bytes(view.as_ref(), &data[a..b]));

    match frozen.try_into_mut() {
        Ok(back) => {
            assert!(n == 0 || a == b);
            assert!(same_bytes(back.as_ref(), &data[..n]));
            if n > 0 {
                assert_eq!(back.capacity(), cap);
            }
            kani::cover!(n == 0, "empty buffer: no owner");
            kani::cover!(
                n > 0 && a == b && n < cap,
                "empty slice, spare capacity returns"
            );
        }
        Err(frozen) => {
            assert!(n > 0 && a < b);
            assert!(same_bytes(frozen.as_ref(), &data[..n]));
            drop(view);
            let back = frozen.try_into_mut();
            assert!(back.is_ok());
            let back = back.unwrap();
            assert!(same_bytes(back.as_ref(), &data[..n]));
            assert_eq!(back.capacity(), cap);
            kani::cover!(a > 0 && b < n, "an inner slice shared the allocation");
        }
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn kani_p1_clone_shares() {
    let n: usize = kani::any();
    kani::assume(n >= 1 && n <= MAX);
    let data: [u8; MAX] = kani::any();

    let original = IoBuf::copy_from_slice(&data[..n]);
    assert!(same_bytes(original.as_ref(), &data[..n]));
    let clone = original.clone();
    assert!(same_bytes(clone.as_ref(), &data[..n]));

    let original = match original.try_into_mut() {
        Ok(_) => panic!("a clone shares the allocation"),
        Err(original) => original,
    };
    drop(clone);
    match original.try_into_mut() {
        Ok(back) => {
            assert!(same_bytes(back.as_ref(), &data[..n]));
            consistency!(back.capacity() == n);
            kani::cover!(n == MAX, "the largest buffer");
        }
        Err(_) => panic!("the only handle must convert"),
    }
}
