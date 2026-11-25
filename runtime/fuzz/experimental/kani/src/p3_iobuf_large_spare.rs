//! P3: buffers whose capacity or spare capacity is too large for the compact owner word still
//! freeze and convert back, and a nonempty one gets its full capacity back.
//!
//! The owner word of a heap buffer records the allocation only up to a size and a spare
//! capacity (runtime/src/iobuf/mod.rs, module docs); beyond them the buffer uses a separate
//! owner record. Kani needs no memory for a symbolic capacity, so this proof reaches
//! capacities that a fuzzer cannot allocate.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_p3_freeze_large_spare`: for EVERY capacity above 128 KiB + 2 and up to 2^41 bytes and
//! EVERY written length up to 2 bytes:
//!
//! - `with_capacity` gives exactly that capacity. runtime/src/iobuf/buf.rs,
//!   `IoBufMut::with_capacity`: "Create a buffer whose [capacity](Self#capacity) is exactly
//!   `capacity` bytes."
//! - freezing keeps the bytes. `IoBufMut::freeze`: "Freeze into immutable [`IoBuf`]." and
//!   "Freezing allocates only when the spare capacity `capacity() - len()` is too large to
//!   record in the handle (at least 128 KiB on 64-bit targets, 128 bytes on 32-bit targets)"
//! - the only handle converts back, and a nonempty one gets its full capacity back.
//!   `IoBuf::try_into_mut`: "Succeeds when this view, whole or sliced, is the only handle to a
//!   native allocation (one that an [`IoBufMut`] allocated or adopted from a [`Vec<u8>`]). The
//!   recovered capacity runs from the view's start to the end of the allocation, so spare
//!   capacity beyond the view returns with it. An empty view with no owner converts to an
//!   empty [`IoBufMut`]."; the allocation is exactly the capacity (runtime/src/iobuf/mod.rs,
//!   module docs: "Runtime-owned heap buffers allocate exactly the requested size and
//!   alignment").
//!
//! Kani also checks every pointer use, allocation and free for memory safety.
//!
//! # Implementation consistency
//!
//! None.
//!
//! # Bounds
//!
//! Capacity from 128 KiB + 3 to 2^41 bytes (1 TiB is 2^40, so both the spare-capacity limit
//! and the size limit of the owner word are crossed); at most 2 bytes written; nothing is
//! read past them. Loops unwound 4 times. `usize` is 64 bits: the 32-bit limits (128 bytes,
//! 16 MiB) are not covered.

use bytes::BufMut as _;
use commonware_runtime::{IoBuf, IoBufMut};

#[kani::proof]
#[kani::unwind(4)]
fn kani_p3_freeze_large_spare() {
    let cap: usize = kani::any();
    kani::assume(cap > (1 << 17) + 2 && cap <= 1 << 41);
    let n: usize = kani::any();
    kani::assume(n <= 2);
    let data: [u8; 2] = kani::any();

    let mut m = IoBufMut::with_capacity(cap);
    assert_eq!(m.capacity(), cap);
    m.put_slice(&data[..n]);
    let frozen: IoBuf = m.freeze();
    assert_eq!(frozen.len(), n);
    if n > 0 {
        assert_eq!(frozen.as_ref()[0], data[0]);
    }

    match frozen.try_into_mut() {
        Ok(back) => {
            assert_eq!(back.len(), n);
            if n > 0 {
                assert_eq!(back.capacity(), cap);
                assert_eq!(back.as_ref()[n - 1], data[n - 1]);
            }
            kani::cover!(
                n == 2 && cap >= 1 << 40,
                "two bytes, capacity of 1 TiB or more"
            );
            kani::cover!(n == 1 && cap < 1 << 40, "one byte, capacity below 1 TiB");
            kani::cover!(n == 0, "empty");
        }
        Err(_) => panic!("the only handle must convert"),
    }
}
