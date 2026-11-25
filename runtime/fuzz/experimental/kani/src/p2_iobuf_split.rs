//! P2: `IoBuf::split_to` splits the bytes at the given index, zero-copy.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_p2_split_to`: for EVERY content of 0 to 4 bytes and EVERY split index up to the
//! length:
//!
//! - the halves hold the bytes before and after the index. runtime/src/iobuf/buf.rs,
//!   `IoBuf::split_to`: "Afterwards `self` contains bytes `[at, len)`, and the returned
//!   [`IoBuf`] contains bytes `[0, at)`."
//! - a split that leaves both halves nonempty shares the allocation, so `try_into_mut` of a
//!   half fails while the other half lives; a split at either end leaves the nonempty half as
//!   the only handle, so it converts. `IoBuf::split_to`: "A split that leaves both halves
//!   nonempty shares the allocation, which allocates the owner record of an unshared native
//!   buffer. The empty half of a split at either end of a nonempty buffer is detached and
//!   holds no allocation. Splitting an empty buffer leaves `self` unchanged."; the
//!   `IoBuf::try_into_mut` quotes of `p1`.
//! - after the other half is dropped, the remaining half converts and keeps its bytes (the
//!   same quotes).
//!
//! Kani also checks every pointer use, allocation and free for memory safety.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - the recovered tail `[at, len)` of a `copy_from_slice` buffer has capacity `len - at` (the
//!   docs do not give the capacity of a copy).
//!
//! # Bounds
//!
//! Content up to 4 bytes (`MAX`); one split. Loops unwound 6 times. Not covered: `at > len`,
//! which the docs of `IoBuf::split_to` say panics; a proof of a panic needs a `should_panic`
//! harness (see the section Not covered of `README.md`). `usize` is 64 bits.

use crate::common::{MAX, consistency, same_bytes};
use commonware_runtime::IoBuf;

#[kani::proof]
#[kani::unwind(6)]
fn kani_p2_split_to() {
    let n: usize = kani::any();
    kani::assume(n <= MAX);
    let data: [u8; MAX] = kani::any();
    let at: usize = kani::any();
    kani::assume(at <= n);

    let mut tail = IoBuf::copy_from_slice(&data[..n]);
    let head = tail.split_to(at);
    assert!(same_bytes(head.as_ref(), &data[..at]));
    assert!(same_bytes(tail.as_ref(), &data[at..n]));

    let tail = match tail.try_into_mut() {
        Ok(back) => {
            assert!(at == 0 || at == n);
            assert!(same_bytes(back.as_ref(), &data[at..n]));
            kani::cover!(n > 0 && at == 0, "split at the start");
            kani::cover!(n > 0 && at == n, "split at the end");
            kani::cover!(n == 0, "empty buffer");
            return;
        }
        Err(tail) => {
            assert!(at > 0 && at < n);
            tail
        }
    };
    drop(head);
    match tail.try_into_mut() {
        Ok(back) => {
            assert!(same_bytes(back.as_ref(), &data[at..n]));
            consistency!(back.capacity() == n - at);
            kani::cover!(at == 1 && n == MAX, "an inner split");
        }
        Err(_) => panic!("the only handle must convert"),
    }
}
