//! P5: the length checks and size bounds in `commonware_codec::util` cannot overflow.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_p5_at_least_items`: for EVERY `len`, `item_size` and remaining count (all `usize`), the
//! check does not panic, passes exactly when `len * item_size <= remaining` in 128-bit
//! arithmetic, and fails with `EndOfBuffer`. codec/src/util.rs, `at_least_items`: "Checks if
//! the buffer has at least `len * item_size` bytes remaining, treating multiplication overflow
//! as insufficient. Returns an [Error::EndOfBuffer] if not."
//!
//! `kani_p5_max_items_size`: for EVERY `len <= u32::MAX` and `item_size <= u32::MAX`, the
//! function does not panic and returns AT LEAST `len * item_size + 5` in 128-bit arithmetic.
//! codec/src/util.rs, `max_items_size`: "Returns an upper bound on the encoded size of a ...
//! sequence of `len` items that each encode to at most `item_size` bytes, with the length
//! prefix at its widest"; the widest prefix is the five-byte `u32` varint (codec/src/lib.rs,
//! crate docs, "Size Bounds": "128 bytes of data and a five-byte
//! [`UInt<u32>`](varint::UInt) length prefix"). The proof assumes `len <= u32::MAX` because
//! of codec/src/util.rs, `max_items_size`, "# Panics": "Panics if `len` exceeds
//! `u32::MAX`."
//!
//! `kani_p5_ensure_zeros`: for EVERY buffer of `0..=6` bytes, split at EVERY point into two
//! chunks, and EVERY `size` (any `usize`), the function does not panic and returns `Ok` exactly
//! when the buffer holds at least `size` bytes and the next `size` bytes are all zero.
//! codec/src/util.rs, `ensure_zeros`: "Ensures the next `size` bytes are all zeroes in the
//! provided buffer, returning an [Error] otherwise." No panic: codec/src/codec.rs,
//! `Read::read_cfg`, and codec/src/lib.rs, crate docs, "Decode Inputs", puts "length or
//! padding validation" on the read path.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! Stronger than the docs above. A valid change of the implementation could break these.
//!
//! - `max_items_size` returns EXACTLY `len * item_size + 5` (the docs promise an upper bound);
//! - `ensure_zeros` on `Ok` has consumed exactly `size` bytes (the docs do not say that it
//!   advances; a unit test does, codec/src/util.rs, the test `test_ensure_zeros`);
//! - `ensure_zeros` on a short buffer returns `EndOfBuffer` and consumes nothing;
//! - `ensure_zeros` on a non-zero byte returns `Invalid("codec", "non-zero bytes")`, and
//!   returns no other error.
//!
//! # Bounds
//!
//! `kani_p5_at_least_items`: none (64-bit `usize`).
//!
//! `kani_p5_max_items_size`: `item_size <= u32::MAX`, so the documented bound
//! `len * item_size + 5` fits a 64-bit `usize`. Not asserted: what the function does when
//! that bound does not fit a `usize`.
//!
//! `kani_p5_ensure_zeros`: at most 6 bytes in at most two chunks; loops unwound 16 times (the
//! longest is the comparison of the 14-byte error message in the consistency build).
//!
//! `usize` is 64 bits: nothing here speaks for 32-bit targets.

use crate::common::{Remaining, consistency};
use bytes::Buf as _;
use commonware_codec::{
    Copying, Error,
    util::{at_least_items, ensure_zeros, max_items_size},
};

#[kani::proof]
fn kani_p5_at_least_items() {
    let len: usize = kani::any();
    let item_size: usize = kani::any();
    let remaining: usize = kani::any();

    let result = at_least_items(&mut Remaining(remaining), len, item_size);
    let needed = (len as u128) * (item_size as u128);
    let passed = match result {
        Ok(()) => true,
        Err(Error::EndOfBuffer) => false,
        Err(_) => panic!("unexpected error kind"),
    };
    assert!(passed == (needed <= remaining as u128));

    kani::cover!(
        passed && len > 0 && item_size > 1,
        "enough bytes for several items"
    );
    kani::cover!(
        !passed && needed <= usize::MAX as u128,
        "too few bytes, no overflow"
    );
    kani::cover!(needed > usize::MAX as u128, "the product overflows usize");
    kani::cover!(
        passed && needed == remaining as u128,
        "exactly enough bytes"
    );
}

#[kani::proof]
fn kani_p5_max_items_size() {
    let len: usize = kani::any();
    let item_size: usize = kani::any();
    kani::assume(len <= u32::MAX as usize);
    kani::assume(item_size <= u32::MAX as usize);

    let size = max_items_size(len, item_size);
    let largest = (len as u128) * (item_size as u128) + 5;
    assert!(size as u128 >= largest);
    consistency!(size as u128 == largest);

    kani::cover!(len == u32::MAX as usize, "the largest length");
    kani::cover!(
        len == u32::MAX as usize && item_size == u32::MAX as usize,
        "the largest length and item size"
    );
    kani::cover!(len == 0, "an empty sequence");
}

#[kani::proof]
#[kani::unwind(16)]
fn kani_p5_ensure_zeros() {
    const N: usize = 6;
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    let split: usize = kani::any();
    kani::assume(len <= N);
    kani::assume(split <= len);
    let size: usize = kani::any();

    // The definition: `size` bytes exist and all of them are zero.
    let mut zeros = size <= len;
    if zeros {
        let mut i = 0;
        while i < size {
            zeros &= bytes[i] == 0;
            i += 1;
        }
    }

    // Contract: no panic, and `Ok` exactly for a zero region.
    let mut buf = Copying(&bytes[..split]).chain(Copying(&bytes[split..len]));
    let result = ensure_zeros(&mut buf, size);
    let left = buf.remaining();
    assert!(result.is_ok() == zeros);

    match result {
        Ok(()) => {
            consistency!(left == len - size);

            kani::cover!(size == 0, "a zero-length check passes");
            kani::cover!(size == N, "the whole buffer is zero");
            kani::cover!(
                split > 0 && split < size,
                "the zero region spans both chunks"
            );
            kani::cover!(
                size < len && bytes[size] != 0,
                "a non-zero byte right after the region is ignored"
            );
        }
        Err(Error::EndOfBuffer) => {
            consistency!(size > len);
            consistency!(left == len);

            kani::cover!(size == len + 1, "one byte short");
            kani::cover!(size == usize::MAX, "the largest size");
        }
        Err(Error::Invalid(context, message)) => {
            consistency!(context == "codec" && message == "non-zero bytes");
            consistency!(size <= len);

            kani::cover!(
                split < size && bytes[size - 1] != 0,
                "a non-zero last byte in chunk two"
            );
            kani::cover!(
                split > 0 && bytes[0] != 0,
                "a non-zero first byte in chunk one"
            );
        }
        Err(_) => {
            consistency!(false, "unexpected error kind");
        }
    }
}
