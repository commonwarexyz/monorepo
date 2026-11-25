//! `BitMap`: `is_unset` and `truncate`.
//!
//! A `BitMap<N>` holds its bits in chunks of `N` bytes. `is_unset` scans the chunks a range
//! touches: the first and the last in part, the ones between whole. `truncate` pops single
//! bits until the length is chunk-aligned, then whole chunks, then single bits again.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! 1. `is_unset`. utils/src/bitmap/mod.rs, `BitMap::is_unset`: "Returns `true` if every index
//!    in the range is unset (i.e. [`Self::get`] returns `false`). Returns `true` if the range
//!    is empty."
//! 2. `truncate`. utils/src/bitmap/mod.rs, `BitMap::truncate`: "Shrink the bitmap to `new_len`
//!    bits, discarding trailing bits." `BitMap::extend_to`, used to look at the discarded
//!    positions: "Extend the bitmap to `new_len` bits, filling new positions with zero." The
//!    crate's test `test_truncate` asserts the new length and that every kept bit is unchanged.
//! 3. `push`, `get` and `len`, used to build and read the bitmaps of items 1 and 2.
//!    utils/src/bitmap/mod.rs, `BitMap::push`: "Add a single bit to the bitmap.";
//!    `BitMap::get`: "Get the value of the bit at the given index."; `BitMap::len`: "Return the
//!    number of bits currently stored in the bitmap."
//!
//! # What is proven
//!
//! `kani_bitmap_is_unset` (`N = 1`): for EVERY bitmap of 17 bits built by `push` (every bit
//! pattern), `get` returns the pushed bits, and for EVERY range `start..end` with `end <= 17`
//! (any `start`, also `start > end`), `is_unset` is `true` exactly when no bit of the range is
//! set.
//!
//! `kani_bitmap_truncate` (`N = 1`): for EVERY bitmap of 17 bits built by `push` (every bit
//! pattern) and every `new_len` from 0 to 17, `truncate(new_len)` leaves the length `new_len`
//! and every kept bit as it was, and extending back to the old length reads every discarded
//! position as zero.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - `kani_bitmap_truncate`: the truncated bitmap equals (`==`) a bitmap built by pushing the
//!   kept bits. The derived equality compares the chunks, which the documentation does not
//!   describe.
//!
//! # Bounds
//!
//! `N = 1` and one bitmap length, 17 bits: three chunks, so that a range can span a whole
//! middle chunk and a truncation can pop bits, a whole chunk, then bits. The bit pattern and
//! the range are any value; `truncate` is checked for each `new_len` from 0 to 17 in turn (a
//! symbolic `new_len`, and every length up to 24 bits, made the solver pass 40 GB of memory).
//! Loops unwind once more than their longest run. `usize` is 64 bits: the 32-bit chunk-count
//! limit in the docs of `BitMap` ("Operations panic if `bit / CHUNK_SIZE_BITS > usize::MAX`")
//! is not reached.
//!
//! # Not covered
//!
//! - The panics that the documentation states (`is_unset` past the length, `truncate` to a
//!   larger size): a Kani harness that expects a panic needs a pass rule the scheduled run
//!   does not have yet.
//! - Decoding (`Read for BitMap`): see "Not covered" in the README.

use crate::common::consistency;
use commonware_utils::bitmap::BitMap;

/// The bitmap length of the `is_unset` and `truncate` proofs.
const LEN: u64 = 17;

/// A bitmap of `len` bits built by `push`, bit `i` being bit `i` of `pattern`.
fn build(len: u64, pattern: u32) -> BitMap<1> {
    let mut bitmap = BitMap::<1>::new();
    let mut i = 0;
    while i < len {
        bitmap.push((pattern >> i) & 1 == 1);
        i += 1;
    }
    bitmap
}

#[kani::proof]
#[kani::unwind(19)]
fn kani_bitmap_is_unset() {
    const MAX: u64 = LEN;
    let len = LEN;
    let pattern: u32 = kani::any();
    let bitmap = build(len, pattern);
    let start: u64 = kani::any();
    let end: u64 = kani::any();
    kani::assume(end <= len);

    // The first set bit inside `start..end`, by the definition of item 1.
    let mut first_set: Option<u64> = None;
    let mut i = 0;
    while i < MAX {
        if i < len {
            let bit = (pattern >> i) & 1 == 1;
            assert!(bitmap.get(i) == bit);
            if start <= i && i < end && bit && first_set.is_none() {
                first_set = Some(i);
            }
        }
        i += 1;
    }

    let unset = bitmap.is_unset(start..end);
    assert!(unset == first_set.is_none());

    kani::cover!(start > end, "a reversed range is empty");
    kani::cover!(
        start < end && start / 8 == (end - 1) / 8 && unset,
        "one chunk, unset"
    );
    kani::cover!(
        start < end && start / 8 == (end - 1) / 8 && !unset,
        "one chunk, a bit set"
    );
    kani::cover!(
        start < end && (end - 1) / 8 >= start / 8 + 2 && unset,
        "three chunks, unset"
    );
    kani::cover!(
        matches!(first_set, Some(f) if f / 8 == start / 8 && (end - 1) / 8 > start / 8),
        "a set bit in the first of several chunks"
    );
    kani::cover!(
        matches!(first_set, Some(f) if f / 8 > start / 8 && f / 8 < (end - 1) / 8),
        "a set bit in a middle chunk"
    );
    kani::cover!(
        matches!(first_set, Some(f) if f / 8 == (end - 1) / 8 && f / 8 > start / 8),
        "a set bit in the last of several chunks"
    );
}

#[kani::proof]
#[kani::unwind(19)]
fn kani_bitmap_truncate() {
    let pattern: u32 = kani::any();
    let full = build(LEN, pattern);
    let mut new_len = 0;
    while new_len <= LEN {
        truncate_to(&full, pattern, new_len);
        new_len += 1;
    }
}

/// Truncates a copy of `full` (bits of `pattern`, `LEN` of them) to `new_len` and checks it.
fn truncate_to(full: &BitMap<1>, pattern: u32, new_len: u64) {
    const MAX: u64 = LEN;
    let len = LEN;
    let mut bitmap = full.clone();
    bitmap.truncate(new_len);
    assert!(bitmap.len() == new_len);
    let mut i = 0;
    while i < MAX {
        if i < new_len {
            assert!(bitmap.get(i) == ((pattern >> i) & 1 == 1));
        }
        i += 1;
    }
    consistency!(bitmap == build(new_len, pattern));

    bitmap.extend_to(len);
    assert!(bitmap.len() == len);
    let mut i = 0;
    while i < MAX {
        if new_len <= i && i < len {
            assert!(!bitmap.get(i));
        }
        i += 1;
    }

    kani::cover!(new_len == len, "truncating to the length changes nothing");
    kani::cover!(new_len == 0 && len == MAX, "truncating everything");
    kani::cover!(
        len % 8 != 0 && len - new_len >= 8 && new_len % 8 != 0,
        "bits, a whole chunk, then bits"
    );
    kani::cover!(
        (new_len..len).any(|i| (pattern >> i) & 1 == 1),
        "a discarded bit was set"
    );
}
