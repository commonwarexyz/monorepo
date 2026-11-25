//! P5: the synchronous public items of the contiguous journal.
//!
//! The journal types themselves are built only by an asynchronous `init` on a runtime, which
//! Kani cannot run, and the offset math under them is private: see "Not covered" in
//! `README.md`. What is left on the public, synchronous surface is the batch that `replay`
//! yields and the item list that `append_many` takes.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! storage/src/journal/contiguous/mod.rs, `Batch`: "A batch of consecutive items yielded by
//! [`Contiguous::replay`]. `items[i]` is the item at position `start + i`, so `start +
//! items.len()` must not exceed `u64::MAX`." `impl IntoIterator for Batch`, `into_iter`: "Iterate
//! the items paired with their positions."
//!
//! storage/src/journal/contiguous/mod.rs, `Many`: "Items to append via [`Mutable::append_many`].
//! `Flat` wraps a single contiguous slice; `Nested` wraps multiple slices appended in order."
//! `Many::len`: "Returns the total number of items across all segments." `Many::is_empty`:
//! "Returns `true` if there are no items across all segments."
//!
//! Harnesses:
//!
//! - `kani_p5_batch_into_iter`: for every start position with `start + len <= u64::MAX` and
//!   every list of up to 3 items, the iterator yields exactly `len` pairs, the `i`-th being
//!   `(start + i, items[i])`.
//! - `kani_p5_many_len`: for every `Flat` slice of up to 4 items and every `Nested` list of up to
//!   3 slices of up to 2 items each, `len` is the total item count and `is_empty` is true exactly
//!   when it is zero.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! None.
//!
//! # Bounds
//!
//! - `kani_p5_batch_into_iter`: up to 3 items (a heap `Vec`); every start position inside the
//!   documented precondition. Loops unwound 5 times.
//! - `kani_p5_many_len`: up to 4 items in a `Flat` slice; up to 3 segments of up to 2 items in a
//!   `Nested` list, empty segments included. Loops unwound 5 times.
//!
//! `usize` is 64 bits: nothing here speaks for 32-bit targets.

use commonware_storage::journal::contiguous::{Batch, Many};

#[kani::proof]
#[kani::unwind(5)]
fn kani_p5_batch_into_iter() {
    const MAX: usize = 3;
    let items: [u8; MAX] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= MAX);
    let start: u64 = kani::any();
    kani::assume(start <= u64::MAX - len as u64);

    let batch = Batch {
        start,
        items: items[..len].to_vec(),
    };
    let mut seen: usize = 0;
    for (position, item) in batch {
        assert!(seen < len);
        assert!(position == start + seen as u64);
        assert!(item == items[seen]);
        seen += 1;
    }
    assert!(seen == len);

    kani::cover!(len == MAX, "the largest batch");
    kani::cover!(len == 0, "an empty batch");
    kani::cover!(
        len > 0 && start == u64::MAX - len as u64,
        "the last position is u64::MAX - 1"
    );
}

#[kani::proof]
#[kani::unwind(5)]
fn kani_p5_many_len() {
    // Flat: one slice of up to 4 items.
    let flat: [u8; 4] = kani::any();
    let flat_len: usize = kani::any();
    kani::assume(flat_len <= flat.len());
    let many = Many::Flat(&flat[..flat_len]);
    assert!(many.len() == flat_len);
    assert!(many.is_empty() == (flat_len == 0));
    kani::cover!(flat_len == 0, "an empty flat slice");
    kani::cover!(flat_len == flat.len(), "a full flat slice");

    // Nested: up to 3 segments of up to 2 items, empty segments included.
    let data: [u8; 6] = kani::any();
    let lens: [usize; 3] = kani::any();
    kani::assume(lens[0] <= 2 && lens[1] <= 2 && lens[2] <= 2);
    let segments: usize = kani::any();
    kani::assume(segments <= 3);
    let parts: [&[u8]; 3] = [
        &data[0..lens[0]],
        &data[2..2 + lens[1]],
        &data[4..4 + lens[2]],
    ];
    let mut total = 0;
    let mut i = 0;
    while i < segments {
        total += lens[i];
        i += 1;
    }
    let many = Many::Nested(&parts[..segments]);
    assert!(many.len() == total);
    assert!(many.is_empty() == (total == 0));
    kani::cover!(segments == 0, "no segments");
    kani::cover!(segments == 3 && total == 0, "only empty segments");
    kani::cover!(segments == 3 && total == 6, "three full segments");
    kani::cover!(
        segments >= 2 && lens[0] == 0 && total > 0,
        "an empty segment before a full one"
    );
}
