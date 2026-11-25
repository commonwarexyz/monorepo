//! P5: `IoBufs`, several buffers read as one byte stream.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! After every sequence of operations below, for the container and each part it returns:
//! `len()` is the total byte count, `chunk_count()` counts only nonempty chunks, `chunk_at(i)`
//! gives those chunks in order and `None` for every index from `chunk_count()` on, and the
//! chunks, read in order, are the expected bytes. runtime/src/iobuf/bufs.rs, `IoBufs::len`:
//! "Number of bytes remaining across all buffers."; `IoBufs::chunk_count`: "Number of
//! non-empty readable chunks."; `IoBufs::chunk_at`: "Returns the readable chunk at the given
//! index without advancing the buffers." and "Returns `None` when `index` is greater than or
//! equal to [`Self::chunk_count`]."
//!
//! `kani_p5_append_prepend`: for EVERY content of the shape below (append 1 byte, prepend 1
//! byte, append an empty buffer, prepend 1 byte): the stream is the buffers in the order the
//! calls put them, and the empty buffer adds no chunk. `IoBufs::prepend`: "Prepend a buffer to
//! the front." and "Empty input buffers are ignored."; `IoBufs::append`: "Append a buffer to
//! the back."
//!
//! `kani_p5_many_chunks`: the same for 4 `append` calls and then 1 `prepend`, each with 1 byte
//! of EVERY content, so the container holds 5 chunks (the representation for many chunks).
//!
//! `kani_p5_split_to`: for EVERY content of a container of two 2-byte buffers and EVERY split
//! index up to its length: the container keeps the bytes from the index on and the returned
//! one holds the bytes before it. `IoBufs::split_to`: "Afterwards `self` contains bytes `[at,
//! len)`, and the returned [`IoBufs`] contains bytes `[0, at)`."
//!
//! `kani_p5_coalesce`: for EVERY content of a container of two 2-byte buffers: `coalesce` gives
//! one buffer with all the bytes. `IoBufs::coalesce`: "Coalesce all remaining bytes into a
//! single contiguous [`IoBuf`]."
//!
//! Kani also checks every pointer use, allocation and free for memory safety.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - a container of 5 chunks, and one of two 2-byte buffers, is not `is_single()` (the docs of
//!   `IoBufs::is_single` say what it means, "Whether this contains a single contiguous
//!   buffer.", but not which containers of several chunks keep the single representation).
//!
//! # Bounds
//!
//! One concrete shape per harness, with every content: the lengths and the order of the calls
//! are fixed as stated above, and `kani_p5_split_to` also takes every split index. With the
//! buffer lengths left symbolic (up to 2 bytes each) the proofs gave no answer within 8
//! minutes. Loops unwound 7 times. Not covered: other shapes, and `split_to` past the length,
//! which the docs of `IoBufs::split_to` say panics (see the section Not covered of
//! `README.md`). `usize` is 64 bits.

use crate::common::{consistency, same_bytes};
use commonware_runtime::{IoBuf, IoBufs};

/// Bytes of the stream model.
const CAP: usize = 6;

/// Checks the chunk accounting of `bufs` and returns whether its chunks, read in order, are
/// `expected`.
fn chunks_are(bufs: &IoBufs, expected: &[u8]) -> bool {
    assert_eq!(bufs.len(), expected.len());
    let count = bufs.chunk_count();
    // Every index from `chunk_count()` on, not only the first one.
    let beyond: usize = kani::any();
    kani::assume(beyond >= count);
    assert!(bufs.chunk_at(beyond).is_none());
    kani::cover!(beyond > count, "an index past chunk_count gives no chunk");
    let mut out = [0u8; CAP];
    let mut at = 0;
    let mut i = 0;
    while i < count {
        let chunk = bufs
            .chunk_at(i)
            .expect("an index below chunk_count has a chunk");
        assert!(!chunk.is_empty());
        let mut j = 0;
        while j < chunk.len() {
            assert!(at < CAP);
            out[at] = chunk[j];
            at += 1;
            j += 1;
        }
        i += 1;
    }
    same_bytes(&out[..at], expected)
}

/// A container of two 2-byte buffers holding `data`.
fn two_pairs(data: &[u8; 4]) -> IoBufs {
    let mut bufs = IoBufs::default();
    bufs.append(IoBuf::copy_from_slice(&data[..2]));
    bufs.append(IoBuf::copy_from_slice(&data[2..]));
    bufs
}

#[kani::proof]
#[kani::unwind(7)]
fn kani_p5_append_prepend() {
    let data: [u8; 3] = kani::any();
    let mut bufs = IoBufs::default();
    bufs.append(IoBuf::copy_from_slice(&data[..1]));
    bufs.prepend(IoBuf::copy_from_slice(&data[1..2]));
    bufs.append(IoBuf::copy_from_slice(&[]));
    bufs.prepend(IoBuf::copy_from_slice(&data[2..]));

    assert_eq!(bufs.chunk_count(), 3);
    assert!(chunks_are(&bufs, &[data[2], data[1], data[0]]));
    kani::cover!(data[0] != data[2], "distinct first and last bytes");
}

#[kani::proof]
#[kani::unwind(7)]
fn kani_p5_many_chunks() {
    let data: [u8; 5] = kani::any();
    let mut bufs = IoBufs::default();
    let mut i = 1;
    while i < 5 {
        bufs.append(IoBuf::copy_from_slice(&data[i..i + 1]));
        i += 1;
    }
    bufs.prepend(IoBuf::copy_from_slice(&data[..1]));
    assert_eq!(bufs.chunk_count(), 5);
    consistency!(!bufs.is_single());
    assert!(chunks_are(&bufs, &data));
    kani::cover!(data[0] != data[4], "distinct first and last bytes");
}

#[kani::proof]
#[kani::unwind(7)]
fn kani_p5_split_to() {
    let data: [u8; 4] = kani::any();
    let mut bufs = two_pairs(&data);
    let at: usize = kani::any();
    kani::assume(at <= 4);

    let head = bufs.split_to(at);
    assert!(chunks_are(&head, &data[..at]));
    assert!(chunks_are(&bufs, &data[at..]));

    kani::cover!(at == 1, "the split lands inside the first chunk");
    kani::cover!(at == 2, "the split lands on the chunk boundary");
    kani::cover!(at == 3, "the split lands inside the second chunk");
}

#[kani::proof]
#[kani::unwind(7)]
fn kani_p5_coalesce() {
    let data: [u8; 4] = kani::any();
    let bufs = two_pairs(&data);
    consistency!(!bufs.is_single());
    let whole = bufs.coalesce();
    assert!(same_bytes(whole.as_ref(), &data));
    kani::cover!(data[0] != data[3], "distinct first and last bytes");
}
