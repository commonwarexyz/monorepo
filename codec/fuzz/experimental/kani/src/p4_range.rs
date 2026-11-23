//! P4: a decoded length is never outside the caller's range.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_p4_range_contains`: for EVERY pair of bounds (each `Included`, `Excluded` or
//! `Unbounded`, with any `usize` value) and EVERY `usize` value, `RangeCfg::contains` equals
//! interval membership computed in 128-bit signed arithmetic, where no bound can overflow.
//! codec/src/config.rs:8-10: `RangeCfg` is "Configuration for limiting the range of a value";
//! codec/src/config.rs:131: `contains` "Returns true if the value is within this range". The
//! bounds are `core::ops::Bound`, with its standard meaning.
//!
//! `kani_p4_usize_read`: for EVERY byte string of length `0..=6` and EVERY range,
//! `usize::read_cfg`:
//!
//! 1. does not panic. codec/src/codec.rs:226-228: "Parsing a message (often untrusted) should
//!    never result in a panic."
//! 2. on `Ok(v)`: `v` is inside the range. codec/src/types/primitives.rs:11-13: "callers must
//!    supply a [RangeCfg] to bound the allowable value. This protects against
//!    denial-of-service attacks that would allocate oversized buffers";
//!    codec/src/codec.rs:223-224: "must return [Error] if decoding fails due to ... violation
//!    of constraints imposed by the `cfg`".
//! 3. on `Ok(v)`: `v` fits in a `u32`. codec/src/types/primitives.rs:16-17: "`usize` is
//!    restricted to values that fit in a `u32`".
//! 4. on `InvalidLength(v)`: `v` is outside the range. codec/src/error.rs:47-54: the "value
//!    fell outside the permitted range"; "The contained `usize` is the invalid length that
//!    was decoded."
//! 5. a malformed varint is refused: it gives no value and no `InvalidLength`.
//!    codec/src/types/primitives.rs:8-17: `usize` "uses variable-length (varint) encoding";
//!    codec/src/varint.rs:479-481, on the varint read: "Returns an error if:" "The varint is
//!    invalid (too long or malformed)". Which bytes are malformed: those that `UInt<u32>`
//!    refuses with `InvalidVarint` (codec/src/varint.rs:117: "`Err(InvalidVarint)` if the
//!    varint is malformed (overflow or invalid encoding)"). The documentation does not say
//!    with which error `usize` itself refuses them, so the gate does not fix the kind of
//!    that failure: no assertion and no cover check of the default build looks at it.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - the value, the cursor and the error (kind and payload) equal those of
//!   `UInt::<u32>::read` on the same input. The docs say a `usize` is a varint that fits a
//!   `u32`; they do not name `UInt<u32>`. This is also a shared-code check, not an independent
//!   oracle: `usize::read_cfg` calls `UInt::read` (codec/src/types/primitives.rs:181).
//! - `InvalidUsize` never happens (on a 64-bit target every `u32` fits a `usize`), and no
//!   failure has a kind other than `InvalidLength`, `EndOfBuffer` or `InvalidVarint`.
//! - the cover check that expects a malformed varint under `InvalidVarint` is compiled only
//!   with the feature.
//!
//! # Bounds
//!
//! `kani_p4_range_contains`: none. `kani_p4_usize_read`: inputs up to 6 bytes (one more than
//! the longest `u32` varint). `usize` is 64 bits: nothing here speaks for 32-bit targets.

use crate::common::consistency;
use bytes::Buf as _;
use commonware_codec::{Copying, Error, RangeCfg, Read, ReadExt, varint::UInt};
use core::ops::Bound;

/// Returns any bound over any `usize`.
fn any_bound() -> Bound<usize> {
    let value: usize = kani::any();
    let kind: u8 = kani::any();
    kani::assume(kind < 3);
    match kind {
        0 => Bound::Included(value),
        1 => Bound::Excluded(value),
        _ => Bound::Unbounded,
    }
}

/// Interval membership in 128-bit signed arithmetic.
///
/// `Excluded(s)` as a start means `> s`, i.e. `>= s + 1`; as an end it means `<= e - 1`.
/// A `usize` plus or minus one always fits an `i128`.
fn in_interval(start: Bound<usize>, end: Bound<usize>, value: usize) -> bool {
    let low: i128 = match start {
        Bound::Included(s) => s as i128,
        Bound::Excluded(s) => s as i128 + 1,
        Bound::Unbounded => 0,
    };
    let high: i128 = match end {
        Bound::Included(e) => e as i128,
        Bound::Excluded(e) => e as i128 - 1,
        Bound::Unbounded => usize::MAX as i128,
    };
    let value = value as i128;
    low <= value && value <= high
}

#[kani::proof]
fn kani_p4_range_contains() {
    let start = any_bound();
    let end = any_bound();
    let value: usize = kani::any();

    let range = RangeCfg::new((start, end));
    let expected = in_interval(start, end, value);
    assert!(range.contains(&value) == expected);

    kani::cover!(expected, "a value inside the range");
    kani::cover!(!expected, "a value outside the range");
    kani::cover!(
        matches!(end, Bound::Excluded(e) if e == value),
        "the value equals an excluded end"
    );
    kani::cover!(
        matches!(start, Bound::Excluded(s) if s == value),
        "the value equals an excluded start"
    );
    kani::cover!(
        matches!(end, Bound::Included(e) if e == value) && expected,
        "the value equals an included end and is accepted"
    );
    kani::cover!(
        matches!((start, end), (Bound::Included(s), Bound::Excluded(e)) if s >= e),
        "an empty range"
    );
}

#[kani::proof]
#[kani::unwind(8)]
fn kani_p4_usize_read() {
    const N: usize = 6;
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let input = &bytes[..len];
    let start = any_bound();
    let end = any_bound();
    let range = RangeCfg::new((start, end));

    // Contract 1: this call must not panic.
    let mut buf = Copying(input);
    let result = usize::read_cfg(&mut buf, &range);
    let left = buf.remaining();

    // Contract 5: the bytes are a malformed 32-bit varint when `UInt<u32>` refuses them with
    // `InvalidVarint`.
    let mut reference_buf = Copying(input);
    let reference = UInt::<u32>::read(&mut reference_buf);
    let malformed = matches!(reference, Err(Error::InvalidVarint(_)));

    // This check asks for a failure and does not look at its kind, so it holds for whatever
    // error `usize` gives.
    kani::cover!(
        malformed && result.is_err(),
        "a malformed varint is refused"
    );

    match &result {
        Ok(v) => {
            // Contract 2 and 3.
            assert!(in_interval(start, end, *v));
            assert!(*v <= u32::MAX as usize);

            // Contract 5: a malformed varint gives no value.
            assert!(!malformed);

            kani::cover!(*v == 0, "accepts length zero");
            kani::cover!(*v == u32::MAX as usize, "accepts the largest length");
            kani::cover!(
                matches!(end, Bound::Included(e) if e == *v),
                "accepts a length equal to an included end"
            );
        }
        Err(Error::InvalidLength(v)) => {
            // Contract 4.
            assert!(!in_interval(start, end, *v));

            // Contract 5: a malformed varint gives no length to report.
            assert!(!malformed);

            kani::cover!(*v == 0, "rejects length zero");
            kani::cover!(
                matches!(end, Bound::Excluded(e) if e == *v),
                "rejects a length equal to an excluded end"
            );
            kani::cover!(
                matches!(end, Bound::Included(e) if e as u128 + 1 == *v as u128),
                "rejects a length one past an included end"
            );
        }
        Err(Error::EndOfBuffer) => {
            kani::cover!(len == 4, "a four-byte prefix ends the buffer");
        }
        // Contract 5: any other failure refuses the bytes. Its kind is a consistency check,
        // so no cover check of the default build is in the three arms below: an error of
        // another kind may never come to one of them.
        Err(Error::InvalidVarint(_)) => {
            #[cfg(feature = "consistency")]
            kani::cover!(malformed, "an invalid varint is reported");
        }
        Err(Error::InvalidUsize) => {
            consistency!(false, "InvalidUsize cannot happen on a 64-bit target");
        }
        Err(_) => {
            consistency!(false, "a failure of another kind");
        }
    }

    // Consistency: agrees with the u32 varint reader on the same input.
    if cfg!(feature = "consistency") {
        match (&result, &reference) {
            (Ok(v), Ok(UInt(r))) | (Err(Error::InvalidLength(v)), Ok(UInt(r))) => {
                assert!(*r as usize == *v);
                assert!(left == reference_buf.remaining());
            }
            (Err(Error::EndOfBuffer), Err(Error::EndOfBuffer)) => {}
            (Err(Error::InvalidVarint(a)), Err(Error::InvalidVarint(b))) => {
                assert!(a == b);
            }
            _ => panic!("usize::read_cfg and the u32 varint reader disagree"),
        }
    }
}
