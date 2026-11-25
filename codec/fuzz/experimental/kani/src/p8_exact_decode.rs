//! P8: `decode` accepts exactly what `write` produced, for the primitives and other
//! fixed-size types.
//!
//! `read` takes a value from the front of a buffer. `decode` is the check on top of it: the
//! buffer must hold one value and nothing else. This proof is about `decode`,
//! `decode_fixed` and `encode_fixed`.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! 1. `decode` fails when bytes remain after the value. codec/src/codec.rs, `Decode`: "Trait
//!    combining [Read] with a check for remaining bytes." "Ensures that *all* bytes from the
//!    input buffer were consumed during decoding." codec/src/codec.rs, `Decode::decode_cfg`:
//!    "Returns [Error] if decoding fails via [Read::read_cfg] or if there are leftover bytes
//!    in `buf` after reading."
//! 2. That failure is `ExtraData` with the number of bytes that remain, and it is given only
//!    after a value was read. codec/src/error.rs, `Error::ExtraData`: "Indicates that after
//!    successfully decoding a value using a method like [crate::Decode::decode_cfg], there
//!    were still unconsumed bytes remaining in the input buffer." "The contained `usize` is
//!    the number of bytes that remained unconsumed."
//! 3. `decode` is `decode_cfg` with the default configuration. codec/src/extensions.rs,
//!    `DecodeExt`: "Import this trait to use the `.decode(buf)` method as a shorthand for
//!    `.decode_cfg(buf, &X::default())`."
//! 4. A fixed-size type has one encoded length. codec/src/codec.rs, `FixedSize`: "the encoded
//!    representation of this type *always* has the same byte length, regardless of the
//!    specific value."
//! 5. Too few bytes fail with `EndOfBuffer`: for a fixed-size type fewer bytes than its
//!    length, for `usize` a cut encoding. codec/src/error.rs, `Error::EndOfBuffer`:
//!    "Indicates that the input buffer (`Buf`) did not contain enough bytes to read the next
//!    piece of data required by a [crate::Read] implementation."
//! 6. A written value decodes to itself. codec/src/lib.rs, crate docs, "Example 1.
//!    Fixed-Size Type": "let bytes = point.encode();" ... "let decoded_point =
//!    Point::decode(bytes).unwrap();" ... "assert_eq!(point, decoded_point);".
//! 7. `encode_fixed` gives the written bytes as an array, and `decode_fixed` decodes such an
//!    array in full. codec/src/codec.rs, `EncodeFixed::encode_fixed`: "Encodes `self` into a
//!    fixed-size byte array `[u8; N]`." codec/src/codec.rs, `DecodeFixed::decode_fixed`:
//!    "Decodes a value from a fixed-size byte array `[u8; N]`, ensuring all bytes are
//!    consumed."
//! 8. `Uint` refuses a set bit beyond its width. codec/src/uint.rs, `Uint`: "Decoding refuses
//!    an encoding with a bit set beyond the width, so every value has exactly one encoding."
//! 9. `usize` is a varint of at most 32 bits. codec/src/types/primitives.rs, module docs: "it
//!    uses variable-length (varint) encoding to save space" and "`usize` is restricted to
//!    values that fit in a `u32`". A malformed varint is refused. codec/src/varint.rs, the
//!    private `read`: "Returns an error if:" "The varint is invalid (too long or
//!    malformed)". Which bytes are malformed: those that `UInt<u32>` refuses with
//!    `InvalidVarint`. codec/src/varint.rs, `Decoder::feed`: "`Err(InvalidVarint)` if the
//!    varint is malformed (overflow or invalid encoding)". The documentation of `usize` does
//!    not say with which error `usize` itself refuses them.
//!
//! From the crate's own tests, not from API documentation:
//!
//! 10. The bytes of zero do not decode as a non-zero integer.
//!     codec/src/types/primitives.rs, the test `test_nonzero_u16`:
//!     "assert!(NonZeroU16::decode(0u16.encode()).is_err());" (the same in `test_nonzero_u32`
//!     and `test_nonzero_u64`). These tests assert that decoding fails. They do not assert
//!     with which error.
//! 11. The failure of item 8 is `Error::Invalid`. codec/src/uint.rs, the test
//!     `test_rejects_bits_beyond_the_width`, expects an `Error::Invalid` named `Uint` from
//!     "U36::decode(Copying(&[0xff; 5])),".
//!
//! # What is proven
//!
//! Each `kani_p8_exact_<type>` has two parts.
//!
//! Part A, for EVERY value `x` of the type, EVERY 2 bytes `t` and EVERY length `n` from 0 to
//! `SIZE + 2`: with `b` = the bytes `write` gives for `x`, followed by `t`,
//! `decode(b[..n])` is
//!
//! - `Err(EndOfBuffer)` when `n < SIZE` (a cut encoding),
//! - `Ok(x)` when `n == SIZE` (exactly the encoding),
//! - `Err(ExtraData(n - SIZE))` when `n > SIZE` (the encoding and 1 or 2 more bytes).
//!
//! And `encode_fixed` gives `b[..SIZE]`, and `decode_fixed` of it gives `x`.
//!
//! Part B, for EVERY byte string of length `0..=SIZE+2`: `decode` does not panic, and
//!
//! - `Ok(v)` only when the input is exactly what `write` gives for `v`, and `read` gives
//!   the same value and leaves nothing;
//! - `Err(ExtraData(n))` only when `read` succeeds and leaves `n > 0` bytes;
//! - `Err(EndOfBuffer)` only when the input is shorter than `SIZE`;
//! - any other error only when the first `SIZE` bytes are not an encoding at all: all zero
//!   for a `NonZero` type (item 10), a bit beyond the width for `Uint<14, 1>` (item 8). For
//!   `Uint<14, 1>` that error is `Invalid` (item 11). For the other types every string of
//!   `SIZE` bytes is an encoding, and `decode` gives no other error.
//!
//! So the bytes of zero are never accepted as a `NonZero` value.
//!
//! `kani_p8_exact_usize` is the same for `usize`, for every value up to `u32::MAX`. Its
//! encoding has 1 to 5 bytes (item 9), and the range is `..`: a cut encoding fails with
//! `EndOfBuffer` (item 5). Bytes that are a malformed 32-bit varint are refused: `decode`
//! accepts them neither whole nor with bytes after them. The gate does not fix the kind of
//! that failure: no assertion and no cover check of the default build looks at it.
//! `RangeCfg` limits are the subject of P4.
//!
//! The types: `u8`, `u16`, `u32`, `u64`, `u128`, `i8`, `i16`, `i32`, `i64`, `i128`, `f32`,
//! `f64` (every bit pattern, compared by bits), `NonZeroU16`, `NonZeroU32`, `NonZeroU64`,
//! `[u8; 4]`, `[u16; 2]`, `Uint<14, 1>` and `usize`. `bool` and `Option` are in P10.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! When `read` fails, `decode` fails with the same kind of error. Item 1 says only that
//! `decode` fails then, and item 2 that the failure is not `ExtraData`.
//!
//! For a `NonZero` type the failure for the bytes of zero is `Error::Invalid`. The tests of
//! item 10 assert only that decoding fails. One test of the crate asserts this kind, for
//! `NonZeroU32::read_vec` (`test_nonzero_read_vec_bounds`), a function no harness here calls.
//!
//! For `usize` the failure for a malformed varint is `InvalidVarint`. Item 9 documents that
//! kind for `UInt<u32>`, not for `usize`, which reads a varint and then converts it, and
//! which has an error kind of its own for that (codec/src/error.rs, `Error::InvalidUsize`).
//! The cover checks that expect the malformed inputs under that kind are compiled only
//! with the feature.
//!
//! # Bounds
//!
//! At most 2 bytes after an encoding. Values: every value of the fixed-size types; for
//! `usize`, every value up to `u32::MAX`. Those are the values the codec encodes (item 9):
//! `write` panics on a larger one, and this proof does not range over them. Loops are
//! unwound up to `SIZE + 4` times, where `SIZE` is the longest encoding of the type (5 for
//! `usize`). The one exception is `kani_p8_exact_uint14`, with 12: the `Uint` code compares
//! the 8 bytes of a limb in a loop. `usize` is 64 bits.

use crate::common::{consistency, cover_unless_never, same_bytes, write_into};
use bytes::Buf as _;
use commonware_codec::{
    Copying, Decode, DecodeExt, DecodeFixed, EncodeFixed, EncodeSize, Error, FixedSize, RangeCfg,
    Read, ReadExt, Uint, varint::UInt,
};
use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};

/// Bytes that may follow an encoding.
const EXTRA: usize = 2;

fn equal<T: PartialEq>(a: &T, b: &T) -> bool {
    a == b
}

/// Every string of `SIZE` bytes is an encoding.
fn never(_: &[u8]) -> bool {
    false
}

/// Item 10: the bytes of zero.
fn all_zero(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// Item 8: a 14-bit value leaves the two top bits of its first byte clear.
fn beyond_14_bits(bytes: &[u8]) -> bool {
    bytes[0] & 0xC0 != 0
}

/// `true` when the two results are errors of the same kind.
fn same_kind<T>(a: &Result<T, Error>, b: &Result<T, Error>) -> bool {
    match (a, b) {
        (Err(a), Err(b)) => core::mem::discriminant(a) == core::mem::discriminant(b),
        _ => false,
    }
}

/// Checks that the failure for bytes that are no encoding is `Error::Invalid`.
///
/// With `gate` every build asserts it: a test of the crate asserts this kind (item 11). With
/// `consistency` only `--features consistency` asserts it: the tests assert that decoding
/// fails, not with which error (item 10). With no word nothing is asserted: the type has no
/// such bytes.
macro_rules! refusal_is_invalid {
    (; $error:expr) => {
        let _ = $error;
    };
    (gate; $error:expr) => {
        assert!(matches!($error, Error::Invalid(_, _)));
    };
    (consistency; $error:expr) => {
        consistency!(matches!($error, Error::Invalid(_, _)));
    };
}

/// `$invalid` names the predicate that is `true` for `SIZE` bytes that are no encoding:
/// `never` for a type whose every string of `SIZE` bytes is an encoding. For another
/// predicate, `$kind` says where the kind of the failure is asserted: see
/// `refusal_is_invalid!`.
macro_rules! exact {
    (
        $name:ident,
        $ty:ty,
        $size:expr,
        $unwind:expr,
        $any:expr,
        $same:expr,
        $invalid:ident $(, $kind:ident)?
    ) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            const SIZE: usize = $size;
            const N: usize = SIZE + EXTRA;
            let same: fn(&$ty, &$ty) -> bool = $same;
            let invalid: fn(&[u8]) -> bool = $invalid;
            assert!(<$ty as FixedSize>::SIZE == SIZE);

            // Part A: a value, its encoding, and the encoding cut or followed by more bytes.
            let value: $ty = $any;
            let mut bytes: [u8; N] = kani::any();
            let written = write_into(&value, &mut bytes[..SIZE]);
            assert!(written == SIZE);

            let len: usize = kani::any();
            kani::assume(len <= N);
            let result = <$ty>::decode(Copying(&bytes[..len]));
            if len < SIZE {
                // Items 4 and 5.
                assert!(matches!(result, Err(Error::EndOfBuffer)));
            } else if len == SIZE {
                // Item 6.
                assert!(matches!(result, Ok(ref v) if same(v, &value)));
            } else {
                // Items 1 and 2.
                assert!(matches!(result, Err(Error::ExtraData(n)) if n == len - SIZE));
            }
            kani::cover!(len == SIZE - 1, "the encoding without its last byte");
            kani::cover!(len == SIZE, "exactly the encoding");
            kani::cover!(len == SIZE + 1, "the encoding and one more byte");
            kani::cover!(len == N, "the encoding and two more bytes");

            // Item 7.
            let fixed: [u8; SIZE] = value.encode_fixed();
            assert!(same_bytes(&fixed, &bytes[..SIZE]));
            let decoded = <$ty>::decode_fixed(fixed);
            assert!(matches!(decoded, Ok(ref v) if same(v, &value)));

            // Part B: any bytes.
            let bytes: [u8; N] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= N);
            let input = &bytes[..len];

            let mut buf = Copying(input);
            let read = <$ty>::read(&mut buf);
            let left = buf.remaining();
            let result = <$ty>::decode(Copying(input));

            match result {
                Ok(ref value) => {
                    // Item 1: nothing remained, and it is the value `read` gives.
                    assert!(matches!(read, Ok(ref v) if same(v, value)));
                    assert!(left == 0);
                    assert!(len == SIZE);

                    // The input is exactly what `write` produces for this value.
                    let mut out = [0u8; SIZE];
                    let written = write_into(value, &mut out);
                    assert!(same_bytes(&out[..written], input));
                    assert!(!invalid(input));

                    kani::cover!(len == SIZE, "accepts bytes that are exactly an encoding");
                }
                Err(Error::ExtraData(n)) => {
                    // Item 2: a value was read, and `n` bytes remained.
                    assert!(read.is_ok());
                    assert!(n == left && n > 0);
                    assert!(n == len - SIZE);

                    kani::cover!(n == 1, "one byte after an encoding");
                    kani::cover!(n == EXTRA, "two bytes after an encoding");
                }
                Err(Error::EndOfBuffer) => {
                    // Item 5.
                    assert!(len < SIZE);
                    assert!(read.is_err());
                    consistency!(same_kind(&read, &result));

                    kani::cover!(len == 0, "an empty input ends the buffer");
                    kani::cover!(len == SIZE - 1, "one byte short ends the buffer");
                }
                Err(ref error) => {
                    // Items 8 and 10: any other failure refuses bytes that are no encoding:
                    // enough bytes, and they are no value. For a type with no such bytes this
                    // assertion fails, so no other error passes.
                    assert!(len >= SIZE && invalid(&input[..SIZE]));
                    assert!(read.is_err());

                    // Item 11 for `Uint`. For a `NonZero` type the kind is a consistency
                    // check: item 10 says that decoding fails, not with which error.
                    refusal_is_invalid!($($kind)?; error);
                    consistency!(same_kind(&read, &result));

                    cover_unless_never!($invalid, len == SIZE, "rejects bytes that are no value");
                    cover_unless_never!($invalid, len == N, "rejects them before two more bytes");
                }
            }
        }
    };
}

exact!(kani_p8_exact_u8, u8, 1, 5, kani::any(), equal, never);
exact!(kani_p8_exact_u16, u16, 2, 6, kani::any(), equal, never);
exact!(kani_p8_exact_u32, u32, 4, 8, kani::any(), equal, never);
exact!(kani_p8_exact_u64, u64, 8, 12, kani::any(), equal, never);
exact!(kani_p8_exact_u128, u128, 16, 20, kani::any(), equal, never);
exact!(kani_p8_exact_i8, i8, 1, 5, kani::any(), equal, never);
exact!(kani_p8_exact_i16, i16, 2, 6, kani::any(), equal, never);
exact!(kani_p8_exact_i32, i32, 4, 8, kani::any(), equal, never);
exact!(kani_p8_exact_i64, i64, 8, 12, kani::any(), equal, never);
exact!(kani_p8_exact_i128, i128, 16, 20, kani::any(), equal, never);

// A float is built from every bit pattern and compared by its bits, so that every NaN
// pattern counts as a value of its own.
exact!(
    kani_p8_exact_f32,
    f32,
    4,
    8,
    f32::from_bits(kani::any()),
    |a, b| a.to_bits() == b.to_bits(),
    never
);
exact!(
    kani_p8_exact_f64,
    f64,
    8,
    12,
    f64::from_bits(kani::any()),
    |a, b| a.to_bits() == b.to_bits(),
    never
);

/// Every value of a `NonZero` type: `new` gives `None` only for zero.
macro_rules! any_nonzero {
    ($nz:ty) => {{
        let value = <$nz>::new(kani::any());
        kani::assume(value.is_some());
        value.unwrap()
    }};
}

exact!(
    kani_p8_exact_nonzero_u16,
    NonZeroU16,
    2,
    6,
    any_nonzero!(NonZeroU16),
    equal,
    all_zero,
    consistency
);
exact!(
    kani_p8_exact_nonzero_u32,
    NonZeroU32,
    4,
    8,
    any_nonzero!(NonZeroU32),
    equal,
    all_zero,
    consistency
);
exact!(
    kani_p8_exact_nonzero_u64,
    NonZeroU64,
    8,
    12,
    any_nonzero!(NonZeroU64),
    equal,
    all_zero,
    consistency
);

exact!(
    kani_p8_exact_array_u8_4,
    [u8; 4],
    4,
    8,
    kani::any(),
    equal,
    never
);
exact!(
    kani_p8_exact_array_u16_2,
    [u16; 2],
    4,
    8,
    kani::any(),
    equal,
    never
);

type U14 = Uint<14, 1>;

/// Every 14-bit value.
fn any_u14() -> U14 {
    let limb: u64 = kani::any();
    kani::assume(limb < 1 << 14);
    U14::from_limbs([limb])
}

// Comparing two `Uint` values compares the 8 bytes of a limb, so the bound is above 8.
exact!(
    kani_p8_exact_uint14,
    U14,
    2,
    12,
    any_u14(),
    equal,
    beyond_14_bits,
    gate
);

#[kani::proof]
#[kani::unwind(9)]
fn kani_p8_exact_usize() {
    // Item 9: the longest varint of 32 bits has 5 bytes.
    const MAX: usize = 5;
    const N: usize = MAX + EXTRA;
    let all = RangeCfg::new(..);

    // Part A: a value, its encoding, and the encoding cut or followed by more bytes.
    let value: usize = kani::any();
    kani::assume(value <= u32::MAX as usize);
    let size = value.encode_size();
    assert!(size >= 1 && size <= MAX);
    let mut bytes: [u8; N] = kani::any();
    let written = write_into(&value, &mut bytes[..size]);
    assert!(written == size);

    let len: usize = kani::any();
    kani::assume(len <= size + EXTRA);
    let result = usize::decode_cfg(Copying(&bytes[..len]), &all);
    if len < size {
        assert!(matches!(result, Err(Error::EndOfBuffer)));
    } else if len == size {
        assert!(matches!(result, Ok(v) if v == value));
    } else {
        assert!(matches!(result, Err(Error::ExtraData(n)) if n == len - size));
    }
    kani::cover!(size == 1 && len == 0, "a one-byte encoding cut to nothing");
    kani::cover!(
        size == MAX && len == MAX - 1,
        "the longest encoding without its last byte"
    );
    kani::cover!(size == MAX && len == MAX, "exactly the longest encoding");
    kani::cover!(
        size == MAX && len == N,
        "the longest encoding and two more bytes"
    );

    // Part B: any bytes.
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let input = &bytes[..len];

    let mut buf = Copying(input);
    let read = usize::read_cfg(&mut buf, &all);
    let left = buf.remaining();
    let result = usize::decode_cfg(Copying(input), &all);

    // Item 9: the bytes are a malformed 32-bit varint when `UInt<u32>` refuses them with
    // `InvalidVarint`.
    let varint = UInt::<u32>::read(&mut Copying(input));
    let malformed = matches!(varint, Err(Error::InvalidVarint(_)));

    // Item 9: a malformed varint is refused. These checks ask for a failure and do not look
    // at its kind, so they hold for whatever error `usize` gives.
    kani::cover!(
        malformed && result.is_err() && len == 2,
        "rejects a varint that ends in a zero byte"
    );
    kani::cover!(
        malformed && result.is_err() && len == MAX,
        "rejects a malformed varint of the longest size"
    );
    kani::cover!(
        malformed && result.is_err() && len == N,
        "rejects a malformed varint with bytes after it"
    );

    // The kind of that failure is a consistency check: item 9 does not name it for `usize`.
    consistency!(!malformed || matches!(result, Err(Error::InvalidVarint(_))));

    match result {
        Ok(value) => {
            // Item 1: nothing remained, and it is the value `read_cfg` gives.
            assert!(matches!(read, Ok(v) if v == value));
            assert!(left == 0);

            // Item 9: a malformed varint is not accepted.
            assert!(!malformed);

            // The input is exactly what `write` produces for this value.
            let mut out = [0u8; MAX];
            let written = write_into(&value, &mut out);
            assert!(same_bytes(&out[..written], input));

            kani::cover!(len == 1, "accepts a one-byte encoding");
            kani::cover!(len == MAX, "accepts the longest encoding");
        }
        Err(Error::ExtraData(n)) => {
            // Item 2: a value was read, and `n` bytes remained.
            assert!(read.is_ok());
            assert!(n == left && n > 0);

            // Item 9: a malformed varint is not accepted with bytes after it either.
            assert!(!malformed);

            kani::cover!(n == N - 1, "six bytes after a one-byte encoding");
        }
        Err(Error::EndOfBuffer) => {
            assert!(read.is_err());
            consistency!(same_kind(&read, &result));

            kani::cover!(len == 0, "an empty input ends the buffer");
            kani::cover!(len == MAX - 1, "four bytes that all ask for another one");
        }
        Err(ref error) => {
            // Any other failure: `read_cfg` refused the bytes. Item 9 says that a malformed
            // varint is refused, not with which error, so the kind is a consistency check.
            // No cover check of the default build is in this arm: an error of another kind
            // may never come here.
            assert!(read.is_err());
            consistency!(matches!(error, Error::InvalidVarint(_)));
            consistency!(same_kind(&read, &result));

            // With the kind asserted, the malformed inputs are refused in this arm.
            #[cfg(feature = "consistency")]
            {
                kani::cover!(
                    malformed && len == 2,
                    "rejects a varint that ends in a zero byte as an invalid varint"
                );
                kani::cover!(
                    malformed && len == MAX,
                    "rejects a malformed varint of the longest size as an invalid varint"
                );
                kani::cover!(
                    malformed && len == N,
                    "rejects a malformed varint with bytes after it as an invalid varint"
                );
            }
        }
    }
}
