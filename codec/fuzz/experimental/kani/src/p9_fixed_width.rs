//! P9: fixed-width integers and floats, arrays, tuples and `Uint` have the exact size, the
//! byte layout and the round trip their documentation gives.
//!
//! This proof is about `write`, `read` and the size functions. P8 is about `decode`.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! 1. Decoding does not panic, a failure is an error, and too few bytes fail with
//!    `EndOfBuffer`. codec/src/codec.rs, `Read::read_cfg`: "Implementations must return
//!    [Error] if decoding fails due to invalid data, insufficient bytes in the buffer" and
//!    "Parsing a message (often untrusted) should never result in a panic."
//!    codec/src/error.rs, `Error::EndOfBuffer`: "Indicates that the input buffer (`Buf`) did
//!    not contain enough bytes to read the next piece of data required by a [crate::Read]
//!    implementation." A malformed varint fails with `InvalidVarint`. codec/src/varint.rs,
//!    `Decoder::feed`: "`Err(InvalidVarint)` if the varint is malformed (overflow or invalid
//!    encoding)". Reading a `UInt<U>` is that varint read and nothing more
//!    (codec/src/varint.rs, `Read for UInt<U>`: "read(buf).map(UInt)").
//! 2. An accepted input is read to the end of the value and no further.
//!    codec/src/codec.rs, `Read::read_cfg`: "Implementations should consume the exact number
//!    of bytes required from `buf` to reconstruct the value."
//! 3. A fixed-size type has one encoded length, which is also its `encode_size` and its
//!    `MAX_ENCODE_SIZE`. codec/src/codec.rs, `FixedSize`: "the encoded representation of this
//!    type *always* has the same byte length, regardless of the specific value." "This
//!    automatically provides implementations of [EncodeSize] and [MaxEncodeSize]."
//!    codec/src/codec.rs, `EncodeSize::encode_size`: "Returns the encoded size of this value
//!    (in bytes)."
//! 4. Integers and floats are big-endian. codec/src/types/primitives.rs, module docs: "All
//!    fixed-size integers and floats are written big-endian".
//! 5. An array is fixed-size when its element is. codec/src/lib.rs, crate docs, "Supported
//!    Types": "Arrays: `[T; N]` supports [Write] and [Read] when `T` does, and supports
//!    [FixedSize], [Encode], [Codec], [EncodeFixed], and [CodecFixed] when `T: FixedSize`."
//! 6. Tuples are supported, and the size bound of a composite type is the sum of the bounds
//!    of its parts. codec/src/lib.rs, crate docs, "Supported Types": "Tuples: `(T1, T2, ...)`
//!    (up to 12 elements)". codec/src/lib.rs, crate docs, "Size Bounds": "[FixedSize] types
//!    contribute their fixed size. Composite types sum their fields' bounds".
//!    codec/src/codec.rs, `MaxEncodeSize::MAX_ENCODE_SIZE`: "An upper bound on the encoded
//!    size, in bytes."
//! 7. `Uint`. codec/src/uint.rs, `Uint`: "An unsigned integer of `BITS` bits held in `LIMBS`
//!    limbs of 64 bits." "It encodes as its value in big-endian over the fewest bytes that
//!    hold its bits. Decoding refuses an encoding with a bit set beyond the width, so every
//!    value has exactly one encoding." codec/src/uint.rs, `Uint::BYTES`: the "Number of bytes
//!    the encoding takes."
//! 8. A written value decodes to itself. codec/src/lib.rs, crate docs, "Example 1.
//!    Fixed-Size Type": "let bytes = point.encode();" ... "let decoded_point =
//!    Point::decode(bytes).unwrap();" ... "assert_eq!(point, decoded_point);".
//!
//! From the crate's own tests, not from API documentation. The documentation does not say in
//! which order the parts of an array or of a tuple are written, or that zero is refused:
//!
//! 9. An array is its elements in order, with no length in front, and its size is the
//!    element size times the count. codec/src/types/primitives.rs, the test `test_array`:
//!    "`[u8; N]` encodes exactly N payload bytes, with no length prefix." and "Larger
//!    fixed-size elements compose normally and preserve big-endian encoding." with
//!    "assert_eq!(<[u16; 3] as FixedSize>::SIZE, 6);". Nested arrays, in the same test:
//!    "Nested arrays inherit the same fixed-size encoding from their elements."
//! 10. A tuple is its parts in order. codec/src/types/tuple.rs, the test `test_conformity`,
//!     for example "assert_eq!(t2.encode(), &[0xAB, 0xCD, 0x00, 0xDE, 0xAD, 0xBE, 0xEF][..]);".
//! 11. The bytes of zero do not decode as a non-zero integer.
//!     codec/src/types/primitives.rs, the test `test_nonzero_u16`:
//!     "assert!(NonZeroU16::decode(0u16.encode()).is_err());" (the same in `test_nonzero_u32`
//!     and `test_nonzero_u64`). These tests assert that decoding fails. They do not assert
//!     with which error.
//! 12. In a `Uint` of more than one limb the bytes of the most significant limb come first.
//!     codec/src/uint.rs, the test `test_partial_limbs_encode_their_bytes_only`: "A partial
//!     limb above a whole one encodes its bytes first." The failure for a bit beyond the
//!     width is `Error::Invalid`: codec/src/uint.rs, the test
//!     `test_rejects_bits_beyond_the_width`, expects an `Error::Invalid` named `Uint` from
//!     "U36::decode(Copying(&[0xff; 5])),".
//!
//! # What is proven
//!
//! `kani_p9_int_*`, `kani_p9_float_*`, `kani_p9_nonzero_*` (items 1 to 4, 8 and 11). For
//! EVERY value of the type: `write` writes exactly `SIZE` bytes, `SIZE` is `encode_size()`
//! and `MAX_ENCODE_SIZE`, the bytes are the big-endian bytes of the value (for a signed
//! integer of its two's complement bits, for a float of its IEEE 754 bits), and `read` gives
//! the value back and leaves a following byte alone. For EVERY byte string of length
//! `0..=SIZE+1`: `read` does not panic; it gives `Ok(v)` only with `v` = the big-endian value
//! of the first `SIZE` bytes, read exactly; `EndOfBuffer` only for fewer than `SIZE` bytes;
//! any other error only for a `NonZero` type and `SIZE` zero bytes. So the bytes of zero are
//! never read as a `NonZero` value, and an integer or a float fails only with `EndOfBuffer`.
//!
//! `kani_p9_array_*` (items 5, 8 and 9). The same for `[u8; 5]`, `[u16; 3]` and
//! `[[u16; 2]; 2]`: `SIZE` is the element size times the count, and element `i` is the bytes
//! from `i * ELEM`. `kani_p9_array_empty`: `[u8; 0]` and `[u32; 0]` have size 0, write nothing
//! and read nothing.
//!
//! `kani_p9_tuple_*` (items 6, 8 and 10). For EVERY value of `(u8, u16)`, of
//! `(UInt<u16>, u32)` (a part of variable size), of `((u8, u16), (u32,))` (nested, and a
//! tuple of one part) and of a tuple of twelve `u8` (the largest): `encode_size()` is the
//! sum of the `encode_size()` of the parts and the number of bytes written, at most
//! `MAX_ENCODE_SIZE`, which is the sum of the bounds of the parts; the bytes are the parts
//! in order; `read_cfg` and `decode` give the value back. For EVERY byte string up to one
//! byte past the longest encoding of `(u8, u16)` and `(UInt<u16>, u32)`: `read_cfg` does not
//! panic, reads exactly the bytes that `write` gives for the value it returns, and fails
//! with `EndOfBuffer` (or, for the `UInt<u16>` part, `InvalidVarint`: item 1) and nothing
//! else.
//!
//! `kani_p9_uint_*` (items 7, 8 and 12). For `Uint<14, 1>`, `Uint<72, 2>` and `Uint<256, 4>`
//! (the alias `U256`), for
//! EVERY value: `SIZE` and `BYTES` are the fewest bytes that hold `BITS` bits, the bytes are
//! the value in big-endian, and `read` gives the value back. For EVERY byte string of length
//! `0..=SIZE+1`: `Ok(v)` only with `v` = the big-endian value of the first `SIZE` bytes;
//! `Invalid` only when a bit beyond the width is set (possible only for 14 bits);
//! `EndOfBuffer` only for fewer than `SIZE` bytes.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! For a `NonZero` type the failure for the bytes of zero is `Error::Invalid`. The tests of
//! item 11 assert only that decoding fails. One test of the crate asserts this kind, for
//! `NonZeroU32::read_vec` (`test_nonzero_read_vec_bounds`), a function no harness here calls.
//!
//! # Bounds
//!
//! The array lengths, tuple shapes and `Uint` widths named above: other lengths, shapes and
//! widths are not covered. Arrays of an element type that has no fixed size are not covered.
//! One byte after an encoding. No bound on the values. Loops are unwound up to `SIZE + 4`
//! times, where `SIZE` is the longest encoding of the harness. The exceptions are the two
//! harnesses on `Uint<14, 1>` (`kani_p9_uint_14` and `kani_p9_uint_14_refuses_spare_bits`),
//! with 12: the `Uint` code compares the 8 bytes of a limb in a loop. `usize` is 64 bits.

use crate::common::{big_endian, consistency, cover_unless_never, same_bytes, write_into};
use bytes::Buf as _;
use commonware_codec::{
    Copying, Decode, DecodeExt, EncodeSize, Error, FixedSize, MaxEncodeSize, Read, ReadExt, Uint,
    varint::UInt,
};
use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};

/// Every string of `SIZE` bytes is an encoding.
fn never(_: &[u8]) -> bool {
    false
}

/// Item 11: the bytes of zero.
fn all_zero(bytes: &[u8]) -> bool {
    big_endian(bytes) == 0
}

/// One fixed-width scalar. `$bits` gives the value as the unsigned integer its bytes spell.
/// `$invalid` names the predicate that is `true` for `SIZE` bytes that are no encoding:
/// `never` for a type whose every string of `SIZE` bytes is an encoding.
macro_rules! fixed_width {
    ($name:ident, $ty:ty, $size:expr, $unwind:expr, $any:expr, $bits:expr, $invalid:ident) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            const SIZE: usize = $size;
            const N: usize = SIZE + 1;
            let bits: fn(&$ty) -> u128 = $bits;
            let invalid: fn(&[u8]) -> bool = $invalid;

            // Item 3.
            assert!(<$ty as FixedSize>::SIZE == SIZE);
            assert!(<$ty as MaxEncodeSize>::MAX_ENCODE_SIZE == SIZE);

            // From a value. `write_into` panics if more than SIZE bytes are written. The last
            // byte of `out` is any byte that follows the encoding.
            let value: $ty = $any;
            let mut out: [u8; N] = kani::any();
            let written = write_into(&value, &mut out[..SIZE]);
            assert!(written == SIZE);
            assert!(value.encode_size() == SIZE);

            // Item 4.
            assert!(big_endian(&out[..SIZE]) == bits(&value));

            // Items 2 and 8.
            let mut buf = Copying(&out[..]);
            let decoded = <$ty>::read(&mut buf);
            assert!(matches!(decoded, Ok(ref v) if bits(v) == bits(&value)));
            assert!(buf.remaining() == 1);

            // From any bytes. Item 1: this call must not panic.
            let bytes: [u8; N] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= N);
            let input = &bytes[..len];
            let mut buf = Copying(input);
            let result = <$ty>::read(&mut buf);
            let consumed = len - buf.remaining();

            match result {
                Ok(ref v) => {
                    // Items 2 and 4.
                    assert!(consumed == SIZE);
                    assert!(bits(v) == big_endian(&input[..SIZE]));
                    assert!(!invalid(&input[..SIZE]));

                    kani::cover!(len == SIZE, "accepts an input of exactly the size");
                    kani::cover!(len == N, "accepts with a byte left in the buffer");
                }
                Err(Error::EndOfBuffer) => {
                    // Item 1.
                    assert!(len < SIZE);

                    kani::cover!(len == SIZE - 1, "one byte short ends the buffer");
                }
                Err(ref error) => {
                    // Item 11: any other failure refuses the bytes of zero. For a type with
                    // no such bytes this assertion fails, so no other error passes.
                    assert!(len >= SIZE && invalid(&input[..SIZE]));

                    // Item 11 says that decoding fails, not with which error.
                    consistency!(matches!(error, Error::Invalid(_, _)));

                    cover_unless_never!($invalid, len == SIZE, "rejects the bytes of zero");
                    cover_unless_never!($invalid, len == N, "rejects them with a byte after them");
                }
            }
        }
    };
}

fixed_width!(kani_p9_int_u8, u8, 1, 5, kani::any(), |v| *v as u128, never);
fixed_width!(
    kani_p9_int_u16,
    u16,
    2,
    6,
    kani::any(),
    |v| *v as u128,
    never
);
fixed_width!(
    kani_p9_int_u32,
    u32,
    4,
    8,
    kani::any(),
    |v| *v as u128,
    never
);
fixed_width!(
    kani_p9_int_u64,
    u64,
    8,
    12,
    kani::any(),
    |v| *v as u128,
    never
);
fixed_width!(kani_p9_int_u128, u128, 16, 20, kani::any(), |v| *v, never);

// A signed integer is written as its two's complement bits.
fixed_width!(
    kani_p9_int_i8,
    i8,
    1,
    5,
    kani::any(),
    |v| *v as u8 as u128,
    never
);
fixed_width!(
    kani_p9_int_i16,
    i16,
    2,
    6,
    kani::any(),
    |v| *v as u16 as u128,
    never
);
fixed_width!(
    kani_p9_int_i32,
    i32,
    4,
    8,
    kani::any(),
    |v| *v as u32 as u128,
    never
);
fixed_width!(
    kani_p9_int_i64,
    i64,
    8,
    12,
    kani::any(),
    |v| *v as u64 as u128,
    never
);
fixed_width!(
    kani_p9_int_i128,
    i128,
    16,
    20,
    kani::any(),
    |v| *v as u128,
    never
);

// A float is written as its IEEE 754 bits. It is built from every bit pattern, so each NaN
// is a value here too.
fixed_width!(
    kani_p9_float_f32,
    f32,
    4,
    8,
    f32::from_bits(kani::any()),
    |v| v.to_bits() as u128,
    never
);
fixed_width!(
    kani_p9_float_f64,
    f64,
    8,
    12,
    f64::from_bits(kani::any()),
    |v| v.to_bits() as u128,
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

fixed_width!(
    kani_p9_nonzero_u16,
    NonZeroU16,
    2,
    6,
    any_nonzero!(NonZeroU16),
    |v| v.get() as u128,
    all_zero
);
fixed_width!(
    kani_p9_nonzero_u32,
    NonZeroU32,
    4,
    8,
    any_nonzero!(NonZeroU32),
    |v| v.get() as u128,
    all_zero
);
fixed_width!(
    kani_p9_nonzero_u64,
    NonZeroU64,
    8,
    12,
    any_nonzero!(NonZeroU64),
    |v| v.get() as u128,
    all_zero
);

/// An array of `$count` elements of `$elem_size` bytes each.
macro_rules! array {
    ($name:ident, $elem:ty, $count:expr, $elem_size:expr, $unwind:expr, $bits:expr) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            const COUNT: usize = $count;
            const ELEM: usize = $elem_size;
            const SIZE: usize = COUNT * ELEM;
            const N: usize = SIZE + 1;
            let bits: fn(&$elem) -> u128 = $bits;

            // Items 3, 5 and 9: the element size times the count.
            assert!(<$elem as FixedSize>::SIZE == ELEM);
            assert!(<[$elem; COUNT] as FixedSize>::SIZE == SIZE);
            assert!(<[$elem; COUNT] as MaxEncodeSize>::MAX_ENCODE_SIZE == SIZE);

            // From a value. The last byte of `out` is any byte that follows the encoding.
            let value: [$elem; COUNT] = kani::any();
            let mut out: [u8; N] = kani::any();
            let written = write_into(&value, &mut out[..SIZE]);
            assert!(written == SIZE);
            assert!(value.encode_size() == SIZE);

            // Item 9: element `i` is the bytes from `i * ELEM`.
            let mut i = 0;
            while i < COUNT {
                assert!(big_endian(&out[i * ELEM..(i + 1) * ELEM]) == bits(&value[i]));
                i += 1;
            }

            // Items 2 and 8.
            let mut buf = Copying(&out[..]);
            let decoded = <[$elem; COUNT]>::read(&mut buf);
            assert!(buf.remaining() == 1);
            match decoded {
                Ok(ref v) => {
                    let mut i = 0;
                    while i < COUNT {
                        assert!(bits(&v[i]) == bits(&value[i]));
                        i += 1;
                    }
                }
                Err(_) => panic!("a written array must decode"),
            }

            // From any bytes. Item 1: this call must not panic.
            let bytes: [u8; N] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= N);
            let input = &bytes[..len];
            let mut buf = Copying(input);
            let result = <[$elem; COUNT]>::read(&mut buf);
            let consumed = len - buf.remaining();

            match result {
                Ok(ref v) => {
                    assert!(consumed == SIZE);
                    let mut i = 0;
                    while i < COUNT {
                        assert!(bits(&v[i]) == big_endian(&input[i * ELEM..(i + 1) * ELEM]));
                        i += 1;
                    }

                    kani::cover!(len == SIZE, "accepts an input of exactly the size");
                    kani::cover!(len == N, "accepts with a byte left in the buffer");
                }
                Err(Error::EndOfBuffer) => {
                    assert!(len < SIZE);

                    kani::cover!(len == 0, "empty input ends the buffer");
                    kani::cover!(len == SIZE - 1, "one byte short ends the buffer");
                }
                Err(_) => panic!("unexpected error kind"),
            }
        }
    };
}

array!(kani_p9_array_u8_5, u8, 5, 1, 9, |v| *v as u128);
array!(kani_p9_array_u16_3, u16, 3, 2, 10, |v| *v as u128);
array!(kani_p9_array_nested, [u16; 2], 2, 4, 12, |v| {
    ((v[0] as u128) << 16) | v[1] as u128
});

/// Item 9: an array of no elements has no bytes.
#[kani::proof]
#[kani::unwind(3)]
fn kani_p9_array_empty() {
    assert!(<[u8; 0] as FixedSize>::SIZE == 0);
    assert!(<[u32; 0] as FixedSize>::SIZE == 0);

    let any_byte: [u8; 1] = kani::any();
    let mut out = any_byte;
    assert!(write_into(&[0u8; 0], &mut out) == 0);
    assert!(write_into(&[0u32; 0], &mut out) == 0);
    assert!(out[0] == any_byte[0]);

    let len: usize = kani::any();
    kani::assume(len <= 1);
    let mut buf = Copying(&any_byte[..len]);
    assert!(<[u8; 0]>::read(&mut buf).is_ok());
    assert!(<[u32; 0]>::read(&mut buf).is_ok());
    assert!(buf.remaining() == len);

    kani::cover!(len == 0, "reads from an empty buffer");
    kani::cover!(len == 1, "leaves the byte in the buffer");
}

#[kani::proof]
#[kani::unwind(7)]
fn kani_p9_tuple_pair() {
    const SIZE: usize = 3;
    const N: usize = SIZE + 1;
    type Pair = (u8, u16);
    let cfg = ((), ());

    // Item 6: the bound is the sum of the bounds of the parts.
    assert!(Pair::MAX_ENCODE_SIZE == u8::MAX_ENCODE_SIZE + u16::MAX_ENCODE_SIZE);
    assert!(Pair::MAX_ENCODE_SIZE == SIZE);

    // From a value.
    let value: Pair = (kani::any(), kani::any());
    let mut out: [u8; N] = kani::any();
    let written = write_into(&value, &mut out[..SIZE]);
    assert!(written == value.encode_size());
    assert!(value.encode_size() == value.0.encode_size() + value.1.encode_size());
    assert!(written <= Pair::MAX_ENCODE_SIZE);

    // Items 4 and 10: the parts in order.
    assert!(out[0] == value.0);
    assert!(big_endian(&out[1..3]) == value.1 as u128);

    // Items 2 and 8.
    let mut buf = Copying(&out[..]);
    let decoded = Pair::read_cfg(&mut buf, &cfg);
    assert!(matches!(decoded, Ok(v) if v == value));
    assert!(buf.remaining() == 1);
    assert!(matches!(Pair::decode(Copying(&out[..SIZE])), Ok(v) if v == value));

    // From any bytes. Item 1: this call must not panic.
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let input = &bytes[..len];
    let mut buf = Copying(input);
    let result = Pair::read_cfg(&mut buf, &cfg);
    let consumed = len - buf.remaining();

    match result {
        Ok(v) => {
            assert!(consumed == v.encode_size());
            assert!(v.0 == input[0]);
            assert!(v.1 as u128 == big_endian(&input[1..3]));

            kani::cover!(len == SIZE, "accepts an input of exactly the size");
            kani::cover!(len == N, "accepts with a byte left in the buffer");
        }
        Err(Error::EndOfBuffer) => {
            assert!(len < SIZE);

            kani::cover!(len == 0, "no byte for the first part");
            kani::cover!(len == 2, "half of the second part");
        }
        Err(_) => panic!("unexpected error kind"),
    }
}

/// A tuple with a part of variable size: a varint of 1 to 3 bytes, then 4 bytes.
#[kani::proof]
#[kani::unwind(10)]
fn kani_p9_tuple_varint() {
    const MAX: usize = 7;
    const N: usize = MAX + 1;
    type Mixed = (UInt<u16>, u32);
    let cfg = ((), ());

    // Item 6: the bound is the sum of the bounds of the parts.
    assert!(Mixed::MAX_ENCODE_SIZE == UInt::<u16>::MAX_ENCODE_SIZE + u32::MAX_ENCODE_SIZE);
    assert!(Mixed::MAX_ENCODE_SIZE == MAX);

    // From a value. `write_into` panics if more than MAX bytes are written.
    let value: Mixed = (UInt(kani::any()), kani::any());
    let mut out = [0u8; MAX];
    let written = write_into(&value, &mut out);
    let first = value.0.encode_size();
    assert!(written == value.encode_size());
    assert!(value.encode_size() == first + value.1.encode_size());
    assert!(written <= Mixed::MAX_ENCODE_SIZE);

    // Item 10: the parts in order.
    let mut part = [0u8; 3];
    assert!(write_into(&value.0, &mut part) == first);
    assert!(same_bytes(&out[..first], &part[..first]));
    assert!(big_endian(&out[first..written]) == value.1 as u128);

    // Items 2 and 8.
    let mut buf = Copying(&out[..written]);
    let decoded = Mixed::read_cfg(&mut buf, &cfg);
    assert!(matches!(decoded, Ok((UInt(a), b)) if a == value.0.0 && b == value.1));
    assert!(buf.remaining() == 0);
    let decoded = Mixed::decode_cfg(Copying(&out[..written]), &cfg);
    assert!(matches!(decoded, Ok((UInt(a), b)) if a == value.0.0 && b == value.1));

    kani::cover!(first == 1, "a one-byte first part");
    kani::cover!(written == MAX, "a value of the maximum size");

    // From any bytes. Item 1: this call must not panic.
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let input = &bytes[..len];
    let mut buf = Copying(input);
    let result = Mixed::read_cfg(&mut buf, &cfg);
    let consumed = len - buf.remaining();

    match result {
        Ok(v) => {
            // Item 2: exactly the bytes that `write` gives for this value.
            assert!(consumed == v.encode_size());
            let mut again = [0u8; MAX];
            let written = write_into(&v, &mut again);
            assert!(same_bytes(&again[..written], &input[..consumed]));

            kani::cover!(consumed == 5, "accepts the shortest encoding");
            kani::cover!(consumed == MAX, "accepts the longest encoding");
            kani::cover!(consumed < len, "accepts with a byte left in the buffer");
        }
        Err(Error::EndOfBuffer) => {
            // An input of the maximum size is never too short.
            assert!(len < MAX);

            kani::cover!(len == 0, "no byte for the first part");
            kani::cover!(len == MAX - 1, "the longest encoding without its last byte");
        }
        Err(Error::InvalidVarint(_)) => {
            // Item 1: the first part is a `UInt<u16>`, and a malformed varint fails with
            // `InvalidVarint`.
            kani::cover!(len == N, "rejects a malformed first part of a full input");
        }
        Err(_) => panic!("unexpected error kind"),
    }
}

/// A tuple of tuples, one of them with a single part.
#[kani::proof]
#[kani::unwind(11)]
fn kani_p9_tuple_nested() {
    const SIZE: usize = 7;
    type Nested = ((u8, u16), (u32,));
    let cfg = (((), ()), ((),));

    // Item 6: the bound is the sum of the bounds of the parts.
    assert!(Nested::MAX_ENCODE_SIZE == <(u8, u16)>::MAX_ENCODE_SIZE + <(u32,)>::MAX_ENCODE_SIZE);
    assert!(<(u32,)>::MAX_ENCODE_SIZE == u32::MAX_ENCODE_SIZE);
    assert!(Nested::MAX_ENCODE_SIZE == SIZE);

    let value: Nested = ((kani::any(), kani::any()), (kani::any(),));
    let mut out = [0u8; SIZE];
    let written = write_into(&value, &mut out);
    assert!(written == value.encode_size());
    assert!(value.encode_size() == value.0.encode_size() + value.1.encode_size());
    assert!(written == SIZE);

    // Item 10: the parts in order, at every level.
    assert!(out[0] == value.0.0);
    assert!(big_endian(&out[1..3]) == value.0.1 as u128);
    assert!(big_endian(&out[3..7]) == value.1.0 as u128);

    // Items 2 and 8.
    let mut buf = Copying(&out[..]);
    let decoded = Nested::read_cfg(&mut buf, &cfg);
    assert!(matches!(decoded, Ok(v) if v == value));
    assert!(buf.remaining() == 0);
    // A tuple of one part has no `decode` shorthand: its configuration is not unit-like.
    assert!(matches!(Nested::decode_cfg(Copying(&out[..]), &cfg), Ok(v) if v == value));

    kani::cover!(written == SIZE, "a value is written and read back");
}

/// The largest tuple: twelve parts.
#[kani::proof]
#[kani::unwind(16)]
fn kani_p9_tuple_twelve() {
    const SIZE: usize = 12;
    type Twelve = (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8);
    let cfg = ((), (), (), (), (), (), (), (), (), (), (), ());

    // Item 6: the bound is the sum of the bounds of the parts.
    assert!(Twelve::MAX_ENCODE_SIZE == 12 * u8::MAX_ENCODE_SIZE);

    let b: [u8; SIZE] = kani::any();
    let value: Twelve = (
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
    );
    let mut out = [0u8; SIZE];
    let written = write_into(&value, &mut out);
    assert!(written == value.encode_size());
    assert!(written == SIZE);

    // Item 10: part `i` is byte `i`.
    assert!(same_bytes(&out, &b));

    // Items 2 and 8.
    let mut buf = Copying(&out[..]);
    let decoded = Twelve::read_cfg(&mut buf, &cfg);
    assert!(matches!(decoded, Ok(v) if v == value));
    assert!(buf.remaining() == 0);
    assert!(matches!(Twelve::decode(Copying(&out[..])), Ok(v) if v == value));

    // One byte short.
    let short = Twelve::read_cfg(&mut Copying(&out[..SIZE - 1]), &cfg);
    assert!(matches!(short, Err(Error::EndOfBuffer)));

    kani::cover!(written == SIZE, "a value is written and read back");
}

/// Items 7 and 12: `true` when `bytes` is the big-endian value of `limbs` (the least
/// significant limb first, as `Uint::as_limbs` gives them).
fn spells_limbs(limbs: &[u64], bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        // Byte `i` counted from the end is byte `i % 8` of limb `i / 8`.
        let byte = (limbs[i / 8] >> (8 * (i % 8))) as u8;
        if bytes[bytes.len() - 1 - i] != byte {
            return false;
        }
        i += 1;
    }
    true
}

/// A `Uint` of `$bits` bits in `$limbs` limbs. `$top` is the largest value of its most
/// significant limb, `$spare` the bits of the first byte that are beyond the width.
/// `$refused` is `never` for a width that ends on a byte boundary, where no input is refused,
/// and `spare_bits` otherwise.
macro_rules! uint {
    (
        $name:ident,
        $bits:expr,
        $limbs:expr,
        $size:expr,
        $unwind:expr,
        $top:expr,
        $spare:expr,
        $refused:ident
    ) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            const BITS: usize = $bits;
            const LIMBS: usize = $limbs;
            const SIZE: usize = $size;
            const N: usize = SIZE + 1;
            const TOP: u64 = $top;
            const SPARE: u8 = $spare;
            type Value = Uint<BITS, LIMBS>;

            // Items 3 and 7: the fewest bytes that hold the bits.
            assert!(SIZE == BITS.div_ceil(8));
            assert!(Value::BYTES == SIZE);
            assert!(Value::SIZE == SIZE);
            assert!(Value::MAX_ENCODE_SIZE == SIZE);

            // From a value: every value below 2^BITS.
            let limbs: [u64; LIMBS] = kani::any();
            kani::assume(limbs[LIMBS - 1] <= TOP);
            let value = Value::from_limbs(limbs);
            let mut out: [u8; N] = kani::any();
            let written = write_into(&value, &mut out[..SIZE]);
            assert!(written == SIZE);
            assert!(value.encode_size() == SIZE);

            // Items 7 and 12.
            assert!(spells_limbs(&limbs, &out[..SIZE]));

            // Items 2 and 8.
            let mut buf = Copying(&out[..]);
            let decoded = Value::read(&mut buf);
            assert!(matches!(decoded, Ok(ref v) if same_limbs(v.as_limbs(), &limbs)));
            assert!(buf.remaining() == 1);

            // From any bytes. Item 1: this call must not panic.
            let bytes: [u8; N] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= N);
            let input = &bytes[..len];
            let mut buf = Copying(input);
            let result = Value::read(&mut buf);
            let consumed = len - buf.remaining();

            match result {
                Ok(ref v) => {
                    // Items 2 and 7: the value the bytes spell, with no bit beyond the width.
                    assert!(consumed == SIZE);
                    assert!(spells_limbs(v.as_limbs(), &input[..SIZE]));
                    assert!(input[0] & SPARE == 0);
                    assert!(v.as_limbs()[LIMBS - 1] <= TOP);

                    kani::cover!(len == SIZE, "accepts an input of exactly the size");
                    kani::cover!(len == N, "accepts with a byte left in the buffer");
                    kani::cover!(v.as_limbs()[LIMBS - 1] == TOP, "accepts a full top limb");
                }
                Err(Error::EndOfBuffer) => {
                    assert!(len < SIZE);

                    kani::cover!(len == 0, "empty input ends the buffer");
                    kani::cover!(len == SIZE - 1, "one byte short ends the buffer");
                }
                Err(Error::Invalid(_, _)) => {
                    // Item 7: only a bit beyond the width.
                    assert!(len >= SIZE && input[0] & SPARE != 0);

                    cover_unless_never!($refused, len == SIZE, "refuses a bit beyond the width");
                    cover_unless_never!($refused, len == N, "refuses it with a byte after it");
                }
                Err(_) => panic!("unexpected error kind"),
            }
        }
    };
}

fn same_limbs(a: &[u64], b: &[u64]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

uint!(
    kani_p9_uint_14,
    14,
    1,
    2,
    12,
    (1 << 14) - 1,
    0xC0,
    spare_bits
);
uint!(kani_p9_uint_72, 72, 2, 9, 13, 0xFF, 0x00, never);
uint!(kani_p9_uint_256, 256, 4, 32, 36, u64::MAX, 0x00, never);

/// The 14-bit width does refuse an input: the other two widths end on a byte boundary.
#[kani::proof]
#[kani::unwind(12)]
fn kani_p9_uint_14_refuses_spare_bits() {
    let bytes: [u8; 2] = kani::any();
    let result = Uint::<14, 1>::read(&mut Copying(&bytes[..]));
    // Item 7: "Decoding refuses an encoding with a bit set beyond the width".
    assert!(result.is_err() == (bytes[0] & 0xC0 != 0));

    kani::cover!(result.is_err(), "refuses a bit beyond the width");
    kani::cover!(result.is_ok(), "accepts a value inside the width");
}
