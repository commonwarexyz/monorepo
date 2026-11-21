//! P2: every integer round-trips through its varint encoding, at the minimal length.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! This proof has no consistency-only assertions.
//!
//! - codec/src/varint.rs:5-8: protobuf varints, 7 value bits per byte plus a continuation bit.
//! - codec/src/varint.rs:501-505: `size` is "the number of bytes needed to encode" a value.
//! - codec/src/varint.rs:57-71: `MAX_U*_VARINT_SIZE` is the maximum encoded size.
//! - codec/src/varint.rs:244-246: signed values use ZigZag, which "moves the sign bit to the
//!   least significant bit", so values close to zero stay short.
//! - codec/src/codec.rs:39: `encode_size` "Returns the encoded size of this value (in bytes)".
//! - codec/src/codec.rs:220-228, on `Read::read_cfg`: "Implementations should consume the exact
//!   number of bytes required from `buf` to reconstruct the value"; "Parsing a message (often
//!   untrusted) should never result in a panic."
//!
//! # What is proven
//!
//! For EVERY value `x` of the type (all 2^16, 2^32, 2^64 or 2^128 of them):
//!
//! 1. `UInt(x).write` does not panic and writes at most `MAX` bytes;
//! 2. it writes exactly `UInt(x).encode_size()` bytes;
//! 3. that count is minimal: `x` fits in `7 * size` bits and (for `size > 1`) not in
//!    `7 * (size - 1)` bits;
//! 4. `UInt::read` on the written bytes returns `x` and consumes all of them.
//!
//! Signed: the same 1, 2 and 4 for `SInt(x)`, and
//!
//! 5. the bytes of `SInt(x)` decode, as an unsigned varint, to the ZigZag value of `x` computed
//!    by an independent definition (`2x` for `x >= 0`, `2|x| - 1` for `x < 0`).
//!
//! With P1 (every accepted string re-encodes to itself) this gives a bijection between values
//! and accepted strings.
//!
//! # Bounds
//!
//! None on the value. Loops are unwound `MAX + 2` times. `usize` is 64 bits.

use crate::common::write_into;
use bytes::Buf as _;
use commonware_codec::{
    Copying, EncodeSize, ReadExt,
    varint::{SInt, UInt},
};

macro_rules! roundtrip_unsigned {
    ($name:ident, $ty:ty, $max:expr, $unwind:expr) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            const MAX: usize = $max;
            let value: $ty = kani::any();

            // 1. `write_into` panics if the encoding does not fit in MAX bytes.
            let mut out = [0u8; MAX];
            let written = write_into(&UInt(value), &mut out);

            // 2. The size function is exact.
            let size = UInt(value).encode_size();
            assert!(written == size);

            // 3. The size is minimal. `7 * MAX >= BITS`, so the upper check is only needed (and
            // only shifts in range) below MAX.
            assert!(size >= 1 && size <= MAX);
            assert!(size == MAX || value >> (7 * size) == 0);
            assert!(size == 1 || value >> (7 * (size - 1)) != 0);

            // 4. Decoding gives the value back and consumes everything.
            let mut buf = Copying(&out[..written]);
            let decoded = UInt::<$ty>::read(&mut buf);
            assert!(matches!(decoded, Ok(UInt(v)) if v == value));
            assert!(buf.remaining() == 0);

            kani::cover!(size == 1, "one-byte value");
            kani::cover!(size == 2, "two-byte value");
            kani::cover!(size == MAX, "value of maximum length");
            kani::cover!(value == <$ty>::MAX, "largest value");
            kani::cover!(value == 127, "largest one-byte value");
            kani::cover!(value == 128, "smallest two-byte value");
        }
    };
}

roundtrip_unsigned!(kani_p2_roundtrip_u16, u16, 3, 5);
roundtrip_unsigned!(kani_p2_roundtrip_u32, u32, 5, 7);
roundtrip_unsigned!(kani_p2_roundtrip_u64, u64, 10, 12);
roundtrip_unsigned!(kani_p2_roundtrip_u128, u128, 19, 21);

macro_rules! roundtrip_signed {
    ($name:ident, $sty:ty, $uty:ty, $max:expr, $unwind:expr) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            const MAX: usize = $max;
            let value: $sty = kani::any();

            // 1. Fits in MAX bytes.
            let mut out = [0u8; MAX];
            let written = write_into(&SInt(value), &mut out);

            // 2. The size function is exact.
            let size = SInt(value).encode_size();
            assert!(written == size);
            assert!(size >= 1 && size <= MAX);

            // 4. Decoding gives the value back and consumes everything.
            let mut buf = Copying(&out[..written]);
            let decoded = SInt::<$sty>::read(&mut buf);
            assert!(matches!(decoded, Ok(SInt(v)) if v == value));
            assert!(buf.remaining() == 0);

            // 5. The wire bytes are the unsigned varint of the ZigZag value. This definition
            // does not use the codec's shift-and-xor form. Neither branch can overflow:
            // `2 * MAX_SIGNED` and `2 * MAX_SIGNED + 1` fit the unsigned type.
            let zigzag: $uty = if value >= 0 {
                (value as $uty) * 2
            } else {
                ((-(value + 1)) as $uty) * 2 + 1
            };
            let mut buf = Copying(&out[..written]);
            let unsigned = UInt::<$uty>::read(&mut buf);
            assert!(matches!(unsigned, Ok(UInt(u)) if u == zigzag));

            // Values close to zero stay in one byte, on both sides of zero.
            assert!((size == 1) == (value >= -64 && value <= 63));

            kani::cover!(value == 0, "zero");
            kani::cover!(value == -1, "minus one");
            kani::cover!(value == <$sty>::MIN, "smallest value");
            kani::cover!(value == <$sty>::MAX, "largest value");
            kani::cover!(size == MAX && value < 0, "negative value of maximum length");
            kani::cover!(size == MAX && value > 0, "positive value of maximum length");
        }
    };
}

roundtrip_signed!(kani_p2_roundtrip_i16, i16, u16, 3, 5);
roundtrip_signed!(kani_p2_roundtrip_i32, i32, u32, 5, 7);
roundtrip_signed!(kani_p2_roundtrip_i64, i64, u64, 10, 12);
roundtrip_signed!(kani_p2_roundtrip_i128, i128, u128, 19, 21);
