//! P1: the varint decoder is total and accepts only canonical encodings.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! For EVERY byte string of length `0..=MAX+1` (`MAX` = the type's maximum varint size),
//! `UInt::<T>::read`:
//!
//! 1. does not panic. codec/src/codec.rs, `Read::read_cfg`: "Parsing a message (often
//!    untrusted) should never result in a panic."
//! 2. fails only with `EndOfBuffer` or `InvalidVarint` (any payload).
//!    codec/src/codec.rs, `Read::read_cfg`: "Implementations must return [Error] if decoding
//!    fails due to invalid data, insufficient bytes in the buffer". codec/src/varint.rs, the
//!    private `read`: "Returns an error if: - The varint is invalid (too long or malformed) -
//!    The buffer ends while reading". The two kinds: codec/src/error.rs, `Error::EndOfBuffer`
//!    and `Error::InvalidVarint`.
//! 3. on `Ok(v)` has read exactly the bytes `UInt(v).write` produces.
//!    codec/src/varint.rs, a comment in `Decoder::feed`: "we ensure that every value has
//!    exactly one unique, valid encoding".
//! 4. on `Ok(v)` has read exactly `UInt(v).encode_size()` bytes.
//!    codec/src/codec.rs, `Read::read_cfg`: "Implementations should consume the exact number
//!    of bytes required from `buf` to reconstruct the value"; codec/src/codec.rs,
//!    `EncodeSize::encode_size`: "Returns the encoded size of this value (in bytes)".
//! 5. returns `EndOfBuffer` only when no byte of the input ends a varint (every byte has the
//!    continuation bit). codec/src/error.rs, `Error::EndOfBuffer`: "Indicates that the input
//!    buffer (`Buf`) did not contain enough bytes to read the next piece of data".
//!    codec/src/varint.rs, `CONTINUATION_BIT_MASK`: "If this bit is set, the varint
//!    continues, if clear this is the final byte."
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! Stronger than the docs above. A valid change of the implementation could break these.
//!
//! - at most `MAX` bytes are read on every path, also on an error (the docs bound the size
//!   of an encoding, codec/src/varint.rs, `MAX_U16_VARINT_SIZE` to `MAX_U128_VARINT_SIZE`,
//!   not the cursor after a failure);
//! - on `EndOfBuffer` the whole input was read and it is shorter than `MAX`;
//! - `InvalidVarint` carries `size_of::<T>()`, and at least one byte was read.
//!
//! # Bounds
//!
//! Input length `<= MAX + 1` bytes: 4 (u16), 6 (u32), 11 (u64), 20 (u128). With the
//! consistency checks on, the proof shows the decoder never reads past `MAX` bytes, so longer
//! inputs add nothing. Loops are unwound `MAX + 2` times; Kani's unwinding assertions prove
//! that is enough. `usize` is 64 bits (Kani verifies for the host target).

use crate::common::{CONT, consistency, write_into};
use bytes::Buf as _;
use commonware_codec::{Copying, EncodeSize, Error, ReadExt, varint::UInt};

macro_rules! decode_total_and_canonical {
    ($name:ident, $ty:ty, $max:expr, $unwind:expr) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            const MAX: usize = $max;
            const N: usize = MAX + 1;
            let bytes: [u8; N] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= N);
            let input = &bytes[..len];

            // Contract 1: this call must not panic.
            let mut buf = Copying(input);
            let result = UInt::<$ty>::read(&mut buf);
            let consumed = len - buf.remaining();

            consistency!(consumed <= MAX);

            match result {
                Ok(UInt(value)) => {
                    // Contract 3 and 4: re-encoding gives back exactly the bytes read.
                    let mut out = [0u8; MAX];
                    let written = write_into(&UInt(value), &mut out);
                    assert!(written == consumed);
                    assert!(UInt(value).encode_size() == consumed);
                    let mut i = 0;
                    while i < consumed {
                        assert!(out[i] == input[i]);
                        i += 1;
                    }

                    kani::cover!(consumed == 1, "accepts a one-byte varint");
                    kani::cover!(consumed == MAX, "accepts a varint of maximum length");
                    kani::cover!(value == <$ty>::MAX, "accepts the largest value");
                    kani::cover!(consumed < len, "accepts with bytes left in the buffer");
                }
                Err(Error::EndOfBuffer) => {
                    // Contract 5: the bytes ran out inside the varint.
                    let mut i = 0;
                    while i < len {
                        assert!(input[i] & CONT != 0);
                        i += 1;
                    }

                    consistency!(consumed == len);
                    consistency!(len < MAX);

                    kani::cover!(len == 0, "empty input ends the buffer");
                    kani::cover!(len == MAX - 1, "longest prefix that still asks for more");
                }
                Err(Error::InvalidVarint(size)) => {
                    consistency!(size == core::mem::size_of::<$ty>());
                    consistency!(consumed >= 1);

                    kani::cover!(
                        consumed >= 2 && input[consumed - 1] == 0,
                        "rejects a non-canonical trailing zero byte"
                    );
                    kani::cover!(
                        consumed == MAX && input[consumed - 1] & CONT == 0,
                        "rejects a last byte whose data bits overflow the type"
                    );
                    kani::cover!(
                        consumed == MAX && input[consumed - 1] & CONT != 0,
                        "rejects a continuation bit on the last possible byte"
                    );
                }
                // Contract 2: no other failure.
                Err(_) => panic!("unexpected error kind"),
            }
        }
    };
}

decode_total_and_canonical!(kani_p1_decode_u16, u16, 3, 5);
decode_total_and_canonical!(kani_p1_decode_u32, u32, 5, 7);
decode_total_and_canonical!(kani_p1_decode_u64, u64, 10, 12);
decode_total_and_canonical!(kani_p1_decode_u128, u128, 19, 21);

/// The `MAX` literals above are the codec's own constants.
#[kani::proof]
fn kani_p1_max_sizes_match_codec() {
    use commonware_codec::varint::{
        MAX_U16_VARINT_SIZE, MAX_U32_VARINT_SIZE, MAX_U64_VARINT_SIZE, MAX_U128_VARINT_SIZE,
    };
    assert!(MAX_U16_VARINT_SIZE == 3);
    assert!(MAX_U32_VARINT_SIZE == 5);
    assert!(MAX_U64_VARINT_SIZE == 10);
    assert!(MAX_U128_VARINT_SIZE == 19);
}
