//! P6: the varint decoders on a width that is a multiple of 7 bits.
//!
//! # Why this exists
//!
//! P1-P3 instantiate the generic decoder at 16, 32, 64 and 128 bits. None of these is a
//! multiple of 7, so the branch `remaining_bits <= DATA_BITS_PER_BYTE` (varint.rs:138) is
//! never taken with exactly 7 bits left. The codec also offers varints over
//! `Uint<BITS, LIMBS>` of any width (varint.rs:14, :216). At 14 bits the last byte has
//! exactly 7 bits left, so these proofs reach the boundary the primitive widths cannot.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_p6_decode_uint14`: items 1 to 5 of P1 (see `p1_varint_decode.rs` for the quotes), for
//! `UInt<Uint<14, 1>>`, whose maximum length is `MAX_ENCODE_SIZE = 14.div_ceil(7) = 2`
//! (varint.rs:366-372). It adds: on `Ok(v)` the value is below 2^14 (uint.rs:10: "An unsigned
//! integer of `BITS` bits").
//!
//! `kani_p6_stream_uint14`: items 1 to 4 of P3 (see `p3_stream_decoder.rs` for the quotes), for
//! `Decoder::<Uint<14, 1>>`: no panic, more bytes only after a continuation byte, a failure
//! is `InvalidVarint`, and it stops within 2 bytes.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! The same extra checks as P1: at most 2 bytes read on every path; on `EndOfBuffer` the
//! whole input was read and it is shorter than 2 bytes; `InvalidVarint` carries 2.
//!
//! # Bounds
//!
//! One width (14 bits, one limb). Other widths are not covered. Inputs up to 3 bytes.

use crate::common::{CONT, consistency, write_into};
use bytes::Buf as _;
use commonware_codec::{
    Copying, EncodeSize, Error, MaxEncodeSize, ReadExt, Uint,
    varint::{Decoder, UInt},
};

type U14 = Uint<14, 1>;

const MAX: usize = 2;
const N: usize = MAX + 1;

#[kani::proof]
#[kani::unwind(6)]
fn kani_p6_decode_uint14() {
    assert!(UInt::<U14>::MAX_ENCODE_SIZE == MAX);

    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let input = &bytes[..len];

    // Contract 1: this call must not panic.
    let mut buf = Copying(input);
    let result = UInt::<U14>::read(&mut buf);
    let consumed = len - buf.remaining();
    consistency!(consumed <= MAX);

    match result {
        Ok(UInt(value)) => {
            let low = value.as_limbs()[0];
            assert!(low < (1 << 14));

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
            kani::cover!(low == (1 << 14) - 1, "accepts the largest value");
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

            kani::cover!(len == MAX - 1, "longest prefix that still asks for more");
        }
        Err(Error::InvalidVarint(size)) => {
            consistency!(size == 2);

            kani::cover!(
                consumed == MAX && input[consumed - 1] & CONT != 0,
                "rejects a continuation bit on the last possible byte"
            );
            kani::cover!(
                consumed == MAX && input[consumed - 1] == 0,
                "rejects a non-canonical trailing zero byte"
            );
        }
        // Contract 2: no other failure.
        Err(_) => panic!("unexpected error kind"),
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn kani_p6_stream_uint14() {
    let bytes: [u8; N] = kani::any();

    let mut decoder = Decoder::<U14>::new();
    let mut finished = false;
    let mut accepted = false;
    let mut fed = 0;
    while fed < N {
        let byte = bytes[fed];
        fed += 1;
        // Contract 1: this call must not panic.
        match decoder.feed(byte) {
            Ok(None) => {
                // Contract 2: asks for more only after a continuation byte.
                assert!(byte & CONT != 0);
            }
            Ok(Some(_)) => {
                finished = true;
                accepted = true;
                break;
            }
            Err(e) => {
                // Contract 3: a failure is `InvalidVarint`.
                assert!(matches!(e, Error::InvalidVarint(_)));
                finished = true;
                break;
            }
        }
    }

    // Contract 4: stops within MAX bytes.
    assert!(finished);
    assert!(fed <= MAX);

    kani::cover!(accepted && fed == 1, "completes on the first byte");
    kani::cover!(
        accepted && fed == MAX,
        "completes on the last possible byte"
    );
    kani::cover!(
        !accepted && fed == MAX && bytes[MAX - 1] & CONT != 0,
        "rejects a continuation bit with exactly 7 bits left"
    );
}
