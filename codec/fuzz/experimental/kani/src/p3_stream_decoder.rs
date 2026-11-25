//! P3: the byte-at-a-time decoder finishes within the maximum length.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! For EVERY sequence of `MAX + 1` bytes fed to a fresh `Decoder::<T>` until it stops asking:
//!
//! 1. `feed` does not panic. codec/src/varint.rs, `Decoder`: it is "for reading varints
//!    byte-by-byte from streams"; codec/src/codec.rs, `Read::read_cfg`: "Parsing a message
//!    (often untrusted) should never result in a panic."
//! 2. it asks for more (`Ok(None)`) only after a byte with the continuation bit.
//!    codec/src/varint.rs, `Decoder::feed`: "`Ok(None)` when more bytes are needed";
//!    codec/src/varint.rs, `CONTINUATION_BIT_MASK`: "If this bit is set, the varint
//!    continues, if clear this is the final byte."
//! 3. a failure is `InvalidVarint` (any payload). codec/src/varint.rs, `Decoder::feed`:
//!    "`Err(InvalidVarint)` if the varint is malformed (overflow or invalid encoding)".
//! 4. it stops (a value or an error) at or before byte number `MAX`.
//!    codec/src/varint.rs, `MAX_U16_VARINT_SIZE` to `MAX_U128_VARINT_SIZE`: the "Maximum
//!    encoded size", so a varint that still continues at byte `MAX` is malformed, and item 3
//!    makes that an error. The implementation states the intent in a comment in
//!    codec/src/varint.rs, `Decoder::feed`: the last-byte check "prevents continuing to read".
//!    (That third source is a comment in the code, not API documentation.)
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - the result equals what `UInt::<T>::read` returns for the same bytes: the same value, or
//!   the same `InvalidVarint` width. The docs do not state this.
//!
//! # Limits
//!
//! - The contract part says nothing about the VALUE `feed` returns. P1 checks values, through
//!   `UInt::read`.
//! - The consistency check is not an independent oracle: `UInt::read` calls the same
//!   `Decoder::feed` for every multi-byte varint (codec/src/varint.rs, the private `read`). A
//!   wrong rule shared by both passes it.
//!
//! # Bounds
//!
//! `MAX + 1` bytes per type (4, 6, 11, 20). The decoder is used once, from `new()`: feeding a
//! decoder again after it returned a value or an error is not covered (the docs do not define
//! it). Loops are unwound `MAX + 3` times. `usize` is 64 bits.

use crate::common::CONT;
use commonware_codec::{
    Copying, Error, ReadExt,
    varint::{Decoder, UInt},
};

macro_rules! stream_decoder {
    ($name:ident, $ty:ty, $max:expr, $unwind:expr) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            const MAX: usize = $max;
            const N: usize = MAX + 1;
            let bytes: [u8; N] = kani::any();

            let mut decoder = Decoder::<$ty>::new();
            let mut outcome: Option<Result<$ty, Error>> = None;
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
                    Ok(Some(value)) => {
                        outcome = Some(Ok(value));
                        break;
                    }
                    Err(e) => {
                        // Contract 3: a failure is `InvalidVarint`.
                        assert!(matches!(e, Error::InvalidVarint(_)));
                        outcome = Some(Err(e));
                        break;
                    }
                }
            }

            // Contract 4: stops within MAX bytes.
            assert!(outcome.is_some());
            assert!(fed <= MAX);

            match &outcome {
                Some(Ok(_)) => {
                    kani::cover!(fed == 1, "completes on the first byte");
                    kani::cover!(fed == MAX, "completes on the last possible byte");
                }
                _ => {
                    kani::cover!(fed == 2, "rejects on the second byte");
                    kani::cover!(fed == MAX, "rejects on the last possible byte");
                }
            }

            // Consistency: agrees with the buffer reader on the same bytes.
            if cfg!(feature = "consistency") {
                let mut buf = Copying(&bytes[..]);
                let read = UInt::<$ty>::read(&mut buf);
                match (outcome, read) {
                    (Some(Ok(a)), Ok(UInt(b))) => {
                        assert!(a == b);
                    }
                    (Some(Err(Error::InvalidVarint(a))), Err(Error::InvalidVarint(b))) => {
                        assert!(a == b);
                    }
                    _ => panic!("the stream decoder and the buffer reader disagree"),
                }
            }
        }
    };
}

stream_decoder!(kani_p3_stream_u16, u16, 3, 6);
stream_decoder!(kani_p3_stream_u32, u32, 5, 8);
stream_decoder!(kani_p3_stream_u64, u64, 10, 13);
stream_decoder!(kani_p3_stream_u128, u128, 19, 22);
