//! `parse` splits a muxed message into the subchannel its prefix names and the rest.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! p2p/src/utils/mux.rs, `parse`: "Parse a muxed message into its subchannel and payload." The
//! layout, p2p/src/utils/mux.rs, module documentation: "subchannel (varint, 1-10) | payload".
//! `Channel` is `u64` (p2p/src/lib.rs, `Channel`).
//!
//! The varint is the one of `commonware_codec::varint`. Its rules, each with its source:
//!
//! - R1. Each byte holds 7 data bits and a continuation bit, the most significant one: set, the
//!   varint continues; clear, this is the final byte. codec/src/varint.rs, module documentation:
//!   "Google's Protocol Buffers variable-length integer encoding. Each byte uses: - 7 bits for
//!   the value - 1 "continuation" bit to indicate if more bytes follow" (a list in the original);
//!   codec/src/varint.rs, `CONTINUATION_BIT_MASK`: "If this bit is set, the varint continues, if
//!   clear this is the final byte."
//! - R2. The first byte holds the least significant 7 bits. codec/src/varint.rs, in the example of
//!   `Decoder`: "300 encodes as [0xAC, 0x02]"; the test `test_conformity` (codec/src/varint.rs):
//!   `128` encodes as `[0x80, 0x01]`.
//! - R3. A `u64` varint has at most 10 bytes. codec/src/varint.rs, `MAX_U64_VARINT_SIZE`, and
//!   the "1-10" of the layout above.
//! - R4. No byte after the first is zero: every value has one encoding. codec/src/varint.rs, a
//!   comment in `Decoder::feed`: "we ensure that every value has exactly one unique, valid
//!   encoding"; the test `test_zeroed_byte` (codec/src/varint.rs) refuses `[0xFF, 0x00]` as a
//!   `u64`.
//! - R5. The last possible byte holds no bit beyond the 64 of the value, which also refuses a
//!   continuation bit on it. codec/src/varint.rs, a comment in `Decoder::feed`: "If this must be
//!   the last byte, check for overflow (i.e. set bits beyond the size of T). Because the
//!   continuation bit is the most-significant bit, this check also happens to check for an invalid
//!   continuation bit."; the test `test_overflow` (codec/src/varint.rs) refuses nine `0x80` bytes
//!   followed by `0x02` as a `u64`.
//!
//! The harness carries its own decoder of these rules, `reference` below. It does not call
//! the codec: comparing `parse` with the decoder it is built on would test the code against
//! itself. For EVERY byte string of length `0..=N`:
//!
//! 1. `parse` does not panic. codec/src/codec.rs, on the `Read::read_cfg` that
//!    `parse` calls through `UInt::read`: "Parsing a message (often untrusted) should never
//!    result in a panic."
//! 2. It returns `Ok((c, rest))` exactly when `reference` accepts a prefix of `k` bytes
//!    with the value `c`, and then `rest` holds the input without those `k` bytes.
//! 3. It returns an error exactly when `reference` refuses the input: the input ends inside
//!    the varint, or the varint breaks R4 or R5.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - When the input ends inside the varint, the error is `EndOfBuffer`; when the varint breaks R4
//!   or R5, it is `InvalidVarint(8)`. `parse` documents no error kinds; these are the kinds of
//!   `UInt::read` (codec/src/varint.rs, the `read` that `UInt`'s `Read` calls) and the payload the
//!   codec's tests expect (codec/src/varint.rs, test `test_zeroed_byte`).
//!
//! # Bounds
//!
//! Input length `<= N = 12` bytes: the longest prefix and 2 bytes of payload. The reference
//! never reads past byte 10, so longer inputs only lengthen `rest`. Loops are unwound
//! `N + 2` times; Kani's unwinding assertions prove that is enough. `usize` is 64 bits.
//!
//! # Trusted
//!
//! `reference` is the trusted part of the proof. A planted bug in it (accepting a zero byte
//! after the first) makes this harness fail; the evidence is in the report of the build.

use crate::common::{consistency, same_bytes};
use commonware_codec::Error;
use commonware_p2p::utils::mux::parse;
use commonware_runtime::IoBuf;

/// The longest input the proof covers.
const N: usize = 12;

/// The continuation bit (R1).
const CONT: u8 = 0x80;

/// The longest `u64` varint (R3).
const MAX_PREFIX: usize = 10;

/// What the reference decoder makes of an input.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reference {
    /// A varint of `len` bytes with this value starts the input.
    Accept { value: u64, len: usize },
    /// The input ends before a byte without the continuation bit.
    Short,
    /// The varint breaks R4 or R5.
    Invalid,
}

/// Decodes a `u64` varint from the start of `input` by the rules R1 to R5 of the header.
fn reference(input: &[u8]) -> Reference {
    let mut value: u64 = 0;
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        // R4: no zero byte after the first.
        if i > 0 && byte == 0 {
            return Reference::Invalid;
        }
        // R5: the tenth byte may hold only bit 63 of the value (63 bits come before it), so
        // any value above 1 sets a bit beyond 64 or the continuation bit.
        if i == MAX_PREFIX - 1 && byte > 1 {
            return Reference::Invalid;
        }
        // R1 and R2: 7 data bits, least significant group first.
        value |= ((byte & !CONT) as u64) << (7 * i);
        if byte & CONT == 0 {
            return Reference::Accept { value, len: i + 1 };
        }
        i += 1;
    }
    Reference::Short
}

#[kani::proof]
#[kani::unwind(14)]
fn kani_mux_parse() {
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let input = &bytes[..len];

    let expected = reference(input);

    // Contract 1: this call must not panic.
    let result = parse(IoBuf::copy_from_slice(input));

    match result {
        Ok((channel, rest)) => {
            // Contract 2: the reference accepts the same prefix with the same value, and the
            // payload is the rest of the input.
            let Reference::Accept { value, len: k } = expected else {
                panic!("parse accepted an input the reference refuses");
            };
            assert!(channel == value);
            assert!(same_bytes(rest.as_ref(), &input[k..]));

            kani::cover!(k == 1, "accepts a one-byte prefix");
            kani::cover!(k == MAX_PREFIX, "accepts a prefix of maximum length");
            kani::cover!(channel == u64::MAX, "accepts the largest subchannel");
            kani::cover!(rest.is_empty(), "accepts a message with an empty payload");
            kani::cover!(rest.len() >= 2, "accepts a message with a payload");
        }
        Err(err) => {
            // Contract 3: the reference refuses the input too.
            assert!(expected == Reference::Short || expected == Reference::Invalid);
            match expected {
                Reference::Short => consistency!(matches!(err, Error::EndOfBuffer)),
                _ => consistency!(matches!(err, Error::InvalidVarint(8))),
            }

            kani::cover!(len == 0, "refuses an empty message");
            kani::cover!(
                expected == Reference::Short && len == MAX_PREFIX - 1,
                "refuses the longest prefix that still asks for more"
            );
            kani::cover!(
                len >= 2 && input[1] == 0,
                "refuses a zero byte after the first (R4)"
            );
            kani::cover!(
                len >= MAX_PREFIX && input[MAX_PREFIX - 1] > 1 && input[MAX_PREFIX - 1] & CONT == 0,
                "refuses a tenth byte with bits beyond 64 (R5)"
            );
            kani::cover!(
                len >= MAX_PREFIX && input[MAX_PREFIX - 1] & CONT != 0,
                "refuses a continuation bit on the tenth byte (R5)"
            );
        }
    }
}
