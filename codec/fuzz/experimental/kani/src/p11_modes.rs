//! P11: a `Modes` packet has one encoding, of the size `encode_size` gives, and decoding
//! accepts nothing else.
//!
//! A `Modes<N>` packet holds up to `N` seven-bit values, one byte each. It is the one type
//! of codec/src/mode.rs with an encoding.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! 1. A mode is a seven-bit value. codec/src/mode.rs, `Mode`: "A seven-bit value in an
//!    ordered [`Modes`] packet." "The high bit is reserved for packet framing and cannot be
//!    represented by this type." codec/src/mode.rs, `Mode::new`: "Creates a mode value, or
//!    returns `None` when the reserved high bit is set."
//! 2. The packet. codec/src/mode.rs, `Modes`: "A canonical packet of ordered mode values."
//!    "`N` is the maximum number of modes and must be greater than zero." "The high bit
//!    indicates that another mode follows, and trailing zero-valued modes are omitted.
//!    Appending a new mode with value zero therefore preserves the existing encoding. A
//!    `Modes` value denotes a present packet. An all-zero list denotes no packet."
//! 3. No packet for a list of zeros. codec/src/mode.rs, `Modes::new`: "Returns `None` when
//!    every mode is zero."
//! 4. Decoding does not panic, a failure is an error, and an accepted input is read to the
//!    end of the value and no further. codec/src/codec.rs, `Read::read_cfg`:
//!    "Implementations should consume the exact number of bytes required from `buf` to
//!    reconstruct the value." "Implementations must return [Error] if decoding fails due to
//!    invalid data, insufficient bytes in the buffer" and "Parsing a message (often
//!    untrusted) should never result in a panic."
//! 5. `encode_size` is the number of bytes written. codec/src/codec.rs,
//!    `EncodeSize::encode_size`: "Returns the encoded size of this value (in bytes)."
//! 6. A written value decodes to itself. codec/src/mode.rs, `Modes`, its example:
//!    "assert_eq!(encoded.as_ref(), &[0x81, 0x80, 0x02]);" and
//!    "assert_eq!(Modes::<3>::decode(encoded).unwrap(), modes);".
//!
//! From the crate's own tests, not from API documentation. The documentation does not name
//! the error of each malformed packet:
//!
//! 7. An input whose every byte asks for another byte fails with `EndOfBuffer` while fewer
//!    than `N` bytes were given, and with `Error::Invalid` once `N` bytes were given.
//!    codec/src/mode.rs, the test `rejects_truncated_and_oversized_packets`, for example
//!    "Modes::<2>::decode(Copying(&[0x80]))," with "Err(Error::EndOfBuffer)", and an
//!    `Error::Invalid` named `Modes` from "Modes::<2>::decode(Copying(&[0x80, 0x80])),".
//! 8. A packet that ends in a zero byte fails with `Error::Invalid`.
//!    codec/src/mode.rs, the test `rejects_non_canonical_packets`, for example
//!    an `Error::Invalid` named `Modes` from "Modes::<2>::decode(Copying(&[0x81, 0x00])),".
//!
//! # What is proven
//!
//! `kani_p11_mode_new` (item 1), for EVERY byte: `Mode::new` and `Mode::try_from` accept it
//! exactly when its high bit is clear, and the mode gives the byte back.
//!
//! `kani_p11_modes_1` and `kani_p11_modes_3`, for `N` = 1 and 3. For EVERY list of `N`
//! modes: `Modes::new` gives `None` exactly when all are zero (item 3). Otherwise `write`
//! writes exactly `encode_size()` bytes, which is the position of the last non-zero mode
//! (item 2: trailing zeros are omitted), at most `N`; every byte but the last is its mode
//! with the high bit set, the last is its mode with the high bit clear; `read` and `decode`
//! give the packet back (item 6). For EVERY byte string of length `0..=N+1`: `read` does not
//! panic, and
//!
//! - `Ok(packet)` only when one of the first `N` bytes has a clear high bit and the first
//!   such byte is not zero; exactly the bytes up to it were read, and `write` gives the
//!   same bytes back;
//! - `Err(EndOfBuffer)` only when every byte has the high bit set and fewer than `N` bytes
//!   were given (item 7);
//! - `Err(Invalid)` only when the first byte with a clear high bit is zero (item 8), or the
//!   first `N` bytes all have the high bit set (item 7);
//! - no other error.
//!
//! `kani_p11_modes_append` (item 2), for EVERY list of 2 modes: the list and the list with
//! one more zero mode give the same bytes, or both give no packet; and the bytes of the
//! 2-mode packet decode as a 3-mode packet.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! None. Every assertion rests on an item above.
//!
//! # Bounds
//!
//! `N` = 1 and 3 (and 2 against 3 for the appended mode): other sizes are not covered.
//! Inputs up to `N + 1` bytes. Loops are unwound up to 8 times. `usize` is 64 bits.

use crate::common::{CONT, same_bytes, write_into};
use bytes::Buf as _;
use commonware_codec::{Copying, DecodeExt, EncodeSize, Error, Mode, Modes, ReadExt};

/// Item 1.
#[kani::proof]
fn kani_p11_mode_new() {
    let byte: u8 = kani::any();
    let mode = Mode::new(byte);
    assert!(mode.is_some() == (byte & CONT == 0));
    assert!(Mode::try_from(byte).is_ok() == mode.is_some());
    if let Some(mode) = mode {
        assert!(u8::from(mode) == byte);
        assert!(Mode::try_from(byte) == Ok(mode));
    }

    kani::cover!(byte == 0x7f, "the largest mode");
    kani::cover!(byte == CONT, "the smallest byte that is no mode");
}

/// Every mode.
fn any_mode() -> (u8, Mode) {
    let byte: u8 = kani::any();
    kani::assume(byte & CONT == 0);
    (byte, Mode::new(byte).unwrap())
}

macro_rules! modes {
    ($name:ident, $count:expr) => {
        #[kani::proof]
        #[kani::unwind(8)]
        fn $name() {
            const COUNT: usize = $count;
            const N: usize = COUNT + 1;

            // From a list of modes. `raw[i]` is the byte of mode `i`.
            let mut raw = [0u8; COUNT];
            let modes: [Mode; COUNT] = core::array::from_fn(|i| {
                let (byte, mode) = any_mode();
                raw[i] = byte;
                mode
            });

            // The number of modes up to the last one that is not zero.
            let mut used = 0;
            let mut i = 0;
            while i < COUNT {
                if raw[i] != 0 {
                    used = i + 1;
                }
                i += 1;
            }

            match Modes::<COUNT>::new(modes) {
                // Item 3.
                None => {
                    assert!(used == 0);
                }
                Some(packet) => {
                    assert!(used > 0);

                    // Items 2 and 5. `write_into` panics if more than COUNT bytes are
                    // written.
                    let mut out = [0u8; COUNT];
                    let written = write_into(&packet, &mut out);
                    assert!(written == packet.encode_size());
                    assert!(written == used);

                    // Item 2: the high bit says that another mode follows.
                    let mut i = 0;
                    while i < used {
                        let expected = if i + 1 < used { raw[i] | CONT } else { raw[i] };
                        assert!(out[i] == expected);
                        i += 1;
                    }

                    // Items 4 and 6.
                    let mut buf = Copying(&out[..written]);
                    let decoded = Modes::<COUNT>::read(&mut buf);
                    assert!(matches!(decoded, Ok(v) if v == packet));
                    assert!(buf.remaining() == 0);
                    let decoded = Modes::<COUNT>::decode(Copying(&out[..written]));
                    assert!(matches!(decoded, Ok(v) if v == packet));

                    kani::cover!(used == 1, "a packet of one byte");
                    kani::cover!(used == COUNT, "a packet of the maximum size");
                }
            }
            kani::cover!(used == 0, "no packet for a list of zeros");

            // From any bytes. Item 4: this call must not panic.
            let bytes: [u8; N] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= N);
            let input = &bytes[..len];
            let mut buf = Copying(input);
            let result = Modes::<COUNT>::read(&mut buf);
            let consumed = len - buf.remaining();

            // The first byte with a clear high bit among the first COUNT bytes: `end` is its
            // position, or `limit` when there is none.
            let limit = if len < COUNT { len } else { COUNT };
            let mut end = limit;
            let mut i = 0;
            while i < limit {
                if input[i] & CONT == 0 {
                    end = i;
                    break;
                }
                i += 1;
            }

            match result {
                Ok(packet) => {
                    // Items 2 and 4: the packet ends at that byte, which is not zero.
                    assert!(end < limit && input[end] != 0);
                    assert!(consumed == end + 1);
                    assert!(packet.encode_size() == consumed);

                    // Writing it gives the same bytes back.
                    let mut out = [0u8; COUNT];
                    let written = write_into(&packet, &mut out);
                    assert!(same_bytes(&out[..written], &input[..consumed]));

                    kani::cover!(consumed == 1, "accepts a packet of one byte");
                    kani::cover!(consumed == COUNT, "accepts a packet of the maximum size");
                    kani::cover!(consumed < len, "accepts with a byte left in the buffer");
                }
                Err(Error::EndOfBuffer) => {
                    // Item 7: every byte asks for another one, and there is room for it.
                    assert!(end == limit && len < COUNT);

                    kani::cover!(len == 0, "empty input ends the buffer");
                    kani::cover!(len == COUNT - 1, "one byte short of the maximum");
                }
                Err(Error::Invalid(_, _)) => {
                    // Item 8: a zero byte ends the packet. Item 7: no byte ends it.
                    assert!((end < limit && input[end] == 0) || (end == limit && len >= COUNT));

                    kani::cover!(end < limit, "rejects a packet that ends in zero");
                    kani::cover!(end == limit, "rejects more modes than the maximum");
                }
                Err(_) => panic!("unexpected error kind"),
            }
        }
    };
}

modes!(kani_p11_modes_1, 1);
modes!(kani_p11_modes_3, 3);

/// Item 2, codec/src/mode.rs, `Modes`: "Appending a new mode with value zero therefore
/// preserves the existing encoding."
#[kani::proof]
#[kani::unwind(8)]
fn kani_p11_modes_append() {
    let (_, first) = any_mode();
    let (_, second) = any_mode();
    let (_, zero) = any_mode();
    kani::assume(u8::from(zero) == 0);

    let short = Modes::<2>::new([first, second]);
    let long = Modes::<3>::new([first, second, zero]);

    match (short, long) {
        (None, None) => {
            kani::cover!(u8::from(second) == 0, "no packet for two zero modes");
        }
        (Some(short), Some(long)) => {
            let mut short_bytes = [0u8; 2];
            let short_len = write_into(&short, &mut short_bytes);
            let mut long_bytes = [0u8; 3];
            let long_len = write_into(&long, &mut long_bytes);
            assert!(same_bytes(
                &short_bytes[..short_len],
                &long_bytes[..long_len]
            ));

            // A reader that knows one more mode reads the old packet.
            let decoded = Modes::<3>::decode(Copying(&short_bytes[..short_len]));
            assert!(matches!(decoded, Ok(v) if v == long));

            kani::cover!(short_len == 1, "a packet of one byte");
            kani::cover!(short_len == 2, "a packet of two bytes");
        }
        _ => panic!("the appended zero changed whether there is a packet"),
    }
}
