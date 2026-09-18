#![doc(hidden)]

//! Implementation of the [`crate::hex!`] macro.
//!
//! Modified from the [`hex-literal`](https://github.com/RustCrypto/utils/tree/master/hex-literal)
//! crate to allow `0x` prefixes.
//!
//! Vendored from [`alloy-primitives`](https://github.com/alloy-rs/core/tree/main/crates/primitives).
//!
//! This module is public only so that macro expansions can access it from downstream crates.
//! Callers must not invoke its functions directly. For accepted input, the macro maintains these
//! invariants:
//!
//! - Each literal has at most one leading `0x` or `0X` prefix removed.
//! - The decoded length is computed from the same prefix-free literals that are decoded.
//! - The computed length equals the number of bytes represented by those literals.

const fn next_hex_char(string: &[u8], mut pos: usize) -> Option<(u8, usize)> {
    while pos < string.len() {
        let raw_val = string[pos];
        pos += 1;
        let val = match raw_val {
            b'0'..=b'9' => raw_val - 48,
            b'A'..=b'F' => raw_val - 55,
            b'a'..=b'f' => raw_val - 87,
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            0..=127 => panic!("Encountered invalid ASCII character"),
            _ => panic!("Encountered non-ASCII character"),
        };
        return Some((val, pos));
    }
    None
}

const fn next_byte(string: &[u8], pos: usize) -> Option<(u8, usize)> {
    let (half1, pos) = match next_hex_char(string, pos) {
        Some(v) => v,
        None => return None,
    };
    let (half2, pos) = match next_hex_char(string, pos) {
        Some(v) => v,
        None => panic!("Odd number of hex characters"),
    };
    Some(((half1 << 4) + half2, pos))
}

/// Removes at most one leading `0x` or `0X` prefix from `string`.
///
/// All other input is returned unchanged. This function is an implementation detail and callers
/// must not invoke it directly.
#[doc(hidden)]
pub const fn strip_hex_prefix(string: &[u8]) -> &[u8] {
    if let [b'0', b'x' | b'X', rest @ ..] = string {
        rest
    } else {
        string
    }
}

/// Computes the number of bytes represented by `strings`.
///
/// Each string must be prefix-free and contain an even number of hexadecimal digits after spaces,
/// tabs, carriage returns, and newlines are ignored. This function is an implementation detail and
/// callers must not invoke it directly.
///
/// # Panics
///
/// Panics if a string contains anything other than a hexadecimal digit, space, tab, carriage
/// return, or newline, or if it contains an odd number of hexadecimal digits.
#[doc(hidden)]
pub const fn len(strings: &[&[u8]]) -> usize {
    let mut i = 0;
    let mut len = 0;
    while i < strings.len() {
        let mut pos = 0;
        while let Some((_, new_pos)) = next_byte(strings[i], pos) {
            len += 1;
            pos = new_pos;
        }
        i += 1;
    }
    len
}

/// Decodes `strings` into a byte array with a precomputed length.
///
/// `LEN` must equal [`len(strings)`](len). The [`crate::hex!`] macro guarantees this by computing
/// `LEN` from the same prefix-free strings passed to this function. This function is an
/// implementation detail and callers must not invoke it directly.
///
/// # Panics
///
/// Panics if a string contains anything other than a hexadecimal digit, space, tab, carriage
/// return, or newline, if it contains an odd number of hexadecimal digits, or if `LEN` differs from
/// the number of decoded bytes.
#[doc(hidden)]
pub const fn decode<const LEN: usize>(strings: &[&[u8]]) -> [u8; LEN] {
    let mut i = 0;
    let mut buf = [0u8; LEN];
    let mut buf_pos = 0;
    while i < strings.len() {
        let mut pos = 0;
        while let Some((byte, new_pos)) = next_byte(strings[i], pos) {
            buf[buf_pos] = byte;
            buf_pos += 1;
            pos = new_pos;
        }
        i += 1;
    }
    if LEN != buf_pos {
        panic!("Length mismatch. Please report this bug.");
    }
    buf
}

/// Converts string literals containing hexadecimal data into a byte array.
///
/// Each literal may begin with `0x` or `0X`; when present, the prefix must be its first two
/// characters. Spaces, tabs, carriage returns, and newlines are ignored. Each literal must contain
/// an even number of hexadecimal digits after its optional prefix and whitespace are removed.
///
/// The array length is computed from the same prefix-free literals that are decoded, so the output
/// contains exactly the bytes represented by the input.
///
/// # Examples
///
/// ```
/// use commonware_formatting::hex;
///
/// const BYTES: [u8; 4] = hex!("0x12 34" "0Xab cd");
/// assert_eq!(BYTES, [0x12, 0x34, 0xab, 0xcd]);
/// ```
#[macro_export]
macro_rules! hex {
    ($($s:literal)*) => {const {
        const STRINGS: &[&[u8]] = &[$( $crate::hex_literal::strip_hex_prefix($s.as_bytes()), )*];
        $crate::hex_literal::decode::<{ $crate::hex_literal::len(STRINGS) }>(STRINGS)
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn single_literal() {
        assert_eq!(hex!("ff e4"), [0xff, 0xe4]);
    }

    #[test]
    fn empty() {
        let nothing: [u8; 0] = hex!();
        let empty_literals: [u8; 0] = hex!("" "" "");
        let expected: [u8; 0] = [];
        assert_eq!(nothing, expected);
        assert_eq!(empty_literals, expected);
    }

    #[test]
    fn upper_case() {
        assert_eq!(hex!("AE DF 04 B2"), [0xae, 0xdf, 0x04, 0xb2]);
        assert_eq!(hex!("FF BA 8C 00 01"), [0xff, 0xba, 0x8c, 0x00, 0x01]);
    }

    #[test]
    fn mixed_case() {
        assert_eq!(hex!("bF dd E4 Cd"), [0xbf, 0xdd, 0xe4, 0xcd]);
    }

    #[test]
    fn optional_prefix() {
        assert_eq!(hex!("1a2b3c"), [0x1a, 0x2b, 0x3c]);
        assert_eq!(hex!("0x1a2b3c"), [0x1a, 0x2b, 0x3c]);
        assert_eq!(hex!("0X1a2b3c"), [0x1a, 0x2b, 0x3c]);
        assert_eq!(hex!("0xa1" "b2" "0Xc3"), [0xa1, 0xb2, 0xc3]);
    }

    #[test]
    fn strips_exactly_one_prefix() {
        assert_eq!(super::strip_hex_prefix(b"0x12"), b"12");
        assert_eq!(super::strip_hex_prefix(b"0X12"), b"12");
        assert_eq!(super::strip_hex_prefix(b"0x0X12"), b"0X12");
        assert_eq!(super::strip_hex_prefix(b"x012"), b"x012");
    }

    #[test]
    fn computed_length_matches_decoded_bytes() {
        const STRINGS: &[&[u8]] = &[
            super::strip_hex_prefix(b"0x12 34"),
            super::strip_hex_prefix(b"0Xab\ncd"),
        ];
        const LEN: usize = super::len(STRINGS);

        assert_eq!(LEN, 4);
        assert_eq!(super::decode::<LEN>(STRINGS), [0x12, 0x34, 0xab, 0xcd]);
    }

    #[test]
    fn multiple_literals() {
        assert_eq!(
            hex!(
                "01 dd f7 7f"
                "ee f0 d8"
            ),
            [0x01, 0xdd, 0xf7, 0x7f, 0xee, 0xf0, 0xd8]
        );
        assert_eq!(
            hex!(
                "ff"
                "e8 d0"
                ""
                "01 1f"
                "ab"
            ),
            [0xff, 0xe8, 0xd0, 0x01, 0x1f, 0xab]
        );
    }

    #[test]
    fn no_spacing() {
        assert_eq!(hex!("abf0d8bb0f14"), [0xab, 0xf0, 0xd8, 0xbb, 0x0f, 0x14]);
        assert_eq!(
            hex!("09FFd890cbcCd1d08F"),
            [0x09, 0xff, 0xd8, 0x90, 0xcb, 0xcc, 0xd1, 0xd0, 0x8f]
        );
    }

    #[test]
    fn allows_various_spacing() {
        // newlines
        assert_eq!(
            hex!(
                "f
                f
                d
                0
                e

                8
                "
            ),
            [0xff, 0xd0, 0xe8]
        );
        // tabs
        assert_eq!(hex!("9f	d		1		f07	3		01	"), [0x9f, 0xd1, 0xf0, 0x73, 0x01]);
        // spaces
        assert_eq!(hex!(" e    e d0  9 1   f  f  "), [0xee, 0xd0, 0x91, 0xff]);
    }

    #[test]
    const fn can_use_const() {
        const _: [u8; 4] = hex!("ff d3 01 7f");
    }
}

// https://github.com/alloy-rs/core/blob/main/LICENSE-MIT
//
// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
