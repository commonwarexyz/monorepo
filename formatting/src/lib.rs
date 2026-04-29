//! Format and parse encoded data.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

// `pub mod hex_literal;` is declared at the crate root (rather than inside the
// `stability_scope!` block) so the `#[macro_export] macro_rules! hex` it
// contains can be referenced via absolute paths within this crate.
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
pub mod hex_literal;

commonware_macros::stability_scope!(BETA {
    extern crate alloc;

    use alloc::{string::String, vec::Vec};
    use core::fmt;

    /// Converts bytes to a lowercase hexadecimal [String].
    pub fn hex(bytes: &[u8]) -> String {
        const_hex::encode(bytes)
    }

    /// Converts a hexadecimal string to bytes.
    ///
    /// Returns [None] if the input has odd length, contains non-hex characters,
    /// or is otherwise malformed. Does not strip a leading `0x` / `0X` prefix
    /// or any whitespace; see [from_hex_formatted] for that.
    pub fn from_hex(s: &str) -> Option<Vec<u8>> {
        let bytes = s.as_bytes();
        if !bytes.len().is_multiple_of(2) {
            return None;
        }
        bytes
            .chunks_exact(2)
            .map(|chunk| {
                let hi = decode_hex_digit(chunk[0])?;
                let lo = decode_hex_digit(chunk[1])?;
                Some((hi << 4) | lo)
            })
            .collect()
    }

    /// Converts a hexadecimal string to bytes, stripping ASCII whitespace and an
    /// optional `0x` / `0X` prefix. Commonly used in tests to encode external test
    /// vectors without modification.
    pub fn from_hex_formatted(s: &str) -> Option<Vec<u8>> {
        let s = s.replace(['\t', '\n', '\r', ' '], "");
        let s = s.strip_prefix("0x").unwrap_or(&s);
        from_hex(s)
    }

    #[inline]
    const fn decode_hex_digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    /// Display/Debug wrapper that renders bytes as lowercase hex without
    /// allocating an intermediate [String].
    ///
    /// Use this in `Display` or `Debug` implementations to format a byte slice
    /// directly into the output `Formatter` via `const-hex`'s stack-allocated
    /// buffer. For owned conversion to [String], use [hex()] instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_formatting::Hex;
    ///
    /// struct Digest([u8; 32]);
    ///
    /// impl core::fmt::Display for Digest {
    ///     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    ///         write!(f, "{}", Hex(&self.0))
    ///     }
    /// }
    /// ```
    pub struct Hex<T: AsRef<[u8]>>(pub T);

    impl<T: AsRef<[u8]>> fmt::Display for Hex<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_hex(self.0.as_ref(), f)
        }
    }

    impl<T: AsRef<[u8]>> fmt::Debug for Hex<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_hex(self.0.as_ref(), f)
        }
    }

    /// Writes `bytes` to the formatter as lowercase hex without heap allocation.
    ///
    /// Uses a fixed-size stack buffer per chunk to avoid bounding the input
    /// length at compile time.
    fn write_hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Encode in chunks that fit in a stack buffer to support arbitrary input lengths.
        const CHUNK: usize = 64;
        let mut buf = [0u8; CHUNK * 2];
        for slice in bytes.chunks(CHUNK) {
            let out = &mut buf[..slice.len() * 2];
            const_hex::encode_to_slice(slice, out).expect("slice fits in buffer");
            // SAFETY: `encode_to_slice` writes only ASCII hex digits, which are valid UTF-8.
            let s = unsafe { core::str::from_utf8_unchecked(out) };
            f.write_str(s)?;
        }
        Ok(())
    }
});

#[cfg(test)]
mod tests {
    use crate::{from_hex, from_hex_formatted, Hex};

    #[test]
    fn test_hex() {
        // Empty bytes
        let b: &[u8] = &[];
        let h = crate::hex(b);
        assert_eq!(h, "");
        assert_eq!(from_hex(&h).unwrap(), b.to_vec());

        // Single byte
        let b: &[u8] = &[0x01];
        let h = crate::hex(b);
        assert_eq!(h, "01");
        assert_eq!(from_hex(&h).unwrap(), b.to_vec());

        // Multiple bytes
        let b: &[u8] = &[0x01, 0x02, 0x03];
        let h = crate::hex(b);
        assert_eq!(h, "010203");
        assert_eq!(from_hex(&h).unwrap(), b.to_vec());

        // Odd number of characters
        assert!(from_hex("0102030").is_none());

        // Invalid hex character
        assert!(from_hex("01g3").is_none());

        // Invalid `+`
        assert!(from_hex("+123").is_none());

        // Empty string
        assert_eq!(from_hex(""), Some(vec![]));

        // `0x` prefix is NOT stripped by from_hex.
        assert!(from_hex("0x010203").is_none());
    }

    #[test]
    fn test_from_hex_formatted() {
        let expected: Vec<u8> = vec![0x01, 0x02, 0x03];

        // No formatting
        assert_eq!(from_hex_formatted("010203").unwrap(), expected);

        // Whitespace
        assert_eq!(from_hex_formatted("01 02 03").unwrap(), expected);

        // 0x prefix
        assert_eq!(from_hex_formatted("0x010203").unwrap(), expected);

        // 0x prefix + mixed whitespace (tabs, newlines, spaces, carriage returns)
        let h = "    \n\n0x\r\n01
                            02\t03\n";
        assert_eq!(from_hex_formatted(h).unwrap(), expected);

        // Invalid character is still rejected
        assert!(from_hex_formatted("01g3").is_none());

        // Odd length is still rejected
        assert!(from_hex_formatted("0102030").is_none());
    }

    #[test]
    fn test_from_hex_utf8_char_boundaries() {
        // Ensure that `from_hex` handles misaligned UTF-8 character boundaries.
        const MISALIGNMENT_CASE: &str = "쀘\n";
        assert!(from_hex(MISALIGNMENT_CASE).is_none());
    }

    #[test]
    fn test_hex_newtype_display() {
        let bytes = [0x01u8, 0x02, 0xab, 0xcd];
        let s = format!("{}", Hex(&bytes[..]));
        assert_eq!(s, "0102abcd");

        // Owned input
        let v = bytes.to_vec();
        assert_eq!(format!("{}", Hex(v)), "0102abcd");

        // Empty
        assert_eq!(format!("{}", Hex::<&[u8]>(&[])), "");

        // Larger than the internal CHUNK to exercise the loop
        let big: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
        let formatted = format!("{}", Hex(&big));
        assert_eq!(formatted, super::hex(&big));
    }

    #[test]
    fn test_hex_newtype_debug() {
        let bytes = [0xff, 0x00];
        assert_eq!(format!("{:?}", Hex(&bytes[..])), "ff00");
    }
}
