//! Format and parse encoded data.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

// Declared at the crate root (rather than inside the `stability_scope!` block
// below) so the `#[macro_export] macro_rules! hex` it contains can be
// referenced via absolute paths within this crate.
commonware_macros::stability_mod!(BETA, pub mod hex_literal);

commonware_macros::stability_scope!(BETA {
    extern crate alloc;

    use alloc::{string::String, vec::Vec};
    use core::fmt;

    /// Converts bytes to a lowercase hexadecimal [String].
    pub fn hex(bytes: &[u8]) -> String {
        const_hex::encode(bytes)
    }

    /// Converts a hexadecimal string to bytes, stripping ASCII whitespace and an
    /// optional `0x` / `0X` prefix. Commonly used in tests to encode external test
    /// vectors without modification.
    pub fn from_hex(s: &str) -> Option<Vec<u8>> {
        let s = s.replace(['\t', '\n', '\r', ' '], "");
        // `const_hex::decode` only strips lowercase `0x`; handle uppercase ourselves.
        let stripped = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(&s);
        const_hex::decode(stripped).ok()
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

    impl<T: AsRef<[u8]>> From<T> for Hex<T> {
        fn from(value: T) -> Self {
            Self(value)
        }
    }

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
    use crate::{from_hex, Hex};

    #[test]
    fn test_hex_roundtrip() {
        for (bytes, encoded) in [
            (&[][..], ""),
            (&[0x01][..], "01"),
            (&[0x01, 0x02, 0x03][..], "010203"),
        ] {
            assert_eq!(crate::hex(bytes), encoded);
            assert_eq!(from_hex(encoded).unwrap(), bytes.to_vec());
        }
    }

    #[test]
    fn test_from_hex() {
        let expected: Vec<u8> = vec![0x01, 0x02, 0x03];

        // No formatting
        assert_eq!(from_hex("010203").unwrap(), expected);

        // Whitespace
        assert_eq!(from_hex("01 02 03").unwrap(), expected);

        // 0x prefix (lowercase)
        assert_eq!(from_hex("0x010203").unwrap(), expected);

        // 0X prefix (uppercase)
        assert_eq!(from_hex("0X010203").unwrap(), expected);

        // 0x prefix + mixed whitespace (tabs, newlines, spaces, carriage returns)
        let h = "    \n\n0x\r\n01
                            02\t03\n";
        assert_eq!(from_hex(h).unwrap(), expected);

        // Empty string
        assert_eq!(from_hex(""), Some(vec![]));

        // Odd length
        assert!(from_hex("0102030").is_none());

        // Invalid hex character
        assert!(from_hex("01g3").is_none());

        // Invalid `+`
        assert!(from_hex("+123").is_none());
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

    #[test]
    fn test_hex_newtype_from() {
        let bytes = [0x01u8, 0x02, 0xab, 0xcd];

        // From<T> for Hex<T> is callable both ways round.
        let from_slice: Hex<&[u8]> = (&bytes[..]).into();
        assert_eq!(format!("{from_slice}"), "0102abcd");
        let from_owned: Hex<Vec<u8>> = bytes.to_vec().into();
        assert_eq!(format!("{from_owned}"), "0102abcd");
    }
}
