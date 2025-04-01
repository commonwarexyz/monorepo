use super::Translator;

/// Cap the key to a fixed length.
///
/// # Behavior
///
/// - If input is shorter than `N`, the output is zero-padded.
/// - If input is longer than `N`, the output is truncated.
/// - If input is exactly `N`, the output is identical.
fn cap<const N: usize>(key: &[u8]) -> [u8; N] {
    let mut capped = [0; N];
    let len = key.len().min(N);
    capped[..len].copy_from_slice(&key[..len]);
    capped
}
macro_rules! define_cap_translator {
    ($name:ident, $size:expr) => {
        #[doc = concat!("A translator that caps the key to ", stringify!($size), " bytes.")]
        #[derive(Clone)]
        pub struct $name;

        impl Translator for $name {
            type Key = [u8; $size];

            fn transform(&self, key: &[u8]) -> Self::Key {
                cap(key)
            }
        }
    };
}

define_cap_translator!(TwoCap, 2);
define_cap_translator!(FourCap, 4);
define_cap_translator!(EightCap, 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_two_cap() {
        let translator = TwoCap;
        assert_eq!(translator.transform(b""), [0, 0]);
        assert_eq!(translator.transform(b"a"), [b'a', 0]);
        assert_eq!(translator.transform(b"ab"), [b'a', b'b']);
        assert_eq!(translator.transform(b"abc"), [b'a', b'b']);
    }

    #[test]
    fn test_four_cap() {
        let translator = FourCap;
        assert_eq!(translator.transform(b""), [0, 0, 0, 0]);
        assert_eq!(translator.transform(b"a"), [b'a', 0, 0, 0]);
        assert_eq!(translator.transform(b"abcd"), [b'a', b'b', b'c', b'd']);
        assert_eq!(translator.transform(b"abcdef"), [b'a', b'b', b'c', b'd']);
    }

    #[test]
    fn test_eight_cap() {
        let translator = EightCap;
        assert_eq!(translator.transform(b""), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(translator.transform(b"a"), [b'a', 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            translator.transform(b"abcdefgh"),
            [b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h']
        );
        assert_eq!(
            translator.transform(b"abcdefghijk"),
            [b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h']
        );
    }
}
