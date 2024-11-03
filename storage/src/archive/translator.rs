use super::Translator;

/// Cap the key to a fixed length.
fn cap<const N: usize>(key: &[u8]) -> [u8; N] {
    let mut capped = [0; N];
    let len = key.len().min(N);
    capped[..len].copy_from_slice(&key[..len]);
    capped
}

/// A translator that caps the key to two bytes.
#[derive(Clone)]
pub struct TwoCap;

impl Translator for TwoCap {
    type Key = [u8; 2];

    fn transform(&self, key: &[u8]) -> Self::Key {
        cap(key)
    }
}

/// A translator that caps the key to four bytes.
#[derive(Clone)]
pub struct FourCap;

impl Translator for FourCap {
    type Key = [u8; 4];

    fn transform(&self, key: &[u8]) -> Self::Key {
        cap(key)
    }
}

/// A translator that caps the key to eight bytes.
#[derive(Clone)]
pub struct EightCap;

impl Translator for EightCap {
    type Key = [u8; 8];

    fn transform(&self, key: &[u8]) -> Self::Key {
        cap(key)
    }
}

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
