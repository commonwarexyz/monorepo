//! Primitive implementations of [Translator].

use std::hash::{BuildHasher, Hash, Hasher};

/// Translate keys into a new representation (often a smaller one).
///
/// # Warning
///
/// The output of [Translator::transform] is often used as a key in a hash table. If the output is
/// not uniformly distributed, the performance of said hash table will degrade substantially.
pub trait Translator: Clone + BuildHasher {
    /// The type of the internal representation of keys.
    ///
    /// Although [Translator] is a [BuildHasher], the `Key` type must still implement [Hash] for
    /// compatibility with any hash table that wraps [Translator]. We also require [Ord] for
    /// compatibility with ordered collections.
    type Key: Ord + Hash + Copy;

    /// Transform a key into its new representation.
    fn transform(&self, key: &[u8]) -> Self::Key;
}

/// A “do-nothing” hasher for `uint`.
///
/// Most users typically store keys that are **already hashed** (shortened by the [Translator]).
/// Re-hashing them with SipHash (by [std::collections::HashMap]) would waste CPU, so we give
/// [std::collections::HashMap] this identity hasher instead:
///
/// * [Hasher::write_u8], [Hasher::write_u16], [Hasher::write_u32], [Hasher::write_u64] copies the
///   input into an internal field;
/// * [Hasher::finish] returns that value unchanged.
///
/// # Warning
///
/// This hasher is not suitable for general use. If the hasher is called over some type that is not
/// [u8], [u16], [u32] or [u64], it will panic.
#[derive(Default, Clone)]
pub struct UintIdentity {
    value: u64,
}

impl Hasher for UintIdentity {
    #[inline]
    fn write(&mut self, _: &[u8]) {
        unimplemented!("we should only ever call type-specific write methods");
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.value = i as u64;
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.value = i as u64;
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.value = i as u64;
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.value = i;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.value
    }
}

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
    ($name:ident, $size:expr, $int:ty) => {
        #[doc = concat!("Translator that caps the key to ", stringify!($size), " byte(s) and returns it packed in a ", stringify!($int), ".")]
        #[derive(Clone, Default)]
        pub struct $name;

        impl Translator for $name {
            // Minimal uint size for the key.
            type Key = $int;

            #[inline]
            fn transform(&self, key: &[u8]) -> Self::Key {
                let capped = cap::<$size>(key);
                <$int>::from_le_bytes(capped)
            }
        }

        // Implement the `BuildHasher` trait for `IdentityHasher`.
        impl BuildHasher for $name {
            type Hasher = UintIdentity;

            #[inline]
            fn build_hasher(&self) -> Self::Hasher {
                UintIdentity::default()
            }
        }
    };
}

// Define translators for different sizes.
define_cap_translator!(OneCap, 1, u8);
define_cap_translator!(TwoCap, 2, u16);
define_cap_translator!(FourCap, 4, u32);
define_cap_translator!(EightCap, 8, u64);

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hasher;

    #[test]
    fn test_one_cap() {
        let t = OneCap;
        assert_eq!(t.transform(b"").to_le_bytes(), [0]);
        assert_eq!(t.transform(b"a").to_le_bytes(), [b'a']);
        assert_eq!(t.transform(b"ab").to_le_bytes(), [b'a']);
        assert_eq!(t.transform(b"abc").to_le_bytes(), [b'a']);
    }

    #[test]
    fn test_two_cap() {
        let t = TwoCap;
        assert_eq!(t.transform(b"").to_le_bytes(), [0, 0]);
        assert_eq!(t.transform(b"a").to_le_bytes(), [b'a', 0]);
        assert_eq!(t.transform(b"ab").to_le_bytes(), [b'a', b'b']);
        assert_eq!(t.transform(b"abc").to_le_bytes(), [b'a', b'b']);
    }

    #[test]
    fn test_four_cap() {
        let t = FourCap;
        assert_eq!(t.transform(b"").to_le_bytes(), [0, 0, 0, 0]);
        assert_eq!(t.transform(b"a").to_le_bytes(), [b'a', 0, 0, 0]);
        assert_eq!(t.transform(b"abcd").to_le_bytes(), [b'a', b'b', b'c', b'd']);
        assert_eq!(
            t.transform(b"abcdef").to_le_bytes(),
            [b'a', b'b', b'c', b'd']
        );
    }

    #[test]
    fn test_eight_cap() {
        let t = EightCap;
        assert_eq!(t.transform(b"").to_le_bytes(), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(t.transform(b"a").to_le_bytes(), [b'a', 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            t.transform(b"abcdefgh").to_le_bytes(),
            [b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h']
        );
        assert_eq!(
            t.transform(b"abcdefghijk").to_le_bytes(),
            [b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h']
        );
    }

    #[test]
    #[should_panic(expected = "we should only ever call type-specific write methods")]
    fn identity_hasher_panics_on_write_slice() {
        let mut h = UintIdentity::default();
        h.write(b"not an int");
    }
}
