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
/// This hasher is not suitable for general use. If the hasher is called on a byte slice longer
/// than `size_of::<u64>()`, it will panic.
#[derive(Default, Clone)]
pub struct UintIdentity {
    value: u64,
}

impl Hasher for UintIdentity {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        assert!(bytes.len() <= 8, "UintIdenty hasher cannot handle >8 bytes");
        // Treat the input array as a little-endian int to ensure low-order bits don't end up mostly
        // 0s, given that we right-pad.
        self.value = u64::from_le_bytes(cap::<8>(bytes));
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
                <$int>::from_be_bytes(capped)
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

// Define order-preserving translators for different sizes.
define_cap_translator!(OneCap, 1, u8);
define_cap_translator!(TwoCap, 2, u16);
define_cap_translator!(FourCap, 4, u32);
define_cap_translator!(EightCap, 8, u64);

/// Define a special array type for which we'll implement our own identity hasher. This avoids the
/// overhead of the default Array hasher which unnecessarily (for our use case) includes a length
/// prefix.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct UnhashedArray<const N: usize> {
    pub inner: [u8; N],
}

impl<const N: usize> Hash for UnhashedArray<N> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.inner);
    }
}

impl<const N: usize> PartialEq<[u8; N]> for UnhashedArray<N> {
    fn eq(&self, other: &[u8; N]) -> bool {
        &self.inner == other
    }
}

/// Translators for keys that are not the length of a standard integer.
#[derive(Clone, Copy)]
pub struct Cap<const N: usize>;

impl<const N: usize> Cap<N> {
    pub const fn new() -> Self {
        const {
            assert!(N <= 8 && N > 0, "Cap must be between 1 and 8");
        };
        Self
    }
}

// Manually implement Default for Cap<N> so it calls new() which validates N.
impl<const N: usize> Default for Cap<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Translator for Cap<N> {
    type Key = UnhashedArray<N>;

    #[inline]
    fn transform(&self, key: &[u8]) -> Self::Key {
        const {
            assert!(N <= 8 && N > 0, "Cap must be between 1 and 8");
        };
        UnhashedArray {
            inner: cap::<N>(key),
        }
    }
}

impl<const N: usize> BuildHasher for Cap<N> {
    type Hasher = UintIdentity;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        UintIdentity::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hasher;

    #[test]
    fn test_one_cap() {
        let t = OneCap;
        assert_eq!(t.transform(b""), 0);
        assert_eq!(t.transform(b"a"), b'a');
        assert_eq!(t.transform(b"ab"), b'a');
        assert_eq!(t.transform(b"abc"), b'a');
    }

    #[test]
    fn test_two_cap() {
        let t = TwoCap;
        assert_eq!(t.transform(b""), 0);
        assert_eq!(t.transform(b"abc"), t.transform(b"ab"));
        assert!(t.transform(b"") < t.transform(b"a"));
        assert!(t.transform(b"a") < t.transform(b"b"));
        assert!(t.transform(b"ab") < t.transform(b"ac"));
        assert!(t.transform(b"z") < t.transform(b"zz"));
        assert_eq!(t.transform(b"zz"), t.transform(b"zzabc"));
    }

    #[test]
    fn test_four_cap() {
        let t = FourCap;
        let t1 = t.transform(b"");
        let t2 = t.transform(b"a");
        let t3 = t.transform(b"abcd");
        let t4 = t.transform(b"abcdef");
        let t5 = t.transform(b"b");

        assert_eq!(t1, 0);
        assert!(t1 < t2);
        assert!(t2 < t3);
        assert_eq!(t3, t4);
        assert!(t3 < t5);
        assert!(t4 < t5);
    }

    #[test]
    fn test_cap_3() {
        let t = Cap::<3>::new();
        assert_eq!(t.transform(b""), [0; 3]);
        assert_eq!(t.transform(b"abc"), *b"abc");
        assert_eq!(t.transform(b"abcdef"), *b"abc");
        assert_eq!(t.transform(b"ab"), [b'a', b'b', 0]);
    }

    #[test]
    fn test_cap_6() {
        let t = Cap::<6>::new();
        assert_eq!(t.transform(b""), [0; 6]);
        assert_eq!(t.transform(b"abcdef"), *b"abcdef");
        assert_eq!(t.transform(b"abcdefghi"), *b"abcdef");
        assert_eq!(t.transform(b"abc"), [b'a', b'b', b'c', 0, 0, 0]);
    }

    #[test]
    fn test_eight_cap() {
        let t = EightCap;
        let t1 = t.transform(b"");
        let t2 = t.transform(b"a");
        let t3 = t.transform(b"abcdefghaaaaaaa");
        let t4 = t.transform(b"abcdefghijkzzzzzzzzzzzzzzzzzz");
        let t5 = t.transform(b"b");

        assert_eq!(t1, 0);
        assert!(t1 < t2);
        assert!(t2 < t3);
        assert_eq!(t3, t4);
        assert!(t3 < t5);
        assert!(t4 < t5);
    }

    #[test]
    fn identity_hasher_works_on_small_slice() {
        let mut h = UintIdentity::default();
        h.write(b"abc");
        assert_eq!(h.finish(), u64::from_le_bytes(cap::<8>(b"abc")));
    }

    #[test]
    #[should_panic]
    fn identity_hasher_panics_on_large_write_slice() {
        let mut h = UintIdentity::default();
        h.write(b"too big for an int");
    }
}
