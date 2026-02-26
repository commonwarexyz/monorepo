//! Primitive implementations of [Translator].

use std::hash::{BuildHasher, Hash, Hasher};

/// Translate keys into a new representation (often a smaller one).
///
/// # Warning
///
/// The output of [Translator::transform] is often used as a key in a hash table. If the output is
/// not uniformly distributed, the performance of said hash table will degrade substantially.
pub trait Translator: Clone + BuildHasher + Send + Sync + 'static {
    /// The type of the internal representation of keys.
    ///
    /// Although [Translator] is a [BuildHasher], the `Key` type must still implement [Hash] for
    /// compatibility with any hash table that wraps [Translator]. We also require [Ord] for
    /// compatibility with ordered collections. [Send] and [Sync] are required for thread-safe
    /// concurrent access.
    type Key: Ord + Hash + Copy + Send + Sync;

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

/// Collision-resistant wrapper for any [Translator].
///
/// Hashes the full key with a per-instance secret seed (via [ahash::RandomState]) before delegating
/// to the inner translator. This makes translated-key collisions unpredictable to an adversary who
/// does not know the seed, similar to how [std::collections::HashMap] uses
/// [std::collections::hash_map::RandomState] to prevent HashDoS attacks. It can also be used to
/// ensure uniform distribution of skewed keyspaces when used by non-hashing structures such as
/// [crate::index].
///
/// # Warning
///
/// Hashing destroys lexicographic key ordering. Do not use [Hashed] with ordered indices when
/// callers rely on translated-key adjacency matching original-key adjacency (e.g., exclusion proofs
/// in the ordered QMDB). [Hashed] is safe for unordered indices and partitioned unordered indices.
///
/// # `no_std`
///
/// [Hashed::new] and [Default] use [ahash::RandomState::new] which requires OS-provided randomness
/// (the `runtime-rng` feature of `ahash`, enabled by the `std` feature of this crate). In `no_std`
/// builds without `runtime-rng`, [Hashed::new] will compile but may use fixed seeds, providing no
/// adversarial protection. In `no_std` environments, use [Hashed::from_seed] with an
/// externally-sourced random seed instead.
///
/// # Stability
///
/// [ahash::RandomState] is used as the underlying hasher. While `ahash` is robust, its exact
/// algorithm might change across versions. As a result, transformed outputs are not stable across
/// Rust versions or platforms. Treat this translator as an in-memory collision-hardening mechanism,
/// not as a stable/persisted encoding.
///
/// # Examples
///
/// ```
/// use commonware_storage::translator::{Hashed, TwoCap, Translator};
///
/// // Random seed (production use):
/// let t = Hashed::new(TwoCap);
/// let k = t.transform(b"hello");
///
/// // Deterministic seed (testing within the same toolchain/runtime):
/// let t = Hashed::from_seed(42, TwoCap);
/// assert_eq!(t.transform(b"hello"), t.transform(b"hello"));
/// ```
#[derive(Clone)]
pub struct Hashed<T: Translator> {
    random_state: ahash::RandomState,
    inner: T,
}

impl<T: Translator + Default> Default for Hashed<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Translator> Hashed<T> {
    /// Create a new [Hashed] translator with a random seed.
    pub fn new(inner: T) -> Self {
        Self {
            random_state: ahash::RandomState::new(),
            inner,
        }
    }

    /// Create a new [Hashed] translator with a specific seed.
    ///
    /// Determinism is scoped to the current `ahash` implementation. Outputs are not guaranteed to
    /// be stable across crate versions or platforms.
    pub fn from_seed(seed: u64, inner: T) -> Self {
        // Derive four independent seeds from the single input using ahash itself.
        // A fixed RandomState acts as a key-derivation function: hashing (seed, index) pairs
        // produces well-distributed independent values without requiring std::hash::DefaultHasher.
        let kdf = ahash::RandomState::with_seeds(0, 0, 0, 0);
        let derive = |index: u64| -> u64 { kdf.hash_one((seed, index)) };
        let random_state =
            ahash::RandomState::with_seeds(derive(0), derive(1), derive(2), derive(3));
        Self {
            random_state,
            inner,
        }
    }
}

impl<T: Translator> Translator for Hashed<T> {
    type Key = T::Key;

    #[inline]
    fn transform(&self, key: &[u8]) -> T::Key {
        let hash_val = self.random_state.hash_one(key);
        self.inner.transform(&hash_val.to_le_bytes())
    }
}

impl<T: Translator> BuildHasher for Hashed<T> {
    type Hasher = <T as BuildHasher>::Hasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        self.inner.build_hasher()
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

    #[test]
    fn test_hashed_consistency() {
        let t = Hashed::from_seed(42, TwoCap);
        assert_eq!(t.transform(b"hello"), t.transform(b"hello"));
        assert_eq!(t.transform(b""), t.transform(b""));
        assert_eq!(t.transform(b"abcdef"), t.transform(b"abcdef"));
    }

    #[test]
    fn test_hashed_seed_determinism() {
        let t1 = Hashed::from_seed(42, TwoCap);
        let t2 = Hashed::from_seed(42, TwoCap);
        assert_eq!(t1.transform(b"hello"), t2.transform(b"hello"));
        assert_eq!(t1.transform(b"world"), t2.transform(b"world"));
    }

    #[test]
    fn test_hashed_seed_independence() {
        let t1 = Hashed::from_seed(1, EightCap);
        let t2 = Hashed::from_seed(2, EightCap);
        // Different seeds should (with overwhelming probability) produce different outputs.
        assert_ne!(t1.transform(b"hello"), t2.transform(b"hello"));
    }

    #[test]
    fn test_hashed_prefix_collisions_avoided() {
        // Without hashing, keys sharing a prefix collide. With hashing, they should not.
        let t = Hashed::from_seed(99, TwoCap);
        let k1 = t.transform(b"abXXX");
        let k2 = t.transform(b"abYYY");
        // The unhashed TwoCap would map both to the same value (first 2 bytes "ab").
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_hashed_all_cap_sizes() {
        let t1 = Hashed::from_seed(7, OneCap);
        assert_eq!(t1.transform(b"test"), t1.transform(b"test"));

        let t4 = Hashed::from_seed(7, FourCap);
        assert_eq!(t4.transform(b"test"), t4.transform(b"test"));

        let t8 = Hashed::from_seed(7, EightCap);
        assert_eq!(t8.transform(b"test"), t8.transform(b"test"));

        let tc = Hashed::from_seed(7, Cap::<3>::new());
        assert_eq!(tc.transform(b"test"), tc.transform(b"test"));
    }

    #[test]
    fn test_hashed_random_seed() {
        // Two instances with random seeds should (with overwhelming probability)
        // produce different outputs.
        let t1 = Hashed::new(EightCap);
        let t2 = Hashed::new(EightCap);
        assert_ne!(t1.transform(b"hello"), t2.transform(b"hello"));
    }
}
