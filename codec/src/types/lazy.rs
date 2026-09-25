//! This module exports the [`Lazy`] type.

use crate::{Buf, BufsMut, Decode, Encode, EncodeSize, FixedSize, Read, Write};
use bytes::{Buf as _, Bytes};
use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};
#[cfg(feature = "std")]
use std::sync::OnceLock;

/// A type which can be deserialized lazily.
///
/// This is useful when deserializing a value is expensive, and you don't want
/// to immediately pay this cost. This type allows you to move this cost to a
/// later point in your program, or use parallelism to spread the cost across
/// computing cores.
///
/// # Usage
///
/// Any usage of the type requires that `T` implements [`Read`], because we need
/// to know what type [`Read::Cfg`] is.
///
/// ## Construction
///
/// If you have a `T`, you can use [`Lazy::new`]:
///
/// ```
/// # use commonware_codec::types::lazy::Lazy;
/// let l = Lazy::new(4000u64);
/// ```
///
/// or [`Into`]:
///
/// ```
/// # use commonware_codec::types::lazy::Lazy;
/// let l: Lazy<u64> = 4000u64.into();
/// ```
///
/// If you *don't* have a `T`, then you can instead create a [`Lazy`] using
/// bytes and a [`Read::Cfg`]:
///
/// ```
/// # use commonware_codec::{Encode, types::lazy::Lazy};
/// let l: Lazy<u64> = Lazy::deferred(&mut 4000u64.encode(), ());
/// ```
///
/// ## Consumption
///
/// Given a [`Lazy`], use [`Lazy::get`] to access the value:
///
/// ```
/// # use commonware_codec::{Encode, types::lazy::Lazy};
/// let l = Lazy::<u64>::deferred(&mut 4000u64.encode(), ());
/// assert_eq!(l.get(), Some(&4000u64));
/// // Does not pay the cost of deserializing again
/// assert_eq!(l.get(), Some(&4000u64));
/// ```
///
/// This returns an [`Option`], because deserialization might fail.
///
/// ## Traits
///
/// [`Lazy`] can be serialized and deserialized, implementing [`Read`], [`Write`],
/// and [`EncodeSize`], based on the underlying implementation of `T`.
///
/// ## Equality, Ordering, and Hashing
///
/// Equality, ordering, and hashing follow the canonical encoding, so they never force
/// decoding and never depend on whether deferred bytes were decoded:
///
/// - Ordering is lexicographic over the encoded bytes and never consults `T`'s [`Ord`], so it
///   can differ from the order of the decoded values.
/// - Two values constructed with [`Lazy::new`] compare with `T`'s [`PartialEq`], which is
///   cheaper than encoding them, so `T`'s equality must agree with equality of encodings.
/// - Deferred bytes compare as bytes, so encodings of one value that a lenient decoder accepts
///   stay distinct, as do distinct undecodable byte strings.
#[derive(Clone)]
pub struct Lazy<T: Read> {
    /// This should only be `None` if `value` is initialized.
    pending: Option<Pending<T>>,
    #[cfg(feature = "std")]
    value: OnceLock<Option<T>>,
    #[cfg(not(feature = "std"))]
    value: Option<T>,
}

#[derive(Clone)]
struct Pending<T: Read> {
    bytes: Bytes,
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    cfg: T::Cfg,
}

impl<T: Read> Lazy<T> {
    // I considered calling this "now", but this was too close to "new".
    /// Create a [`Lazy`] using a value.
    #[cfg(feature = "std")]
    pub fn new(value: T) -> Self {
        Self {
            pending: None,
            value: OnceLock::from(Some(value)),
        }
    }

    /// Create a [`Lazy`] using a value.
    #[cfg(not(feature = "std"))]
    pub const fn new(value: T) -> Self {
        Self {
            pending: None,
            value: Some(value),
        }
    }

    /// Create a [`Lazy`] by deferring decoding of an underlying value.
    ///
    /// Retains the remaining encoded bytes, sharing the input allocation when possible
    /// and copying otherwise.
    ///
    /// Use [`Self::get`] to access the actual value, by decoding these bytes.
    pub fn deferred(buf: &mut impl Buf, cfg: T::Cfg) -> Self {
        let bytes = buf.copy_to_bytes(buf.remaining());
        cfg_if::cfg_if! {
            if #[cfg(feature = "std")] {
                Self {
                    pending: Some(Pending { bytes, cfg }),
                    value: Default::default(),
                }
            } else {
                Self {
                    value: T::decode_cfg(bytes.clone(), &cfg).ok(),
                    pending: Some(Pending { bytes, cfg }),
                }
            }
        }
    }

    /// Force decoding of the underlying value.
    ///
    /// This will return `None` only if decoding the value fails.
    ///
    /// This function wil incur the cost of decoding the value only once,
    /// so there's no need to cache its output.
    #[cfg(feature = "std")]
    pub fn get(&self) -> Option<&T> {
        self.value
            .get_or_init(|| {
                let Pending { bytes, cfg } = self
                    .pending
                    .as_ref()
                    .expect("Lazy should have pending if value is not initialized");
                T::decode_cfg(bytes.clone(), cfg).ok()
            })
            .as_ref()
    }

    /// Returns a reference to the underlying value, or `None` if decoding failed.
    #[cfg(not(feature = "std"))]
    pub const fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }
}

impl<T: Read + Encode> From<T> for Lazy<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

// # Implementing Codec.
//
// The strategy here is that for writing, we use the underlying bytes stored
// in the value, and for reading, we rely on the type having a fixed size.

impl<T: Read + EncodeSize> EncodeSize for Lazy<T> {
    fn encode_size(&self) -> usize {
        if let Some(pending) = &self.pending {
            return pending.bytes.len();
        }
        self.get()
            .expect("Lazy should have a value if pending is None")
            .encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        if self.pending.is_some() {
            return 0;
        }
        self.get()
            .expect("Lazy should have a value if pending is None")
            .encode_inline_size()
    }
}

impl<T: Read + Write> Write for Lazy<T> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        if let Some(pending) = &self.pending {
            // Write raw bytes without length prefix (Bytes::write adds a length prefix)
            buf.put_slice(&pending.bytes);
            return;
        }
        self.get()
            .expect("Lazy should have a value if pending is None")
            .write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        if let Some(pending) = &self.pending {
            // Write raw bytes without length prefix (Bytes::write_bufs adds a length prefix)
            buf.push(pending.bytes.clone());
            return;
        }
        self.get()
            .expect("Lazy should have a value if pending is None")
            .write_bufs(buf);
    }
}

impl<T: Read + FixedSize> Read for Lazy<T> {
    type Cfg = T::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, crate::Error> {
        // In this case, we can be a bit more helpful, and fail earlier, rather
        // than deferring this error until later.
        if buf.remaining() < T::SIZE {
            return Err(crate::Error::EndOfBuffer);
        }
        Ok(Self::deferred(&mut buf.take(T::SIZE), cfg.clone()))
    }
}

// # Forwarded Impls
//
// We want to provide some convenience functions which might exist on the underlying
// value in a Lazy. To do so, we really on `get` to access that value.
//
// Comparison and hashing work on the canonical encoding instead: deferred bytes are already
// that encoding, and an eagerly constructed value encodes far more cheaply than deferred bytes
// decode (for group elements, decoding also runs a subgroup check).

/// Largest eager encoding that comparison and hashing write to the stack instead of allocating.
const STACK_ENCODING_SIZE: usize = 128;

impl<T: Read + Write + EncodeSize> Lazy<T> {
    /// Calls `f` with the canonical encoding, without decoding deferred bytes.
    ///
    /// Deferred bytes are borrowed. An eager value is encoded on the stack when it fits in
    /// [`STACK_ENCODING_SIZE`] bytes, and into a new allocation otherwise.
    ///
    /// # Panics
    ///
    /// Panics if `T::write` does not write `T::encode_size` bytes.
    fn with_encoding<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        if let Some(pending) = &self.pending {
            return f(&pending.bytes);
        }
        let value = self
            .get()
            .expect("Lazy should have a value if pending is None");
        let len = value.encode_size();
        if len > STACK_ENCODING_SIZE {
            return f(&value.encode());
        }
        let mut buf = [0u8; STACK_ENCODING_SIZE];
        let mut unwritten = &mut buf[..len];
        value.write(&mut unwritten);
        assert!(unwritten.is_empty(), "write() did not write expected bytes");
        f(&buf[..len])
    }
}

impl<T: Read + Write + EncodeSize + PartialEq> PartialEq for Lazy<T> {
    fn eq(&self, other: &Self) -> bool {
        // Choose by construction, never by decode state, so a decode cannot change the result.
        // Retained bytes compare directly, and two eager values compare with `T`'s equality,
        // which is cheaper than encoding them and agrees with it.
        match (&self.pending, &other.pending) {
            (Some(left), Some(right)) => left.bytes == right.bytes,
            (None, None) => {
                let left = self
                    .get()
                    .expect("Lazy should have a value if pending is None");
                let right = other
                    .get()
                    .expect("Lazy should have a value if pending is None");
                left == right
            }
            _ => self.with_encoding(|left| other.with_encoding(|right| left == right)),
        }
    }
}

impl<T: Read + Write + EncodeSize + Eq> Eq for Lazy<T> {}

impl<T: Read + Write + EncodeSize + Eq> PartialOrd for Lazy<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Read + Write + EncodeSize + Eq> Ord for Lazy<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Never falls back to `T::cmp`, even when both sides are decoded: it can disagree with
        // the byte order, and mixing the two orders would break transitivity.
        self.with_encoding(|left| other.with_encoding(|right| left.cmp(right)))
    }
}

impl<T: Read + Write + EncodeSize> Hash for Lazy<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.with_encoding(|bytes| bytes.hash(state));
    }
}

impl<T: Read + core::fmt::Debug> core::fmt::Debug for Lazy<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.get().fmt(f)
    }
}

#[cfg(test)]
mod test {
    use super::{Lazy, STACK_ENCODING_SIZE};
    use crate::{
        Buf, Copying, Decode, DecodeExt, Encode, FixedSize, Read, Write,
        types::tests::TrackingWriteBuf,
    };
    use bytes::Bytes;
    use core::hash::{Hash, Hasher};
    use proptest::prelude::*;
    use std::{
        collections::{BTreeMap, hash_map::DefaultHasher},
        sync::atomic::{AtomicUsize, Ordering::SeqCst},
    };

    /// A byte that's always <= 100
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Small(u8);

    impl FixedSize for Small {
        const SIZE: usize = 1;
    }

    impl Write for Small {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            self.0.write(buf);
        }
    }

    impl Read for Small {
        type Cfg = ();

        fn read_cfg(buf: &mut impl crate::Buf, _cfg: &Self::Cfg) -> Result<Self, crate::Error> {
            let byte = u8::read_cfg(buf, &())?;
            if byte > 100 {
                return Err(crate::Error::Invalid("Small", "value > 100"));
            }
            Ok(Self(byte))
        }
    }

    impl Arbitrary for Small {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            (0..=100u8).prop_map(Small).boxed()
        }
    }

    /// A byte whose decoding is counted, to prove comparisons never decode.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Counted(u8);

    static DECODES: AtomicUsize = AtomicUsize::new(0);

    impl FixedSize for Counted {
        const SIZE: usize = 1;
    }

    impl Write for Counted {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            self.0.write(buf);
        }
    }

    impl Read for Counted {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, crate::Error> {
            DECODES.fetch_add(1, SeqCst);
            Ok(Self(u8::read_cfg(buf, &())?))
        }
    }

    /// A byte whose decoder ignores the top bit, so two encodings decode to each value.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Lenient(u8);

    impl FixedSize for Lenient {
        const SIZE: usize = 1;
    }

    impl Write for Lenient {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            self.0.write(buf);
        }
    }

    impl Read for Lenient {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, crate::Error> {
            Ok(Self(u8::read_cfg(buf, &())? & 0x7f))
        }
    }

    fn hash_of(value: &impl Hash) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    /// Returns `value` as an eager, a deferred, and a decoded deferred [`Lazy`].
    fn forms<T: Read + Encode + Clone>(value: T, cfg: &T::Cfg) -> [Lazy<T>; 3] {
        let deferred = Lazy::deferred(&mut value.encode(), cfg.clone());
        let decoded = deferred.clone();
        assert!(decoded.get().is_some());
        [Lazy::new(value), deferred, decoded]
    }

    /// Asserts that equality, ordering, and hashing between every construction form of `a`
    /// and `b` follow their encodings.
    fn assert_follows_encoding<T: Read + Encode + Eq + Clone>(a: T, b: T, cfg: &T::Cfg) {
        let expected = a.encode().cmp(&b.encode());
        assert_eq!(expected.is_eq(), a == b);
        for left in forms(a, cfg) {
            for right in forms(b.clone(), cfg) {
                assert_eq!(left.cmp(&right), expected);
                assert_eq!(left.partial_cmp(&right), Some(expected));
                assert_eq!(left == right, expected.is_eq());
                if expected.is_eq() {
                    assert_eq!(hash_of(&left), hash_of(&right));
                }
            }
        }
    }

    #[test]
    fn comparisons_and_hashing_do_not_decode() {
        let a = Lazy::<Counted>::deferred(&mut Counted(7).encode(), ());
        let b = Lazy::<Counted>::deferred(&mut Counted(7).encode(), ());
        let c = Lazy::<Counted>::deferred(&mut Counted(9).encode(), ());
        let eager = Lazy::new(Counted(7));
        // Without `std`, `deferred` decodes up front, so count only the decodes that follow.
        let decodes = DECODES.load(SeqCst);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, eager);
        assert!(a < c);
        assert_eq!(hash_of(&a), hash_of(&eager));
        assert_eq!(DECODES.load(SeqCst), decodes);
        assert_eq!(a.get(), Some(&Counted(7)));
        #[cfg(feature = "std")]
        assert_eq!(DECODES.load(SeqCst), decodes + 1);
    }

    proptest! {
        #[test]
        fn test_lazy_new_eq_deferred(x: Small) {
            let from_new = Lazy::new(x);
            let from_deferred = Lazy::deferred(&mut x.encode(), ());
            prop_assert_eq!(from_new, from_deferred);
        }

        #[test]
        fn test_lazy_write_eq_direct(x: Small) {
            let direct = x.encode();
            let via_lazy = Lazy::new(x).encode();
            prop_assert_eq!(direct, via_lazy);
        }

        #[test]
        fn test_lazy_encode_consistent_across_construction(x: Small) {
            let direct = x.encode();
            let via_new = Lazy::new(x).encode();
            let via_deferred = Lazy::<Small>::deferred(&mut x.encode(), ()).encode();
            prop_assert_eq!(&direct, &via_new);
            prop_assert_eq!(&direct, &via_deferred);
        }

        #[test]
        fn test_lazy_read_eq_direct(byte: u8) {
            let direct: Option<Small> = Small::decode(byte.encode()).ok();
            let via_lazy: Option<Small> =
                Lazy::<Small>::decode(byte.encode()).ok().and_then(|l| l.get().copied());
            prop_assert_eq!(direct, via_lazy);
        }

        #[test]
        fn test_lazy_cmp_eq_direct(a: Small, b: Small) {
            let la = Lazy::new(a);
            let lb = Lazy::new(b);
            prop_assert_eq!(a == b, la == lb);
            prop_assert_eq!(a < b, la < lb);
            prop_assert_eq!(a >= b, la >= lb);
        }

        #[test]
        fn test_lazy_order_follows_encoding(a: i16, b: i16) {
            // Negative values encode above positive ones, so this order disagrees with `i16`'s.
            assert_follows_encoding(a, b, &());
        }
    }

    #[test]
    fn test_lazy_order_follows_encoding_beyond_stack() {
        let cfg = (..).into();
        let lengths = [
            0,
            1,
            STACK_ENCODING_SIZE - 2,
            STACK_ENCODING_SIZE - 1,
            STACK_ENCODING_SIZE,
            2 * STACK_ENCODING_SIZE,
        ];
        let values: Vec<Bytes> = lengths
            .into_iter()
            .flat_map(|len| [Bytes::from(vec![1; len]), Bytes::from(vec![2; len])])
            .collect();
        for a in &values {
            for b in &values {
                assert_follows_encoding(a.clone(), b.clone(), &cfg);
            }
        }
    }

    // The cached decode is interior mutability, but ordering reads only the encoding.
    #[allow(clippy::mutable_key_type)]
    #[test]
    fn test_lazy_btree_map_orders_by_encoding() {
        let values = [i16::MIN, -2, -1, 0, 1, 2, i16::MAX];
        let mut map = BTreeMap::new();
        for (index, value) in values.into_iter().enumerate() {
            let key = forms(value, &()).into_iter().nth(index % 3).unwrap();
            assert!(map.insert(key, value).is_none());
        }

        // Iteration follows the encodings, which disagree with the numeric order
        let mut expected = values.to_vec();
        expected.sort_by_key(|value| value.encode());
        assert_ne!(expected, values);
        assert!(map.values().eq(&expected));

        // Every construction form finds the key, whichever form was inserted
        for value in values {
            for key in forms(value, &()) {
                assert_eq!(map.get(&key), Some(&value));
            }
        }
    }

    #[test]
    fn test_lazy_undecodable_bytes_stay_distinct() {
        let a = Lazy::<Small>::deferred(&mut Bytes::from_static(&[101]), ());
        let b = Lazy::<Small>::deferred(&mut Bytes::from_static(&[102]), ());
        assert_eq!(a.get(), None);
        assert_eq!(b.get(), None);
        assert_eq!(a, a.clone());
        assert_ne!(a, b);
        assert!(a < b);
        assert!(Lazy::new(Small(100)) < a);
    }

    #[test]
    fn test_lazy_equality_ignores_decode_state() {
        let eager = Lazy::new(Lenient(1));
        let canonical = Lazy::<Lenient>::deferred(&mut Bytes::from_static(&[0x01]), ());
        let alternate = Lazy::<Lenient>::deferred(&mut Bytes::from_static(&[0x81]), ());

        // Only the canonical bytes match the eager value's encoding
        assert_eq!(eager, canonical);
        assert_ne!(eager, alternate);
        assert_ne!(canonical, alternate);

        // Decoding both to the eager value changes no comparison
        assert_eq!(canonical.get(), Some(&Lenient(1)));
        assert_eq!(alternate.get(), Some(&Lenient(1)));
        assert_eq!(eager, canonical);
        assert_ne!(eager, alternate);
        assert_ne!(alternate, eager);
        assert_ne!(canonical, alternate);
        assert_eq!(hash_of(&eager), hash_of(&canonical));
    }

    #[test]
    fn test_lazy_view() {
        let value: Vec<Lazy<Small>> = (0..64u8).map(|i| Lazy::new(Small(i))).collect();
        let source = value.encode();
        let cfg = ((..).into(), ());
        let range = source.as_ptr_range();

        // Decoding from the owned buffer defers every element as a view of it
        let decoded = Vec::<Lazy<Small>>::decode_cfg(source.clone(), &cfg).unwrap();
        assert_eq!(decoded, value);
        let mut buf = TrackingWriteBuf::new();
        decoded.write_bufs(&mut buf);
        assert_eq!(buf.pushed.len(), value.len());
        assert!(buf.pushed.iter().all(|b| range.contains(&b.as_ptr())));

        // Decoding from a slice of it copies every element
        let copied = Vec::<Lazy<Small>>::decode_cfg(Copying(&source), &cfg).unwrap();
        assert_eq!(copied, value);
        let mut buf = TrackingWriteBuf::new();
        copied.write_bufs(&mut buf);
        assert_eq!(buf.pushed.len(), value.len());
        assert!(buf.pushed.iter().all(|b| !range.contains(&b.as_ptr())));
    }
}
