//! This module exports the [`Lazy`] type.

use crate::{Buf, BufsMut, Decode, Encode, EncodeSize, FixedSize, Read, Write};
use bytes::{Buf as _, Bytes};
use core::hash::Hash;
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
/// Equality, ordering, and hashing compare the canonical encoding, so they never force
/// decoding. Because encodings are canonical, this agrees with `T`'s own equality for values
/// that decode, and it keeps distinct undecodable byte strings distinct.
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
}

impl<T: Read> Lazy<T> {
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

impl<T: Read> Lazy<T> {
    /// Returns the value if it has already been decoded, without forcing a decode.
    #[cfg(feature = "std")]
    fn decoded(&self) -> Option<&T> {
        self.value.get().and_then(Option::as_ref)
    }

    /// Returns the value if it has already been decoded, without forcing a decode.
    #[cfg(not(feature = "std"))]
    const fn decoded(&self) -> Option<&T> {
        self.value.as_ref()
    }
}

impl<T: Read + Write + EncodeSize> Lazy<T> {
    /// Returns the canonical encoding without decoding deferred bytes.
    fn encoded(&self) -> Bytes {
        self.pending.as_ref().map_or_else(
            || {
                self.get()
                    .expect("Lazy should have a value if pending is None")
                    .encode()
            },
            |pending| pending.bytes.clone(),
        )
    }
}

impl<T: Read + Write + EncodeSize + PartialEq> PartialEq for Lazy<T> {
    fn eq(&self, other: &Self) -> bool {
        // Two decoded values compare directly; otherwise the canonical encodings decide, which
        // never decodes and only allocates when one side was constructed from a value.
        match (self.decoded(), other.decoded()) {
            (Some(left), Some(right)) => left == right,
            _ => self.encoded() == other.encoded(),
        }
    }
}

impl<T: Read + Write + EncodeSize + PartialEq> Eq for Lazy<T> {}

impl<T: Read + Write + EncodeSize + PartialEq> PartialOrd for Lazy<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Read + Write + EncodeSize + PartialEq> Ord for Lazy<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.encoded().cmp(&other.encoded())
    }
}

impl<T: Read + Write + EncodeSize> Hash for Lazy<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.encoded().hash(state);
    }
}

impl<T: Read + core::fmt::Debug> core::fmt::Debug for Lazy<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.get().fmt(f)
    }
}

#[cfg(test)]
mod test {
    use super::Lazy;
    use crate::{
        Buf, Copying, Decode, DecodeExt, Encode, FixedSize, Read, Write,
        types::tests::TrackingWriteBuf,
    };
    use proptest::prelude::*;

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

    static DECODES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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
            DECODES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Self(u8::read_cfg(buf, &())?))
        }
    }

    #[test]
    fn comparisons_and_hashing_do_not_decode() {
        use core::hash::{Hash, Hasher};
        let a = Lazy::<Counted>::deferred(&mut Counted(7).encode(), ());
        let b = Lazy::<Counted>::deferred(&mut Counted(7).encode(), ());
        let c = Lazy::<Counted>::deferred(&mut Counted(9).encode(), ());
        let eager = Lazy::new(Counted(7));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, eager);
        assert!(a < c);
        let mut ha = std::collections::hash_map::DefaultHasher::new();
        let mut hb = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut ha);
        eager.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
        assert_eq!(DECODES.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(a.get(), Some(&Counted(7)));
        assert_eq!(DECODES.load(std::sync::atomic::Ordering::SeqCst), 1);
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
