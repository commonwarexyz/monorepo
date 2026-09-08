//! This module exports the [`Lazy`] type.

use crate::{BufsMut, Decode, DecodeWith, Encode, EncodeSize, FixedSize, Read, Write};
use bytes::{Buf, Bytes};
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
/// Furthermore, we implement [`Eq`], [`Ord`], [`Hash`] based on the implementation
/// of `T` as well. These methods will force deserialization of the value.
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
    /// The only cost incurred when this function is called is that of copying
    /// some bytes.
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
                    value: T::decode_cfg(bytes.as_ref(), &cfg).ok(),
                    pending: Some(Pending { bytes, cfg }),
                }
            }
        }
    }
}

impl<T: Read> Lazy<T> {
    /// Initializes the cache using the pending bytes and configuration.
    #[cfg(feature = "std")]
    fn initialize_with(
        &self,
        decode: impl FnOnce(&[u8], &T::Cfg) -> Result<T, crate::Error>,
    ) -> Option<&T> {
        self.value
            .get_or_init(|| {
                let Pending { bytes, cfg } = self
                    .pending
                    .as_ref()
                    .expect("Lazy should have pending if value is not initialized");
                decode(bytes.as_ref(), cfg).ok()
            })
            .as_ref()
    }

    /// Force decoding of the underlying value.
    ///
    /// This will return `None` only if decoding the value fails.
    ///
    /// This function will incur the cost of decoding the value only once,
    /// so there's no need to cache its output.
    #[cfg(feature = "std")]
    pub fn get(&self) -> Option<&T> {
        self.initialize_with(|bytes, cfg| T::decode_cfg(bytes, cfg))
    }

    /// Returns a reference to the underlying value, or `None` if decoding failed.
    #[cfg(not(feature = "std"))]
    pub const fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Returns the cached decoding result without initializing it.
    ///
    /// `None` means decoding has not completed, `Some(None)` means decoding failed, and
    /// `Some(Some(value))` contains the decoded value. Without `std`, decoding is eager, so this
    /// always returns `Some`.
    pub fn get_cached(&self) -> Option<Option<&T>> {
        #[cfg(feature = "std")]
        {
            self.value.get().map(Option::as_ref)
        }
        #[cfg(not(feature = "std"))]
        {
            Some(self.value.as_ref())
        }
    }
}

impl<T: DecodeWith> Lazy<T> {
    /// Accesses the value, reusing decoding work when the cache is uninitialized.
    ///
    /// This shares its cache with [`Self::get`], including failed decoding. The context must
    /// preserve ordinary decoding semantics as required by [`DecodeWith`]. Without `std`, this
    /// returns the value decoded eagerly at construction.
    pub fn get_with(&self, context: &T::Context) -> Option<&T> {
        #[cfg(feature = "std")]
        {
            self.initialize_with(|bytes, cfg| T::decode_with(bytes, cfg, context))
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = context;
            self.value.as_ref()
        }
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

impl<T: Read + PartialEq> PartialEq for Lazy<T> {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl<T: Read + Eq> Eq for Lazy<T> {}

impl<T: Read + PartialOrd> PartialOrd for Lazy<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.get().partial_cmp(&other.get())
    }
}

impl<T: Read + Ord> Ord for Lazy<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}

impl<T: Read + Hash> Hash for Lazy<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.get().hash(state);
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
    use crate::{Decode, DecodeExt, DecodeWith, Encode, Error, FixedSize, Read, Write};
    use proptest::prelude::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    #[cfg(feature = "std")]
    use std::{sync::Barrier, thread};

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

        fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, crate::Error> {
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

    #[derive(Default)]
    struct DecodeCalls {
        ordinary: AtomicUsize,
        contextual: AtomicUsize,
    }

    #[derive(Clone)]
    struct CountingCfg {
        max: u8,
        calls: Arc<DecodeCalls>,
    }

    impl CountingCfg {
        fn new(max: u8) -> Self {
            Self {
                max,
                calls: Arc::default(),
            }
        }

        fn counts(&self) -> (usize, usize) {
            (
                self.calls.ordinary.load(Ordering::Relaxed),
                self.calls.contextual.load(Ordering::Relaxed),
            )
        }
    }

    /// A configured byte that also accepts encodings with the high bit set.
    #[derive(Debug, PartialEq, Eq)]
    struct CachedByte(u8);

    impl FixedSize for CachedByte {
        const SIZE: usize = 1;
    }

    impl Write for CachedByte {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            self.0.write(buf);
        }
    }

    impl Read for CachedByte {
        type Cfg = CountingCfg;

        fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
            cfg.calls.ordinary.fetch_add(1, Ordering::Relaxed);
            let value = u8::read_cfg(buf, &())? & 0x7f;
            if value > cfg.max {
                return Err(Error::Invalid("CachedByte", "value exceeds maximum"));
            }
            Ok(Self(value))
        }
    }

    struct ByteContext {
        encoding: u8,
        value: u8,
    }

    impl ByteContext {
        fn new(encoding: u8) -> Self {
            Self {
                encoding,
                value: encoding & 0x7f,
            }
        }
    }

    impl DecodeWith for CachedByte {
        type Context = ByteContext;

        fn decode_with(
            bytes: &[u8],
            cfg: &Self::Cfg,
            context: &Self::Context,
        ) -> Result<Self, Error> {
            cfg.calls.contextual.fetch_add(1, Ordering::Relaxed);
            if bytes.first() != Some(&context.encoding) {
                return Self::decode_cfg(bytes, cfg);
            }
            if context.value > cfg.max {
                return Err(Error::Invalid("CachedByte", "value exceeds maximum"));
            }
            if bytes.len() > Self::SIZE {
                return Err(Error::ExtraData(bytes.len() - Self::SIZE));
            }
            Ok(Self(context.value))
        }
    }

    #[test]
    fn contextual_and_ordinary_access_share_cache() {
        for contextual_first in [false, true] {
            let cfg = CountingCfg::new(10);
            let lazy = Lazy::<CachedByte>::deferred(&mut &[0x87][..], cfg.clone());
            let context = ByteContext::new(0x87);
            if cfg!(feature = "std") {
                assert_eq!(lazy.get_cached(), None);
                assert_eq!(cfg.counts(), (0, 0));
            } else {
                assert_eq!(lazy.get_cached(), Some(Some(&CachedByte(7))));
                assert_eq!(cfg.counts(), (1, 0));
            }

            let value = if contextual_first {
                lazy.get_with(&context)
            } else {
                lazy.get()
            }
            .unwrap();
            assert_eq!(value, &CachedByte(7));
            assert!(core::ptr::eq(value, lazy.get().unwrap()));
            assert!(core::ptr::eq(value, lazy.get_with(&context).unwrap()));
            assert_eq!(lazy.get_cached(), Some(Some(value)));
            let expected = if cfg!(feature = "std") && contextual_first {
                (0, 1)
            } else {
                (1, 0)
            };
            assert_eq!(cfg.counts(), expected);
        }

        let lazy = Lazy::new(CachedByte(7));
        assert_eq!(lazy.get_cached(), Some(Some(&CachedByte(7))));
        assert_eq!(lazy.get_with(&ByteContext::new(12)), Some(&CachedByte(7)));
    }

    #[test]
    fn contextual_and_ordinary_access_cache_failures() {
        for contextual_first in [false, true] {
            let cfg = CountingCfg::new(6);
            let lazy = Lazy::<CachedByte>::deferred(&mut &[7][..], cfg.clone());
            let context = ByteContext::new(7);
            if contextual_first {
                assert_eq!(lazy.get_with(&context), None);
            } else {
                assert_eq!(lazy.get(), None);
            }
            assert_eq!(lazy.get_cached(), Some(None));
            assert_eq!(lazy.get(), None);
            assert_eq!(lazy.get_with(&context), None);
            let expected = if cfg!(feature = "std") && contextual_first {
                (0, 1)
            } else {
                (1, 0)
            };
            assert_eq!(cfg.counts(), expected);
        }
    }

    #[test]
    fn contextual_decode_matches_ordinary_constraints() {
        let inputs: &[&[u8]] = &[&[], &[7], &[0x87], &[12], &[7, 0], &[12, 0]];
        for bytes in inputs {
            for max in [7, 20] {
                for encoding in [7, 0x87, 12] {
                    let cfg = CountingCfg::new(max);
                    let context = ByteContext::new(encoding);
                    let expected =
                        CachedByte::decode_cfg(*bytes, &cfg).map_err(|error| error.to_string());
                    let actual = CachedByte::decode_with(bytes, &cfg, &context)
                        .map_err(|error| error.to_string());
                    assert_eq!(actual, expected);

                    let mut encoded = *bytes;
                    let lazy = Lazy::<CachedByte>::deferred(&mut encoded, cfg);
                    assert_eq!(lazy.get_with(&context), expected.ok().as_ref());
                }
            }
        }
    }

    #[test]
    fn unrelated_context_falls_back_to_ordinary_decode() {
        let cfg = CountingCfg::new(10);
        let lazy = Lazy::<CachedByte>::deferred(&mut &[7][..], cfg.clone());
        assert_eq!(lazy.get_with(&ByteContext::new(8)), Some(&CachedByte(7)));
        assert_eq!(cfg.counts(), (1, usize::from(cfg!(feature = "std"))));
        assert_eq!(lazy.get(), Some(&CachedByte(7)));
        assert_eq!(cfg.counts(), (1, usize::from(cfg!(feature = "std"))));
    }

    #[test]
    fn contextual_decode_preserves_original_serialization() {
        for max in [6, 7] {
            let lazy = Lazy::<CachedByte>::deferred(&mut &[0x87][..], CountingCfg::new(max));
            assert_eq!(lazy.encode().as_ref(), &[0x87]);
            let value = lazy.get_with(&ByteContext::new(0x87));
            assert_eq!(value.is_some(), max == 7);
            assert_eq!(lazy.encode().as_ref(), &[0x87]);
            if let Some(value) = value {
                assert_eq!(value.encode().as_ref(), &[7]);
            }
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn concurrent_contextual_and_ordinary_access_initialize_once() {
        for max in [6, 7] {
            let cfg = CountingCfg::new(max);
            let lazy = Lazy::<CachedByte>::deferred(&mut &[7][..], cfg.clone());
            let context = ByteContext::new(7);
            let barrier = Barrier::new(3);
            thread::scope(|scope| {
                let ordinary = scope.spawn(|| {
                    barrier.wait();
                    lazy.get()
                });
                let contextual = scope.spawn(|| {
                    barrier.wait();
                    lazy.get_with(&context)
                });
                barrier.wait();
                let ordinary = ordinary.join().unwrap();
                let contextual = contextual.join().unwrap();
                assert_eq!(ordinary, contextual);
                assert_eq!(ordinary.is_some(), max == 7);
                if let Some(ordinary) = ordinary {
                    assert!(core::ptr::eq(ordinary, contextual.unwrap()));
                }
            });
            let (ordinary, contextual) = cfg.counts();
            assert_eq!(ordinary + contextual, 1);
            assert_eq!(lazy.get_cached().unwrap().is_some(), max == 7);
        }
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
}
