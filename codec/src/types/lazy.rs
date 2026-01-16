//! This module exports the [`Lazy`] type.
use crate::{Decode, Encode, EncodeSize, FixedSize, Read, Write};
use bytes::{Buf, Bytes};
use core::hash::Hash;
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
    proto: Option<Proto<T>>,
    value: OnceLock<Option<T>>,
}

#[derive(Clone)]
struct Proto<T: Read> {
    bytes: Bytes,
    cfg: T::Cfg,
}

impl<T: Read> Lazy<T> {
    // I considered calling this "now", but this was too close to "new".
    /// Create a [`Lazy`] using a value.
    pub fn new(value: T) -> Self {
        Self {
            proto: None,
            value: Some(value).into(),
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
        Self {
            proto: Some(Proto { bytes, cfg }),
            value: Default::default(),
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
    pub fn get(&self) -> Option<&T> {
        self.value
            .get_or_init(|| {
                let Proto { bytes, cfg } = self
                    .proto
                    .as_ref()
                    .expect("Lazy should have proto if value is not initialized");
                T::decode_cfg(bytes.clone(), cfg).ok()
            })
            .as_ref()
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
        if let Some(proto) = &self.proto {
            return proto.bytes.len();
        }
        self.get()
            .expect("Lazy should have a value if proto is None")
            .encode_size()
    }
}

impl<T: Read + Write> Write for Lazy<T> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        if let Some(proto) = &self.proto {
            proto.bytes.write(buf);
            return;
        }
        self.get()
            .expect("Lazy should have a value if proto is None")
            .write(buf);
    }
}

impl<T: Read + FixedSize> Read for Lazy<T> {
    type Cfg = T::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, crate::Error> {
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
    use crate::{DecodeExt, Encode, FixedSize, Read, Write};
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
