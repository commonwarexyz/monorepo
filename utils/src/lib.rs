//! Leverage common functionality across multiple primitives.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

commonware_macros::stability_scope!(ALPHA, cfg(feature = "std") {
    pub use rng::{FuzzRng, TestRng, test_rng};
});
commonware_macros::stability_scope!(BETA {
    #[cfg(not(feature = "std"))]
    extern crate alloc;

    #[cfg(not(feature = "std"))]
    use alloc::{boxed::Box, vec::Vec};
    use bytes::{BufMut, BytesMut};
    use core::time::Duration;
    pub mod faults;
    pub use faults::{Faults, N3f1, N5f1};

    pub mod sequence;
    pub use sequence::{Array, Span};

    pub mod hostname;
    pub use hostname::Hostname;

    pub mod bitmap;
    pub mod cache;
    pub mod ordered;
    pub mod range;

    use bytes::Buf;
    use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write, varint::UInt};

    /// 64-bit golden-ratio-derived odd mixing constant.
    ///
    /// Equal to `floor(2^64 / phi)`. Because it is odd, multiplication by it
    /// is a bijection modulo `2^64`.
    pub const GOLDEN_RATIO: u64 = 0x9e37_79b9_7f4a_7c15;

    /// Represents a participant/validator index within a consensus committee.
    ///
    /// Participant indices are used to identify validators in attestations,
    /// votes, and certificates. The index corresponds to the position of the
    /// validator's public key in the ordered participant set.
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct Participant(u32);

    impl Participant {
        /// Creates a new participant from a u32 index.
        pub const fn new(index: u32) -> Self {
            Self(index)
        }

        /// Creates a new participant from a usize index.
        ///
        /// # Panics
        ///
        /// Panics if `index` exceeds `u32::MAX`.
        pub fn from_usize(index: usize) -> Self {
            Self(u32::try_from(index).expect("participant index exceeds u32::MAX"))
        }

        /// Returns the underlying u32 index.
        pub const fn get(self) -> u32 {
            self.0
        }
    }

    impl From<Participant> for usize {
        fn from(p: Participant) -> Self {
            p.0 as Self
        }
    }

    impl core::fmt::Display for Participant {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Read for Participant {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
            let value: u32 = UInt::read(buf)?.into();
            Ok(Self(value))
        }
    }

    impl Write for Participant {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            UInt(self.0).write(buf);
        }
    }

    impl EncodeSize for Participant {
        fn encode_size(&self) -> usize {
            UInt(self.0).encode_size()
        }
    }

    /// A type that can be constructed from an iterator, possibly failing.
    pub trait TryFromIterator<T>: Sized {
        /// The error type returned when construction fails.
        type Error;

        /// Attempts to construct `Self` from an iterator.
        fn try_from_iter<I: IntoIterator<Item = T>>(iter: I) -> Result<Self, Self::Error>;
    }

    /// Extension trait for iterators that provides fallible collection.
    pub trait TryCollect: Iterator + Sized {
        /// Attempts to collect elements into a collection that may fail.
        fn try_collect<C: TryFromIterator<Self::Item>>(self) -> Result<C, C::Error> {
            C::try_from_iter(self)
        }
    }

    impl<I: Iterator> TryCollect for I {}

    /// Alias for boxed errors that are `Send` and `Sync`.
    pub type BoxedError = Box<dyn core::error::Error + Send + Sync>;

    /// Computes the union of two byte slices.
    pub fn union(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut union = Vec::with_capacity(a.len() + b.len());
        union.extend_from_slice(a);
        union.extend_from_slice(b);
        union
    }

    /// Concatenate a namespace and a message, prepended by a varint encoding of the namespace length.
    ///
    /// This produces a unique byte sequence (i.e. no collisions) for each `(namespace, msg)` pair.
    pub fn union_unique(namespace: &[u8], msg: &[u8]) -> Vec<u8> {
        use commonware_codec::EncodeSize;
        let len_prefix = namespace.len();
        let mut buf =
            BytesMut::with_capacity(len_prefix.encode_size() + namespace.len() + msg.len());
        len_prefix.write(&mut buf);
        BufMut::put_slice(&mut buf, namespace);
        BufMut::put_slice(&mut buf, msg);
        buf.into()
    }

    /// Compute the modulo of bytes interpreted as a big-endian integer.
    ///
    /// This function is used to select a random entry from an array when the bytes are a random seed.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero.
    pub fn modulo(bytes: &[u8], n: u64) -> u64 {
        assert_ne!(n, 0, "modulus must be non-zero");

        let n = n as u128;
        let mut result = 0u128;
        for &byte in bytes {
            result = (result << 8) | (byte as u128);
            result %= n;
        }

        // Result is either 0 or modulo `n`, so we can safely cast to u64
        result as u64
    }

    /// A wrapper around `Duration` that guarantees the duration is non-zero.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct NonZeroDuration(Duration);

    impl NonZeroDuration {
        /// Creates a `NonZeroDuration` if the given duration is non-zero.
        pub fn new(duration: Duration) -> Option<Self> {
            if duration == Duration::ZERO {
                None
            } else {
                Some(Self(duration))
            }
        }

        /// Creates a `NonZeroDuration` from the given duration, panicking if it's zero.
        pub fn new_panic(duration: Duration) -> Self {
            Self::new(duration).expect("duration must be non-zero")
        }

        /// Returns the wrapped `Duration`.
        pub const fn get(self) -> Duration {
            self.0
        }
    }

    impl From<NonZeroDuration> for Duration {
        fn from(nz_duration: NonZeroDuration) -> Self {
            nz_duration.0
        }
    }

    /// An integer value no greater than `MAX`.
    ///
    /// The wrapped type can provide additional invariants. For example,
    /// `AtMost<NonZeroU32, 1024>` represents values in `1..=1024`.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_utils::AtMost;
    /// use core::num::NonZeroU32;
    ///
    /// type MessageSize = AtMost<NonZeroU32, 1024>;
    ///
    /// let size: MessageSize = AtMost!(512);
    /// assert_eq!(size.get(), 512);
    /// assert!(MessageSize::try_from(0).is_err());
    /// assert!(MessageSize::try_from(1025).is_err());
    /// ```
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct AtMost<T, const MAX: u32>(T);

    /// Literal construction support for [`AtMost!`].
    #[doc(hidden)]
    pub trait __AtMostLiteral<const VALUE: i128>: Sized {
        /// Primitive type accepted by the literal constructor.
        type Input: Copy;

        /// Validated `AtMost` value.
        const OUTPUT: Self;
    }

    impl<T: Copy, const MAX: u32> AtMost<T, MAX> {
        /// Returns the wrapped value.
        pub const fn into_inner(self) -> T {
            self.0
        }
    }

    macro_rules! impl_at_most {
        (primitive: $($ty:ty),+ $(,)?) => {
            $(
                impl<const MAX: u32> AtMost<$ty, MAX> {
                    /// Returns the value.
                    pub const fn get(self) -> $ty {
                        self.0
                    }

                    /// Creates a value if it does not exceed `MAX`.
                    pub const fn new(value: $ty) -> Option<Self> {
                        if MAX as u128 >= <$ty>::MAX as u128 || value <= MAX as $ty {
                            Some(Self(value))
                        } else {
                            None
                        }
                    }
                }

                impl<const MAX: u32> TryFrom<$ty> for AtMost<$ty, MAX> {
                    type Error = $ty;

                    fn try_from(value: $ty) -> Result<Self, Self::Error> {
                        Self::new(value).ok_or(value)
                    }
                }

                impl<const MAX: u32, const VALUE: i128> __AtMostLiteral<VALUE>
                    for AtMost<$ty, MAX>
                {
                    type Input = $ty;

                    const OUTPUT: Self = {
                        Self::new(VALUE as $ty).expect("value exceeds maximum")
                    };
                }
            )+
        };
        (nonzero: $(($ty:ty, $inner:ty)),+ $(,)?) => {
            $(
                impl<const MAX: u32> AtMost<$ty, MAX> {
                    /// Returns the value.
                    pub const fn get(self) -> $inner {
                        self.0.get()
                    }

                    /// Creates a value if it does not exceed `MAX`.
                    pub const fn new(value: $ty) -> Option<Self> {
                        let value_inner = value.get();
                        if MAX as u128 >= <$inner>::MAX as u128 || value_inner <= MAX as $inner {
                            Some(Self(value))
                        } else {
                            None
                        }
                    }
                }

                impl<const MAX: u32> TryFrom<$ty> for AtMost<$ty, MAX> {
                    type Error = $ty;

                    fn try_from(value: $ty) -> Result<Self, Self::Error> {
                        Self::new(value).ok_or(value)
                    }
                }

                impl<const MAX: u32> TryFrom<$inner> for AtMost<$ty, MAX> {
                    type Error = $inner;

                    fn try_from(value: $inner) -> Result<Self, Self::Error> {
                        <$ty>::new(value).and_then(Self::new).ok_or(value)
                    }
                }

                impl<const MAX: u32, const VALUE: i128> __AtMostLiteral<VALUE>
                    for AtMost<$ty, MAX>
                {
                    type Input = $inner;

                    const OUTPUT: Self = {
                        let value = <$ty>::new(VALUE as $inner)
                            .expect("value violates wrapped type invariant");
                        Self::new(value).expect("value exceeds maximum")
                    };
                }
            )+
        };
    }

    impl_at_most!(primitive: u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);
    impl_at_most!(nonzero:
        (core::num::NonZeroU8, u8),
        (core::num::NonZeroU16, u16),
        (core::num::NonZeroU32, u32),
        (core::num::NonZeroU64, u64),
        (core::num::NonZeroU128, u128),
        (core::num::NonZeroUsize, usize),
        (core::num::NonZeroI8, i8),
        (core::num::NonZeroI16, i16),
        (core::num::NonZeroI32, i32),
        (core::num::NonZeroI64, i64),
        (core::num::NonZeroI128, i128),
        (core::num::NonZeroIsize, isize),
    );

    /// An integer value within the inclusive range `MIN..=MAX`.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_utils::Within;
    ///
    /// type Participants = Within<usize, 2, 64>;
    ///
    /// let participants: Participants = Within!(5);
    /// assert_eq!(participants.get(), 5);
    /// assert!(Participants::try_from(1).is_err());
    /// assert!(Participants::try_from(65).is_err());
    /// ```
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Within<T, const MIN: u32, const MAX: u32>(T);

    impl<T: Copy, const MIN: u32, const MAX: u32> Within<T, MIN, MAX> {
        /// Returns the wrapped value.
        pub const fn into_inner(self) -> T {
            self.0
        }
    }

    macro_rules! impl_within {
        ($wide:ty; $($ty:ty),+ $(,)?) => {
            $(
                impl<const MIN: u32, const MAX: u32> Within<$ty, MIN, MAX> {
                    /// Returns the value.
                    pub const fn get(self) -> $ty {
                        self.0
                    }

                    /// Creates a value if it is within `MIN..=MAX`.
                    pub const fn new(value: $ty) -> Option<Self> {
                        let value_wide = value as $wide;
                        if value_wide >= MIN as $wide && value_wide <= MAX as $wide {
                            Some(Self(value))
                        } else {
                            None
                        }
                    }
                }

                impl<const MIN: u32, const MAX: u32> TryFrom<$ty> for Within<$ty, MIN, MAX> {
                    type Error = $ty;

                    fn try_from(value: $ty) -> Result<Self, Self::Error> {
                        Self::new(value).ok_or(value)
                    }
                }
            )+
        };
    }

    impl_within!(u128; u8, u16, u32, u64, u128, usize);
    impl_within!(i128; i8, i16, i32, i64, i128, isize);
});
commonware_macros::stability_scope!(BETA, cfg(feature = "std") {
    pub mod rng;
    pub use rng::sys_rng;

    pub mod acknowledgement;
    pub use acknowledgement::Acknowledgement;

    pub mod net;
    pub use net::IpAddrExt;

    pub mod time;
    pub use time::{DurationExt, SystemTimeExt};

    pub mod rational;
    pub use rational::BigRationalExt;

    mod priority_set;
    pub use priority_set::PrioritySet;

    pub mod channel;
    pub mod concurrency;
    pub mod futures;
    pub mod sync;

    pub mod thread_local;
    pub use thread_local::Cached;
});

/// Creates an [`AtMost`](struct@AtMost) value, panicking if the value exceeds its maximum.
///
/// Primitive and `NZU*` literals can be used in const contexts. The one-argument expression form
/// infers the result type and validates at runtime.
///
/// # Panics
///
/// Panics if the value exceeds the encoded maximum or violates an invariant of the wrapped type.
///
/// # Examples
///
/// ```
/// use commonware_utils::{AtMost, NZU32};
/// use core::num::NonZeroU32;
///
/// type MessageSize = AtMost<NonZeroU32, 1024>;
/// const MESSAGE_SIZE: MessageSize = AtMost!(NZU32!(512));
/// assert_eq!(MESSAGE_SIZE.get(), 512);
///
/// let inferred: MessageSize = AtMost!(256);
/// assert_eq!(inferred.get(), 256);
/// ```
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
#[macro_export]
macro_rules! AtMost {
    (NZUsize!($val:literal)) => {
        const {
            $crate::AtMost::<::core::num::NonZeroUsize, _>::new($crate::NZUsize!($val))
                .expect("value exceeds maximum")
        }
    };
    (NZUsize!($val:expr)) => {
        $crate::AtMost::<::core::num::NonZeroUsize, _>::new($crate::NZUsize!($val))
            .expect("value exceeds maximum")
    };
    (NZU8!($val:literal)) => {
        const {
            $crate::AtMost::<::core::num::NonZeroU8, _>::new($crate::NZU8!($val))
                .expect("value exceeds maximum")
        }
    };
    (NZU8!($val:expr)) => {
        $crate::AtMost::<::core::num::NonZeroU8, _>::new($crate::NZU8!($val))
            .expect("value exceeds maximum")
    };
    (NZU16!($val:literal)) => {
        const {
            $crate::AtMost::<::core::num::NonZeroU16, _>::new($crate::NZU16!($val))
                .expect("value exceeds maximum")
        }
    };
    (NZU16!($val:expr)) => {
        $crate::AtMost::<::core::num::NonZeroU16, _>::new($crate::NZU16!($val))
            .expect("value exceeds maximum")
    };
    (NZU32!($val:literal)) => {
        const {
            $crate::AtMost::<::core::num::NonZeroU32, _>::new($crate::NZU32!($val))
                .expect("value exceeds maximum")
        }
    };
    (NZU32!($val:expr)) => {
        $crate::AtMost::<::core::num::NonZeroU32, _>::new($crate::NZU32!($val))
            .expect("value exceeds maximum")
    };
    (NZU64!($val:literal)) => {
        const {
            $crate::AtMost::<::core::num::NonZeroU64, _>::new($crate::NZU64!($val))
                .expect("value exceeds maximum")
        }
    };
    (NZU64!($val:expr)) => {
        $crate::AtMost::<::core::num::NonZeroU64, _>::new($crate::NZU64!($val))
            .expect("value exceeds maximum")
    };
    ($ty:ty, $val:literal) => {
        const { $crate::AtMost::<$ty, _>::new($val).expect("value exceeds maximum") }
    };
    ($ty:ty, $val:expr) => {
        $crate::AtMost::<$ty, _>::new($val).expect("value exceeds maximum")
    };
    ($val:literal) => {
        const {
            const fn infer_at_most_literal<const VALUE: i128, T, const MAX: u32>(
                value: $crate::AtMost<T, MAX>,
                _: <$crate::AtMost<T, MAX> as $crate::__AtMostLiteral<VALUE>>::Input,
            ) -> $crate::AtMost<T, MAX>
            where
                $crate::AtMost<T, MAX>: $crate::__AtMostLiteral<VALUE>,
            {
                value
            }

            infer_at_most_literal::<{ $val as i128 }, _, _>(
                <_ as $crate::__AtMostLiteral<{ $val as i128 }>>::OUTPUT,
                $val,
            )
        }
    };
    ($val:expr) => {{
        fn infer_at_most<T, const MAX: u32>(
            value: $crate::AtMost<T, MAX>,
        ) -> $crate::AtMost<T, MAX> {
            value
        }

        infer_at_most(match ::core::convert::TryInto::try_into($val) {
            ::core::result::Result::Ok(value) => value,
            ::core::result::Result::Err(_) => panic!("value is outside allowed range"),
        })
    }};
}

/// Creates a [`Within`](struct@Within) value, panicking unless it is within the inclusive range.
///
/// Typed literals can be used in const contexts. The one-argument form infers the result type and
/// validates at runtime.
///
/// # Panics
///
/// Panics if the value is outside the inclusive range.
///
/// # Examples
///
/// ```
/// use commonware_utils::Within;
///
/// type Participants = Within<usize, 2, 64>;
/// const PARTICIPANTS: Participants = Within!(usize, 4);
/// assert_eq!(PARTICIPANTS.get(), 4);
///
/// let inferred: Participants = Within!(8);
/// assert_eq!(inferred.get(), 8);
/// ```
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
#[macro_export]
macro_rules! Within {
    ($ty:ty, $val:literal) => {
        const { $crate::Within::<$ty, _, _>::new($val).expect("value is outside allowed range") }
    };
    ($ty:ty, $val:expr) => {
        $crate::Within::<$ty, _, _>::new($val).expect("value is outside allowed range")
    };
    ($val:expr) => {{
        fn infer_within<T, const MIN: u32, const MAX: u32>(
            value: $crate::Within<T, MIN, MAX>,
        ) -> $crate::Within<T, MIN, MAX> {
            value
        }

        infer_within(match ::core::convert::TryInto::try_into($val) {
            ::core::result::Result::Ok(value) => value,
            ::core::result::Result::Err(_) => panic!("value is outside allowed range"),
        })
    }};
}

#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
pub mod vec;

/// A macro to create a `NonZeroUsize` from a value, panicking if the value is zero.
/// For literal values, validation occurs at compile time. For expressions, validation
/// occurs at runtime.
#[macro_export]
macro_rules! NZUsize {
    ($val:literal) => {
        const { ::core::num::NonZeroUsize::new($val).expect("value must be non-zero") }
    };
    ($val:expr) => {
        // This will panic at runtime if $val is zero.
        ::core::num::NonZeroUsize::new($val).expect("value must be non-zero")
    };
}

/// A macro to create a `NonZeroU8` from a value, panicking if the value is zero.
/// For literal values, validation occurs at compile time. For expressions, validation
/// occurs at runtime.
#[macro_export]
macro_rules! NZU8 {
    ($val:literal) => {
        const { ::core::num::NonZeroU8::new($val).expect("value must be non-zero") }
    };
    ($val:expr) => {
        // This will panic at runtime if $val is zero.
        ::core::num::NonZeroU8::new($val).expect("value must be non-zero")
    };
}

/// A macro to create a `NonZeroU16` from a value, panicking if the value is zero.
/// For literal values, validation occurs at compile time. For expressions, validation
/// occurs at runtime.
#[macro_export]
macro_rules! NZU16 {
    ($val:literal) => {
        const { ::core::num::NonZeroU16::new($val).expect("value must be non-zero") }
    };
    ($val:expr) => {
        // This will panic at runtime if $val is zero.
        ::core::num::NonZeroU16::new($val).expect("value must be non-zero")
    };
}

/// A macro to create a `NonZeroU32` from a value, panicking if the value is zero.
/// For literal values, validation occurs at compile time. For expressions, validation
/// occurs at runtime.
#[macro_export]
macro_rules! NZU32 {
    ($val:literal) => {
        const { ::core::num::NonZeroU32::new($val).expect("value must be non-zero") }
    };
    ($val:expr) => {
        // This will panic at runtime if $val is zero.
        ::core::num::NonZeroU32::new($val).expect("value must be non-zero")
    };
}

/// A macro to create a `NonZeroU64` from a value, panicking if the value is zero.
/// For literal values, validation occurs at compile time. For expressions, validation
/// occurs at runtime.
#[macro_export]
macro_rules! NZU64 {
    ($val:literal) => {
        const { ::core::num::NonZeroU64::new($val).expect("value must be non-zero") }
    };
    ($val:expr) => {
        // This will panic at runtime if $val is zero.
        ::core::num::NonZeroU64::new($val).expect("value must be non-zero")
    };
}

/// Re-export of `commonware_formatting` so that the `fixed_bytes!` macro's
/// expansion can resolve `hex!` in any caller's namespace.
#[doc(hidden)]
pub use ::commonware_formatting as __formatting;

/// Macro for converting sequence of string literals containing hex-encoded data
/// into a [`crate::sequence::FixedBytes`] type.
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
#[macro_export]
macro_rules! fixed_bytes {
    ($s:tt) => {
        const { $crate::sequence::FixedBytes::new($crate::__formatting::hex!($s)) }
    };
}

/// A macro to create a `NonZeroDuration` from a duration, panicking if the duration is zero.
#[macro_export]
macro_rules! NZDuration {
    ($val:expr) => {
        // This will panic at runtime if $val is zero.
        $crate::NonZeroDuration::new_panic($val)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestRng;
    use commonware_formatting::hex;
    use num_bigint::BigUint;
    use rand::RngExt as _;

    #[test]
    fn test_union() {
        // Test case 0: empty slices
        assert_eq!(union(&[], &[]), Vec::<u8>::new());

        // Test case 1: empty and non-empty slices
        assert_eq!(union(&[], &hex!("0x010203")), hex!("0x010203"));

        // Test case 2: non-empty and non-empty slices
        assert_eq!(
            union(&hex!("0x010203"), &hex!("0x040506")),
            hex!("0x010203040506")
        );
    }

    #[test]
    fn test_union_unique() {
        let namespace = b"namespace";
        let msg = b"message";

        let length_encoding = vec![0b0000_1001];
        let mut expected = Vec::with_capacity(length_encoding.len() + namespace.len() + msg.len());
        expected.extend_from_slice(&length_encoding);
        expected.extend_from_slice(namespace);
        expected.extend_from_slice(msg);

        let result = union_unique(namespace, msg);
        assert_eq!(result, expected);
        assert_eq!(result.len(), result.capacity());
    }

    #[test]
    fn test_union_unique_zero_length() {
        let namespace = b"";
        let msg = b"message";

        let length_encoding = vec![0];
        let mut expected = Vec::with_capacity(length_encoding.len() + namespace.len() + msg.len());
        expected.extend_from_slice(&length_encoding);
        expected.extend_from_slice(msg);

        let result = union_unique(namespace, msg);
        assert_eq!(result, expected);
        assert_eq!(result.len(), result.capacity());
    }

    #[test]
    fn test_union_unique_long_length() {
        // Use a namespace of over length 127.
        let namespace = &b"n".repeat(256);
        let msg = b"message";

        let length_encoding = vec![0b1000_0000, 0b0000_0010];
        let mut expected = Vec::with_capacity(length_encoding.len() + namespace.len() + msg.len());
        expected.extend_from_slice(&length_encoding);
        expected.extend_from_slice(namespace);
        expected.extend_from_slice(msg);

        let result = union_unique(namespace, msg);
        assert_eq!(result, expected);
        assert_eq!(result.len(), result.capacity());
    }

    #[test]
    fn test_modulo() {
        // Test case 0: empty bytes
        assert_eq!(modulo(&[], 1), 0);

        // Test case 1: single byte
        assert_eq!(modulo(&hex!("0x01"), 1), 0);

        // Test case 2: multiple bytes
        assert_eq!(modulo(&hex!("0x010203"), 10), 1);

        // Test case 3: check equivalence with BigUint
        for i in 0..100 {
            let mut rng = TestRng::new(i);
            let bytes: [u8; 32] = rng.random();

            // 1-byte modulus
            let n = 11u64;
            let big_modulo = BigUint::from_bytes_be(&bytes) % n;
            let utils_modulo = modulo(&bytes, n);
            assert_eq!(big_modulo, BigUint::from(utils_modulo));

            // 2-byte modulus
            let n = 11_111u64;
            let big_modulo = BigUint::from_bytes_be(&bytes) % n;
            let utils_modulo = modulo(&bytes, n);
            assert_eq!(big_modulo, BigUint::from(utils_modulo));

            // 8-byte modulus
            let n = 0xDFFFFFFFFFFFFFFD;
            let big_modulo = BigUint::from_bytes_be(&bytes) % n;
            let utils_modulo = modulo(&bytes, n);
            assert_eq!(big_modulo, BigUint::from(utils_modulo));
        }
    }

    #[test]
    #[should_panic]
    fn test_modulo_zero_panics() {
        modulo(&hex!("0x010203"), 0);
    }

    #[test]
    fn test_non_zero_macros_compile_time() {
        // Literal values are validated at compile time.
        // NZU32!(0) would be a compile error.
        assert_eq!(NZUsize!(1).get(), 1);
        assert_eq!(NZU8!(2).get(), 2);
        assert_eq!(NZU16!(3).get(), 3);
        assert_eq!(NZU32!(4).get(), 4);
        assert_eq!(NZU64!(5).get(), 5);

        // Literals can be used in const contexts
        const _: core::num::NonZeroUsize = NZUsize!(1);
        const _: core::num::NonZeroU8 = NZU8!(2);
        const _: core::num::NonZeroU16 = NZU16!(3);
        const _: core::num::NonZeroU32 = NZU32!(4);
        const _: core::num::NonZeroU64 = NZU64!(5);
    }

    #[test]
    fn test_non_zero_macros_runtime() {
        // Runtime variables are validated at runtime
        let one_usize: usize = 1;
        let two_u8: u8 = 2;
        let three_u16: u16 = 3;
        let four_u32: u32 = 4;
        let five_u64: u64 = 5;

        assert_eq!(NZUsize!(one_usize).get(), 1);
        assert_eq!(NZU8!(two_u8).get(), 2);
        assert_eq!(NZU16!(three_u16).get(), 3);
        assert_eq!(NZU32!(four_u32).get(), 4);
        assert_eq!(NZU64!(five_u64).get(), 5);

        // Zero runtime values panic
        let zero_usize: usize = 0;
        let zero_u8: u8 = 0;
        let zero_u16: u16 = 0;
        let zero_u32: u32 = 0;
        let zero_u64: u64 = 0;

        assert!(std::panic::catch_unwind(|| NZUsize!(zero_usize)).is_err());
        assert!(std::panic::catch_unwind(|| NZU8!(zero_u8)).is_err());
        assert!(std::panic::catch_unwind(|| NZU16!(zero_u16)).is_err());
        assert!(std::panic::catch_unwind(|| NZU32!(zero_u32)).is_err());
        assert!(std::panic::catch_unwind(|| NZU64!(zero_u64)).is_err());

        // NZDuration is runtime-only since Duration has no literal syntax
        assert!(std::panic::catch_unwind(|| NZDuration!(Duration::ZERO)).is_err());
        assert_eq!(
            NZDuration!(Duration::from_secs(1)).get(),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn test_at_most_const_literal_inference() {
        const VALUE: AtMost<u32, 21> = AtMost!(1);
        const MAXIMUM: AtMost<u32, { u32::MAX }> = AtMost!(4_294_967_295);

        assert_eq!(VALUE.get(), 1);
        assert_eq!(MAXIMUM.get(), u32::MAX);
    }

    #[test]
    fn test_at_most_const_negative_literal_inference() {
        const PRIMITIVE: AtMost<i32, 21> = AtMost!(-1);
        const NON_ZERO: AtMost<core::num::NonZeroI32, 21> = AtMost!(-1);
        const LARGE: AtMost<i64, 21> = AtMost!(-2_147_483_649);
        const MINIMUM: AtMost<i8, 21> = AtMost!(-128i8);

        assert_eq!(PRIMITIVE.get(), -1);
        assert_eq!(NON_ZERO.get(), -1);
        assert_eq!(LARGE.get(), -2_147_483_649);
        assert_eq!(MINIMUM.get(), i8::MIN);
    }

    #[test]
    fn test_at_most_bounds() {
        type MessageSize = AtMost<core::num::NonZeroU32, 1024>;
        type OptionalSize = AtMost<u32, 1024>;

        const MAXIMUM: MessageSize = AtMost!(NZU32!(1024));
        const MAXIMUM_VALUE: u32 = MAXIMUM.get();
        const MAXIMUM_INNER: core::num::NonZeroU32 = MAXIMUM.into_inner();
        const ZERO: OptionalSize = AtMost!(u32, 0);

        assert_eq!(MAXIMUM_VALUE, 1024);
        assert_eq!(MAXIMUM_INNER, NZU32!(1024));
        assert_eq!(ZERO.get(), 0);
        assert_eq!(MessageSize::new(NZU32!(1)).unwrap().get(), 1);
        assert_eq!(MessageSize::new(NZU32!(1025)), None);

        let wrapped = MessageSize::try_from(512).unwrap();
        assert_eq!(wrapped.get(), 512);
        let inferred: MessageSize = AtMost!(512);
        assert_eq!(inferred.get(), 512);
        assert!(MessageSize::try_from(0).is_err());
        assert!(MessageSize::try_from(1025).is_err());

        let zero = 0;
        let too_large = 1025;
        assert!(
            std::panic::catch_unwind(|| {
                let _: MessageSize = AtMost!(zero);
            })
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| {
                let _: OptionalSize = AtMost!(too_large);
            })
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| {
                let _: MessageSize = AtMost!(NZU32!(too_large));
            })
            .is_err()
        );
    }

    #[test]
    fn test_within_bounds() {
        type Participants = Within<usize, 2, 64>;
        type SignedRange = Within<i16, 2, 64>;

        const MINIMUM: Participants = Within!(usize, 2);
        const MAXIMUM: Participants = Within!(usize, 64);
        const MINIMUM_INNER: usize = MINIMUM.into_inner();

        assert_eq!(MINIMUM.get(), 2);
        assert_eq!(MAXIMUM.get(), 64);
        assert_eq!(MINIMUM_INNER, 2);

        let inferred: Participants = Within!(8);
        assert_eq!(inferred.get(), 8);
        assert!(Participants::try_from(1).is_err());
        assert!(Participants::try_from(65).is_err());
        assert!(SignedRange::try_from(-1).is_err());
        assert_eq!(SignedRange::try_from(2).unwrap().get(), 2);
        assert!(Within::<u32, 5, 4>::try_from(5).is_err());
        assert!(Within::<u8, 256, 300>::try_from(u8::MAX).is_err());

        for outside in [1, 65] {
            assert!(
                std::panic::catch_unwind(|| {
                    let _: Participants = Within!(outside);
                })
                .is_err()
            );
        }
    }

    #[test]
    fn test_non_zero_duration() {
        // Test case 0: zero duration
        assert!(NonZeroDuration::new(Duration::ZERO).is_none());

        // Test case 1: non-zero duration
        let duration = Duration::from_millis(100);
        let nz_duration = NonZeroDuration::new(duration).unwrap();
        assert_eq!(nz_duration.get(), duration);
        assert_eq!(Duration::from(nz_duration), duration);

        // Test case 2: panic on zero
        assert!(std::panic::catch_unwind(|| NonZeroDuration::new_panic(Duration::ZERO)).is_err());

        // Test case 3: ordering
        let d1 = NonZeroDuration::new(Duration::from_millis(100)).unwrap();
        let d2 = NonZeroDuration::new(Duration::from_millis(200)).unwrap();
        assert!(d1 < d2);
    }

    #[test]
    fn test_participant_constructors() {
        assert_eq!(Participant::new(0).get(), 0);
        assert_eq!(Participant::new(42).get(), 42);
        assert_eq!(Participant::from_usize(0).get(), 0);
        assert_eq!(Participant::from_usize(42).get(), 42);
        assert_eq!(Participant::from_usize(u32::MAX as usize).get(), u32::MAX);
    }

    #[test]
    #[should_panic(expected = "participant index exceeds u32::MAX")]
    fn test_participant_from_usize_overflow() {
        Participant::from_usize((u32::MAX as usize) + 1);
    }

    #[test]
    fn test_participant_display() {
        assert_eq!(format!("{}", Participant::new(0)), "0");
        assert_eq!(format!("{}", Participant::new(42)), "42");
        assert_eq!(format!("{}", Participant::new(1000)), "1000");
    }

    #[test]
    fn test_participant_ordering() {
        assert!(Participant::new(0) < Participant::new(1));
        assert!(Participant::new(5) < Participant::new(10));
        assert!(Participant::new(10) > Participant::new(5));
        assert_eq!(Participant::new(42), Participant::new(42));
    }

    #[test]
    fn test_participant_encode_decode() {
        use commonware_codec::{DecodeExt, Encode};

        let cases = vec![0u32, 1, 127, 128, 255, 256, u32::MAX];
        for value in cases {
            let participant = Participant::new(value);
            let encoded = participant.encode();
            assert_eq!(encoded.len(), participant.encode_size());
            let decoded = Participant::decode(encoded).unwrap();
            assert_eq!(participant, decoded);
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Participant>,
        }
    }
}
