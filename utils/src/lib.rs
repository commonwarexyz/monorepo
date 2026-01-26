//! Leverage common functionality across multiple primitives.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

/// Applies stability cfg attributes to an item.
///
/// Use this for modules containing `#[macro_export]` macros where proc macros don't work.
///
/// # Example
/// ```rust,ignore
/// commonware_utils::stability_cfg!(GAMMA, pub mod my_module;);
/// ```
#[macro_export]
macro_rules! stability_cfg {
    (ALPHA, $($item:tt)*) => {
        #[cfg(not(commonware_stability_BETA))]
        #[cfg(not(commonware_stability_GAMMA))]
        #[cfg(not(commonware_stability_DELTA))]
        #[cfg(not(commonware_stability_EPSILON))]
        $($item)*
    };
    (BETA, $($item:tt)*) => {
        #[cfg(not(commonware_stability_GAMMA))]
        #[cfg(not(commonware_stability_DELTA))]
        #[cfg(not(commonware_stability_EPSILON))]
        $($item)*
    };
    (GAMMA, $($item:tt)*) => {
        #[cfg(not(commonware_stability_DELTA))]
        #[cfg(not(commonware_stability_EPSILON))]
        $($item)*
    };
    (DELTA, $($item:tt)*) => {
        #[cfg(not(commonware_stability_EPSILON))]
        $($item)*
    };
    (EPSILON, $($item:tt)*) => {
        $($item)*
    };
}

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};
use bytes::{BufMut, BytesMut};
use core::{
    fmt::{Debug, Write as FmtWrite},
    time::Duration,
};

pub mod faults;
pub use faults::{Faults, N3f1, N5f1};
#[cfg(feature = "std")]
pub mod acknowledgement;
#[cfg(feature = "std")]
pub use acknowledgement::Acknowledgement;
#[cfg(feature = "std")]
pub mod channels;
pub mod hex_literal;
#[cfg(feature = "std")]
pub mod net;
pub mod vec;

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

commonware_macros::stability_scope!(GAMMA {
    use bytes::Buf;
    use commonware_codec::{varint::UInt, EncodeSize, Error as CodecError, Read, ReadExt, Write};

    pub mod sequence;
    pub use sequence::{Array, Span};
    pub mod bitmap;
    pub mod hostname;
    pub use hostname::Hostname;
    pub mod ordered;

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
});

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
#[cfg(feature = "std")]
pub use net::IpAddrExt;
#[cfg(feature = "std")]
pub mod time;
#[cfg(feature = "std")]
pub use time::{DurationExt, SystemTimeExt};
#[cfg(feature = "std")]
pub mod rational;
#[cfg(feature = "std")]
pub use rational::BigRationalExt;
#[cfg(feature = "std")]
mod priority_set;
#[cfg(feature = "std")]
pub use priority_set::PrioritySet;
#[cfg(feature = "std")]
pub mod concurrency;
#[cfg(feature = "std")]
pub mod futures;

/// Returns a seeded RNG for deterministic testing.
///
/// Uses seed 0 by default to ensure reproducible test results.
#[cfg(feature = "std")]
pub fn test_rng() -> rand::rngs::StdRng {
    rand::SeedableRng::seed_from_u64(0)
}

/// Returns a seeded RNG with a custom seed for deterministic testing.
///
/// Use this when you need multiple independent RNG streams in the same test,
/// or when a helper function needs its own RNG that won't collide with the caller's.
#[cfg(feature = "std")]
pub fn test_rng_seeded(seed: u64) -> rand::rngs::StdRng {
    rand::SeedableRng::seed_from_u64(seed)
}

/// Alias for boxed errors that are `Send` and `Sync`.
pub type BoxedError = Box<dyn core::error::Error + Send + Sync>;

/// Converts bytes to a hexadecimal string.
pub fn hex(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for byte in bytes.iter() {
        write!(hex, "{byte:02x}").expect("writing to string should never fail");
    }
    hex
}

/// Converts a hexadecimal string to bytes.
pub fn from_hex(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }

    bytes
        .chunks_exact(2)
        .map(|chunk| {
            let hi = decode_hex_digit(chunk[0])?;
            let lo = decode_hex_digit(chunk[1])?;
            Some((hi << 4) | lo)
        })
        .collect()
}

#[inline]
const fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Converts a hexadecimal string to bytes, stripping whitespace and/or a `0x` prefix. Commonly used
/// in testing to encode external test vectors without modification.
pub fn from_hex_formatted(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.replace(['\t', '\n', '\r', ' '], "");
    let res = hex.strip_prefix("0x").unwrap_or(&hex);
    from_hex(res)
}

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
#[commonware_macros::stability(GAMMA)]
pub fn union_unique(namespace: &[u8], msg: &[u8]) -> Vec<u8> {
    use commonware_codec::EncodeSize;
    let len_prefix = namespace.len();
    let mut buf = BytesMut::with_capacity(len_prefix.encode_size() + namespace.len() + msg.len());
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
    use num_bigint::BigUint;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn test_hex() {
        // Test case 0: empty bytes
        let b = &[];
        let h = hex(b);
        assert_eq!(h, "");
        assert_eq!(from_hex(&h).unwrap(), b.to_vec());

        // Test case 1: single byte
        let b = &hex!("0x01");
        let h = hex(b);
        assert_eq!(h, "01");
        assert_eq!(from_hex(&h).unwrap(), b.to_vec());

        // Test case 2: multiple bytes
        let b = &hex!("0x010203");
        let h = hex(b);
        assert_eq!(h, "010203");
        assert_eq!(from_hex(&h).unwrap(), b.to_vec());

        // Test case 3: odd number of bytes
        let h = "0102030";
        assert!(from_hex(h).is_none());

        // Test case 4: invalid hexadecimal character
        let h = "01g3";
        assert!(from_hex(h).is_none());

        // Test case 5: invalid `+` in string
        let h = "+123";
        assert!(from_hex(h).is_none());

        // Test case 6: empty string
        assert_eq!(from_hex(""), Some(vec![]));
    }

    #[test]
    fn test_from_hex_formatted() {
        // Test case 0: empty bytes
        let b = &[];
        let h = hex(b);
        assert_eq!(h, "");
        assert_eq!(from_hex_formatted(&h).unwrap(), b.to_vec());

        // Test case 1: single byte
        let b = &hex!("0x01");
        let h = hex(b);
        assert_eq!(h, "01");
        assert_eq!(from_hex_formatted(&h).unwrap(), b.to_vec());

        // Test case 2: multiple bytes
        let b = &hex!("0x010203");
        let h = hex(b);
        assert_eq!(h, "010203");
        assert_eq!(from_hex_formatted(&h).unwrap(), b.to_vec());

        // Test case 3: odd number of bytes
        let h = "0102030";
        assert!(from_hex_formatted(h).is_none());

        // Test case 4: invalid hexadecimal character
        let h = "01g3";
        assert!(from_hex_formatted(h).is_none());

        // Test case 5: whitespace
        let h = "01 02 03";
        assert_eq!(from_hex_formatted(h).unwrap(), b.to_vec());

        // Test case 6: 0x prefix
        let h = "0x010203";
        assert_eq!(from_hex_formatted(h).unwrap(), b.to_vec());

        // Test case 7: 0x prefix + different whitespace chars
        let h = "    \n\n0x\r\n01
                            02\t03\n";
        assert_eq!(from_hex_formatted(h).unwrap(), b.to_vec());
    }

    #[test]
    fn test_from_hex_utf8_char_boundaries() {
        const MISALIGNMENT_CASE: &str = "쀘\n";

        // Ensure that `from_hex` can handle misaligned UTF-8 character boundaries.
        let b = from_hex(MISALIGNMENT_CASE);
        assert!(b.is_none());
    }

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
            let mut rng = StdRng::seed_from_u64(i);
            let bytes: [u8; 32] = rng.gen();

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
