//! Leverage common functionality across multiple primitives.

use bytes::{BufMut, BytesMut};
use commonware_codec::{EncodeSize, Write};
use std::time::Duration;

pub mod sequence;
pub use sequence::{Array, Span};
mod bitvec;
pub use bitvec::{BitIterator, BitVec};
pub mod channels;
mod time;
pub use time::{parse_duration, SystemTimeExt};
mod priority_set;
pub use priority_set::PrioritySet;
pub mod futures;
mod stable_buf;
pub use stable_buf::StableBuf;

/// Converts bytes to a hexadecimal string.
pub fn hex(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for byte in bytes.iter() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Converts a hexadecimal string to bytes.
pub fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Converts a hexadecimal string to bytes, stripping whitespace and/or a `0x` prefix. Commonly used
/// in testing to encode external test vectors without modification.
pub fn from_hex_formatted(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.replace(['\t', '\n', '\r', ' '], "");
    let res = hex.strip_prefix("0x").unwrap_or(&hex);
    from_hex(res)
}

/// Compute the maximum number of `f` (faults) that can be tolerated for a given set of `n`
/// participants. This is the maximum integer `f` such that `n >= 3*f + 1`. `f` may be zero.
pub fn max_faults(n: u32) -> u32 {
    n.saturating_sub(1) / 3
}

/// Compute the quorum size for a given set of `n` participants. This is the minimum integer `q`
/// such that `3*q >= 2*n + 1`. It is also equal to `n - f`, where `f` is the maximum number of
/// faults.
///
/// # Panics
///
/// Panics if `n` is zero.
pub fn quorum(n: u32) -> u32 {
    assert!(n > 0, "n must not be zero");
    n - max_faults(n)
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
pub fn union_unique(namespace: &[u8], msg: &[u8]) -> Vec<u8> {
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
#[macro_export]
macro_rules! NZUsize {
    ($val:expr) => {
        // This will panic at runtime if $val is zero.
        // For literals, the compiler *might* optimize, but the check is still conceptually there.
        std::num::NonZeroUsize::new($val).expect("value must be non-zero")
    };
}

/// A macro to create a `NonZeroU8` from a value, panicking if the value is zero.
#[macro_export]
macro_rules! NZU8 {
    ($val:expr) => {
        std::num::NonZeroU8::new($val).expect("value must be non-zero")
    };
}

/// A macro to create a `NonZeroU16` from a value, panicking if the value is zero.
#[macro_export]
macro_rules! NZU16 {
    ($val:expr) => {
        std::num::NonZeroU16::new($val).expect("value must be non-zero")
    };
}

/// A macro to create a `NonZeroU32` from a value, panicking if the value is zero.
#[macro_export]
macro_rules! NZU32 {
    ($val:expr) => {
        // This will panic at runtime if $val is zero.
        // For literals, the compiler *might* optimize, but the check is still conceptually there.
        std::num::NonZeroU32::new($val).expect("value must be non-zero")
    };
}

/// A macro to create a `NonZeroU64` from a value, panicking if the value is zero.
#[macro_export]
macro_rules! NZU64 {
    ($val:expr) => {
        // This will panic at runtime if $val is zero.
        // For literals, the compiler *might* optimize, but the check is still conceptually there.
        std::num::NonZeroU64::new($val).expect("value must be non-zero")
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
    pub fn get(self) -> Duration {
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
        let b = &[0x01];
        let h = hex(b);
        assert_eq!(h, "01");
        assert_eq!(from_hex(&h).unwrap(), b.to_vec());

        // Test case 2: multiple bytes
        let b = &[0x01, 0x02, 0x03];
        let h = hex(b);
        assert_eq!(h, "010203");
        assert_eq!(from_hex(&h).unwrap(), b.to_vec());

        // Test case 3: odd number of bytes
        let h = "0102030";
        assert!(from_hex(h).is_none());

        // Test case 4: invalid hexadecimal character
        let h = "01g3";
        assert!(from_hex(h).is_none());
    }

    #[test]
    fn test_from_hex_formatted() {
        // Test case 0: empty bytes
        let b = &[];
        let h = hex(b);
        assert_eq!(h, "");
        assert_eq!(from_hex_formatted(&h).unwrap(), b.to_vec());

        // Test case 1: single byte
        let b = &[0x01];
        let h = hex(b);
        assert_eq!(h, "01");
        assert_eq!(from_hex_formatted(&h).unwrap(), b.to_vec());

        // Test case 2: multiple bytes
        let b = &[0x01, 0x02, 0x03];
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
    fn test_max_faults_zero() {
        assert_eq!(max_faults(0), 0);
    }

    #[test]
    #[should_panic]
    fn test_quorum_zero() {
        quorum(0);
    }

    #[test]
    fn test_quorum_and_max_faults() {
        // n, expected_f, expected_q
        let test_cases = [
            (1, 0, 1),
            (2, 0, 2),
            (3, 0, 3),
            (4, 1, 3),
            (5, 1, 4),
            (6, 1, 5),
            (7, 2, 5),
            (8, 2, 6),
            (9, 2, 7),
            (10, 3, 7),
            (11, 3, 8),
            (12, 3, 9),
            (13, 4, 9),
            (14, 4, 10),
            (15, 4, 11),
            (16, 5, 11),
            (17, 5, 12),
            (18, 5, 13),
            (19, 6, 13),
            (20, 6, 14),
            (21, 6, 15),
        ];

        for (n, ef, eq) in test_cases {
            assert_eq!(max_faults(n), ef);
            assert_eq!(quorum(n), eq);
            assert_eq!(n, ef + eq);
        }
    }

    #[test]
    fn test_union() {
        // Test case 0: empty slices
        assert_eq!(union(&[], &[]), []);

        // Test case 1: empty and non-empty slices
        assert_eq!(union(&[], &[0x01, 0x02, 0x03]), [0x01, 0x02, 0x03]);

        // Test case 2: non-empty and non-empty slices
        assert_eq!(
            union(&[0x01, 0x02, 0x03], &[0x04, 0x05, 0x06]),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
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
        assert_eq!(modulo(&[0x01], 1), 0);

        // Test case 2: multiple bytes
        assert_eq!(modulo(&[0x01, 0x02, 0x03], 10), 1);

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
        modulo(&[0x01, 0x02, 0x03], 0);
    }

    #[test]
    fn test_non_zero_macros() {
        // Test case 0: zero value
        assert!(std::panic::catch_unwind(|| NZUsize!(0)).is_err());
        assert!(std::panic::catch_unwind(|| NZU32!(0)).is_err());
        assert!(std::panic::catch_unwind(|| NZU64!(0)).is_err());
        assert!(std::panic::catch_unwind(|| NZDuration!(Duration::ZERO)).is_err());

        // Test case 1: non-zero value
        assert_eq!(NZUsize!(1).get(), 1);
        assert_eq!(NZU32!(2).get(), 2);
        assert_eq!(NZU64!(3).get(), 3);
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
}
