//! Leverage common functionality across multiple primitives.

use prost::{encode_length_delimiter, length_delimiter_len};
use sha2::{Digest, Sha256};

mod time;
pub use time::SystemTimeExt;
mod priority_set;
pub use priority_set::PrioritySet;

/// Converts bytes to a hexadecimal string.
pub fn hex(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for byte in bytes.iter() {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// Converts a hexadecimal string to bytes.
pub fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| match u8::from_str_radix(&hex[i..i + 2], 16) {
            Ok(byte) => Some(byte),
            Err(_) => None,
        })
        .collect()
}

/// Converts a hexadecimal string to bytes, stripping whitespace and/or a `0x` prefix. Commonly used
/// in testing to encode external test vectors without modification.
pub fn from_hex_formatted(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.replace(['\t', '\n', '\r', ' '], "");
    let res = hex.strip_prefix("0x").unwrap_or(&hex);
    from_hex(res)
}

/// Compute the maximum value of `f` (faults) that can be tolerated given `n = 3f + 1`.
pub fn max_faults(n: u32) -> Option<u32> {
    let f = n.checked_sub(1)? / 3;
    if f == 0 {
        return None;
    }
    Some(f)
}

/// Assuming that `n = 3f + 1`, compute the minimum size of `q` such that `q >= 2f + 1`.
///
/// If the value of `n` is too small to tolerate any faults, this function returns `None`.
pub fn quorum(n: u32) -> Option<u32> {
    let f = max_faults(n)?;
    Some((2 * f) + 1)
}

/// Hashes the given `Bytes` using SHA-256.
pub fn hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
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
    let ld_len = length_delimiter_len(namespace.len());
    let mut result = Vec::with_capacity(ld_len + namespace.len() + msg.len());
    encode_length_delimiter(namespace.len(), &mut result).unwrap();
    result.extend_from_slice(namespace);
    result.extend_from_slice(msg);
    result
}

/// Compute the modulo of bytes interpreted as a big-endian integer.
///
/// This function is used to select a random entry from an array
/// when the bytes are a random seed.
pub fn modulo(bytes: &[u8], n: u64) -> u64 {
    let mut result = 0;
    for &byte in bytes {
        result = (result << 8) | (byte as u64);
        result %= n;
    }
    result
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
    fn test_quorum() {
        // Test case 0: n = 3 (3*0 + 1)
        assert_eq!(quorum(3), None);

        // Test case 1: n = 4 (3*1 + 1)
        assert_eq!(quorum(4), Some(3));

        // Test case 2: n = 7 (3*2 + 1)
        assert_eq!(quorum(7), Some(5));

        // Test case 3: n = 10 (3*3 + 1)
        assert_eq!(quorum(10), Some(7));
    }

    #[test]
    fn test_hash() {
        // Test case 0: empty bytes
        let empty = hash(b"");
        assert_eq!(
            hex(&empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );

        // Test case 1: single byte
        let single = hash(b"a");
        assert_eq!(
            hex(&single),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        );

        // Test case 2: multiple bytes
        let multiple = hash(b"hello world");
        assert_eq!(
            hex(&multiple),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        );
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
        let n = 11u64;
        for i in 0..100 {
            let mut rng = StdRng::seed_from_u64(i);
            let bytes: [u8; 32] = rng.gen();
            let big_modulo = BigUint::from_bytes_be(&bytes) % n;
            let utils_modulo = modulo(&bytes, n);
            assert_eq!(big_modulo, BigUint::from(utils_modulo));
        }
    }
}
