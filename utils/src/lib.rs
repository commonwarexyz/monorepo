//! Leverage common functionality across multiple primitives.

use sha2::{Digest, Sha256};

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

/// Assuming that `n = 3f + 1`, compute the minimum size of `t` such that `t >= 2f + 1`.
pub fn quorum(n: u32) -> Option<u32> {
    let f = (n - 1) / 3;
    if f == 0 {
        return None;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
