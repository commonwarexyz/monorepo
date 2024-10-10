//! Leverage common functionality across multiple primitives.

use bytes::Bytes;
use sha2::{Digest, Sha256};

/// Converts a byte slice to a hexadecimal string.
pub fn hex(bytes: &Bytes) -> String {
    let mut hex = String::new();
    for byte in bytes.iter() {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
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
pub fn hash(bytes: &Bytes) -> Bytes {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex() {
        // Test case 0: empty bytes
        assert_eq!(hex(&Bytes::new()), "");

        // Test case 1: single byte
        assert_eq!(hex(&Bytes::from_static(&[0x01])), "01");

        // Test case 2: multiple bytes
        assert_eq!(hex(&Bytes::from_static(&[0x01, 0x02, 0x03])), "010203");
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
        let empty = hash(&Bytes::from_static(b""));
        assert_eq!(
            hex(&empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );

        // Test case 1: single byte
        let single = hash(&Bytes::from_static(b"a"));
        assert_eq!(
            hex(&single),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        );

        // Test case 2: multiple bytes
        let multiple = hash(&Bytes::from_static(b"hello world"));
        assert_eq!(
            hex(&multiple),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        );
    }
}
