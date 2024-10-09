/// TBD
use bytes::Bytes;

/// Converts a byte slice to a hexadecimal string.
pub fn hex(bytes: &Bytes) -> String {
    let mut hex = String::new();
    for byte in bytes.iter() {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// Assuming that `n = 3f + 1`, compute the minimum required threshold to satisfy `t = 2f + 1`.
pub fn threshold(n: u32) -> Option<u32> {
    let f = (n - 1) / 3;
    if f == 0 {
        return None;
    }
    Some((2 * f) + 1)
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
    fn test_threshold() {
        // Test case 0: n = 3 (3*0 + 1)
        assert_eq!(threshold(3), None);

        // Test case 1: n = 4 (3*1 + 1)
        assert_eq!(threshold(4), Some(3));

        // Test case 2: n = 7 (3*2 + 1)
        assert_eq!(threshold(7), Some(5));

        // Test case 3: n = 10 (3*3 + 1)
        assert_eq!(threshold(10), Some(7));
    }
}
