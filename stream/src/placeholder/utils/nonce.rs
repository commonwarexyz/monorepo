use chacha20poly1305::Nonce;

pub fn encode(dialer: bool, iter: u16, seq: u64) -> Nonce {
    let mut result = Nonce::default();
    if dialer {
        result[0] = 0b10000000; // Set the first bit of the byte
    }
    if iter > 0 {
        result[2..4].copy_from_slice(&iter.to_be_bytes());
    }
    result[4..].copy_from_slice(&seq.to_be_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        // Test case 1: dialer is true
        let nonce = encode(true, 1, 1);
        assert_eq!(nonce[0], 0b10000000);
        assert_eq!(&nonce[2..4], &1u16.to_be_bytes());
        assert_eq!(&nonce[4..], &1u64.to_be_bytes());

        // Test case 2: dialer is false
        let nonce = encode(false, 1, 1);
        assert_eq!(nonce[0], 0b00000000);
        assert_eq!(&nonce[2..4], &1u16.to_be_bytes());
        assert_eq!(&nonce[4..], &1u64.to_be_bytes());

        // Test case 3: different iter and seq values
        let nonce = encode(true, 65535, 123456789);
        assert_eq!(nonce[0], 0b10000000);
        assert_eq!(&nonce[2..4], &65535u16.to_be_bytes());
        assert_eq!(&nonce[4..], &123456789u64.to_be_bytes());

        // Test case 4: iter is 0
        let nonce = encode(true, 0, 123456789);
        assert_eq!(nonce[0], 0b10000000);
        assert_eq!(&nonce[2..4], &0u16.to_be_bytes());
        assert_eq!(&nonce[4..], &123456789u64.to_be_bytes());
    }
}
