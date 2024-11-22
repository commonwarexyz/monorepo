use chacha20poly1305::Nonce;

pub fn nonce_bytes(dialer: bool, iter: u16, seq: u64) -> Nonce {
    let mut nonce_bytes = Nonce::default();
    if dialer {
        nonce_bytes[0] = 0b10000000; // Set the first bit of the byte
    }
    if iter > 0 {
        nonce_bytes[2..4].copy_from_slice(&iter.to_be_bytes());
    }
    nonce_bytes[4..].copy_from_slice(&seq.to_be_bytes());
    nonce_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_bytes() {
        // Test case 1: dialer is true
        let nonce = nonce_bytes(true, 1, 1);
        assert_eq!(nonce[0], 0b10000000);
        assert_eq!(&nonce[2..4], &1u16.to_be_bytes());
        assert_eq!(&nonce[4..], &1u64.to_be_bytes());

        // Test case 2: dialer is false
        let nonce = nonce_bytes(false, 1, 1);
        assert_eq!(nonce[0], 0b00000000);
        assert_eq!(&nonce[2..4], &1u16.to_be_bytes());
        assert_eq!(&nonce[4..], &1u64.to_be_bytes());

        // Test case 3: different iter and seq values
        let nonce = nonce_bytes(true, 65535, 123456789);
        assert_eq!(nonce[0], 0b10000000);
        assert_eq!(&nonce[2..4], &65535u16.to_be_bytes());
        assert_eq!(&nonce[4..], &123456789u64.to_be_bytes());

        // Test case 4: iter is 0
        let nonce = nonce_bytes(true, 0, 123456789);
        assert_eq!(nonce[0], 0b10000000);
        assert_eq!(&nonce[2..4], &0u16.to_be_bytes());
        assert_eq!(&nonce[4..], &123456789u64.to_be_bytes());
    }
}
