//! RNG utilities for testing and fuzzing.

use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};

/// An RNG that reads from a byte buffer, falling back to a seeded RNG when exhausted.
///
/// This is useful for fuzzing where you want the fuzzer to control randomness
/// through byte mutations. The raw bytes are consumed sequentially, and when
/// exhausted, a fallback RNG (seeded from the last 8 bytes) provides additional
/// randomness deterministically.
pub struct BytesRng {
    bytes: Vec<u8>,
    offset: usize,
    fallback: StdRng,
}

impl BytesRng {
    /// Creates a new `BytesRng` from a byte buffer.
    ///
    /// The fallback RNG is seeded from the last 8 bytes of the buffer (or fewer
    /// if the buffer is shorter than 8 bytes, zero-padded on the left).
    pub fn new(bytes: Vec<u8>) -> Self {
        let mut seed = [0u8; 8];
        let start = bytes.len().saturating_sub(8);
        let len = bytes.len().min(8);
        seed[..len].copy_from_slice(&bytes[start..]);
        let fallback = StdRng::seed_from_u64(u64::from_be_bytes(seed));
        Self {
            bytes,
            offset: 0,
            fallback,
        }
    }

    /// Returns the number of raw bytes remaining before fallback.
    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    /// Returns the total number of bytes consumed from the raw buffer.
    pub fn consumed(&self) -> usize {
        self.offset.min(self.bytes.len())
    }
}

impl RngCore for BytesRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_be_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_be_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            if self.offset < self.bytes.len() {
                *byte = self.bytes[self.offset];
                self.offset += 1;
            } else {
                *byte = self.fallback.next_u32() as u8;
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for BytesRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_bytes() {
        let mut rng = BytesRng::new(vec![]);
        assert_eq!(rng.remaining(), 0);
        assert_eq!(rng.consumed(), 0);

        // Should use fallback immediately
        let v1 = rng.next_u64();
        let v2 = rng.next_u64();
        assert_ne!(v1, v2); // Fallback should produce different values
    }

    #[test]
    fn test_consumes_bytes_in_order() {
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut rng = BytesRng::new(bytes);

        assert_eq!(rng.remaining(), 8);
        assert_eq!(rng.consumed(), 0);

        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [1, 2, 3, 4]);
        assert_eq!(rng.remaining(), 4);
        assert_eq!(rng.consumed(), 4);

        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [5, 6, 7, 8]);
        assert_eq!(rng.remaining(), 0);
        assert_eq!(rng.consumed(), 8);
    }

    #[test]
    fn test_fallback_after_exhaustion() {
        let bytes = vec![1, 2, 3, 4];
        let mut rng = BytesRng::new(bytes.clone());

        // Consume all bytes
        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [1, 2, 3, 4]);

        // Now should use fallback
        rng.fill_bytes(&mut buf);
        let first_fallback = buf;

        // Create another RNG with same bytes - fallback should be deterministic
        let mut rng2 = BytesRng::new(bytes);
        let mut buf2 = [0u8; 4];
        rng2.fill_bytes(&mut buf2); // Skip raw bytes
        rng2.fill_bytes(&mut buf2); // Get fallback

        assert_eq!(first_fallback, buf2);
    }

    #[test]
    fn test_fallback_seed_uses_last_8_bytes() {
        // Two buffers with same last 8 bytes should have same fallback
        let bytes1 = vec![99, 99, 1, 2, 3, 4, 5, 6, 7, 8];
        let bytes2 = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let mut rng1 = BytesRng::new(bytes1);
        let mut rng2 = BytesRng::new(bytes2);

        // Exhaust both
        let mut buf = [0u8; 10];
        rng1.fill_bytes(&mut buf);
        let mut buf = [0u8; 8];
        rng2.fill_bytes(&mut buf);

        // Fallback values should match
        assert_eq!(rng1.next_u64(), rng2.next_u64());
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn test_short_buffer_fallback_seed() {
        // Buffer shorter than 8 bytes
        let bytes = vec![1, 2, 3];
        let mut rng = BytesRng::new(bytes);

        // Exhaust buffer
        let mut buf = [0u8; 3];
        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [1, 2, 3]);

        // Should still work with fallback
        let v = rng.next_u64();
        assert_ne!(v, 0); // Just verify it produces something
    }

    #[test]
    fn test_deterministic_with_same_input() {
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let mut rng1 = BytesRng::new(bytes.clone());
        let mut rng2 = BytesRng::new(bytes);

        // Both should produce identical sequences
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn test_next_u32() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let mut rng = BytesRng::new(bytes);

        let v = rng.next_u32();
        assert_eq!(v, u32::from_be_bytes([0x01, 0x02, 0x03, 0x04]));
    }

    #[test]
    fn test_next_u64() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut rng = BytesRng::new(bytes);

        let v = rng.next_u64();
        assert_eq!(
            v,
            u64::from_be_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
    }
}
