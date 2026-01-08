//! CRC32 checksum utilities.
//!
//! This module provides CRC32C checksum computation using the iSCSI polynomial
//! (0x1EDC6F41) as specified in RFC 3720.

/// Size of a CRC32 checksum in bytes.
pub const SIZE: usize = 4;

/// The CRC32 algorithm used (CRC32C/iSCSI/Castagnoli).
const ALGORITHM: crc_fast::CrcAlgorithm = crc_fast::CrcAlgorithm::Crc32Iscsi;

/// Incremental CRC32 hasher for computing checksums over multiple data chunks.
pub struct Crc32 {
    inner: crc_fast::Digest,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// Create a new incremental hasher.
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: crc_fast::Digest::new(ALGORITHM),
        }
    }

    /// Add data to the checksum computation.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the checksum.
    #[inline]
    pub fn finalize(self) -> u32 {
        self.inner.finalize() as u32
    }

    /// Compute a CRC32 checksum of the given data.
    #[inline]
    pub fn checksum(data: &[u8]) -> u32 {
        crc_fast::checksum(ALGORITHM, data) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crc::{Crc, CRC_32_ISCSI};

    /// Reference CRC32C implementation from the [`crc`](https://crates.io/crates/crc) crate.
    const CRC32C_REF: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

    /// Verify checksum against both the reference `crc` crate and our implementation.
    fn verify(data: &[u8], expected: u32) {
        assert_eq!(CRC32C_REF.checksum(data), expected);
        assert_eq!(Crc32::checksum(data), expected);
    }

    /// Generate deterministic test data: sequential bytes wrapping at 256.
    fn sequential_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i & 0xFF) as u8).collect()
    }

    /// Test vectors from RFC 3720 Appendix B.4 "CRC Examples".
    /// https://datatracker.ietf.org/doc/html/rfc3720#appendix-B.4
    #[test]
    fn rfc3720_test_vectors() {
        // 32 bytes of zeros -> CRC = aa 36 91 8a
        verify(&[0x00; 32], 0x8A9136AA);

        // 32 bytes of 0xFF -> CRC = 43 ab a8 62
        verify(&[0xFF; 32], 0x62A8AB43);

        // 32 bytes ascending (0x00..0x1F) -> CRC = 4e 79 dd 46
        let ascending: Vec<u8> = (0x00..0x20).collect();
        verify(&ascending, 0x46DD794E);

        // 32 bytes descending (0x1F..0x00) -> CRC = 5c db 3f 11
        let descending: Vec<u8> = (0x00..0x20).rev().collect();
        verify(&descending, 0x113FDB5C);

        // iSCSI SCSI Read (10) Command PDU -> CRC = 56 3a 96 d9
        let iscsi_read_pdu: [u8; 48] = [
            0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x14,
            0x00, 0x00, 0x00, 0x18, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        verify(&iscsi_read_pdu, 0xD9963A56);
    }

    /// Additional test vectors from external sources.
    /// https://reveng.sourceforge.io/crc-catalogue/17plus.htm#crc.cat.crc-32c
    /// https://github.com/ICRAR/crc32c/blob/master/test/test_crc32c.py
    /// https://github.com/google/leveldb/blob/main/util/crc32c_test.cc
    #[test]
    fn external_test_vectors() {
        // CRC catalogue test vector
        verify(b"", 0x00000000);
        verify(b"123456789", 0xE3069283);

        // ICRAR test vectors
        verify(b"23456789", 0xBFE92A83);
        verify(b"The quick brown fox jumps over the lazy dog", 0x22620404);

        // LevelDB test vector: sequential 0x01-0xF0 (240 bytes)
        let sequential_240: Vec<u8> = (0x01..=0xF0).collect();
        verify(&sequential_240, 0x24C5D375);
    }

    /// SIMD boundary tests.
    ///
    /// SIMD implementations (PCLMULQDQ, ARM CRC) have different code paths
    /// based on input size. These tests verify correctness at critical boundaries.
    #[test]
    fn simd_boundaries() {
        // Critical sizes where SIMD implementations change code paths:
        // - 16: single 128-bit register
        // - 32: two 128-bit registers / one 256-bit register
        // - 64: fold-by-4 block size
        // - 128: large data threshold
        // - 256, 512, 1024: power-of-2 boundaries
        // - 4096: page boundary (common in storage)
        const BOUNDARY_SIZES: &[usize] = &[
            0, 1, 2, 3, 4, 7, 8, 9, // Small sizes
            15, 16, 17, // 128-bit boundary
            31, 32, 33, // 256-bit boundary
            63, 64, 65, // Fold-by-4 boundary
            127, 128, 129, // Large threshold
            255, 256, 257, // 256-byte boundary
            511, 512, 513, // 512-byte boundary
            1023, 1024, 1025, // 1KB boundary
            4095, 4096, 4097, // Page boundary
        ];

        // Pre-computed expected values for sequential data pattern.
        // Generated with the [`crc`](https://crates.io/crates/crc) crate.
        const EXPECTED: &[(usize, u32)] = &[
            (0, 0x00000000),
            (1, 0x527D5351),
            (2, 0x030AF4D1),
            (3, 0x92FD4BFA),
            (4, 0xD9331AA3),
            (7, 0xA359ED4C),
            (8, 0x8A2CBC3B),
            (9, 0x7144C5A8),
            (15, 0x68EF03F6),
            (16, 0xD9C908EB),
            (17, 0x38435E17),
            (31, 0xE95CABCB),
            (32, 0x46DD794E), // Matches RFC 3720
            (33, 0x9F85A26D),
            (63, 0x7A873004),
            (64, 0xFB6D36EB),
            (65, 0x694420FA),
            (127, 0x6C31BD0C),
            (128, 0x30D9C515),
            (129, 0xF514629F),
            (255, 0x8953C482),
            (256, 0x9C44184B),
            (257, 0x8A13A1CE),
            (511, 0x35348950),
            (512, 0xAE10EE5A),
            (513, 0x6814B154),
            (1023, 0x0C8F24D0),
            (1024, 0x2CDF6E8F),
            (1025, 0x8EB48B63),
            (4095, 0xBCB5BD82),
            (4096, 0x9C71FE32),
            (4097, 0x83391BE9),
        ];

        assert_eq!(
            BOUNDARY_SIZES,
            EXPECTED.iter().map(|(size, _)| *size).collect::<Vec<_>>()
        );

        for &(size, expected) in EXPECTED {
            let data = sequential_data(size);
            verify(&data, expected);
        }
    }

    /// Verify incremental hashing produces the same result regardless of chunk size.
    #[test]
    fn chunk_size_independence() {
        let data = sequential_data(1024);
        let expected = CRC32C_REF.checksum(&data);

        // Test chunk sizes from 1 to 64 bytes
        for chunk_size in 1..=64 {
            let mut hasher = Crc32::new();
            for chunk in data.chunks(chunk_size) {
                hasher.update(chunk);
            }
            assert_eq!(hasher.finalize(), expected);
        }
    }

    /// Test with unaligned data by processing at different offsets within a buffer.
    #[test]
    fn alignment_independence() {
        // Create a larger buffer and test CRC of a fixed-size window at different offsets
        let base_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let test_len = 64;

        // Get reference CRC for the first 64 bytes
        let reference = CRC32C_REF.checksum(&base_data[..test_len]);

        // Verify the same 64-byte pattern produces the same CRC regardless of where
        // it appears in the source buffer (tests alignment handling)
        for offset in 0..16 {
            let data = &base_data[offset..offset + test_len];
            let expected = CRC32C_REF.checksum(data);
            assert_eq!(Crc32::checksum(data), expected);
        }

        // Also verify that the first 64 bytes always produce the reference CRC
        verify(&base_data[..test_len], reference);
    }
}
