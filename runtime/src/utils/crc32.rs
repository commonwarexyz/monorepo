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

    /// Test vectors from RFC 3720 Appendix B.4 "CRC Examples".
    /// https://datatracker.ietf.org/doc/html/rfc3720#appendix-B.4
    #[test]
    fn rfc3720_test_vectors() {
        // 32 bytes of zeros -> CRC = aa 36 91 8a
        assert_eq!(Crc32::checksum(&[0x00; 32]), 0x8A9136AA);

        // 32 bytes of 0xFF -> CRC = 43 ab a8 62
        assert_eq!(Crc32::checksum(&[0xFF; 32]), 0x62A8AB43);

        // 32 bytes ascending (0x00..0x1F) -> CRC = 4e 79 dd 46
        let ascending: Vec<u8> = (0x00..0x20).collect();
        assert_eq!(Crc32::checksum(&ascending), 0x46DD794E);

        // 32 bytes descending (0x1F..0x00) -> CRC = 5c db 3f 11
        let descending: Vec<u8> = (0x00..0x20).rev().collect();
        assert_eq!(Crc32::checksum(&descending), 0x113FDB5C);

        // iSCSI SCSI Read (10) Command PDU -> CRC = 56 3a 96 d9
        let iscsi_read_pdu: [u8; 48] = [
            0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x14,
            0x00, 0x00, 0x00, 0x18, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(Crc32::checksum(&iscsi_read_pdu), 0xD9963A56);
    }

    /// Check value from the CRC catalogue.
    /// https://reveng.sourceforge.io/crc-catalogue/17plus.htm#crc.cat.crc-32c
    #[test]
    fn crc_catalogue_check_value() {
        assert_eq!(Crc32::checksum(b"123456789"), 0xE3069283);
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";

        let oneshot = Crc32::checksum(data);

        // Chunked
        let mut hasher = Crc32::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..25]);
        hasher.update(&data[25..]);
        assert_eq!(hasher.finalize(), oneshot);

        // Byte-by-byte
        let mut hasher = Crc32::new();
        for byte in data {
            hasher.update(&[*byte]);
        }
        assert_eq!(hasher.finalize(), oneshot);
    }
}
