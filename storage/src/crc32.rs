//! CRC32 checksum utilities.

/// Size of a CRC32 checksum in bytes.
pub const SIZE: usize = 4;

/// The CRC32 algorithm used (CRC32C).
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
