//! CRC32 checksum utilities.

/// Size of a CRC32 checksum in bytes.
pub const SIZE: usize = 4;

/// Incremental CRC32 hasher for computing checksums over multiple data chunks.
#[derive(Default)]
pub struct Crc32 {
    inner: crc32fast::Hasher,
}

impl Crc32 {
    /// Create a new incremental hasher.
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: crc32fast::Hasher::new(),
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
        self.inner.finalize()
    }

    /// Compute a CRC32 checksum of the given data.
    #[inline]
    pub fn checksum(data: &[u8]) -> u32 {
        crc32fast::hash(data)
    }
}
