mod storage;
pub use storage::Archive;

/// Configuration for `Archive` storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The partition to use for the archive's metadata.
    pub metadata_partition: String,

    /// The partition to use for the archive's journal.
    pub journal_partition: String,

    /// The partition to use for the archive's ordinal.
    pub ordinal_partition: String,

    /// The compression level to use for the archive's [crate::journal] storage.
    pub compression: Option<u8>,

    /// The codec configuration to use for the value stored in the archive.
    pub codec_config: C,

    /// Mask to apply to indices to determine section.
    ///
    /// This value is `index & section_mask`.
    pub section_mask: u64,

    /// The amount of bytes that can be buffered in a section before being written to disk.
    pub write_buffer: usize,
}
