mod storage;
pub use storage::Archive;

/// Configuration for `Archive` storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The partition to use for the archive's metadata.
    pub metadata_partition: String,

    /// The partition to use for the archive's table.
    pub table_partition: String,

    /// The size of the archive's table.
    pub table_initial_size: u32,

    /// The number of items added to the table before it is resized.
    pub table_resize_frequency: u8,

    /// The partition to use for the archive's journal.
    pub journal_partition: String,

    /// The target size of the archive's journal.
    pub target_journal_size: u64,

    /// The partition to use for the archive's ordinal.
    pub ordinal_partition: String,

    /// The compression level to use for the archive's [crate::journal] storage.
    pub compression: Option<u8>,

    /// The codec configuration to use for the value stored in the archive.
    pub codec_config: C,

    /// The number of items per section.
    pub items_per_section: u64,

    /// The amount of bytes that can be buffered in a section before being written to disk.
    pub write_buffer: usize,

    /// The amount of bytes to use when replaying the ordinal.
    pub replay_buffer: usize,
}
