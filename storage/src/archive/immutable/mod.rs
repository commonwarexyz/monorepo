//! An immutable key-value store for ordered data with a minimal memory footprint.
//!
//! Data is stored in a [crate::freezer::Freezer] and a [crate::ordinal::Ordinal] to enable
//! lookups by both index and key with minimal memory overhead.
//!
//! # Uniqueness
//!
//! [Archive] assumes all stored indexes and keys are unique. If the same key is associated with
//! multiple `indices`, there is no guarantee which value will be returned. If the key is written to
//! an existing `index`, [Archive] will return an error.
//!
//! # Compression
//!
//! [Archive] supports compressing data before storing it on disk. This can be enabled by setting
//! the `compression` field in the `Config` struct to a valid `zstd` compression level. This setting
//! can be changed between initializations of [Archive], however, it must remain populated if any
//! data was written with compression enabled.
//!
//! # Querying for Gaps
//!
//! [Archive] tracks gaps in the index space to enable the caller to efficiently fetch unknown keys
//! using `next_gap`. This is a very common pattern when syncing blocks in a blockchain.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic};
//! use commonware_cryptography::hash;
//! use commonware_storage::{
//!     archive::{
//!         Archive as _,
//!         immutable::{Archive, Config},
//!     },
//! };
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create an archive
//!     let cfg = Config {
//!         metadata_partition: "metadata".into(),
//!         freezer_table_partition: "table".into(),
//!         freezer_table_initial_size: 65_536,
//!         freezer_table_resize_frequency: 4,
//!         freezer_journal_partition: "journal".into(),
//!         freezer_journal_target_size: 1024,
//!         freezer_journal_compression: Some(3),
//!         ordinal_partition: "ordinal".into(),
//!         items_per_section: 1024,
//!         write_buffer: 1024,
//!         replay_buffer: 1024,
//!         codec_config: (),
//!     };
//!     let mut archive = Archive::init(context, cfg).await.unwrap();
//!
//!     // Put a key
//!     archive.put(1, hash(b"data"), 10).await.unwrap();
//!
//!     // Close the archive (also closes the freezer and ordinal)
//!     archive.close().await.unwrap();
//! });

mod storage;
pub use storage::Archive;

/// Configuration for [Archive] storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The partition to use for the archive's metadata.
    pub metadata_partition: String,

    /// The partition to use for the archive's freezer table.
    pub freezer_table_partition: String,

    /// The size of the archive's freezer table.
    pub freezer_table_initial_size: u32,

    /// The number of items added to the freezer table before it is resized.
    pub freezer_table_resize_frequency: u8,

    /// The partition to use for the archive's freezer journal.
    pub freezer_journal_partition: String,

    /// The target size of the archive's freezer journal.
    pub freezer_journal_target_size: u64,

    /// The compression level to use for the archive's freezer journal.
    pub freezer_journal_compression: Option<u8>,

    /// The partition to use for the archive's ordinal.
    pub ordinal_partition: String,

    /// The number of items per section.
    pub items_per_section: u64,

    /// The amount of bytes that can be buffered in a section before being written to a
    /// [commonware_runtime::Blob].
    pub write_buffer: usize,

    /// The buffer size to use when replaying a [commonware_runtime::Blob].
    pub replay_buffer: usize,

    /// The [commonware_codec::Codec] configuration to use for the value stored in the archive.
    pub codec_config: C,
}
