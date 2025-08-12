use crate::Block;
use commonware_cryptography::{bls12381::primitives::variant::Variant, PublicKey};
use commonware_resolver::p2p::Coordinator;
use commonware_runtime::buffer::PoolRef;
use governor::Quota;
use std::num::{NonZeroU64, NonZeroUsize};

/// Marshal configuration.
pub struct Config<V: Variant, P: PublicKey, Z: Coordinator<PublicKey = P>, B: Block> {
    /// The public key of the validator.
    pub public_key: P,

    /// The identity of the network.
    pub identity: V::Public,

    /// The coordinator for the resolvers.
    pub coordinator: Z,

    /// The prefix to use for all partitions.
    pub partition_prefix: String,

    /// Size of backfill request/response mailbox.
    pub mailbox_size: usize,

    /// Backfill rate limit.
    pub backfill_quota: Quota,

    /// Minimum number of views to retain temporary data after the application processes a block.
    ///
    /// Useful for keeping around information that peers may desire to have.
    pub view_retention_timeout: u64,

    /// Namespace for proofs.
    pub namespace: Vec<u8>,

    /// Prunable archive partition prefix.
    pub prunable_items_per_section: NonZeroU64,

    /// The number of items to store per section in immutable archives.
    pub immutable_items_per_section: NonZeroU64,

    /// The initial size of the freezer table.
    pub freezer_table_initial_size: u32,

    /// The frequency (in number of resizes) at which to check if the freezer table
    /// should be resized.
    pub freezer_table_resize_frequency: u8,

    /// The number of items to add to the freezer table when resizing.
    pub freezer_table_resize_chunk_size: u32,

    /// The target size of the freezer journal.
    pub freezer_journal_target_size: u64,

    /// The compression level to use for the freezer journal.
    pub freezer_journal_compression: Option<u8>,

    /// The buffer pool to use for the freezer journal.
    pub freezer_journal_buffer_pool: PoolRef,

    /// The size of the replay buffer for storage archives.
    pub replay_buffer: NonZeroUsize,

    /// The size of the write buffer for storage archives.
    pub write_buffer: NonZeroUsize,

    /// Codec configuration for block type.
    pub codec_config: B::Cfg,

    /// Maximum number of blocks to repair at once
    pub max_repair: u64,
}
