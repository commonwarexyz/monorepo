use crate::{
    types::{Epoch, ViewDelta},
    Block,
};
use commonware_cryptography::certificate::Provider;
use commonware_runtime::buffer::PoolRef;
use std::num::{NonZeroU64, NonZeroUsize};

/// Marshal configuration.
pub struct Config<B, P>
where
    B: Block,
    P: Provider<Scope = Epoch>,
{
    /// Provider for epoch-specific signing schemes.
    pub provider: P,

    /// The length of an epoch in number of blocks.
    pub epoch_length: u64,

    /// The prefix to use for all partitions.
    pub partition_prefix: String,

    /// Size of backfill request/response mailbox.
    pub mailbox_size: usize,

    /// Minimum number of views to retain temporary data after the application processes a block.
    ///
    /// Useful for keeping around information that peers may desire to have.
    pub view_retention_timeout: ViewDelta,

    /// Namespace for proofs.
    pub namespace: Vec<u8>,

    /// Prunable archive partition prefix.
    pub prunable_items_per_section: NonZeroU64,

    /// The buffer pool to use for the freezer journal.
    pub buffer_pool: PoolRef,

    /// The size of the replay buffer for storage archives.
    pub replay_buffer: NonZeroUsize,

    /// The size of the write buffer for storage archives.
    pub write_buffer: NonZeroUsize,

    /// Codec configuration for block type.
    pub block_codec_config: B::Cfg,

    /// Maximum number of blocks to repair at once.
    pub max_repair: NonZeroUsize,
}
