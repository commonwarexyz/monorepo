use crate::{
    marshal::consensus::{MarshalConsensus, MarshalFinalization, MarshalNotarization},
    types::{Epoch, Epocher, ViewDelta},
    Block,
};
use commonware_cryptography::certificate::Provider;
use commonware_parallel::Strategy;
use commonware_runtime::buffer::PoolRef;
use std::num::{NonZeroU64, NonZeroUsize};

/// Marshal configuration.
pub struct Config<B, C, P, ES, T>
where
    B: Block,
    C: MarshalConsensus<Digest = B::Commitment>,
    P: Provider<Scope = Epoch, Scheme = C::Scheme>,
    ES: Epocher,
    T: Strategy,
{
    /// Provider for epoch-specific signing schemes.
    pub provider: P,

    /// Configuration for epoch lengths across block height ranges.
    pub epocher: ES,

    /// The prefix to use for all partitions.
    pub partition_prefix: String,

    /// Size of backfill request/response mailbox.
    pub mailbox_size: usize,

    /// Minimum number of views to retain temporary data after the application processes a block.
    ///
    /// Useful for keeping around information that peers may desire to have.
    pub view_retention_timeout: ViewDelta,

    /// Prunable archive partition prefix.
    pub prunable_items_per_section: NonZeroU64,

    /// The buffer pool to use for the freezer journal.
    pub buffer_pool: PoolRef,

    /// The size of the replay buffer for storage archives.
    pub replay_buffer: NonZeroUsize,

    /// The size of the write buffer for the key journal of storage archives.
    pub key_write_buffer: NonZeroUsize,

    /// The size of the write buffer for the value journal of storage archives.
    pub value_write_buffer: NonZeroUsize,

    /// Codec configuration for block type.
    pub block_codec_config: B::Cfg,

    /// Codec configuration for notarization certificates.
    pub notarization_codec_config:
        <C::Notarization as MarshalNotarization<C::Scheme, C::Digest>>::Cfg,

    /// Codec configuration for finalization certificates.
    pub finalization_codec_config:
        <C::Finalization as MarshalFinalization<C::Scheme, C::Digest>>::Cfg,

    /// Maximum number of blocks to repair at once.
    pub max_repair: NonZeroUsize,

    /// Strategy for parallel operations.
    pub strategy: T,
}
