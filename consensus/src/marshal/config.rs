use crate::{
    types::{Epoch, Epocher, ViewDelta},
    Block,
};
use commonware_cryptography::certificate::Provider;
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
use std::num::{NonZeroU64, NonZeroUsize};

/// Marshal configuration.
///
/// # Warning
///
/// Any height the marshal is asked to sync must be covered by both the
/// [epocher](Self::epocher) and the [provider](Self::provider). If the epocher
/// cannot map a height to an epoch, or the provider cannot supply a scheme for
/// that epoch, the marshal will silently drop the sync request. Callers are
/// responsible for ensuring both are configured for the full range of heights
/// they intend to sync.
///
/// # Pruning
///
/// It is safe for an application to prune entries from the
/// [epocher](Self::epocher) and [provider](Self::provider) for epochs whose
/// highest height is at or below the floor (i.e. `last_processed_height`,
/// updated either by application acks or by an explicit
/// `Mailbox::set_floor`). In-flight backfill responses for those epochs are
/// silently discarded and the serving peer is not blocked.
///
/// Pruning entries for epochs that span heights above the floor is unsafe:
/// in-flight responses for those heights cannot be verified and the marshal
/// will block the serving peer (which is presumed to have sent invalid data).
/// Applications must therefore retain epocher/provider entries for every
/// epoch covering a height above the floor.
pub struct Config<B, P, ES, T>
where
    B: Block,
    P: Provider<Scope = Epoch>,
    ES: Epocher,
    T: Strategy,
{
    /// Provider for epoch-specific signing schemes.
    ///
    /// Must cover every epoch that contains heights the marshal will sync.
    pub provider: P,

    /// Configuration for epoch lengths across block height ranges.
    ///
    /// Must cover every height the marshal will sync.
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

    /// The page cache to use for the freezer journal.
    pub page_cache: CacheRef,

    /// The size of the replay buffer for storage archives.
    pub replay_buffer: NonZeroUsize,

    /// The size of the write buffer for the key journal of storage archives.
    pub key_write_buffer: NonZeroUsize,

    /// The size of the write buffer for the value journal of storage archives.
    pub value_write_buffer: NonZeroUsize,

    /// Codec configuration for block type.
    pub block_codec_config: B::Cfg,

    /// Maximum number of blocks to repair at once.
    pub max_repair: NonZeroUsize,

    /// Maximum number of blocks dispatched to the application that have not
    /// yet been acknowledged. Increasing this value allows the application
    /// to buffer work while marshal continues dispatching, hiding ack latency.
    pub max_pending_acks: NonZeroUsize,

    /// Strategy for parallel operations.
    pub strategy: T,
}
