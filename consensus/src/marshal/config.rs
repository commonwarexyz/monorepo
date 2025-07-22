use commonware_cryptography::{bls12381::primitives::variant::Variant, PublicKey};
use commonware_resolver::p2p::Coordinator;
use governor::Quota;

/// Marshal configuration.
#[derive(Debug)]
pub struct Config<V: Variant, P: PublicKey, D: Coordinator<PublicKey = P>> {
    /// The public key of the validator.
    pub public_key: P,

    /// The identity of the network.
    pub identity: V::Public,

    /// The coordinator for the resolvers.
    pub coordinator: D,

    /// The prefix to use for all partitions.
    pub partition_prefix: String,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,

    /// The rate limit for backfilling.
    pub backfill_quota: Quota,

    /// The timeout for pruning consensus activity, in views.
    pub activity_timeout: u64,

    /// The number of items to store per section in prunable archives.
    pub prunable_items_per_section: u64,

    /// The number of items to store per section in immutable archives.
    pub immutable_items_per_section: u64,

    /// The initial size of the freezer table for finalizations.
    pub finalized_freezer_table_initial_size: u64,

    /// The initial size of the freezer table for blocks.
    pub blocks_freezer_table_initial_size: u64,

    /// The frequency (in number of resizes) at which to check if the freezer table
    /// should be resized.
    pub freezer_table_resize_frequency: u8,

    /// The number of items to add to the freezer table when resizing.
    pub freezer_table_resize_chunk_size: u32,

    /// The target size of the freezer journal.
    pub freezer_journal_target_size: u64,

    /// The compression level to use for the freezer journal.
    pub freezer_journal_compression: Option<u8>,

    /// The size of the replay buffer for storage archives.
    pub replay_buffer: usize,

    /// The size of the write buffer for storage archives.
    pub write_buffer: usize,

    /// Stream buffer size for finalized blocks
    pub finalized_stream_buffer_size: usize,

    /// Enable fast-path streaming for contiguous blocks
    pub enable_fast_path: bool,

    /// The namespace to use for all notarizations and finalizations.
    pub namespace: Vec<u8>,
}
