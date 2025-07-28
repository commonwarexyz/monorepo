use crate::Block;
use commonware_cryptography::{bls12381::primitives::variant::Variant, PublicKey};
use commonware_resolver::p2p::Coordinator;
use governor::Quota;

/// Marshal configuration.
#[derive(Debug)]
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

    /// Minimum grace period for retaining activity after the application has processed the block.
    ///
    /// For notarizations, this is in number of views.
    /// For blocks and finalizations, this is in number of blocks.
    ///
    /// Useful for keeping around information that peers may desire to have.
    pub grace_period: u64,

    /// Namespace for proofs.
    pub namespace: Vec<u8>,

    /// Prunable archive partition prefix.
    pub prunable_items_per_section: u64,

    /// The size of the replay buffer for storage archives.
    pub replay_buffer: usize,

    /// The size of the write buffer for storage archives.
    pub write_buffer: usize,

    /// Codec configuration for block type.
    pub codec_config: B::Cfg,

    /// Maximum number of blocks to repair at once
    pub max_repair: u64,
}
