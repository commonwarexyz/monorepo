use crate::{
    Block,
    simplex::types::Finalization,
    types::{Epoch, Epocher, ViewDelta},
};
use commonware_codec::Codec;
use commonware_cryptography::{
    Digest, Digestible,
    certificate::{Provider, Scheme},
};
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
use std::num::{NonZeroU64, NonZeroUsize};

/// Startup anchor for marshal.
///
/// Durable progress from a previous run takes precedence when it already supersedes the configured
/// anchor. That progress includes the processed round floor. The round floor covers every
/// finalization round seen for a processed block or an installed floor anchor, and every round of
/// an epoch that ends at or below such a block. A later start neither verifies nor fetches a floor
/// whose round the processed round floor covers.
pub enum Start<S: Scheme, C: Digest, B> {
    /// Start from the height-zero genesis block.
    Genesis(B),
    /// Start from a finalized commitment.
    Floor(Finalization<S, C>),
}

/// Marshal configuration.
///
/// # Epocher and Provider Coverage
///
/// Any height marshal is asked to sync must be covered by both the
/// [epocher](Self::epocher) and the [provider](Self::provider). If either returns `None` for a
/// requested height, responses to resolver requests for it are ignored: the request is retired
/// without validating the response, attributing it to the serving peer, or retrying. If the data
/// is no longer needed (say a duplicate request for a height we've long since processed), this is
/// harmless. However, failing to provide either the epocher or the provider for a height we still
/// require to process the canonical chain will lead marshal to stall.
///
/// ## Safe Pruning
///
/// Applications may prune epocher/provider entries once the last processed
/// height passes a prune target. The last processed height can be
/// derived from an `Update::Block` at height `H` as
/// `H - max_pending_acks` (the maximum backlog of blocks the application can buffer).
pub struct Config<P, ES, T, AB, B, C = <AB as Digestible>::Digest>
where
    AB: Block + Codec,
    C: Digest,
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

    /// Startup anchor for marshal's processed floor.
    pub start: Start<P::Scheme, C, B>,

    /// The prefix to use for all partitions.
    pub partition_prefix: String,

    /// Size of backfill request/response mailbox.
    pub mailbox_size: NonZeroUsize,

    /// Minimum number of views to retain temporary data after the application processes a block.
    ///
    /// Useful for keeping around information that peers may desire to have. Data is kept for at
    /// least this many views behind the previously witnessed finalization round, which advances
    /// with the finalizations of processed blocks and installed floor anchors. Views restart with
    /// each epoch, so the part of the window that reaches below an epoch's first view is counted
    /// in whole earlier epochs instead: the previous epoch stays until that round is this many
    /// views into its epoch, and at most this many earlier epochs stay.
    ///
    /// ```text
    /// window of 10 views behind the previously witnessed round P
    /// (`=` kept, `.` eligible for pruning)
    ///
    ///   P = (8, 15)   ep 7 ........ | ep 8  . . . . . = = = = = = = = = = P
    ///                 the window fits in epoch 8: prune below (8, 5) and all earlier epochs
    ///
    ///   P = (8, 3)    ep 0 ........ | ep 1 == | ep 2 == | ... | ep 7 == | ep 8  = = = P
    ///                 epoch 8 has 3 of the 10 views; epochs 7 to 1 stand in for the other 7
    /// ```
    pub view_retention: ViewDelta,

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

    /// Codec configuration for the block type.
    /// [`max_payload_size`](crate::marshal::max_payload_size) sizes marshal's payloads from the
    /// largest block this configuration decodes.
    pub block_codec_config: AB::Cfg,

    /// Maximum number of missing finalized heights fetched from peers at a time.
    ///
    /// Repair fetches the lowest missing heights above the processed height and moves up as they
    /// fill, so a larger value fills a gap with more parallel requests. Blocks requested by
    /// commitment, hints, and subscriptions are not counted.
    pub max_repair: NonZeroUsize,

    /// Maximum number of dispatched blocks awaiting application acknowledgement,
    /// with up to twice this many finalized blocks retained in memory for subsequent
    /// dispatch without archive reads.
    pub max_pending_acks: NonZeroUsize,

    /// Strategy for parallel operations.
    pub strategy: T,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{coding::types::CodedBlock, mocks::block::Block},
        simplex::{scheme::ed25519, types::Context},
        types::{FixedEpocher, coding::Commitment},
    };
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{
        certificate::ConstantProvider,
        ed25519::PublicKey,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_parallel::Sequential;

    #[test]
    fn config_compiles_with_distinct_application_and_start_blocks() {
        type AB = Block<Sha256Digest, Context<Sha256Digest, PublicKey>>;
        type TestCommitment = Commitment<AB, ReedSolomon<Sha256>, Sha256>;
        type B = CodedBlock<AB, ReedSolomon<Sha256>, Sha256>;
        type Provider = ConstantProvider<ed25519::Scheme, Epoch>;

        fn assert_well_formed<T>() {}

        assert_well_formed::<Config<Provider, FixedEpocher, Sequential, AB, B, TestCommitment>>();
    }
}
