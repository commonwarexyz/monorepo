//! Native partitions for a balance replica and its two cumulative logs.

use crate::{
    chain::validator::{IO_BUFFER_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE},
    protocol::{MAX_DESTINATION_BYTES, state_config},
};
use commonware_clearing::bajillion::{logs, replica};
use commonware_codec::RangeCfg;
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, buffer::paged::CacheRef};
use commonware_storage::{journal::contiguous, merkle::full, qmdb::keyless};
use commonware_utils::NZU64;
use std::num::NonZeroU64;

pub(super) const LOG_OPERATIONS_PER_SECTION: NonZeroU64 = NZU64!(128);
pub(super) const LOG_MERKLE_NODES_PER_BLOB: NonZeroU64 = NZU64!(1024);

/// Remove a recorded generation when no intact native owner is available. Intact owners use
/// `destroy` to drain pending work. Repeating removal is safe when some partitions are absent.
pub(super) async fn remove_generation<E: commonware_storage::Context, S: Strategy>(
    context: &E,
    config: replica::Config<S>,
) -> anyhow::Result<()> {
    let journals = [
        config.state.merkle_config.journal_partition,
        config.state.journal_config.partition,
        config.logs.activity.merkle.journal_partition,
        format!("{}_offsets", config.logs.activity.log.partition),
        config.logs.payouts.merkle.journal_partition,
        format!("{}_offsets", config.logs.payouts.log.partition),
    ];
    let partitions = [
        config.state.merkle_config.metadata_partition,
        config.state.grafted_metadata_partition,
        config.logs.activity.merkle.metadata_partition,
        format!("{}_data", config.logs.activity.log.partition),
        config.logs.payouts.merkle.metadata_partition,
        format!("{}_data", config.logs.payouts.log.partition),
    ];
    // Fixed journals own their configured legacy partition and the native blob/metadata pair.
    // Variable journals own a data partition and a fixed offsets journal.
    for partition in partitions.into_iter().chain(
        journals
            .into_iter()
            .flat_map(|base| [format!("{base}-blobs"), format!("{base}-metadata"), base]),
    ) {
        match context.remove(&partition, None).await {
            Ok(()) | Err(commonware_runtime::Error::PartitionMissing(_)) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(crate) fn replica_config<S: Strategy>(
    prefix: &str,
    pooler: &impl BufferPooler,
    strategy: S,
) -> replica::Config<S> {
    let cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    let merkle = |role: &str| full::Config {
        journal_partition: format!("{prefix}-{role}-merkle"),
        metadata_partition: format!("{prefix}-{role}-pins"),
        items_per_blob: LOG_MERKLE_NODES_PER_BLOB,
        write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
        strategy: strategy.clone(),
        page_cache: cache.clone(),
    };
    replica::Config {
        state: state_config(&format!("{prefix}-balances"), pooler, strategy.clone()),
        logs: logs::Config {
            activity: keyless::variable::Config {
                merkle: merkle("activity"),
                log: contiguous::variable::Config {
                    partition: format!("{prefix}-activity-log"),
                    items_per_section: LOG_OPERATIONS_PER_SECTION,
                    compression: None,
                    codec_config: (),
                    page_cache: cache.clone(),
                    write_buffer: IO_BUFFER_SIZE,
                    replay_buffer: IO_BUFFER_SIZE,
                },
            },
            payouts: keyless::variable::Config {
                merkle: merkle("payouts"),
                log: contiguous::variable::Config {
                    partition: format!("{prefix}-payouts-log"),
                    items_per_section: LOG_OPERATIONS_PER_SECTION,
                    compression: None,
                    codec_config: RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                    page_cache: cache,
                    write_buffer: IO_BUFFER_SIZE,
                    replay_buffer: IO_BUFFER_SIZE,
                },
            },
        },
    }
}
