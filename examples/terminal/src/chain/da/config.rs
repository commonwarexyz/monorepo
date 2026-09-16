//! Native partitions for a balance replica and its two cumulative logs.

use crate::protocol::{MAX_DESTINATION_BYTES, state_config};
use commonware_clearing::bajillion::{logs, replica};
use commonware_codec::RangeCfg;
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_storage::{journal::contiguous, merkle::full, qmdb::keyless};
use commonware_utils::NZU64;
use std::num::NonZeroU64;

// GiB-scale sections amortize rollover. Small test sections keep rollover and pruning reachable.
pub(super) const LOG_OPERATIONS_PER_SECTION: NonZeroU64 =
    NZU64!(if cfg!(test) { 4_096 } else { 1 << 25 });
pub(super) const LOG_MERKLE_NODES_PER_BLOB: NonZeroU64 =
    NZU64!(if cfg!(test) { 4_096 } else { 1 << 26 });

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
    cache: CacheRef,
    strategy: S,
) -> replica::Config<S> {
    let io_buffer = crate::chain::validator::IO_BUFFER_SIZE;
    let merkle = |role: &str| full::Config {
        journal_partition: format!("{prefix}-{role}-merkle"),
        metadata_partition: format!("{prefix}-{role}-pins"),
        items_per_blob: LOG_MERKLE_NODES_PER_BLOB,
        write_buffer: io_buffer,
        replay_buffer: io_buffer,
        strategy: strategy.clone(),
        page_cache: cache.clone(),
    };
    replica::Config {
        state: state_config(
            &format!("{prefix}-balances"),
            cache.clone(),
            strategy.clone(),
        ),
        logs: logs::Config {
            activity: keyless::variable::Config {
                merkle: merkle("activity"),
                log: contiguous::variable::Config {
                    partition: format!("{prefix}-activity-log"),
                    items_per_section: LOG_OPERATIONS_PER_SECTION,
                    compression: None,
                    codec_config: (),
                    page_cache: cache.clone(),
                    write_buffer: io_buffer,
                    replay_buffer: io_buffer,
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
                    write_buffer: io_buffer,
                    replay_buffer: io_buffer,
                },
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, Strategizer as _, deterministic};
    use commonware_utils::NZUsize;

    #[test]
    fn replica_config_uses_one_cache() {
        deterministic::Runner::default().start(|context| async move {
            let cache = crate::protocol::fixture_page_cache(&context);
            let config = replica_config("shared-cache", cache, context.strategy(NZUsize!(1)));
            let caches = [
                &config.state.merkle_config.page_cache,
                &config.state.journal_config.page_cache,
                &config.logs.activity.merkle.page_cache,
                &config.logs.activity.log.page_cache,
                &config.logs.payouts.merkle.page_cache,
                &config.logs.payouts.log.page_cache,
            ];
            for (expected, cache) in caches.into_iter().enumerate() {
                assert_eq!(cache.next_id(), expected as u64);
            }
        });
    }
}
