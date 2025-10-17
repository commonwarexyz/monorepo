use crate::{
    adb,
    journal::{
        contiguous::{self, Variable as ContiguousVariable},
        variable,
    },
    mmr::Location,
};
use commonware_codec::Codec;
use commonware_runtime::{Metrics, Storage};
use core::ops::Range;
use std::num::NonZeroU64;
use tracing::debug;

/// Initialize a contiguous Variable journal for use in state sync.
///
/// The bounds are item locations (not section numbers). This function prepares the
/// on-disk journal so that subsequent appends go to the correct physical location for the
/// requested range.
///
/// Behavior by existing on-disk state:
/// - Fresh (no data): returns an empty journal.
/// - Stale (all data strictly before `range.start`): destroys existing data and returns an
///   empty journal.
/// - Overlap within [`range.start`, `range.end`]:
///   - Prunes to `range.start`
/// - Unexpected data beyond `range.end`: returns [adb::Error::UnexpectedData].
///
/// # Arguments
/// - `context`: storage context
/// - `cfg`: journal configuration (partition will have `_data` and `_locations` suffixes added)
/// - `items_per_section`: number of items per section
/// - `range`: range of item locations to retain
///
/// # Returns
/// A contiguous journal ready for sync operations. The journal's size will be within the range.
///
/// # Errors
/// Returns [adb::Error::UnexpectedData] if existing data extends beyond `range.end`.
pub(super) async fn init_journal<E: Storage + Metrics, V: Codec + Send>(
    context: E,
    cfg: variable::Config<V::Cfg>,
    range: Range<u64>,
    items_per_section: NonZeroU64,
) -> Result<ContiguousVariable<E, V>, adb::Error> {
    assert!(!range.is_empty(), "range must not be empty");

    debug!(
        range.start,
        range.end,
        items_per_section = items_per_section.get(),
        "initializing contiguous variable journal for sync"
    );

    // Initialize contiguous journal
    let mut journal = ContiguousVariable::init(
        context.with_label("journal"),
        contiguous::Config {
            data_partition: format!("{}_data", cfg.partition),
            locations_partition: format!("{}_locations", cfg.partition),
            items_per_section,
            compression: cfg.compression,
            codec_config: cfg.codec_config.clone(),
            buffer_pool: cfg.buffer_pool.clone(),
            write_buffer: cfg.write_buffer,
        },
    )
    .await?;

    let size = journal.size().await?;

    // No existing data - initialize at the start of the sync range if needed
    if size == 0 {
        if range.start == 0 {
            debug!("no existing journal data, returning empty journal");
            return Ok(journal);
        } else {
            debug!(
                range.start,
                "no existing journal data, initializing at sync range start"
            );
            journal.destroy().await?;
            return Ok(ContiguousVariable::init_at_size(
                context,
                contiguous::Config {
                    data_partition: format!("{}_data", cfg.partition),
                    locations_partition: format!("{}_locations", cfg.partition),
                    items_per_section,
                    compression: cfg.compression,
                    codec_config: cfg.codec_config,
                    buffer_pool: cfg.buffer_pool,
                    write_buffer: cfg.write_buffer,
                },
                range.start,
            )
            .await?);
        }
    }

    // Check if data exceeds the sync range
    if size > range.end {
        return Err(adb::Error::UnexpectedData(Location::new_unchecked(size)));
    }

    // If all existing data is before our sync range, destroy and recreate fresh
    if size <= range.start {
        // All data is stale (ends at or before range.start)
        debug!(
            size,
            range.start, "existing journal data is stale, re-initializing at start position"
        );
        journal.destroy().await?;
        return Ok(ContiguousVariable::init_at_size(
            context,
            contiguous::Config {
                data_partition: format!("{}_data", cfg.partition),
                locations_partition: format!("{}_locations", cfg.partition),
                items_per_section,
                compression: cfg.compression,
                codec_config: cfg.codec_config,
                buffer_pool: cfg.buffer_pool,
                write_buffer: cfg.write_buffer,
            },
            range.start,
        )
        .await?);
    }

    // Prune to lower bound if needed
    let oldest = journal.oldest_retained_pos().await?;
    if let Some(oldest_pos) = oldest {
        if oldest_pos < range.start {
            debug!(
                oldest_pos,
                range.start, "pruning journal to sync range start"
            );
            journal.prune(range.start).await?;
        }
    }

    Ok(journal)
}
