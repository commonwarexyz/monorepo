use crate::{
    adb::{
        self,
        any::{
            self,
            variable::{read_oldest_retained_loc, write_oldest_retained_loc},
        },
        sync::{self, Journal as SyncJournal},
    },
    index::Index,
    journal::{
        fixed,
        variable::{Config as VConfig, Journal as VJournal, ITEM_ALIGNMENT},
    },
    metadata::Metadata,
    mmr::{hasher::Standard, iterator::leaf_num_to_pos},
    store::operation::Variable,
    translator::Translator,
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage as RStorage, Storage};
use commonware_utils::{sequence::prefixed_u64::U64, Array};
use futures::{pin_mut, StreamExt};
use std::{num::NonZeroU64, ops::Bound};
use tracing::debug;

impl<E, K, V, H, T> sync::Database for any::variable::Any<E, K, V, H, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Codec,
    H: Hasher,
    T: Translator,
{
    type Op = Variable<K, V>;
    type Journal = Journal<E, K, V>;
    type Hasher = H;
    type Error = adb::Error;
    type Config = any::variable::Config<T, V::Cfg>;
    type Digest = H::Digest;
    type Context = E;

    async fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, <Self::Journal as sync::Journal>::Error> {
        // Initialize the variable journal
        let mut journal = VJournal::init(
            context.clone(),
            VConfig {
                partition: config.log_journal_partition.clone(),
                compression: config.log_compression,
                codec_config: config.log_codec_config.clone(),
                write_buffer: config.log_write_buffer,
                buffer_pool: config.buffer_pool.clone(),
            },
        )
        .await?;

        // Initialize metadata storage
        let mut metadata = Metadata::<E, U64, u64>::init(
            context.with_label("metadata"),
            crate::metadata::Config {
                partition: config.metadata_partition.clone(),
                codec_config: (),
            },
        )
        .await?;

        // Prune the journal to the sync range
        let size = prune_journal(
            &mut journal,
            &mut metadata,
            lower_bound,
            upper_bound,
            config.log_items_per_section,
        )
        .await?;

        // Create the sync journal wrapper
        Journal::new(journal, config.log_items_per_section, metadata, size).await
    }

    async fn from_sync_result(
        context: Self::Context,
        db_config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        lower_bound: u64,
        upper_bound: u64,
        _apply_batch_size: usize,
    ) -> Result<Self, Self::Error> {
        // Initialize MMR for sync with proper bounds and pinned nodes
        let mmr = crate::mmr::journaled::Mmr::init_sync(
            context.with_label("mmr"),
            crate::mmr::journaled::SyncConfig {
                config: crate::mmr::journaled::Config {
                    journal_partition: db_config.mmr_journal_partition,
                    metadata_partition: db_config.mmr_metadata_partition,
                    items_per_blob: db_config.mmr_items_per_blob,
                    write_buffer: db_config.mmr_write_buffer,
                    thread_pool: db_config.thread_pool.clone(),
                    buffer_pool: db_config.buffer_pool.clone(),
                },
                lower_bound: leaf_num_to_pos(lower_bound),
                upper_bound: leaf_num_to_pos(upper_bound + 1) - 1,
                pinned_nodes,
            },
        )
        .await
        .map_err(adb::Error::Mmr)?;

        // Initialize locations journal
        let locations = crate::adb::any::fixed::sync::init_journal(
            context.with_label("locations"),
            fixed::Config {
                partition: db_config.locations_journal_partition.clone(),
                items_per_blob: db_config.locations_items_per_blob,
                write_buffer: db_config.log_write_buffer,
                buffer_pool: db_config.buffer_pool.clone(),
            },
            lower_bound,
            upper_bound,
        )
        .await
        .map_err(adb::Error::Journal)?;

        // Create the database instance
        let snapshot = Index::init(context.with_label("snapshot"), db_config.translator.clone());
        let (log, metadata) = journal.into_inner();
        let oldest_retained_loc = read_oldest_retained_loc(&metadata);
        let db = any::variable::Any {
            mmr,
            log,
            log_size: upper_bound + 1,
            inactivity_floor_loc: lower_bound,
            oldest_retained_loc,
            metadata,
            locations,
            log_items_per_section: db_config.log_items_per_section.get(),
            uncommitted_ops: 0,
            snapshot,
            hasher: Standard::<H>::new(),
        };

        // Build the database from the log
        let mut db = db.build_snapshot_from_log().await?;

        // Persist the state
        db.sync().await?;
        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        any::variable::Any::root(self, &mut Standard::<H>::new())
    }

    async fn resize_journal(
        journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, Self::Error> {
        let size = journal.size().await.map_err(adb::Error::from)?;
        if size <= lower_bound {
            let (log, metadata) = journal.into_inner();
            log.close().await.map_err(adb::Error::from)?;
            metadata.close().await.map_err(adb::Error::from)?;
            return Self::create_journal(context, config, lower_bound, upper_bound)
                .await
                .map_err(adb::Error::from);
        }

        let (mut journal, mut metadata) = journal.into_inner();
        let next_write_loc = prune_journal(
            &mut journal,
            &mut metadata,
            lower_bound,
            upper_bound,
            config.log_items_per_section,
        )
        .await?;

        Journal::new(
            journal,
            config.log_items_per_section,
            metadata,
            next_write_loc,
        )
        .await
        .map_err(adb::Error::from)
    }
}

/// Initialize a Variable journal for use in state sync.
///
/// The bounds are item locations (not section numbers). This function prepares the
/// on-disk journal so that subsequent appends go to the correct physical location for the
/// requested range.
///
/// Behavior by existing on-disk state:
/// - Fresh (no data): returns an empty journal.
/// - Stale (all data strictly before `lower_bound`): destroys existing data and returns an
///   empty journal.
/// - Overlap within [`lower_bound`, `upper_bound`]:
///   - Prunes sections strictly below `lower_bound / items_per_section` (section-aligned).
///   - Removes any sections strictly greater than `upper_bound / items_per_section`.
///   - Truncates the final retained section so that no item with location greater
///     than `upper_bound` remains.
///
/// Note that lower-bound pruning is section-aligned. This means the first retained section may
/// still contain items whose locations are < `lower_bound`. Callers should ignore these.
///
/// # Arguments
/// - `context`: storage context
/// - `cfg`: journal configuration
/// - `lower_bound`: first item location to retain (inclusive)
/// - `upper_bound`: last item location to retain (inclusive)
/// - `items_per_section`: number of items per section
///
/// # Returns
/// A journal whose sections satisfy:
/// - No section index < `lower_bound / items_per_section` exists.
/// - No section index > `upper_bound / items_per_section` exists.
/// - The last retained section is truncated so that its last item’s location is `<= upper_bound`.
pub(crate) async fn init_journal<E: Storage + Metrics, V: Codec>(
    context: E,
    cfg: VConfig<V::Cfg>,
    lower_bound: u64,
    upper_bound: u64,
    items_per_section: NonZeroU64,
) -> Result<VJournal<E, V>, crate::journal::Error> {
    if lower_bound > upper_bound {
        return Err(crate::journal::Error::InvalidSyncRange(
            lower_bound,
            upper_bound,
        ));
    }

    // Calculate the section ranges based on item locations
    let items_per_section = items_per_section.get();
    let lower_section = lower_bound / items_per_section;
    let upper_section = upper_bound / items_per_section;

    debug!(
        lower_bound,
        upper_bound,
        lower_section,
        upper_section,
        items_per_section = items_per_section,
        "initializing variable journal"
    );

    // Initialize the base journal to see what existing data we have
    let mut journal = VJournal::init(context.clone(), cfg.clone()).await?;

    let last_section = journal.blobs.last_key_value().map(|(&s, _)| s);

    // No existing data
    let Some(last_section) = last_section else {
        debug!("no existing journal data, creating fresh journal");
        return Ok(journal);
    };

    // If all existing data is before our sync range, destroy and recreate fresh
    if last_section < lower_section {
        debug!(
            last_section,
            lower_section, "existing journal data is stale, re-initializing"
        );
        journal.destroy().await?;
        return VJournal::init(context, cfg).await;
    }

    // Prune sections below the lower bound.
    if lower_section > 0 {
        journal.prune(lower_section).await?;
    }

    // Remove any sections beyond the upper bound
    if last_section > upper_section {
        debug!(
            last_section,
            lower_section,
            upper_section,
            "existing journal data exceeds sync range, removing sections beyond upper bound"
        );

        let sections_to_remove: Vec<u64> = journal
            .blobs
            .range((Bound::Excluded(upper_section), Bound::Unbounded))
            .map(|(&section, _)| section)
            .collect();

        for section in sections_to_remove {
            debug!(section, "removing section beyond upper bound");
            if let Some(blob) = journal.blobs.remove(&section) {
                drop(blob);
                let name = section.to_be_bytes();
                journal
                    .context
                    .remove(&journal.cfg.partition, Some(&name))
                    .await?;
                journal.tracked.dec();
            }
        }
    }

    // Remove any items beyond upper_bound
    prune_upper(&mut journal, upper_bound, items_per_section).await?;

    Ok(journal)
}

/// Wraps a [VJournal] to provide a sync-compatible interface.
pub struct Journal<E, K, V>
where
    E: Storage + Metrics + Clock,
    K: Array,
    V: Codec,
{
    /// Underlying variable journal storing the operations.
    inner: VJournal<E, Variable<K, V>>,

    /// Operations per storage section in the `inner` journal.
    items_per_section: NonZeroU64,

    /// Next location to append to in the `inner` journal.
    size: u64,

    /// Tracks the oldest retained location in the `inner` journal.
    metadata: Metadata<E, U64, u64>,
}

impl<E, K, V> Journal<E, K, V>
where
    E: Storage + Metrics + Clock,
    K: Array,
    V: Codec,
{
    /// Create a new sync-compatible [Journal].
    ///
    /// Arguments:
    /// - `inner`: The wrapped [VJournal], whose logical last operation location is `size - 1`.
    /// - `items_per_section`: Operations per section.
    /// - `lower_bound`: Lower bound of the range being synced.
    /// - `upper_bound`: Upper bound of the range being synced.
    /// - `metadata`: Metadata for the journal. Tracks the oldest retained location.
    pub async fn new(
        inner: VJournal<E, Variable<K, V>>,
        items_per_section: NonZeroU64,
        metadata: Metadata<E, U64, u64>,
        size: u64,
    ) -> Result<Self, crate::journal::Error> {
        Ok(Self {
            inner,
            items_per_section,
            size,
            metadata,
        })
    }

    /// Return the inner [VJournal] and [Metadata].
    #[allow(clippy::type_complexity)]
    pub fn into_inner(self) -> (VJournal<E, Variable<K, V>>, Metadata<E, U64, u64>) {
        (self.inner, self.metadata)
    }
}

impl<E, K, V> sync::Journal for Journal<E, K, V>
where
    E: Storage + Metrics + Clock,
    K: Array,
    V: Codec,
{
    type Op = Variable<K, V>;
    type Error = crate::journal::Error;

    async fn size(&self) -> Result<u64, Self::Error> {
        Ok(self.size)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        let section = self.size / self.items_per_section;
        self.inner.append(section, op).await?;
        self.size += 1;
        Ok(())
    }

    async fn close(self) -> Result<(), Self::Error> {
        self.inner.close().await
    }
}

/// Remove items beyond the `upper_bound` location (inclusive).
/// Assumes each section contains `items_per_section` items.
async fn prune_upper<E: Storage + Metrics, V: Codec>(
    journal: &mut VJournal<E, V>,
    upper_bound: u64,
    items_per_section: u64,
) -> Result<(), crate::journal::Error> {
    // Find which section contains the upper_bound item
    let upper_section = upper_bound / items_per_section;
    let Some(blob) = journal.blobs.get(&upper_section) else {
        return Ok(()); // Section doesn't exist, nothing to truncate
    };

    // Calculate the logical item range for this section
    let section_start = upper_section * items_per_section;
    let section_end = section_start + items_per_section - 1;

    // If upper_bound is at the very end of the section, no truncation needed
    if upper_bound >= section_end {
        return Ok(());
    }

    // Calculate how many items to keep (upper_bound is inclusive)
    let items_to_keep = (upper_bound - section_start + 1) as u32;
    debug!(
        upper_section,
        upper_bound,
        section_start,
        section_end,
        items_to_keep,
        "truncating section to remove items beyond upper_bound"
    );

    // Find where to rewind to (after the last item we want to keep)
    let target_byte_size = compute_offset::<E, V>(
        blob,
        &journal.cfg.codec_config,
        journal.cfg.compression.is_some(),
        items_to_keep,
    )
    .await?;

    // Rewind to the appropriate position to remove items beyond the upper bound
    journal
        .rewind_section(upper_section, target_byte_size)
        .await?;

    debug!(
        upper_section,
        items_to_keep, target_byte_size, "section truncated"
    );

    Ok(())
}

/// Return the byte offset of the next element after `items_count` elements of `blob`.
async fn compute_offset<E: Storage + Metrics, V: Codec>(
    blob: &commonware_runtime::buffer::Append<E::Blob>,
    codec_config: &V::Cfg,
    compressed: bool,
    items_count: u32,
) -> Result<u64, crate::journal::Error> {
    if items_count == 0 {
        return Ok(0);
    }

    let mut current_offset = 0u32;
    for _ in 0..items_count {
        match VJournal::<E, V>::read(compressed, codec_config, blob, current_offset).await {
            Ok((next_slot, _item_len, _item)) => {
                current_offset = next_slot;
            }
            Err(crate::journal::Error::Runtime(
                commonware_runtime::Error::BlobInsufficientLength,
            )) => {
                // This section has fewer than `items_count` items.
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok((current_offset as u64) * ITEM_ALIGNMENT)
}

/// Count the actual number of items in a journal section.
async fn count_items_in_section<E: Storage + Metrics, V: Codec>(
    blob: &commonware_runtime::buffer::Append<E::Blob>,
    codec_config: &V::Cfg,
    compressed: bool,
) -> Result<u32, crate::journal::Error> {
    let mut current_offset = 0u32;
    let mut item_count = 0u32;

    loop {
        match VJournal::<E, V>::read(compressed, codec_config, blob, current_offset).await {
            Ok((next_slot, _item_len, _item)) => {
                current_offset = next_slot;
                item_count += 1;
            }
            Err(crate::journal::Error::Runtime(
                commonware_runtime::Error::BlobInsufficientLength,
            )) => {
                // Reached the end of the section
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(item_count)
}

/// Prune the section containing `lower_bound`.
/// If existing items are contiguous with `lower_bound`, preserves all items and sets
/// `oldest_retained_loc` to the section boundary. Otherwise, rebuilds the section to
/// remove items before `lower_bound` and updates metadata accordingly.
async fn prune_lower<E, V>(
    journal: &mut VJournal<E, V>,
    metadata: &mut Metadata<E, U64, u64>,
    lower_bound: u64,
    items_per_section: NonZeroU64,
) -> Result<(), crate::journal::Error>
where
    E: Storage + Metrics + Clock,
    V: Codec,
{
    // Find which section contains the lower_bound item
    let lower_section = lower_bound / items_per_section.get();

    if !journal.blobs.contains_key(&lower_section) {
        return Ok(()); // Section doesn't exist, nothing to prune
    };

    let oldest_retained_loc = read_oldest_retained_loc(metadata);

    // Scan the section to find the location of its first and last items
    let mut existing_bounds = None;
    {
        let mut loc = oldest_retained_loc; // Location of the current item in stream below
        let mut min_loc = None; // Minimum location of the existing items in the section
        let mut max_loc = None; // Maximum location of the existing items in the section

        let stream = journal
            .replay(0, 0, commonware_utils::NZUsize!(1024))
            .await?;
        pin_mut!(stream);
        while let Some(result) = stream.next().await {
            let (section, _offset, _size, _operation) = result?;

            // Only process operations from the target section
            if section != lower_section {
                assert!(section > lower_section); // lower_section should be the first section
                break; // We've moved past our target section
            }

            if min_loc.is_none() {
                min_loc = Some(loc);
            }
            max_loc = Some(loc);
            loc += 1;
        }

        if let (Some(min), Some(max)) = (min_loc, max_loc) {
            existing_bounds = Some((min, max));
        }
    }

    // Determine if existing items are contiguous with the new lower_bound
    let Some((existing_min, existing_max)) = existing_bounds else {
        return Ok(()); // Nothing in this section; nothing to rebuild
    };
    let is_contiguous = lower_bound <= existing_max + 1;
    if is_contiguous {
        debug!(
            existing_min,
            existing_max,
            lower_bound,
            oldest_retained_loc,
            "existing items are contiguous with new range, skipping rebuild"
        );
        return Ok(()); // Don't rebuild
    }

    debug!(
        existing_min,
        existing_max,
        lower_bound,
        oldest_retained_loc,
        "existing items are non-contiguous, rebuilding section"
    );

    // Read all operations from the current section
    let mut operations_to_keep = Vec::new();
    {
        let stream = journal
            .replay(0, 0, commonware_utils::NZUsize!(1024))
            .await?;
        pin_mut!(stream);

        let mut loc = oldest_retained_loc;
        while let Some(result) = stream.next().await {
            let (section, _offset, _size, operation) = result?;

            // Only process operations from the target section
            if section != lower_section {
                assert!(section > lower_section); // lower_section should be the first section
                break; // We've moved past our target section
            }

            // Keep operations that are >= lower_bound
            if loc >= lower_bound {
                operations_to_keep.push(operation);
            }

            loc += 1;
        }
    }

    debug!(
        operations_to_keep = operations_to_keep.len(),
        "operations to keep after filtering"
    );

    // Remove the old section
    if let Some(blob) = journal.blobs.remove(&lower_section) {
        drop(blob);
        let name = lower_section.to_be_bytes();
        journal
            .context
            .remove(&journal.cfg.partition, Some(&name))
            .await
            .map_err(crate::journal::Error::Runtime)?;
        journal.tracked.dec();
    }

    if !operations_to_keep.is_empty() {
        // Recreate the section with only the operations we want to keep
        for operation in operations_to_keep {
            journal.append(lower_section, operation).await?;
        }

        // Sync the rebuilt section
        journal.sync(lower_section).await?;
    }

    // Update metadata with the new oldest_retained_loc since we removed items
    write_oldest_retained_loc(metadata, lower_bound);
    metadata.sync().await?;
    Ok(())
}

/// Prune a journal to contain only elements within [lower_bound, upper_bound].
///
/// 1. Remove all sections before the one containing lower_bound
/// 2. Prune the lower section, if needed, to make contiguous with range starting at lower_bound
/// 3. Remove all sections after the one containing upper_bound  
/// 4. Truncate the upper section to remove elements after upper_bound
///
/// Returns the next logical location for writing. Updates metadata with the new
/// oldest_retained_loc (either at section boundaries for contiguous cases or at
/// lower_bound for rebuilt sections).
pub async fn prune_journal<E, V>(
    journal: &mut VJournal<E, V>,
    metadata: &mut Metadata<E, U64, u64>,
    lower_bound: u64,
    upper_bound: u64,
    items_per_section: NonZeroU64,
) -> Result<u64, crate::journal::Error>
where
    E: Storage + Metrics + Clock,
    V: Codec,
{
    if lower_bound > upper_bound {
        return Err(crate::journal::Error::InvalidSyncRange(
            lower_bound,
            upper_bound,
        ));
    }

    let oldest_retained_loc = read_oldest_retained_loc(metadata);
    let items_per_section_val = items_per_section.get();
    let lower_section = lower_bound / items_per_section_val;
    let upper_section = upper_bound / items_per_section_val;

    debug!(
        lower_bound,
        upper_bound,
        oldest_retained_loc,
        lower_section,
        upper_section,
        items_per_section = items_per_section_val,
        "pruning journal"
    );

    // Remove sections before the lower_section
    let lower_section_start = lower_section * items_per_section_val;
    if lower_section > 0 {
        debug!(lower_section, "removing sections before lower_section");
        // Update metadata before pruning to ensure recovery is possible
        // if we crash during pruning.
        if oldest_retained_loc < lower_section_start {
            write_oldest_retained_loc(metadata, lower_section_start);
            metadata.sync().await?;
        }
        journal.prune(lower_section).await?;
    }

    // Remove sections after the upper_section
    let sections_to_remove: Vec<u64> = journal
        .blobs
        .range((Bound::Excluded(upper_section), Bound::Unbounded))
        .map(|(&section, _)| section)
        .collect();

    for section in sections_to_remove {
        debug!(section, "removing section beyond upper bound");
        if let Some(blob) = journal.blobs.remove(&section) {
            drop(blob);
            let name = section.to_be_bytes();
            journal
                .context
                .remove(&journal.cfg.partition, Some(&name))
                .await?;
            journal.tracked.dec();
        }
    }

    // Prune the lower section if needed
    if lower_bound > lower_section_start {
        debug!(lower_section, "pruning lower section");
        prune_lower(journal, metadata, lower_bound, items_per_section).await?;
    }

    // Prune the upper section if needed
    prune_upper(journal, upper_bound, items_per_section_val).await?;

    // Compute the next location to write and the new oldest_retained_loc
    // If journal is empty, return (lower_bound, lower_bound)
    if journal.blobs.is_empty() {
        // The first element we write will be at lower_bound.
        write_oldest_retained_loc(metadata, lower_bound);
        metadata.sync().await?;
        return Ok(lower_bound);
    }

    let last_section = journal
        .blobs
        .last_key_value()
        .map(|(section, _)| *section)
        .unwrap();
    let last_blob = journal.blobs.get(&last_section).unwrap();
    let items_in_last_section = count_items_in_section::<E, V>(
        last_blob,
        &journal.cfg.codec_config,
        journal.cfg.compression.is_some(),
    )
    .await?;
    let last_section_start = last_section * items_per_section_val;
    let next_loc = last_section_start + items_in_last_section as u64;
    Ok(next_loc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adb::sync::{
            self,
            engine::{Config, NextStep},
            resolver::tests::FailResolver,
            Engine, Target,
        },
        journal::variable::ITEM_ALIGNMENT,
        mmr::hasher::Standard,
        store::operation::Variable,
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256, Digest as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _, RwLock};
    use commonware_utils::{NZUsize, NZU64};
    use futures::{channel::mpsc, SinkExt as _};
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use std::{slice::from_ref, sync::Arc};
    use test_case::test_case;

    fn test_hasher() -> Standard<Sha256> {
        Standard::<Sha256>::new()
    }

    // Use some jank sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 2;

    /// Test `init_journal` when there is no existing data on disk.
    #[test_traced]
    fn test_init_journal_no_existing_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_fresh_start".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Initialize journal with sync boundaries when no existing data exists
            let lower_bound = 10;
            let upper_bound = 25;
            let items_per_section = NZU64!(5);
            let mut journal = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with sync boundaries");

            // Verify the journal is ready for sync items
            assert!(journal.blobs.is_empty()); // No sections created yet
            assert_eq!(journal.oldest_section(), None); // No pruning applied

            // Verify that items can be appended starting from the sync position
            let lower_section = lower_bound / items_per_section; // 10/5 = 2

            // Append an element
            let (offset, _) = journal.append(lower_section, 42u64).await.unwrap();
            assert_eq!(offset, 0); // First item in section

            // Verify the item can be retrieved
            let retrieved = journal.get(lower_section, offset).await.unwrap();
            assert_eq!(retrieved, Some(42u64));

            // Append another element
            let (offset2, _) = journal.append(lower_section, 43u64).await.unwrap();
            assert_eq!(
                journal.get(lower_section, offset2).await.unwrap(),
                Some(43u64)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_journal` when there is existing data that overlaps with the sync target range.
    #[test_traced]
    fn test_init_journal_existing_data_overlap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_overlap".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data in multiple sections
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            let items_per_section = NZU64!(5);

            // Add data to sections 0, 1, 2, 3 (simulating items 0-19 with items_per_section=5)
            for section in 0..4 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 10 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that overlap with existing data
            // lower_bound: 8 (section 1), upper_bound: 30 (section 6)
            let lower_bound = 8;
            let upper_bound = 30;
            let mut journal = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with overlap");

            // Verify pruning: sections before lower_section are pruned
            let lower_section = lower_bound / items_per_section; // 8/5 = 1
            assert_eq!(lower_section, 1);
            assert_eq!(journal.oldest_section(), Some(lower_section));

            // Verify section 0 is pruned (< lower_section), section 1+ are retained (>= lower_section)
            assert!(!journal.blobs.contains_key(&0)); // Section 0 should be pruned
            assert!(journal.blobs.contains_key(&1)); // Section 1 should be retained (contains item 8)
            assert!(journal.blobs.contains_key(&2)); // Section 2 should be retained
            assert!(journal.blobs.contains_key(&3)); // Section 3 should be retained
            assert!(!journal.blobs.contains_key(&4)); // Section 4 should not exist

            // Verify data integrity: existing data in retained sections is accessible
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(10u64)); // First item in section 1 (1*10+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(11)); // Second item in section 1 (1*10+1)
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, Some(20)); // First item in section 2 (2*10+0)
            let last_element_section = 19 / items_per_section;
            let last_element_offset = (19 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, Some(34)); // Last item in section 3 (3*10+4)
            let next_element_section = 20 / items_per_section;
            let next_element_offset = (20 % items_per_section.get()) as u32;
            let item = journal
                .get(next_element_section, next_element_offset)
                .await
                .unwrap();
            assert_eq!(item, None); // Next element should not exist

            // Assert journal can accept new items
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_journal` with invalid parameters.
    #[test_traced]
    fn test_init_journal_invalid_parameters() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_invalid".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Test invalid bounds: lower > upper
            let result = init_journal::<deterministic::Context, u64>(
                context.clone(),
                cfg.clone(),
                10,        // lower_bound
                5,         // upper_bound (invalid: < lower_bound)
                NZU64!(5), // items_per_section
            )
            .await;
            assert!(matches!(
                result,
                Err(crate::journal::Error::InvalidSyncRange(10, 5))
            ));
        });
    }

    /// Test `init_journal` when existing data exactly matches the sync range.
    #[test_traced]
    fn test_init_journal_existing_data_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_exact_match".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data exactly matching sync range
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data to sections 1, 2, 3 (operations 5-19 with items_per_section=5)
            let items_per_section = NZU64!(5);
            for section in 1..4 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that exactly match existing data
            let lower_bound = 5; // section 1
            let upper_bound = 19; // section 3
            let journal = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with exact match");

            // Verify pruning to lower bound
            let lower_section = lower_bound / items_per_section; // 5/5 = 1
            assert_eq!(journal.oldest_section(), Some(lower_section));

            // Verify section 0 is pruned, sections 1-3 are retained
            assert!(!journal.blobs.contains_key(&0)); // Section 0 should be pruned
            assert!(journal.blobs.contains_key(&1)); // Section 1 should be retained (contains operation 5)
            assert!(journal.blobs.contains_key(&2)); // Section 2 should be retained
            assert!(journal.blobs.contains_key(&3)); // Section 3 should be retained

            // Verify data integrity: existing data in retained sections is accessible
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(100u64)); // First item in section 1 (1*100+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(101)); // Second item in section 1 (1*100+1)
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, Some(200)); // First item in section 2 (2*100+0)
            let last_element_section = 19 / items_per_section;
            let last_element_offset = (19 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, Some(304)); // Last item in section 3 (3*100+4)
            let next_element_section = 20 / items_per_section;
            let next_element_offset = (20 % items_per_section.get()) as u32;
            let item = journal
                .get(next_element_section, next_element_offset)
                .await
                .unwrap();
            assert_eq!(item, None); // Next element should not exist

            // Assert journal can accept new operations
            let mut journal = journal;
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_journal` when existing data exceeds the sync target range.
    #[test_traced]
    fn test_init_journal_existing_data_with_rewind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_rewind".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data beyond sync range
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data to sections 0-5 (operations 0-29 with items_per_section=5)
            let items_per_section = NZU64!(5);
            for section in 0..6 {
                for item in 0..items_per_section.get() {
                    journal
                        .append(section, section * 1000 + item)
                        .await
                        .unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that are exceeded by existing data
            let lower_bound = 8; // section 1
            let upper_bound = 17; // section 3
            let mut journal = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with rewind");

            // Verify pruning to lower bound and rewinding beyond upper bound
            let lower_section = lower_bound / items_per_section; // 8/5 = 1
            assert_eq!(journal.oldest_section(), Some(lower_section));

            // Verify section 0 is pruned (< lower_section)
            assert!(!journal.blobs.contains_key(&0));

            // Verify sections within sync range exist (lower_section <= section <= upper_section)
            assert!(journal.blobs.contains_key(&1)); // Section 1 (contains operation 8)
            assert!(journal.blobs.contains_key(&2)); // Section 2
            assert!(journal.blobs.contains_key(&3)); // Section 3 (contains operation 17)

            // Verify sections beyond upper bound are removed (> upper_section)
            assert!(!journal.blobs.contains_key(&4)); // Section 4 should be removed
            assert!(!journal.blobs.contains_key(&5)); // Section 5 should be removed

            // Verify data integrity in retained sections
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(1000u64)); // First item in section 1 (1*1000+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(1001)); // Second item in section 1 (1*1000+1)
            let item = journal.get(3, 0).await.unwrap();
            assert_eq!(item, Some(3000)); // First item in section 3 (3*1000+0)
            let last_element_section = 17 / items_per_section;
            let last_element_offset = (17 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, Some(3002)); // Last item in section 3 (3*1000+2)

            // Verify that section 3 was properly truncated
            let section_3_size = journal.size(3).await.unwrap();
            assert_eq!(section_3_size, 3 * ITEM_ALIGNMENT);

            // Verify that operations beyond upper_bound (17) are not accessible
            // Reading beyond the truncated section should return an error
            let result = journal.get(3, 3).await;
            assert!(result.is_err()); // Operation 18 should be inaccessible (beyond upper_bound=17)

            // Assert journal can accept new operations
            let (offset, _) = journal.append(3, 999).await.unwrap();
            assert_eq!(journal.get(3, offset).await.unwrap(), Some(999));

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_journal` when all existing data is stale (before lower bound).
    #[test_traced]
    fn test_init_journal_existing_data_stale() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_stale".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with stale data
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data to sections 0, 1 (operations 0-9 with items_per_section=5)
            let items_per_section = NZU64!(5);
            for section in 0..2 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries beyond all existing data
            let lower_bound = 15; // section 3
            let upper_bound = 25; // section 5
            let journal = init_journal::<deterministic::Context, u64>(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with stale data");

            // Verify fresh journal (all old data destroyed)
            assert!(journal.blobs.is_empty());
            assert_eq!(journal.oldest_section(), None);

            // Verify old sections don't exist
            assert!(!journal.blobs.contains_key(&0));
            assert!(!journal.blobs.contains_key(&1));

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_journal` with section boundary edge cases.
    #[test_traced]
    fn test_init_journal_section_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_boundaries".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create journal with data at section boundaries
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            let items_per_section = NZU64!(5);

            // Add data to sections 0, 1, 2, 3, 4
            for section in 0..5 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Test sync boundaries exactly at section boundaries
            let lower_bound = 10; // Exactly at section boundary (10/5 = 2)
            let upper_bound = 19; // Exactly at section boundary (19/5 = 3)
            let mut journal = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal at boundaries");

            // Verify correct section range
            let lower_section = lower_bound / items_per_section; // 2
            assert_eq!(journal.oldest_section(), Some(lower_section));

            // Verify sections 2, 3, 4 exist, others don't
            assert!(!journal.blobs.contains_key(&0));
            assert!(!journal.blobs.contains_key(&1));
            assert!(journal.blobs.contains_key(&2));
            assert!(journal.blobs.contains_key(&3));
            assert!(!journal.blobs.contains_key(&4)); // Section 4 should not exist

            // Verify data integrity in retained sections
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, Some(200u64)); // First item in section 2
            let item = journal.get(3, 4).await.unwrap();
            assert_eq!(item, Some(304)); // Last element
            let next_element_section = 4;
            let item = journal.get(next_element_section, 0).await.unwrap();
            assert_eq!(item, None); // Next element should not exist

            // Assert journal can accept new operations
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_journal` when lower_bound and upper_bound are in the same section.
    #[test_traced]
    fn test_init_journal_same_section_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_same_section".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create journal with data in multiple sections
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            let items_per_section = NZU64!(5);

            // Add data to sections 0, 1, 2
            for section in 0..3 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Test sync boundaries within the same section
            let lower_bound = 6; // operation 6 (section 1: 6/5 = 1)
            let upper_bound = 8; // operation 8 (section 1: 8/5 = 1)
            let journal = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with same-section bounds");

            // Both operations are in section 1, so section 0 should be pruned, section 1+ retained
            let target_section = lower_bound / items_per_section; // 6/5 = 1
            assert_eq!(journal.oldest_section(), Some(target_section));

            // Verify pruning and retention
            assert!(!journal.blobs.contains_key(&0)); // Section 0 should be pruned
            assert!(journal.blobs.contains_key(&1)); // Section 1 should be retained
            assert!(!journal.blobs.contains_key(&2)); // Section 2 should be removed (> upper_section)

            // Verify data integrity
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(100u64)); // First item in section 1
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(101)); // Second item in section 1 (1*100+1)
            let item = journal.get(1, 3).await.unwrap();
            assert_eq!(item, Some(103)); // Item at offset 3 in section 1 (1*100+3)

            // Verify that section 1 was properly truncated
            let section_1_size = journal.size(1).await.unwrap();
            assert_eq!(section_1_size, 64); // Should be 4 operations * 16 bytes = 64 bytes

            // Verify that operation beyond upper_bound (8) is not accessible
            let result = journal.get(1, 4).await;
            assert!(result.is_err()); // Operation 9 should be inaccessible (beyond upper_bound=8)

            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, None); // Section 2 was removed, so no items

            // Assert journal can accept new operations
            let mut journal = journal;
            let (offset, _) = journal.append(target_section, 999).await.unwrap();
            assert_eq!(
                journal.get(target_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `compute_offset` correctly calculates byte boundaries for variable-sized items.
    #[test_traced]
    fn test_compute_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_compute_offset".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create a journal and populate a section with 5 operations
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create journal");

            let section = 0;
            for i in 0..5 {
                journal.append(section, i as u64).await.unwrap();
            }
            journal.sync(section).await.unwrap();

            let blob = journal.blobs.get(&section).unwrap();

            // Helper function to compute byte size for N operations
            let compute_offset = |operations_count: u32| async move {
                compute_offset::<deterministic::Context, u64>(
                    blob,
                    &journal.cfg.codec_config,
                    journal.cfg.compression.is_some(),
                    operations_count,
                )
                .await
                .unwrap()
            };

            // Test various operation counts (each u64 operation takes 16 bytes when aligned)
            assert_eq!(compute_offset(0).await, 0); // 0 operations = 0 bytes
            assert_eq!(compute_offset(1).await, 16); // 1 operation = 16 bytes
            assert_eq!(compute_offset(3).await, 48); // 3 operations = 48 bytes
            assert_eq!(compute_offset(5).await, 80); // 5 operations = 80 bytes

            // Test requesting more operations than available (should return size of all available)
            assert_eq!(compute_offset(10).await, 80); // Still 80 bytes (capped at available)

            journal.destroy().await.unwrap();
        });
    }

    /// Test `prune_upper` correctly removes items beyond sync boundaries.
    #[test_traced]
    fn test_prune_upper() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_prune_upper".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };
            let items_per_section = 5;

            // Helper to create a fresh journal with test data
            let create_journal = || async {
                let mut journal =
                    VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                        .await
                        .expect("Failed to create journal");

                // Add operations to sections 0, 1, 2
                for section in 0..3 {
                    for i in 0..items_per_section {
                        journal.append(section, section * 100 + i).await.unwrap();
                    }
                    journal.sync(section).await.unwrap();
                }
                journal
            };

            // Test 1: No truncation needed (upper_bound at section end)
            {
                let mut journal = create_journal().await;
                let upper_bound = 9; // End of section 1 (section 1: ops 5-9)
                prune_upper(&mut journal, upper_bound, items_per_section)
                    .await
                    .unwrap();

                // Section 1 should remain unchanged (5 operations = 80 bytes)
                let section_1_size = journal.size(1).await.unwrap();
                assert_eq!(section_1_size, 80);
                journal.destroy().await.unwrap();
            }

            // Test 2: Truncation needed (upper_bound mid-section)
            {
                let mut journal = create_journal().await;
                let upper_bound = 7; // Middle of section 1 (keep ops 5, 6, 7)
                prune_upper(&mut journal, upper_bound, items_per_section)
                    .await
                    .unwrap();

                // Section 1 should now have only 3 operations (48 bytes)
                let section_1_size = journal.size(1).await.unwrap();
                assert_eq!(section_1_size, 48);

                // Verify the remaining operations are accessible
                assert_eq!(journal.get(1, 0).await.unwrap(), Some(100)); // section 1, offset 0 = 1*100+0
                assert_eq!(journal.get(1, 1).await.unwrap(), Some(101)); // section 1, offset 1 = 1*100+1
                assert_eq!(journal.get(1, 2).await.unwrap(), Some(102)); // section 1, offset 2 = 1*100+2

                // Verify truncated operations are not accessible
                let result = journal.get(1, 3).await;
                assert!(result.is_err()); // op at logical loc 8 should be gone
                journal.destroy().await.unwrap();
            }

            // Test 3: Non-existent section (should not error)
            {
                let mut journal = create_journal().await;
                prune_upper(
                    &mut journal,
                    99, // upper_bound that would be in a non-existent section
                    items_per_section,
                )
                .await
                .unwrap(); // Should not error
                journal.destroy().await.unwrap();
            }

            // Test 4: Upper bound beyond section (no truncation)
            {
                let mut journal = create_journal().await;
                let upper_bound = 15; // Beyond section 2
                let original_section_2_size = journal.size(2).await.unwrap();
                prune_upper(&mut journal, upper_bound, items_per_section)
                    .await
                    .unwrap();

                // Section 2 should remain unchanged
                let section_2_size = journal.size(2).await.unwrap();
                assert_eq!(section_2_size, original_section_2_size);
                journal.destroy().await.unwrap();
            }
        });
    }

    /// Test intra-section pruning.
    #[test_traced]
    fn test_prune_mid_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_prune_mid_section".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };
            let items_per_section = 3;

            // Create journal with data across multiple sections
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create journal");

            // Section 0: items 0, 1, 2
            // Section 1: items 3, 4, 5
            // Section 2: items 6, 7, 8
            for section in 0..3 {
                for i in 0..items_per_section {
                    let op_value = section * items_per_section + i;
                    journal.append(section, op_value).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Test with upper_bound in middle of section 1 (upper_bound = 4)
            // Should keep: items 2, 3, 4 (sections 0 partially removed, 1 truncated, 2 removed)
            let lower_bound = 2;
            let upper_bound = 4;
            let mut journal = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                NZU64!(items_per_section),
            )
            .await
            .expect("Failed to initialize synced journal");

            // Verify section 0 is partially present (only item 2)
            assert!(journal.blobs.contains_key(&0));
            assert_eq!(journal.get(0, 2).await.unwrap(), Some(2u64));

            // Verify section 1 is truncated (items 3, 4 only)
            assert!(journal.blobs.contains_key(&1));
            assert_eq!(journal.get(1, 0).await.unwrap(), Some(3));
            assert_eq!(journal.get(1, 1).await.unwrap(), Some(4));

            // item 5 should be inaccessible (truncated)
            let result = journal.get(1, 2).await;
            assert!(result.is_err());

            // Verify section 2 is completely removed
            assert!(!journal.blobs.contains_key(&2));

            // Test that new appends work correctly after truncation
            let (offset, _) = journal.append(1, 999).await.unwrap();
            assert_eq!(journal.get(1, offset).await.unwrap(), Some(999));

            journal.destroy().await.unwrap();
        });
    }

    type AnyTest = crate::adb::any::variable::Any<
        deterministic::Context,
        sha256::Digest,
        sha256::Digest,
        Sha256,
        TwoCap,
    >;

    fn create_sync_config(suffix: &str) -> crate::adb::any::variable::Config<TwoCap, ()> {
        const PAGE_SIZE: usize = 77;
        const PAGE_CACHE_SIZE: usize = 9;
        crate::adb::any::variable::Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("mmr_metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_section: NZU64!(7),
            log_compression: None,
            log_codec_config: (),
            log_write_buffer: NZUsize!(1024),
            locations_journal_partition: format!("locations_journal_{suffix}"),
            locations_items_per_blob: NZU64!(7),
            metadata_partition: format!("adb_metadata_{suffix}"),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    async fn create_test_db(mut context: deterministic::Context) -> AnyTest {
        let cfg = create_sync_config(&format!("var_any_sync_{}", context.next_u64()));
        AnyTest::init(context, cfg).await.unwrap()
    }

    fn create_updates(count: usize) -> Vec<(sha256::Digest, sha256::Digest)> {
        let mut rng = StdRng::seed_from_u64(1337);
        (0..count)
            .map(|_| {
                (
                    sha256::Digest::random(&mut rng),
                    sha256::Digest::random(&mut rng),
                )
            })
            .collect()
    }

    async fn apply_updates(db: &mut AnyTest, updates: &[(sha256::Digest, sha256::Digest)]) {
        for (k, v) in updates.iter().copied() {
            db.update(k, v).await.unwrap();
        }
    }

    #[test_traced("WARN")]
    fn test_variable_any_sync_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let updates = create_updates(100);
            apply_updates(&mut target_db, &updates).await;
            target_db.commit(None).await.unwrap();

            // Capture target state
            let mut hasher = crate::mmr::hasher::Standard::<Sha256>::new();
            let root = target_db.root(&mut hasher);
            let lower_bound = target_db.oldest_retained_loc().unwrap_or(0);
            let upper_bound = target_db.op_count() - 1;

            // Configure sync engine
            let db_config = create_sync_config(&format!("client_{}", context.next_u64()));
            let resolver = Arc::new(RwLock::new(target_db));
            let engine_cfg = sync::engine::Config {
                context: context.clone(),
                resolver: resolver.clone(),
                target: Target {
                    root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                max_outstanding_requests: 2,
                fetch_batch_size: NZU64!(10),
                apply_batch_size: 256,
                db_config: db_config.clone(),
                update_rx: None,
            };

            // Run sync
            let synced_db: AnyTest = sync::sync(engine_cfg).await.unwrap();

            // Validate state
            let mut hasher = crate::mmr::hasher::Standard::<Sha256>::new();
            assert_eq!(synced_db.root(&mut hasher), root);
            assert_eq!(synced_db.op_count(), upper_bound + 1);
            assert_eq!(synced_db.oldest_retained_loc().unwrap_or(0), lower_bound);

            // Smoke: verify some keys
            for (k, v) in updates.iter().take(10).copied() {
                let got = synced_db.get(&k).await.unwrap();
                assert_eq!(got, Some(v));
            }

            // Close and reopen to verify persistence
            synced_db.close().await.unwrap();
            let reopened = AnyTest::init(context, db_config).await.unwrap();
            let mut hasher = crate::mmr::hasher::Standard::<Sha256>::new();
            assert_eq!(reopened.root(&mut hasher), root);
        });
    }

    // Helper function to create test operations for variable::Any
    fn create_test_ops(count: usize) -> Vec<Variable<sha256::Digest, sha256::Digest>> {
        let mut rng = StdRng::seed_from_u64(1337);
        (0..count)
            .map(|_| {
                Variable::Set(
                    sha256::Digest::random(&mut rng),
                    sha256::Digest::random(&mut rng),
                )
            })
            .collect()
    }

    // Helper function to apply operations to database
    async fn apply_ops(db: &mut AnyTest, ops: &[Variable<sha256::Digest, sha256::Digest>]) {
        for op in ops {
            match op {
                Variable::Set(key, value) => {
                    db.update(*key, *value).await.unwrap();
                }
                Variable::Update(key, value) => {
                    db.update(*key, *value).await.unwrap();
                }
                Variable::Delete(key) => {
                    db.delete(*key).await.unwrap();
                }
                Variable::Commit(metadata) => {
                    db.commit(*metadata).await.unwrap();
                }
                Variable::CommitFloor(metadata, _floor) => {
                    // variable::Any doesn't have commit_floor, just use regular commit
                    db.commit(*metadata).await.unwrap();
                }
            }
        }
    }

    #[test_case(1, NZU64!(1); "singleton db with batch size == 1")]
    #[test_case(1, NZU64!(2); "singleton db with batch size > db size")]
    #[test_case(100, NZU64!(1); "db with batch size 1")]
    #[test_case(100, NZU64!(3); "db size not evenly divided by batch size")]
    #[test_case(100, NZU64!(99); "db size not evenly divided by batch size; different batch size")]
    #[test_case(100, NZU64!(50); "db size divided by batch size")]
    #[test_case(100, NZU64!(100); "db size == batch size")]
    #[test_case(100, NZU64!(101); "batch size > db size")]
    fn test_sync(target_db_ops: usize, fetch_batch_size: NonZeroU64) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_db_ops = create_test_ops(target_db_ops);

            apply_ops(&mut target_db, &target_db_ops).await;
            target_db.commit(None).await.unwrap();
            let target_op_count = target_db.op_count();
            let target_inactivity_floor = target_db.inactivity_floor_loc();

            let mut hasher = crate::mmr::hasher::Standard::<Sha256>::new();
            let target_root = target_db.root(&mut hasher);

            // Capture target database state and deleted keys before moving into config
            let mut expected_kvs = std::collections::HashMap::new();
            let mut deleted_keys = std::collections::HashSet::new();
            for op in &target_db_ops {
                match op {
                    Variable::Set(key, value) => {
                        // Only include keys that are actually accessible in the target database
                        if let Some(target_value) = target_db.get(key).await.unwrap() {
                            if target_value == *value {
                                expected_kvs.insert(*key, *value);
                                deleted_keys.remove(key);
                            }
                        }
                    }
                    Variable::Delete(key) => {
                        expected_kvs.remove(key);
                        deleted_keys.insert(*key);
                    }
                    Variable::Update(key, value) => {
                        // Only include keys that are actually accessible in the target database
                        if let Some(target_value) = target_db.get(key).await.unwrap() {
                            if target_value == *value {
                                expected_kvs.insert(*key, *value);
                                deleted_keys.remove(key);
                            }
                        }
                    }
                    Variable::CommitFloor(_metadata, _floor) => {}
                    Variable::Commit(_metadata) => {}
                }
            }

            let db_config = create_sync_config(&format!("sync_client_{}", context.next_u64()));
            let target_db = Arc::new(RwLock::new(target_db));
            let config = sync::engine::Config {
                db_config: db_config.clone(),
                fetch_batch_size,
                target: Target {
                    root: target_root,
                    lower_bound_ops: target_inactivity_floor,
                    upper_bound_ops: target_op_count - 1,
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let mut got_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify database state
            let mut hasher = crate::mmr::hasher::Standard::<Sha256>::new();
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(got_db.inactivity_floor_loc(), target_inactivity_floor);

            // Verify the root digest matches the target
            assert_eq!(got_db.root(&mut hasher), target_root);

            // Verify operation counts match
            let target_guard = target_db.read().await;
            assert_eq!(got_db.op_count(), target_guard.op_count(),);

            // Verify oldest retained location matches the sync lower bound
            // (synced database should only retain operations from lower_bound onwards)
            assert_eq!(
                got_db.oldest_retained_loc,
                target_inactivity_floor, // This should be the sync lower_bound
            );

            // Verify root hashes match (already checked above, but let's be explicit)
            let mut target_hasher = crate::mmr::hasher::Standard::<Sha256>::new();
            assert_eq!(
                got_db.root(&mut hasher),
                target_guard.root(&mut target_hasher),
            );
            drop(target_guard);

            // Verify that the synced database matches the target state
            for (key, expected_value) in &expected_kvs {
                let synced_value = got_db.get(key).await.unwrap();
                assert_eq!(synced_value, Some(*expected_value));
            }
            // Verify that deleted keys are absent
            for key in &deleted_keys {
                assert!(got_db.get(key).await.unwrap().is_none());
            }

            // Put more key-value pairs into both databases
            let mut new_ops = Vec::new();
            let mut rng = StdRng::seed_from_u64(42);
            let mut new_kvs = std::collections::HashMap::new();
            for _ in 0..expected_kvs.len() {
                let key = sha256::Digest::random(&mut rng);
                let value = sha256::Digest::random(&mut rng);
                new_ops.push(Variable::Set(key, value));
                new_kvs.insert(key, value);
            }
            apply_ops(&mut got_db, &new_ops).await;
            apply_ops(&mut *target_db.write().await, &new_ops).await;

            got_db.commit(None).await.unwrap();
            target_db.write().await.commit(None).await.unwrap();

            // Verify that the databases match
            for (key, value) in &new_kvs {
                let got_value = got_db.get(key).await.unwrap().unwrap();
                let target_value = target_db.read().await.get(key).await.unwrap().unwrap();
                assert_eq!(got_value, target_value);
                assert_eq!(got_value, *value);
            }

            let final_target_root = target_db.write().await.root(&mut hasher);
            let final_synced_root = got_db.root(&mut hasher);
            assert_eq!(final_synced_root, final_target_root);

            // Capture the database state before closing
            let final_synced_op_count = got_db.op_count();
            let final_synced_oldest_retained_loc = got_db.oldest_retained_loc().unwrap_or(0);
            let final_synced_root = got_db.root(&mut hasher);

            // Close the database
            got_db.close().await.unwrap();

            // Reopen the database using the same configuration and verify the state is unchanged
            let reopened_db = AnyTest::init(context, db_config).await.unwrap();

            // Compare state against the database state before closing
            assert_eq!(reopened_db.op_count(), final_synced_op_count);
            assert_eq!(
                reopened_db.oldest_retained_loc().unwrap_or(0),
                final_synced_oldest_retained_loc
            );
            assert_eq!(reopened_db.root(&mut hasher), final_synced_root);

            // Verify that the original key-value pairs are still correct
            for (key, &value) in &expected_kvs {
                let reopened_value = reopened_db.get(key).await.unwrap();
                assert_eq!(reopened_value, Some(value));
            }

            // Verify all new key-value pairs are still correct
            for (key, &value) in &new_kvs {
                let reopened_value = reopened_db.get(key).await.unwrap().unwrap();
                assert_eq!(reopened_value, value);
            }

            // Verify that deleted keys are still absent
            for key in &deleted_keys {
                assert!(reopened_db.get(key).await.unwrap().is_none());
            }

            reopened_db.destroy().await.unwrap();
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };
            target_db.destroy().await.unwrap();
        });
    }

    /// Test that invalid bounds are rejected
    #[test_traced("WARN")]
    fn test_sync_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_db = create_test_db(context.clone()).await;
            let db_config = create_sync_config(&format!("invalid_bounds_{}", context.next_u64()));
            let config = sync::engine::Config {
                db_config,
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root: sha256::Digest::from([1u8; 32]),
                    lower_bound_ops: 31, // Invalid: lower > upper
                    upper_bound_ops: 30,
                },
                context,
                resolver: Arc::new(RwLock::new(target_db)),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };

            let result: Result<AnyTest, _> = sync::sync(config).await;
            assert!(matches!(
                result,
                Err(sync::Error::InvalidTarget {
                    lower_bound_pos: 31,
                    upper_bound_pos: 30,
                }),
            ));
        });
    }

    /// Test that sync works when target database has operations beyond the requested range
    /// of operations to sync.
    #[test]
    fn test_sync_subset_of_target_database() {
        const TARGET_DB_OPS: usize = 1000;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(TARGET_DB_OPS);
            // Apply all but the last operation
            apply_ops(&mut target_db, &target_ops[0..TARGET_DB_OPS - 1]).await;
            target_db.commit(None).await.unwrap();

            let mut hasher = crate::mmr::hasher::Standard::<Sha256>::new();
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;
            let upper_bound_ops = target_db.op_count() - 1;

            // Add another operation after the sync range
            let final_op = &target_ops[TARGET_DB_OPS - 1];
            apply_ops(&mut target_db, from_ref(final_op)).await;
            target_db.commit(None).await.unwrap();

            // Sync to the "old" range (not including the final op)
            let config = sync::engine::Config {
                db_config: create_sync_config(&format!("subset_{}", context.next_u64())),
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context,
                resolver: Arc::new(RwLock::new(target_db)),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let synced_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify the synced database has the correct range of operations
            assert_eq!(synced_db.inactivity_floor_loc, lower_bound_ops);
            assert_eq!(synced_db.oldest_retained_loc(), Some(lower_bound_ops));
            assert_eq!(
                synced_db.mmr.pruned_to_pos(),
                leaf_num_to_pos(lower_bound_ops)
            );
            assert_eq!(synced_db.op_count(), upper_bound_ops + 1);

            // Verify the final root digest matches our target
            assert_eq!(synced_db.root(&mut hasher), root);

            // Verify the synced database doesn't have any operations beyond the sync range.
            assert_eq!(synced_db.get(final_op.key().unwrap()).await.unwrap(), None);

            synced_db.destroy().await.unwrap();
        });
    }

    // Test syncing where the sync client has some but not all of the operations in the target
    // database.
    #[test]
    fn test_sync_use_existing_db_partial_match() {
        const ORIGINAL_DB_OPS: usize = 1_000;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let original_ops = create_test_ops(ORIGINAL_DB_OPS);

            // Create two databases
            let mut target_db = create_test_db(context.clone()).await;
            let sync_db_config =
                create_sync_config(&format!("partial_match_{}", context.next_u64()));
            let mut sync_db = AnyTest::init(context.clone(), sync_db_config.clone())
                .await
                .unwrap();

            // Apply the same operations to both databases
            apply_ops(&mut target_db, &original_ops).await;
            apply_ops(&mut sync_db, &original_ops).await;
            target_db.commit(None).await.unwrap();
            sync_db.commit(None).await.unwrap();

            // Close sync_db
            sync_db.close().await.unwrap();

            // Add one more operation and commit the target database
            let last_op = create_test_ops(1);
            apply_ops(&mut target_db, &last_op).await;
            target_db.commit(None).await.unwrap();
            let mut hasher = crate::mmr::hasher::Standard::<Sha256>::new();
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;
            let upper_bound_ops = target_db.op_count() - 1; // Up to the last operation

            // Reopen the sync database and sync it to the target database
            let target_db = Arc::new(RwLock::new(target_db));
            let config = sync::engine::Config {
                db_config: sync_db_config, // Use same config as before
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let sync_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), upper_bound_ops + 1);
            assert_eq!(
                sync_db.inactivity_floor_loc,
                target_db.read().await.inactivity_floor_loc
            );
            assert!(sync_db.oldest_retained_loc().unwrap() <= lower_bound_ops);
            assert_eq!(
                sync_db.mmr.pruned_to_pos(),
                leaf_num_to_pos(lower_bound_ops)
            );
            // Verify the root digest matches the target
            assert_eq!(sync_db.root(&mut hasher), root);

            // Verify the last operation is present
            let last_key = last_op[0].key().unwrap();
            let last_value = *last_op[0].value().unwrap();
            assert_eq!(sync_db.get(last_key).await.unwrap(), Some(last_value));

            sync_db.destroy().await.unwrap();
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test case where existing database on disk exactly matches the sync target
    #[test_traced("WARN")]
    fn test_sync_use_existing_db_exact_match() {
        const NUM_OPS: usize = 50;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(NUM_OPS);
            apply_ops(&mut target_db, &target_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture target state
            let target_db_op_count = target_db.op_count();
            let target_db_oldest_retained_loc = target_db.oldest_retained_loc().unwrap_or(0);
            let mut hasher = crate::mmr::hasher::Standard::<Sha256>::new();
            let target_root = target_db.root(&mut hasher);

            // Create sync database with exactly the same operations
            let sync_db_config = create_sync_config(&format!("exact_match_{}", context.next_u64()));
            let mut sync_db: AnyTest = AnyTest::init(context.clone(), sync_db_config.clone())
                .await
                .unwrap();
            apply_ops(&mut sync_db, &target_ops).await;
            sync_db.commit(None).await.unwrap();

            // Verify they have the same state before sync
            assert_eq!(sync_db.op_count(), target_db_op_count);
            assert_eq!(sync_db.root(&mut hasher), target_root);

            // Close the sync database
            sync_db.close().await.unwrap();

            // Sync should recognize the exact match and reuse existing data
            let target_db = Arc::new(RwLock::new(target_db));
            let config = sync::engine::Config {
                db_config: sync_db_config,
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root: target_root,
                    lower_bound_ops: target_db_oldest_retained_loc,
                    upper_bound_ops: target_db_op_count - 1,
                },
                context,
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let sync_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify database state matches exactly
            let mut hasher = crate::mmr::hasher::Standard::<Sha256>::new();
            assert_eq!(sync_db.op_count(), target_db_op_count);
            assert_eq!(
                sync_db.oldest_retained_loc().unwrap_or(0),
                target_db_oldest_retained_loc
            );
            assert_eq!(sync_db.root(&mut hasher), target_root);

            // Verify data integrity
            let mut expected_kvs = std::collections::HashMap::new();
            for op in &target_ops {
                if let Variable::Set(key, value) = op {
                    expected_kvs.insert(*key, *value);
                }
            }

            for (key, expected_value) in &expected_kvs {
                let target_value = target_db.read().await.get(key).await.unwrap().unwrap();
                let synced_value = sync_db.get(key).await.unwrap().unwrap();
                assert_eq!(synced_value, target_value);
                assert_eq!(synced_value, *expected_value);
            }

            sync_db.destroy().await.unwrap();
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };
            target_db.destroy().await.unwrap();
        });
    }

    /// Test that the client fails to sync if the lower bound is decreased
    #[test_traced("WARN")]
    fn test_target_update_lower_bound_decrease() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, &target_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture initial target state
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc();
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_sync_config(&format!("test_config_{}", context.next_u64())),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };
            let client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();

            // Send target update with decreased lower bound
            update_sender
                .send(Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound.saturating_sub(1),
                    upper_bound_ops: initial_upper_bound.saturating_add(1),
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::SyncTargetMovedBackward { .. })
            ));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client fails to sync if the upper bound is decreased
    #[test_traced("WARN")]
    fn test_target_update_upper_bound_decrease() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, &target_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture initial target state
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc();
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_sync_config(&format!("test_config_{}", context.next_u64())),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };
            let client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();

            // Send target update with decreased upper bound
            update_sender
                .send(Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound.saturating_sub(1),
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::SyncTargetMovedBackward { .. })
            ));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client succeeds when bounds are updated
    #[test_traced("WARN")]
    fn test_target_update_bounds_increase() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(100);
            apply_ops(&mut target_db, &target_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture initial target state
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc();
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Apply more operations to the target database
            let more_ops = create_test_ops(1);
            apply_ops(&mut target_db, &more_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture final target state
            let mut hasher = test_hasher();
            let final_lower_bound = target_db.inactivity_floor_loc();
            let final_upper_bound = target_db.op_count() - 1;
            let final_root = target_db.root(&mut hasher);

            // Create client with placeholder initial target (stale compared to final target)
            let (mut update_sender, update_receiver) = mpsc::channel(1);

            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_sync_config(&format!("test_config_{}", context.next_u64())),
                fetch_batch_size: NZU64!(1),
                target: Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: Some(update_receiver),
            };

            // Send target update with increased bounds
            update_sender
                .send(Target {
                    root: final_root,
                    lower_bound_ops: final_lower_bound,
                    upper_bound_ops: final_upper_bound,
                })
                .await
                .unwrap();

            // Complete the sync
            let synced_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify the synced database has the expected state
            let mut hasher = test_hasher();
            assert_eq!(synced_db.root(&mut hasher), final_root);
            assert_eq!(synced_db.op_count(), final_upper_bound + 1);
            assert_eq!(synced_db.inactivity_floor_loc(), final_lower_bound);
            assert_eq!(synced_db.oldest_retained_loc().unwrap(), final_lower_bound);

            synced_db.destroy().await.unwrap();

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client fails to sync with invalid bounds (lower > upper)
    #[test_traced("WARN")]
    fn test_target_update_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, &target_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture initial target state
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc();
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_sync_config(&format!("test_config_{}", context.next_u64())),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };
            let client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();

            // Send target update with invalid bounds (lower > upper)
            update_sender
                .send(Target {
                    root: initial_root,
                    lower_bound_ops: initial_upper_bound, // Greater than upper bound
                    upper_bound_ops: initial_lower_bound, // Less than lower bound
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(result, Err(sync::Error::InvalidTarget { .. })));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that target updates can be sent even after the client is done
    #[test_traced("WARN")]
    fn test_target_update_on_done_client() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, &target_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture target state
            let mut hasher = test_hasher();
            let lower_bound = target_db.inactivity_floor_loc();
            let upper_bound = target_db.op_count() - 1;
            let root = target_db.root(&mut hasher);

            // Create client with target that will complete immediately
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_sync_config(&format!("test_config_{}", context.next_u64())),
                fetch_batch_size: NZU64!(20),
                target: Target {
                    root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };

            // Complete the sync
            let synced_db: AnyTest = sync::sync(config).await.unwrap();

            // Attempt to apply a target update after sync is complete to verify
            // we don't panic
            let _ = update_sender
                .send(Target {
                    // Dummy target update
                    root: sha256::Digest::from([2u8; 32]),
                    lower_bound_ops: lower_bound + 1,
                    upper_bound_ops: upper_bound + 1,
                })
                .await;

            // Verify the synced database has the expected state
            let mut hasher = test_hasher();
            assert_eq!(synced_db.root(&mut hasher), root);
            assert_eq!(synced_db.op_count(), upper_bound + 1);
            assert_eq!(synced_db.inactivity_floor_loc(), lower_bound);

            synced_db.destroy().await.unwrap();

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client can handle target updates during sync execution
    #[test_case(1, 1)]
    #[test_case(1, 2)]
    #[test_case(1, 100)]
    #[test_case(2, 1)]
    #[test_case(2, 2)]
    #[test_case(2, 100)]
    // Regression test: panicked when we didn't set pinned nodes after updating target
    #[test_case(20, 10)]
    #[test_case(100, 1)]
    #[test_case(100, 2)]
    #[test_case(100, 100)]
    #[test_case(100, 1000)]
    #[test_traced("WARN")]
    fn test_target_update_during_sync(initial_ops: usize, additional_ops: usize) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database with initial operations
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(initial_ops);
            apply_ops(&mut target_db, &target_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture initial target state
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc();
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Wrap target database for shared mutable access
            let target_db = Arc::new(RwLock::new(target_db));

            // Create client with initial target and small batch size
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            // Step the client to process a batch
            let client = {
                let config = Config {
                    context: context.clone(),
                    db_config: create_sync_config(&format!("test_config_{}", context.next_u64())),
                    target: Target {
                        root: initial_root,
                        lower_bound_ops: initial_lower_bound,
                        upper_bound_ops: initial_upper_bound,
                    },
                    resolver: target_db.clone(),
                    fetch_batch_size: NZU64!(1), // Small batch size so we don't finish after one batch
                    max_outstanding_requests: 10,
                    apply_batch_size: 1024,
                    update_rx: Some(update_receiver),
                };
                let mut client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();
                loop {
                    // Step the client until we have processed a batch of operations
                    client = match client.step().await.unwrap() {
                        NextStep::Continue(new_client) => new_client,
                        NextStep::Complete(_) => panic!("client should not be complete"),
                    };
                    let log_size = client.journal().size().await.unwrap();
                    if log_size > initial_lower_bound {
                        break client;
                    }
                }
            };

            // Modify the target database by adding more operations
            let additional_ops = create_test_ops(additional_ops);
            let new_root = {
                let mut db = target_db.write().await;
                apply_ops(&mut db, &additional_ops).await;
                db.commit(None).await.unwrap();

                // Capture new target state
                let mut hasher = test_hasher();
                let new_lower_bound = db.inactivity_floor_loc;
                let new_upper_bound = db.op_count() - 1;
                let new_root = db.root(&mut hasher);

                // Send target update with new target
                update_sender
                    .send(Target {
                        root: new_root,
                        lower_bound_ops: new_lower_bound,
                        upper_bound_ops: new_upper_bound,
                    })
                    .await
                    .unwrap();

                new_root
            };

            // Complete the sync
            let synced_db = match client.sync().await {
                Ok(db) => db,
                Err(e) => {
                    panic!("Sync failed: {e:?}");
                }
            };

            // Verify the synced database has the expected final state
            let mut hasher = test_hasher();
            let synced_root = synced_db.root(&mut hasher);

            // Verify the target database matches the synced database
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };

            // Now do the assertions after seeing the debug output
            assert_eq!(synced_root, new_root);

            {
                assert_eq!(synced_db.op_count(), target_db.op_count());
                assert_eq!(
                    synced_db.inactivity_floor_loc,
                    target_db.inactivity_floor_loc
                );
                assert_eq!(
                    synced_db.oldest_retained_loc().unwrap(),
                    target_db.inactivity_floor_loc
                );
                assert_eq!(synced_db.root(&mut hasher), target_db.root(&mut hasher));
            }

            // Verify the expected operations are present in the synced database.
            for i in synced_db.inactivity_floor_loc..synced_db.op_count() {
                let got = synced_db.get_op(i).await.unwrap();
                let expected = target_db.get_op(i).await.unwrap();
                assert_eq!(got, expected);
            }
            for i in synced_db.mmr.oldest_retained_pos().unwrap()..synced_db.mmr.size() {
                let got = synced_db.mmr.get_node(i).await.unwrap();
                let expected = target_db.mmr.get_node(i).await.unwrap();
                assert_eq!(got, expected);
            }

            synced_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_sync_database_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create and populate a simple target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, &target_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture target state
            let mut hasher = test_hasher();
            let target_root = target_db.root(&mut hasher);
            let lower_bound = target_db.inactivity_floor_loc();
            let upper_bound = target_db.op_count() - 1;

            // Perform sync
            let db_config = create_sync_config("test_persistence_42");
            let context_clone = context.clone();
            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: target_root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                context,
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let synced_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify initial sync worked
            let mut hasher = test_hasher();
            assert_eq!(synced_db.root(&mut hasher), target_root);

            // Save state before closing
            let expected_root = synced_db.root(&mut hasher);
            let expected_op_count = synced_db.op_count();
            let expected_inactivity_floor_loc = synced_db.inactivity_floor_loc();
            let expected_oldest_retained_loc = synced_db.oldest_retained_loc();
            let expected_pruned_to_pos = synced_db.mmr.pruned_to_pos();

            // Close the database
            synced_db.close().await.unwrap();

            // Re-open the database
            let reopened_db = AnyTest::init(context_clone, db_config).await.unwrap();

            // Verify the state is unchanged
            assert_eq!(reopened_db.root(&mut hasher), expected_root);
            assert_eq!(reopened_db.op_count(), expected_op_count);
            assert_eq!(
                reopened_db.inactivity_floor_loc(),
                expected_inactivity_floor_loc
            );
            assert_eq!(
                reopened_db.oldest_retained_loc(),
                expected_oldest_retained_loc
            );
            assert_eq!(reopened_db.mmr.pruned_to_pos(), expected_pruned_to_pos);

            // Cleanup
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
            reopened_db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_sync_resolver_fails() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let resolver =
                FailResolver::<sha256::Digest, Variable<sha256::Digest, sha256::Digest>>::new();
            let target_root = sha256::Digest::from([0; 32]);

            let db_config =
                create_sync_config(&format!("test_fail_resolver_{}", context.next_u64()));
            let engine_config = Config {
                context,
                target: Target {
                    root: target_root,
                    lower_bound_ops: 0,
                    upper_bound_ops: 4,
                },
                resolver,
                apply_batch_size: 2,
                max_outstanding_requests: 2,
                fetch_batch_size: NZU64!(2),
                db_config,
                update_rx: None,
            };

            // Attempt to sync - should fail due to resolver error
            let result: Result<AnyTest, _> = sync::sync(engine_config).await;
            assert!(result.is_err());
        });
    }

    /// Test prune_journal with an empty journal
    #[test_traced]
    fn test_prune_journal_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_prune_empty".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            let mut journal = VJournal::<deterministic::Context, u64>::init(context.clone(), cfg)
                .await
                .expect("Failed to create journal");

            let mut metadata = Metadata::<deterministic::Context, U64, u64>::init(
                context.clone(),
                crate::metadata::Config {
                    partition: "test_prune_empty_metadata".into(),
                    codec_config: (),
                },
            )
            .await
            .expect("Failed to create metadata");

            let lower_bound = 10;
            let upper_bound = 20;
            write_oldest_retained_loc(&mut metadata, 0);
            let items_per_section = NZU64!(5);

            let next_loc = prune_journal(
                &mut journal,
                &mut metadata,
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to prune journal");

            // Oldest retained loc and next write loc should be lower_bound
            assert_eq!(next_loc, lower_bound);
            let new_oldest_retained_loc = read_oldest_retained_loc(&metadata);
            assert_eq!(new_oldest_retained_loc, lower_bound);
            assert!(journal.blobs.is_empty());
        });
    }

    /// Test prune_journal with data entirely before lower_bound
    #[test_traced]
    fn test_prune_journal_data_before_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_prune_before".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            let mut journal = VJournal::<deterministic::Context, u64>::init(context.clone(), cfg)
                .await
                .expect("Failed to create journal");

            let mut metadata = Metadata::<deterministic::Context, U64, u64>::init(
                context.clone(),
                crate::metadata::Config {
                    partition: "test_prune_before_metadata".into(),
                    codec_config: (),
                },
            )
            .await
            .expect("Failed to create metadata");

            // Add data to sections 0 and 1 (locations 0-9)
            let items_per_section = NZU64!(5);
            for section in 0..2 {
                for i in 0..items_per_section.get() {
                    journal.append(section, section * 100 + i).await.unwrap();
                }
            }

            // New bounds are ahead of data in the journal
            let lower_bound = 15; // Section 3
            let upper_bound = 25; // Section 5
            write_oldest_retained_loc(&mut metadata, 0);

            let next_loc = prune_journal(
                &mut journal,
                &mut metadata,
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to prune journal");

            // All data is before lower_bound, should be pruned
            assert_eq!(next_loc, lower_bound);
            let new_oldest_retained_loc = read_oldest_retained_loc(&metadata);
            assert_eq!(new_oldest_retained_loc, lower_bound); // Empty journal
            assert!(journal.blobs.is_empty());
        });
    }

    /// Test prune_journal with data partly after lower_bound but not reaching upper_bound
    #[test_traced]
    fn test_prune_journal_before_lower_and_before_upper() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_prune_partly_before".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            let mut journal = VJournal::<deterministic::Context, u64>::init(context.clone(), cfg)
                .await
                .expect("Failed to create journal");

            let mut metadata = Metadata::<deterministic::Context, U64, u64>::init(
                context.clone(),
                crate::metadata::Config {
                    partition: "test_prune_partly_before_metadata".into(),
                    codec_config: (),
                },
            )
            .await
            .expect("Failed to create metadata");

            // Add data to sections 0, 1, 2 (locations 0-14)
            let items_per_section = NZU64!(5);
            for section in 0..3 {
                for i in 0..items_per_section.get() {
                    journal.append(section, section * 100 + i).await.unwrap();
                }
            }

            let lower_bound = 7; // Middle of section 1
            let upper_bound = 20; // Section 4
            write_oldest_retained_loc(&mut metadata, 0);

            let next_loc = prune_journal(
                &mut journal,
                &mut metadata,
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to prune journal");

            // Should have data from locations 5-14 (all of section 1 and all of section 2)
            assert_eq!(next_loc, 15);
            let new_oldest_retained_loc = read_oldest_retained_loc(&metadata);
            assert_eq!(new_oldest_retained_loc, 5); // Should be section boundary (start of section 1)

            // Section 0 should be removed
            assert!(!journal.blobs.contains_key(&0));

            // Sections 1 and 2 should remain
            assert!(journal.blobs.contains_key(&1));
            assert!(journal.blobs.contains_key(&2));
        });
    }

    /// Test prune_journal with data starting after lower_bound but not reaching upper_bound
    #[test_traced]
    fn test_prune_journal_data_after_lower_not_reaching_upper() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_prune_after_lower".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            let mut journal = VJournal::<deterministic::Context, u64>::init(context.clone(), cfg)
                .await
                .expect("Failed to create journal");

            let mut metadata = Metadata::<deterministic::Context, U64, u64>::init(
                context.clone(),
                crate::metadata::Config {
                    partition: "test_prune_after_lower_metadata".into(),
                    codec_config: (),
                },
            )
            .await
            .expect("Failed to create metadata");

            let items_per_section = NZU64!(5);

            // Add data to sections 2 and 3 (locations 10-19)
            for section in 2..4 {
                for i in 0..items_per_section.get() {
                    journal.append(section, section * 100 + i).await.unwrap();
                }
            }

            let lower_bound = 5; // Section 1
            let upper_bound = 25; // Section 5
            write_oldest_retained_loc(&mut metadata, 10); // Start of section 2

            let next_loc = prune_journal(
                &mut journal,
                &mut metadata,
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to prune journal");

            // Should have data from locations 10-19
            assert_eq!(next_loc, 20);
            let new_oldest_retained_loc = read_oldest_retained_loc(&metadata);
            assert_eq!(new_oldest_retained_loc, 10);

            // Sections 2 and 3 should remain
            assert!(journal.blobs.contains_key(&2));
            assert!(journal.blobs.contains_key(&3));
        });
    }

    /// Test prune_journal with data that is a superset of sync range
    #[test_traced]
    fn test_prune_journal_data_superset_of_range() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_prune_spanning".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            let mut journal = VJournal::<deterministic::Context, u64>::init(context.clone(), cfg)
                .await
                .expect("Failed to create journal");

            let mut metadata = Metadata::<deterministic::Context, U64, u64>::init(
                context.clone(),
                crate::metadata::Config {
                    partition: "test_prune_spanning_metadata".into(),
                    codec_config: (),
                },
            )
            .await
            .expect("Failed to create metadata");

            let items_per_section = NZU64!(5);

            // Add data to sections 0-4 (locations 0-24)
            for section in 0..5 {
                for i in 0..items_per_section.get() {
                    journal.append(section, section * 100 + i).await.unwrap();
                }
            }

            let lower_bound = 7; // Middle of section 1
            let upper_bound = 17; // Middle of section 3
            write_oldest_retained_loc(&mut metadata, 5); // Start of section 1

            let next_loc = prune_journal(
                &mut journal,
                &mut metadata,
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to prune journal");

            // Should have data from location 5 to 17 (contiguity preserves section boundary)
            assert_eq!(next_loc, 18);
            let new_oldest_retained_loc = read_oldest_retained_loc(&metadata);
            assert_eq!(new_oldest_retained_loc, 5); // Should be section boundary (start of section 1)

            // Sections 0 and 4 should be removed
            assert!(!journal.blobs.contains_key(&0));
            assert!(!journal.blobs.contains_key(&4));

            // Sections 1, 2, and 3 should remain
            assert!(journal.blobs.contains_key(&1));
            assert!(journal.blobs.contains_key(&2));
            assert!(journal.blobs.contains_key(&3));
        });
    }

    /// Test prune_journal with lower and upper bounds in the same section
    #[test_traced]
    fn test_prune_journal_bounds_same_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_prune_same_section".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            let mut journal = VJournal::<deterministic::Context, u64>::init(context.clone(), cfg)
                .await
                .expect("Failed to create journal");

            let mut metadata = Metadata::<deterministic::Context, U64, u64>::init(
                context.clone(),
                crate::metadata::Config {
                    partition: "test_prune_same_section_metadata".into(),
                    codec_config: (),
                },
            )
            .await
            .expect("Failed to create metadata");

            // Add data to sections 0-2 (locations 0-29)
            let items_per_section = NZU64!(10);
            for section in 0..3 {
                for i in 0..items_per_section.get() {
                    journal.append(section, section * 100 + i).await.unwrap();
                }
            }

            let lower_bound = 12; // Within section 1
            let upper_bound = 17; // Also within section 1
            write_oldest_retained_loc(&mut metadata, 0);

            let next_loc = prune_journal(
                &mut journal,
                &mut metadata,
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to prune journal");

            // Should keep all elements 10-17 from section 1
            // The upper section pruning will truncate section 1 to only contain elements 10-17
            assert_eq!(next_loc, 18);
            let new_oldest_retained_loc = read_oldest_retained_loc(&metadata);
            assert_eq!(new_oldest_retained_loc, 10); // Section boundary (start of section 1)

            // Only section 1 should remain
            assert!(!journal.blobs.contains_key(&0));
            assert!(journal.blobs.contains_key(&1));
            assert!(!journal.blobs.contains_key(&2));
        });
    }

    /// Test prune_journal with bounds at section boundaries
    #[test_traced]
    fn test_prune_journal_bounds_at_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_prune_boundaries".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            let mut journal = VJournal::<deterministic::Context, u64>::init(context.clone(), cfg)
                .await
                .expect("Failed to create journal");

            let mut metadata = Metadata::<deterministic::Context, U64, u64>::init(
                context.clone(),
                crate::metadata::Config {
                    partition: "test_prune_boundaries_metadata".into(),
                    codec_config: (),
                },
            )
            .await
            .expect("Failed to create metadata");

            let items_per_section = NZU64!(5);

            // Add data to sections 0-4 (locations 0-24)
            for section in 0..5 {
                for i in 0..items_per_section.get() {
                    journal.append(section, section * 100 + i).await.unwrap();
                }
            }

            let lower_bound = 10; // Start of section 2
            let upper_bound = 19; // End of section 3
            write_oldest_retained_loc(&mut metadata, 0);

            let next_loc = prune_journal(
                &mut journal,
                &mut metadata,
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to prune journal");

            // Should have data from location 10 to 19
            assert_eq!(next_loc, 20);
            let new_oldest_retained_loc = read_oldest_retained_loc(&metadata);
            assert_eq!(new_oldest_retained_loc, lower_bound); // Should be lower_bound after pruning at start of section 2

            // Sections 0, 1, and 4 should be removed
            assert!(!journal.blobs.contains_key(&0));
            assert!(!journal.blobs.contains_key(&1));
            assert!(!journal.blobs.contains_key(&4));

            // Sections 2 and 3 should remain
            assert!(journal.blobs.contains_key(&2));
            assert!(journal.blobs.contains_key(&3));
        });
    }

    /// Test prune_journal with invalid bounds (lower > upper)
    #[test_traced]
    fn test_prune_journal_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_prune_invalid".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            let mut journal = VJournal::<deterministic::Context, u64>::init(context.clone(), cfg)
                .await
                .expect("Failed to create journal");

            let mut metadata = Metadata::<deterministic::Context, U64, u64>::init(
                context.clone(),
                crate::metadata::Config {
                    partition: "test_prune_invalid_metadata".into(),
                    codec_config: (),
                },
            )
            .await
            .expect("Failed to create metadata");

            let lower_bound = 20;
            let upper_bound = 10; // Invalid: lower > upper
            write_oldest_retained_loc(&mut metadata, 0);
            let items_per_section = NZU64!(5);

            let result = prune_journal(
                &mut journal,
                &mut metadata,
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await;

            // Should return an error for invalid bounds
            assert!(matches!(
                result,
                Err(crate::journal::Error::InvalidSyncRange(_, _))
            ));
        });
    }

    /// Test prune_journal when lower section needs rebuilding (non-contiguous case)
    #[test_traced]
    fn test_prune_journal_non_contiguous_rebuild() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_non_contiguous".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            let mut journal = VJournal::<deterministic::Context, u64>::init(context.clone(), cfg)
                .await
                .expect("Failed to create journal");

            let mut metadata = Metadata::<deterministic::Context, U64, u64>::init(
                context.clone(),
                crate::metadata::Config {
                    partition: "test_non_contiguous_metadata".into(),
                    codec_config: (),
                },
            )
            .await
            .expect("Failed to create metadata");

            let items_per_section = NZU64!(10);

            // Add data to section 1 (locations 10-14)
            for i in 0..5 {
                journal.append(1, 100 + i).await.unwrap();
            }

            // Set up non-contiguous scenario: existing items [10,14], lower_bound=16 (gap exists)
            let lower_bound = 16; // Gap between existing_max(14) and lower_bound(16)
            let upper_bound = 19;
            write_oldest_retained_loc(&mut metadata, 10);

            let next_loc = prune_journal(
                &mut journal,
                &mut metadata,
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to prune journal");

            // Should rebuild section and set oldest_retained_loc to lower_bound
            assert_eq!(next_loc, lower_bound); // Journal should be empty after rebuild
            let new_oldest_retained_loc = read_oldest_retained_loc(&metadata);
            assert_eq!(new_oldest_retained_loc, lower_bound); // Should be lower_bound, not section boundary

            // Section 1 should be removed since no operations were kept after rebuild
            assert!(!journal.blobs.contains_key(&1));
        });
    }
}
