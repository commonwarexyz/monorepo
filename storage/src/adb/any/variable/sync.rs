use crate::journal::{
    variable::{Config as VConfig, Journal as VJournal},
    Error,
};
use commonware_codec::Codec;
use commonware_runtime::{Metrics, Storage};
use std::{num::NonZeroU64, ops::Bound};
use tracing::debug;

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
) -> Result<VJournal<E, V>, Error> {
    if lower_bound > upper_bound {
        return Err(Error::InvalidSyncRange(lower_bound, upper_bound));
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
    truncate_upper_section(&mut journal, upper_bound, items_per_section).await?;

    Ok(journal)
}

/// Remove items beyond the `upper_bound` location (inclusive).
/// Assumes each section contains `items_per_section` items.
async fn truncate_upper_section<E: Storage + Metrics, V: Codec>(
    journal: &mut VJournal<E, V>,
    upper_bound: u64,
    items_per_section: u64,
) -> Result<(), Error> {
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
) -> Result<u64, Error> {
    use crate::journal::variable::{Journal, ITEM_ALIGNMENT};

    if items_count == 0 {
        return Ok(0);
    }

    let mut current_offset = 0u32;

    // Read through items one by one to find where each one ends
    for _ in 0..items_count {
        match Journal::<E, V>::read(compressed, codec_config, blob, current_offset).await {
            Ok((next_slot, _item_len, _item)) => {
                current_offset = next_slot;
            }
            Err(Error::Runtime(commonware_runtime::Error::BlobInsufficientLength)) => {
                // This section has fewer than `items_count` items.
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok((current_offset as u64) * ITEM_ALIGNMENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::variable::ITEM_ALIGNMENT;
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU64};

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
            assert_eq!(retrieved, 42u64);

            // Append another element
            let (offset2, _) = journal.append(lower_section, 43u64).await.unwrap();
            assert_eq!(journal.get(lower_section, offset2).await.unwrap(), 43u64);

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
            assert_eq!(item, 10u64); // First item in section 1 (1*10+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, 11); // Second item in section 1 (1*10+1)
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, 20); // First item in section 2 (2*10+0)
            let last_element_section = 19 / items_per_section;
            let last_element_offset = (19 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, 34); // Last item in section 3 (3*10+4)
            let next_element_section = 20 / items_per_section;
            let next_element_offset = (20 % items_per_section.get()) as u32;
            let result = journal.get(next_element_section, next_element_offset).await;
            assert!(matches!(result, Err(Error::SectionOutOfRange(4)))); // Next element should not exist

            // Assert journal can accept new items
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                999
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
            assert!(matches!(result, Err(Error::InvalidSyncRange(10, 5))));
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
            assert_eq!(item, 100u64); // First item in section 1 (1*100+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, 101); // Second item in section 1 (1*100+1)
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, 200); // First item in section 2 (2*100+0)
            let last_element_section = 19 / items_per_section;
            let last_element_offset = (19 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, 304); // Last item in section 3 (3*100+4)
            let next_element_section = 20 / items_per_section;
            let next_element_offset = (20 % items_per_section.get()) as u32;
            let result = journal.get(next_element_section, next_element_offset).await;
            assert!(matches!(result, Err(Error::SectionOutOfRange(4)))); // Next element should not exist

            // Assert journal can accept new operations
            let mut journal = journal;
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                999
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
            assert_eq!(item, 1000u64); // First item in section 1 (1*1000+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, 1001); // Second item in section 1 (1*1000+1)
            let item = journal.get(3, 0).await.unwrap();
            assert_eq!(item, 3000); // First item in section 3 (3*1000+0)
            let last_element_section = 17 / items_per_section;
            let last_element_offset = (17 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, 3002); // Last item in section 3 (3*1000+2)

            // Verify that section 3 was properly truncated
            let section_3_size = journal.size(3).await.unwrap();
            assert_eq!(section_3_size, 3 * ITEM_ALIGNMENT);

            // Verify that operations beyond upper_bound (17) are not accessible
            // Reading beyond the truncated section should return an error
            let result = journal.get(3, 3).await;
            assert!(result.is_err()); // Operation 18 should be inaccessible (beyond upper_bound=17)

            // Assert journal can accept new operations
            let (offset, _) = journal.append(3, 999).await.unwrap();
            assert_eq!(journal.get(3, offset).await.unwrap(), 999);

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
            assert_eq!(item, 200u64); // First item in section 2
            let item = journal.get(3, 4).await.unwrap();
            assert_eq!(item, 304); // Last element
            let next_element_section = 4;
            let result = journal.get(next_element_section, 0).await;
            assert!(matches!(result, Err(Error::SectionOutOfRange(4))));

            // Assert journal can accept new operations
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                999
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
            assert_eq!(item, 100u64); // First item in section 1
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, 101); // Second item in section 1 (1*100+1)
            let item = journal.get(1, 3).await.unwrap();
            assert_eq!(item, 103); // Item at offset 3 in section 1 (1*100+3)

            // Verify that section 1 was properly truncated
            let section_1_size = journal.size(1).await.unwrap();
            assert_eq!(section_1_size, 64); // Should be 4 operations * 16 bytes = 64 bytes

            // Verify that operation beyond upper_bound (8) is not accessible
            let result = journal.get(1, 4).await;
            assert!(result.is_err()); // Operation 9 should be inaccessible (beyond upper_bound=8)

            let result = journal.get(2, 0).await;
            assert!(matches!(result, Err(Error::SectionOutOfRange(2)))); // Section 2 was removed, so no items

            // Assert journal can accept new operations
            let mut journal = journal;
            let (offset, _) = journal.append(target_section, 999).await.unwrap();
            assert_eq!(journal.get(target_section, offset).await.unwrap(), 999);

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

    /// Test `truncate_upper_section` correctly removes items beyond sync boundaries.
    #[test_traced]
    fn test_truncate_section_to_upper_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_truncate_section".into(),
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
                truncate_upper_section(&mut journal, upper_bound, items_per_section)
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
                truncate_upper_section(&mut journal, upper_bound, items_per_section)
                    .await
                    .unwrap();

                // Section 1 should now have only 3 operations (48 bytes)
                let section_1_size = journal.size(1).await.unwrap();
                assert_eq!(section_1_size, 48);

                // Verify the remaining operations are accessible
                assert_eq!(journal.get(1, 0).await.unwrap(), 100); // section 1, offset 0 = 1*100+0
                assert_eq!(journal.get(1, 1).await.unwrap(), 101); // section 1, offset 1 = 1*100+1
                assert_eq!(journal.get(1, 2).await.unwrap(), 102); // section 1, offset 2 = 1*100+2

                // Verify truncated operations are not accessible
                let result = journal.get(1, 3).await;
                assert!(result.is_err());
                journal.destroy().await.unwrap();
            }

            // Test 3: Non-existent section (should not error)
            {
                let mut journal = create_journal().await;
                truncate_upper_section(
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
                truncate_upper_section(&mut journal, upper_bound, items_per_section)
                    .await
                    .unwrap();

                // Section 2 should remain unchanged
                let section_2_size = journal.size(2).await.unwrap();
                assert_eq!(section_2_size, original_section_2_size);
                journal.destroy().await.unwrap();
            }
        });
    }

    /// Test intra-section truncation.
    #[test_traced]
    fn test_truncate_section_mid_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_truncation_integration".into(),
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

            // Test sync with upper_bound in middle of section 1 (upper_bound = 4)
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
            assert_eq!(journal.get(0, 2).await.unwrap(), 2u64);

            // Verify section 1 is truncated (items 3, 4 only)
            assert!(journal.blobs.contains_key(&1));
            assert_eq!(journal.get(1, 0).await.unwrap(), 3);
            assert_eq!(journal.get(1, 1).await.unwrap(), 4);

            // item 5 should be inaccessible (truncated)
            let result = journal.get(1, 2).await;
            assert!(result.is_err());

            // Verify section 2 is completely removed
            assert!(!journal.blobs.contains_key(&2));

            // Test that new appends work correctly after truncation
            let (offset, _) = journal.append(1, 999).await.unwrap();
            assert_eq!(journal.get(1, offset).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }
}
