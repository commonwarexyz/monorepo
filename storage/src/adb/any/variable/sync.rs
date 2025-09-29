use crate::{
    adb,
    journal::variable::{Config as VConfig, Journal as VJournal},
    mmr::Location,
};
use commonware_codec::Codec;
use commonware_runtime::{Metrics, Storage};
use commonware_utils::NZUsize;
use core::num::NonZeroUsize;
use futures::{pin_mut, StreamExt as _};
use std::num::NonZeroU64;
use tracing::debug;

/// The size of the read buffer to use for replaying log operations.
const REPLAY_BUFFER_SIZE: NonZeroUsize = NZUsize!(1 << 14);

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
/// - Unexpected data beyond `upper_bound`: returns [adb::Error::UnexpectedData].
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
/// (journal, size) where:
/// - No section index < `lower_bound / items_per_section` exists.
/// - No section index > `upper_bound / items_per_section` exists.
/// - No item with location > `upper_bound` exists.
/// - `size` is the next location that should be appended to by the sync engine.
///
/// # Errors
/// Returns [adb::Error::UnexpectedData] if existing data extends beyond `upper_bound`.
pub(crate) async fn init_journal<E: Storage + Metrics, V: Codec>(
    context: E,
    cfg: VConfig<V::Cfg>,
    lower_bound: u64,
    upper_bound: u64,
    items_per_section: NonZeroU64,
) -> Result<(VJournal<E, V>, u64), adb::Error> {
    assert!(
        lower_bound <= upper_bound,
        "lower_bound ({lower_bound}) must be <= upper_bound ({upper_bound})"
    );

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
        return Ok((journal, lower_bound));
    };

    // If all existing data is before our sync range, destroy and recreate fresh
    if last_section < lower_section {
        debug!(
            last_section,
            lower_section, "existing journal data is stale, re-initializing"
        );
        journal.destroy().await?;
        let journal = VJournal::init(context, cfg).await?;
        return Ok((journal, lower_bound));
    }

    // Prune sections below the lower bound.
    if lower_section > 0 {
        journal.prune(lower_section).await?;
    }

    // Check if data exceeds the sync range
    if last_section > upper_section {
        let loc = last_section * items_per_section;
        return Err(adb::Error::UnexpectedData(Location::new(loc)));
    }

    let size = get_size(&journal, items_per_section).await?;
    if size > upper_bound + 1 {
        return Err(adb::Error::UnexpectedData(Location::new(size)));
    }

    Ok((journal, size))
}

/// Returns the number of items in the journal.
pub(crate) async fn get_size<E: Storage + Metrics, V: Codec>(
    journal: &VJournal<E, V>,
    items_per_section: u64,
) -> Result<u64, adb::Error> {
    let Some(last_section) = journal.blobs.last_key_value().map(|(&s, _)| s) else {
        return Ok(0);
    };
    let last_section_start = last_section * items_per_section;
    let stream = journal.replay(last_section, 0, REPLAY_BUFFER_SIZE).await?;
    pin_mut!(stream);
    let mut size = last_section_start;
    while let Some(item) = stream.next().await {
        let (section, _offset, _size, _op) = item?;
        assert_eq!(section, last_section);
        size += 1;
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Error;
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
            let (mut journal, size) = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with sync boundaries");
            assert_eq!(size, lower_bound);

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
            let (mut journal, size) = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with overlap");
            assert_eq!(size, 20);

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
    #[should_panic]
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

            let _result = init_journal::<deterministic::Context, u64>(
                context.clone(),
                cfg.clone(),
                10,        // lower_bound
                5,         // upper_bound (invalid: < lower_bound)
                NZU64!(5), // items_per_section
            )
            .await;
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
            let (journal, size) = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with exact match");
            assert_eq!(size, 20);

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
    /// This tests that UnexpectedData error is returned when existing data goes beyond the upper bound.
    #[test_traced]
    fn test_init_journal_existing_data_exceeds_upper_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_unexpected_data".into(),
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
            for upper_bound in 9..28 {
                let result = init_journal::<deterministic::Context, u64>(
                    context.clone(),
                    cfg.clone(),
                    lower_bound,
                    upper_bound,
                    items_per_section,
                )
                .await;

                // Should return UnexpectedData error since data exists beyond upper_bound
                assert!(matches!(result, Err(adb::Error::UnexpectedData(_))));
            }
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
            let (journal, size) = init_journal::<deterministic::Context, u64>(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with stale data");
            assert_eq!(size, 15);

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
            let lower_bound = 15; // Exactly at section boundary (15/5 = 3)
            let upper_bound = 24; // Exactly at section boundary (24/5 = 4)
            let (mut journal, size) = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal at boundaries");
            assert_eq!(size, 25);

            // Verify correct section range
            let lower_section = lower_bound / items_per_section; // 2
            assert_eq!(journal.oldest_section(), Some(lower_section));

            // Verify sections 2, 3, 4 exist, others don't
            assert!(!journal.blobs.contains_key(&0));
            assert!(!journal.blobs.contains_key(&1));
            assert!(!journal.blobs.contains_key(&2));
            assert!(journal.blobs.contains_key(&3));
            assert!(journal.blobs.contains_key(&4));

            // Verify data integrity in retained sections
            let item = journal.get(3, 0).await.unwrap();
            assert_eq!(item, 300u64); // First item in section 3
            let item = journal.get(3, 4).await.unwrap();
            assert_eq!(item, 304); // Last element
            let next_element_section = 5;
            let result = journal.get(next_element_section, 0).await;
            assert!(matches!(result, Err(Error::SectionOutOfRange(5))));

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
            let lower_bound = 10; // operation 10 (section 2: 10/5 = 2)
            let upper_bound = 14; // operation 14 (section 2: 14/5 = 2)
            let (journal, size) = init_journal(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with same-section bounds");
            assert_eq!(size, 15);

            // Both operations are in section 2, so sections 0, 1 should be pruned, section 2 retained
            let target_section = lower_bound / items_per_section; // 10/5 = 2
            assert_eq!(journal.oldest_section(), Some(target_section));
            assert!(!journal.blobs.contains_key(&0));
            assert!(!journal.blobs.contains_key(&1));
            assert!(journal.blobs.contains_key(&2));

            // Verify data integrity
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, 200u64); // First item in section 2
            let item = journal.get(2, 1).await.unwrap();
            assert_eq!(item, 201); // Second item in section 2 (2*100+1)
            let item = journal.get(2, 3).await.unwrap();
            assert_eq!(item, 203); // Item at offset 3 in section 2 (2*100+3)

            // Verify section 2 size
            let section_2_size = journal.size(2).await.unwrap();
            assert_eq!(section_2_size, 80); // Should be 5 operations * 16 bytes = 80 bytes

            let result = journal.get(3, 0).await;
            assert!(matches!(result, Err(Error::SectionOutOfRange(3)))); // Section 3 was never created

            // Assert journal can accept new operations
            let mut journal = journal;
            let (offset, _) = journal.append(3, 999).await.unwrap();
            assert_eq!(journal.get(3, offset).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }
}
