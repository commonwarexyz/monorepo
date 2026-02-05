#![no_main]

//! Fuzz test for journal crash recovery (both fixed and variable journals).

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_runtime::{deterministic, Metrics as _, Runner};
use commonware_storage::journal::contiguous::{
    fixed::{Config as FixedConfig, Journal as FixedJournal},
    variable::{Config as VariableConfig, Journal as VariableJournal},
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{
    num::{NonZeroU16, NonZeroUsize},
    ops::Range,
};

/// Item size for journal entries (32 bytes like a hash digest).
const ITEM_SIZE: usize = 32;

/// Type alias for the journal item type.
type Item = FixedBytes<ITEM_SIZE>;

/// Maximum replay buffer size.
const MAX_REPLAY_BUF: usize = 2048;

/// Maximum write buffer size.
const MAX_WRITE_BUF: usize = 2048;

fn bounded_non_zero(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=MAX_REPLAY_BUF)
}

fn bounded_page_size(u: &mut Unstructured<'_>) -> Result<u16> {
    u.int_in_range(1..=256)
}

fn bounded_page_cache_size(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=16)
}

fn bounded_items_per_section(u: &mut Unstructured<'_>) -> Result<u64> {
    u.int_in_range(1..=64)
}

fn bounded_write_buffer(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=MAX_WRITE_BUF)
}

fn bounded_nonzero_rate(u: &mut Unstructured<'_>) -> Result<f64> {
    let percent: u8 = u.int_in_range(1..=100)?;
    Ok(f64::from(percent) / 100.0)
}

/// Journal type selector.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum JournalType {
    Fixed,
    Variable,
}

/// Operations that can be performed on the journal.
#[derive(Arbitrary, Debug, Clone)]
enum JournalOperation {
    /// Append a single item to the journal.
    Append { value: [u8; ITEM_SIZE] },
    /// Read an item at a specific position.
    Read { pos: u64 },
    /// Sync the journal to storage.
    Sync,
    /// Rewind the journal to a smaller size.
    Rewind { size: u64 },
    /// Prune items before a position.
    Prune { min_pos: u64 },
    /// Replay items from the journal.
    Replay {
        #[arbitrary(with = bounded_non_zero)]
        buffer: usize,
        start_pos: u64,
    },
    /// Commit pending changes (variable journal only, no-op for fixed).
    Commit,
}

/// Fuzz input containing fault injection parameters and operations.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Which journal type to test.
    journal_type: JournalType,
    /// Seed for deterministic execution.
    seed: u64,
    /// Page size for buffer pool.
    #[arbitrary(with = bounded_page_size)]
    page_size: u16,
    /// Number of pages in the buffer pool cache.
    #[arbitrary(with = bounded_page_cache_size)]
    page_cache_size: usize,
    /// Items per section/blob.
    #[arbitrary(with = bounded_items_per_section)]
    items_per_section: u64,
    /// Write buffer size.
    #[arbitrary(with = bounded_write_buffer)]
    write_buffer: usize,
    /// Failure rate for sync operations (0, 1].
    #[arbitrary(with = bounded_nonzero_rate)]
    sync_failure_rate: f64,
    /// Failure rate for write operations (0, 1].
    #[arbitrary(with = bounded_nonzero_rate)]
    write_failure_rate: f64,
    /// Sequence of operations to execute.
    operations: Vec<JournalOperation>,
}

fn fixed_config(
    partition: &str,
    page_size: NonZeroU16,
    page_cache_size: NonZeroUsize,
    items_per_section: u64,
    write_buffer: NonZeroUsize,
) -> FixedConfig {
    FixedConfig {
        partition: partition.to_string(),
        items_per_blob: NZU64!(items_per_section),
        page_cache: commonware_runtime::buffer::paged::CacheRef::new(page_size, page_cache_size),
        write_buffer,
    }
}

fn variable_config(
    partition: &str,
    page_size: NonZeroU16,
    page_cache_size: NonZeroUsize,
    items_per_section: u64,
    write_buffer: NonZeroUsize,
) -> VariableConfig<()> {
    VariableConfig {
        partition: partition.to_string(),
        items_per_section: NZU64!(items_per_section),
        compression: None,
        codec_config: (),
        page_cache: commonware_runtime::buffer::paged::CacheRef::new(page_size, page_cache_size),
        write_buffer,
    }
}

/// Trait abstracting over fixed and variable journals for the fuzz test.
trait FuzzJournal: Sized {
    type Config;

    fn config(
        partition: &str,
        page_size: NonZeroU16,
        page_cache_size: NonZeroUsize,
        items_per_section: u64,
        write_buffer: NonZeroUsize,
    ) -> Self::Config;

    fn init(
        ctx: deterministic::Context,
        cfg: Self::Config,
    ) -> impl std::future::Future<Output = Result<Self, commonware_storage::journal::Error>> + Send;

    fn size(&self) -> u64;
    fn bounds(&self) -> Range<u64>;

    fn append(
        &mut self,
        item: Item,
    ) -> impl std::future::Future<Output = Result<u64, commonware_storage::journal::Error>> + Send;

    fn read(
        &self,
        pos: u64,
    ) -> impl std::future::Future<Output = Result<Item, commonware_storage::journal::Error>> + Send;

    fn sync(
        &mut self,
    ) -> impl std::future::Future<Output = Result<(), commonware_storage::journal::Error>> + Send;

    fn rewind(
        &mut self,
        size: u64,
    ) -> impl std::future::Future<Output = Result<(), commonware_storage::journal::Error>> + Send;

    fn prune(
        &mut self,
        min_pos: u64,
    ) -> impl std::future::Future<Output = Result<bool, commonware_storage::journal::Error>> + Send;

    // Return value is ignored in the fuzz test.
    fn replay(
        &mut self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> impl std::future::Future<Output = Result<(), commonware_storage::journal::Error>> + Send;

    fn commit(
        &mut self,
    ) -> impl std::future::Future<Output = Result<(), commonware_storage::journal::Error>> + Send;

    fn destroy(
        self,
    ) -> impl std::future::Future<Output = Result<(), commonware_storage::journal::Error>> + Send;
}

impl FuzzJournal for FixedJournal<deterministic::Context, Item> {
    type Config = FixedConfig;

    fn config(
        partition: &str,
        page_size: NonZeroU16,
        page_cache_size: NonZeroUsize,
        items_per_section: u64,
        write_buffer: NonZeroUsize,
    ) -> Self::Config {
        fixed_config(
            partition,
            page_size,
            page_cache_size,
            items_per_section,
            write_buffer,
        )
    }

    async fn init(
        ctx: deterministic::Context,
        cfg: Self::Config,
    ) -> Result<Self, commonware_storage::journal::Error> {
        FixedJournal::init(ctx, cfg).await
    }

    fn size(&self) -> u64 {
        FixedJournal::size(self)
    }

    fn bounds(&self) -> Range<u64> {
        FixedJournal::bounds(self)
    }

    async fn append(&mut self, item: Item) -> Result<u64, commonware_storage::journal::Error> {
        FixedJournal::append(self, item).await
    }

    async fn read(&self, pos: u64) -> Result<Item, commonware_storage::journal::Error> {
        FixedJournal::read(self, pos).await
    }

    async fn sync(&mut self) -> Result<(), commonware_storage::journal::Error> {
        FixedJournal::sync(self).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), commonware_storage::journal::Error> {
        FixedJournal::rewind(self, size).await
    }

    async fn prune(&mut self, min_pos: u64) -> Result<bool, commonware_storage::journal::Error> {
        FixedJournal::prune(self, min_pos).await
    }

    async fn replay(
        &mut self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> Result<(), commonware_storage::journal::Error> {
        let _ = FixedJournal::replay(self, buffer, start_pos).await?;
        Ok(())
    }

    async fn commit(&mut self) -> Result<(), commonware_storage::journal::Error> {
        // Fixed journal doesn't have commit; call sync instead
        self.sync().await
    }

    async fn destroy(self) -> Result<(), commonware_storage::journal::Error> {
        FixedJournal::destroy(self).await
    }
}

impl FuzzJournal for VariableJournal<deterministic::Context, Item> {
    type Config = VariableConfig<()>;

    fn config(
        partition: &str,
        page_size: NonZeroU16,
        page_cache_size: NonZeroUsize,
        items_per_section: u64,
        write_buffer: NonZeroUsize,
    ) -> Self::Config {
        variable_config(
            partition,
            page_size,
            page_cache_size,
            items_per_section,
            write_buffer,
        )
    }

    async fn init(
        ctx: deterministic::Context,
        cfg: Self::Config,
    ) -> Result<Self, commonware_storage::journal::Error> {
        VariableJournal::init(ctx, cfg).await
    }

    fn size(&self) -> u64 {
        VariableJournal::size(self)
    }

    fn bounds(&self) -> Range<u64> {
        VariableJournal::bounds(self)
    }

    async fn append(&mut self, item: Item) -> Result<u64, commonware_storage::journal::Error> {
        VariableJournal::append(self, item).await
    }

    async fn read(&self, pos: u64) -> Result<Item, commonware_storage::journal::Error> {
        VariableJournal::read(self, pos).await
    }

    async fn sync(&mut self) -> Result<(), commonware_storage::journal::Error> {
        VariableJournal::sync(self).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), commonware_storage::journal::Error> {
        VariableJournal::rewind(self, size).await
    }

    async fn prune(&mut self, min_pos: u64) -> Result<bool, commonware_storage::journal::Error> {
        VariableJournal::prune(self, min_pos).await
    }

    async fn replay(
        &mut self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> Result<(), commonware_storage::journal::Error> {
        let _ = VariableJournal::replay(self, start_pos, buffer).await?;
        Ok(())
    }

    async fn commit(&mut self) -> Result<(), commonware_storage::journal::Error> {
        VariableJournal::commit(self).await
    }

    async fn destroy(self) -> Result<(), commonware_storage::journal::Error> {
        VariableJournal::destroy(self).await
    }
}

async fn run_operations<J: FuzzJournal>(
    journal: &mut J,
    operations: &[JournalOperation],
) -> (u64, u64, u64, u64) {
    let mut min_expected_size = 0u64;
    let mut max_expected_size = journal.size();
    let mut min_expected_oldest = 0u64;
    let mut max_expected_oldest = journal.bounds().start;

    for op in operations.iter() {
        let step_result: Result<(), ()> = match op {
            JournalOperation::Append { value } => {
                let size_before = journal.size();
                if journal.append(Item::from(*value)).await.is_err() {
                    max_expected_size = max_expected_size.max(size_before + 1);
                    Err(())
                } else {
                    max_expected_size = max_expected_size.max(journal.size());
                    Ok(())
                }
            }

            JournalOperation::Read { pos } => {
                let _ = journal.read(*pos).await;
                Ok(())
            }

            JournalOperation::Sync => {
                if journal.sync().await.is_err() {
                    Err(())
                } else {
                    let size = journal.size();
                    min_expected_size = size;
                    max_expected_size = max_expected_size.max(size);
                    let oldest = journal.bounds().start;
                    min_expected_oldest = oldest;
                    max_expected_oldest = max_expected_oldest.max(oldest);
                    Ok(())
                }
            }

            JournalOperation::Rewind { size } => {
                let prev_size = journal.size();
                if *size >= prev_size {
                    Ok(())
                } else if journal.rewind(*size).await.is_err() {
                    min_expected_size = min_expected_size.min(*size);
                    Err(())
                } else {
                    min_expected_size = min_expected_size.min(*size);
                    Ok(())
                }
            }

            JournalOperation::Prune { min_pos } => match journal.prune(*min_pos).await {
                Err(_) => {
                    max_expected_oldest = max_expected_oldest.max((*min_pos).min(journal.size()));
                    Err(())
                }
                Ok(false) => Ok(()),
                Ok(true) => {
                    let new_oldest = journal.bounds().start;
                    min_expected_oldest = new_oldest;
                    max_expected_oldest = new_oldest;
                    Ok(())
                }
            },

            JournalOperation::Replay { buffer, start_pos } => {
                // Replay may internally do a write so failure should be treated as fatal
                if journal.replay(NZUsize!(*buffer), *start_pos).await.is_err() {
                    Err(())
                } else {
                    Ok(())
                }
            }

            JournalOperation::Commit => {
                if journal.commit().await.is_err() {
                    Err(())
                } else {
                    let size = journal.size();
                    min_expected_size = size;
                    max_expected_size = size;
                    let oldest = journal.bounds().start;
                    min_expected_oldest = oldest;
                    max_expected_oldest = oldest;
                    Ok(())
                }
            }
        };

        if step_result.is_err() {
            break;
        }
    }

    (
        min_expected_size,
        max_expected_size,
        min_expected_oldest,
        max_expected_oldest,
    )
}

async fn verify_recovery<J: FuzzJournal>(
    journal: &mut J,
    min_expected_size: u64,
    max_expected_size: u64,
    min_expected_oldest: u64,
    max_expected_oldest: u64,
) {
    let size = journal.size();
    let oldest = journal.bounds().start;
    assert!(size >= oldest);

    assert!(
        size <= max_expected_size,
        "size {} > max {}",
        size,
        max_expected_size
    );
    assert!(
        size >= min_expected_size,
        "size {} < min {}",
        size,
        min_expected_size
    );

    assert!(oldest >= min_expected_oldest);
    assert!(oldest <= max_expected_oldest);

    // Verify we can append new data after recovery
    let test_value = [0xABu8; ITEM_SIZE];
    let new_pos = journal
        .append(Item::from(test_value))
        .await
        .expect("Should be able to append after recovery");
    assert_eq!(new_pos, size);
}

fn fuzz_journal<J: FuzzJournal + Send + 'static>(input: &FuzzInput, partition_prefix: &str)
where
    J::Config: Send,
{
    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_section = input.items_per_section;
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();
    let cfg = deterministic::Config::default().with_seed(input.seed);
    let partition_name = format!("{}_{}", partition_prefix, input.seed);
    let runner = deterministic::Runner::new(cfg);
    let operations = input.operations.clone();
    let sync_failure_rate = input.sync_failure_rate;
    let write_failure_rate = input.write_failure_rate;

    let (
        (min_expected_size, max_expected_size, min_expected_oldest, max_expected_oldest),
        checkpoint,
    ) = runner.start_and_recover(|ctx| {
        let partition_name = partition_name.clone();
        let operations = operations.clone();
        async move {
            let mut journal = J::init(
                ctx.with_label("journal"),
                J::config(
                    &partition_name,
                    page_size,
                    page_cache_size,
                    items_per_section,
                    write_buffer,
                ),
            )
            .await
            .unwrap();

            let fault_config = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_failure_rate),
                ..Default::default()
            };
            let faults = ctx.storage_faults();
            *faults.write().unwrap() = fault_config;

            run_operations(&mut journal, &operations).await
        }
    });

    let runner = deterministic::Runner::from(checkpoint);
    runner.start(|ctx| async move {
        *ctx.storage_faults().write().unwrap() = deterministic::FaultConfig::default();

        let mut journal = J::init(
            ctx.with_label("recovered"),
            J::config(
                &partition_name,
                page_size,
                page_cache_size,
                items_per_section,
                write_buffer,
            ),
        )
        .await
        .expect("Journal recovery should succeed without panic");

        verify_recovery(
            &mut journal,
            min_expected_size,
            max_expected_size,
            min_expected_oldest,
            max_expected_oldest,
        )
        .await;

        journal
            .destroy()
            .await
            .expect("Should be able to destroy journal");
    });
}

fn fuzz(input: FuzzInput) {
    if input.operations.is_empty() {
        return;
    }

    match input.journal_type {
        JournalType::Fixed => {
            fuzz_journal::<FixedJournal<deterministic::Context, Item>>(
                &input,
                "fixed_crash_recovery",
            );
        }
        JournalType::Variable => {
            fuzz_journal::<VariableJournal<deterministic::Context, Item>>(
                &input,
                "variable_crash_recovery",
            );
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
