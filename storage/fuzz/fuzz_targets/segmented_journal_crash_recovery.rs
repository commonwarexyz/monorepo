#![no_main]

//! Fuzz target for standalone segmented-journal crash recovery.
//!
//! Every `Crash` splits the operation stream into another deterministic-runtime checkpoint cycle.
//! Before the cycle ends, replay flushes accepted appends without syncing them. Recovering the
//! checkpoint can therefore retain an arbitrary subset of those dirty bytes. Recovery must return
//! a well-formed prefix in each section, retain every successfully synced prefix, finish replay,
//! and remain appendable.

use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use commonware_codec::{EncodeSize as _, varint::UInt};
use commonware_runtime::{
    BufferPooler, Runner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::journal::{
    Error,
    segmented::{
        fixed::{Config as FixedConfig, Journal as FixedJournal, Replay as FixedReplay},
        variable::{
            Config as VariableConfig, Journal as VariableJournal, Replay as VariableReplay,
        },
    },
};
use commonware_storage_fuzz::{
    RNG_BYTES, bounded_page_cache_size, bounded_page_size, fuzz_runner, remove_faults, split_cycles,
};
use commonware_utils::sequence::FixedBytes;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeMap,
    future::Future,
    num::{NonZeroU16, NonZeroUsize},
};

const ITEM_SIZE: usize = 32;
const MAX_OPERATIONS: usize = 64;
const MAX_REPLAY_BUFFER: usize = 2048;
const MAX_SECTIONS: u8 = 4;
const MAX_WRITE_BUFFER: usize = 2048;

type Item = FixedBytes<ITEM_SIZE>;
type State = BTreeMap<u64, Vec<Entry>>;

fn bounded_replay_buffer(u: &mut Unstructured<'_>) -> ArbitraryResult<usize> {
    u.int_in_range(1..=MAX_REPLAY_BUFFER)
}

fn bounded_write_buffer(u: &mut Unstructured<'_>) -> ArbitraryResult<usize> {
    u.int_in_range(1..=MAX_WRITE_BUFFER)
}

fn bounded_operations(u: &mut Unstructured<'_>) -> ArbitraryResult<Vec<Operation>> {
    let len = u.int_in_range(0..=MAX_OPERATIONS)?;
    (0..len).map(|_| Operation::arbitrary(u)).collect()
}

const fn normalized_section(raw: u8) -> u64 {
    (raw % MAX_SECTIONS) as u64
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum JournalType {
    Fixed,
    Variable,
}

#[derive(Arbitrary, Clone, Debug)]
enum Operation {
    Append { section: u8, value: [u8; ITEM_SIZE] },
    Sync { section: u8 },
    SyncAll,
    Prune { min: u8 },
    Crash,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    journal_type: JournalType,
    raw_bytes: [u8; RNG_BYTES],
    compression: bool,
    #[arbitrary(with = bounded_page_size)]
    page_size: u16,
    #[arbitrary(with = bounded_page_cache_size)]
    page_cache_size: usize,
    #[arbitrary(with = bounded_replay_buffer)]
    replay_buffer: usize,
    #[arbitrary(with = bounded_write_buffer)]
    write_buffer: usize,
    #[arbitrary(with = bounded_operations)]
    operations: Vec<Operation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    /// Byte offset within the section. Fixed-journal item positions are normalized to byte
    /// offsets so both journal variants use the same contiguity checks.
    location: u64,
    /// Encoded byte span: the item size for fixed journals and the complete frame size for
    /// variable journals.
    span: u64,
    item: Item,
}

impl Entry {
    fn fixed(position: u64, item: Item) -> Self {
        Self {
            location: position
                .checked_mul(ITEM_SIZE as u64)
                .expect("fixed-journal location overflow"),
            span: ITEM_SIZE as u64,
            item,
        }
    }

    fn variable(location: u64, payload_size: u32, item: Item) -> Self {
        let span = (UInt(payload_size).encode_size() as u64)
            .checked_add(u64::from(payload_size))
            .expect("variable-journal frame size overflow");
        Self {
            location,
            span,
            item,
        }
    }

    fn end(&self) -> u64 {
        self.location
            .checked_add(self.span)
            .expect("journal entry end overflow")
    }
}

#[derive(Clone, Debug, Default)]
struct Expected {
    /// Exact accepted contents before the crash, used as the per-section upper bound.
    attempted: State,
    /// Number of entries guaranteed to survive in each section.
    durable: BTreeMap<u64, usize>,
    /// In-memory prune floor for the current execution.
    prune_floor: u64,
}

impl Expected {
    fn exact(state: State) -> Self {
        let durable = state
            .iter()
            .map(|(&section, entries)| (section, entries.len()))
            .collect();
        Self {
            attempted: state,
            durable,
            prune_floor: 0,
        }
    }

    fn append(&mut self, section: u64, entry: Entry) {
        let entries = self.attempted.entry(section).or_default();
        let expected_location = entries.last().map_or(0, Entry::end);
        assert_eq!(
            entry.location, expected_location,
            "append was not contiguous in section {section}"
        );
        entries.push(entry);
    }

    fn sync(&mut self, section: u64) {
        let len = self.attempted.get(&section).map_or(0, Vec::len);
        self.durable.insert(section, len);
    }

    fn sync_all(&mut self) {
        self.durable = self
            .attempted
            .iter()
            .map(|(&section, entries)| (section, entries.len()))
            .collect();
    }

    fn prune(&mut self, min: u64) {
        self.prune_floor = self.prune_floor.max(min);
        self.attempted.retain(|&section, _| section >= min);
        self.durable.retain(|&section, _| section >= min);
    }
}

#[derive(Clone, Copy)]
struct Params {
    page_size: NonZeroU16,
    page_cache_size: NonZeroUsize,
    replay_buffer: NonZeroUsize,
    write_buffer: NonZeroUsize,
    compression: bool,
}

trait HarnessJournal: Sized {
    type Config: Send;

    fn config(partition: &str, pooler: &impl BufferPooler, params: Params) -> Self::Config;

    fn init(
        context: deterministic::Context,
        config: Self::Config,
        buffer: NonZeroUsize,
    ) -> impl Future<Output = Result<(Self, Vec<(u64, Entry)>), Error>> + Send;

    fn replay(
        self,
        buffer: NonZeroUsize,
    ) -> impl Future<Output = Result<(Self, Vec<(u64, Entry)>), Error>> + Send;

    fn append(
        self,
        section: u64,
        item: Item,
    ) -> impl Future<Output = Result<(Self, Entry), Error>> + Send;

    fn sync(self, section: u64) -> impl Future<Output = Result<Self, Error>> + Send;

    fn sync_all(self) -> impl Future<Output = Result<Self, Error>> + Send;

    fn prune(self, min: u64) -> impl Future<Output = Result<(Self, bool), Error>> + Send;

    fn destroy(self) -> impl Future<Output = Result<(), Error>> + Send;
}

async fn finish_fixed(
    mut replay: FixedReplay<deterministic::Context, Item>,
) -> Result<
    (
        FixedJournal<deterministic::Context, Item>,
        Vec<(u64, Entry)>,
    ),
    Error,
> {
    let mut entries = Vec::new();
    while let Some(result) = replay.next().await {
        let (section, position, item) = result?;
        entries.push((section, Entry::fixed(position, item)));
    }
    Ok((replay.finish()?, entries))
}

impl HarnessJournal for FixedJournal<deterministic::Context, Item> {
    type Config = FixedConfig;

    fn config(partition: &str, pooler: &impl BufferPooler, params: Params) -> Self::Config {
        FixedConfig {
            partition: partition.into(),
            page_cache: CacheRef::from_pooler(pooler, params.page_size, params.page_cache_size),
            write_buffer: params.write_buffer,
        }
    }

    async fn init(
        context: deterministic::Context,
        config: Self::Config,
        buffer: NonZeroUsize,
    ) -> Result<(Self, Vec<(u64, Entry)>), Error> {
        finish_fixed(FixedJournal::init(context, config, buffer).await?).await
    }

    async fn replay(self, buffer: NonZeroUsize) -> Result<(Self, Vec<(u64, Entry)>), Error> {
        finish_fixed(FixedJournal::replay(self, 0, 0, buffer).await?).await
    }

    async fn append(self, section: u64, item: Item) -> Result<(Self, Entry), Error> {
        let (journal, position) = FixedJournal::append(self, section, &item).await?;
        Ok((journal, Entry::fixed(position, item)))
    }

    async fn sync(self, section: u64) -> Result<Self, Error> {
        FixedJournal::sync(self, section).await
    }

    async fn sync_all(self) -> Result<Self, Error> {
        FixedJournal::sync_all(self).await
    }

    async fn prune(self, min: u64) -> Result<(Self, bool), Error> {
        FixedJournal::prune(self, min).await
    }

    async fn destroy(self) -> Result<(), Error> {
        FixedJournal::destroy(self).await
    }
}

async fn finish_variable(
    mut replay: VariableReplay<deterministic::Context, Item>,
) -> Result<
    (
        VariableJournal<deterministic::Context, Item>,
        Vec<(u64, Entry)>,
    ),
    Error,
> {
    let mut entries = Vec::new();
    while let Some(result) = replay.next().await {
        let (section, location, payload_size, item) = result?;
        entries.push((section, Entry::variable(location, payload_size, item)));
    }
    Ok((replay.finish()?, entries))
}

impl HarnessJournal for VariableJournal<deterministic::Context, Item> {
    type Config = VariableConfig<()>;

    fn config(partition: &str, pooler: &impl BufferPooler, params: Params) -> Self::Config {
        VariableConfig {
            partition: partition.into(),
            compression: params.compression.then_some(3),
            codec_config: (),
            page_cache: CacheRef::from_pooler(pooler, params.page_size, params.page_cache_size),
            write_buffer: params.write_buffer,
        }
    }

    async fn init(
        context: deterministic::Context,
        config: Self::Config,
        buffer: NonZeroUsize,
    ) -> Result<(Self, Vec<(u64, Entry)>), Error> {
        finish_variable(VariableJournal::init(context, config, buffer).await?).await
    }

    async fn replay(self, buffer: NonZeroUsize) -> Result<(Self, Vec<(u64, Entry)>), Error> {
        finish_variable(VariableJournal::replay(self, 0, 0, buffer).await?).await
    }

    async fn append(self, section: u64, item: Item) -> Result<(Self, Entry), Error> {
        let (journal, location, payload_size) =
            VariableJournal::append(self, section, &item).await?;
        Ok((journal, Entry::variable(location, payload_size, item)))
    }

    async fn sync(self, section: u64) -> Result<Self, Error> {
        VariableJournal::sync(self, section).await
    }

    async fn sync_all(self) -> Result<Self, Error> {
        VariableJournal::sync_all(self).await
    }

    async fn prune(self, min: u64) -> Result<(Self, bool), Error> {
        VariableJournal::prune(self, min).await
    }

    async fn destroy(self) -> Result<(), Error> {
        VariableJournal::destroy(self).await
    }
}

/// Check that replay produced exactly one valid prefix per section within the crash bounds.
fn assert_recovered(replayed: Vec<(u64, Entry)>, expected: &Expected) -> State {
    let mut recovered: State = BTreeMap::new();
    let mut previous_section = None;

    for (section, entry) in replayed {
        if let Some(previous) = previous_section {
            assert!(
                section >= previous,
                "replay section order moved backward: {section} after {previous}"
            );
        }
        previous_section = Some(section);

        let attempted = expected
            .attempted
            .get(&section)
            .unwrap_or_else(|| panic!("replay returned unexpected section {section}"));
        let section_entries = recovered.entry(section).or_default();
        let index = section_entries.len();
        let expected_location = section_entries.last().map_or(0, Entry::end);
        assert_eq!(
            entry.location, expected_location,
            "replay was not contiguous in section {section} at index {index}"
        );
        assert!(
            index < attempted.len(),
            "replay returned too many entries for section {section}"
        );
        assert_eq!(
            entry, attempted[index],
            "replay diverged from accepted prefix in section {section} at index {index}"
        );
        section_entries.push(entry);
    }

    for &section in expected.attempted.keys() {
        let recovered_len = recovered.get(&section).map_or(0, Vec::len);
        let durable_len = expected.durable.get(&section).copied().unwrap_or(0);
        assert!(
            recovered_len >= durable_len,
            "section {section} lost durable entries: recovered {recovered_len}, durable {durable_len}"
        );
    }

    recovered
}

async fn run_operations<J: HarnessJournal>(
    mut journal: J,
    expected: &mut Expected,
    operations: &[Operation],
) -> J {
    for operation in operations {
        journal = match operation {
            Operation::Append { section, value } => {
                let section = normalized_section(*section).max(expected.prune_floor);
                let item = Item::from(*value);
                let (journal, entry) = journal
                    .append(section, item)
                    .await
                    .expect("valid append should succeed");
                expected.append(section, entry);
                journal
            }
            Operation::Sync { section } => {
                let section = normalized_section(*section).max(expected.prune_floor);
                let journal = journal
                    .sync(section)
                    .await
                    .expect("section sync should succeed");
                expected.sync(section);
                journal
            }
            Operation::SyncAll => {
                let journal = journal.sync_all().await.expect("sync_all should succeed");
                expected.sync_all();
                journal
            }
            Operation::Prune { min } => {
                let min = normalized_section(*min);
                let (journal, pruned) = journal.prune(min).await.expect("prune should succeed");
                if pruned {
                    expected.prune(min);
                }
                journal
            }
            Operation::Crash => break,
        };
    }
    journal
}

fn run_cycle<J: HarnessJournal + Send + 'static>(
    runner: deterministic::Runner,
    partition: String,
    params: Params,
    expected: Expected,
    operations: Vec<Operation>,
) -> (Expected, deterministic::Checkpoint) {
    runner.start_and_recover(move |context| async move {
        let (journal, replayed) = J::init(
            context.child("journal"),
            J::config(&partition, &context, params),
            params.replay_buffer,
        )
        .await
        .expect("checkpoint recovery should complete");
        let recovered = assert_recovered(replayed, &expected);
        let mut expected = Expected::exact(recovered);

        let journal = run_operations(journal, &mut expected, &operations).await;

        // Replay flushes the dirty tail to storage without making it durable. This gives
        // Runner::from(checkpoint) pending writes on which to sample arbitrary surviving bytes.
        let (journal, replayed) = J::replay(journal, params.replay_buffer)
            .await
            .expect("live replay should complete");
        assert_eq!(
            assert_recovered(replayed, &expected),
            expected.attempted,
            "live replay must contain every accepted append"
        );
        drop(journal);
        expected
    })
}

fn run<J: HarnessJournal + Send + 'static>(input: &FuzzInput, tag: &str) {
    let params = Params {
        page_size: NonZeroU16::new(input.page_size).unwrap(),
        page_cache_size: NonZeroUsize::new(input.page_cache_size).unwrap(),
        replay_buffer: NonZeroUsize::new(input.replay_buffer).unwrap(),
        write_buffer: NonZeroUsize::new(input.write_buffer).unwrap(),
        compression: input.compression,
    };
    let partition = format!("segmented-crash-{tag}");
    let cycles = split_cycles(input.operations.iter().cloned(), |operation| {
        matches!(operation, Operation::Crash)
    });
    let runner = fuzz_runner(&input.raw_bytes);
    let (mut expected, mut checkpoint) = run_cycle::<J>(
        runner,
        partition.clone(),
        params,
        Expected::default(),
        cycles[0].clone(),
    );

    for operations in cycles.iter().skip(1) {
        (expected, checkpoint) = run_cycle::<J>(
            deterministic::Runner::from(checkpoint),
            partition.clone(),
            params,
            expected,
            operations.clone(),
        );
    }

    // Populate and sync every section after recovery, then cross one more checkpoint. This proves
    // that a repaired journal remains appendable and gives interrupted prune several real removal
    // awaits to cross.
    let (expected, checkpoint) = deterministic::Runner::from(checkpoint).start_and_recover({
        let partition = partition.clone();
        move |context| async move {
            let (journal, replayed) = J::init(
                context.child("sentinel"),
                J::config(&partition, &context, params),
                params.replay_buffer,
            )
            .await
            .expect("sentinel recovery should complete");
            let recovered = assert_recovered(replayed, &expected);
            let mut expected = Expected::exact(recovered);
            let mut journal = journal;
            for section in 0..u64::from(MAX_SECTIONS) {
                let sentinel = Item::from([0xE0 | section as u8; ITEM_SIZE]);
                let (next, entry) = journal
                    .append(section, sentinel)
                    .await
                    .expect("append after recovery should succeed");
                journal = next;
                expected.append(section, entry);
            }
            let journal = journal
                .sync_all()
                .await
                .expect("sentinel sync should succeed");
            expected.sync_all();
            drop(journal);
            expected
        }
    });

    const PRUNE_MIN: u64 = MAX_SECTIONS as u64 - 1;
    let prune_partition = partition.clone();
    let (expected, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(move |context| async move {
            let (journal, replayed) = J::init(
                context.child("prune"),
                J::config(&prune_partition, &context, params),
                params.replay_buffer,
            )
            .await
            .expect("pre-prune recovery should complete");
            assert_recovered(replayed, &expected);

            *context.storage_fault_config().write() = remove_faults();
            let _ = journal.prune(PRUNE_MIN).await;
            expected
        });

    let destroy_partition = partition.clone();
    let ((), checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(move |context| async move {
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let (journal, replayed) = J::init(
                context.child("prune_recovery"),
                J::config(&destroy_partition, &context, params),
                params.replay_buffer,
            )
            .await
            .expect("journal must reopen after interrupted prune");

            let mut relaxed = expected.clone();
            for section in 0..PRUNE_MIN {
                relaxed.durable.insert(section, 0);
            }
            let recovered = assert_recovered(replayed, &relaxed);
            let mut retained = false;
            for section in 0..PRUNE_MIN {
                let recovered_entries = recovered.get(&section).map_or(&[][..], Vec::as_slice);
                if recovered_entries.is_empty() {
                    assert!(
                        !retained,
                        "interrupted ascending prune left a hole before section {section}"
                    );
                } else {
                    assert_eq!(
                        recovered_entries, expected.attempted[&section],
                        "interrupted prune partially removed section {section}"
                    );
                    retained = true;
                }
            }

            let (journal, _) = journal
                .prune(PRUNE_MIN)
                .await
                .expect("prune retry must succeed");
            *context.storage_fault_config().write() = remove_faults();
            let _ = journal.destroy().await;
        });

    let redestroy_partition = partition.clone();
    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        let (journal, _) = J::init(
            context.child("redestroy"),
            J::config(&redestroy_partition, &context, params),
            params.replay_buffer,
        )
        .await
        .expect("segmented journal must reopen after interrupted destroy");
        journal.destroy().await.expect("destroy retry must succeed");
    });
}

fn fuzz(input: FuzzInput) {
    match input.journal_type {
        JournalType::Fixed => run::<FixedJournal<deterministic::Context, Item>>(&input, "fixed"),
        JournalType::Variable => {
            run::<VariableJournal<deterministic::Context, Item>>(&input, "variable")
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
