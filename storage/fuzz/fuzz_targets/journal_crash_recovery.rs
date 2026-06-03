#![no_main]

//! Fuzz target contiguous journal crash recovery.
//!
//! A journal is an append-only log of items. Appends are buffered; `sync` and `commit` push data
//! to storage, and an unclean shutdown loses anything not yet durable. On the next `init()` the
//! journal must rebuild a consistent state from whatever survived. This target tests recovering
//! after storage faults.
//!
//! # Cycles
//!
//! One fuzz input drives a single journal through a series of *cycles*, each one crash-and-recover
//! round:
//!   1. `init()` recovers the journal left by the previous cycle's crash.
//!   2. Check it against the `Expected` carried from that crash.
//!   3. Append and query under fault injection (the cycle's `ops`).
//!   4. Drop the journal without a clean shutdown: the crash. Unsynced data is lost.
//!
//! `Crash` markers split the op list into one `ops` list per cycle. Driving recovery repeatedly on
//! the same journal is the point: watermark, pruning-metadata, and section-layout bugs often need a
//! recover-then-mutate-then-recover sequence to appear, not just a single crash.
//!
//! # Expected
//!
//! A crash can land anywhere in a range, so `Expected` tracks conservative bounds (a
//! guaranteed-durable prefix plus size/pruning ceilings), not an exact state.
//! `assert_matches_expected` checks recovery falls within them; `to_expected` then snapshots it as the
//! next cycle's start.
//!
//! # Faults
//!
//! The operation phase runs under write/sync/resize fault injection. The torn-write modes
//! (`partial_write_rate`, `partial_resize_rate`) cut a write or truncation short, leaving the
//! half-finished bytes a real crash would.
//!
//! # Positions
//!
//! Position arguments (`Read`, `Rewind`, `Replay`) come straight from the fuzzer, so a random `u64`
//! is almost always out of range. Each such op runs twice: once with the value clamped into the
//! live range, which must take the success path, and once with the raw value, which exercises the
//! validation path (`ItemPruned` below the start, `ItemOutOfRange` past the end). Clamping
//! guarantees the success path is covered on every input; the raw value still tests rejection.

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{deterministic, BufferPooler, Runner, Supervisor as _};
use commonware_storage::journal::{
    contiguous::{
        fixed::{Config as FixedConfig, Journal as FixedJournal},
        variable::{Config as VariableConfig, Journal as VariableJournal},
        Reader,
    },
    Error,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use futures::StreamExt;
use libfuzzer_sys::fuzz_target;
use std::{
    future::Future,
    num::{NonZeroU16, NonZeroUsize},
    ops::Range,
};

/// Item size for journal entries (32 bytes like a hash digest).
const ITEM_SIZE: usize = 32;

/// The journal item type.
type Item = FixedBytes<ITEM_SIZE>;

/// Maximum replay buffer size.
const MAX_REPLAY_BUF: usize = 2048;

/// Maximum write buffer size.
const MAX_WRITE_BUF: usize = 2048;

/// Buffer size used for internal verification replays.
const VERIFY_REPLAY_BUF: usize = 1024;

/// Maximum number of operations per fuzz input.
const MAX_OPERATIONS: usize = 128;

fn bounded_non_zero(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(1..=MAX_REPLAY_BUF)
}

fn bounded_page_size(u: &mut Unstructured<'_>) -> arbitrary::Result<u16> {
    u.int_in_range(1..=256)
}

fn bounded_page_cache_size(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(1..=16)
}

fn bounded_items_per_section(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    u.int_in_range(1..=64)
}

fn bounded_write_buffer(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(1..=MAX_WRITE_BUF)
}

/// A fault rate in [0.0, 1.0]. Allows 0 so the fuzzer can disable individual fault types.
fn bounded_rate(u: &mut Unstructured<'_>) -> arbitrary::Result<f64> {
    let percent: u8 = u.int_in_range(0..=100)?;
    Ok(f64::from(percent) / 100.0)
}

/// Op sequence capped at `MAX_OPERATIONS`; a derived `Vec` would instead grow with input length.
fn bounded_operations(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<JournalOperation>> {
    let num_ops = u.int_in_range(0..=MAX_OPERATIONS)?;
    (0..num_ops)
        .map(|_| JournalOperation::arbitrary(u))
        .collect()
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
    /// Commit the journal.
    Commit,
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
    /// End the current cycle: drop the journal without a clean sync and recover in the next cycle.
    Crash,
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
    /// Failure rate for write operations.
    #[arbitrary(with = bounded_rate)]
    write_failure_rate: f64,
    /// Probability that a write failure is a partial (torn) write.
    #[arbitrary(with = bounded_rate)]
    partial_write_rate: f64,
    /// Failure rate for sync operations.
    #[arbitrary(with = bounded_rate)]
    sync_failure_rate: f64,
    /// Failure rate for resize operations (truncation during rewind/prune).
    #[arbitrary(with = bounded_rate)]
    resize_failure_rate: f64,
    /// Probability that a resize failure is partial.
    #[arbitrary(with = bounded_rate)]
    partial_resize_rate: f64,
    /// Operations to execute, split into one `ops` list per cycle at each `Crash` marker.
    #[arbitrary(with = bounded_operations)]
    operations: Vec<JournalOperation>,
}

/// Journal config plus fault-injection rates, shared by every cycle.
#[derive(Clone, Copy)]
struct Params {
    page_size: NonZeroU16,
    page_cache_size: NonZeroUsize,
    items_per_section: u64,
    write_buffer: NonZeroUsize,
    write_rate: f64,
    partial_write_rate: f64,
    sync_rate: f64,
    resize_rate: f64,
    partial_resize_rate: f64,
}

impl Params {
    /// The fault config applied during the operation phase of each cycle.
    fn fault_config(&self) -> deterministic::FaultConfig {
        deterministic::FaultConfig {
            write_rate: Some(self.write_rate),
            partial_write_rate: Some(self.partial_write_rate),
            sync_rate: Some(self.sync_rate),
            resize_rate: Some(self.resize_rate),
            partial_resize_rate: Some(self.partial_resize_rate),
            ..Default::default()
        }
    }
}

/// Conservative bounds on what a recovery may produce after an unclean shutdown:
/// - positions `[0, durable_prune)` are pruned (reads return `ItemPruned`),
/// - positions `[max_prune, durable_len)` hold the exact content `values[pos]`,
/// - the recovered size is in `[durable_len, max_size]`,
/// - the recovered pruning boundary is in `[durable_prune, max_prune]`.
#[derive(Clone, Default)]
struct Expected {
    /// Guaranteed-durable prefix length; also the minimum recovered size.
    durable_len: u64,
    /// Upper bound on the recovered size.
    max_size: u64,
    /// Guaranteed pruning floor; positions below are guaranteed pruned.
    durable_prune: u64,
    /// Upper bound on the recovered pruning boundary.
    max_prune: u64,
    /// Latest value appended at each position (index == position).
    values: Vec<Item>,
}

impl Expected {
    /// Successful append: not durable until the next sync/commit, so only raise the ceiling.
    fn appended(&mut self, item: Item) {
        self.values.push(item);
        self.max_size = self.max_size.max(self.values.len() as u64);
    }

    /// Failed append: the item may have partially persisted, so only raise the ceiling.
    fn append_failed(&mut self, size_before: u64) {
        self.max_size = self.max_size.max(size_before + 1);
    }

    /// Sync pins size, content, and pruning boundary exactly.
    fn synced(&mut self, bounds: Range<u64>) {
        self.durable_len = bounds.end;
        self.max_size = bounds.end;
        self.durable_prune = bounds.start;
        self.max_prune = bounds.start;
    }

    /// Commit pins the size but not the pruning boundary.
    fn committed(&mut self, size: u64) {
        self.durable_len = size;
        self.max_size = size;
    }

    /// Rewind: the truncated tail may or may not persist, so recovered size is in `[target, prev]`.
    fn rewound(&mut self, target: u64, prev_size: u64) {
        self.durable_len = self.durable_len.min(target);
        self.max_size = self.max_size.max(prev_size);
    }

    /// Successful prune durably deletes whole sections, so recovery can never reopen below
    /// `boundary`; pin it exactly. (The boundary only moves forward.)
    fn pruned(&mut self, boundary: u64) {
        self.durable_prune = boundary;
        self.max_prune = boundary;
    }

    /// Failed prune may have deleted sections (oldest-first) up to `ceiling`, but not certain.
    fn prune_failed(&mut self, ceiling: u64) {
        self.max_prune = self.max_prune.max(ceiling);
    }
}

/// Trait abstracting over fixed and variable journals for the fuzz test.
trait FuzzJournal: Sized {
    type Config;

    fn config(partition: &str, pooler: &impl BufferPooler, params: &Params) -> Self::Config;

    fn init(
        ctx: deterministic::Context,
        cfg: Self::Config,
    ) -> impl Future<Output = Result<Self, Error>> + Send;

    fn size(&self) -> impl Future<Output = u64> + Send;
    fn bounds(&self) -> impl Future<Output = Range<u64>> + Send;

    fn append(&mut self, item: Item) -> impl Future<Output = Result<u64, Error>> + Send;
    fn read(&self, pos: u64) -> impl Future<Output = Result<Item, Error>> + Send;
    fn sync(&mut self) -> impl Future<Output = Result<(), Error>> + Send;
    fn commit(&mut self) -> impl Future<Output = Result<(), Error>> + Send;
    fn rewind(&mut self, size: u64) -> impl Future<Output = Result<(), Error>> + Send;
    fn prune(&mut self, min_pos: u64) -> impl Future<Output = Result<bool, Error>> + Send;

    fn replay(
        &self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> impl Future<Output = Result<Vec<(u64, Item)>, Error>> + Send;

    fn destroy(self) -> impl Future<Output = Result<(), Error>> + Send;
}

/// Drain a reader's replay stream into a `(position, item)` vector.
async fn collect_replay<R: Reader<Item = Item>>(
    reader: R,
    buffer: NonZeroUsize,
    start_pos: u64,
) -> Result<Vec<(u64, Item)>, Error> {
    let stream = reader.replay(buffer, start_pos).await?;
    futures::pin_mut!(stream);
    let mut out = Vec::new();
    while let Some(result) = stream.next().await {
        out.push(result?);
    }
    Ok(out)
}

impl FuzzJournal for FixedJournal<deterministic::Context, Item> {
    type Config = FixedConfig;

    fn config(partition: &str, pooler: &impl BufferPooler, params: &Params) -> Self::Config {
        FixedConfig {
            partition: partition.into(),
            items_per_blob: NZU64!(params.items_per_section),
            page_cache: commonware_runtime::buffer::paged::CacheRef::from_pooler(
                pooler,
                params.page_size,
                params.page_cache_size,
            ),
            write_buffer: params.write_buffer,
        }
    }

    async fn init(ctx: deterministic::Context, cfg: Self::Config) -> Result<Self, Error> {
        FixedJournal::init(ctx, cfg).await
    }

    async fn size(&self) -> u64 {
        FixedJournal::size(self).await
    }

    // Cannot use `async fn` here due to RPITIT Send auto-trait limitation.
    #[allow(clippy::manual_async_fn)]
    fn bounds(&self) -> impl Future<Output = Range<u64>> + Send {
        async { self.reader().await.bounds() }
    }

    async fn append(&mut self, item: Item) -> Result<u64, Error> {
        FixedJournal::append(self, &item).await
    }

    // Cannot use `async fn` here due to RPITIT Send auto-trait limitation.
    #[allow(clippy::manual_async_fn)]
    fn read(&self, pos: u64) -> impl Future<Output = Result<Item, Error>> + Send {
        async move { self.reader().await.read(pos).await }
    }

    async fn sync(&mut self) -> Result<(), Error> {
        FixedJournal::sync(self).await
    }

    async fn commit(&mut self) -> Result<(), Error> {
        FixedJournal::commit(self).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        FixedJournal::rewind(self, size).await
    }

    async fn prune(&mut self, min_pos: u64) -> Result<bool, Error> {
        FixedJournal::prune(self, min_pos).await
    }

    // Cannot use `async fn` here due to RPITIT Send auto-trait limitation.
    #[allow(clippy::manual_async_fn)]
    fn replay(
        &self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> impl Future<Output = Result<Vec<(u64, Item)>, Error>> + Send {
        async move { collect_replay(self.reader().await, buffer, start_pos).await }
    }

    async fn destroy(self) -> Result<(), Error> {
        FixedJournal::destroy(self).await
    }
}

impl FuzzJournal for VariableJournal<deterministic::Context, Item> {
    type Config = VariableConfig<()>;

    fn config(partition: &str, pooler: &impl BufferPooler, params: &Params) -> Self::Config {
        VariableConfig {
            partition: partition.into(),
            items_per_section: NZU64!(params.items_per_section),
            compression: None,
            codec_config: (),
            page_cache: commonware_runtime::buffer::paged::CacheRef::from_pooler(
                pooler,
                params.page_size,
                params.page_cache_size,
            ),
            write_buffer: params.write_buffer,
        }
    }

    async fn init(ctx: deterministic::Context, cfg: Self::Config) -> Result<Self, Error> {
        VariableJournal::init(ctx, cfg).await
    }

    async fn size(&self) -> u64 {
        VariableJournal::size(self).await
    }

    // Cannot use `async fn` here due to RPITIT Send auto-trait limitation.
    #[allow(clippy::manual_async_fn)]
    fn bounds(&self) -> impl Future<Output = Range<u64>> + Send {
        async { self.reader().await.bounds() }
    }

    async fn append(&mut self, item: Item) -> Result<u64, Error> {
        VariableJournal::append(self, &item).await
    }

    // Cannot use `async fn` here due to RPITIT Send auto-trait limitation.
    #[allow(clippy::manual_async_fn)]
    fn read(&self, pos: u64) -> impl Future<Output = Result<Item, Error>> + Send {
        async move { self.reader().await.read(pos).await }
    }

    async fn sync(&mut self) -> Result<(), Error> {
        VariableJournal::sync(self).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        VariableJournal::rewind(self, size).await
    }

    async fn prune(&mut self, min_pos: u64) -> Result<bool, Error> {
        VariableJournal::prune(self, min_pos).await
    }

    // Cannot use `async fn` here due to RPITIT Send auto-trait limitation.
    #[allow(clippy::manual_async_fn)]
    fn replay(
        &self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> impl Future<Output = Result<Vec<(u64, Item)>, Error>> + Send {
        async move { collect_replay(self.reader().await, buffer, start_pos).await }
    }

    async fn commit(&mut self) -> Result<(), Error> {
        VariableJournal::commit(self).await
    }

    async fn destroy(self) -> Result<(), Error> {
        VariableJournal::destroy(self).await
    }
}

/// Verify the recovered journal matches the `Expected` carried from the previous (crashed) cycle.
async fn assert_matches_expected<J: FuzzJournal>(journal: &J, expected: &Expected) {
    let Range {
        start: boundary,
        end: size,
    } = journal.bounds().await;
    assert!(size >= boundary, "size {size} < boundary {boundary}");

    // Size and boundary fall within the expected bounds.
    assert!(
        size >= expected.durable_len,
        "recovered size {size} < durable_len {}",
        expected.durable_len
    );
    assert!(
        size <= expected.max_size,
        "recovered size {size} > max_size {}",
        expected.max_size
    );
    assert!(
        boundary >= expected.durable_prune,
        "recovered boundary {boundary} < durable_prune {}",
        expected.durable_prune
    );
    assert!(
        boundary <= expected.max_prune,
        "recovered boundary {boundary} > max_prune {}",
        expected.max_prune
    );

    // Below the boundary every position is pruned.
    for pos in 0..boundary {
        match journal.read(pos).await {
            Err(Error::ItemPruned(_)) => {}
            other => panic!("expected ItemPruned below boundary at {pos}, got {other:?}"),
        }
    }

    // Within [boundary, size) every position is readable; content is pinned only for the durable
    // prefix. Items are saved for the replay cross-check below.
    let mut read_items = Vec::with_capacity((size - boundary) as usize);
    for pos in boundary..size {
        let item = journal
            .read(pos)
            .await
            .unwrap_or_else(|e| panic!("in-bounds pos {pos} unreadable: {e:?}"));
        if pos < expected.durable_len {
            assert_eq!(
                item, expected.values[pos as usize],
                "content mismatch at durable pos {pos}"
            );
        }
        read_items.push(item);
    }

    // Replay must yield exactly [boundary, size) contiguously and agree with `read()` everywhere.
    let items = journal
        .replay(NZUsize!(VERIFY_REPLAY_BUF), boundary)
        .await
        .expect("replay during recovery verification");
    assert_eq!(
        items.len() as u64,
        size - boundary,
        "replay returned {} items but bounds are [{boundary}, {size})",
        items.len()
    );
    for (i, (pos, item)) in items.iter().enumerate() {
        let expected_pos = boundary + i as u64;
        assert_eq!(
            *pos, expected_pos,
            "replay non-contiguous: got {pos}, expected {expected_pos}"
        );
        assert_eq!(*item, read_items[i], "replay/read divergence at {pos}");
    }
}

/// Read the recovered journal back into an `Expected` pinned to exactly that state.
async fn to_expected<J: FuzzJournal>(journal: &J) -> Expected {
    let bounds = journal.bounds().await;
    let items = journal
        .replay(NZUsize!(VERIFY_REPLAY_BUF), bounds.start)
        .await
        .expect("to_expected replay");
    let mut values = vec![Item::from([0u8; ITEM_SIZE]); bounds.end as usize];
    for (pos, item) in items {
        values[pos as usize] = item;
    }
    Expected {
        durable_len: bounds.end,
        max_size: bounds.end,
        durable_prune: bounds.start,
        max_prune: bounds.start,
        values,
    }
}

/// Check `read(pos)` against `bounds`. No read faults are injected and `read` is a pure lookup, so
/// anything but `Ok` in range / `ItemPruned` below / `ItemOutOfRange` past the end is a real bug.
fn assert_read(result: Result<Item, Error>, pos: u64, bounds: &Range<u64>) {
    let ok = match &result {
        Ok(_) => bounds.contains(&pos),
        Err(Error::ItemPruned(_)) => pos < bounds.start,
        Err(Error::ItemOutOfRange(_)) => pos >= bounds.end,
        Err(_) => false,
    };
    assert!(
        ok,
        "read at {pos} (bounds [{}, {})) returned {result:?}",
        bounds.start, bounds.end
    );
}

/// Whether the cycle continues after the raw replay. Validation
/// precedes any I/O, so an out-of-range start is deterministic: `< start` -> `ItemPruned`,
/// `> end` -> `ItemOutOfRange` (`== end` is in range). An in-range start succeeds or hits a
/// tail-repair I/O fault (ends the cycle); any other result is a bug.
fn should_continue_raw_replay(
    result: Result<Vec<(u64, Item)>, Error>,
    start_pos: u64,
    bounds: &Range<u64>,
) -> bool {
    let in_range = start_pos >= bounds.start && start_pos <= bounds.end;
    match &result {
        Ok(_) if in_range => true,
        Err(Error::ItemPruned(_)) if start_pos < bounds.start => true,
        Err(Error::ItemOutOfRange(_)) if start_pos > bounds.end => true,
        // An in-range start that failed with a non-validation error is a tail-repair I/O fault.
        Err(e) if in_range && !matches!(e, Error::ItemPruned(_) | Error::ItemOutOfRange(_)) => {
            false
        }
        _ => panic!(
            "raw replay at {start_pos} (bounds [{}, {})) returned {result:?}",
            bounds.start, bounds.end
        ),
    }
}

/// Assert the items from replaying an in-bounds `start` are exactly positions `[start, bounds.end)`,
/// contiguous and in order.
fn assert_replay_suffix(items: &[(u64, Item)], start: u64, bounds: &Range<u64>) {
    assert_eq!(
        items.len() as u64,
        bounds.end - start,
        "replay from {start} returned {} items, expected suffix [{start}, {})",
        items.len(),
        bounds.end
    );
    for (i, (pos, _)) in items.iter().enumerate() {
        let want = start + i as u64;
        assert_eq!(
            *pos, want,
            "replay from {start} non-contiguous: got {pos}, expected {want}"
        );
    }
}

/// Run a cycle's ops under faults, updating `expected`. Stops early on any error that may have left
/// the journal inconsistent (a mutable-method error or a tail-repair I/O fault); the caller then
/// drops the journal to crash. Reads never fault, so a bad read panics instead of ending the cycle.
async fn run_ops<J: FuzzJournal>(
    journal: &mut J,
    expected: &mut Expected,
    ops: &[JournalOperation],
    params: Params,
) {
    for op in ops {
        let should_continue = match op {
            JournalOperation::Append { value } => {
                let item = Item::from(*value);
                let size_before = journal.size().await;
                match journal.append(item.clone()).await {
                    Ok(pos) => {
                        assert_eq!(pos, size_before, "append returned non-contiguous position");
                        expected.appended(item);
                        true
                    }
                    Err(_) => {
                        expected.append_failed(size_before);
                        false
                    }
                }
            }

            JournalOperation::Read { pos } => {
                let bounds = journal.bounds().await;
                if !bounds.is_empty() {
                    let target = bounds.start + (*pos % (bounds.end - bounds.start));
                    assert_read(journal.read(target).await, target, &bounds);
                }
                assert_read(journal.read(*pos).await, *pos, &bounds);
                true
            }

            JournalOperation::Sync => match journal.sync().await {
                Ok(()) => {
                    expected.synced(journal.bounds().await);
                    true
                }
                Err(_) => false,
            },

            JournalOperation::Commit => match journal.commit().await {
                Ok(()) => {
                    expected.committed(journal.size().await);
                    true
                }
                Err(_) => false,
            },

            JournalOperation::Rewind { size } => {
                let bounds = journal.bounds().await;
                if bounds.is_empty() {
                    true
                } else {
                    // Usually clamp to a valid retained target; occasionally pass the raw value to
                    // exercise the validation paths.
                    let use_raw_target = *size % 8 == 0;
                    let target = if use_raw_target {
                        *size
                    } else {
                        bounds.start + (*size % (bounds.end - bounds.start + 1))
                    };
                    match journal.rewind(target).await {
                        Ok(()) => {
                            expected.rewound(target, bounds.end);
                            expected.values.truncate(target as usize);
                            true
                        }
                        // Validation error: rejected before any mutation, so leave the expectation
                        // put. Only a raw target can be invalid; on a clamped target this is a bug.
                        Err(e @ (Error::InvalidRewind(_) | Error::ItemPruned(_))) => {
                            assert!(
                                use_raw_target,
                                "rewind to clamped retained target {target} (bounds [{}, {})) \
                                 returned {e:?}",
                                bounds.start, bounds.end
                            );
                            true
                        }
                        // I/O fault mid-truncation: data above `target` may be lost, so lower
                        // durable_len conservatively and end the cycle.
                        Err(_) => {
                            expected.rewound(target.min(bounds.end), bounds.end);
                            false
                        }
                    }
                }
            }

            JournalOperation::Prune { min_pos } => {
                // Raw position: `prune` caps it to size internally, covering prune-past-size.
                let size = journal.size().await;
                match journal.prune(*min_pos).await {
                    Ok(_) => {
                        expected.pruned(journal.bounds().await.start);
                        true
                    }
                    Err(_) => {
                        // A failed prune advances the boundary at most to the section floor.
                        let capped = (*min_pos).min(size);
                        let section_floor =
                            capped / params.items_per_section * params.items_per_section;
                        expected.prune_failed(section_floor);
                        false
                    }
                }
            }

            JournalOperation::Replay { buffer, start_pos } => {
                // The clamped replay must return the full suffix matching `read()`, or hit a
                // tail-repair I/O fault.
                let bounds = journal.bounds().await;
                let clamped = bounds.start + (*start_pos % (bounds.end - bounds.start + 1));
                let clamped_ok = match journal.replay(NZUsize!(*buffer), clamped).await {
                    Ok(items) => {
                        assert_replay_suffix(&items, clamped, &bounds);
                        for (pos, item) in &items {
                            let via_read = journal.read(*pos).await.unwrap_or_else(|e| {
                                panic!("read({pos}) cross-check during replay: {e:?}")
                            });
                            assert_eq!(*item, via_read, "replay/read divergence at {pos}");
                        }
                        true
                    }
                    // A clamped start is always in bounds, so a validation error is a bug.
                    Err(e @ (Error::ItemPruned(_) | Error::ItemOutOfRange(_))) => panic!(
                        "in-bounds replay at {clamped} (bounds [{}, {})) returned {e:?}",
                        bounds.start, bounds.end
                    ),
                    // Tail-repair I/O fault: end the cycle.
                    Err(_) => false,
                };
                clamped_ok
                    && should_continue_raw_replay(
                        journal.replay(NZUsize!(*buffer), *start_pos).await,
                        *start_pos,
                        &bounds,
                    )
            }

            // `split_into_cycles` strips `Crash`; a stray one defensively ends the cycle.
            JournalOperation::Crash => false,
        };

        if !should_continue {
            break;
        }
    }
}

/// Run one crash cycle: recover, check against `expected`, run the ops under faults, then crash
/// (drop). Returns the `Expected` and checkpoint for the next cycle.
fn run_cycle<J: FuzzJournal + Send + 'static>(
    runner: deterministic::Runner,
    expected: Expected,
    ops: Vec<JournalOperation>,
    partition: String,
    params: Params,
) -> (Expected, deterministic::Checkpoint)
where
    J::Config: Send,
{
    runner.start_and_recover(move |ctx| async move {
        // Recover with faults disabled to obtain clean ground truth.
        *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();
        let cfg = J::config(&partition, &ctx, &params);
        let mut journal = J::init(ctx.child("journal"), cfg)
            .await
            .expect("recovery should succeed without panic");
        assert_matches_expected(&journal, &expected).await;

        let mut expected = to_expected(&journal).await;

        // Faults on for the operation phase; returning drops the journal (the crash).
        *ctx.storage_fault_config().write() = params.fault_config();
        run_ops(&mut journal, &mut expected, &ops, params).await;
        expected
    })
}

/// Split the operation stream into one `ops` list per cycle, cutting at each `Crash` marker. Always
/// returns at least one list (possibly empty), so a bare recovery is still exercised.
fn split_into_cycles(ops: &[JournalOperation]) -> Vec<Vec<JournalOperation>> {
    let mut cycles = Vec::new();
    let mut current = Vec::new();
    for op in ops {
        if matches!(op, JournalOperation::Crash) {
            cycles.push(std::mem::take(&mut current));
        } else {
            current.push(op.clone());
        }
    }
    cycles.push(current);
    cycles
}

fn run<J: FuzzJournal + Send + 'static>(input: &FuzzInput, tag: &str)
where
    J::Config: Send,
{
    let params = Params {
        page_size: NonZeroU16::new(input.page_size).unwrap(),
        page_cache_size: NonZeroUsize::new(input.page_cache_size).unwrap(),
        items_per_section: input.items_per_section,
        write_buffer: NonZeroUsize::new(input.write_buffer).unwrap(),
        write_rate: input.write_failure_rate,
        partial_write_rate: input.partial_write_rate,
        sync_rate: input.sync_failure_rate,
        resize_rate: input.resize_failure_rate,
        partial_resize_rate: input.partial_resize_rate,
    };
    let partition = format!("crash-recovery-{tag}-{}", input.seed);
    let cycles = split_into_cycles(&input.operations);

    // First cycle starts from a fresh runtime and recovers an empty journal, so the expectation is
    // empty too.
    let runner = deterministic::Runner::new(deterministic::Config::default().with_seed(input.seed));
    let (mut expected, mut checkpoint) = run_cycle::<J>(
        runner,
        Expected::default(),
        cycles[0].clone(),
        partition.clone(),
        params,
    );

    for ops in cycles.iter().skip(1) {
        let runner = deterministic::Runner::from(checkpoint);
        (expected, checkpoint) = run_cycle::<J>(
            runner,
            expected.clone(),
            ops.clone(),
            partition.clone(),
            params,
        );
    }

    // Final fault-free phase: verify the last recovery, then append, sync, drop, and reopen a
    // sentinel to prove the synced state survives restart.
    deterministic::Runner::from(checkpoint).start(move |ctx| async move {
        *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();
        let mut journal = J::init(
            ctx.child("journal_final"),
            J::config(&partition, &ctx, &params),
        )
        .await
        .expect("final recovery should succeed");
        assert_matches_expected(&journal, &expected).await;

        // Append a sentinel and sync it, pinning the exact durable state.
        let mut expected = to_expected(&journal).await;
        let size = journal.size().await;
        let sentinel = Item::from([0xEFu8; ITEM_SIZE]);
        let pos = journal
            .append(sentinel.clone())
            .await
            .expect("final append");
        assert_eq!(pos, size);
        expected.appended(sentinel.clone());
        journal.sync().await.expect("final sync");
        expected.synced(journal.bounds().await);
        drop(journal);

        // Reopen and confirm the synced sentinel survived the restart.
        let journal = J::init(
            ctx.child("journal_final_verify"),
            J::config(&partition, &ctx, &params),
        )
        .await
        .expect("final reopen should succeed");
        assert_matches_expected(&journal, &expected).await;
        assert_eq!(
            journal.read(pos).await.expect("final read"),
            sentinel,
            "final sentinel readback mismatch"
        );
        journal.destroy().await.expect("destroy");
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
