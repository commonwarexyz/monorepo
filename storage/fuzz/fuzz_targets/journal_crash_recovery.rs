#![no_main]

//! Fuzz target for crash recovery of the contiguous journals (fixed and variable).
//!
//! A journal is an append-only log of items. Appends are buffered; `sync` and `commit` push data
//! to storage, and an unclean shutdown loses anything not yet durable. On the next `init()` the
//! journal must rebuild a consistent state from whatever survived. This target stresses that
//! rebuild under storage faults.
//!
//! # Cycles
//!
//! One fuzz input drives a single journal through a series of *cycles*. A cycle is one
//! crash-and-recover round:
//!   1. `init()` recovers the journal left behind by the previous cycle's crash.
//!   2. Check the recovered journal against the `Expected` carried over from that crash.
//!   3. Append and query under fault injection (the cycle's `ops`).
//!   4. Drop the journal without a clean shutdown. That is the crash: unsynced data is lost.
//!
//! The fuzzer's operation list is split at `Crash` markers, giving one `ops` list per cycle.
//! Repeating this on the same journal is the point: bugs in the recovery watermark, pruning
//! metadata, or section layout tend to surface only after a journal has been recovered, mutated,
//! and crashed several times over, not on the first crash.
//!
//! # Expected
//!
//! A crash can land anywhere in a range of outcomes, so we cannot predict the exact recovered
//! state. `Expected` instead tracks conservative bounds: a guaranteed-durable prefix plus ceilings
//! on the size and pruning boundary. `assert_matches_expected` asserts the real recovery lands within them.
//! Once it passes, the state is known exactly, so `observe` reads it back as the precise starting
//! point for the next cycle.
//!
//! # Faults
//!
//! The operation phase runs under write/sync/resize fault injection. The torn-write modes
//! (`partial_write_rate`, `partial_resize_rate`) cut a write or truncation off partway, leaving the
//! half-finished bytes a real crash would leave behind for recovery to sort out.

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

/// Maximum number of operations per fuzz input. Bounds the number of crash cycles and the per-cycle
/// verification/replay work so executions stay fast (total cost is ~O(cycles * size), both capped
/// here).
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

/// A bounded-length operation sequence, so input size (hence cycle count and verification cost)
/// stays capped regardless of how much data the fuzzer provides.
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

/// Operations applied to the journal within a cycle.
#[derive(Arbitrary, Debug, Clone)]
enum JournalOperation {
    /// Append a single item to the journal.
    Append { value: [u8; ITEM_SIZE] },
    /// Read an item at a specific position.
    Read { pos: u64 },
    /// Sync the journal to storage (durability checkpoint).
    Sync,
    /// Flush pending data without advancing the recovery watermark, so recovery walks blob lengths.
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

/// Configuration knobs shared by every cycle: journal config plus fault-injection rates.
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

/// What a recovery is expected to produce after an unclean shutdown: a guaranteed-durable floor and
/// conservative upper bounds.
///
/// The bounds are deliberately conservative, so every assertion in `assert_matches_expected` is sound under
/// any fault/crash interleaving:
/// - positions `[0, durable_prune)` are pruned (reads return `ItemPruned`),
/// - positions `[max_prune, durable_len)` are present with the exact content `values[pos]`,
/// - the recovered size is in `[durable_len, max_size]`,
/// - the recovered pruning boundary is in `[durable_prune, max_prune]`,
/// - `values.len()` tracks the in-memory size, so `values[pos]` is the latest value at `pos`.
///
/// The methods below are the per-operation update rules that maintain these invariants.
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
    /// A successful tail append. The item is not durable until the next sync/commit, so it only
    /// raises the size ceiling.
    fn appended(&mut self, item: Item) {
        self.values.push(item);
        self.max_size = self.max_size.max(self.values.len() as u64);
    }

    /// A failed append: the item may have partially persisted, so widen the size ceiling only.
    fn append_failed(&mut self, size_before: u64) {
        self.max_size = self.max_size.max(size_before + 1);
    }

    /// Sync makes the whole in-memory state durable: size, content, and pruning boundary are all
    /// pinned exactly.
    fn synced(&mut self, bounds: Range<u64>) {
        self.durable_len = bounds.end;
        self.max_size = bounds.end;
        self.durable_prune = bounds.start;
        self.max_prune = bounds.start;
    }

    /// Commit makes appended data durable but not the pruning boundary, so pin only the size.
    fn committed(&mut self, size: u64) {
        self.durable_len = size;
        self.max_size = size;
    }

    /// Rewind to `target`: data below `target` is untouched on disk, while the truncated tail may
    /// or may not persist, so the recovered size ranges over `[target, prev_size]`.
    fn rewound(&mut self, target: u64, prev_size: u64) {
        self.durable_len = self.durable_len.min(target);
        self.max_size = self.max_size.max(prev_size);
    }

    /// A successful prune durably advances the pruning boundary to `boundary`. Pruning deletes whole
    /// section blobs from storage (`context.remove`, not buffered behind a sync), and recovery
    /// rebuilds the boundary forward from the surviving blobs, so a reopen can never resurrect data
    /// below `boundary`. Pin the boundary exactly. (The boundary only moves forward, so this never
    /// lowers `durable_prune`.)
    fn pruned(&mut self, boundary: u64) {
        self.durable_prune = boundary;
        self.max_prune = boundary;
    }

    /// A failed prune may have deleted some sections before erroring (sections go oldest-first), so
    /// the boundary may have advanced as far as `ceiling` but is not guaranteed to have moved. Raise
    /// only the ceiling.
    fn prune_failed(&mut self, ceiling: u64) {
        self.max_prune = self.max_prune.max(ceiling);
    }
}

/// Abstracts over fixed and variable journals. `read` and `replay` return their items so content
/// can be verified after recovery.
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

    /// Replay from `start_pos`, returning all `(position, item)` pairs.
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

    // `async fn` can't add the `+ Send` bound here (RPITIT).
    #[allow(clippy::manual_async_fn)]
    fn bounds(&self) -> impl Future<Output = Range<u64>> + Send {
        async { self.reader().await.bounds() }
    }

    async fn append(&mut self, item: Item) -> Result<u64, Error> {
        FixedJournal::append(self, &item).await
    }

    // `async fn` can't add the `+ Send` bound here (RPITIT).
    #[allow(clippy::manual_async_fn)]
    fn read(&self, pos: u64) -> impl Future<Output = Result<Item, Error>> + Send {
        async move { self.reader().await.read(pos).await }
    }

    async fn sync(&mut self) -> Result<(), Error> {
        FixedJournal::sync(self).await
    }

    async fn commit(&mut self) -> Result<(), Error> {
        // Unlike `sync`, `commit` flushes without advancing the watermark, so recovery must walk
        // blob lengths; exercise that path here.
        FixedJournal::commit(self).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        FixedJournal::rewind(self, size).await
    }

    async fn prune(&mut self, min_pos: u64) -> Result<bool, Error> {
        FixedJournal::prune(self, min_pos).await
    }

    // `async fn` can't add the `+ Send` bound here (RPITIT).
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

    // `async fn` can't add the `+ Send` bound here (RPITIT).
    #[allow(clippy::manual_async_fn)]
    fn bounds(&self) -> impl Future<Output = Range<u64>> + Send {
        async { self.reader().await.bounds() }
    }

    async fn append(&mut self, item: Item) -> Result<u64, Error> {
        VariableJournal::append(self, &item).await
    }

    // `async fn` can't add the `+ Send` bound here (RPITIT).
    #[allow(clippy::manual_async_fn)]
    fn read(&self, pos: u64) -> impl Future<Output = Result<Item, Error>> + Send {
        async move { self.reader().await.read(pos).await }
    }

    async fn sync(&mut self) -> Result<(), Error> {
        VariableJournal::sync(self).await
    }

    async fn commit(&mut self) -> Result<(), Error> {
        VariableJournal::commit(self).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        VariableJournal::rewind(self, size).await
    }

    async fn prune(&mut self, min_pos: u64) -> Result<bool, Error> {
        VariableJournal::prune(self, min_pos).await
    }

    // `async fn` can't add the `+ Send` bound here (RPITIT).
    #[allow(clippy::manual_async_fn)]
    fn replay(
        &self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> impl Future<Output = Result<Vec<(u64, Item)>, Error>> + Send {
        async move { collect_replay(self.reader().await, buffer, start_pos).await }
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

    // Below the recovered boundary every position is pruned, so reads must return `ItemPruned`.
    // Using the actual boundary (not the `durable_prune` floor) makes the pruned vs. in-bounds
    // split exact, so the loop below can require everything in bounds to be readable.
    for pos in 0..boundary {
        match journal.read(pos).await {
            Err(Error::ItemPruned(_)) => {}
            other => panic!("expected ItemPruned below boundary at {pos}, got {other:?}"),
        }
    }

    // Within bounds [boundary, size) every position must be readable (never pruned). Content is
    // pinned for the durable prefix; the volatile tail is readable but its content is unconstrained
    // (torn writes / unsynced rewind). Reads are collected for the replay cross-check.
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

    // Replay must yield exactly [boundary, size) contiguously and agree with `read()` at every
    // position. The cross-check covers the whole range, including the volatile tail where neither
    // path is checked against `expected`, so a read/replay divergence cannot slip through.
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

/// Read the recovered journal back into an `Expected` describing exactly that state. The data is on
/// disk and durable against the next unclean drop, except where a later rewind/prune/torn-append
/// touches it (handled by the per-op update rules).
async fn observe<J: FuzzJournal>(journal: &J) -> Expected {
    let bounds = journal.bounds().await;
    let items = journal
        .replay(NZUsize!(VERIFY_REPLAY_BUF), bounds.start)
        .await
        .expect("observe replay");
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

/// Confirm the journal is usable after opening by appending a sentinel and reading it back. Runs
/// fault-free, so it must succeed; the sentinel is unsynced, so it only widens the size ceiling.
async fn assert_round_trip<J: FuzzJournal>(journal: &mut J, expected: &mut Expected) {
    let size = journal.size().await;
    let sentinel = Item::from([0xCDu8; ITEM_SIZE]);
    let pos = journal
        .append(sentinel.clone())
        .await
        .expect("append after open");
    assert_eq!(pos, size, "post-open append at wrong position");
    assert_eq!(
        journal.read(pos).await.expect("read sentinel"),
        sentinel,
        "sentinel readback mismatch"
    );
    expected.appended(sentinel);
}

/// Check that `read(pos)` returned the right result for where `pos` sits, and panic if it did not.
///
/// Relative to the live range `bounds` (= `[start, end)`):
///   - live (`start <= pos < end`) -> `Ok(item)`,
///   - pruned (`pos < start`)      -> `Err(ItemPruned)`,
///   - past the end (`pos >= end`) -> `Err(ItemOutOfRange)`.
///
/// Anything else is a real bug: no read faults are injected and `read` is a pure lookup, so it
/// cannot legitimately fail here (unlike `replay`, which repairs the tail). A bad read panics.
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

/// Whether the cycle should continue after a raw `replay(start_pos)` at an arbitrary start.
///
/// `replay` validates the start before doing any I/O, so an out-of-range start is deterministic:
///   - `start_pos < start` -> `Err(ItemPruned)`,
///   - `start_pos > end`   -> `Err(ItemOutOfRange)` (`start_pos == end` is in range: an empty replay).
///
/// An in-range start either succeeds or hits a legitimate tail-repair I/O fault (`replay` resizes
/// and syncs under faults); the fault ends the cycle. Success out of range, the wrong validation
/// error, or a validation error for an in-range start is a bug, so panic.
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

/// Assert an in-bounds `replay(start)` returned the full contiguous suffix `[start, bounds.end)`.
/// The `Append` write buffer serves replay from its logical view, so buffered (unsynced) tail items
/// are included; the recovered length equals `bounds.end - start` exactly.
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

/// Run a cycle's ops under faults, updating `expected`. Stops early if an op may have left the
/// journal inconsistent (any mutable error, or a replay that hit a tail-repair I/O fault); the
/// caller then drops the journal to simulate the crash. Reads never fault here, so a bad read
/// panics rather than ending the cycle.
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
                // Exercise a guaranteed in-bounds read each cycle (the raw `pos` may be out of
                // bounds), then the raw read to cover the pruned / out-of-range paths. Reads inject
                // no faults and are pure lookups, so every outcome is determined by `bounds` and is
                // asserted exactly; a read never ends the cycle.
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
                    // Usually clamp to a retained position in [start, end], which is always a valid
                    // rewind target; occasionally pass the raw value to exercise the validation
                    // paths (target past the end, or below the pruning boundary).
                    let use_raw_target = *size % 8 == 0;
                    let target = if use_raw_target {
                        *size
                    } else {
                        bounds.start + (*size % (bounds.end - bounds.start + 1))
                    };
                    match journal.rewind(target).await {
                        Ok(()) => {
                            // Rewound to `target`; the truncated tail may or may not persist.
                            expected.rewound(target, bounds.end);
                            expected.values.truncate(target as usize);
                            true
                        }
                        // Validation error (target out of range): rejected before any mutation, so
                        // the journal is unchanged and the expectation must stay put (lowering
                        // durable_len would mask later loss of still-durable data). Only the raw
                        // target can be invalid; a clamped target is always a retained position, so
                        // a validation error there is a bug.
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
                // Pass the raw position: `prune` caps it to the size internally, so this also covers
                // the prune-past-size path. The capped target bounds how far the boundary can move.
                let size = journal.size().await;
                match journal.prune(*min_pos).await {
                    Ok(_) => {
                        // The deleted sections are durably gone; pin the boundary exactly.
                        expected.pruned(journal.bounds().await.start);
                        true
                    }
                    Err(_) => {
                        // Pruning removes whole sections, so a failed prune can advance the boundary
                        // at most to the section-aligned floor of the capped target.
                        let capped = (*min_pos).min(size);
                        let section_floor =
                            capped / params.items_per_section * params.items_per_section;
                        expected.prune_failed(section_floor);
                        false
                    }
                }
            }

            JournalOperation::Replay { buffer, start_pos } => {
                // The clamped (in-bounds) replay must return the full contiguous suffix matching
                // `read()`, or hit a legitimate tail-repair I/O fault; the raw replay probes the
                // validation paths.
                let bounds = journal.bounds().await;
                let clamped = bounds.start + (*start_pos % (bounds.end - bounds.start + 1));
                let clamped_ok = match journal.replay(NZUsize!(*buffer), clamped).await {
                    Ok(items) => {
                        assert_replay_suffix(&items, clamped, &bounds);
                        // Cross-check replay content against `read()` (reads are fault-free here),
                        // so a start-dependent replay regression cannot pass as long as it returns
                        // `Ok`.
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

            // `split_into_cycles` strips `Crash`; treat a stray one defensively as ending the cycle.
            JournalOperation::Crash => false,
        };

        if !should_continue {
            break;
        }
    }
}

/// Run one crash cycle: recover via `init`, verify the recovered state matches the `Expected`
/// carried from the prior crash, `observe` the journal, prove it still works, then run the cycle's
/// ops under faults and crash (drop). Returns the updated `Expected` and a checkpoint for the next
/// cycle.
fn run_cycle<J: FuzzJournal + Send + 'static>(
    runner: deterministic::Runner,
    incoming: Expected,
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
        // The recovered state must match what the previous cycle left durable.
        assert_matches_expected(&journal, &incoming).await;

        let mut expected = observe(&journal).await;
        assert_round_trip(&mut journal, &mut expected).await;

        // Enable faults for the operation phase, then drop the journal at the end (the crash).
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

    // Each later cycle recovers from the previous crash, runs its ops, then crashes again.
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

    // Final fault-free recovery: full verification, a clean durable round-trip, then cleanup.
    deterministic::Runner::from(checkpoint).start(move |ctx| async move {
        *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();
        let mut journal = J::init(
            ctx.child("journal_final"),
            J::config(&partition, &ctx, &params),
        )
        .await
        .expect("final recovery should succeed");

        assert_matches_expected(&journal, &expected).await;

        let size = journal.size().await;
        let sentinel = Item::from([0xEFu8; ITEM_SIZE]);
        let pos = journal
            .append(sentinel.clone())
            .await
            .expect("final append");
        assert_eq!(pos, size);
        journal.sync().await.expect("final sync");
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
