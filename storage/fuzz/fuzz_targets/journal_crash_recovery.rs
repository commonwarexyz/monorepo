#![no_main]

//! Fuzz test for journal crash recovery (both fixed and variable journals).
//!
//! Drives a journal through repeated unclean shutdowns. Each cycle:
//!   1. recovers the journal from the previous (unclean) shutdown,
//!   2. verifies the recovered state matches a model of what is durably guaranteed (exact item
//!      content for the durable prefix, pruned positions error, size/boundary within bounds),
//!   3. continues appending and querying, then
//!   4. crashes again (faults + unclean drop, losing the in-memory write buffer).
//!
//! Each cycle re-runs `init()` on a journal produced by a prior crash recovery, so any bug in the
//! recovery watermark, pruning metadata, or section layout compounds across restarts. The
//! operation phase runs under write/sync/resize fault injection, including the torn-write modes
//! (`partial_write_rate`, `partial_resize_rate`) that model a real crash mid-write.

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

/// Maximum number of operations per fuzz input. Bounds the number of crash cycles and the
/// per-cycle verification/replay work so executions stay fast and `rebaseline`'s allocation stays
/// small (total cost is ~O(cycles * size), both capped by this).
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

/// Operations that can be performed on the journal within a segment.
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
    /// Mark an unclean shutdown: end the current segment, drop the journal without a clean sync,
    /// and recover in the next segment.
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
    /// Sequence of operations to execute (split into segments at `Crash` markers).
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

/// Model of the journal's state after an unclean shutdown: a guaranteed-durable floor and
/// conservative upper bounds.
///
/// The bounds are deliberately conservative, so every assertion in `verify_recovery` is sound under
/// any fault/crash interleaving:
/// - positions `[0, durable_prune)` are pruned (reads return `ItemPruned`),
/// - positions `[max_prune, durable_len)` are present with the exact content `values[pos]`,
/// - the recovered size is in `[durable_len, max_size]`,
/// - the recovered pruning boundary is in `[durable_prune, max_prune]`,
/// - `values.len()` tracks the in-memory size, so `values[pos]` is the latest value at `pos`.
///
/// The methods below are the per-operation update rules that maintain these invariants.
#[derive(Clone, Default)]
struct Model {
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

impl Model {
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

    /// Prune may advance the recovered pruning boundary up to `boundary` (durable only after sync).
    fn pruned(&mut self, boundary: u64) {
        self.max_prune = self.max_prune.max(boundary);
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

    // Spelled-out future, not `async fn`: the latter can't carry the `+ Send` bound (RPITIT).
    #[allow(clippy::manual_async_fn)]
    fn bounds(&self) -> impl Future<Output = Range<u64>> + Send {
        async { self.reader().await.bounds() }
    }

    async fn append(&mut self, item: Item) -> Result<u64, Error> {
        FixedJournal::append(self, &item).await
    }

    // Spelled-out future, not `async fn`: the latter can't carry the `+ Send` bound (RPITIT).
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

    // Spelled-out future, not `async fn`: the latter can't carry the `+ Send` bound (RPITIT).
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

    // Spelled-out future, not `async fn`: the latter can't carry the `+ Send` bound (RPITIT).
    #[allow(clippy::manual_async_fn)]
    fn bounds(&self) -> impl Future<Output = Range<u64>> + Send {
        async { self.reader().await.bounds() }
    }

    async fn append(&mut self, item: Item) -> Result<u64, Error> {
        VariableJournal::append(self, &item).await
    }

    // Spelled-out future, not `async fn`: the latter can't carry the `+ Send` bound (RPITIT).
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

    // Spelled-out future, not `async fn`: the latter can't carry the `+ Send` bound (RPITIT).
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

/// Split the operation stream into one segment per crash cycle, cutting at each `Crash` marker.
/// Always returns at least one segment (possibly empty), so a bare recovery is still exercised.
fn split_segments(ops: &[JournalOperation]) -> Vec<Vec<JournalOperation>> {
    let mut segments = Vec::new();
    let mut current = Vec::new();
    for op in ops {
        if matches!(op, JournalOperation::Crash) {
            segments.push(std::mem::take(&mut current));
        } else {
            current.push(op.clone());
        }
    }
    segments.push(current);
    segments
}

/// Verify the recovered journal matches the model carried from the previous (crashed) segment.
async fn verify_recovery<J: FuzzJournal>(journal: &J, model: &Model) {
    let Range {
        start: boundary,
        end: size,
    } = journal.bounds().await;
    assert!(size >= boundary, "size {size} < boundary {boundary}");

    // Size and boundary fall within the modeled bounds.
    assert!(
        size >= model.durable_len,
        "recovered size {size} < durable_len {}",
        model.durable_len
    );
    assert!(
        size <= model.max_size,
        "recovered size {size} > max_size {}",
        model.max_size
    );
    assert!(
        boundary >= model.durable_prune,
        "recovered boundary {boundary} < durable_prune {}",
        model.durable_prune
    );
    assert!(
        boundary <= model.max_prune,
        "recovered boundary {boundary} > max_prune {}",
        model.max_prune
    );

    // Below the recovered boundary every position is pruned, so reads must return `ItemPruned`.
    // Using the actual boundary (not the model's `durable_prune` floor) makes the pruned vs.
    // in-bounds split exact, so the loop below can require everything in bounds to be readable.
    for pos in 0..boundary {
        match journal.read(pos).await {
            Err(Error::ItemPruned(_)) => {}
            other => panic!("expected ItemPruned below boundary at {pos}, got {other:?}"),
        }
    }

    // Within bounds [boundary, size) every position must be readable (never pruned). Content is
    // pinned to the model for the durable prefix; the volatile tail is readable but its content is
    // unconstrained (torn writes / unsynced rewind). Reads are collected for the replay cross-check.
    let mut read_items = Vec::with_capacity((size - boundary) as usize);
    for pos in boundary..size {
        let item = journal
            .read(pos)
            .await
            .unwrap_or_else(|e| panic!("in-bounds pos {pos} unreadable: {e:?}"));
        if pos < model.durable_len {
            assert_eq!(
                item, model.values[pos as usize],
                "content mismatch at durable pos {pos}"
            );
        }
        read_items.push(item);
    }

    // Replay must yield exactly [boundary, size) contiguously and agree with `read()` at every
    // position. The cross-check covers the whole range, including the volatile tail where neither
    // path is checked against the model, so a read/replay divergence cannot slip through.
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
        let expected = boundary + i as u64;
        assert_eq!(
            *pos, expected,
            "replay non-contiguous: got {pos}, expected {expected}"
        );
        assert_eq!(*item, read_items[i], "replay/read divergence at {pos}");
    }
}

/// Re-baseline the model to the now-on-disk recovered state. The recovered data came from disk and
/// is durable against the next unclean drop (except where a later rewind/prune/torn-append touches
/// it, which the per-op update rules handle).
async fn rebaseline<J: FuzzJournal>(journal: &J) -> Model {
    let bounds = journal.bounds().await;
    let items = journal
        .replay(NZUsize!(VERIFY_REPLAY_BUF), bounds.start)
        .await
        .expect("rebaseline replay");
    let mut values = vec![Item::from([0u8; ITEM_SIZE]); bounds.end as usize];
    for (pos, item) in items {
        values[pos as usize] = item;
    }
    Model {
        durable_len: bounds.end,
        max_size: bounds.end,
        durable_prune: bounds.start,
        max_prune: bounds.start,
        values,
    }
}

/// Confirm the journal is usable after opening by appending a sentinel and reading it back. Runs
/// fault-free, so it must succeed; the sentinel is unsynced, so it only widens the size ceiling.
async fn prove_usable<J: FuzzJournal>(journal: &mut J, model: &mut Model) {
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
    model.appended(sentinel);
}

/// Check a read/replay of an in-range position, returning whether the segment stays alive. `Ok` is
/// fine; an I/O fault (e.g. a failed internal flush) may have left the journal inconsistent, so the
/// segment ends. `ItemPruned`/`ItemOutOfRange` can't happen in range, so it means a broken `Reader`
/// contract and panics.
fn in_range_probe<T>(result: Result<T, Error>, pos: u64, bounds: &Range<u64>) -> bool {
    match result {
        Ok(_) => true,
        Err(e @ (Error::ItemPruned(_) | Error::ItemOutOfRange(_))) => panic!(
            "in-bounds access at {pos} ([{}, {})) returned {e:?}",
            bounds.start, bounds.end
        ),
        Err(_) => false,
    }
}

/// Check a read/replay of an arbitrary position. Success, or a validation error that did no I/O
/// (`ItemPruned`/`ItemOutOfRange`), keeps the segment alive; any other error is an I/O fault that
/// may have left the journal inconsistent, so the segment ends.
fn raw_probe<T>(result: Result<T, Error>) -> bool {
    matches!(
        result,
        Ok(_) | Err(Error::ItemPruned(_)) | Err(Error::ItemOutOfRange(_))
    )
}

/// Run the segment's ops under faults, updating `model`. Stops early if an op may have left the
/// journal inconsistent (any mutable error, or an in-range read/replay that hit an I/O fault); the
/// caller then drops the journal to simulate the crash.
async fn run_segment<J: FuzzJournal>(
    journal: &mut J,
    model: &mut Model,
    ops: &[JournalOperation],
    params: Params,
) {
    for op in ops {
        // `alive` becomes false once an op may have left the journal inconsistent; the segment ends.
        let alive = match op {
            JournalOperation::Append { value } => {
                let item = Item::from(*value);
                let size_before = journal.size().await;
                match journal.append(item.clone()).await {
                    Ok(pos) => {
                        assert_eq!(pos, size_before, "append returned non-contiguous position");
                        model.appended(item);
                        true
                    }
                    Err(_) => {
                        model.append_failed(size_before);
                        false
                    }
                }
            }

            JournalOperation::Read { pos } => {
                // An in-range read must succeed; the raw read also exercises the out-of-range and
                // pruned paths.
                let bounds = journal.bounds().await;
                let mut alive = true;
                if !bounds.is_empty() {
                    let target = bounds.start + (*pos % (bounds.end - bounds.start));
                    alive = in_range_probe(journal.read(target).await, target, &bounds);
                }
                if alive {
                    alive = raw_probe(journal.read(*pos).await);
                }
                alive
            }

            JournalOperation::Sync => match journal.sync().await {
                Ok(()) => {
                    model.synced(journal.bounds().await);
                    true
                }
                Err(_) => false,
            },

            JournalOperation::Commit => match journal.commit().await {
                Ok(()) => {
                    model.committed(journal.size().await);
                    true
                }
                Err(_) => false,
            },

            JournalOperation::Rewind { size } => {
                let bounds = journal.bounds().await;
                if bounds.is_empty() {
                    true
                } else {
                    // Usually clamp to a retained position in [start, end]; occasionally pass the raw
                    // value to exercise the validation paths (target past the end, or below the
                    // pruning boundary).
                    let target = if *size % 8 == 0 {
                        *size
                    } else {
                        bounds.start + (*size % (bounds.end - bounds.start + 1))
                    };
                    match journal.rewind(target).await {
                        Ok(()) => {
                            // Rewound to `target`; the truncated tail may or may not persist.
                            model.rewound(target, bounds.end);
                            model.values.truncate(target as usize);
                            true
                        }
                        // Validation error (target out of range): rejected before any mutation, so
                        // the journal is unchanged and the model must stay put (lowering durable_len
                        // would mask later loss of still-durable data).
                        Err(Error::InvalidRewind(_)) | Err(Error::ItemPruned(_)) => true,
                        // I/O fault mid-truncation: data above `target` may be lost, so lower
                        // durable_len conservatively and end the segment.
                        Err(_) => {
                            model.rewound(target.min(bounds.end), bounds.end);
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
                        model.pruned(journal.bounds().await.start);
                        true
                    }
                    Err(_) => {
                        // Pruning removes whole sections, so a failed prune can advance the boundary
                        // at most to the section-aligned floor of the capped target.
                        let capped = (*min_pos).min(size);
                        let section_floor =
                            capped / params.items_per_section * params.items_per_section;
                        model.pruned(section_floor);
                        false
                    }
                }
            }

            JournalOperation::Replay { buffer, start_pos } => {
                // Same contract as `Read`: the clamped (in-range) replay must succeed; the raw replay
                // probes the validation paths.
                let bounds = journal.bounds().await;
                let clamped = bounds.start + (*start_pos % (bounds.end - bounds.start + 1));
                let mut alive = in_range_probe(
                    journal.replay(NZUsize!(*buffer), clamped).await,
                    clamped,
                    &bounds,
                );
                if alive {
                    alive = raw_probe(journal.replay(NZUsize!(*buffer), *start_pos).await);
                }
                alive
            }

            // `split_segments` strips `Crash`; treat a stray one defensively as ending the segment.
            JournalOperation::Crash => false,
        };

        if !alive {
            break;
        }
    }
}

/// Run one crash cycle: recover via `init`, verify the recovered state matches the model
/// carried from the prior crash, re-baseline, prove the journal still works, then run the segment
/// under faults and crash (drop). Returns the updated model and a checkpoint for the next cycle.
fn run_cycle<J: FuzzJournal + Send + 'static>(
    runner: deterministic::Runner,
    incoming: Model,
    ops: Vec<JournalOperation>,
    partition: String,
    params: Params,
) -> (Model, deterministic::Checkpoint)
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
        verify_recovery(&journal, &incoming).await;

        let mut model = rebaseline(&journal).await;
        prove_usable(&mut journal, &mut model).await;

        // Enable faults for the operation phase, then drop the journal at the end (the crash).
        *ctx.storage_fault_config().write() = params.fault_config();
        run_segment(&mut journal, &mut model, &ops, params).await;
        model
    })
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
    let segments = split_segments(&input.operations);

    // First cycle starts from a fresh runtime, recovers an empty journal, and the model is empty.
    let runner = deterministic::Runner::new(deterministic::Config::default().with_seed(input.seed));
    let (mut model, mut checkpoint) = run_cycle::<J>(
        runner,
        Model::default(),
        segments[0].clone(),
        partition.clone(),
        params,
    );

    // Each later cycle recovers from the previous crash and runs its ops, then crashes again.
    for ops in segments.iter().skip(1) {
        let runner = deterministic::Runner::from(checkpoint);
        (model, checkpoint) = run_cycle::<J>(
            runner,
            model.clone(),
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

        verify_recovery(&journal, &model).await;

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
