#![no_main]

//! Fuzz target contiguous journal crash recovery.
//!
//! A journal is an append-only log of items. Appends are buffered; `sync` and `commit` establish
//! durability, while the configured crash policy may retain unsynchronized storage mutations. On
//! the next `init()` the journal must rebuild a consistent state from whatever survived. This
//! target tests recovering after storage faults.
//!
//! # Cycles
//!
//! One fuzz input drives a single journal through a series of *cycles*, each one crash-and-recover
//! round:
//!   1. `init()` recovers the journal left by the previous cycle's crash.
//!   2. Check it against the `Expected` carried from that crash.
//!   3. Append and query under fault injection (the cycle's `ops`).
//!   4. Drop the journal without a clean shutdown: the crash. Unsynchronized bytes survive
//!      according to the configured write-retention policy.
//!
//! Between cycles, a chain of recovery attempts runs under storage faults, each crashing into
//! the next. The next clean `init()` verifies that checkpoint before operations continue.
//!
//! `Crash` markers split the op list into one `ops` list per cycle. Driving recovery repeatedly on
//! the same journal is the point: watermark, pruning-metadata, and section-layout bugs often need a
//! recover-then-mutate-then-recover sequence to appear, not just a single crash.
//!
//! `Reset` markers also end a cycle, but route the next recovery through `init_at_size`: the
//! between-cycle faulted attempt runs the reset itself so its staged clear can crash anywhere,
//! and the cycle's clean recovery then checks the staged-clear contract (see [Recovery]).
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
//! The operation phase runs under write/sync/resize fault injection. `write_config` controls write
//! failures and whether retained bytes form a prefix or arbitrary subset, while
//! `partial_resize_rate` can stop a failed truncation at an intermediate length.
//!
//! # Positions
//!
//! Position arguments (`Read`, `Rewind`, `Replay`) come straight from the fuzzer, so a random `u64`
//! is almost always out of range. `Read` and `Replay` run twice (`Read` skips the clamped pass on
//! an empty journal): once with the value clamped into the live range, which must take the success
//! path, and once with the raw value, which exercises the validation path (`ItemPruned` below the
//! start, `ItemOutOfRange` past the end). `Rewind` runs once, usually clamped, occasionally raw.

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{BufferPooler, ReadOptions, Runner, Supervisor as _, deterministic};
use commonware_storage::journal::{
    Error,
    contiguous::{
        Contiguous,
        fixed::{Config as FixedConfig, Journal as FixedJournal},
        variable::{Config as VariableConfig, Journal as VariableJournal},
    },
};
use commonware_storage_fuzz::{
    bounded_buffer, bounded_items, bounded_page_cache_size, bounded_page_size, faulted_recovery,
};
use commonware_utils::{NZU64, NZUsize, Probability, probability, sequence::FixedBytes};
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

/// Buffer size used for internal verification replays.
const VERIFY_REPLAY_BUF: usize = 1024;

/// Maximum number of operations per fuzz input.
const MAX_OPERATIONS: usize = 128;

/// Reset targets are taken modulo this bound, keeping `Expected::values` and per-recovery scans
/// small while still spanning multiple sections at every `items_per_section`.
const MAX_RESET_SIZE: u64 = 256;

/// A fault rate in [0.0, 1.0]. Allows 0 so the fuzzer can disable individual fault types.
fn bounded_rate(u: &mut Unstructured<'_>) -> arbitrary::Result<Probability> {
    let percent: u8 = u.int_in_range(0..=100)?;
    Ok(probability!(u64::from(percent), 100))
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
    /// Capture and drop a snapshot reader, flushing buffered data without a durability barrier.
    Snapshot,
    /// Commit the journal.
    Commit,
    /// Rewind the journal to a smaller size.
    Rewind { size: u64 },
    /// Prune items before a position.
    Prune { min_pos: u64 },
    /// Replay items from the journal.
    Replay {
        #[arbitrary(with = bounded_buffer)]
        buffer: usize,
        start_pos: u64,
    },
    /// End the current cycle: drop the journal without a clean sync and recover in the next cycle.
    Crash,
    /// End the current cycle and recover through an `init_at_size` reset (see [Recovery::Reset]).
    Reset { size: u64, complete: bool },
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
    #[arbitrary(with = bounded_items)]
    items_per_section: u64,
    /// Write buffer size.
    #[arbitrary(with = bounded_buffer)]
    write_buffer: usize,
    /// Replay buffer size.
    #[arbitrary(with = bounded_buffer)]
    replay_buffer: usize,
    /// Failure and byte-retention configuration for write operations.
    write_config: deterministic::WriteConfig,
    /// Failure rate for sync operations.
    #[arbitrary(with = bounded_rate)]
    sync_failure_rate: Probability,
    /// Failure rate for resize operations (truncation during rewind/prune).
    #[arbitrary(with = bounded_rate)]
    resize_failure_rate: Probability,
    /// Probability that a resize failure is partial.
    #[arbitrary(with = bounded_rate)]
    partial_resize_rate: Probability,
    /// Operations to execute, split into one `ops` list per cycle at each `Crash` or
    /// `Reset` marker.
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
    replay_buffer: NonZeroUsize,
    write_config: deterministic::WriteConfig,
    sync_rate: Probability,
    resize_rate: Probability,
    partial_resize_rate: Probability,
    recovery_seed: u64,
}

impl Params {
    /// The fault config applied during the operation phase of each cycle.
    fn fault_config(&self) -> deterministic::FaultConfig {
        deterministic::FaultConfig {
            write_rate: Some(self.write_config),
            sync_rate: Some(self.sync_rate),
            resize_rate: Some(deterministic::ResizeConfig {
                failure_rate: self.resize_rate,
                partial_rate: self.partial_resize_rate,
            }),
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
    /// State after a completed `init_at_size(target)`: fully pruned at `target` with no items.
    /// `values` can stay empty because content is only checked on `[boundary, durable_len)`,
    /// an empty range here.
    fn reset(target: u64) -> Self {
        Self {
            durable_len: target,
            max_size: target,
            durable_prune: target,
            max_prune: target,
            values: Vec::new(),
        }
    }

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

    /// A completed data barrier (commit, or the sync inside a successful prune) pins size and
    /// content but not the pruning boundary.
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

    fn init_at_size(
        ctx: deterministic::Context,
        cfg: Self::Config,
        size: u64,
    ) -> impl Future<Output = Result<Self, Error>> + Send;

    fn size(&self) -> impl Future<Output = u64> + Send;
    fn bounds(&self) -> Range<u64>;

    fn append(self, item: Item) -> impl Future<Output = Result<(Self, u64), Error>> + Send;
    fn read(&self, pos: u64) -> impl Future<Output = Result<Item, Error>> + Send;
    fn sync(self) -> impl Future<Output = Result<Self, Error>> + Send;
    fn snapshot(self) -> impl Future<Output = Result<Self, Error>> + Send;
    fn commit(self) -> impl Future<Output = Result<Self, Error>> + Send;
    fn rewind(self, size: u64) -> impl Future<Output = Result<Self, Error>> + Send;
    fn prune(self, min_pos: u64) -> impl Future<Output = Result<(Self, bool), Error>> + Send;

    fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> impl Future<Output = Result<Vec<(u64, Item)>, Error>> + Send;

    fn destroy(self) -> impl Future<Output = Result<(), Error>> + Send;
}

/// Drain a reader's replay stream into a `(position, item)` vector.
async fn collect_replay<C: Contiguous<Item = Item>>(
    reader: &C,
    start_pos: u64,
    buffer: NonZeroUsize,
) -> Result<Vec<(u64, Item)>, Error> {
    let stream = reader
        .replay(start_pos, buffer, ReadOptions::default())
        .await?;
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
            replay_buffer: params.replay_buffer,
        }
    }

    async fn init(ctx: deterministic::Context, cfg: Self::Config) -> Result<Self, Error> {
        FixedJournal::init(ctx, cfg).await
    }

    async fn init_at_size(
        ctx: deterministic::Context,
        cfg: Self::Config,
        size: u64,
    ) -> Result<Self, Error> {
        FixedJournal::init_at_size(ctx, cfg, size).await
    }

    async fn size(&self) -> u64 {
        FixedJournal::size(self)
    }

    fn bounds(&self) -> Range<u64> {
        Contiguous::bounds(self)
    }

    async fn append(self, item: Item) -> Result<(Self, u64), Error> {
        FixedJournal::append(self, &item).await
    }

    async fn read(&self, pos: u64) -> Result<Item, Error> {
        Contiguous::read(self, pos).await
    }

    async fn sync(self) -> Result<Self, Error> {
        FixedJournal::sync(self).await
    }

    async fn snapshot(self) -> Result<Self, Error> {
        let (journal, reader) = FixedJournal::snapshot(self).await?;
        drop(reader);
        Ok(journal)
    }

    async fn commit(self) -> Result<Self, Error> {
        FixedJournal::commit(self).await
    }

    async fn rewind(self, size: u64) -> Result<Self, Error> {
        FixedJournal::rewind(self, size).await
    }

    async fn prune(self, min_pos: u64) -> Result<(Self, bool), Error> {
        FixedJournal::prune(self, min_pos).await
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<Vec<(u64, Item)>, Error> {
        collect_replay(self, start_pos, buffer).await
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
            replay_buffer: params.replay_buffer,
        }
    }

    async fn init(ctx: deterministic::Context, cfg: Self::Config) -> Result<Self, Error> {
        VariableJournal::init(ctx, cfg).await
    }

    async fn init_at_size(
        ctx: deterministic::Context,
        cfg: Self::Config,
        size: u64,
    ) -> Result<Self, Error> {
        VariableJournal::init_at_size(ctx, cfg, size).await
    }

    async fn size(&self) -> u64 {
        VariableJournal::size(self)
    }

    fn bounds(&self) -> Range<u64> {
        Contiguous::bounds(self)
    }

    async fn append(self, item: Item) -> Result<(Self, u64), Error> {
        VariableJournal::append(self, &item).await
    }

    async fn read(&self, pos: u64) -> Result<Item, Error> {
        Contiguous::read(self, pos).await
    }

    async fn sync(self) -> Result<Self, Error> {
        VariableJournal::sync(self).await
    }

    async fn snapshot(self) -> Result<Self, Error> {
        let (journal, reader) = VariableJournal::snapshot(self).await?;
        drop(reader);
        Ok(journal)
    }

    async fn rewind(self, size: u64) -> Result<Self, Error> {
        VariableJournal::rewind(self, size).await
    }

    async fn prune(self, min_pos: u64) -> Result<(Self, bool), Error> {
        VariableJournal::prune(self, min_pos).await
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<Vec<(u64, Item)>, Error> {
        collect_replay(self, start_pos, buffer).await
    }

    async fn commit(self) -> Result<Self, Error> {
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
    } = journal.bounds();
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
        .replay(boundary, NZUsize!(VERIFY_REPLAY_BUF))
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
    let bounds = journal.bounds();
    let items = journal
        .replay(bounds.start, NZUsize!(VERIFY_REPLAY_BUF))
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

/// Check a raw-position replay. Validation precedes any I/O, so an out-of-range start is
/// deterministic: `< start` -> `ItemPruned`, `> end` -> `ItemOutOfRange` (`== end` is in
/// range). Replay is a pure read and read faults are never injected, so an in-range start
/// must succeed and any other result is a real bug.
fn assert_raw_replay(result: Result<Vec<(u64, Item)>, Error>, start_pos: u64, bounds: &Range<u64>) {
    let ok = match &result {
        Ok(_) => start_pos >= bounds.start && start_pos <= bounds.end,
        Err(Error::ItemPruned(_)) => start_pos < bounds.start,
        Err(Error::ItemOutOfRange(_)) => start_pos > bounds.end,
        Err(_) => false,
    };
    assert!(
        ok,
        "raw replay at {start_pos} (bounds [{}, {})) returned {result:?}",
        bounds.start, bounds.end
    );
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

/// Run a cycle's ops under faults, updating `expected`. Stops early on a mutable-method error,
/// which may have left the journal inconsistent. The journal is then dropped to crash. Reads and
/// replays never fault, so a bad one panics instead of ending the cycle.
async fn run_ops<J: FuzzJournal>(
    mut journal: J,
    expected: &mut Expected,
    ops: &[JournalOperation],
    params: Params,
) {
    for op in ops {
        // A mutation error ends the cycle.
        journal = match op {
            JournalOperation::Append { value } => {
                let item = Item::from(*value);
                let size_before = journal.size().await;
                match journal.append(item.clone()).await {
                    Ok((journal, pos)) => {
                        assert_eq!(pos, size_before, "append returned non-contiguous position");
                        expected.appended(item);
                        journal
                    }
                    Err(err) => {
                        assert!(
                            !matches!(err, Error::Corruption(_)),
                            "append reported corruption mid-cycle: {err:?}"
                        );
                        expected.append_failed(size_before);
                        return;
                    }
                }
            }

            JournalOperation::Read { pos } => {
                let bounds = journal.bounds();
                if !bounds.is_empty() {
                    let target = bounds.start + (*pos % (bounds.end - bounds.start));
                    assert_read(journal.read(target).await, target, &bounds);
                }
                assert_read(journal.read(*pos).await, *pos, &bounds);
                journal
            }

            JournalOperation::Sync => match journal.sync().await {
                Ok(journal) => {
                    expected.synced(journal.bounds());
                    journal
                }
                Err(err) => {
                    assert!(
                        !matches!(err, Error::Corruption(_)),
                        "sync reported corruption mid-cycle: {err:?}"
                    );
                    return;
                }
            },

            // A snapshot flushes buffered data without a durability barrier, changing no
            // durability expectation. It schedules unsynced partial-page rewrites for the
            // next crash to cut.
            JournalOperation::Snapshot => match journal.snapshot().await {
                Ok(journal) => journal,
                Err(err) => {
                    assert!(
                        !matches!(err, Error::Corruption(_)),
                        "snapshot reported corruption mid-cycle: {err:?}"
                    );
                    return;
                }
            },

            JournalOperation::Commit => match journal.commit().await {
                Ok(journal) => {
                    expected.committed(journal.size().await);
                    journal
                }
                Err(err) => {
                    assert!(
                        !matches!(err, Error::Corruption(_)),
                        "commit reported corruption mid-cycle: {err:?}"
                    );
                    return;
                }
            },

            JournalOperation::Rewind { size } => {
                let bounds = journal.bounds();
                if bounds.is_empty() {
                    journal
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
                        Ok(journal) => {
                            expected.rewound(target, bounds.end);
                            expected.values.truncate(target as usize);
                            journal
                        }
                        // Any error ends the cycle. Validation errors reject before
                        // mutating and are only possible for a raw target; seeing one for
                        // a clamped target is a bug. Any other error
                        // may have interrupted the truncation and lost data above `target`,
                        // so lower durable_len conservatively.
                        Err(e @ (Error::InvalidRewind(_) | Error::ItemPruned(_))) => {
                            assert!(
                                use_raw_target,
                                "rewind to clamped retained target {target} (bounds [{}, {})) \
                                 returned {e:?}",
                                bounds.start, bounds.end
                            );
                            return;
                        }
                        Err(err) => {
                            assert!(
                                !matches!(err, Error::Corruption(_)),
                                "rewind reported corruption mid-cycle: {err:?}"
                            );
                            expected.rewound(target.min(bounds.end), bounds.end);
                            return;
                        }
                    }
                }
            }

            JournalOperation::Prune { min_pos } => {
                // Raw position: `prune` caps it to size internally, covering prune-past-size.
                let Range {
                    start: boundary,
                    end: size,
                } = journal.bounds();
                match journal.prune(*min_pos).await {
                    Ok((journal, pruned)) => {
                        // The boundary only moves forward, and the returned bool's contract
                        // (true iff items were pruned) must match the observed move.
                        let new_boundary = journal.bounds().start;
                        assert!(
                            new_boundary >= boundary,
                            "prune moved boundary backward {boundary} -> {new_boundary}"
                        );
                        assert_eq!(
                            pruned,
                            new_boundary != boundary,
                            "prune returned {pruned} with boundary {boundary} -> {new_boundary}"
                        );

                        // A completed prune syncs and awaits all buffered data before removing
                        // any blob, so it pins the pre-prune size and content like a commit. A
                        // no-op prune performs no sync and earns no credit.
                        if pruned {
                            expected.committed(size);
                        }
                        expected.pruned(new_boundary);
                        journal
                    }
                    Err(err) => {
                        assert!(
                            !matches!(err, Error::Corruption(_)),
                            "prune reported corruption mid-cycle: {err:?}"
                        );

                        // A failed prune advances the boundary at most to the section floor.
                        let capped = (*min_pos).min(size);
                        let section_floor =
                            capped / params.items_per_section * params.items_per_section;
                        expected.prune_failed(section_floor);
                        return;
                    }
                }
            }

            JournalOperation::Replay { buffer, start_pos } => {
                // The clamped replay must return the full suffix matching `read()`. Replay
                // is a pure read over successfully written data, so any error is a real bug.
                let bounds = journal.bounds();
                let clamped = bounds.start + (*start_pos % (bounds.end - bounds.start + 1));
                let items = journal
                    .replay(clamped, NZUsize!(*buffer))
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "in-bounds replay at {clamped} (bounds [{}, {})) returned {e:?}",
                            bounds.start, bounds.end
                        )
                    });
                assert_replay_suffix(&items, clamped, &bounds);
                for (pos, item) in &items {
                    let via_read = journal
                        .read(*pos)
                        .await
                        .unwrap_or_else(|e| panic!("read({pos}) cross-check during replay: {e:?}"));
                    assert_eq!(*item, via_read, "replay/read divergence at {pos}");
                }
                assert_raw_replay(
                    journal.replay(*start_pos, NZUsize!(*buffer)).await,
                    *start_pos,
                    &bounds,
                );
                journal
            }

            // `split_into_cycles` strips the cycle markers. A stray one defensively ends the
            // cycle.
            JournalOperation::Crash | JournalOperation::Reset { .. } => return,
        };
    }
}

/// How a cycle's clean recovery reopens the crashed journal.
#[derive(Clone, Copy)]
enum Recovery {
    /// Ordinary `init` of whatever the crash left.
    Init,
    /// The between-cycle faulted attempt ran `init_at_size(target)`, so a staged clear may have
    /// crashed anywhere. With `complete`, the recovery reruns `init_at_size(target)` and must
    /// land at exactly `target..target`. Otherwise it runs `init`, which must observe either
    /// the prior state (the clear intent never became durable) or the completed reset (a
    /// durable intent finished during `init`), never a mix.
    Reset { target: u64, complete: bool },
}

/// One crash cycle: how to recover the crashed journal and the ops to run before the next crash.
#[derive(Clone)]
struct Cycle {
    recovery: Recovery,
    ops: Vec<JournalOperation>,
}

/// Run one crash cycle: recover per `cycle.recovery`, check the recovered state, run the ops under
/// faults, then crash (drop). Returns the `Expected` and checkpoint for the next cycle.
fn run_cycle<J: FuzzJournal + Send + 'static>(
    runner: deterministic::Runner,
    expected: Expected,
    cycle: Cycle,
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
        let journal = match cycle.recovery {
            Recovery::Init => {
                let journal = J::init(ctx.child("journal"), cfg)
                    .await
                    .expect("recovery should succeed without panic");
                assert_matches_expected(&journal, &expected).await;
                journal
            }

            // A clean reset lands at exactly `target..target` no matter what the crashed
            // `init_at_size` attempt left behind.
            Recovery::Reset {
                target,
                complete: true,
            } => {
                let journal = J::init_at_size(ctx.child("journal"), cfg, target)
                    .await
                    .expect("clean init_at_size should succeed");
                assert_matches_expected(&journal, &Expected::reset(target)).await;
                journal
            }

            // Ordinary `init` after the crashed `init_at_size` attempt: the staged-clear
            // contract allows exactly the prior state or the completed reset.
            Recovery::Reset {
                target,
                complete: false,
            } => {
                let journal = J::init(ctx.child("journal"), cfg)
                    .await
                    .expect("recovery should succeed without panic");
                if journal.bounds() == (target..target) {
                    assert_matches_expected(&journal, &Expected::reset(target)).await;
                } else {
                    assert_matches_expected(&journal, &expected).await;
                }
                journal
            }
        };

        let mut expected = to_expected(&journal).await;

        // Faults on for the operation phase; returning drops the journal (the crash).
        *ctx.storage_fault_config().write() = params.fault_config();
        run_ops(journal, &mut expected, &cycle.ops, params).await;
        expected
    })
}

/// Attempt journal recovery under storage faults and return its crash checkpoint.
///
/// `cycle` varies the fault selectors per restart, so a multi-cycle run can hit a different
/// mutation class (write, sync, resize, or remove) at each recovery. With `reset`, the attempt
/// runs `init_at_size(target)` instead of `init`, planting a staged clear that the crash can
/// interrupt anywhere: before the intent is durable, mid-clear, or after completion.
fn faulted_restart<J: FuzzJournal + Send + 'static>(
    checkpoint: deterministic::Checkpoint,
    partition: String,
    params: Params,
    cycle: u64,
    reset: Option<u64>,
) -> deterministic::Checkpoint
where
    J::Config: Send,
{
    faulted_recovery(checkpoint, params.recovery_seed ^ cycle, move |ctx| {
        let partition = partition.clone();
        async move {
            let cfg = J::config(&partition, &ctx, &params);
            let ctx = ctx.child("faulted_recovery");
            match reset {
                Some(target) => J::init_at_size(ctx, cfg, target).await,
                None => J::init(ctx, cfg).await,
            }
        }
    })
}

/// Split the operation stream into one [Cycle] per crash, cutting at each `Crash` or `Reset`
/// marker. A `Reset` marker selects `init_at_size` recovery for the cycle that follows it.
/// Always returns at least one cycle (possibly with no ops), so a bare recovery is still
/// exercised.
fn split_into_cycles(ops: &[JournalOperation]) -> Vec<Cycle> {
    let mut cycles = Vec::new();
    let mut current = Vec::new();
    let mut recovery = Recovery::Init;
    for op in ops {
        let next = match op {
            JournalOperation::Crash => Recovery::Init,
            JournalOperation::Reset { size, complete } => Recovery::Reset {
                target: size % MAX_RESET_SIZE,
                complete: *complete,
            },
            _ => {
                current.push(op.clone());
                continue;
            }
        };
        cycles.push(Cycle {
            recovery,
            ops: std::mem::take(&mut current),
        });
        recovery = next;
    }
    cycles.push(Cycle {
        recovery,
        ops: current,
    });
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
        replay_buffer: NonZeroUsize::new(input.replay_buffer).unwrap(),
        write_config: input.write_config,
        sync_rate: input.sync_failure_rate,
        resize_rate: input.resize_failure_rate,
        partial_resize_rate: input.partial_resize_rate,
        recovery_seed: input.seed,
    };
    let partition = format!("crash-recovery-{tag}-{}", input.seed);
    let cycles = split_into_cycles(&input.operations);

    // First cycle starts from a fresh runtime and recovers an empty journal, so the expectation is
    // empty too.
    let mut runner =
        deterministic::Runner::new(deterministic::Config::default().with_seed(input.seed));
    let mut expected = Expected::default();
    for (i, cycle) in cycles.iter().enumerate() {
        let (next, checkpoint) =
            run_cycle::<J>(runner, expected, cycle.clone(), partition.clone(), params);
        expected = next;

        // The faulted attempt before a reset cycle runs the reset itself, so its staged clear
        // can crash at any point.
        let reset = match cycles.get(i + 1).map(|cycle| cycle.recovery) {
            Some(Recovery::Reset { target, .. }) => Some(target),
            _ => None,
        };
        let checkpoint =
            faulted_restart::<J>(checkpoint, partition.clone(), params, i as u64, reset);
        runner = deterministic::Runner::from(checkpoint);
    }

    // Final fault-free phase: verify the last recovery, then append, sync, drop, and reopen a
    // sentinel to prove the synced state survives restart.
    runner.start(move |ctx| async move {
        *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();
        let journal = J::init(
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
        let (journal, pos) = journal
            .append(sentinel.clone())
            .await
            .expect("final append");
        assert_eq!(pos, size);
        expected.appended(sentinel.clone());
        let journal = journal.sync().await.expect("final sync");
        expected.synced(journal.bounds());
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
