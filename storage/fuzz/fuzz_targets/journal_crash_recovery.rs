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
//!   4. Drop the journal without a clean shutdown. The crash may retain any subset of unsynced
//!      write bytes.
//!
//! `Crash` markers split the op list into one `ops` list per cycle. Driving recovery repeatedly on
//! the same journal is the point: watermark, pruning-metadata, and section-layout bugs often need a
//! recover-then-mutate-then-recover sequence to appear, not just a single crash.
//!
//! # Expected
//!
//! A crash can land anywhere in a range, so `Expected` tracks a guaranteed-durable prefix and the
//! whole items that may survive, not an exact state.
//! `assert_matches_expected` checks recovery falls within them and snapshots it as the next cycle's
//! start.
//!
//! # Faults
//!
//! The operation phase runs under write, sync, and atomic-batch fault injection. Failed writes can
//! persist an arbitrary byte subset. A batch failure exposes either the complete old state before
//! commit or the complete new state after commit, never a partial operation set.
//!
//! # Positions
//!
//! Position arguments (`Read`, `Rewind`, `Replay`) come straight from the fuzzer, so a random `u64`
//! is almost always out of range. Each such op runs twice: once with the value clamped into the
//! live range, which must take the success path, and once with the raw value, which exercises the
//! validation path (`ItemPruned` below the start, `ItemOutOfRange` past the end). Clamping
//! guarantees the success path is covered on every input; the raw value still tests rejection.

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{BufferPooler, Runner, Supervisor as _, deterministic};
use commonware_storage::journal::{
    Error,
    contiguous::{
        Contiguous,
        fixed::{Config as FixedConfig, Journal as FixedJournal},
        variable::{Config as VariableConfig, Journal as VariableJournal},
    },
};
use commonware_storage_fuzz::{
    RNG_BYTES, bounded_items_per_section, bounded_page_cache_size, bounded_page_size, bounded_rate,
    fuzz_runner, split_cycles,
};
use commonware_utils::{NZU64, NZUsize, sequence::FixedBytes};
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

fn bounded_write_buffer(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(1..=MAX_WRITE_BUF)
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
    /// Fuzzer-controlled randomness for deterministic runtime choices.
    raw_bytes: [u8; RNG_BYTES],
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
    /// Optional compression for the variable journal.
    compression: bool,
    /// Failure rate for write operations.
    #[arbitrary(with = bounded_rate)]
    write_failure_rate: f64,
    /// Probability that a write failure is a partial (torn) write.
    #[arbitrary(with = bounded_rate)]
    partial_write_rate: f64,
    /// Failure rate for sync operations.
    #[arbitrary(with = bounded_rate)]
    sync_failure_rate: f64,
    /// Failure rate before an atomic physical batch commits.
    #[arbitrary(with = bounded_rate)]
    batch_failure_rate: f64,
    /// Failure rate after an atomic physical batch commits.
    #[arbitrary(with = bounded_rate)]
    batch_post_commit_rate: f64,
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
    batch_rate: f64,
    batch_post_commit_rate: f64,
    compression: bool,
}

impl Params {
    /// The fault config applied during the operation phase of each cycle.
    fn fault_config(&self) -> deterministic::FaultConfig {
        deterministic::FaultConfig {
            write_rate: Some(self.write_rate),
            partial_write_rate: Some(self.partial_write_rate),
            sync_rate: Some(self.sync_rate),
            batch_rate: Some(self.batch_rate),
            batch_post_commit_rate: Some(self.batch_post_commit_rate),
            ..Default::default()
        }
    }

    fn writes_fail_before_io(&self) -> bool {
        self.write_rate == 1.0 && self.partial_write_rate == 0.0
    }

    fn batches_fail_before_commit(&self) -> bool {
        self.batch_rate == 1.0
    }
}

/// Conservative bounds on what a recovery may produce after an unclean shutdown:
/// - positions `[0, durable_prune)` are pruned (reads return `ItemPruned`),
/// - positions `[durable_prune, durable_len)` hold the exact content `values[pos]`,
/// - the recovered size is in `[durable_len, allowed_values.len()]`,
/// - the recovered pruning boundary is `durable_prune`,
/// - a failed atomic prune or rewind may instead recover the exact committed state in
///   `atomic_bounds`,
/// - every recovered tail item is one of the whole items attempted at that position.
#[derive(Clone, Default)]
struct Expected {
    /// Guaranteed-durable prefix length; also the minimum recovered size.
    durable_len: u64,
    /// Guaranteed pruning floor; positions below are guaranteed pruned.
    durable_prune: u64,
    /// Exact bounds if a failed physical batch committed before reporting its error.
    atomic_bounds: Option<Range<u64>>,
    /// Latest value appended at each position (index == position).
    values: Vec<Item>,
    /// Whole item values a crash may recover at each position. Rewinds can leave an old value in
    /// storage and a later append can replace it, but a bytewise hybrid is never valid.
    allowed_values: Vec<Vec<Item>>,
}

impl Expected {
    fn allow(&mut self, pos: usize, item: Item) {
        if self.allowed_values.len() <= pos {
            self.allowed_values.resize_with(pos + 1, Vec::new);
        }
        if !self.allowed_values[pos].contains(&item) {
            self.allowed_values[pos].push(item);
        }
    }

    fn pin_live(&mut self) {
        self.allowed_values = self.values.iter().cloned().map(|item| vec![item]).collect();
    }

    /// Successful append: not durable until the next sync/commit.
    fn appended(&mut self, item: Item) {
        let pos = self.values.len();
        self.values.push(item.clone());
        self.allow(pos, item);
    }

    /// Failed append: either no item or the complete attempted item may have persisted.
    fn append_failed(&mut self, size_before: u64, item: Item) {
        self.allow(size_before as usize, item);
    }

    /// Sync pins size, content, and pruning boundary exactly.
    fn synced(&mut self, bounds: Range<u64>) {
        self.durable_len = bounds.end;
        self.durable_prune = bounds.start;
        self.atomic_bounds = None;
        self.pin_live();
    }

    /// Commit pins the size but not the pruning boundary.
    fn committed(&mut self, size: u64) {
        self.durable_len = size;
        self.atomic_bounds = None;
        self.pin_live();
    }

    /// A successful shrink commits the exact shortened state.
    fn shrunk(&mut self, bounds: Range<u64>) {
        self.values.truncate(bounds.end as usize);
        self.durable_len = bounds.end;
        self.durable_prune = bounds.start;
        self.atomic_bounds = None;
        self.pin_live();
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
    fn bounds(&self) -> Range<u64>;

    fn append(self, item: Item) -> impl Future<Output = Result<(Self, u64), Error>> + Send;
    fn read(&self, pos: u64) -> impl Future<Output = Result<Item, Error>> + Send;
    fn sync(self) -> impl Future<Output = Result<Self, Error>> + Send;
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
    let stream = reader.replay(start_pos, buffer).await?;
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
            compression: params.compression.then_some(3),
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

/// Verify the recovered journal matches the `Expected` carried from the previous (crashed) cycle,
/// then return an exact snapshot of the recovered state.
async fn assert_matches_expected<J: FuzzJournal>(journal: &J, expected: &Expected) -> Expected {
    let Range {
        start: boundary,
        end: size,
    } = journal.bounds();
    assert!(size >= boundary, "size {size} < boundary {boundary}");

    let recovered_bounds = boundary..size;
    let atomic_bounds_match = expected.atomic_bounds.as_ref() == Some(&recovered_bounds);
    let old_bounds_match = boundary == expected.durable_prune
        && size >= expected.durable_len
        && size <= expected.allowed_values.len() as u64;
    assert!(
        atomic_bounds_match || old_bounds_match,
        "recovered bounds {recovered_bounds:?} match neither the prior crash bounds nor the exact \
         committed batch state {:?}",
        expected.atomic_bounds
    );

    // Below the boundary every position is pruned.
    for pos in 0..boundary {
        match journal.read(pos).await {
            Err(Error::ItemPruned(_)) => {}
            other => panic!("expected ItemPruned below boundary at {pos}, got {other:?}"),
        }
    }

    // Within [boundary, size) every position is readable and contains a whole attempted item.
    let mut values = vec![Item::from([0u8; ITEM_SIZE]); size as usize];
    let mut atomic = atomic_bounds_match;
    for pos in boundary..size {
        let item = journal
            .read(pos)
            .await
            .unwrap_or_else(|e| panic!("in-bounds pos {pos} unreadable: {e:?}"));
        atomic &= expected.values.get(pos as usize) == Some(&item);
        values[pos as usize] = item;
    }

    assert!(
        atomic || old_bounds_match,
        "recovered batch bounds matched the committed state, but its contents did not"
    );
    if !atomic {
        for pos in boundary..size {
            let item = &values[pos as usize];
            if pos < expected.durable_len {
                assert_eq!(
                    item, &expected.values[pos as usize],
                    "content mismatch at required pos {pos}"
                );
            } else {
                assert!(
                    expected
                        .allowed_values
                        .get(pos as usize)
                        .is_some_and(|allowed| allowed.contains(item)),
                    "recovered unattempted content at pos {pos}: {item:?}"
                );
            }
        }
    } else {
        for pos in boundary..size {
            assert_eq!(
                values[pos as usize], expected.values[pos as usize],
                "content mismatch at required pos {pos}"
            );
        }
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
        assert_eq!(
            *item, values[*pos as usize],
            "replay/read divergence at {pos}"
        );
    }

    Expected {
        durable_len: size,
        durable_prune: boundary,
        atomic_bounds: None,
        allowed_values: values.iter().cloned().map(|item| vec![item]).collect(),
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

/// Run a cycle's ops under faults, updating `expected`. Stops early on a mutable-method error that
/// may have left the journal inconsistent; the journal is then dropped to crash. Reads and replays
/// never fault, so an unexpected result panics instead of ending the cycle.
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
                    Err(_) => {
                        if !params.writes_fail_before_io() {
                            expected.append_failed(size_before, item);
                        }
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

            JournalOperation::Sync => {
                let journal = match journal.commit().await {
                    Ok(journal) => {
                        expected.committed(journal.size().await);
                        journal
                    }
                    Err(_) => return,
                };
                match journal.sync().await {
                    Ok(journal) => {
                        expected.synced(journal.bounds());
                        journal
                    }
                    Err(_) => return,
                }
            }

            JournalOperation::Commit => match journal.commit().await {
                Ok(journal) => {
                    expected.committed(journal.size().await);
                    journal
                }
                Err(_) => return,
            },

            JournalOperation::Rewind { size } => {
                let bounds = journal.bounds();
                if bounds.is_empty() {
                    journal
                } else {
                    // Exercise real shrinks and no-op rewinds directly; occasionally pass the raw
                    // value to exercise the validation paths.
                    let use_raw_target = *size % 8 == 0;
                    let target = if use_raw_target {
                        *size
                    } else if *size % 2 == 0 {
                        bounds.end
                    } else {
                        bounds.start + (*size % (bounds.end - bounds.start))
                    };
                    match journal.rewind(target).await {
                        Ok(journal) => {
                            if target < bounds.end {
                                expected.shrunk(bounds.start..target);
                            }
                            journal
                        }
                        // Validation errors reject before mutation and are only possible for a raw
                        // target. Other errors can recover either the prior state or the exact
                        // committed rewind batch.
                        Err(e @ (Error::InvalidRewind(_) | Error::ItemPruned(_))) => {
                            assert!(
                                use_raw_target,
                                "rewind to clamped retained target {target} (bounds [{}, {})) \
                                 returned {e:?}",
                                bounds.start, bounds.end
                            );
                            return;
                        }
                        Err(_) => {
                            if !params.batches_fail_before_commit() {
                                expected.atomic_bounds = Some(bounds.start..target.min(bounds.end));
                            }
                            return;
                        }
                    }
                }
            }

            JournalOperation::Prune { min_pos } => {
                // Raw position: `prune` caps it to size internally, covering prune-past-size.
                let size = journal.size().await;
                match journal.prune(*min_pos).await {
                    Ok((journal, pruned)) => {
                        if pruned {
                            expected.synced(journal.bounds());
                        }
                        journal
                    }
                    Err(_) => {
                        let capped = (*min_pos).min(size);
                        let section_floor =
                            capped / params.items_per_section * params.items_per_section;
                        if !params.batches_fail_before_commit() {
                            expected.atomic_bounds = Some(section_floor..size);
                        }
                        return;
                    }
                }
            }

            JournalOperation::Replay { buffer, start_pos } => {
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

                match journal.replay(*start_pos, NZUsize!(*buffer)).await {
                    Ok(items) if *start_pos >= bounds.start && *start_pos <= bounds.end => {
                        assert_replay_suffix(&items, *start_pos, &bounds);
                        for (pos, item) in &items {
                            let via_read = journal.read(*pos).await.unwrap_or_else(|e| {
                                panic!("read({pos}) cross-check during raw replay: {e:?}")
                            });
                            assert_eq!(*item, via_read, "raw replay/read divergence at {pos}");
                        }
                    }
                    Err(Error::ItemPruned(_)) if *start_pos < bounds.start => {}
                    Err(Error::ItemOutOfRange(_)) if *start_pos > bounds.end => {}
                    result => panic!(
                        "raw replay at {start_pos} (bounds [{}, {})) returned {result:?}",
                        bounds.start, bounds.end
                    ),
                }
                journal
            }

            // `split_cycles` strips `Crash`; a stray one defensively ends the cycle.
            JournalOperation::Crash => return,
        };
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
        let journal = J::init(ctx.child("journal"), cfg)
            .await
            .expect("recovery should succeed without panic");
        let mut expected = assert_matches_expected(&journal, &expected).await;

        // Faults on for the operation phase; returning drops the journal (the crash).
        *ctx.storage_fault_config().write() = params.fault_config();
        run_ops(journal, &mut expected, &ops, params).await;
        expected
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
        batch_rate: input.batch_failure_rate,
        batch_post_commit_rate: input.batch_post_commit_rate,
        compression: input.compression,
    };
    let partition = format!("crash-recovery-{tag}");
    let cycles = split_cycles(input.operations.iter().cloned(), |op| {
        matches!(op, JournalOperation::Crash)
    });

    // First cycle starts from a fresh runtime and recovers an empty journal, so the expectation is
    // empty too.
    let runner = fuzz_runner(&input.raw_bytes);
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

    // Final fault-free phase: verify the last recovery, then append and sync a sentinel.
    let sentinel_partition = partition.clone();
    let ((expected, pos, sentinel), checkpoint) = deterministic::Runner::from(checkpoint)
        .start_and_recover(move |ctx| async move {
            *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();
            let journal = J::init(
                ctx.child("journal_final"),
                J::config(&sentinel_partition, &ctx, &params),
            )
            .await
            .expect("final recovery should succeed");
            // Verify recovery and retain its exact snapshot without replaying the full journal a
            // second time.
            let mut expected = assert_matches_expected(&journal, &expected).await;

            // Append a sentinel and sync it, pinning the exact durable state.
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
            (expected, pos, sentinel)
        });

    // Cross another crash boundary, confirm the synced sentinel, and clean up once.
    deterministic::Runner::from(checkpoint).start(move |ctx| async move {
        *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();
        let journal = J::init(
            ctx.child("journal_final_verify"),
            J::config(&partition, &ctx, &params),
        )
        .await
        .expect("final reopen should succeed");
        let _ = assert_matches_expected(&journal, &expected).await;
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
