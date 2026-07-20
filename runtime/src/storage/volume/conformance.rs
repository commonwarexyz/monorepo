//! Trace conformance: the exhaustive `model` as an oracle over the REAL
//! volume implementation.
//!
//! The model proves the commit PROTOCOL. This module checks that the
//! implementation REFINES it (the middle layer of the trust story in the
//! model docs). Every workload here executes real volume operations in
//! lockstep with the model's transition function:
//!
//! - EXECUTOR: each [`Op`] maps to real API calls (a model cell is half a
//!   [`BLOCK`], filled with a unique repeating token per write) and to a
//!   model action sequence. Operations the implementation fuses — `remove`
//!   and creation commit internally — map to composite sequences
//!   (`[Remove, Snapshot, WriteMeta, FsyncOk]`).
//! - CRASHES: at every point of interest the harness materializes power
//!   loss at the model's granularity — each pending inner write resolves
//!   per block to any queued version, the durable content, or a torn
//!   block — and re-opens the real volume over each outcome. Crash points
//!   inside a commit are pinned by parking its driver task at the inner fsync
//!   (all metadata writes issued, nothing durable), which covers both of
//!   the model's in-flight phases: the disk state after `Snapshot` alone
//!   is a subset of the `MetaWritten` outcomes (every metadata block
//!   resolving to "vanished").
//! - EXTRACTOR: the recovered volume is read back through the public API
//!   (scan, open, full reads) and decoded to a model observable — per
//!   slot: absent, or the sequence of cell tokens. The observable must
//!   equal one the model allows for exactly that history (the crash fan
//!   of the lockstep state), translated through the per-state map from
//!   model cell values to written tokens. Cell tokens are globally unique
//!   (they never repeat across a replayed history), so any resurrection
//!   of stale bytes that the model would excuse as replay-identical is
//!   caught here rather than masked.
//!
//! Nondeterminism delta against the model, stated precisely: the model
//! resolves fsyncgate residue (`FsyncFail`) into per-block
//! kept/landed/lost cache states. The harness collapses that step because
//! the union of crash outcomes over every residue state equals the crash
//! outcomes of the pre-fail state (kept and lost both resolve to
//! {durable, any version, torn} minus nothing), and the implementation's
//! poison latch makes residue unobservable except through a crash. The
//! latch itself is asserted directly (every post-fail operation errors).
//! Where a crash point's outcome product exceeds the enumeration cap, the
//! harness checks every single-block deviation from the all-landed and
//! all-vanished corners plus seeded random samples — the exhaustive
//! product is used whenever it fits (stated per workload in the stats).
//!
//! CANCELLATION INJECTION (the third layer): sync, start-sync, remove,
//! batch-apply, and apply-start-sync futures are dropped after every
//! possible poll count (a pass-through storage wrapper turns each inner
//! I/O into a poll boundary). Callers are pure observers of driver-task
//! commits, so every drop point must be BENIGN: the operation completes
//! regardless, nothing poisons, and the recovered state stays trace
//! conformant. The driver-abort arm of the contract (poison on a task
//! dropped mid-commit) is pinned by
//! `tests::test_volume_aborted_commit_task_poisons`.

use super::{
    model::{
        initial_state, step, Action, Cell, Logical, State as ModelState, Violation, BLOBS,
        CELLS_PER_BLOCK, SPEC,
    },
    state::Ready,
    tests::{audit_volume, test_driver, test_pool, Gated, Tearing},
    Batch, Blob as VBlob, Config, Storage as Volume, BLOCK,
};
use crate::{Blob as _, BufferPool, Error, IoBuf, IoBufs, IoBufsMut, Storage as _};
use commonware_utils::TestRng;
use futures::FutureExt as _;
use rand::RngExt as _;
use std::{
    collections::{BTreeMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

/// Bytes per model cell (the model packs two cells per block).
const CELL: u64 = BLOCK / CELLS_PER_BLOCK as u64;

/// Partition holding the workload blobs.
const PARTITION: &str = "p";

/// Blob name for a model slot.
fn name(slot: u8) -> Vec<u8> {
    vec![b'a' + slot]
}

/// The cell content written for token `ctr`: the token's bytes repeated
/// across the whole cell (never all-zero; `ctr` starts at 1).
fn pattern(ctr: u64) -> Vec<u8> {
    let tok = ctr.to_be_bytes();
    let mut out = vec![0u8; CELL as usize];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&tok);
    }
    out
}

/// What one recovered cell reads back as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum CellObs {
    Zero,
    Token(u64),
    /// Neither zeros nor a uniform token: never legal in committed space.
    Garbage,
}

/// A recovered volume's observable state: per slot, absent or (pruned
/// floor in cells, the cell sequence at and above it).
type Obs = Vec<Option<(u8, Vec<CellObs>)>>;

/// Decode a blob's content into cells.
fn decode_cells(bytes: &[u8]) -> Vec<CellObs> {
    bytes
        .chunks(CELL as usize)
        .map(|cell| {
            if cell.len() != CELL as usize {
                return CellObs::Garbage;
            }
            if cell.iter().all(|&b| b == 0) {
                return CellObs::Zero;
            }
            let tok = u64::from_be_bytes(cell[..8].try_into().expect("cell holds a token"));
            if tok != 0 && cell.chunks(8).all(|c| c == tok.to_be_bytes()) {
                CellObs::Token(tok)
            } else {
                CellObs::Garbage
            }
        })
        .collect()
}

/// One lockstep correspondence: a model state plus the map from its cell
/// values to the tokens the harness actually wrote for them.
#[derive(Clone)]
struct Tracked {
    state: ModelState,
    translate: BTreeMap<Cell, u64>,
}

/// The value the model will generate for the next write of `cell` on
/// `slot` (mirrors the model's `next_val` without stepping).
fn peek_val(state: &ModelState, slot: u8, cell: u8) -> Cell {
    let b = &state.volume.blobs[slot as usize];
    Cell::Val {
        slot,
        gen: b.gen,
        cell,
        ver: b.vers.get(&cell).copied().unwrap_or(0) + 1,
    }
}

/// Render a model violation with its trace.
fn render(v: &Violation) -> String {
    let mut out = format!("model violation: {}\n  model trace:\n", v.reason);
    for (i, a) in v.trace.iter().enumerate() {
        out.push_str(&format!("    {i}: {a:?}\n"));
    }
    out
}

/// Translate a model logical view through a tracked state's token map.
fn translated(t: &Tracked, logical: &Logical) -> Obs {
    logical
        .blobs
        .iter()
        .map(|blob| {
            blob.as_ref().map(|(_gen, floor, cells)| {
                (
                    *floor,
                    cells
                        .iter()
                        .map(|cell| match cell {
                            Cell::Zero => CellObs::Zero,
                            Cell::Val { .. } => CellObs::Token(
                                *t.translate
                                    .get(cell)
                                    .unwrap_or_else(|| panic!("untranslated model value {cell:?}")),
                            ),
                            Cell::Garbage => panic!("model logical exposes garbage"),
                        })
                        .collect(),
                )
            })
        })
        .collect()
}

/// Step `tracked` through `actions`, returning every reachable state with
/// its parent index. Non-final actions must be deterministic. The final
/// action may fan out (a crash).
fn states_after(
    tracked: &[Tracked],
    actions: &[Action],
    trace: &[Action],
) -> Vec<(usize, ModelState)> {
    let mut out = Vec::new();
    let mut full = trace.to_vec();
    full.extend_from_slice(actions);
    for (parent, t) in tracked.iter().enumerate() {
        let mut states = vec![t.state.clone()];
        for action in actions {
            let mut next = Vec::new();
            for s in &states {
                let successors = step(s, *action, &SPEC, &full)
                    .unwrap_or_else(|v| panic!("{}", render(&v)))
                    .unwrap_or_else(|| panic!("model action {action:?} disabled mid-sequence"));
                next.extend(successors);
            }
            states = next;
        }
        out.extend(states.into_iter().map(|s| (parent, s)));
    }
    out
}

// ---------------------------------------------------------------------------
// Crash-space enumeration
// ---------------------------------------------------------------------------

/// Deterministic garbage for a torn block (never a valid token pattern or
/// checksummed structure).
fn torn_block(block: u64) -> Vec<u8> {
    let mut state = block.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(BLOCK as usize);
    while out.len() < BLOCK as usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_be_bytes());
    }
    out
}

/// The power-loss outcome space of a volume file: durable content plus,
/// per dirtied block, the queue of pending versions. Mirrors the model's
/// `Disk::crash_outcomes` granularity exactly: each dirtied block resolves
/// independently to the durable content, any pending version, or a torn
/// block.
struct CrashSpace {
    durable: Vec<u8>,
    /// (block index, pending versions oldest-first, each a full block).
    blocks: Vec<(u64, Vec<Vec<u8>>)>,
    /// Padded image length (covers every pending write).
    len: usize,
}

/// One materialized outcome.
struct CrashCase {
    desc: String,
    image: Vec<u8>,
}

impl CrashSpace {
    /// Snapshot the outcome space from a tearing wrapper's recorded state.
    fn capture(tearing: &Tearing) -> Self {
        let durable = tearing.durable.lock().clone();
        let writes = tearing.unsynced.lock().clone();
        let mut len = durable.len();
        for (offset, bytes) in &writes {
            len =
                len.max((*offset as usize + bytes.len()).div_ceil(BLOCK as usize) * BLOCK as usize);
        }
        let block_at = |durable: &[u8], block: u64| -> Vec<u8> {
            let start = (block * BLOCK) as usize;
            let mut out = vec![0u8; BLOCK as usize];
            if start < durable.len() {
                let end = (start + BLOCK as usize).min(durable.len());
                out[..end - start].copy_from_slice(&durable[start..end]);
            }
            out
        };
        let mut map: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();
        for (offset, bytes) in &writes {
            let mut cursor = 0usize;
            while cursor < bytes.len() {
                let at = *offset as usize + cursor;
                let block = at as u64 / BLOCK;
                let piece_end = bytes
                    .len()
                    .min(((block + 1) * BLOCK) as usize - *offset as usize);
                let versions = map.entry(block).or_default();
                let mut base = versions
                    .last()
                    .cloned()
                    .unwrap_or_else(|| block_at(&durable, block));
                let rel = at - (block * BLOCK) as usize;
                base[rel..rel + piece_end - cursor].copy_from_slice(&bytes[cursor..piece_end]);
                // Dedupe identical consecutive versions (a rewrite of the
                // same bytes adds no outcome).
                if versions.last() != Some(&base) {
                    versions.push(base);
                }
                cursor = piece_end;
            }
        }
        map.retain(|_, versions| !versions.is_empty());
        Self {
            durable,
            blocks: map.into_iter().collect(),
            len,
        }
    }

    /// Total outcomes (saturating).
    fn count(&self) -> usize {
        let mut total: usize = 1;
        for (_, versions) in &self.blocks {
            total = total.saturating_mul(versions.len() + 2);
        }
        total
    }

    /// Build one outcome. `choices[i]`: 0 = durable, 1..=k = version,
    /// k + 1 = torn.
    fn case(&self, choices: &[usize]) -> CrashCase {
        let mut image = self.durable.clone();
        image.resize(self.len, 0);
        let mut desc = String::new();
        for ((block, versions), &choice) in self.blocks.iter().zip(choices) {
            let at = (*block * BLOCK) as usize;
            let what = if choice == 0 {
                "durable"
            } else if choice <= versions.len() {
                image[at..at + BLOCK as usize].copy_from_slice(&versions[choice - 1]);
                "landed"
            } else {
                image[at..at + BLOCK as usize].copy_from_slice(&torn_block(*block));
                "torn"
            };
            desc.push_str(&format!("b{block}={what}({choice}) "));
        }
        CrashCase { desc, image }
    }

    /// Enumerate outcomes: the exhaustive product when it fits in `cap`,
    /// otherwise the corner set (all-durable, all-newest, and every
    /// single-block deviation from all-newest) plus seeded random samples
    /// up to `cap`.
    fn enumerate(&self, cap: usize, seed: u64) -> (Vec<CrashCase>, bool) {
        let n = self.blocks.len();
        if n == 0 {
            return (vec![self.case(&[])], true);
        }
        let radices: Vec<usize> = self.blocks.iter().map(|(_, v)| v.len() + 2).collect();
        if self.count() <= cap {
            let mut cases = Vec::with_capacity(self.count());
            let mut choices = vec![0usize; n];
            loop {
                cases.push(self.case(&choices));
                let mut i = 0;
                loop {
                    if i == n {
                        return (cases, true);
                    }
                    choices[i] += 1;
                    if choices[i] < radices[i] {
                        break;
                    }
                    choices[i] = 0;
                    i += 1;
                }
            }
        }
        // Corners + samples.
        let mut seen: HashSet<Vec<usize>> = HashSet::new();
        let mut cases = Vec::new();
        let newest: Vec<usize> = self.blocks.iter().map(|(_, v)| v.len()).collect();
        let mut push = |space: &Self, choices: Vec<usize>, cases: &mut Vec<CrashCase>| {
            if seen.insert(choices.clone()) {
                cases.push(space.case(&choices));
            }
        };
        push(self, vec![0; n], &mut cases);
        push(self, newest.clone(), &mut cases);
        for i in 0..n {
            for choice in 0..radices[i] {
                let mut choices = newest.clone();
                choices[i] = choice;
                push(self, choices, &mut cases);
            }
            // The all-vanished neighborhood too: one block resolving while
            // everything else vanished.
            for choice in 0..radices[i] {
                let mut choices = vec![0; n];
                choices[i] = choice;
                push(self, choices, &mut cases);
            }
        }
        let mut rng = TestRng::new(seed);
        while cases.len() < cap {
            let choices: Vec<usize> = radices.iter().map(|&r| rng.random_range(0..r)).collect();
            push(self, choices, &mut cases);
        }
        (cases, false)
    }
}

// ---------------------------------------------------------------------------
// Yielding wrapper (poll boundaries for cancellation injection)
// ---------------------------------------------------------------------------

/// Pending exactly once, then ready.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// While active, yield once before the next inner operation.
async fn pause(active: &Arc<AtomicBool>) {
    if active.load(Ordering::SeqCst) {
        YieldOnce(false).await;
    }
}

/// A pass-through storage wrapper that (while `active`) yields once before
/// every inner operation, turning each inner I/O into a scheduling
/// boundary that discretizes a driver task's progress: dropping an
/// observer future after every poll count (polls interleaved with
/// `yield_now`) samples the drop against each inner-I/O stage — the
/// await-point analogue of crash-at-every-write, and every stage must be
/// benign. Concurrently joined I/O shares one boundary (the commit's
/// metadata writes all yield in one poll of their `try_join_all` and
/// issue in the next), which costs nothing for the checked contracts
/// because the joined writes commute.
#[derive(Clone)]
struct Yielding<S> {
    inner: S,
    active: Arc<AtomicBool>,
}

impl<S: crate::Storage> crate::Storage for Yielding<S> {
    type Blob = YieldingBlob<S::Blob>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        let (blob, len, version) = self.inner.open_versioned(partition, name, versions).await?;
        Ok((
            YieldingBlob {
                inner: blob,
                active: self.active.clone(),
            },
            len,
            version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.inner.scan(partition).await
    }
}

#[derive(Clone)]
struct YieldingBlob<B> {
    inner: B,
    active: Arc<AtomicBool>,
}

impl<B: crate::Blob> crate::Blob for YieldingBlob<B> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        pause(&self.active).await;
        self.inner.read_at(offset, len).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        pause(&self.active).await;
        self.inner.read_at_buf(offset, len, bufs).await
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        pause(&self.active).await;
        self.inner.write_at(offset, bufs).await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.write_at(offset, bufs).await?;
        self.sync().await
    }

    async fn prune(&self, offset: u64) -> Result<(), Error> {
        pause(&self.active).await;
        self.inner.prune(offset).await
    }

    fn floor(&self) -> u64 {
        self.inner.floor()
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        pause(&self.active).await;
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        pause(&self.active).await;
        self.inner.sync().await
    }

    async fn start_sync(&self) -> crate::Handle<()> {
        crate::Handle::ready(self.sync().await)
    }
}

// ---------------------------------------------------------------------------
// The rig: a real volume in lockstep with the model
// ---------------------------------------------------------------------------

type Stack = Yielding<Gated<Tearing>>;

/// Harness operations: the model's action vocabulary at the real API's
/// granularity (commits are fused, `remove`/`open` carry their internal
/// commit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Append(u8),
    Overwrite(u8),
    ResizeDown(u8),
    ResizeUp(u8),
    Remove(u8),
    Recreate(u8),
    /// Advance the slot's pruned floor by one chunk (Blob::prune).
    Prune(u8),
    /// Sync every live blob in the mask as ONE commit (multi-bit masks
    /// register every root, then await every handle: one union commit
    /// resolves them all).
    Sync(u8),
    BatchAppend(u8),
    /// Stage an overwrite of the first cell at or above the pruned floor
    /// (Batch::write_at at the floor offset).
    BatchOverwrite(u8),
    /// Stage a one-cell shrink (Batch::resize below the staged size).
    BatchResizeDown(u8),
    /// Stage a two-cell grow (Batch::resize above the staged size).
    BatchResizeUp(u8),
    BatchCreate(u8),
    /// Join the batch's group without staging content (Batch::sync).
    BatchSync(u8),
    /// Stage the slot's removal (Batch::remove), committed in-step at
    /// apply.
    BatchRemove(u8),
    BatchApply,
    BatchDrop,
}

struct BatchRig {
    batch: Batch<Stack>,
    /// Handles returned by staged creations, published at apply.
    created: BTreeMap<u8, VBlob<Stack>>,
}

/// Coverage counters for a workload run.
#[derive(Default, Debug)]
struct Stats {
    nodes: usize,
    crash_points: usize,
    cases: usize,
    /// Crash points whose full outcome product fit under the cap.
    exhaustive_points: usize,
}

struct Rig {
    pool: BufferPool,
    tearing: Tearing,
    gated: Gated<Tearing>,
    yields: Arc<AtomicBool>,
    volume: Volume<Stack>,
    blobs: BTreeMap<u8, VBlob<Stack>>,
    batch: Option<BatchRig>,
    tracked: Vec<Tracked>,
    trace: Vec<Action>,
    ops: Vec<Op>,
    next_ctr: u64,
    /// A parked (gated) commit is outstanding: bookkeeping audits skip the
    /// quiesced-only exactness checks.
    in_flight: bool,
}

impl Rig {
    async fn new() -> Self {
        let pool = test_pool();
        let tearing = Tearing::new(pool.clone());
        let gated = Gated::new(tearing.clone());
        let yields = Arc::new(AtomicBool::new(false));
        let stack = Yielding {
            inner: gated.clone(),
            active: yields.clone(),
        };
        let volume = Volume::new(stack, pool.clone(), Config::default(), test_driver());
        let mut blobs = BTreeMap::new();
        for slot in 0..BLOBS {
            let (blob, size) = volume.open(PARTITION, &name(slot)).await.expect("create");
            assert_eq!(size, 0, "fresh blob");
            blobs.insert(slot, blob);
        }
        Self {
            pool,
            tearing,
            gated,
            yields,
            volume,
            blobs,
            batch: None,
            // Budgets sized for every workload here (the model decrements
            // per action).
            tracked: vec![Tracked {
                state: initial_state(120, 6),
                translate: BTreeMap::new(),
            }],
            trace: Vec::new(),
            ops: Vec::new(),
            next_ctr: 0,
            in_flight: false,
        }
    }

    /// Reopen a rig over a crashed image, resuming the lockstep with the
    /// already-filtered tracked states (deep mode).
    async fn resume(
        pool: BufferPool,
        image: Vec<u8>,
        tracked: Vec<Tracked>,
        next_ctr: u64,
        ops: Vec<Op>,
        trace: Vec<Action>,
    ) -> Self {
        let tearing = Tearing::from_image(pool.clone(), image).await;
        let gated = Gated::new(tearing.clone());
        let yields = Arc::new(AtomicBool::new(false));
        let stack = Yielding {
            inner: gated.clone(),
            active: yields.clone(),
        };
        let volume = Volume::new(stack, pool.clone(), Config::default(), test_driver());
        let mut blobs = BTreeMap::new();
        for slot in 0..BLOBS {
            if tracked[0].state.volume.blobs[slot as usize].live {
                let (blob, _) = volume.open(PARTITION, &name(slot)).await.expect("reopen");
                blobs.insert(slot, blob);
            }
        }
        Self {
            pool,
            tearing,
            gated,
            yields,
            volume,
            blobs,
            batch: None,
            tracked,
            trace,
            ops,
            next_ctr,
            in_flight: false,
        }
    }

    fn ctx(&self) -> String {
        format!("ops {:?}", self.ops)
    }

    fn size_cells(&self, slot: u8) -> u8 {
        self.tracked[0].state.volume.blobs[slot as usize].size
    }

    fn live(&self, slot: u8) -> bool {
        self.tracked[0].state.volume.blobs[slot as usize].live
    }

    /// The model's live floor in cells (identical across tracked states:
    /// actions move it deterministically and crash resumes filter on an
    /// observable that includes it).
    fn floor_cells(&self, slot: u8) -> u8 {
        self.tracked[0].state.volume.blobs[slot as usize].floor
    }

    /// The staged size the next batch write on `slot` appends at (the
    /// model's staged overlay, falling back to the published size).
    fn staged_cells(&self, slot: u8) -> u8 {
        self.tracked[0]
            .state
            .volume
            .batch
            .as_ref()
            .and_then(|batch| batch.slots.get(&slot))
            .filter(|staged| !staged.member)
            .map_or(self.size_cells(slot), |staged| staged.size)
    }

    /// The model action sequence for `op` in the CURRENT state (batch
    /// apply depends on what is staged).
    fn model_actions(&self, op: Op) -> Vec<Action> {
        match op {
            Op::Append(s) => vec![Action::Append(s)],
            Op::Overwrite(s) => vec![Action::Overwrite(s)],
            Op::ResizeDown(s) => vec![Action::ResizeDown(s)],
            Op::ResizeUp(s) => vec![Action::ResizeUp(s)],
            Op::Prune(s) => vec![Action::Prune(s)],
            Op::Remove(s) => vec![
                Action::Remove(s),
                Action::Snapshot(1 << s),
                Action::WriteMeta,
                Action::FsyncOk,
            ],
            Op::Recreate(s) => vec![
                Action::Recreate(s),
                Action::Snapshot(1 << s),
                Action::WriteMeta,
                Action::FsyncOk,
            ],
            Op::Sync(mask) => vec![Action::Snapshot(mask), Action::WriteMeta, Action::FsyncOk],
            Op::BatchAppend(s) => vec![Action::BatchAppend(s)],
            Op::BatchOverwrite(s) => vec![Action::BatchOverwrite(s)],
            Op::BatchResizeDown(s) => vec![Action::BatchResizeDown(s)],
            Op::BatchResizeUp(s) => vec![Action::BatchResizeUp(s)],
            Op::BatchCreate(s) => vec![Action::BatchCreate(s)],
            Op::BatchSync(s) => vec![Action::BatchSync(s)],
            Op::BatchRemove(s) => vec![Action::BatchRemove(s)],
            Op::BatchApply => {
                let (has_creation, creation_only, has_removal) =
                    self.tracked[0].state.volume.batch.as_ref().map_or(
                        (false, false, false),
                        |batch| {
                            (
                                batch.slots.values().any(|staged| staged.created),
                                !batch.slots.is_empty()
                                    && batch.slots.values().all(|staged| staged.created),
                                !batch.removals.is_empty(),
                            )
                        },
                    );
                if has_removal || (has_creation && !creation_only) {
                    // The implementation requires apply_sync here: publish
                    // and the group's commit under one commit-lock hold.
                    vec![Action::BatchApply, Action::WriteMeta, Action::FsyncOk]
                } else {
                    vec![Action::BatchApply]
                }
            }
            Op::BatchDrop => vec![Action::BatchDrop],
        }
    }

    /// Whether `op` is enabled: the model's transition relation is the
    /// authority, and every tracked state must agree.
    fn enabled(&self, op: Op) -> bool {
        let actions = self.model_actions(op);
        let mut verdict: Option<bool> = None;
        for t in &self.tracked {
            let mut states = vec![t.state.clone()];
            let mut ok = true;
            'seq: for action in &actions {
                let mut next = Vec::new();
                for s in &states {
                    match step(s, *action, &SPEC, &self.trace) {
                        Ok(Some(successors)) => next.extend(successors),
                        Ok(None) => {
                            ok = false;
                            break 'seq;
                        }
                        Err(v) => panic!("{}: {}", self.ctx(), render(&v)),
                    }
                }
                states = next;
            }
            match verdict {
                None => verdict = Some(ok),
                Some(prev) => assert_eq!(
                    prev,
                    ok,
                    "{}: tracked states disagree on enabledness of {op:?}",
                    self.ctx()
                ),
            }
        }
        verdict.unwrap_or(false)
    }

    /// The (slot, cell) a value-writing op targets, if any.
    fn value_target(&self, op: Op) -> Option<(u8, u8)> {
        match op {
            Op::Append(s) => Some((s, self.size_cells(s))),
            Op::Overwrite(s) => Some((s, 0)),
            Op::BatchAppend(s) => Some((s, self.staged_cells(s))),
            Op::BatchOverwrite(s) => Some((s, self.floor_cells(s))),
            _ => None,
        }
    }

    /// Step every tracked state through `actions`, recording `val ->
    /// token` translations. Deduplicates identical correspondences.
    fn step_tracked(&mut self, actions: &[Action], vals: Vec<Option<(Cell, u64)>>) {
        let mut full = self.trace.clone();
        full.extend_from_slice(actions);
        let mut next: Vec<Tracked> = Vec::new();
        let mut seen: HashSet<(ModelState, Vec<(Cell, u64)>)> = HashSet::new();
        for (t, val) in self.tracked.iter().zip(vals) {
            let mut states = vec![t.state.clone()];
            for action in actions {
                let mut successors = Vec::new();
                for s in &states {
                    successors.extend(
                        step(s, *action, &SPEC, &full)
                            .unwrap_or_else(|v| panic!("{}: {}", self.ctx(), render(&v)))
                            .unwrap_or_else(|| {
                                panic!("{}: model action {action:?} disabled", self.ctx())
                            }),
                    );
                }
                states = successors;
            }
            let mut translate = t.translate.clone();
            if let Some((cell, ctr)) = val {
                translate.insert(cell, ctr);
            }
            for s in states {
                let key = (
                    s.clone(),
                    translate.iter().map(|(c, v)| (*c, *v)).collect::<Vec<_>>(),
                );
                if seen.insert(key) {
                    next.push(Tracked {
                        state: s,
                        translate: translate.clone(),
                    });
                }
            }
        }
        assert!(
            !next.is_empty(),
            "{}: lockstep lost every state",
            self.ctx()
        );
        self.tracked = next;
        self.trace = full;
    }

    /// Step the model only (the real side already moved through other
    /// means, e.g. a parked commit's snapshot).
    fn step_model_only(&mut self, actions: &[Action]) {
        let vals = vec![None; self.tracked.len()];
        self.step_tracked(actions, vals);
    }

    /// Execute one op against the real volume and the model, then run the
    /// always-on checks.
    async fn execute(&mut self, op: Op) {
        assert!(self.enabled(op), "{}: op {op:?} not enabled", self.ctx());
        let actions = self.model_actions(op);
        let target = self.value_target(op);
        let ctr = target.map(|_| {
            self.next_ctr += 1;
            self.next_ctr
        });
        let vals: Vec<Option<(Cell, u64)>> = self
            .tracked
            .iter()
            .map(|t| target.map(|(s, c)| (peek_val(&t.state, s, c), ctr.expect("token allocated"))))
            .collect();

        self.run_real(op, ctr).await;
        self.step_tracked(&actions, vals);
        self.ops.push(op);

        audit_volume(&self.volume, !self.in_flight && self.batch.is_none());
        self.check_live().await;
    }

    /// Drive the real API for `op`.
    async fn run_real(&mut self, op: Op, ctr: Option<u64>) {
        match op {
            Op::Append(s) => {
                let offset = self.size_cells(s) as u64 * CELL;
                let data = pattern(ctr.expect("append writes a value"));
                self.blobs[&s]
                    .write_at(offset, IoBuf::copy_from_slice(&data))
                    .await
                    .unwrap_or_else(|e| panic!("{}: append: {e}", self.ctx()));
            }
            Op::Overwrite(s) => {
                let data = pattern(ctr.expect("overwrite writes a value"));
                self.blobs[&s]
                    .write_at(0, IoBuf::copy_from_slice(&data))
                    .await
                    .unwrap_or_else(|e| panic!("{}: overwrite: {e}", self.ctx()));
            }
            Op::ResizeDown(s) => {
                let len = (self.size_cells(s) as u64 - 1) * CELL;
                self.blobs[&s]
                    .resize(len)
                    .await
                    .unwrap_or_else(|e| panic!("{}: resize down: {e}", self.ctx()));
            }
            Op::ResizeUp(s) => {
                let len = (self.size_cells(s) as u64 + 2) * CELL;
                self.blobs[&s]
                    .resize(len)
                    .await
                    .unwrap_or_else(|e| panic!("{}: resize up: {e}", self.ctx()));
            }
            Op::Prune(s) => {
                // One model block per prune: the byte offset of the next
                // chunk boundary above the current floor.
                let offset = (self.floor_cells(s) + CELLS_PER_BLOCK) as u64 * CELL;
                self.blobs[&s]
                    .prune(offset)
                    .await
                    .unwrap_or_else(|e| panic!("{}: prune: {e}", self.ctx()));
            }
            Op::Remove(s) => {
                self.blobs.remove(&s);
                self.volume
                    .remove(PARTITION, Some(&name(s)))
                    .await
                    .unwrap_or_else(|e| panic!("{}: remove: {e}", self.ctx()));
            }
            Op::Recreate(s) => {
                let (blob, size) = self
                    .volume
                    .open(PARTITION, &name(s))
                    .await
                    .unwrap_or_else(|e| panic!("{}: recreate: {e}", self.ctx()));
                assert_eq!(size, 0, "{}: recreated blob not empty", self.ctx());
                self.blobs.insert(s, blob);
            }
            Op::Sync(mask) => {
                let slots: Vec<u8> = (0..BLOBS)
                    .filter(|&s| mask & (1 << s) != 0 && self.live(s))
                    .collect();
                if let [slot] = slots[..] {
                    self.blobs[&slot]
                        .sync()
                        .await
                        .unwrap_or_else(|e| panic!("{}: sync: {e}", self.ctx()));
                } else {
                    // Register every root — each registration schedules a
                    // driver task — then await every handle: whichever
                    // driver task leads drains the pool and commits the
                    // union, resolving them all.
                    let mut handles = Vec::new();
                    for slot in slots {
                        handles.push(self.blobs[&slot].start_sync().await);
                    }
                    for handle in handles {
                        handle
                            .await
                            .unwrap_or_else(|e| panic!("{}: pooled sync: {e}", self.ctx()));
                    }
                }
            }
            Op::BatchAppend(s) | Op::BatchOverwrite(s) => {
                let offset = match op {
                    Op::BatchAppend(_) => self.staged_cells(s) as u64 * CELL,
                    // The first writable cell: the pruned floor.
                    _ => self.floor_cells(s) as u64 * CELL,
                };
                let data = pattern(ctr.expect("batch write carries a value"));
                let blob = self.blobs[&s].clone();
                let rig = self.batch_mut().await;
                rig.batch
                    .write_at(&blob, offset, IoBuf::copy_from_slice(&data))
                    .await
                    .unwrap_or_else(|e| panic!("batch write: {e}"));
            }
            Op::BatchResizeDown(s) | Op::BatchResizeUp(s) => {
                let len = match op {
                    Op::BatchResizeDown(_) => (self.staged_cells(s) as u64 - 1) * CELL,
                    _ => (self.staged_cells(s) as u64 + 2) * CELL,
                };
                let blob = self.blobs[&s].clone();
                let rig = self.batch_mut().await;
                rig.batch
                    .resize(&blob, len)
                    .await
                    .unwrap_or_else(|e| panic!("batch resize: {e}"));
            }
            Op::BatchCreate(s) => {
                let rig = self.batch_mut().await;
                let blob = rig
                    .batch
                    .create(PARTITION, &name(s))
                    .unwrap_or_else(|e| panic!("batch create: {e}"));
                rig.created.insert(s, blob);
            }
            Op::BatchSync(s) => {
                let blob = self.blobs[&s].clone();
                let rig = self.batch_mut().await;
                rig.batch.sync(&blob);
            }
            Op::BatchRemove(s) => {
                let target = name(s);
                let rig = self.batch_mut().await;
                rig.batch.remove(PARTITION, Some(&target));
            }
            Op::BatchApply => {
                let rig = self.batch.take().expect("apply without a batch");
                let (has_creation, creation_only, removals) = {
                    let batch = self.tracked[0].state.volume.batch.as_ref();
                    batch.map_or((false, false, Vec::new()), |batch| {
                        (
                            batch.slots.values().any(|staged| staged.created),
                            !batch.slots.is_empty()
                                && batch.slots.values().all(|staged| staged.created),
                            batch.removals.iter().copied().collect(),
                        )
                    })
                };
                if !removals.is_empty() || (has_creation && !creation_only) {
                    rig.batch
                        .apply_sync()
                        .await
                        .unwrap_or_else(|e| panic!("{}: apply_sync: {e}", self.ctx()));
                } else {
                    rig.batch
                        .apply()
                        .await
                        .unwrap_or_else(|e| panic!("{}: apply: {e}", self.ctx()));
                }
                // Removed slots drop their handles. A same-slot recreation
                // re-inserts the created handle below.
                for slot in removals {
                    self.blobs.remove(&slot);
                }
                self.blobs.extend(rig.created);
            }
            Op::BatchDrop => {
                drop(self.batch.take().expect("drop without a batch"));
            }
        }
    }

    /// The live real batch, started on first use (mirrors the model's
    /// `get_or_insert`).
    async fn batch_mut(&mut self) -> &mut BatchRig {
        if self.batch.is_none() {
            let batch = self.volume.batch().await.expect("start batch");
            self.batch = Some(BatchRig {
                batch,
                created: BTreeMap::new(),
            });
        }
        self.batch.as_mut().expect("just created")
    }

    /// Read every live blob through the public API and compare against
    /// every tracked state's translated logical view, including the
    /// pruned floor: `Blob::floor` must match the model's live floor,
    /// and a read below it must be rejected exactly when the model
    /// treats those cells as unreadable.
    async fn check_live(&self) {
        for slot in 0..BLOBS {
            if !self.live(slot) {
                assert!(
                    !self.blobs.contains_key(&slot),
                    "{}: handle for dead slot {slot}",
                    self.ctx()
                );
                continue;
            }
            let floor = self.blobs[&slot].floor();
            for t in &self.tracked {
                assert_eq!(
                    floor,
                    t.state.volume.blobs[slot as usize].floor as u64 * CELL,
                    "{}: floor of slot {slot} diverged from the model",
                    self.ctx()
                );
            }
            if floor > 0 {
                assert!(
                    matches!(
                        self.blobs[&slot].read_at(0, 1).await,
                        Err(Error::OffsetPruned(..))
                    ),
                    "{}: read below the floor of slot {slot} must be rejected",
                    self.ctx()
                );
            }
            let size = self.size_cells(slot) as u64 * CELL;
            let cells = if size == floor {
                Vec::new()
            } else {
                let bytes = self.blobs[&slot]
                    .read_at(floor, (size - floor) as usize)
                    .await
                    .unwrap_or_else(|e| panic!("{}: live read slot {slot}: {e}", self.ctx()))
                    .coalesce();
                decode_cells(bytes.as_ref())
            };
            let obs = ((floor / CELL) as u8, cells);
            for t in &self.tracked {
                let logical = t.state.volume.logical();
                let expected = translated(t, &logical);
                assert_eq!(
                    Some(&obs),
                    expected[slot as usize].as_ref(),
                    "{}: live content of slot {slot} diverged from the model",
                    self.ctx()
                );
            }
        }
    }

    /// Crash the volume after (model-side) `extra` actions and check every
    /// materialized outcome against the model's allowed states.
    async fn crash_probe(&self, extra: &[Action], cap: usize, seed: u64, stats: &mut Stats) {
        let space = CrashSpace::capture(&self.tearing);
        let mut actions = extra.to_vec();
        actions.push(Action::Crash);
        let allowed = states_after(&self.tracked, &actions, &self.trace);
        let allowed_obs: Vec<Obs> = {
            let mut set = Vec::new();
            for (parent, state) in &allowed {
                let obs = translated(&self.tracked[*parent], &state.volume.logical());
                if !set.contains(&obs) {
                    set.push(obs);
                }
            }
            set
        };
        let (cases, exhaustive) = space.enumerate(cap, seed);
        stats.crash_points += 1;
        if exhaustive {
            stats.exhaustive_points += 1;
        }
        for case in cases {
            stats.cases += 1;
            let ctx = format!(
                "{}; model extra {extra:?}; crash case: {}",
                self.ctx(),
                case.desc
            );
            let pool = self.pool.clone();
            let checked = std::panic::AssertUnwindSafe(async {
                let obs = extract(&pool, case.image.clone())
                    .await
                    .unwrap_or_else(|e| {
                        panic!("recovery/read failed on a pure-crash history: {e}")
                    });
                assert!(
                    allowed_obs.contains(&obs),
                    "recovered state is not allowed by the model\n  \
                     recovered: {obs:?}\n  allowed ({}): {allowed_obs:?}",
                    allowed_obs.len()
                );
            })
            .catch_unwind()
            .await;
            if let Err(payload) = checked {
                let msg = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "non-string panic".into());
                panic!("trace conformance failure\n  at: {ctx}\n  {msg}");
            }
        }
    }
}

/// Reopen a crashed image, extract its observable state through the public
/// API, and run the strict bookkeeping audit on the recovered state.
async fn extract(pool: &BufferPool, image: Vec<u8>) -> Result<Obs, String> {
    let tearing = Tearing::from_image(pool.clone(), image).await;
    let gated = Gated::new(tearing.clone());
    let yields = Arc::new(AtomicBool::new(false));
    let stack = Yielding {
        inner: gated,
        active: yields,
    };
    let volume = Volume::new(stack, pool.clone(), Config::default(), test_driver());
    let names = match volume.scan(PARTITION).await {
        Ok(names) => names,
        Err(Error::PartitionMissing(_)) => Vec::new(),
        Err(e) => return Err(format!("scan: {e}")),
    };
    let mut obs: Obs = Vec::new();
    let mut blobs = Vec::new();
    for slot in 0..BLOBS {
        if !names.contains(&name(slot)) {
            obs.push(None);
            continue;
        }
        let (blob, size) = volume
            .open(PARTITION, &name(slot))
            .await
            .map_err(|e| format!("open slot {slot}: {e}"))?;
        if !size.is_multiple_of(CELL) {
            return Err(format!("slot {slot}: size {size} is not cell-aligned"));
        }
        // The recovered floor is part of the observable: it must be the
        // adopted commit's, chunk-aligned, and enforced on reads.
        let floor = blob.floor();
        if !floor.is_multiple_of(BLOCK) {
            return Err(format!("slot {slot}: floor {floor} is not chunk-aligned"));
        }
        if floor > size {
            return Err(format!("slot {slot}: floor {floor} beyond size {size}"));
        }
        if floor > 0 {
            match blob.read_at(floor - 1, 1).await {
                Err(Error::OffsetPruned(..)) => {}
                Err(e) => {
                    return Err(format!("slot {slot}: below-floor read: wrong error {e}"));
                }
                Ok(_) => {
                    return Err(format!("slot {slot}: below-floor read served pruned bytes"));
                }
            }
        }
        let cells = if size == floor {
            Vec::new()
        } else {
            let bytes = blob
                .read_at(floor, (size - floor) as usize)
                .await
                .map_err(|e| format!("read slot {slot}: {e}"))?
                .coalesce();
            decode_cells(bytes.as_ref())
        };
        obs.push(Some(((floor / CELL) as u8, cells)));
        blobs.push(blob);
    }
    // The freshly recovered state is quiesced: bookkeeping must be exact.
    audit_volume(&volume, true);
    Ok(obs)
}

/// Surface-parity tripwire: the exhaustive match forces this ledger to be
/// revisited whenever the harness op vocabulary grows, and the ledger
/// names the volume APIs each op drives. The public durability surface
/// with NO op of its own, and the pin that stands in for each:
///
/// - `Blob::write_at_sync`: `write_at` + `sync` composition (both mapped).
/// - `Blob::floor`: a read accessor with no op of its own — compared
///   against the model's live floor at every lockstep node and against
///   the adopted commit's at every crash extraction, alongside the
///   below-floor read rejection (below-floor writes and resizes are
///   never enumerated, and their rejection is pinned by
///   `tests::test_volume_prune_end_to_end`).
/// - `Batch::apply_start_sync`: `apply`'s publish plus `start_sync`'s
///   registered commit, with the cancellation injector driving the
///   composite.
///
/// Extending the volume's public semantics requires extending the op
/// vocabulary (and a workload reaching it) or adding a line above with
/// its stand-in pin — a silent gap is what the 2026-07 review found five
/// of six bugs hiding in.
#[test]
fn conformance_surface_parity() {
    fn drives(op: Op) -> &'static str {
        match op {
            Op::Append(_) | Op::Overwrite(_) => "Blob::write_at",
            Op::ResizeDown(_) | Op::ResizeUp(_) => "Blob::resize",
            Op::Prune(_) => "Blob::prune",
            Op::Sync(_) => "Blob::sync / Blob::start_sync (pooled union)",
            Op::Remove(_) => "Storage::remove",
            Op::Recreate(_) => "Storage::open (creation commit)",
            Op::BatchAppend(_) | Op::BatchOverwrite(_) => "Batch::write_at",
            Op::BatchResizeDown(_) | Op::BatchResizeUp(_) => "Batch::resize",
            Op::BatchSync(_) => "Batch::sync",
            Op::BatchRemove(_) => "Batch::remove",
            Op::BatchCreate(_) => "Batch::create",
            Op::BatchApply => "Batch::apply / Batch::apply_sync",
            Op::BatchDrop => "drop(Batch)",
        }
    }
    let _ = drives(Op::BatchApply);
}

// ---------------------------------------------------------------------------
// Workload exploration
// ---------------------------------------------------------------------------

/// A bounded-exhaustive workload: DFS over every enabled op sequence up to
/// `depth`, with crash probes at every node and commit-window/fsync-fail
/// probes at shallow nodes.
struct Workload {
    menu: &'static [Op],
    depth: usize,
    /// Commit-window probes: park a sync of each mask at the inner fsync,
    /// interleave up to `window_depth` ops from `window_menu`, then either
    /// crash mid-commit or confirm and crash.
    window_masks: &'static [u8],
    window_menu: &'static [Op],
    window_depth: usize,
    window_max_prefix: usize,
    /// Fsync-failure probes (the poison latch) at prefixes up to this
    /// length (0 = disabled). Probes sync of slot 0.
    fail_max_prefix: usize,
    /// Outcome cap per crash point (exhaustive product when it fits).
    cap: usize,
}

/// All op sequences over `menu` of length 0..=`max`.
fn sequences(menu: &[Op], max: usize) -> Vec<Vec<Op>> {
    let mut out: Vec<Vec<Op>> = vec![Vec::new()];
    let mut frontier: Vec<Vec<Op>> = vec![Vec::new()];
    for _ in 0..max {
        let mut next = Vec::new();
        for seq in &frontier {
            for &op in menu {
                let mut extended = seq.clone();
                extended.push(op);
                next.push(extended.clone());
                out.push(extended);
            }
        }
        frontier = next;
    }
    out
}

/// Replay `prefix` on a fresh rig. Returns None if some op is disabled
/// (the caller enumerated it blindly).
async fn replay(prefix: &[Op]) -> Option<Rig> {
    let mut rig = Rig::new().await;
    for &op in prefix {
        if !rig.enabled(op) {
            return None;
        }
        rig.execute(op).await;
    }
    Some(rig)
}

/// Park a commit of `mask` at the inner fsync on `rig`: registration
/// schedules a driver task, and the gate holds that task at the fsync.
/// Returns the observer handles.
async fn park_commit(rig: &mut Rig, mask: u8) -> Vec<crate::Handle<()>> {
    let slots: Vec<u8> = (0..BLOBS)
        .filter(|&s| mask & (1 << s) != 0 && rig.live(s))
        .collect();
    assert!(!slots.is_empty(), "window mask selects no live blob");
    rig.gated.sync_gate.arm();
    let mut handles = Vec::new();
    for slot in &slots {
        handles.push(rig.blobs[slot].start_sync().await);
    }
    // Bounded wait: the model said the commit is non-clean, so it must
    // reach the inner fsync.
    for _ in 0..1_000_000u32 {
        if rig.gated.sync_gate.is_reached() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        rig.gated.sync_gate.is_reached(),
        "{}: commit of mask {mask:#b} never reached the inner fsync",
        rig.ctx()
    );
    rig.step_model_only(&[Action::Snapshot(mask), Action::WriteMeta]);
    rig.in_flight = true;
    handles
}

/// One commit-window probe: park a sync at the fsync, interleave `suffix`,
/// then crash mid-commit or confirm-and-crash.
async fn window_probe(
    prefix: &[Op],
    mask: u8,
    suffix: &[Op],
    confirm: bool,
    cap: usize,
    seed: u64,
    stats: &mut Stats,
) {
    let Some(mut rig) = replay(prefix).await else {
        return;
    };
    // The model must consider the commit non-clean, or the real sync
    // returns without any fsync to park.
    {
        let probe = step(
            &rig.tracked[0].state,
            Action::Snapshot(mask),
            &SPEC,
            &rig.trace,
        );
        if !matches!(probe, Ok(Some(_))) {
            return;
        }
    }
    let handles = park_commit(&mut rig, mask).await;
    // Interleave ops in the commit window (the post-snapshot write races
    // the model proves the freeze rule against).
    for &op in suffix {
        if !rig.enabled(op) {
            // The released driver task finishes its commit into a rig
            // being torn down, which is inert.
            rig.gated.sync_gate.release();
            return;
        }
        rig.execute(op).await;
    }
    if confirm {
        rig.gated.sync_gate.release();
        for handle in handles {
            handle
                .await
                .unwrap_or_else(|e| panic!("{}: parked commit failed: {e}", rig.ctx()));
        }
        rig.in_flight = false;
        rig.step_model_only(&[Action::FsyncOk]);
        audit_volume(&rig.volume, rig.batch.is_none());
        rig.check_live().await;
        rig.crash_probe(&[], cap, seed, stats).await;
    } else {
        // Crash while the commit's metadata writes are pending.
        rig.crash_probe(&[], cap, seed, stats).await;
        // The released driver task finishes its commit into a rig being
        // torn down, which is inert.
        rig.gated.sync_gate.release();
        drop(handles);
    }
}

/// One fsync-failure probe: the poison latch plus crash conformance. The
/// model-side allowed set is the crash fan of the MetaWritten state — the
/// exact union of the model's fsyncgate residue states' crash outcomes
/// (kept/landed/lost each resolve within {durable, version, torn}).
async fn fail_probe(prefix: &[Op], slot: u8, cap: usize, seed: u64, stats: &mut Stats) {
    let Some(rig) = replay(prefix).await else {
        return;
    };
    {
        let probe = step(
            &rig.tracked[0].state,
            Action::Snapshot(1 << slot),
            &SPEC,
            &rig.trace,
        );
        if !matches!(probe, Ok(Some(_))) {
            return;
        }
    }
    rig.gated.sync_gate.arm_fail();
    let err = rig.blobs[&slot].sync().await;
    assert!(err.is_err(), "{}: gated fsync must fail", rig.ctx());
    // The latch: every subsequent operation fails.
    assert!(
        rig.blobs[&slot]
            .write_at(0, IoBuf::copy_from_slice(&[0u8; 8]))
            .await
            .is_err(),
        "{}: write after a failed commit must fail",
        rig.ctx()
    );
    assert!(
        rig.blobs[&slot].sync().await.is_err(),
        "{}: sync after a failed commit must fail",
        rig.ctx()
    );
    assert!(
        rig.blobs[&slot].prune(0).await.is_err(),
        "{}: prune after a failed commit must fail",
        rig.ctx()
    );
    assert!(
        rig.volume.batch().await.is_err(),
        "{}: batch after a failed commit must fail",
        rig.ctx()
    );
    rig.crash_probe(
        &[Action::Snapshot(1 << slot), Action::WriteMeta],
        cap,
        seed,
        stats,
    )
    .await;
}

/// Explore a workload exhaustively: DFS over enabled op sequences with
/// probes at every node.
async fn explore(w: &Workload) -> Stats {
    let mut stats = Stats::default();
    let window_suffixes = sequences(w.window_menu, w.window_depth);
    let mut stack: Vec<Vec<Op>> = vec![Vec::new()];
    while let Some(prefix) = stack.pop() {
        stats.nodes += 1;
        let seed = prefix.len() as u64 ^ 0xC0FF_EE00;
        let mut rig = Rig::new().await;
        for &op in &prefix {
            rig.execute(op).await;
        }
        // Plain crash at this node.
        rig.crash_probe(&[], w.cap, seed, &mut stats).await;
        // Commit-window and fail probes replay the prefix on fresh rigs.
        if prefix.len() <= w.window_max_prefix {
            for &mask in w.window_masks {
                for suffix in &window_suffixes {
                    for confirm in [false, true] {
                        window_probe(&prefix, mask, suffix, confirm, w.cap, seed, &mut stats).await;
                    }
                }
            }
        }
        if prefix.len() <= w.fail_max_prefix {
            fail_probe(&prefix, 0, w.cap, seed, &mut stats).await;
        }
        // Children.
        if prefix.len() < w.depth {
            for &op in w.menu {
                if rig.enabled(op) {
                    let mut child = prefix.clone();
                    child.push(op);
                    stack.push(child);
                }
            }
        }
    }
    println!("workload stats: {stats:?}");
    stats
}

// ---------------------------------------------------------------------------
// Default-suite workloads (bounded exhaustive)
// ---------------------------------------------------------------------------

/// Core workload: appends on two blobs, an overwrite (COW + freeze rule),
/// group syncs — with commit-window interleavings and fsync failures.
/// The real-volume counterpart of the model's CORE + LATCH workloads.
#[tokio::test]
async fn conformance_core() {
    let stats = explore(&Workload {
        menu: &[
            Op::Append(0),
            Op::Append(1),
            Op::Overwrite(0),
            Op::Sync(0b011),
        ],
        depth: 5,
        window_masks: &[0b001, 0b011],
        window_menu: &[Op::Append(0), Op::Overwrite(0), Op::Prune(0)],
        window_depth: 1,
        window_max_prefix: 3,
        fail_max_prefix: 2,
        cap: 1024,
    })
    .await;
    assert!(stats.cases > 2_000, "suspiciously few cases: {stats:?}");
}

/// Recycling workload: overwrite/rewind/hole-growth/remove/recreate with
/// per-blob commits, plus resizes interleaved into a parked commit's
/// window. The counterpart of the model's RECYCLE + REWIND workloads
/// (extent reuse, deferred frees, shrink shapes).
#[tokio::test]
async fn conformance_recycle() {
    let stats = explore(&Workload {
        menu: &[
            Op::Append(0),
            Op::Overwrite(0),
            Op::ResizeDown(0),
            Op::ResizeUp(0),
            Op::Remove(0),
            Op::Recreate(0),
            Op::Sync(0b001),
        ],
        depth: 3,
        window_masks: &[0b001],
        window_menu: &[Op::ResizeDown(0), Op::ResizeUp(0), Op::Prune(0)],
        window_depth: 1,
        window_max_prefix: 3,
        fail_max_prefix: 0,
        cap: 1024,
    })
    .await;
    assert!(stats.cases > 1_000, "suspiciously few cases: {stats:?}");
}

/// Batch workload: cross-blob staging, publish, drop, selective commits
/// that must respect the applied group (never-split), membership joining
/// the group without staged content (Batch::sync) under those selective
/// commits, plus staging interleaved into a parked commit's window (the
/// model's stage_invisible rule: staged content stays out of the in-flight
/// commit's crash fan). The counterpart of the model's BATCH/BATCH_COW and
/// BATCH_MEMBER workloads.
#[tokio::test]
async fn conformance_batch() {
    let stats = explore(&Workload {
        menu: &[
            Op::Append(0),
            Op::BatchAppend(0),
            Op::BatchAppend(1),
            Op::BatchOverwrite(0),
            Op::BatchSync(0),
            Op::BatchApply,
            Op::BatchDrop,
            Op::Sync(0b001),
        ],
        depth: 4,
        window_masks: &[0b001, 0b010],
        window_menu: &[Op::BatchAppend(0), Op::BatchOverwrite(0)],
        window_depth: 1,
        window_max_prefix: 2,
        fail_max_prefix: 0,
        cap: 512,
    })
    .await;
    assert!(stats.cases > 1_000, "suspiciously few cases: {stats:?}");
}

/// Batch-creation workload: recreating a removed blob through a batch
/// (mixed batches commit atomically via apply_sync, creation-only batches
/// publish commit-free), plus staged removals and remove-then-recreate
/// shapes committing in-step at apply (Batch::remove). The counterpart of
/// the model's BATCH_CREATE, BATCH_CREATE_FREE, BATCH_REMOVE, and
/// BATCH_RECREATE workloads.
#[tokio::test]
async fn conformance_batch_create() {
    let stats = explore(&Workload {
        menu: &[
            Op::Remove(1),
            Op::BatchRemove(1),
            Op::BatchCreate(1),
            Op::BatchAppend(0),
            Op::BatchApply,
            Op::Append(1),
            Op::Sync(0b001),
        ],
        depth: 5,
        window_masks: &[],
        window_menu: &[],
        window_depth: 0,
        window_max_prefix: 0,
        fail_max_prefix: 0,
        cap: 512,
    })
    .await;
    assert!(stats.cases > 1_000, "suspiciously few cases: {stats:?}");
}

/// Batch-over-pruned-blob workload: staged appends, floor-relative
/// overwrites, and staged shrinks bottoming out at the pruned floor,
/// interleaved with prunes, publishes, commits, and staging inside a
/// parked commit's window. The counterpart of the model's BATCH_PRUNE
/// workload (batch content ops over a nonzero floor were the gap the
/// publish_overlay shrink-to-floor defect lived in).
#[tokio::test]
async fn conformance_batch_prune() {
    let stats = explore(&Workload {
        menu: &[
            Op::Append(0),
            Op::Prune(0),
            Op::BatchAppend(0),
            Op::BatchOverwrite(0),
            Op::BatchResizeDown(0),
            Op::BatchApply,
            Op::Sync(0b001),
        ],
        // Depth 6 reaches the staged cow-plus-shrink double-free shape
        // that `conformance_directed_batch_cow_shrink` pins directly.
        depth: 6,
        window_masks: &[0b001],
        window_menu: &[Op::BatchOverwrite(0), Op::BatchResizeDown(0)],
        window_depth: 1,
        window_max_prefix: 3,
        fail_max_prefix: 0,
        cap: 512,
    })
    .await;
    assert!(stats.cases > 1_000, "suspiciously few cases: {stats:?}");
}

/// The staged-resize directed family. A staged shrink bottoming out at
/// the (chunk-aligned) pruned floor — the publish_overlay clear-arm,
/// whose boundary-below-the-floor regression marked dead state dirty —
/// is published and committed, with the same commit also parked at the
/// fsync (crash mid-commit and confirm arms). A shrink below the
/// floor's block regrows through the same overlay (publish truncates at
/// the DEEPEST staged size). A resize-only touch grouped with a
/// sibling's staged write must be captured with it by the sibling's
/// selective commit (never-split for resize-only parts). And a
/// shrink-to-zero regrows as holes.
#[tokio::test]
async fn conformance_directed_batch_resize() {
    let mut stats = Stats::default();
    let traces: &[&[Op]] = &[
        // Shrink bottoming out at the pruned floor, published and
        // committed.
        &[
            Op::Append(0),
            Op::Append(0),
            Op::Append(0),
            Op::Sync(0b001),
            Op::Prune(0),
            Op::BatchResizeDown(0),
            Op::BatchApply,
            Op::Sync(0b001),
        ],
        // The same bottom, regrown through the same overlay before
        // apply.
        &[
            Op::Append(0),
            Op::Append(0),
            Op::Append(0),
            Op::Sync(0b001),
            Op::Prune(0),
            Op::BatchResizeDown(0),
            Op::BatchAppend(0),
            Op::BatchApply,
            Op::Sync(0b001),
        ],
        // Resize-only touch grouped with a sibling's staged write: the
        // sibling's selective commit must capture the shrunk slot with
        // it.
        &[
            Op::Append(0),
            Op::Sync(0b001),
            Op::BatchResizeDown(0),
            Op::BatchAppend(1),
            Op::BatchApply,
            Op::Sync(0b010),
        ],
        // Shrink to zero, regrown as holes, published and committed.
        &[
            Op::Append(0),
            Op::BatchResizeDown(0),
            Op::BatchResizeUp(0),
            Op::BatchApply,
            Op::Sync(0b001),
        ],
    ];
    for (i, trace) in traces.iter().enumerate() {
        let mut rig = Rig::new().await;
        for &op in *trace {
            assert!(rig.enabled(op), "directed trace {i}: {op:?} disabled");
            rig.execute(op).await;
            rig.crash_probe(&[], 2048, i as u64, &mut stats).await;
        }
    }
    // The floor-bottom shape with its commit parked at the inner fsync:
    // crash mid-commit, and the confirm arm.
    let parked = &[
        Op::Append(0),
        Op::Append(0),
        Op::Append(0),
        Op::Sync(0b001),
        Op::Prune(0),
        Op::BatchResizeDown(0),
        Op::BatchApply,
    ];
    window_probe(parked, 0b001, &[], false, 2048, 41, &mut stats).await;
    window_probe(parked, 0b001, &[], true, 2048, 41, &mut stats).await;
    println!("directed batch-resize stats: {stats:?}");
    assert!(
        stats.exhaustive_points == stats.crash_points && stats.cases > 60,
        "suspiciously thin coverage: {stats:?}"
    );
}

/// Staged-COW-then-shrink extent accounting (found by the staged-resize
/// enumeration, 2026-07-19): a staged COW that supersedes a NON-PRIVATE
/// overlay run must mark the underlying base run removed, or a later
/// staged shrink re-exposes the base run and its sweep pushes the same
/// published extent into the replaced list a second time — a double
/// defer-content-free that trips the extent-accounting audit here and
/// the allocator's double-free assert in production. Trace 1 is the
/// found shape (append into the shared tail block, overwrite below the
/// committed size, shrink the block away). Trace 2 is the multi-block
/// sibling: the COW leaves a PRIVATE run at the base key and a
/// non-private suffix, so dropping the private run (which marks nothing
/// removed) would re-expose the base run with its full extent,
/// overlapping the suffix's own push.
#[tokio::test]
async fn conformance_directed_batch_cow_shrink() {
    let mut stats = Stats::default();
    let traces: &[&[Op]] = &[
        &[
            Op::Append(0),
            Op::Sync(0b001),
            Op::BatchAppend(0),
            Op::BatchOverwrite(0),
            Op::BatchResizeDown(0),
            Op::BatchResizeDown(0),
            Op::BatchApply,
            Op::Sync(0b001),
        ],
        &[
            Op::Append(0),
            Op::Append(0),
            Op::Append(0),
            Op::Sync(0b001),
            Op::BatchOverwrite(0),
            Op::BatchResizeDown(0),
            Op::BatchResizeDown(0),
            Op::BatchResizeDown(0),
            Op::BatchApply,
            Op::Sync(0b001),
        ],
    ];
    for trace in traces {
        let mut rig = Rig::new().await;
        for (i, &op) in trace.iter().enumerate() {
            assert!(rig.enabled(op), "cow-shrink trace: {op:?} disabled at {i}");
            rig.execute(op).await;
            rig.crash_probe(&[], 2048, 43, &mut stats).await;
        }
    }
    println!("directed batch cow-shrink stats: {stats:?}");
    assert!(stats.cases > 40, "suspiciously few cases: {stats:?}");
}

/// The stale-tail directed family (blocker B1's shape): shrink a sparse
/// blob into (or below) a hole, then make a LOWER chunk the new partial
/// frontier and commit it. A stale tail buffer would durably record the
/// dropped pre-shrink frontier as the new frontier's shadow, which
/// recovery would then splice over the committed bytes — detected here as
/// an illegal rollback or a failed pure-crash recovery.
#[tokio::test]
async fn conformance_directed_shrink_into_hole() {
    let mut stats = Stats::default();
    // Grow over a hole, back the high block, commit, shrink below all
    // backing, then commit a new low partial frontier.
    let traces: &[&[Op]] = &[
        &[
            Op::ResizeUp(0),
            Op::Append(0),
            Op::Sync(0b001),
            Op::ResizeDown(0),
            Op::Overwrite(0),
            Op::Sync(0b001),
        ],
        // The same shape with an extra append before the shrink (the
        // boundary lands in the hole rather than below all backing).
        &[
            Op::ResizeUp(0),
            Op::Append(0),
            Op::Append(0),
            Op::Sync(0b001),
            Op::ResizeDown(0),
            Op::ResizeDown(0),
            Op::Overwrite(0),
            Op::Sync(0b001),
        ],
        // Rewind below a committed boundary, then append back over it.
        &[
            Op::Append(0),
            Op::Append(0),
            Op::Sync(0b001),
            Op::ResizeDown(0),
            Op::Append(0),
            Op::Sync(0b001),
        ],
    ];
    for (i, trace) in traces.iter().enumerate() {
        let mut rig = Rig::new().await;
        for &op in *trace {
            assert!(rig.enabled(op), "directed trace {i}: {op:?} disabled");
            rig.execute(op).await;
            rig.crash_probe(&[], 2048, i as u64, &mut stats).await;
        }
    }
    println!("directed shrink stats: {stats:?}");
    assert!(
        stats.exhaustive_points == stats.crash_points && stats.cases > 30,
        "suspiciously thin coverage: {stats:?}"
    );
}

/// Directed batch-namespace family: remove-and-recreate-same-name in
/// one batch (the publish-order blocker — the removal must resolve
/// against the pre-publish namespace, never the staged recreation), a
/// bare staged removal alongside a sibling write (all-or-nothing across
/// crash), and the membership rebase (Batch::sync, then legal direct
/// growth, then staged writes: publish must rebase, never truncate the
/// growth as a staged shrink).
#[tokio::test]
async fn conformance_directed_batch_namespace() {
    let mut stats = Stats::default();
    let traces: &[&[Op]] = &[
        &[
            Op::Append(0),
            Op::Sync(0b001),
            Op::BatchAppend(1),
            Op::BatchRemove(0),
            Op::BatchCreate(0),
            Op::BatchApply,
            Op::Append(0),
            Op::Sync(0b001),
        ],
        &[
            Op::Append(0),
            Op::Sync(0b001),
            Op::BatchAppend(1),
            Op::BatchRemove(0),
            Op::BatchApply,
        ],
        &[
            Op::Append(0),
            Op::Sync(0b001),
            Op::BatchSync(0),
            Op::Append(0),
            Op::BatchAppend(1),
            Op::BatchAppend(0),
            Op::BatchApply,
        ],
    ];
    for (i, trace) in traces.iter().enumerate() {
        let mut rig = Rig::new().await;
        for &op in *trace {
            assert!(rig.enabled(op), "directed trace {i}: {op:?} disabled");
            rig.execute(op).await;
            rig.crash_probe(&[], 2048, i as u64, &mut stats).await;
        }
    }
    assert!(stats.cases > 60, "suspiciously few cases: {stats:?}");
}

/// The torn-shadow directed family (blocker B2's shape): a committed
/// partial frontier, then a commit whose dirt avoids the frontier (a COW
/// of chunk 0), crashed at the fsync. The outcome where everything lands
/// except the fresh shadow (which tears) must reject the candidate and
/// roll back exactly one commit — never splice the torn shadow over the
/// committed frontier.
#[tokio::test]
async fn conformance_directed_torn_shadow() {
    let mut stats = Stats::default();
    // Three cells: chunk 0 full, chunk 1 a committed partial frontier.
    let prefix = &[
        Op::Append(0),
        Op::Append(0),
        Op::Append(0),
        Op::Sync(0b001),
        Op::Overwrite(0),
    ];
    window_probe(prefix, 0b001, &[], false, 4096, 7, &mut stats).await;
    // The confirm arm as well: freeze-rule coverage for the same shape.
    window_probe(prefix, 0b001, &[Op::Append(0)], true, 4096, 7, &mut stats).await;
    println!("directed torn-shadow stats: {stats:?}");
    assert!(
        stats.exhaustive_points >= 1,
        "torn-shadow probe must enumerate exhaustively: {stats:?}"
    );
    assert!(stats.cases > 200, "suspiciously few cases: {stats:?}");
}

/// The capture-gated content-free directed family: a committed full block
/// on blob 0 is dropped into pending frees by a COW overwrite, then blob 1
/// commits twice WITHOUT capturing blob 0 (no default workload commits
/// while excluding a blob that holds pending content frees). Releasing
/// blob 0's content free at the first uncapturing commit would let the
/// second commit's table write recycle the block while the confirmed
/// table still references it — detected here as blob 0 recovering to
/// garbage or a stale token.
#[tokio::test]
async fn conformance_directed_capture_gated_frees() {
    let mut stats = Stats::default();
    let trace: &[Op] = &[
        Op::Append(0),
        Op::Append(0),
        Op::Sync(0b001),
        Op::Overwrite(0),
        Op::Append(1),
        Op::Sync(0b010),
        Op::Append(1),
        Op::Sync(0b010),
    ];
    let mut rig = Rig::new().await;
    for (i, &op) in trace.iter().enumerate() {
        assert!(
            rig.enabled(op),
            "capture-gated trace: {op:?} disabled at {i}"
        );
        rig.execute(op).await;
        rig.crash_probe(&[], 2048, i as u64, &mut stats).await;
    }
    println!("directed capture-gated-free stats: {stats:?}");
    assert!(
        stats.exhaustive_points == stats.crash_points && stats.cases > 20,
        "suspiciously thin coverage: {stats:?}"
    );
}

/// The directed prune family: a committed prefix is pruned, and a crash
/// BEFORE the pruning commit must regress the floor to the committed one
/// (the pruned cells readable again), while a crash AFTER the pruning
/// commit must keep the floor durable — no confirmed-pruned part is ever
/// served again. The model-side floor sets are asserted explicitly so
/// both arms stay directed, and the crash probes then hold the real
/// recovered state to them (extraction compares `Blob::floor` and the
/// below-floor read rejection against the model's allowed states).
#[tokio::test]
async fn conformance_directed_prune() {
    let mut stats = Stats::default();
    let mut rig = Rig::new().await;
    for op in [
        Op::Append(0),
        Op::Append(0),
        Op::Append(0),
        Op::Sync(0b001),
        Op::Prune(0),
    ] {
        assert!(rig.enabled(op), "directed prune: {op:?} disabled");
        rig.execute(op).await;
        rig.crash_probe(&[], 2048, 31, &mut stats).await;
    }
    // The pruning commit never landed: every recovery regresses the floor.
    let regressed = states_after(&rig.tracked, &[Action::Crash], &rig.trace);
    assert!(
        regressed
            .iter()
            .all(|(_, state)| state.volume.blobs[0].floor == 0),
        "model must regress the crashed-away floor"
    );
    // The pruning commit lands: the floor is durable across the crash.
    rig.execute(Op::Sync(0b001)).await;
    rig.crash_probe(&[], 2048, 32, &mut stats).await;
    let persisted = states_after(&rig.tracked, &[Action::Crash], &rig.trace);
    assert!(
        persisted
            .iter()
            .all(|(_, state)| state.volume.blobs[0].floor == CELLS_PER_BLOCK),
        "model must keep the committed floor"
    );
    println!("directed prune stats: {stats:?}");
    assert!(
        stats.exhaustive_points == stats.crash_points && stats.cases > 10,
        "suspiciously thin coverage: {stats:?}"
    );
}

// ---------------------------------------------------------------------------
// Deep randomized mode (soak profile)
// ---------------------------------------------------------------------------

/// Everything the random walk may do.
const DEEP_MENU: &[Op] = &[
    Op::Append(0),
    Op::Append(1),
    Op::Append(2),
    Op::Overwrite(0),
    Op::Overwrite(1),
    Op::ResizeDown(0),
    Op::ResizeUp(0),
    Op::Prune(0),
    Op::Prune(1),
    Op::Remove(0),
    Op::Recreate(0),
    Op::Sync(0b001),
    Op::Sync(0b010),
    Op::Sync(0b111),
    Op::BatchAppend(0),
    Op::BatchAppend(1),
    Op::BatchOverwrite(0),
    Op::BatchResizeDown(0),
    Op::BatchResizeUp(0),
    Op::BatchCreate(1),
    Op::BatchSync(0),
    Op::BatchRemove(1),
    Op::BatchApply,
    Op::BatchDrop,
];

/// Seeded random deep walk: long traces over the full vocabulary with
/// mid-walk crashes (sampled outcomes, all checked — one outcome resumed
/// with the lockstep filtered to the matching model states). Deeper
/// budgets than the default suite, run with the full test profile.
#[tokio::test]
#[ignore]
async fn conformance_random_deep() {
    for seed in 0..16u64 {
        random_walk(seed).await;
    }
}

async fn random_walk(seed: u64) {
    let mut rng = TestRng::new(seed);
    let mut stats = Stats::default();
    let mut rig = Rig::new().await;
    let mut crashes = 0usize;
    for step_idx in 0..18u32 {
        // Occasionally crash (bounded), otherwise a random enabled op.
        if crashes < 2 && rng.random_range(0..8u8) == 0 {
            crashes += 1;
            let space = CrashSpace::capture(&rig.tearing);
            let allowed = states_after(&rig.tracked, &[Action::Crash], &rig.trace);
            let (cases, _) = space.enumerate(64, seed ^ step_idx as u64);
            let mut resumed = false;
            for case in cases {
                stats.cases += 1;
                let obs = extract(&rig.pool, case.image.clone())
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "seed {seed} step {step_idx}: recovery failed ({}): {e}",
                            case.desc
                        )
                    });
                let matching: Vec<Tracked> = allowed
                    .iter()
                    .filter(|(parent, state)| {
                        translated(&rig.tracked[*parent], &state.volume.logical()) == obs
                    })
                    .map(|(parent, state)| {
                        // Budgets are exploration bounds, not semantic
                        // state: recovery's re-crash exploration returns
                        // matching states with depleted budgets, so
                        // resumed lockstep states get fresh ones (which
                        // also lets the dedupe below collapse them).
                        let mut state = state.clone();
                        state.actions_left = 120;
                        state.crashes_left = 6;
                        Tracked {
                            state,
                            translate: rig.tracked[*parent].translate.clone(),
                        }
                    })
                    .collect();
                assert!(
                    !matching.is_empty(),
                    "seed {seed} step {step_idx}: recovered state not allowed \
                     ({}):\n  {obs:?}",
                    case.desc
                );
                // Resume the walk on the first outcome (the rest were
                // membership-checked and dropped).
                if !resumed {
                    resumed = true;
                    let mut deduped: Vec<Tracked> = Vec::new();
                    let mut seen: HashSet<(ModelState, Vec<(Cell, u64)>)> = HashSet::new();
                    for t in matching {
                        let key = (
                            t.state.clone(),
                            t.translate.iter().map(|(c, v)| (*c, *v)).collect(),
                        );
                        if seen.insert(key) {
                            deduped.push(t);
                        }
                    }
                    let next_ctr = rig.next_ctr;
                    let ops = rig.ops.clone();
                    let trace = rig.trace.clone();
                    rig = Rig::resume(rig.pool.clone(), case.image, deduped, next_ctr, ops, trace)
                        .await;
                    rig.check_live().await;
                }
            }
            continue;
        }
        let enabled: Vec<Op> = DEEP_MENU
            .iter()
            .copied()
            .filter(|&op| rig.enabled(op))
            .collect();
        if enabled.is_empty() {
            break;
        }
        let op = enabled[rng.random_range(0..enabled.len())];
        rig.execute(op).await;
    }
    // Final crash conformance.
    rig.crash_probe(&[], 256, seed, &mut stats).await;
    println!("random walk seed {seed}: {stats:?}");
}

// ---------------------------------------------------------------------------
// Cancellation injection (the layer below the model)
// ---------------------------------------------------------------------------

/// Poll `fut` up to `polls` times, yielding between polls so the volume's
/// driver tasks (spawned onto this test's tokio runtime) make progress.
/// Returns whether it completed (with its result asserted Ok).
async fn poll_n<F: Future<Output = Result<(), Error>> + Unpin>(fut: &mut F, polls: usize) -> bool {
    for _ in 0..polls {
        if let Poll::Ready(result) = futures::poll!(&mut *fut) {
            result.expect("observed commit succeeds");
            return true;
        }
        tokio::task::yield_now().await;
    }
    false
}

/// Wait for a driver task to confirm a commit past `confirmed` (driver
/// tasks run on the ambient tokio executor, so yielding lets them finish).
async fn quiesce_confirmed(ready: &Ready<Stack>, confirmed: u64) {
    for _ in 0..1_000_000u32 {
        if ready.state.lock().confirmed_seq() > confirmed {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("driver task never confirmed a commit");
}

/// Drop a `blob.sync()` future after every possible poll count. Callers
/// are pure OBSERVERS of driver-task commits: every drop point is benign —
/// the commit still lands, nothing poisons, and the volume stays fully
/// consistent (B3's caller-cancellation hazard dissolved by construction;
/// the driver-abort arm of the contract is pinned by
/// `tests::test_volume_aborted_commit_task_poisons`).
#[tokio::test]
async fn conformance_cancel_sync() {
    let mut polls = 1usize;
    loop {
        let mut rig = Rig::new().await;
        rig.execute(Op::Append(0)).await;
        rig.execute(Op::Append(1)).await;

        let ready = rig.volume.shared.ready.get().expect("recovered").clone();
        let confirmed = ready.state.lock().confirmed_seq();
        rig.yields.store(true, Ordering::SeqCst);
        let completed = {
            let mut fut = Box::pin(rig.blobs[&0].sync());
            let completed = poll_n(&mut fut, polls).await;
            drop(fut);
            completed
        };
        rig.yields.store(false, Ordering::SeqCst);

        // The first poll registered and scheduled the commit: it lands
        // whether or not the observer survived.
        quiesce_confirmed(&ready, confirmed).await;
        assert!(
            ready.poisoned.get().is_none(),
            "polls {polls}: dropping a sync observer must stay benign"
        );
        rig.step_model_only(&[Action::Snapshot(0b001), Action::WriteMeta, Action::FsyncOk]);
        audit_volume(&rig.volume, true);
        rig.check_live().await;
        let mut stats = Stats::default();
        rig.crash_probe(&[], 256, polls as u64, &mut stats).await;
        if completed {
            println!("cancel_sync: enumerated {polls} poll boundaries");
            break;
        }
        polls += 1;
        assert!(polls < 10_000, "cancellation enumeration diverged");
    }
}

/// Drop a `start_sync` handle after every poll count (including never
/// polled): the handle only observes, and registration schedules the
/// commit eagerly, so it lands in every case and nothing poisons.
#[tokio::test]
async fn conformance_cancel_start_sync_handle() {
    // Never polled: the commit still lands (start = begin now).
    {
        let mut rig = Rig::new().await;
        rig.execute(Op::Append(0)).await;
        let ready = rig.volume.shared.ready.get().expect("recovered").clone();
        let confirmed = ready.state.lock().confirmed_seq();
        let handle = rig.blobs[&0].start_sync().await;
        drop(handle);
        quiesce_confirmed(&ready, confirmed).await;
        assert!(
            ready.poisoned.get().is_none(),
            "never-polled handle drop must stay benign"
        );
        rig.step_model_only(&[Action::Snapshot(0b001), Action::WriteMeta, Action::FsyncOk]);
        audit_volume(&rig.volume, true);
        rig.check_live().await;
        let mut stats = Stats::default();
        rig.crash_probe(&[], 256, 0, &mut stats).await;
    }

    // Dropped at every poll boundary: identical outcome.
    let mut polls = 1usize;
    loop {
        let mut rig = Rig::new().await;
        rig.execute(Op::Append(0)).await;
        let ready = rig.volume.shared.ready.get().expect("recovered").clone();
        let confirmed = ready.state.lock().confirmed_seq();
        rig.yields.store(true, Ordering::SeqCst);
        let completed = {
            let mut handle = Box::pin(rig.blobs[&0].start_sync().await);
            let completed = poll_n(&mut handle, polls).await;
            drop(handle);
            completed
        };
        rig.yields.store(false, Ordering::SeqCst);
        quiesce_confirmed(&ready, confirmed).await;
        assert!(
            ready.poisoned.get().is_none(),
            "polls {polls}: dropped handle must stay benign"
        );
        rig.step_model_only(&[Action::Snapshot(0b001), Action::WriteMeta, Action::FsyncOk]);
        audit_volume(&rig.volume, true);
        rig.check_live().await;
        if completed {
            println!("cancel_start_sync: enumerated {polls} poll boundaries");
            break;
        }
        polls += 1;
        assert!(polls < 10_000, "cancellation enumeration diverged");
    }
}

/// Drop a `Storage::remove` future after every poll count: the unlink and
/// its commit run in a driver task, so every drop point is benign and the
/// removal lands durably regardless.
#[tokio::test]
async fn conformance_cancel_remove() {
    let mut polls = 1usize;
    loop {
        let mut rig = Rig::new().await;
        rig.execute(Op::Append(0)).await;
        rig.execute(Op::Sync(0b001)).await;
        let ready = rig.volume.shared.ready.get().expect("recovered").clone();
        let confirmed = ready.state.lock().confirmed_seq();
        rig.blobs.remove(&0);
        rig.yields.store(true, Ordering::SeqCst);
        let completed = {
            let target = name(0);
            let mut fut = Box::pin(rig.volume.remove(PARTITION, Some(&target)));
            let completed = poll_n(&mut fut, polls).await;
            drop(fut);
            completed
        };
        rig.yields.store(false, Ordering::SeqCst);

        // The first poll scheduled the removal task: it completes (and
        // commits) whether or not the caller kept observing.
        quiesce_confirmed(&ready, confirmed).await;
        assert!(
            ready.poisoned.get().is_none(),
            "polls {polls}: dropping a remove observer must stay benign"
        );
        rig.step_model_only(&[
            Action::Remove(0),
            Action::Snapshot(0b001),
            Action::WriteMeta,
            Action::FsyncOk,
        ]);
        audit_volume(&rig.volume, true);
        rig.check_live().await;
        let mut stats = Stats::default();
        rig.crash_probe(&[], 256, polls as u64, &mut stats).await;
        if completed {
            println!("cancel_remove: enumerated {polls} poll boundaries");
            break;
        }
        polls += 1;
        assert!(polls < 10_000, "cancellation enumeration diverged");
    }
}

/// Drop a `Batch::apply_sync` future after every poll count: the apply
/// task owns the staged state, so every drop point is benign — the batch
/// publishes AND commits regardless, atomically.
#[tokio::test]
async fn conformance_cancel_apply_sync() {
    let mut polls = 1usize;
    loop {
        let mut rig = Rig::new().await;
        rig.execute(Op::Append(0)).await;
        rig.execute(Op::Sync(0b001)).await;
        rig.execute(Op::BatchAppend(0)).await;
        rig.execute(Op::BatchAppend(1)).await;

        let ready = rig.volume.shared.ready.get().expect("recovered").clone();
        let confirmed = ready.state.lock().confirmed_seq();
        let batch_rig = rig.batch.take().expect("staged batch");
        rig.yields.store(true, Ordering::SeqCst);
        let completed = {
            let mut fut = Box::pin(batch_rig.batch.apply_sync());
            let completed = poll_n(&mut fut, polls).await;
            drop(fut);
            completed
        };
        rig.yields.store(false, Ordering::SeqCst);
        drop(batch_rig.created);

        // The first poll handed the staged state to the apply task: the
        // batch lands whole whether or not the caller kept observing.
        quiesce_confirmed(&ready, confirmed).await;
        assert!(
            ready.poisoned.get().is_none(),
            "polls {polls}: dropping an apply_sync observer must stay benign"
        );
        rig.step_model_only(&[Action::BatchApply, Action::Snapshot(0b011)]);
        rig.step_model_only(&[Action::WriteMeta, Action::FsyncOk]);
        audit_volume(&rig.volume, true);
        rig.check_live().await;
        let mut stats = Stats::default();
        rig.crash_probe(&[], 256, polls as u64, &mut stats).await;
        if completed {
            println!("cancel_apply_sync: enumerated {polls} poll boundaries");
            break;
        }
        polls += 1;
        assert!(polls < 10_000, "cancellation enumeration diverged");
    }
}

/// Drop a `Batch::apply_sync` future while its task is still QUEUED on
/// the commit lock (held by a parked unrelated sync): the drop is benign
/// and the apply proceeds once the lock frees — the batch publishes and
/// commits after the parked commit completes.
#[tokio::test]
async fn conformance_cancel_apply_queued() {
    let mut rig = Rig::new().await;
    rig.execute(Op::Append(2)).await;
    rig.execute(Op::BatchAppend(0)).await;
    rig.execute(Op::BatchAppend(1)).await;

    // Baseline before anything is in flight: exactly two commits land
    // beyond it (the parked sync's, then the batch's).
    let ready = rig.volume.shared.ready.get().expect("recovered").clone();
    let confirmed = ready.state.lock().confirmed_seq();

    // Park an unrelated sync at the inner fsync: it holds the commit lock.
    rig.gated.sync_gate.arm();
    let parked = {
        let blob = rig.blobs[&2].clone();
        tokio::spawn(async move { blob.sync().await })
    };
    rig.gated.sync_gate.wait_reached().await;
    rig.step_model_only(&[Action::Snapshot(0b100), Action::WriteMeta]);

    // The apply task queues on the commit lock. Drop the observer while
    // it waits.
    let batch_rig = rig.batch.take().expect("staged batch");
    {
        let mut fut = Box::pin(batch_rig.batch.apply_sync());
        for _ in 0..16 {
            assert!(
                futures::poll!(fut.as_mut()).is_pending(),
                "apply cannot proceed while the commit lock is held"
            );
        }
        drop(fut);
    }
    drop(batch_rig.created);
    assert!(
        ready.poisoned.get().is_none(),
        "queued apply drop must stay benign"
    );

    // Release the parked sync: its commit confirms, then the apply task
    // acquires the lock, publishes, and commits the batch whole.
    rig.gated.sync_gate.release();
    parked.await.expect("parked task").expect("parked sync");
    rig.step_model_only(&[Action::FsyncOk]);
    // Each snapshot assigns the next consecutive seq, so waiting past
    // `confirmed + 1` observes the SECOND commit (the batch's), however
    // the scheduler interleaved it with the awaits above.
    quiesce_confirmed(&ready, confirmed + 1).await;
    rig.step_model_only(&[
        Action::BatchApply,
        Action::Snapshot(0b011),
        Action::WriteMeta,
        Action::FsyncOk,
    ]);
    audit_volume(&rig.volume, true);
    rig.check_live().await;
    rig.execute(Op::Append(0)).await;
    rig.execute(Op::Sync(0b001)).await;
    let mut stats = Stats::default();
    rig.crash_probe(&[], 256, 11, &mut stats).await;
}

/// Drop a `Batch::apply_start_sync` future (and, separately, its returned
/// handle) after every poll count: the apply task owns the staged state
/// and the handle only observes, so every drop point is benign — the
/// batch publishes and its registered commit lands.
#[tokio::test]
async fn conformance_cancel_apply_start_sync() {
    // Phase 1: drop the apply_start_sync future itself.
    let mut polls = 1usize;
    loop {
        let mut rig = Rig::new().await;
        rig.execute(Op::BatchAppend(0)).await;
        rig.execute(Op::BatchAppend(1)).await;
        let ready = rig.volume.shared.ready.get().expect("recovered").clone();
        let confirmed = ready.state.lock().confirmed_seq();
        let batch_rig = rig.batch.take().expect("staged batch");
        rig.yields.store(true, Ordering::SeqCst);
        let outcome = {
            let mut fut = Box::pin(batch_rig.batch.apply_start_sync());
            let mut outcome = None;
            for _ in 0..polls {
                if let Poll::Ready(result) = futures::poll!(fut.as_mut()) {
                    outcome = Some(result.expect("apply_start_sync succeeds"));
                    break;
                }
                tokio::task::yield_now().await;
            }
            outcome
        };
        rig.yields.store(false, Ordering::SeqCst);
        drop(batch_rig.created);

        // The apply task publishes and registers the group's commit
        // regardless, and the started commit then lands on its own.
        let completed = outcome.is_some();
        if let Some(handle) = outcome {
            handle.await.expect("started commit lands");
        }
        quiesce_confirmed(&ready, confirmed).await;
        assert!(
            ready.poisoned.get().is_none(),
            "polls {polls}: dropping apply_start_sync must stay benign"
        );
        rig.step_model_only(&[
            Action::BatchApply,
            Action::Snapshot(0b011),
            Action::WriteMeta,
            Action::FsyncOk,
        ]);
        audit_volume(&rig.volume, true);
        rig.check_live().await;
        let mut stats = Stats::default();
        rig.crash_probe(&[], 128, polls as u64, &mut stats).await;
        if completed {
            println!("cancel_apply_start_sync: enumerated {polls} poll boundaries");
            break;
        }
        polls += 1;
        assert!(polls < 10_000, "cancellation enumeration diverged");
    }

    // Phase 2: drop the returned handle after every poll count.
    let mut polls = 1usize;
    loop {
        let mut rig = Rig::new().await;
        rig.execute(Op::BatchAppend(0)).await;
        rig.execute(Op::BatchAppend(1)).await;
        let ready = rig.volume.shared.ready.get().expect("recovered").clone();
        let confirmed = ready.state.lock().confirmed_seq();
        let batch_rig = rig.batch.take().expect("staged batch");
        let handle = batch_rig.batch.apply_start_sync().await.expect("publish");
        drop(batch_rig.created);
        rig.yields.store(true, Ordering::SeqCst);
        let completed = {
            let mut handle = Box::pin(handle);
            let completed = poll_n(&mut handle, polls).await;
            drop(handle);
            completed
        };
        rig.yields.store(false, Ordering::SeqCst);
        quiesce_confirmed(&ready, confirmed).await;
        assert!(
            ready.poisoned.get().is_none(),
            "polls {polls}: dropped handle must stay benign"
        );
        rig.step_model_only(&[
            Action::BatchApply,
            Action::Snapshot(0b011),
            Action::WriteMeta,
            Action::FsyncOk,
        ]);
        audit_volume(&rig.volume, true);
        rig.check_live().await;
        if completed {
            println!("cancel_apply_start_sync handle: enumerated {polls} poll boundaries");
            break;
        }
        polls += 1;
        assert!(polls < 10_000, "cancellation enumeration diverged");
    }
}
