//! Exhaustive small-scope model of the volume commit protocol.
//!
//! This is a TLA+-style specification of the volume's on-disk protocol,
//! written as plain Rust and checked by breadth-first exploration of every
//! reachable state under bounded workloads. It exists to prove the crash and
//! power-loss story BEFORE (and independently of) the implementation: the
//! implementation must make the same decisions this model makes, and any
//! protocol change must be reflected here and re-checked.
//!
//! # What is modeled
//!
//! - The inner blob as an array of BLOCKS behind an OS-style write-back
//!   cache: writes queue as pending versions per block, `fsync` applies all
//!   pending, and a crash resolves EACH dirtied block independently to its
//!   last durable content, any pending version, or `Torn` (block-granularity
//!   power loss; sub-block tearing collapses to `Torn`).
//! - Blocks hold two logical CELLS so a committed tail and an uncommitted
//!   append share one block (the shared-tail-block hazard).
//! - The commit protocol split into interleavable phases (snapshot →
//!   metadata writes → fsync), with every other operation free to run
//!   between phases: this encodes the review panel's fatal finding (writes
//!   racing an in-flight commit) and verifies the freeze rule that closes it.
//! - Recovery exactly as specified: superblock slot selection, delta-manifest
//!   verification with shadow splicing, fallback adoption, losing-slot
//!   zeroing, on-disk tail repair — with crashes allowed DURING recovery's
//!   own repair writes.
//! - Chunk checksums as perfect content fingerprints (the table records the
//!   expected cells per block; comparison models CRC32C without collisions).
//! - Extent recycling through deferred frees, hole runs from resize-up, and
//!   the sacred-slot rule for superblock writes.
//!
//! # The freeze rule
//!
//! Every run tracks how many of its cells are FROZEN: covered by the last
//! confirmed table or captured by the in-flight snapshot. A write may land
//! in place iff it touches no frozen cell; otherwise it relocates the run
//! (copy-on-write). Freezing advances at snapshot time, is recomputed from
//! the confirmed table at confirmation, and subsumes both the panel's
//! "barrier at snapshot" fix and the shared-tail append exception (appending
//! at or beyond the frozen boundary of the tail block is in place; the
//! shadow block covers the frozen sibling cell against tearing). Notably it
//! also forbids the in-place tail append after a rewind below a committed
//! boundary — a hazard found while writing this model.
//!
//! # Invariants
//!
//! - I1/I2 (durability + snapshot consistency): every recovery adopts a state
//!   equal to the baseline (the last state this process observed as durable)
//!   or to the snapshot of exactly one commit attempted since — a legal
//!   roll-forward. Frankenstates and stale-slot resurrection are violations.
//! - I3 (no false corruption): on pure-crash histories, recovery succeeds and
//!   every committed cell reads back verified after repairs.
//! - I4 (latch): a failed (non-crash) commit poisons the volume; no later
//!   sync confirms until crash + recovery.
//! - I5 (re-crash safety): crashes during recovery re-recover to a state
//!   satisfying I1-I3 against the original baseline.
//!
//! Each protocol safeguard can be individually disabled via [`Rules`]; tests
//! assert the checker FINDS a violation for every disabled safeguard
//! (mutation-testing the model) and finds none with all safeguards enabled.
//!
//! # Deliberately out of scope
//!
//! Reader/writer async interleavings (the implementation serializes writers
//! per blob and readers use generation-validated retry), blob handles and
//! read-after-remove liveness (RAM-only bookkeeping), partitions/naming, and
//! `remove` durability (modeled as a table change committed by the next
//! sync — crash-equivalent, since an uncommitted remove never happened).

use std::collections::{BTreeMap, HashSet, VecDeque};

/// Total blocks (blocks 0/1 are superblock slots).
const BLOCKS: usize = 12;
/// First allocatable block.
const RESERVED: usize = 2;
/// Logical cells per block.
const CELLS_PER_BLOCK: u8 = 2;
/// Blobs in the workload.
const BLOBS: u8 = 2;
/// Maximum committed cells per blob (bounds the space).
const MAX_CELLS: u8 = 4;

/// A logical cell value.
///
/// `Val` versions resume from the adopted state after recovery, so a replayed
/// history writes byte-identical values — this is what reproduces the
/// stale-slot resurrection scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Cell {
    /// Zeros: holes and explicit zero fill are logically identical.
    Zero,
    /// Unverifiable residue in an uncommitted region (never expected).
    Garbage,
    Val { slot: u8, gen: u8, cell: u8, ver: u8 },
}

/// Durable content of one disk block.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Block {
    Virgin,
    /// Power loss tore this block.
    Torn,
    Data(Cell, Cell),
    /// Shadow copy of a blob's frozen tail cell.
    Shadow(Cell),
    /// Serialized blob table (symbolic).
    Table(Table),
    /// A superblock. `bound` models the stored CRC over the table bytes: it
    /// binds the superblock to the EXACT table content its commit wrote
    /// (collision-free in the model). Binding by content — not by pointer or
    /// by seq — is load-bearing twice over: a dropped table write over a
    /// recycled table block leaves an older valid table at the pointed-to
    /// location, and seq numbers are REUSED after a rollback, so a stale
    /// same-seq table can alias a later commit's block. Both found by this
    /// model (see `mutation_table_binding_detected`).
    Super {
        seq: u64,
        table: usize,
        bound: Table,
    },
    /// Explicitly invalidated superblock slot.
    ZeroedSuper,
}

/// One blob's entry in a durable table.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
struct Entry {
    gen: u8,
    /// Committed size in cells.
    size: u8,
    /// Logical block -> (physical block, expected cells). Absent = hole.
    /// Expected cells are the model's chunk CRC. Cells at or beyond `size`
    /// are uncommitted and never compared.
    runs: BTreeMap<u8, (usize, Cell, Cell)>,
    /// Shadow block for the committed tail cell (odd `size`, backed tail).
    shadow: Option<usize>,
}

/// A durable table: entries plus this commit's delta manifest.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
struct Table {
    blobs: BTreeMap<u8, Entry>,
    /// (blob slot, logical block) whose contents changed in this commit.
    manifest: Vec<(u8, u8)>,
}

/// The inner blob: durable blocks + write-back cache.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Disk {
    durable: Vec<Block>,
    pending: BTreeMap<usize, Vec<Block>>,
    /// Fsyncgate residue: cache pages marked clean without reaching disk.
    /// Read-visible, never written back, gone at crash.
    stale_cache: BTreeMap<usize, Block>,
}

impl Disk {
    fn empty() -> Self {
        Self {
            durable: vec![Block::Virgin; BLOCKS],
            pending: BTreeMap::new(),
            stale_cache: BTreeMap::new(),
        }
    }

    /// Queue a write (readable immediately, durable only after sync). A new
    /// write re-dirties the page, superseding any fsyncgate residue.
    fn write(&mut self, block: usize, content: Block) {
        self.stale_cache.remove(&block);
        self.pending.entry(block).or_default().push(content);
    }

    /// Page-cache read: newest pending version, else clean-but-unwritten
    /// residue, else durable.
    fn read(&self, block: usize) -> &Block {
        self.pending
            .get(&block)
            .and_then(|v| v.last())
            .or_else(|| self.stale_cache.get(&block))
            .unwrap_or(&self.durable[block])
    }

    /// Apply all pending writes durably.
    fn sync(&mut self) {
        for (block, versions) in std::mem::take(&mut self.pending) {
            self.durable[block] = versions.into_iter().last().unwrap();
        }
    }

    /// Every possible durable disk after power loss (pending writes resolve
    /// per block; fsyncgate residue is simply gone).
    fn crash_outcomes(&self) -> Vec<Disk> {
        let mut outcomes = vec![Disk {
            durable: self.durable.clone(),
            pending: BTreeMap::new(),
            stale_cache: BTreeMap::new(),
        }];
        for (&block, versions) in &self.pending {
            let mut choices: Vec<Block> = vec![self.durable[block].clone(), Block::Torn];
            choices.extend(versions.iter().cloned());
            choices.sort();
            choices.dedup();
            let mut next = Vec::with_capacity(outcomes.len() * choices.len());
            for outcome in &outcomes {
                for choice in &choices {
                    let mut disk = outcome.clone();
                    disk.durable[block] = choice.clone();
                    next.push(disk);
                }
            }
            outcomes = next;
        }
        outcomes
    }
}

/// A run in RAM: physical block, expected cells, and how many of its cells
/// are frozen (see module docs).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Run {
    phys: usize,
    cells: (Cell, Cell),
    frozen: u8,
}

/// One blob's RAM state.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
struct BlobState {
    live: bool,
    gen: u8,
    size: u8,
    /// Logical block -> run. Absent = hole.
    runs: BTreeMap<u8, Run>,
    /// Durable shadow block from the last commit covering this blob.
    shadow: Option<usize>,
    /// Per-cell version counters (deterministic, replay-identical values).
    vers: BTreeMap<u8, u8>,
    /// Blocks with content changes since the last snapshot.
    dirty_blocks: Vec<u8>,
    dirty: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Phase {
    Snapshotted,
    MetaWritten,
}

/// An in-flight commit (phases interleave with other operations).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct InFlight {
    seq: u64,
    phase: Phase,
    /// The logical state this commit will confirm.
    logical: Logical,
    table: Table,
    table_block: usize,
    /// New shadow blocks to write in the WRITE phase: (block, tail cell).
    shadows: Vec<(usize, Cell)>,
    /// Blocks this commit stops referencing (freed on confirmation).
    frees: Vec<usize>,
}

/// The volume's RAM state (dies with the process).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Volume {
    blobs: Vec<BlobState>,
    /// Free physical blocks, deterministic order.
    free: Vec<usize>,
    /// (block, freeing seq): allocatable once that seq confirms.
    pending_free: Vec<(usize, u64)>,
    /// Seq of the next commit.
    seq: u64,
    /// Slot (0/1) holding the last confirmed superblock.
    sacred: usize,
    /// Table block of the last confirmed commit (freed on supersede).
    last_table: usize,
    in_flight: Option<InFlight>,
    poisoned: bool,
}

/// A pure logical view: per slot, (generation, committed cells). Holes and
/// explicit zeros both read as `Cell::Zero` — callers cannot distinguish.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
struct Logical {
    blobs: Vec<Option<(u8, Vec<Cell>)>>,
}

/// Protocol safeguards. Production = all enabled; tests disable one at a
/// time to prove the checker detects each corresponding bug class.
#[derive(Clone, Copy, Debug)]
struct Rules {
    /// Freeze snapshotted runs at snapshot time (not only at confirmation).
    /// Disabling reintroduces the panel's fatal-1: post-snapshot in-place
    /// overwrites of manifested chunks roll back confirmed commits.
    freeze_at_snapshot: bool,
    /// Write shadow tail blocks and splice them during recovery. Disabling
    /// reintroduces shared-tail-block torn-write loss.
    shadow_tails: bool,
    /// Zero the losing superblock slot when recovery adopts the fallback.
    /// Disabling reintroduces stale-slot resurrection.
    zero_losing_slot: bool,
    /// Defer extent reuse until the freeing commit confirms. Disabling lets
    /// live fallback data be overwritten before its successor lands.
    deferred_frees: bool,
    /// Poison the volume after a failed commit. Disabling lets a later sync
    /// spuriously report durability (I4).
    latch_on_failure: bool,
    /// Bind each superblock to the exact table bytes it wrote (the stored
    /// table CRC). Disabling reintroduces recycled-table-block aliasing.
    bind_table: bool,
}

const SPEC: Rules = Rules {
    freeze_at_snapshot: true,
    shadow_tails: true,
    zero_losing_slot: true,
    deferred_frees: true,
    latch_on_failure: true,
    bind_table: true,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Append(u8),
    /// Overwrite cell 0 (exercises the freeze rule / COW).
    Overwrite(u8),
    /// Shrink by one cell (rewind).
    ResizeDown(u8),
    /// Grow by two hole cells.
    ResizeUp(u8),
    Remove(u8),
    Recreate(u8),
    Snapshot,
    WriteMeta,
    FsyncOk,
    FsyncFail,
    Crash,
}

/// Committed-cell coverage of logical block `lblock` for a blob of `size`.
fn coverage(size: u8, lblock: u8) -> u8 {
    size.saturating_sub(lblock * CELLS_PER_BLOCK).min(CELLS_PER_BLOCK)
}

impl Volume {
    fn fresh() -> Self {
        Self {
            blobs: (0..BLOBS).map(|_| BlobState { live: true, ..Default::default() }).collect(),
            free: (RESERVED..BLOCKS).collect(),
            pending_free: Vec::new(),
            seq: 1,
            sacred: 0,
            last_table: usize::MAX,
            in_flight: None,
            poisoned: false,
        }
    }

    fn allocate(&mut self) -> usize {
        assert!(!self.free.is_empty(), "model out of blocks");
        self.free.remove(0)
    }

    fn release(&mut self, block: usize, rules: &Rules) {
        if rules.deferred_frees {
            self.pending_free.push((block, self.seq));
        } else {
            self.free.push(block);
            self.free.sort_unstable();
        }
    }

    fn next_val(&mut self, slot: u8, cell: u8) -> Cell {
        let b = &mut self.blobs[slot as usize];
        let ver = b.vers.entry(cell).or_insert(0);
        *ver += 1;
        Cell::Val { slot, gen: b.gen, cell, ver: *ver }
    }

    fn mark_dirty(&mut self, slot: u8, lblock: Option<u8>) {
        let b = &mut self.blobs[slot as usize];
        b.dirty = true;
        if let Some(l) = lblock {
            if !b.dirty_blocks.contains(&l) {
                b.dirty_blocks.push(l);
            }
        }
    }

    /// The logical state a snapshot taken now would capture.
    fn logical(&self) -> Logical {
        let mut blobs = Vec::new();
        for b in &self.blobs {
            if !b.live {
                blobs.push(None);
                continue;
            }
            let cells = (0..b.size)
                .map(|i| match b.runs.get(&(i / CELLS_PER_BLOCK)) {
                    Some(run) => {
                        if i % CELLS_PER_BLOCK == 0 {
                            run.cells.0
                        } else {
                            run.cells.1
                        }
                    }
                    None => Cell::Zero,
                })
                .collect();
            blobs.push(Some((b.gen, cells)));
        }
        Logical { blobs }
    }

    /// Write a cell following the freeze rule: in place iff the touched cell
    /// is not frozen; otherwise relocate the whole run (COW).
    fn write_cell(&mut self, disk: &mut Disk, rules: &Rules, slot: u8, cell: u8, val: Cell) {
        let lblock = cell / CELLS_PER_BLOCK;
        let idx = cell % CELLS_PER_BLOCK;
        match self.blobs[slot as usize].runs.get(&lblock).cloned() {
            None => {
                // Hole or fresh block: allocate, zero-fill the sibling cell.
                let phys = self.allocate();
                let cells = if idx == 0 { (val, Cell::Zero) } else { (Cell::Zero, val) };
                disk.write(phys, Block::Data(cells.0, cells.1));
                self.blobs[slot as usize]
                    .runs
                    .insert(lblock, Run { phys, cells, frozen: 0 });
            }
            Some(run) => {
                let cells = if idx == 0 { (val, run.cells.1) } else { (run.cells.0, val) };
                if idx >= run.frozen {
                    disk.write(run.phys, Block::Data(cells.0, cells.1));
                    self.blobs[slot as usize].runs.insert(lblock, Run { cells, ..run });
                } else {
                    let phys = self.allocate();
                    disk.write(phys, Block::Data(cells.0, cells.1));
                    self.release(run.phys, rules);
                    self.blobs[slot as usize]
                        .runs
                        .insert(lblock, Run { phys, cells, frozen: 0 });
                }
            }
        }
        self.mark_dirty(slot, Some(lblock));
    }
}

/// Verify a candidate's delta manifest against the disk, using shadows as the
/// authority for the frozen cell of partial tail blocks.
fn verify_manifest(disk: &Disk, table: &Table) -> bool {
    for &(slot, lblock) in &table.manifest {
        let Some(entry) = table.blobs.get(&slot) else { continue };
        let Some(&(phys, c0, c1)) = entry.runs.get(&lblock) else { continue };
        let partial_tail = coverage(entry.size, lblock) == 1;
        let shadow_ok = || {
            entry
                .shadow
                .is_some_and(|s| matches!(disk.read(s), Block::Shadow(sc) if *sc == c0))
        };
        let ok = match disk.read(phys) {
            Block::Data(d0, d1) => {
                if partial_tail {
                    // The committed cell is recoverable from the shadow even
                    // if a post-snapshot append tore this block; without a
                    // shadow the on-disk cell must match directly.
                    if entry.shadow.is_some() { shadow_ok() } else { *d0 == c0 }
                } else {
                    *d0 == c0 && *d1 == c1
                }
            }
            // Block missing/torn: acceptable only if the committed content
            // is fully shadow-recoverable.
            _ => partial_tail && shadow_ok(),
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Read one committed cell through a table entry (post-repair disk).
fn read_cell(disk: &Disk, entry: &Entry, cell: u8) -> Result<Cell, String> {
    let Some(&(phys, c0, c1)) = entry.runs.get(&(cell / CELLS_PER_BLOCK)) else {
        return Ok(Cell::Zero);
    };
    let expected = if cell % CELLS_PER_BLOCK == 0 { c0 } else { c1 };
    match disk.read(phys) {
        Block::Data(d0, d1) => {
            let got = if cell % CELLS_PER_BLOCK == 0 { *d0 } else { *d1 };
            if got == expected {
                Ok(got)
            } else {
                Err(format!("phys {phys}: cell {cell} = {got:?}, expected {expected:?}"))
            }
        }
        other => Err(format!("phys {phys}: {other:?}")),
    }
}

/// The verified logical view a table describes.
fn read_logical(disk: &Disk, table: &Table) -> Result<Logical, String> {
    let mut blobs = vec![None; BLOBS as usize];
    for (&slot, entry) in &table.blobs {
        let mut cells = Vec::new();
        for i in 0..entry.size {
            cells.push(read_cell(disk, entry, i)?);
        }
        blobs[slot as usize] = Some((entry.gen, cells));
    }
    Ok(Logical { blobs })
}

/// Outcome of slot selection + verification (no writes).
struct Adopted {
    slot: usize,
    seq: u64,
    table_block: usize,
    table: Table,
    /// Slot to zero because its (newer) commit failed verification.
    losing_slot: Option<usize>,
}

/// Deterministic adoption over a crashed disk.
fn adopt(disk: &Disk, rules: &Rules) -> Result<Adopted, String> {
    let parse = |b: &Block| match b {
        Block::Super { seq, table, bound } => Some((*seq, *table, bound.clone())),
        _ => None,
    };
    let mut slots: Vec<(usize, u64, usize, Table)> =
        [(0usize, parse(disk.read(0))), (1, parse(disk.read(1)))]
            .into_iter()
            .filter_map(|(slot, p)| p.map(|(seq, table, bound)| (slot, seq, table, bound)))
            .collect();
    if slots.is_empty() {
        return Err("no valid superblock".into());
    }
    slots.sort_by_key(|&(_, seq, _, _)| std::cmp::Reverse(seq));

    for (idx, (slot, seq, table_block, bound)) in slots.iter().enumerate() {
        let is_candidate = idx == 0 && slots.len() == 2;
        let adoptable = match disk.read(*table_block) {
            Block::Table(table) if !rules.bind_table || table == bound => {
                verify_manifest(disk, table).then(|| table.clone())
            }
            _ => None,
        };
        match adoptable {
            Some(table) => {
                let losing_slot = (idx == 1).then(|| slots[0].0);
                return Ok(Adopted {
                    slot: *slot,
                    seq: *seq,
                    table_block: *table_block,
                    table,
                    losing_slot,
                });
            }
            None if is_candidate => continue, // torn newest commit -> fallback
            None => return Err(format!("slot {slot} seq {seq} unadoptable")),
        }
    }
    Err("both slots unadoptable".into())
}

/// Build the post-recovery RAM state for an adopted table.
fn rebuild(adopted: &Adopted) -> Volume {
    let mut used = vec![adopted.table_block];
    let mut volume = Volume::fresh();
    volume.blobs = (0..BLOBS)
        .map(|s| {
            let Some(e) = adopted.table.blobs.get(&s) else {
                return BlobState::default();
            };
            let mut vers: BTreeMap<u8, u8> = BTreeMap::new();
            for &(phys, c0, c1) in e.runs.values() {
                used.push(phys);
                for c in [c0, c1] {
                    if let Cell::Val { cell, ver, .. } = c {
                        let v = vers.entry(cell).or_insert(0);
                        *v = (*v).max(ver);
                    }
                }
            }
            if let Some(sh) = e.shadow {
                used.push(sh);
            }
            BlobState {
                live: true,
                gen: e.gen,
                size: e.size,
                runs: e
                    .runs
                    .iter()
                    .map(|(&l, &(phys, c0, c1))| {
                        (l, Run { phys, cells: (c0, c1), frozen: coverage(e.size, l) })
                    })
                    .collect(),
                shadow: e.shadow,
                vers,
                dirty_blocks: Vec::new(),
                dirty: false,
            }
        })
        .collect();
    volume.free = (RESERVED..BLOCKS).filter(|b| !used.contains(b)).collect();
    volume.seq = adopted.seq + 1;
    volume.sacred = adopted.slot;
    volume.last_table = adopted.table_block;
    volume
}

/// Queue recovery's repair writes: zero the losing slot, splice every
/// physically-backed partial tail from its shadow.
fn queue_repairs(disk: &mut Disk, adopted: &Adopted, rules: &Rules) {
    if rules.zero_losing_slot {
        if let Some(slot) = adopted.losing_slot {
            disk.write(slot, Block::ZeroedSuper);
        }
    }
    if !rules.shadow_tails {
        return;
    }
    for entry in adopted.table.blobs.values() {
        if entry.size % CELLS_PER_BLOCK != 1 {
            continue;
        }
        let tail = entry.size / CELLS_PER_BLOCK;
        let (Some(&(phys, _, _)), Some(shadow)) = (entry.runs.get(&tail), entry.shadow)
        else {
            continue;
        };
        let Block::Shadow(sc) = disk.read(shadow) else { continue };
        let sc = *sc;
        // Positional sub-block write of the committed fragment: the sibling
        // cell keeps whatever the block held (garbage if torn/virgin).
        let high = match disk.read(phys) {
            Block::Data(_, d1) => *d1,
            _ => Cell::Garbage,
        };
        disk.write(phys, Block::Data(sc, high));
    }
}

/// The full checker state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct State {
    disk: Disk,
    volume: Volume,
    /// The last logical state observed as durable by this process lineage.
    baseline: Logical,
    /// Snapshots of commits attempted since the baseline was observed.
    attempts: Vec<Logical>,
    /// A commit failed; no further sync may report success (I4).
    latched: bool,
    actions_left: u8,
    crashes_left: u8,
}

/// A violation with its full trace.
#[derive(Debug)]
struct Violation {
    trace: Vec<Action>,
    reason: String,
}

fn initial_state(actions: u8, crashes: u8) -> State {
    // The model starts post-init: seq-0 superblock in slot 0 plus a table
    // containing the workload's (empty) blobs, both durable. Init itself is
    // two syncs — table first, then the superblock pointing at it — so a
    // valid slot always implies a readable table even with only one slot
    // written (see `init_tearing_rejoins`).
    let mut init_table = Table::default();
    for slot in 0..BLOBS {
        init_table.blobs.insert(slot, Entry::default());
    }
    let mut disk = Disk::empty();
    disk.durable[0] =
        Block::Super { seq: 0, table: RESERVED, bound: init_table.clone() };
    disk.durable[RESERVED] = Block::Table(init_table);
    let mut volume = Volume::fresh();
    volume.free.retain(|&b| b != RESERVED);
    volume.last_table = RESERVED;
    let baseline = volume.logical();
    State {
        disk,
        volume,
        baseline,
        attempts: Vec::new(),
        latched: false,
        actions_left: actions,
        crashes_left: crashes,
    }
}

/// Recovery as a process: adopt, check invariants, queue repairs, then either
/// finish cleanly or crash again mid-repair (recursively, budget permitting).
fn recovery_states(
    disk: Disk,
    baseline: &Logical,
    attempts: &[Logical],
    rules: &Rules,
    crashes_left: u8,
    actions_left: u8,
    trace: &[Action],
) -> Result<Vec<State>, Violation> {
    let adopted = match adopt(&disk, rules) {
        Ok(a) => a,
        Err(e) => {
            return Err(Violation {
                trace: trace.to_vec(),
                reason: format!("I3: recovery failed on pure-crash history: {e}"),
            })
        }
    };

    // Queue repairs, then read the adopted state through them.
    let mut repaired = disk;
    queue_repairs(&mut repaired, &adopted, rules);
    let logical = match read_logical(&repaired, &adopted.table) {
        Ok(l) => l,
        Err(e) => {
            return Err(Violation {
                trace: trace.to_vec(),
                reason: format!("I3: adopted state fails verification after repair: {e}"),
            })
        }
    };

    // I1/I2: the adopted state must be the baseline or an attempt made since.
    if logical != *baseline && !attempts.contains(&logical) {
        let dump: String = repaired
            .durable
            .iter()
            .enumerate()
            .map(|(i, b)| format!("    block {i}: {b:?}\n"))
            .collect();
        return Err(Violation {
            trace: trace.to_vec(),
            reason: format!(
                "I1/I2: adopted state is neither the baseline nor an attempted \
                 commit\n  adopted (slot {}, seq {}): {logical:?}\n  baseline: \
                 {baseline:?}\n  attempts: {attempts:?}\n  durable disk:\n{dump}",
                adopted.slot, adopted.seq
            ),
        });
    }

    let mut out = Vec::new();

    // (a) Repairs sync cleanly; recovery returns; adopted state is observed.
    {
        let mut disk = repaired.clone();
        disk.sync();
        out.push(State {
            disk,
            volume: rebuild(&adopted),
            baseline: logical.clone(),
            attempts: Vec::new(),
            latched: false,
            actions_left,
            crashes_left,
        });
    }

    // (b) Power loss during the repair writes (I5). The adopted state was
    // never observed (recovery didn't return), so invariants keep binding to
    // the ORIGINAL baseline/attempts.
    if crashes_left > 0 && !repaired.pending.is_empty() {
        let mut next_trace = trace.to_vec();
        next_trace.push(Action::Crash);
        for outcome in repaired.crash_outcomes() {
            out.extend(recovery_states(
                outcome,
                baseline,
                attempts,
                rules,
                crashes_left - 1,
                actions_left,
                &next_trace,
            )?);
        }
    }
    Ok(out)
}

/// Apply one action. Returns successor states (a crash fans out), or None if
/// the action is not enabled in this state.
fn step(
    state: &State,
    action: Action,
    rules: &Rules,
    trace: &[Action],
) -> Result<Option<Vec<State>>, Violation> {
    if state.actions_left == 0 {
        return Ok(None);
    }
    let mut s = state.clone();
    s.actions_left -= 1;

    // A poisoned volume accepts no further mutations or commits; only a crash
    // (new process) makes progress. Under the latch mutation, mutations stay
    // blocked (the structure above is dead) but a NEW sync is allowed to
    // observe the spurious "clean" state — modeling a sibling structure that
    // never saw the failure.
    let poisoned = s.volume.poisoned;
    let mutations_blocked = poisoned;
    let syncs_blocked = if rules.latch_on_failure { s.latched || poisoned } else { false };

    match action {
        Action::Append(slot) => {
            let b = &s.volume.blobs[slot as usize];
            if mutations_blocked || !b.live || b.size >= MAX_CELLS {
                return Ok(None);
            }
            let cell = b.size;
            let val = s.volume.next_val(slot, cell);
            s.volume.write_cell(&mut s.disk, rules, slot, cell, val);
            s.volume.blobs[slot as usize].size += 1;
            Ok(Some(vec![s]))
        }
        Action::Overwrite(slot) => {
            let b = &s.volume.blobs[slot as usize];
            if mutations_blocked || !b.live || b.size == 0 {
                return Ok(None);
            }
            let val = s.volume.next_val(slot, 0);
            s.volume.write_cell(&mut s.disk, rules, slot, 0, val);
            Ok(Some(vec![s]))
        }
        Action::ResizeDown(slot) => {
            if mutations_blocked
                || !s.volume.blobs[slot as usize].live
                || s.volume.blobs[slot as usize].size == 0
            {
                return Ok(None);
            }
            s.volume.blobs[slot as usize].size -= 1;
            let new_size = s.volume.blobs[slot as usize].size;
            let backed = new_size.div_ceil(CELLS_PER_BLOCK);
            let dropped: Vec<u8> = s.volume.blobs[slot as usize]
                .runs
                .keys()
                .copied()
                .filter(|&l| l >= backed)
                .collect();
            for l in dropped {
                let run = s.volume.blobs[slot as usize].runs.remove(&l).unwrap();
                s.volume.release(run.phys, rules);
            }
            // The (possibly newly partial) tail must re-commit: its shadow
            // and manifest entry change even though its bytes do not.
            if new_size > 0 {
                let tail = (new_size - 1) / CELLS_PER_BLOCK;
                s.volume.mark_dirty(slot, Some(tail));
            } else {
                s.volume.mark_dirty(slot, None);
            }
            Ok(Some(vec![s]))
        }
        Action::ResizeUp(slot) => {
            let b = &s.volume.blobs[slot as usize];
            if mutations_blocked || !b.live || b.size + 2 > MAX_CELLS {
                return Ok(None);
            }
            let old_size = b.size;
            let new_size = old_size + 2;
            // Zero extension: cells that land in PHYSICALLY BACKED blocks
            // must be zeroed through the normal write path (the disk residue
            // there is arbitrary — torn appends, splice leftovers — and the
            // table would otherwise vouch for zeros it never wrote). Cells
            // in unbacked blocks become holes and are synthesized as zeros.
            // Found by this model: committing residue "as zeros" without
            // writing breaks verification after the extension commits.
            for cell in old_size..new_size {
                if s.volume.blobs[slot as usize]
                    .runs
                    .contains_key(&(cell / CELLS_PER_BLOCK))
                {
                    s.volume.write_cell(&mut s.disk, rules, slot, cell, Cell::Zero);
                }
            }
            s.volume.blobs[slot as usize].size = new_size;
            s.volume.mark_dirty(slot, None);
            Ok(Some(vec![s]))
        }
        Action::Remove(slot) => {
            if mutations_blocked || !s.volume.blobs[slot as usize].live {
                return Ok(None);
            }
            s.volume.blobs[slot as usize].live = false;
            s.volume.blobs[slot as usize].dirty = true;
            let runs = std::mem::take(&mut s.volume.blobs[slot as usize].runs);
            let shadow = s.volume.blobs[slot as usize].shadow.take();
            for run in runs.into_values() {
                s.volume.release(run.phys, rules);
            }
            if let Some(sh) = shadow {
                s.volume.release(sh, rules);
            }
            Ok(Some(vec![s]))
        }
        Action::Recreate(slot) => {
            let b = &mut s.volume.blobs[slot as usize];
            if mutations_blocked || b.live {
                return Ok(None);
            }
            let gen = b.gen + 1;
            *b = BlobState { live: true, gen, dirty: true, ..Default::default() };
            Ok(Some(vec![s]))
        }
        Action::Snapshot => {
            if syncs_blocked
                || s.volume.in_flight.is_some()
                || !s.volume.blobs.iter().any(|b| b.dirty)
            {
                return Ok(None);
            }
            let seq = s.volume.seq;
            s.volume.seq += 1;
            let table_block = s.volume.allocate();
            let mut table = Table::default();
            let mut shadows = Vec::new();
            let mut frees = Vec::new();
            if s.volume.last_table != usize::MAX {
                frees.push(s.volume.last_table);
            }
            for slot in 0..BLOBS {
                let dirty_blocks = std::mem::take(&mut s.volume.blobs[slot as usize].dirty_blocks);
                let was_dirty = s.volume.blobs[slot as usize].dirty;
                s.volume.blobs[slot as usize].dirty = false;
                if !s.volume.blobs[slot as usize].live {
                    continue;
                }
                // Freeze everything this snapshot captures.
                let size = s.volume.blobs[slot as usize].size;
                if rules.freeze_at_snapshot {
                    for (&l, run) in s.volume.blobs[slot as usize].runs.iter_mut() {
                        run.frozen = run.frozen.max(coverage(size, l));
                    }
                }
                let b = &s.volume.blobs[slot as usize];
                let mut entry = Entry {
                    gen: b.gen,
                    size,
                    runs: b
                        .runs
                        .iter()
                        .map(|(&l, r)| (l, (r.phys, r.cells.0, r.cells.1)))
                        .collect(),
                    shadow: b.shadow,
                };
                // A dirty blob with an odd, physically-backed tail gets a
                // fresh shadow; the old one is superseded.
                let needs_shadow = rules.shadow_tails
                    && was_dirty
                    && size % CELLS_PER_BLOCK == 1
                    && b.runs.contains_key(&(size / CELLS_PER_BLOCK));
                if needs_shadow {
                    let tail_cell = b.runs[&(size / CELLS_PER_BLOCK)].cells.0;
                    let sh = s.volume.allocate();
                    if let Some(old) = s.volume.blobs[slot as usize].shadow.replace(sh) {
                        frees.push(old);
                    }
                    shadows.push((sh, tail_cell));
                    entry.shadow = Some(sh);
                }
                for l in dirty_blocks {
                    if entry.runs.contains_key(&l) {
                        table.manifest.push((slot, l));
                    }
                }
                table.blobs.insert(slot, entry);
            }
            table.manifest.sort_unstable();
            let logical = s.volume.logical();
            s.attempts.push(logical.clone());
            s.volume.in_flight = Some(InFlight {
                seq,
                phase: Phase::Snapshotted,
                logical,
                table,
                table_block,
                shadows,
                frees,
            });
            Ok(Some(vec![s]))
        }
        Action::WriteMeta => {
            let Some(inf) = s.volume.in_flight.clone() else { return Ok(None) };
            if inf.phase != Phase::Snapshotted {
                return Ok(None);
            }
            for &(block, cell) in &inf.shadows {
                s.disk.write(block, Block::Shadow(cell));
            }
            s.disk.write(inf.table_block, Block::Table(inf.table.clone()));
            let slot = 1 - s.volume.sacred;
            s.disk.write(
                slot,
                Block::Super { seq: inf.seq, table: inf.table_block, bound: inf.table.clone() },
            );
            s.volume.in_flight.as_mut().unwrap().phase = Phase::MetaWritten;
            Ok(Some(vec![s]))
        }
        Action::FsyncOk => {
            let Some(inf) = s.volume.in_flight.clone() else { return Ok(None) };
            if syncs_blocked || inf.phase != Phase::MetaWritten {
                return Ok(None);
            }
            s.disk.sync();
            s.volume.sacred = 1 - s.volume.sacred;
            s.volume.last_table = inf.table_block;
            // Extents dropped by this commit (or earlier) become allocatable.
            let (now, later): (Vec<_>, Vec<_>) =
                s.volume.pending_free.drain(..).partition(|&(_, fs)| fs <= inf.seq);
            s.volume.pending_free = later;
            for (block, _) in now {
                s.volume.free.push(block);
            }
            s.volume.free.extend(inf.frees.iter().copied());
            s.volume.free.sort_unstable();
            s.volume.free.dedup();
            // Re-derive frozen coverage from the confirmed table: runs it
            // does not reference (COW'd since the snapshot) unfreeze.
            for slot in 0..BLOBS {
                let entry = inf.table.blobs.get(&slot).cloned();
                let b = &mut s.volume.blobs[slot as usize];
                for (&l, run) in b.runs.iter_mut() {
                    run.frozen = match &entry {
                        Some(e) => match e.runs.get(&l) {
                            Some(&(phys, _, _)) if phys == run.phys => coverage(e.size, l),
                            _ => 0,
                        },
                        None => 0,
                    };
                }
            }
            s.volume.in_flight = None;
            // Confirmed: this snapshot becomes the observed baseline.
            s.baseline = inf.logical;
            s.attempts.clear();
            Ok(Some(vec![s]))
        }
        Action::FsyncFail => {
            let Some(inf) = s.volume.in_flight.clone() else { return Ok(None) };
            if inf.phase != Phase::MetaWritten {
                return Ok(None);
            }
            let _ = inf;
            // Fsyncgate: after a failed fsync the cache state is undefined.
            // Each pending write independently (a) stays pending, (b) already
            // landed durably, or (c) is LOST — marked clean without reaching
            // disk, so no future fsync will ever write it. The latch exists
            // because of (c): the volume's RAM state still references the
            // lost bytes, and a later "successful" commit would vouch for
            // them. Without the latch, I1 catches the resulting lie.
            s.volume.in_flight = None;
            if rules.latch_on_failure {
                s.volume.poisoned = true;
            }
            s.latched = true;
            let mut outcomes = vec![Disk {
                durable: s.disk.durable.clone(),
                pending: BTreeMap::new(),
                stale_cache: s.disk.stale_cache.clone(),
            }];
            for (&block, versions) in &s.disk.pending {
                let newest = versions.last().unwrap().clone();
                // (a) still dirty, (b) landed durably, (c) marked clean
                // without reaching disk (read-visible residue).
                let mut next = Vec::with_capacity(outcomes.len() * 3);
                for outcome in &outcomes {
                    let mut keep = outcome.clone();
                    keep.pending.insert(block, vec![newest.clone()]);
                    next.push(keep);
                    let mut landed = outcome.clone();
                    landed.durable[block] = newest.clone();
                    next.push(landed);
                    let mut lost = outcome.clone();
                    lost.stale_cache.insert(block, newest.clone());
                    next.push(lost);
                }
                outcomes = next;
            }
            let mut out = Vec::new();
            for disk in outcomes {
                let mut succ = s.clone();
                succ.disk = disk;
                out.push(succ);
            }
            Ok(Some(out))
        }
        Action::Crash => {
            if s.crashes_left == 0 {
                return Ok(None);
            }
            s.crashes_left -= 1;
            let mut out = Vec::new();
            for outcome in s.disk.crash_outcomes() {
                out.extend(recovery_states(
                    outcome,
                    &s.baseline,
                    &s.attempts,
                    rules,
                    s.crashes_left,
                    s.actions_left,
                    trace,
                )?);
            }
            Ok(Some(out))
        }
    }
}

/// Exhaustive BFS over all action interleavings. Returns the first violation
/// found (with its trace), or the number of distinct states on success.
///
/// I4 (the failure latch) is checked through I1: without the latch, a commit
/// confirmed after an fsyncgate loss vouches for bytes that never reached
/// disk, and the next crash exposes the lie as an illegal rollback.
fn check(menu: &[Action], actions: u8, crashes: u8, rules: &Rules) -> Result<usize, Violation> {
    let init = initial_state(actions, crashes);
    let mut visited: HashSet<State> = HashSet::new();
    let mut queue: VecDeque<(State, Vec<Action>)> = VecDeque::new();
    visited.insert(init.clone());
    queue.push_back((init, Vec::new()));

    while let Some((state, trace)) = queue.pop_front() {
        for &action in menu {
            let mut next_trace = trace.clone();
            next_trace.push(action);
            if let Some(successors) = step(&state, action, rules, &next_trace)? {
                for succ in successors {
                    if visited.insert(succ.clone()) {
                        queue.push_back((succ, next_trace.clone()));
                    }
                }
            }
        }
    }
    Ok(visited.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Core workload: appends on two blobs, overwrites, commits, crashes.
    /// Covers group commit, the post-snapshot write window, shared tails,
    /// roll-forward, and rollback.
    const CORE: &[Action] = &[
        Action::Append(0),
        Action::Append(1),
        Action::Overwrite(0),
        Action::Snapshot,
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Recycling workload: remove/recreate + rewind + holes exercise extent
    /// reuse, deferred frees, hole runs, and replay-identical resurrection.
    const RECYCLE: &[Action] = &[
        Action::Append(0),
        Action::Overwrite(0),
        Action::ResizeDown(0),
        Action::ResizeUp(0),
        Action::Remove(0),
        Action::Recreate(0),
        Action::Snapshot,
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Rewind workload: resize-down interleaved with appends and commits —
    /// the in-place-tail-after-rewind hazard found while writing the model.
    const REWIND: &[Action] = &[
        Action::Append(0),
        Action::Append(1),
        Action::ResizeDown(0),
        Action::Snapshot,
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Failure workload: commits may fail without crashing (latch).
    const LATCH: &[Action] = &[
        Action::Append(0),
        Action::Append(1),
        Action::Snapshot,
        Action::WriteMeta,
        Action::FsyncOk,
        Action::FsyncFail,
        Action::Crash,
    ];

    fn render(v: Violation) -> String {
        let mut out = String::from("model violation\n");
        out.push_str(&format!("  reason: {}\n  trace:\n", v.reason));
        for (i, a) in v.trace.iter().enumerate() {
            out.push_str(&format!("    {i}: {a:?}\n"));
        }
        out
    }

    fn assert_holds(menu: &[Action], actions: u8, crashes: u8, min_states: usize) {
        match check(menu, actions, crashes, &SPEC) {
            Ok(states) => assert!(
                states > min_states,
                "suspiciously small state space: {states} (min {min_states})"
            ),
            Err(v) => panic!("{}", render(v)),
        }
    }

    #[test]
    fn spec_holds_core() {
        assert_holds(CORE, 8, 2, 10_000);
    }

    /// Deeper exhaustive sweep of the core workload (minutes; run with the
    /// full test profile).
    #[test]
    #[ignore]
    fn spec_holds_core_deep() {
        assert_holds(CORE, 9, 2, 100_000);
    }

    #[test]
    fn spec_holds_recycling() {
        assert_holds(RECYCLE, 8, 2, 10_000);
    }

    #[test]
    fn spec_holds_rewind() {
        assert_holds(REWIND, 8, 2, 10_000);
    }

    #[test]
    fn spec_holds_latch() {
        assert_holds(LATCH, 8, 2, 1_000);
    }

    /// Disabling snapshot-time freezing must reintroduce the panel's fatal
    /// finding: a post-snapshot in-place overwrite of a manifested chunk
    /// rolls back a confirmed commit.
    #[test]
    fn mutation_freeze_at_snapshot_detected() {
        let rules = Rules { freeze_at_snapshot: false, ..SPEC };
        assert!(check(CORE, 9, 2, &rules).is_err(), "checker missed the freeze bug");
    }

    /// Disabling shadow tails must reintroduce shared-tail-block loss.
    #[test]
    fn mutation_shadow_tails_detected() {
        let rules = Rules { shadow_tails: false, ..SPEC };
        assert!(check(CORE, 9, 2, &rules).is_err(), "checker missed tail tearing");
    }

    /// Disabling losing-slot zeroing must reintroduce stale-slot
    /// resurrection.
    #[test]
    fn mutation_zero_losing_slot_detected() {
        let rules = Rules { zero_losing_slot: false, ..SPEC };
        let core = check(CORE, 9, 2, &rules);
        let recycle = check(RECYCLE, 8, 2, &rules);
        assert!(
            core.is_err() || recycle.is_err(),
            "checker missed slot resurrection"
        );
    }

    /// Disabling deferred frees must let recycled extents clobber data still
    /// referenced by the fallback commit.
    #[test]
    fn mutation_deferred_frees_detected() {
        let rules = Rules { deferred_frees: false, ..SPEC };
        let core = check(CORE, 9, 2, &rules);
        let recycle = check(RECYCLE, 8, 2, &rules);
        assert!(core.is_err() || recycle.is_err(), "checker missed premature reuse");
    }

    /// Disabling the failure latch must surface a durability lie: a sync
    /// confirms after the fsync that covered its data failed.
    #[test]
    fn mutation_latch_detected() {
        let rules = Rules { latch_on_failure: false, ..SPEC };
        assert!(check(LATCH, 8, 2, &rules).is_err(), "checker missed the latch leak");
    }

    /// Disabling the superblock->table binding (the stored table CRC) must
    /// reintroduce recycled-table-block aliasing: a dropped table write over
    /// a recycled block exposes an older valid table, rolling back a
    /// confirmed commit. This bug was FOUND by this model.
    #[test]
    fn mutation_table_binding_detected() {
        let rules = Rules { bind_table: false, ..SPEC };
        assert!(check(CORE, 9, 2, &rules).is_err(), "checker missed table aliasing");
    }

    /// A torn first init must re-run instead of bricking. Init is TWO syncs:
    /// the table becomes durable before any superblock points at it (a
    /// single-sync init could land the superblock while tearing the table,
    /// and with only one slot there is no fallback — found by this model).
    /// After any crash outcome of either phase, the volume is adoptable at
    /// seq 0 or still recognizably fresh (no valid slot).
    #[test]
    fn init_tearing_rejoins() {
        // Phase 1: table write + sync. Crash outcomes: table virgin or torn
        // or durable; no superblock exists yet -> always "fresh", re-run.
        let mut disk = Disk::empty();
        disk.write(RESERVED, Block::Table(Table::default()));
        for outcome in disk.crash_outcomes() {
            assert!(adopt(&outcome, &SPEC).is_err(), "no superblock yet");
            assert!(
                !matches!(outcome.durable[0], Block::Super { .. })
                    && !matches!(outcome.durable[1], Block::Super { .. }),
            );
        }

        // Phase 2: table durable; superblock write + sync. A valid slot now
        // always implies a readable table.
        let mut disk = Disk::empty();
        disk.durable[RESERVED] = Block::Table(Table::default());
        disk.write(
            0,
            Block::Super { seq: 0, table: RESERVED, bound: Table::default() },
        );
        for outcome in disk.crash_outcomes() {
            match adopt(&outcome, &SPEC) {
                Ok(a) => assert_eq!(a.seq, 0),
                Err(_) => {
                    let no_valid_super = !matches!(outcome.durable[0], Block::Super { .. })
                        && !matches!(outcome.durable[1], Block::Super { .. });
                    assert!(no_valid_super, "valid superblock but adoption failed");
                }
            }
        }
    }
}
