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
//! - Prefix pruning: a per-blob floor below which cells are
//!   dropped and unreadable (see below). The model's floor is
//!   cell-granular; the implementation's floor is BYTE-exact within its
//!   chunk (the sub-chunk refinement only tightens the read/write guard
//!   boundary — it is covered by the end-to-end unit test and the
//!   lockstep floor comparison, not enumerated here).
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
//! # Selective commit
//!
//! [`Action::Snapshot`] takes a blob subset: the commit captures only the
//! dirty blobs in that subset and serves every other blob's table entry
//! verbatim from its last confirmed capture. Uncaptured dirty state stays
//! pending (dirty marks, manifest blocks, and content frees are all
//! deferred to a later commit that captures the blob). Two rules keep this
//! sound:
//!
//! - Content frees are CAPTURE-GATED: an extent dropped by a blob's
//!   uncommitted state change (overwrite COW, rewind) is released only once
//!   a commit that CAPTURES the blob confirms. Freeing at the next commit —
//!   sound under group commit, where every commit captures every dirty
//!   blob — recycles an extent the confirmed table still references (see
//!   `mutation_capture_gated_frees_detected`).
//! - The NEVER-SPLIT rule: a commit that captures one blob of an applied
//!   batch must capture every blob of it. Applied batches form pending
//!   atomic groups (merged when they share blobs, cleared when committed)
//!   and capture sets are expanded across them. A group holding a removed
//!   blob is captured by every commit, because every commit drops the
//!   removed entry.
//!
//! # Batches
//!
//! A batch stages writes across blobs, then publishes them atomically.
//! Staging writes through to disk immediately, but staged bytes stay
//! INVISIBLE to snapshots until [`Action::BatchApply`] publishes them:
//! staged placement lands in place only in space no snapshot can capture
//! (batch-private extents, or cells at or beyond BOTH the blob's published
//! size and its freeze boundary — the shared tail block's committed cell
//! stays shadow-protected exactly as for unbatched appends); staged
//! overwrites of published cells relocate to fresh extents that no table
//! references until apply. A batch dropped without apply (or lost to a
//! crash) leaves only writes to unreferenced space. Apply is blocked while
//! a commit is in flight (the commit lock), so a snapshot can never observe
//! a half-applied batch. A blob with staged batch content has ONE writer —
//! the batch — until apply/drop: a direct write into the staged region
//! would rewrite bytes whose staged expected content the batch already
//! recorded (found by this model; it is the Blob contract's writer
//! exclusivity applied to the batch as a deferred writer).
//!
//! A batch can also stage a blob REMOVAL ([`Action::BatchRemove`]),
//! resolved at apply against the PRE-publish state — so a batch may
//! remove a slot and recreate it, and the removal never touches the
//! staged recreation. Removal-bearing batches publish and begin their
//! commit in ONE step (every commit drops a removed slot's entry, so an
//! interleaving commit would make the removal durable without the
//! batch's other members — see `mutation_remove_commit_detected`). And a
//! batch can join a slot for MEMBERSHIP only ([`Action::BatchSync`],
//! Batch::sync): its directly written dirt commits with the group, the
//! slot stays writable outside the batch, and a later staged write
//! REBASES to the then-current published size (direct growth between the
//! touch and the first staged write is never misread as a staged
//! shrink).
//!
//! A batch can also stage a blob CREATION ([`Action::BatchCreate`]): the
//! blob does not exist until apply publishes it. A batch that stages
//! creations ALONGSIDE anything else publishes and begins its commit in
//! ONE step (the implementation's `apply_sync` holds the commit lock
//! across both, and plain apply rejects such batches). This is
//! load-bearing: table assembly emits an entry for EVERY live blob, so a
//! published-but-uncommitted creation would be made durable by any
//! unrelated commit without the batch's other members (see
//! `mutation_create_commit_detected`). A batch staging ONLY creations is
//! exempt and publishes WITHOUT its own commit: every member is an empty
//! creation, so whatever commit comes next emits all of their entries
//! together, and a crash before any commit erases them together (see
//! `mutation_commit_free_gate_detected` for the boundary).
//!
//! # Prefix pruning
//!
//! [`Action::Prune`] advances a blob's pruned FLOOR by one block: cells
//! below the floor drop, and reads, writes, and shrinks into them become
//! illegal (below-floor mutations are simply never enumerated, like other
//! contract violations). Pruning is a MUTATION, not a durability point:
//! it marks the blob dirty, the next commit CAPTURING the blob records
//! the floor in its entry, and the dropped blocks join the same
//! capture-gated free discipline as COW and rewind drops (the last
//! confirmed table still references them). Recovery restores the ADOPTED
//! commit's floor: a floor whose pruning commit never landed regresses
//! and its cells are readable again — prefix bytes reappear, never the
//! reverse (I7). A removed-then-recreated blob starts back at floor
//! zero with its new generation. Pruning a blob over which a batch holds
//! staged state — membership included — violates the implementation's
//! single-writer assertion and is never enumerated. For group capture,
//! pruning is ordinary dirt: never-split needs no prune-specific rule.
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
//! - I6 (never-split): every attempted commit resolves each applied batch
//!   entirely or not at all — no snapshot captures one blob of an applied
//!   batch while leaving another blob's part uncommitted. Combined with I2,
//!   no recovered state can hold a partial batch.
//! - I7 (floor durability): every recovery restores exactly the adopted
//!   commit's floor — never the crashed process's live floor — and once a
//!   commit confirming a floor is observed durable, no later recovery
//!   serves a pruned part below it for the same generation.
//!
//! Each protocol safeguard can be individually disabled via [`Rules`]; tests
//! assert the checker FINDS a violation for every disabled safeguard
//! (mutation-testing the model) and finds none with all safeguards enabled.
//!
//! # Three layers of trust
//!
//! The volume's crash story is checked at three layers, each covering the
//! blind spots of the one above it:
//!
//! 1. THE MODEL (this module) checks the PROTOCOL exhaustively: every
//!    interleaving of the bounded workloads, every per-block crash
//!    resolution, every re-crash during recovery. It proves the protocol's
//!    decisions, but over an abstract volume whose bookkeeping is correct
//!    by construction — implementation state the model does not carry
//!    (tail buffers, CRC caches, allocator bookkeeping, RAM counters) is
//!    outside its reach, and a model that diverges from the code proves
//!    nothing about the code.
//! 2. TRACE CONFORMANCE (the `conformance` module) checks that the
//!    IMPLEMENTATION REFINES the model on enumerated histories: each
//!    bounded workload is executed against the REAL volume, crashes are
//!    materialized at the model's block granularity (every pending inner
//!    write independently lands, vanishes, or tears), and the recovered
//!    real state must be one of the states the model allows for exactly
//!    that history. The correspondence between model and implementation is
//!    CHECKED there, not assumed here. `step`, [`initial_state`], and the
//!    state internals are exposed to that module for lockstep execution.
//! 3. CANCELLATION INJECTION (also `conformance`) covers the class BELOW
//!    the model: caller futures dropped at every await boundary. Commits
//!    execute in runtime-driven tasks and callers only observe, so the
//!    injector pins that every drop point is BENIGN (the commit lands
//!    regardless). The one remaining cancellation hazard — a driver task
//!    aborted mid-commit at runtime teardown — poisons, pinned by a
//!    directed unit test.
//!
//! What remains uncovered by all three layers: platform I/O semantics (the
//! block-granular tearing model, the fsyncgate cache model, and
//! neighboring-block isolation — a crashed write may tear only the blocks
//! it touched, never disturbing others, which is SQLite's "powersafe
//! overwrite" assumption at block granularity and is implicit in the crash
//! fan only resolving WRITTEN blocks — are assumptions about the OS and
//! device, not checked facts), wall-clock effects,
//! reader/writer async interleavings (see below), and staged batch resize
//! (`Batch::resize` has no model action — its shrink-into-hole regressions
//! are pinned by unit tests in `tests`). Batch operations over blobs with a
//! NONZERO pruned floor are likewise unenumerated: `BatchOverwrite` is
//! gated off at `floor > 0` and staged resize has no action, so only
//! `BatchAppend` ever runs against a pruned blob. The `publish_overlay`
//! shrink-to-floor defect lived exactly in that gap and is pinned by
//! `tests::test_volume_batch_shrink_to_pruned_floor`. Enumerating batch
//! ops over pruned blobs is a future model extension that needs a
//! state-space budget. The checksum-extent lifecycle is
//! also uncovered: the model inlines expected chunk content into the
//! superblock-bound table, so the implementation's separately stored
//! commit-written checksum extents — the whole-extent guard CRCs,
//! recovery's unconditional last-ref load, and the `MAX_CHECKSUM_REFS`
//! compaction commit — sit outside all exhaustive checking. The scale
//! soak in `tests` drives that lifecycle at size (ref compaction, overlay
//! eviction, and committed-CRC paging) under materialized power loss
//! against a history oracle, but it samples seeded histories rather than
//! enumerating them. The same soak covers pruning at scale: its prune arm
//! and scripted large-floor crashes (committed, regressed, and parked
//! mid-commit) drive the floor's interaction with checksum-ref dropping,
//! compaction, and paging at size (see `commit::finalize` and the
//! recovery ref-window checks), sampled under the same caveat. Prune
//! ENUMERATION is block-granular: the model's prune action advances by
//! whole chunks and the conformance `extract` asserts block-aligned
//! floors, so mid-chunk floors are covered only by the directed
//! `tests::test_volume_prune_end_to_end` and the scale soak.
//!
//! # Deliberately out of scope
//!
//! Reader/writer async interleavings (the implementation serializes writers
//! per blob and readers use generation-validated retry), blob handles and
//! read-after-remove liveness (RAM-only bookkeeping), partitions/naming, and
//! `remove` durability (modeled as a table change committed by the next
//! sync — crash-equivalent, since an uncommitted remove never happened).

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

/// Total blocks (blocks 0/1 are superblock slots).
const BLOCKS: usize = 12;
/// First allocatable block.
const RESERVED: usize = 2;
/// Logical cells per block.
pub(super) const CELLS_PER_BLOCK: u8 = 2;
/// Blobs in the workload.
pub(super) const BLOBS: u8 = 3;
/// Maximum committed cells per blob (bounds the space).
pub(super) const MAX_CELLS: u8 = 4;

/// A logical cell value.
///
/// `Val` versions resume from the adopted state after recovery, so a replayed
/// history writes byte-identical values — this is what reproduces the
/// stale-slot resurrection scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum Cell {
    /// Zeros: holes and explicit zero fill are logically identical.
    Zero,
    /// Unverifiable residue in an uncommitted region (never expected).
    Garbage,
    Val {
        slot: u8,
        gen: u8,
        cell: u8,
        ver: u8,
    },
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
    /// Committed pruned floor in cells (block-aligned, at most `size`):
    /// cells below were dropped and are never served.
    floor: u8,
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
    fn crash_outcomes(&self) -> Vec<Self> {
        let mut outcomes = vec![Self {
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
pub(super) struct BlobState {
    pub(super) live: bool,
    pub(super) gen: u8,
    pub(super) size: u8,
    /// Live pruned floor in cells (block-aligned, at most `size`): cells
    /// below were dropped, and reads, writes, and shrinks into them are
    /// illegal. Monotonic in RAM, while recovery restores the adopted
    /// commit's floor (I7).
    pub(super) floor: u8,
    /// Logical block -> run. Absent = hole.
    runs: BTreeMap<u8, Run>,
    /// Durable shadow block from the last commit covering this blob.
    shadow: Option<usize>,
    /// Per-cell version counters (deterministic, replay-identical values).
    pub(super) vers: BTreeMap<u8, u8>,
    /// Blocks with content changes since the last capture of this blob.
    dirty_blocks: Vec<u8>,
    dirty: bool,
    /// The entry written by the last confirmed commit that resolved this
    /// blob, served verbatim when a selective commit does not capture it.
    committed: Option<Entry>,
    /// Publish counter, bumped when a batch publishes into this blob.
    pubseq: u64,
    /// `pubseq` as of the last confirmed capture (never-split bookkeeping).
    committed_pubseq: u64,
    /// Blocks dropped by uncommitted state changes (COW, rewind), released
    /// once a commit capturing this blob confirms.
    pending_frees: Vec<usize>,
}

/// One staged run in a batch overlay.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct StagedRun {
    run: Run,
    /// The backing block was allocated by the batch (invisible to every
    /// snapshot and table): always writable in place.
    private: bool,
}

/// One blob's staged overlay in an unapplied batch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct StagedSlot {
    /// Staged logical size (starts at the published size).
    pub(super) size: u8,
    /// Staged run overlay: replaces the published run at the same block.
    runs: BTreeMap<u8, StagedRun>,
    /// Blocks allocated by the batch (freed if it is dropped unapplied).
    fresh: Vec<usize>,
    /// Published blocks replaced by staged COW (pending-freed at apply).
    replaced: Vec<usize>,
    /// The slot is a staged CREATION: the blob does not exist until apply
    /// publishes it (and, per the spec, immediately begins its commit).
    pub(super) created: bool,
    /// MEMBERSHIP only (Batch::sync): the slot joins the batch's group so
    /// its directly written dirt commits with it, but no content is
    /// staged — the slot stays writable outside the batch, and a later
    /// staged write REBASES to the then-current published size.
    pub(super) member: bool,
}

/// A staged (unapplied) batch: per-slot overlays plus staged removals.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub(super) struct Batch {
    pub(super) slots: BTreeMap<u8, StagedSlot>,
    /// Slots staged for removal, resolved at apply against the
    /// PRE-publish state (so a batch may remove a slot and recreate it).
    /// Removal-bearing batches commit in-step
    /// ([`Rules::atomic_remove_commit`]).
    pub(super) removals: BTreeSet<u8>,
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
    /// (slot, pubseq at snapshot) for every slot this commit resolves:
    /// captured live blobs and dropped (removed) blobs.
    resolved: Vec<(u8, u64)>,
}

/// The volume's RAM state (dies with the process).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct Volume {
    pub(super) blobs: Vec<BlobState>,
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
    /// The staged (unapplied) batch, if any. At most one at a time.
    pub(super) batch: Option<Batch>,
    /// Applied-but-uncommitted atomic groups: disjoint slot sets, merged
    /// when batches share slots, cleared when a commit resolves them.
    groups: Vec<Vec<u8>>,
    /// Applied-but-uncommitted batches: slot -> Some((pubseq at apply,
    /// created-by-batch)), or None once the slot was resolved by removal.
    /// Checked at every snapshot for the never-split invariant (I6).
    pending_batches: Vec<BTreeMap<u8, Option<(u64, bool)>>>,
}

/// A pure logical view: per slot, (generation, pruned floor, committed
/// cells at and above the floor). Holes and explicit zeros both read as
/// `Cell::Zero` — callers cannot distinguish.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub(super) struct Logical {
    pub(super) blobs: Vec<Option<(u8, u8, Vec<Cell>)>>,
}

/// Protocol safeguards. Production = all enabled; tests disable one at a
/// time to prove the checker detects each corresponding bug class.
#[derive(Clone, Copy, Debug)]
pub(super) struct Rules {
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
    /// Expand every capture set across applied-batch groups (never-split).
    /// Disabling lets a selective commit persist a partial batch (I6).
    respect_groups: bool,
    /// Keep staged batch bytes invisible to snapshots until apply.
    /// Disabling models a capture that reads staged state: the recorded
    /// table vouches for bytes the API never published (I2/I3).
    stage_invisible: bool,
    /// Gate content frees on a commit that captures the owning blob.
    /// Disabling frees at the next commit even when that commit did not
    /// write the blob's new entry, recycling extents the confirmed table
    /// still references.
    capture_gated_frees: bool,
    /// Publish a batch that stages creations ALONGSIDE anything else and
    /// begin its commit atomically (the implementation's apply_sync holds
    /// the commit lock across both, and plain apply rejects such batches).
    /// Disabling lets an unrelated commit run between publish and the
    /// batch's commit: table assembly emits an entry for EVERY live blob,
    /// so that commit persists the creation while the batch's other
    /// members stay uncommitted (I6).
    atomic_create_commit: bool,
    /// Restrict commit-free publish to batches staging ONLY creations
    /// (the implementation's apply asserts nothing else is staged). A
    /// creation-only batch is safe without its own commit because every
    /// member is an empty creation: any commit emits every live blob's
    /// entry, so the members resolve together, and a crash before any
    /// commit erases them together. Disabling extends the commit-free
    /// path to every creation-bearing batch, bypassing
    /// `atomic_create_commit` and splitting mixed batches exactly as
    /// described there (I6).
    commit_free_creation_gate: bool,
    /// Publish a batch that stages REMOVALS and begin its commit in ONE
    /// step (the implementation's apply_sync requirement for removals).
    /// Disabling lets an unrelated commit run between publish and the
    /// batch's commit: every commit drops a removed slot's entry, so the
    /// removal becomes durable while the batch's staged writes stay
    /// uncommitted (I6).
    atomic_remove_commit: bool,
    /// Include the tail block in the manifest whenever a capture writes a
    /// FRESH shadow, so verification always checks the shadow's content
    /// against the committed tail before adoption. Every capture with a
    /// partial backed tail writes a fresh shadow — even when no dirt
    /// touched the tail block — and recovery's splice is a raw byte copy
    /// that cannot tell a torn shadow from a valid one. Disabling lets a
    /// commit whose dirt avoids the tail block adopt with a torn shadow,
    /// which the splice then writes over the intact committed tail (I3).
    manifest_fresh_shadow: bool,
    /// Route pruned extents through the same capture-gated discipline as
    /// COW and rewind drops (released only once a commit CAPTURING the
    /// blob confirms). Disabling frees them at the next commit even when
    /// that commit serves the blob's old entry verbatim — an entry that
    /// still references the pruned extents, which the recycled table
    /// write then clobbers (I3, via the extent-reuse machinery).
    prune_capture_gated: bool,
    /// Restore each blob's floor from the adopted commit's entry at
    /// recovery. Disabling models an implementation that persists the
    /// floor outside the commit protocol: the crashed process's live
    /// floor survives recovery, making a prune durable without its
    /// commit (I7).
    floor_from_commit: bool,
}

pub(super) const SPEC: Rules = Rules {
    freeze_at_snapshot: true,
    shadow_tails: true,
    zero_losing_slot: true,
    deferred_frees: true,
    latch_on_failure: true,
    bind_table: true,
    respect_groups: true,
    stage_invisible: true,
    capture_gated_frees: true,
    atomic_create_commit: true,
    commit_free_creation_gate: true,
    atomic_remove_commit: true,
    manifest_fresh_shadow: true,
    prune_capture_gated: true,
    floor_from_commit: true,
};

/// Capture mask covering every blob (group-commit behavior).
pub(super) const ALL: u8 = (1 << BLOBS) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    Append(u8),
    /// Overwrite cell 0 (exercises the freeze rule / COW).
    Overwrite(u8),
    /// Shrink by one cell (rewind).
    ResizeDown(u8),
    /// Grow by two hole cells.
    ResizeUp(u8),
    Remove(u8),
    Recreate(u8),
    /// Advance the slot's pruned floor by one block (Blob::prune): cells
    /// below drop into the capture-gated free discipline and the blob
    /// dirties so the next capture records the floor. Never enumerated
    /// past the size (the implementation errors), on a removed blob, or
    /// while a batch holds staged state for the blob — membership
    /// included (the implementation's single-writer assertion).
    Prune(u8),
    /// Begin a commit capturing the dirty blobs in the mask (expanded
    /// across applied-batch groups).
    Snapshot(u8),
    WriteMeta,
    FsyncOk,
    FsyncFail,
    Crash,
    /// Stage one append into the current batch (starting one if needed).
    BatchAppend(u8),
    /// Stage an overwrite of cell 0 into the current batch.
    BatchOverwrite(u8),
    /// Stage the creation of a (removed, or removal-staged) blob into the
    /// current batch.
    BatchCreate(u8),
    /// Join the current batch's group without staging content
    /// (Batch::sync): the slot's directly written dirt commits with the
    /// group, and the slot stays writable outside the batch.
    BatchSync(u8),
    /// Stage the slot's removal into the current batch (Batch::remove),
    /// resolved at apply against the pre-publish state.
    BatchRemove(u8),
    /// Atomically publish the staged batch. A batch staging removals — or
    /// creations alongside anything else — also begins its commit in the
    /// same step (the apply_sync requirement). A creation-ONLY batch
    /// publishes commit-free.
    BatchApply,
    /// Drop the staged batch without applying it.
    BatchDrop,
}

/// Committed-cell coverage of logical block `lblock` for a blob of `size`.
fn coverage(size: u8, lblock: u8) -> u8 {
    size.saturating_sub(lblock * CELLS_PER_BLOCK)
        .min(CELLS_PER_BLOCK)
}

impl Volume {
    fn fresh() -> Self {
        Self {
            blobs: (0..BLOBS)
                .map(|_| BlobState {
                    live: true,
                    ..Default::default()
                })
                .collect(),
            free: (RESERVED..BLOCKS).collect(),
            pending_free: Vec::new(),
            seq: 1,
            sacred: 0,
            last_table: usize::MAX,
            in_flight: None,
            poisoned: false,
            batch: None,
            groups: Vec::new(),
            pending_batches: Vec::new(),
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

    /// Release a block dropped by a blob's uncommitted state change:
    /// capture-gated (held until a commit capturing `slot` confirms), so a
    /// confirmed table that still serves the blob's old entry keeps its
    /// backing allocated. Meaningful only on top of deferred frees.
    fn release_content(&mut self, slot: u8, block: usize, rules: &Rules) {
        if rules.capture_gated_frees && rules.deferred_frees {
            self.blobs[slot as usize].pending_frees.push(block);
        } else {
            self.release(block, rules);
        }
    }

    /// Merge `slots` into the applied-batch groups (shared slots coalesce).
    fn merge_group(&mut self, slots: &[u8]) {
        let mut merged: Vec<u8> = slots.to_vec();
        self.groups.retain(|group| {
            if group.iter().any(|slot| merged.contains(slot)) {
                merged.extend_from_slice(group);
                false
            } else {
                true
            }
        });
        merged.sort_unstable();
        merged.dedup();
        self.groups.push(merged);
    }

    fn next_val(&mut self, slot: u8, cell: u8) -> Cell {
        let b = &mut self.blobs[slot as usize];
        let ver = b.vers.entry(cell).or_insert(0);
        *ver += 1;
        Cell::Val {
            slot,
            gen: b.gen,
            cell,
            ver: *ver,
        }
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
    pub(super) fn logical(&self) -> Logical {
        let mut blobs = Vec::new();
        for b in &self.blobs {
            if !b.live {
                blobs.push(None);
                continue;
            }
            let cells = (b.floor..b.size)
                .map(|i| {
                    b.runs
                        .get(&(i / CELLS_PER_BLOCK))
                        .map_or(Cell::Zero, |run| {
                            if i.is_multiple_of(CELLS_PER_BLOCK) {
                                run.cells.0
                            } else {
                                run.cells.1
                            }
                        })
                })
                .collect();
            blobs.push(Some((b.gen, b.floor, cells)));
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
                let cells = if idx == 0 {
                    (val, Cell::Zero)
                } else {
                    (Cell::Zero, val)
                };
                disk.write(phys, Block::Data(cells.0, cells.1));
                self.blobs[slot as usize].runs.insert(
                    lblock,
                    Run {
                        phys,
                        cells,
                        frozen: 0,
                    },
                );
            }
            Some(run) => {
                let cells = if idx == 0 {
                    (val, run.cells.1)
                } else {
                    (run.cells.0, val)
                };
                if idx >= run.frozen {
                    disk.write(run.phys, Block::Data(cells.0, cells.1));
                    self.blobs[slot as usize]
                        .runs
                        .insert(lblock, Run { cells, ..run });
                } else {
                    let phys = self.allocate();
                    disk.write(phys, Block::Data(cells.0, cells.1));
                    self.release_content(slot, run.phys, rules);
                    self.blobs[slot as usize].runs.insert(
                        lblock,
                        Run {
                            phys,
                            cells,
                            frozen: 0,
                        },
                    );
                }
            }
        }
        self.mark_dirty(slot, Some(lblock));
    }

    /// Stage `val` at `cell` into the current batch's overlay for `slot`.
    ///
    /// Placement mirrors the implementation's batch rule: batch-private
    /// blocks are written in place; a published block is written in place
    /// only for cells at or beyond BOTH the published size and the block's
    /// frozen coverage (unpublished cells no snapshot can capture);
    /// anything else relocates to a fresh private block seeded with the
    /// published content.
    fn stage_cell(&mut self, disk: &mut Disk, slot: u8, cell: u8, val: Cell) {
        let lblock = cell / CELLS_PER_BLOCK;
        let idx = cell % CELLS_PER_BLOCK;
        let published = self.blobs[slot as usize].size;
        let base = self.blobs[slot as usize].runs.get(&lblock).cloned();
        let mut batch = self.batch.take().expect("staging requires a batch");
        {
            let staged = batch.slots.get_mut(&slot).expect("staged slot exists");
            let merge = |cells: (Cell, Cell)| {
                if idx == 0 {
                    (val, cells.1)
                } else {
                    (cells.0, val)
                }
            };
            match staged.runs.get(&lblock).cloned() {
                Some(sr) => {
                    let writable = sr.private || (cell >= published && idx >= sr.run.frozen);
                    if writable {
                        let cells = merge(sr.run.cells);
                        disk.write(sr.run.phys, Block::Data(cells.0, cells.1));
                        staged.runs.insert(
                            lblock,
                            StagedRun {
                                run: Run { cells, ..sr.run },
                                private: sr.private,
                            },
                        );
                    } else {
                        // Staged COW of a base-shared overlay block: the
                        // fresh block carries the overlay content and the
                        // published block is replaced at apply.
                        let phys = self.allocate();
                        let cells = merge(sr.run.cells);
                        disk.write(phys, Block::Data(cells.0, cells.1));
                        staged.replaced.push(sr.run.phys);
                        staged.fresh.push(phys);
                        staged.runs.insert(
                            lblock,
                            StagedRun {
                                run: Run {
                                    phys,
                                    cells,
                                    frozen: 0,
                                },
                                private: true,
                            },
                        );
                    }
                }
                None => match base {
                    Some(run) if cell >= published && idx >= run.frozen => {
                        // In-place into the published run's block, beyond
                        // everything a snapshot can capture.
                        let cells = merge(run.cells);
                        disk.write(run.phys, Block::Data(cells.0, cells.1));
                        staged.runs.insert(
                            lblock,
                            StagedRun {
                                run: Run { cells, ..run },
                                private: false,
                            },
                        );
                    }
                    Some(run) => {
                        // Staged COW of a published block.
                        let phys = self.allocate();
                        let cells = merge(run.cells);
                        disk.write(phys, Block::Data(cells.0, cells.1));
                        staged.replaced.push(run.phys);
                        staged.fresh.push(phys);
                        staged.runs.insert(
                            lblock,
                            StagedRun {
                                run: Run {
                                    phys,
                                    cells,
                                    frozen: 0,
                                },
                                private: true,
                            },
                        );
                    }
                    None => {
                        // Unbacked block: fresh private block.
                        let phys = self.allocate();
                        let cells = if idx == 0 {
                            (val, Cell::Zero)
                        } else {
                            (Cell::Zero, val)
                        };
                        disk.write(phys, Block::Data(cells.0, cells.1));
                        staged.fresh.push(phys);
                        staged.runs.insert(
                            lblock,
                            StagedRun {
                                run: Run {
                                    phys,
                                    cells,
                                    frozen: 0,
                                },
                                private: true,
                            },
                        );
                    }
                },
            }
        }
        self.batch = Some(batch);
    }

    /// The logical state a commit capturing exactly `captured` records:
    /// captured blobs contribute their live (published) state, everything
    /// else its last confirmed capture. This is spec-derived — independent
    /// of the (possibly rule-disabled) table assembly — so a visibility
    /// leak surfaces as an I2 mismatch.
    fn selective_logical(&self, captured: &HashSet<u8>) -> Logical {
        let live = self.logical();
        let mut blobs = Vec::new();
        for (slot, b) in self.blobs.iter().enumerate() {
            if !b.live {
                blobs.push(None);
            } else if captured.contains(&(slot as u8)) {
                blobs.push(live.blobs[slot].clone());
            } else {
                blobs.push(Some(b.committed.as_ref().map_or_else(
                    || (b.gen, 0, Vec::new()),
                    |entry| (entry.gen, entry.floor, entry_cells(entry)),
                )));
            }
        }
        Logical { blobs }
    }
}

/// The committed cells an entry describes, floor..size (holes read as
/// zeros).
fn entry_cells(entry: &Entry) -> Vec<Cell> {
    (entry.floor..entry.size)
        .map(|i| {
            entry
                .runs
                .get(&(i / CELLS_PER_BLOCK))
                .map_or(Cell::Zero, |&(_, c0, c1)| {
                    if i.is_multiple_of(CELLS_PER_BLOCK) {
                        c0
                    } else {
                        c1
                    }
                })
        })
        .collect()
}

/// Verify a candidate's delta manifest against the disk, using shadows as the
/// authority for the frozen cell of partial tail blocks.
fn verify_manifest(disk: &Disk, table: &Table) -> bool {
    for &(slot, lblock) in &table.manifest {
        let Some(entry) = table.blobs.get(&slot) else {
            continue;
        };
        let Some(&(phys, c0, c1)) = entry.runs.get(&lblock) else {
            continue;
        };
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
                    if entry.shadow.is_some() {
                        shadow_ok()
                    } else {
                        *d0 == c0
                    }
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
    let expected = if cell.is_multiple_of(CELLS_PER_BLOCK) {
        c0
    } else {
        c1
    };
    match disk.read(phys) {
        Block::Data(d0, d1) => {
            let got = if cell.is_multiple_of(CELLS_PER_BLOCK) {
                *d0
            } else {
                *d1
            };
            if got == expected {
                Ok(got)
            } else {
                Err(format!(
                    "phys {phys}: cell {cell} = {got:?}, expected {expected:?}"
                ))
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
        for i in entry.floor..entry.size {
            cells.push(read_cell(disk, entry, i)?);
        }
        blobs[slot as usize] = Some((entry.gen, entry.floor, cells));
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

/// Build the post-recovery RAM state for an adopted table. `crashed` holds
/// the crashed process's live (generation, floor) per slot, consumed only
/// by the [`Rules::floor_from_commit`] mutation.
fn rebuild(adopted: &Adopted, crashed: &[Option<(u8, u8)>], rules: &Rules) -> Volume {
    let mut used = vec![adopted.table_block];
    let mut volume = Volume::fresh();
    volume.blobs = (0..BLOBS)
        .map(|s| {
            let Some(e) = adopted.table.blobs.get(&s) else {
                return BlobState::default();
            };
            let floor = if rules.floor_from_commit {
                e.floor
            } else {
                // Mutation: the crashed process's live floor survives
                // recovery when its generation matches the adopted entry
                // (a floor persisted outside the commit protocol).
                match crashed.get(s as usize).copied().flatten() {
                    Some((gen, floor)) if gen == e.gen => e.floor.max(floor),
                    _ => e.floor,
                }
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
                floor,
                runs: e
                    .runs
                    .iter()
                    .map(|(&l, &(phys, c0, c1))| {
                        (
                            l,
                            Run {
                                phys,
                                cells: (c0, c1),
                                frozen: coverage(e.size, l),
                            },
                        )
                    })
                    .collect(),
                shadow: e.shadow,
                vers,
                dirty_blocks: Vec::new(),
                dirty: false,
                committed: Some(e.clone()),
                pubseq: 0,
                committed_pubseq: 0,
                pending_frees: Vec::new(),
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
        let (Some(&(phys, _, _)), Some(shadow)) = (entry.runs.get(&tail), entry.shadow) else {
            continue;
        };
        // The splice is a RAW byte copy: the implementation cannot tell a
        // torn shadow block from a valid one at this point, so the model
        // must not either — whatever the shadow block holds is written
        // over the tail cell (garbage if torn/virgin/recycled). Manifest
        // verification is what keeps an unverified shadow from ever being
        // adopted (see `Rules::manifest_fresh_shadow`).
        let sc = match disk.read(shadow) {
            Block::Shadow(sc) => *sc,
            _ => Cell::Garbage,
        };
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
pub(super) struct State {
    disk: Disk,
    pub(super) volume: Volume,
    /// The last logical state observed as durable by this process lineage.
    baseline: Logical,
    /// Snapshots of commits attempted since the baseline was observed.
    attempts: Vec<Logical>,
    /// A commit failed; no further sync may report success (I4).
    latched: bool,
    pub(super) actions_left: u8,
    pub(super) crashes_left: u8,
}

/// A violation with its full trace.
#[derive(Debug)]
pub(super) struct Violation {
    pub(super) trace: Vec<Action>,
    pub(super) reason: String,
}

pub(super) fn initial_state(actions: u8, crashes: u8) -> State {
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
    disk.durable[0] = Block::Super {
        seq: 0,
        table: RESERVED,
        bound: init_table.clone(),
    };
    disk.durable[RESERVED] = Block::Table(init_table);
    let mut volume = Volume::fresh();
    volume.free.retain(|&b| b != RESERVED);
    volume.last_table = RESERVED;
    for blob in &mut volume.blobs {
        blob.committed = Some(Entry::default());
    }
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

/// The crashed process's view that recovery's invariants bind to: the last
/// observed durable state, the commits attempted since, and each live
/// blob's (generation, floor) for [`rebuild`]'s floor-restore mutation
/// hook.
struct CrashContext<'a> {
    baseline: &'a Logical,
    attempts: &'a [Logical],
    crashed: &'a [Option<(u8, u8)>],
}

/// Recovery as a process: adopt, check invariants, queue repairs, then either
/// finish cleanly or crash again mid-repair (recursively, budget permitting).
fn recovery_states(
    disk: Disk,
    ctx: &CrashContext<'_>,
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
    if logical != *ctx.baseline && !ctx.attempts.contains(&logical) {
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
                 {:?}\n  attempts: {:?}\n  durable disk:\n{dump}",
                adopted.slot, adopted.seq, ctx.baseline, ctx.attempts
            ),
        });
    }

    // I7 (regression arm): once a commit confirming a floor was observed
    // durable, no recovery may serve parts below it for the same
    // generation. Subsumed by I1/I2 while floors ride the logical view —
    // stated directly so floor bookkeeping bugs report as what they are.
    for (slot, base) in ctx.baseline.blobs.iter().enumerate() {
        let (Some((bgen, bfloor, _)), Some((agen, afloor, _))) =
            (base.as_ref(), logical.blobs[slot].as_ref())
        else {
            continue;
        };
        if agen == bgen && afloor < bfloor {
            return Err(Violation {
                trace: trace.to_vec(),
                reason: format!(
                    "I7: pruned-and-confirmed prefix served again on slot {slot}: \
                     adopted floor {afloor} below confirmed floor {bfloor}"
                ),
            });
        }
    }

    let mut out = Vec::new();

    // (a) Repairs sync cleanly; recovery returns; adopted state is observed.
    {
        let volume = rebuild(&adopted, ctx.crashed, rules);
        // I7 (restore arm): the recovered floor is exactly the adopted
        // commit's — never the crashed process's live floor, whose pruning
        // commit may never have landed.
        for slot in 0..BLOBS {
            let b = &volume.blobs[slot as usize];
            let entry_floor = adopted.table.blobs.get(&slot).map_or(0, |e| e.floor);
            if b.live && b.floor != entry_floor {
                return Err(Violation {
                    trace: trace.to_vec(),
                    reason: format!(
                        "I7: recovered floor {} diverges from the adopted commit's \
                         {entry_floor} on slot {slot}",
                        b.floor
                    ),
                });
            }
        }
        let mut disk = repaired.clone();
        disk.sync();
        out.push(State {
            disk,
            volume,
            baseline: logical,
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
                ctx,
                rules,
                crashes_left - 1,
                actions_left,
                &next_trace,
            )?);
        }
    }
    Ok(out)
}

/// Begin a commit capturing the dirty live blobs in `mask` (the RAM snapshot
/// phase). Returns `Ok(false)` when the commit would not change the table
/// (the action is disabled). Callers check `syncs_blocked` and
/// `in_flight.is_none()` first.
fn begin_snapshot(
    s: &mut State,
    mask: u8,
    rules: &Rules,
    trace: &[Action],
) -> Result<bool, Violation> {
    // The capture set: requested dirty live blobs, expanded across
    // applied-batch groups (never-split). Groups holding a removed
    // blob are captured by every commit — every commit drops the
    // removed entry, so its siblings' batch parts must land with it.
    let mut captured: HashSet<u8> = (0..BLOBS)
        .filter(|&slot| {
            let b = &s.volume.blobs[slot as usize];
            mask & (1 << slot) != 0 && b.dirty && b.live
        })
        .collect();
    if rules.respect_groups {
        for group in &s.volume.groups {
            let touches = group.iter().any(|&slot| captured.contains(&slot))
                || group
                    .iter()
                    .any(|&slot| !s.volume.blobs[slot as usize].live);
            if touches {
                captured.extend(
                    group
                        .iter()
                        .filter(|&&slot| s.volume.blobs[slot as usize].live),
                );
            }
        }
    }
    // Enabled only when the commit changes the table: a captured
    // dirty blob or a pending removal.
    let removal_pending = s.volume.blobs.iter().any(|b| !b.live && b.dirty);
    if captured.is_empty() && !removal_pending {
        return Ok(false);
    }

    // I6 (never-split): each applied batch must resolve entirely or
    // not at all. A part is resolved if this commit captures its slot,
    // an earlier commit did (committed_pubseq), or it is a CREATION —
    // always empty in this model — whose entry table assembly emits
    // for every live blob, so any commit makes the creation durable
    // regardless of capture. A part on a DEAD slot is a staged REMOVAL
    // (Action::Remove nulls parts instead): every commit drops the
    // removed entry, so this commit resolves it. Removal-nulled parts
    // (None) count on NEITHER side: the removal already resolved them
    // and only their siblings' capture state matters, so counting a
    // nulled part as included would flag a remove-then-recreate history
    // as a split batch while a live sibling stays legitimately
    // uncaptured (see `removed_then_recreated_part_not_counted`).
    for pb in &s.volume.pending_batches {
        let resolved = |slot: u8, (bp, created): (u64, bool)| {
            created
                || captured.contains(&slot)
                || !s.volume.blobs[slot as usize].live
                || s.volume.blobs[slot as usize].committed_pubseq >= bp
        };
        let parts: Vec<(u8, (u64, bool))> = pb
            .iter()
            .filter_map(|(&sl, bp)| bp.map(|p| (sl, p)))
            .collect();
        let included = parts.iter().filter(|&&(sl, p)| resolved(sl, p)).count();
        if included > 0 && included < parts.len() {
            return Err(Violation {
                trace: trace.to_vec(),
                reason: format!(
                    "I6: commit captures a partial batch: capture {captured:?}, \
                     batch {pb:?}"
                ),
            });
        }
    }

    let seq = s.volume.seq;
    s.volume.seq += 1;
    let table_block = s.volume.allocate();
    let mut table = Table::default();
    let mut shadows = Vec::new();
    let mut frees = Vec::new();
    let mut resolved = Vec::new();
    if s.volume.last_table != usize::MAX {
        frees.push(s.volume.last_table);
    }
    for slot in 0..BLOBS {
        if !s.volume.blobs[slot as usize].live {
            // The entry is dropped by every commit; the removal is
            // resolved when this commit confirms.
            if s.volume.blobs[slot as usize].dirty {
                s.volume.blobs[slot as usize].dirty = false;
                s.volume.blobs[slot as usize].dirty_blocks.clear();
                resolved.push((slot, s.volume.blobs[slot as usize].pubseq));
            }
            continue;
        }
        if !captured.contains(&slot) {
            // Served verbatim from the last confirmed capture; dirty
            // state (marks, manifest blocks, content frees) stays
            // pending for a later capturing commit.
            let b = &s.volume.blobs[slot as usize];
            let mut entry = b.committed.clone().unwrap_or(Entry {
                gen: b.gen,
                ..Default::default()
            });
            // Visibility-leak mutation: the capture reads staged
            // batch state, vouching for bytes the API never
            // published (and that no manifest verifies).
            if !rules.stage_invisible {
                if let Some(staged) = s.volume.batch.as_ref().and_then(|b| b.slots.get(&slot)) {
                    entry = Entry {
                        gen: b.gen,
                        size: staged.size,
                        floor: b.floor,
                        runs: {
                            let mut runs: BTreeMap<u8, (usize, Cell, Cell)> = b
                                .runs
                                .iter()
                                .map(|(&l, r)| (l, (r.phys, r.cells.0, r.cells.1)))
                                .collect();
                            for (&l, sr) in &staged.runs {
                                runs.insert(l, (sr.run.phys, sr.run.cells.0, sr.run.cells.1));
                            }
                            runs
                        },
                        shadow: b.shadow,
                    };
                }
            }
            table.blobs.insert(slot, entry);
            continue;
        }
        let dirty_blocks = std::mem::take(&mut s.volume.blobs[slot as usize].dirty_blocks);
        let was_dirty = s.volume.blobs[slot as usize].dirty;
        s.volume.blobs[slot as usize].dirty = false;
        resolved.push((slot, s.volume.blobs[slot as usize].pubseq));
        // Content frees of a captured blob resolve when this commit
        // confirms (the new entry stops referencing them).
        let pending = std::mem::take(&mut s.volume.blobs[slot as usize].pending_frees);
        for block in pending {
            s.volume.pending_free.push((block, seq));
        }
        // Freeze everything this snapshot captures. Uncaptured dirty
        // blobs keep their frozen coverage: their entries reference
        // only already-frozen extents.
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
            floor: b.floor,
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
            // The fresh shadow is a metadata write this commit may tear:
            // manifest the tail block so verification checks the shadow
            // content before adoption, even when no dirt touched the tail.
            if rules.manifest_fresh_shadow {
                let tail = size / CELLS_PER_BLOCK;
                if !dirty_blocks.contains(&tail) {
                    table.manifest.push((slot, tail));
                }
            }
        }
        for l in dirty_blocks {
            if entry.runs.contains_key(&l) {
                table.manifest.push((slot, l));
            }
        }
        table.blobs.insert(slot, entry);
    }
    table.manifest.sort_unstable();
    let logical = s.volume.selective_logical(&captured);
    s.attempts.push(logical.clone());
    s.volume.in_flight = Some(InFlight {
        seq,
        phase: Phase::Snapshotted,
        logical,
        table,
        table_block,
        shadows,
        frees,
        resolved,
    });
    Ok(true)
}

/// Apply one action. Returns successor states (a crash fans out), or None if
/// the action is not enabled in this state.
pub(super) fn step(
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
    let syncs_blocked = if rules.latch_on_failure {
        s.latched || poisoned
    } else {
        false
    };

    // A blob with staged batch content has ONE writer — the batch: direct
    // mutations are excluded until apply/drop (the Blob contract's writer
    // exclusivity). A direct write into the staged region would rewrite
    // bytes whose staged expected content the batch already recorded,
    // letting apply publish an entry that vouches for overwritten bytes —
    // found by this model.
    let batch_staged = |s: &State, slot: u8| {
        s.volume
            .batch
            .as_ref()
            .is_some_and(|batch| batch.slots.get(&slot).is_some_and(|staged| !staged.member))
    };

    match action {
        Action::Append(slot) => {
            let b = &s.volume.blobs[slot as usize];
            if mutations_blocked || batch_staged(&s, slot) || !b.live || b.size >= MAX_CELLS {
                return Ok(None);
            }
            let cell = b.size;
            let val = s.volume.next_val(slot, cell);
            s.volume.write_cell(&mut s.disk, rules, slot, cell, val);
            s.volume.blobs[slot as usize].size += 1;
            Ok(Some(vec![s]))
        }
        Action::Overwrite(slot) => {
            // Cell 0 sits below any nonzero pruned floor: the write path
            // rejects it (Error::OffsetPruned), so it is never enumerated.
            let b = &s.volume.blobs[slot as usize];
            if mutations_blocked || batch_staged(&s, slot) || !b.live || b.size == 0 || b.floor > 0
            {
                return Ok(None);
            }
            let val = s.volume.next_val(slot, 0);
            s.volume.write_cell(&mut s.disk, rules, slot, 0, val);
            Ok(Some(vec![s]))
        }
        Action::ResizeDown(slot) => {
            // Shrinking below the pruned floor is rejected by the resize
            // path (Error::OffsetPruned): enabled only above the floor,
            // which also covers the empty blob (size == floor == 0).
            if mutations_blocked
                || batch_staged(&s, slot)
                || !s.volume.blobs[slot as usize].live
                || s.volume.blobs[slot as usize].size <= s.volume.blobs[slot as usize].floor
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
                s.volume.release_content(slot, run.phys, rules);
            }
            // The (possibly newly partial) tail must re-commit: its shadow
            // and manifest entry change even though its bytes do not. A
            // shrink landing exactly on a nonzero floor leaves no backed
            // tail (all lower runs were pruned): no block to mark, like
            // the implementation's empty post-shrink frontier.
            if new_size > s.volume.blobs[slot as usize].floor {
                let tail = (new_size - 1) / CELLS_PER_BLOCK;
                s.volume.mark_dirty(slot, Some(tail));
            } else {
                s.volume.mark_dirty(slot, None);
            }
            Ok(Some(vec![s]))
        }
        Action::ResizeUp(slot) => {
            let b = &s.volume.blobs[slot as usize];
            if mutations_blocked || batch_staged(&s, slot) || !b.live || b.size + 2 > MAX_CELLS {
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
                    s.volume
                        .write_cell(&mut s.disk, rules, slot, cell, Cell::Zero);
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
            // The implementation holds the commit lock across
            // unlink-plus-commit (`Storage::remove`, and staged removals
            // under `apply_sync`), so a removal never interleaves with an
            // in-flight commit's phases. The gate is load-bearing: an
            // ungated mid-flight removal plus recreation would let
            // confirmation stamp the in-flight table's dead-generation
            // entry onto the recreated blob as its committed entry, which
            // a later selective commit then serves verbatim — resurrecting
            // removed content. Recreate needs no gate of its own: with
            // removals gated, a mid-flight recreation can only follow a
            // pre-snapshot removal, which already dropped the entry from
            // the in-flight table, so confirmation stamps None (the
            // fresh-blob state) rather than a dead entry.
            if s.volume.in_flight.is_some() {
                return Ok(None);
            }
            s.volume.blobs[slot as usize].live = false;
            s.volume.blobs[slot as usize].dirty = true;
            s.volume.blobs[slot as usize].pubseq += 1;
            let runs = std::mem::take(&mut s.volume.blobs[slot as usize].runs);
            let shadow = s.volume.blobs[slot as usize].shadow.take();
            let pending = std::mem::take(&mut s.volume.blobs[slot as usize].pending_frees);
            for run in runs.into_values() {
                s.volume.release(run.phys, rules);
            }
            if let Some(sh) = shadow {
                s.volume.release(sh, rules);
            }
            // Every commit drops the entry, so capture-gated frees resolve
            // at the next commit.
            for block in pending {
                s.volume.release(block, rules);
            }
            // The removal resolves the blob's part of every applied batch:
            // its staged data can never be observed again, so only its
            // siblings' capture state matters (I6).
            for pb in &mut s.volume.pending_batches {
                if let Some(entry) = pb.get_mut(&slot) {
                    *entry = None;
                }
            }
            Ok(Some(vec![s]))
        }
        Action::Recreate(slot) => {
            if mutations_blocked || batch_staged(&s, slot) {
                return Ok(None);
            }
            let b = &mut s.volume.blobs[slot as usize];
            if b.live {
                return Ok(None);
            }
            let gen = b.gen + 1;
            // Publish-sequence bookkeeping survives the reset for
            // never-split tracking.
            let pubseq = b.pubseq;
            let committed_pubseq = b.committed_pubseq;
            *b = BlobState {
                live: true,
                gen,
                dirty: true,
                pubseq,
                committed_pubseq,
                ..Default::default()
            };
            Ok(Some(vec![s]))
        }
        Action::Prune(slot) => {
            // Stricter batch gate than a write's: the implementation
            // asserts NO batch holds a staged slot for the blob —
            // membership included (Batch::sync stages through the same
            // counter) — so those interleavings are never enumerated.
            let staged_any = s
                .volume
                .batch
                .as_ref()
                .is_some_and(|b| b.slots.contains_key(&slot));
            let b = &s.volume.blobs[slot as usize];
            if mutations_blocked || staged_any || !b.live {
                return Ok(None);
            }
            // One block per action: the floor lands between blocks or at
            // the size. Beyond the size the implementation errors, so the
            // action disables there.
            let floor = b.floor + CELLS_PER_BLOCK;
            if floor > b.size {
                return Ok(None);
            }
            let lfloor = floor / CELLS_PER_BLOCK;
            let dropped: Vec<u8> = s.volume.blobs[slot as usize]
                .runs
                .keys()
                .copied()
                .filter(|&l| l < lfloor)
                .collect();
            for l in dropped {
                let run = s.volume.blobs[slot as usize].runs.remove(&l).unwrap();
                // Pruned extents join the capture-gated free discipline:
                // the last confirmed table still references them through
                // this blob's entry (served verbatim until a capture
                // records the floor).
                if rules.prune_capture_gated {
                    s.volume.release_content(slot, run.phys, rules);
                } else {
                    s.volume.release(run.phys, rules);
                }
            }
            let b = &mut s.volume.blobs[slot as usize];
            b.floor = floor;
            // Dirty marks below the floor drop with their blocks. The
            // prune itself dirties the blob so the next capture records
            // the floor and releases the pruned extents.
            b.dirty_blocks.retain(|&l| l >= lfloor);
            s.volume.mark_dirty(slot, None);
            Ok(Some(vec![s]))
        }
        Action::Snapshot(mask) => {
            if syncs_blocked || s.volume.in_flight.is_some() {
                return Ok(None);
            }
            if !begin_snapshot(&mut s, mask, rules, trace)? {
                return Ok(None);
            }
            Ok(Some(vec![s]))
        }
        Action::WriteMeta => {
            let Some(inf) = s.volume.in_flight.clone() else {
                return Ok(None);
            };
            if inf.phase != Phase::Snapshotted {
                return Ok(None);
            }
            for &(block, cell) in &inf.shadows {
                s.disk.write(block, Block::Shadow(cell));
            }
            s.disk
                .write(inf.table_block, Block::Table(inf.table.clone()));
            let slot = 1 - s.volume.sacred;
            s.disk.write(
                slot,
                Block::Super {
                    seq: inf.seq,
                    table: inf.table_block,
                    bound: inf.table,
                },
            );
            s.volume.in_flight.as_mut().unwrap().phase = Phase::MetaWritten;
            Ok(Some(vec![s]))
        }
        Action::FsyncOk => {
            let Some(inf) = s.volume.in_flight.clone() else {
                return Ok(None);
            };
            if syncs_blocked || inf.phase != Phase::MetaWritten {
                return Ok(None);
            }
            s.disk.sync();
            s.volume.sacred = 1 - s.volume.sacred;
            s.volume.last_table = inf.table_block;
            // Extents dropped by this commit (or earlier) become allocatable.
            let (now, later): (Vec<_>, Vec<_>) = s
                .volume
                .pending_free
                .drain(..)
                .partition(|&(_, fs)| fs <= inf.seq);
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
            // Publish the confirmed entries and resolve batch bookkeeping.
            for slot in 0..BLOBS {
                s.volume.blobs[slot as usize].committed = inf.table.blobs.get(&slot).cloned();
            }
            for &(slot, pubseq) in &inf.resolved {
                let b = &mut s.volume.blobs[slot as usize];
                b.committed_pubseq = b.committed_pubseq.max(pubseq);
            }
            let blobs = &s.volume.blobs;
            s.volume.pending_batches.retain(|pb| {
                pb.iter().any(|(&slot, bp)| {
                    // A created part is resolved by ANY confirmed commit:
                    // this table emitted its entry.
                    bp.is_some_and(|(bp, created)| {
                        !created
                            && blobs[slot as usize].live
                            && blobs[slot as usize].committed_pubseq < bp
                    })
                })
            });
            let resolved_slots: Vec<u8> = inf.resolved.iter().map(|&(slot, _)| slot).collect();
            s.volume
                .groups
                .retain(|group| !group.iter().all(|slot| resolved_slots.contains(slot)));
            s.volume.in_flight = None;
            // Confirmed: this snapshot becomes the observed baseline.
            s.baseline = inf.logical;
            s.attempts.clear();
            Ok(Some(vec![s]))
        }
        Action::FsyncFail => {
            let Some(inf) = s.volume.in_flight.clone() else {
                return Ok(None);
            };
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
                // without reaching disk (read-visible residue). The kept
                // and lost arms bind the NEWEST version — the cache page
                // holds the newest write — but background writeback may
                // have persisted any older pending version before the
                // failed fsync, so the landed arm fans over every distinct
                // pending version (an older version landing means the
                // newest was marked clean and evicted).
                let mut landed_versions = versions.clone();
                landed_versions.sort();
                landed_versions.dedup();
                let mut next = Vec::with_capacity(outcomes.len() * (2 + landed_versions.len()));
                for outcome in &outcomes {
                    let mut keep = outcome.clone();
                    keep.pending.insert(block, vec![newest.clone()]);
                    next.push(keep);
                    for version in &landed_versions {
                        let mut landed = outcome.clone();
                        landed.durable[block] = version.clone();
                        next.push(landed);
                    }
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
        Action::BatchAppend(slot) => {
            if mutations_blocked || !s.volume.blobs[slot as usize].live {
                return Ok(None);
            }
            let published = s.volume.blobs[slot as usize].size;
            let batch = s.volume.batch.get_or_insert_with(Batch::default);
            let staged = batch.slots.entry(slot).or_insert_with(|| StagedSlot {
                size: published,
                runs: BTreeMap::new(),
                fresh: Vec::new(),
                replaced: Vec::new(),
                created: false,
                member: false,
            });
            if staged.member {
                // Membership only until now: staging begins against the
                // slot's CURRENT published size (direct writes may have
                // legally grown it since the touch — the overlay rebases).
                staged.member = false;
                staged.size = published;
            }
            if staged.size >= MAX_CELLS {
                return Ok(None);
            }
            let cell = staged.size;
            staged.size += 1;
            let val = s.volume.next_val(slot, cell);
            s.volume.stage_cell(&mut s.disk, slot, cell, val);
            Ok(Some(vec![s]))
        }
        Action::BatchOverwrite(slot) => {
            // Cell 0 below a nonzero pruned floor: staging it would
            // publish a run below the floor (the caller contract the
            // direct write path rejects), so it is never enumerated.
            if mutations_blocked
                || !s.volume.blobs[slot as usize].live
                || s.volume.blobs[slot as usize].floor > 0
            {
                return Ok(None);
            }
            let published = s.volume.blobs[slot as usize].size;
            let batch = s.volume.batch.get_or_insert_with(Batch::default);
            let staged = batch.slots.entry(slot).or_insert_with(|| StagedSlot {
                size: published,
                runs: BTreeMap::new(),
                fresh: Vec::new(),
                replaced: Vec::new(),
                created: false,
                member: false,
            });
            if staged.member {
                // Membership only until now: staging begins against the
                // slot's CURRENT published size (direct writes may have
                // legally grown it since the touch — the overlay rebases).
                staged.member = false;
                staged.size = published;
            }
            if staged.size == 0 {
                return Ok(None);
            }
            let val = s.volume.next_val(slot, 0);
            s.volume.stage_cell(&mut s.disk, slot, 0, val);
            Ok(Some(vec![s]))
        }
        Action::BatchCreate(slot) => {
            // A live slot may be recreated only when this batch also
            // stages its removal (resolved first at apply).
            let staged_already = s
                .volume
                .batch
                .as_ref()
                .is_some_and(|b| b.slots.contains_key(&slot));
            let removing = s
                .volume
                .batch
                .as_ref()
                .is_some_and(|b| b.removals.contains(&slot));
            if mutations_blocked
                || staged_already
                || (s.volume.blobs[slot as usize].live && !removing)
            {
                return Ok(None);
            }
            let batch = s.volume.batch.get_or_insert_with(Batch::default);
            batch.slots.insert(
                slot,
                StagedSlot {
                    size: 0,
                    runs: BTreeMap::new(),
                    fresh: Vec::new(),
                    replaced: Vec::new(),
                    created: true,
                    member: false,
                },
            );
            Ok(Some(vec![s]))
        }
        Action::BatchSync(slot) => {
            // Membership only (Batch::sync): the slot's directly written
            // dirt commits with the batch's group. No content is staged,
            // so the slot stays writable outside the batch.
            if mutations_blocked || !s.volume.blobs[slot as usize].live {
                return Ok(None);
            }
            let already = s
                .volume
                .batch
                .as_ref()
                .is_some_and(|b| b.slots.contains_key(&slot) || b.removals.contains(&slot));
            if already {
                return Ok(None);
            }
            let published = s.volume.blobs[slot as usize].size;
            let batch = s.volume.batch.get_or_insert_with(Batch::default);
            batch.slots.insert(
                slot,
                StagedSlot {
                    size: published,
                    runs: BTreeMap::new(),
                    fresh: Vec::new(),
                    replaced: Vec::new(),
                    created: false,
                    member: true,
                },
            );
            Ok(Some(vec![s]))
        }
        Action::BatchRemove(slot) => {
            // Stage the slot's removal, resolved at apply against the
            // pre-publish state (a batch may remove a slot and recreate
            // it). Removal-bearing batches commit in-step at apply.
            if mutations_blocked || !s.volume.blobs[slot as usize].live {
                return Ok(None);
            }
            let already = s
                .volume
                .batch
                .as_ref()
                .is_some_and(|b| b.removals.contains(&slot));
            if already {
                return Ok(None);
            }
            s.volume
                .batch
                .get_or_insert_with(Batch::default)
                .removals
                .insert(slot);
            Ok(Some(vec![s]))
        }
        Action::BatchApply => {
            // Apply publishes under the commit lock: it never interleaves
            // with an in-flight commit's phases.
            if mutations_blocked || s.volume.in_flight.is_some() {
                return Ok(None);
            }
            // A staged removal whose slot was directly removed before the
            // apply fails the implementation's validation (the name no
            // longer resolves): the apply errors and publishes nothing,
            // so the action is disabled here.
            let removal_dead = s.volume.batch.as_ref().is_some_and(|batch| {
                batch
                    .removals
                    .iter()
                    .any(|&slot| !s.volume.blobs[slot as usize].live)
            });
            if removal_dead {
                return Ok(None);
            }
            // A batch staging removals — or creations alongside anything
            // else — also begins its commit (apply_sync), which the latch
            // blocks like any other sync. A creation-ONLY batch publishes
            // commit-free: every member is an empty creation, so any later
            // commit emits all of their entries together (staged content
            // into a created slot is unreachable here:
            // BatchAppend/BatchOverwrite require a live blob, and a staged
            // creation's blob is not live until apply).
            let (has_creation, creation_only, has_removal) =
                s.volume
                    .batch
                    .as_ref()
                    .map_or((false, false, false), |batch| {
                        (
                            batch.slots.values().any(|staged| staged.created),
                            !batch.slots.is_empty()
                                && batch.slots.values().all(|staged| staged.created),
                            !batch.removals.is_empty(),
                        )
                    });
            let commit_free = if rules.commit_free_creation_gate {
                creation_only
            } else {
                true
            };
            let must_commit = (has_creation && !commit_free && rules.atomic_create_commit)
                || (has_removal && rules.atomic_remove_commit);
            if must_commit && syncs_blocked {
                return Ok(None);
            }
            let Some(batch) = s.volume.batch.take() else {
                return Ok(None);
            };
            let mut record = BTreeMap::new();
            let mut members = Vec::new();
            // Removals resolve FIRST, against the pre-publish state (the
            // implementation resolves names against the namespace its
            // validation simulated): a batch may remove a slot and
            // recreate it, and the removal never touches the staged
            // recreation. Mirrors Action::Remove's unlink. Each removal is
            // a batch part — the record entry below makes I6 require the
            // entry drop to land with the group (a same-slot recreation
            // overwrites the part with its own, strictly-live obligation).
            for &slot in &batch.removals {
                let b = &mut s.volume.blobs[slot as usize];
                b.live = false;
                b.dirty = true;
                b.pubseq += 1;
                let runs = std::mem::take(&mut b.runs);
                let shadow = b.shadow.take();
                let pending = std::mem::take(&mut b.pending_frees);
                for run in runs.into_values() {
                    s.volume.release(run.phys, rules);
                }
                if let Some(sh) = shadow {
                    s.volume.release(sh, rules);
                }
                for block in pending {
                    s.volume.release(block, rules);
                }
                for pb in &mut s.volume.pending_batches {
                    if let Some(entry) = pb.get_mut(&slot) {
                        *entry = None;
                    }
                }
                record.insert(slot, Some((s.volume.blobs[slot as usize].pubseq, false)));
            }
            for (slot, staged) in batch.slots {
                if staged.created {
                    // Publish the creation: a fresh generation, empty,
                    // dirty. Publish-sequence bookkeeping survives the
                    // reset for never-split tracking.
                    let b = &mut s.volume.blobs[slot as usize];
                    let gen = b.gen + 1;
                    let pubseq = b.pubseq + 1;
                    let committed_pubseq = b.committed_pubseq;
                    *b = BlobState {
                        live: true,
                        gen,
                        dirty: true,
                        pubseq,
                        committed_pubseq,
                        ..Default::default()
                    };
                    record.insert(slot, Some((pubseq, true)));
                    members.push(slot);
                    continue;
                }
                let b = &mut s.volume.blobs[slot as usize];
                if !b.live {
                    // Removed mid-batch (this batch's own staged removal,
                    // or an earlier Remove): its staged blocks are
                    // unreferenced.
                    for block in staged.fresh {
                        s.volume.release(block, rules);
                    }
                    continue;
                }
                if staged.member {
                    // Membership only: no content publishes, but the
                    // slot's direct dirt must commit with the group. A
                    // CLEAN member carries no obligation — nothing of it
                    // publishes, mirroring the implementation's
                    // touched-only roots, which the group's commit
                    // resolves trivially. Recording one anyway makes any
                    // removal- or creation-bearing apply a phantom split
                    // batch: the in-step commit resolves those parts
                    // while the clean member's part is undischargeable
                    // (found by the deep conformance walk, see
                    // `clean_member_removal_apply_allowed`).
                    b.pubseq += 1;
                    if b.dirty {
                        record.insert(slot, Some((b.pubseq, false)));
                    }
                    members.push(slot);
                    continue;
                }
                let touched: Vec<u8> = staged.runs.keys().copied().collect();
                for (l, sr) in staged.runs {
                    b.runs.insert(l, sr.run);
                }
                b.size = staged.size;
                b.pubseq += 1;
                record.insert(slot, Some((b.pubseq, false)));
                members.push(slot);
                for block in staged.replaced {
                    s.volume.release_content(slot, block, rules);
                }
                s.volume.mark_dirty(slot, None);
                for l in touched {
                    s.volume.mark_dirty(slot, Some(l));
                }
            }
            if !record.is_empty() {
                s.volume.merge_group(&members);
                s.volume.pending_batches.push(record);
            }
            // The apply_sync requirement: publish and the batch's commit
            // snapshot happen under ONE hold of the commit lock, so no
            // other commit can emit the created blob's entry — or drop a
            // removed slot's — without capturing the whole group.
            // Creation-only batches are exempt (commit-free publish).
            if must_commit {
                let mask = members.iter().fold(0u8, |mask, &slot| mask | (1 << slot));
                let started = begin_snapshot(&mut s, mask, rules, trace)?;
                assert!(started, "a creation or removal batch must begin its commit");
            }
            Ok(Some(vec![s]))
        }
        Action::BatchDrop => {
            if mutations_blocked {
                return Ok(None);
            }
            let Some(batch) = s.volume.batch.take() else {
                return Ok(None);
            };
            // Staged blocks were never referenced: return them through the
            // ordinary deferred-free path (staged removals simply never
            // happened).
            for staged in batch.slots.into_values() {
                for block in staged.fresh {
                    s.volume.release(block, rules);
                }
            }
            Ok(Some(vec![s]))
        }
        Action::Crash => {
            if s.crashes_left == 0 {
                return Ok(None);
            }
            s.crashes_left -= 1;
            // The dying process's live floors, kept only for the
            // floor-restore mutation hook (see `rebuild`).
            let crashed: Vec<Option<(u8, u8)>> = s
                .volume
                .blobs
                .iter()
                .map(|b| b.live.then_some((b.gen, b.floor)))
                .collect();
            let ctx = CrashContext {
                baseline: &s.baseline,
                attempts: &s.attempts,
                crashed: &crashed,
            };
            let mut out = Vec::new();
            for outcome in s.disk.crash_outcomes() {
                out.extend(recovery_states(
                    outcome,
                    &ctx,
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
        Action::Snapshot(ALL),
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Recycling workload: remove/recreate + rewind + holes + pruning
    /// exercise extent reuse, deferred frees, hole runs, replay-identical
    /// resurrection, and the floor resetting with a recreated generation.
    const RECYCLE: &[Action] = &[
        Action::Append(0),
        Action::Overwrite(0),
        Action::ResizeDown(0),
        Action::ResizeUp(0),
        Action::Prune(0),
        Action::Remove(0),
        Action::Recreate(0),
        Action::Snapshot(ALL),
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
        Action::Snapshot(ALL),
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Failure workload: commits may fail without crashing (latch).
    const LATCH: &[Action] = &[
        Action::Append(0),
        Action::Append(1),
        Action::Snapshot(ALL),
        Action::WriteMeta,
        Action::FsyncOk,
        Action::FsyncFail,
        Action::Crash,
    ];

    /// Selective workload: per-blob commits with dirty state left pending on
    /// the uncaptured blob (served-verbatim entries, deferred manifests,
    /// capture-gated frees, shared-tail writes racing foreign commits).
    const SELECTIVE: &[Action] = &[
        Action::Append(0),
        Action::Append(1),
        Action::Overwrite(0),
        Action::Snapshot(0b01),
        Action::Snapshot(0b10),
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Coalescing workload: one commit captures the UNION of two dirty
    /// blobs — two queued syncs acknowledged by one fsync, the
    /// implementation's commit coalescing — while a third dirty blob stays
    /// uncaptured, then a later commit captures the straggler. A union
    /// capture is ordinary selective capture (a multi-bit mask), so no rule
    /// changes here; this workload pins the interleaving, which no other
    /// workload reaches with dirty content on both captured blobs.
    /// (Overwrites are omitted to bound the space: COW under selective
    /// capture is exercised by SELECTIVE and BATCH_COW.)
    const COALESCE: &[Action] = &[
        Action::Append(0),
        Action::Append(1),
        Action::Append(2),
        Action::Snapshot(0b011),
        Action::Snapshot(0b100),
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Batch workload: cross-blob staging (fresh blocks and in-place
    /// shared-tail appends), publish, drop, and selective commits that must
    /// respect batch groups.
    const BATCH: &[Action] = &[
        Action::Append(0),
        Action::BatchAppend(0),
        Action::BatchAppend(1),
        Action::BatchApply,
        Action::Snapshot(0b01),
        Action::Snapshot(ALL),
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Batch + removal workload: a removal interleaving with selective
    /// commits must resolve an applied group holding the removed blob
    /// all-or-nothing (every commit drops the removed entry, so the group's
    /// live members must be captured with it — the removed-group arm of the
    /// never-split rule).
    const BATCH_REMOVE: &[Action] = &[
        Action::BatchAppend(0),
        Action::BatchAppend(1),
        Action::BatchApply,
        Action::Remove(0),
        Action::Snapshot(0b10),
        Action::Snapshot(ALL),
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Batch creation workload: a batch recreates a removed blob alongside
    /// staged writes to another blob, published and committed in one step.
    const BATCH_CREATE: &[Action] = &[
        Action::Append(0),
        Action::Remove(1),
        Action::BatchAppend(0),
        Action::BatchCreate(1),
        Action::BatchApply,
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Snapshot(ALL),
        Action::Crash,
    ];

    /// Commit-free creation workload: a batch stages ONLY creations and
    /// publishes without its own commit. Later commits — rooted at an
    /// unrelated blob, or at one of the new blobs after direct writes —
    /// must emit both creations together, and a crash before any commit
    /// must erase them together.
    const BATCH_CREATE_FREE: &[Action] = &[
        Action::Append(2),
        Action::Remove(0),
        Action::Remove(1),
        Action::BatchCreate(0),
        Action::BatchCreate(1),
        Action::BatchApply,
        Action::Append(0),
        Action::Snapshot(0b001),
        Action::Snapshot(0b100),
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Batch overwrite workload: staged COW of committed cells plus batch
    /// drop (staged extents returned through deferred frees).
    const BATCH_COW: &[Action] = &[
        Action::Append(0),
        Action::Append(1),
        Action::BatchOverwrite(0),
        Action::BatchAppend(0),
        Action::BatchApply,
        Action::BatchDrop,
        Action::Snapshot(0b10),
        Action::Snapshot(ALL),
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Staged-removal workload: one batch removes a slot, recreates it,
    /// and stages a sibling write — published and committed in one step,
    /// atomic across crash (the removal resolves against the pre-publish
    /// state, so it never touches the recreation).
    const BATCH_RECREATE: &[Action] = &[
        Action::Append(0),
        Action::BatchAppend(1),
        Action::BatchRemove(0),
        Action::BatchCreate(0),
        Action::BatchApply,
        Action::Snapshot(ALL),
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Pruning workload: the floor advances between blocks and to the
    /// size, interleaved with appends, selective commits, and crashes — a
    /// pruned-but-uncaptured blob serves its old entry verbatim (floor
    /// and runs intact), a capturing commit records the floor and
    /// releases the pruned extents, and a crashed-away prune regresses to
    /// the committed floor (I7). Group capture treats prune as ordinary
    /// dirt, so batch interplay needs no dedicated menu entry.
    const PRUNE: &[Action] = &[
        Action::Append(0),
        Action::Append(1),
        Action::Prune(0),
        Action::Snapshot(0b01),
        Action::Snapshot(0b10),
        Action::WriteMeta,
        Action::FsyncOk,
        Action::Crash,
    ];

    /// Membership workload (Batch::sync): a directly written slot joins
    /// the group without staged content, stays writable (its growth
    /// rebases a later staged write), and its dirt commits with the group
    /// under selective commits (never-split).
    const BATCH_MEMBER: &[Action] = &[
        Action::Append(0),
        Action::BatchSync(0),
        Action::BatchAppend(0),
        Action::BatchAppend(1),
        Action::BatchApply,
        Action::Snapshot(0b010),
        Action::Snapshot(ALL),
        Action::WriteMeta,
        Action::FsyncOk,
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

    #[test]
    fn spec_holds_selective() {
        assert_holds(SELECTIVE, 8, 2, 10_000);
    }

    #[test]
    fn spec_holds_coalesce() {
        assert_holds(COALESCE, 7, 2, 10_000);
    }

    #[test]
    fn spec_holds_batch() {
        assert_holds(BATCH, 8, 2, 10_000);
    }

    #[test]
    fn spec_holds_batch_cow() {
        assert_holds(BATCH_COW, 7, 2, 10_000);
    }

    #[test]
    fn spec_holds_batch_remove() {
        assert_holds(BATCH_REMOVE, 8, 2, 10_000);
    }

    #[test]
    fn spec_holds_batch_create() {
        assert_holds(BATCH_CREATE, 8, 2, 1_000);
    }

    #[test]
    fn spec_holds_batch_create_free() {
        assert_holds(BATCH_CREATE_FREE, 8, 2, 1_000);
    }

    #[test]
    fn spec_holds_batch_recreate() {
        assert_holds(BATCH_RECREATE, 8, 2, 1_000);
    }

    #[test]
    fn spec_holds_prune() {
        assert_holds(PRUNE, 8, 2, 10_000);
    }

    #[test]
    fn spec_holds_batch_member() {
        assert_holds(BATCH_MEMBER, 8, 2, 1_000);
    }

    /// A staged removal must publish and begin its commit in one step.
    /// Without that (modeling an apply that does not sync), the first
    /// unrelated snapshot itself trips I6: it counts the removed slot's
    /// part as resolved — every commit drops the removed entry, making
    /// the removal durable — while the batch's staged write to its
    /// sibling stays unresolved.
    #[test]
    fn mutation_remove_commit_detected() {
        let spec_trace: &[Action] = &[
            Action::Append(0),
            Action::Snapshot(0b001),
            Action::WriteMeta,
            Action::FsyncOk,
            Action::Append(2),
            Action::BatchAppend(1),
            Action::BatchRemove(0),
            // Under SPEC the apply also begins the batch's commit. Finish
            // it, after which the unrelated commit is harmless.
            Action::BatchApply,
            Action::WriteMeta,
            Action::FsyncOk,
            Action::Snapshot(0b100),
            Action::WriteMeta,
            Action::FsyncOk,
        ];
        assert!(
            run_trace(spec_trace, &SPEC).is_ok(),
            "spec must allow the trace"
        );

        let mutated_trace: &[Action] = &[
            Action::Append(0),
            Action::Snapshot(0b001),
            Action::WriteMeta,
            Action::FsyncOk,
            Action::Append(2),
            Action::BatchAppend(1),
            Action::BatchRemove(0),
            Action::BatchApply,
            Action::Snapshot(0b100),
        ];
        let rules = Rules {
            atomic_remove_commit: false,
            ..SPEC
        };
        assert!(
            run_trace(mutated_trace, &rules).is_err(),
            "checker missed the uncommitted staged removal"
        );
    }

    /// A creation-only batch publishes WITHOUT its own commit: a later
    /// commit rooted at an unrelated blob emits both creations (durable
    /// together), and a later sync of ONE new blob — after direct writes
    /// through its normal handle — captures the whole group while the
    /// other's empty entry is emitted with it.
    #[test]
    fn commit_free_creation_only_allowed() {
        let unrelated: &[Action] = &[
            Action::Append(2),
            Action::Remove(0),
            Action::Remove(1),
            Action::BatchCreate(0),
            Action::BatchCreate(1),
            Action::BatchApply,
            Action::Snapshot(0b100),
            Action::WriteMeta,
            Action::FsyncOk,
            Action::Crash,
        ];
        assert!(
            run_trace(unrelated, &SPEC).is_ok(),
            "spec must allow an unrelated commit to resolve the creations"
        );

        let sync_one: &[Action] = &[
            Action::Remove(0),
            Action::Remove(1),
            Action::BatchCreate(0),
            Action::BatchCreate(1),
            Action::BatchApply,
            Action::Append(0),
            Action::Snapshot(0b001),
            Action::WriteMeta,
            Action::FsyncOk,
            Action::Crash,
        ];
        assert!(
            run_trace(sync_one, &SPEC).is_ok(),
            "spec must allow syncing one new blob to resolve both creations"
        );
    }

    /// A crash after a commit-free creation-only publish (and before ANY
    /// commit) must erase the creations entirely: every recovery outcome
    /// adopts a table without the created generations. I1/I2 enforce this
    /// in general (the adopted state must equal the baseline, in which the
    /// creations never happened). This test additionally pins the recovered
    /// RAM state explicitly.
    #[test]
    fn commit_free_creation_erased_by_crash() {
        let trace: &[Action] = &[
            Action::Remove(0),
            Action::Remove(1),
            Action::BatchCreate(0),
            Action::BatchCreate(1),
            Action::BatchApply,
            Action::Crash,
        ];
        let mut states = vec![initial_state(trace.len() as u8, 1)];
        for (i, &action) in trace.iter().enumerate() {
            let mut next = Vec::new();
            for state in &states {
                match step(state, action, &SPEC, &trace[..=i]).expect("trace must stay legal") {
                    Some(successors) => next.extend(successors),
                    None => panic!("action {action:?} disabled at step {i}"),
                }
            }
            states = next;
        }
        assert!(!states.is_empty(), "crash must produce recovered states");
        for state in &states {
            for slot in [0usize, 1] {
                let b = &state.volume.blobs[slot];
                assert!(
                    b.gen == 0 && b.size == 0,
                    "slot {slot}: commit-free creation survived the crash"
                );
            }
        }
    }

    /// A staged creation must publish and begin its commit in one step.
    /// Without that (modeling an apply that does not sync), an unrelated
    /// commit emits the created blob's entry — making the creation durable —
    /// while the batch's staged write to its sibling stays uncommitted: a
    /// split batch (I6).
    #[test]
    fn mutation_create_commit_detected() {
        let spec_trace: &[Action] = &[
            // A third blob's dirty append gives the unrelated commit
            // something to capture.
            Action::Append(2),
            // Remove blob 1 so the batch can stage its recreation alongside
            // blob 0's staged write.
            Action::Remove(1),
            Action::BatchAppend(0),
            Action::BatchCreate(1),
            // Under SPEC the apply also begins the batch's commit. Finish
            // it, after which the unrelated commit is harmless.
            Action::BatchApply,
            Action::WriteMeta,
            Action::FsyncOk,
            Action::Snapshot(0b100),
            Action::WriteMeta,
            Action::FsyncOk,
        ];
        assert!(
            run_trace(spec_trace, &SPEC).is_ok(),
            "spec must allow the trace"
        );

        let mutated_trace: &[Action] = &[
            Action::Append(2),
            Action::Remove(1),
            Action::BatchAppend(0),
            Action::BatchCreate(1),
            Action::BatchApply,
            Action::Snapshot(0b100),
        ];
        let rules = Rules {
            atomic_create_commit: false,
            ..SPEC
        };
        assert!(
            run_trace(mutated_trace, &rules).is_err(),
            "checker missed the premature creation"
        );
    }

    /// Commit-free publish is gated on the batch staging ONLY creations.
    /// Disabling the gate (modeling an apply that lets a batch with staged
    /// writes publish commit-free) must be caught: an unrelated commit
    /// emits the created blob's entry while the sibling's staged write
    /// stays uncommitted — a split batch (I6).
    #[test]
    fn mutation_commit_free_gate_detected() {
        let spec_trace: &[Action] = &[
            Action::Append(2),
            Action::Remove(1),
            Action::BatchAppend(0),
            Action::BatchCreate(1),
            // Under SPEC the mixed batch's apply also begins its commit.
            // Finish it, after which the unrelated commit is harmless.
            Action::BatchApply,
            Action::WriteMeta,
            Action::FsyncOk,
            Action::Snapshot(0b100),
            Action::WriteMeta,
            Action::FsyncOk,
        ];
        assert!(
            run_trace(spec_trace, &SPEC).is_ok(),
            "spec must allow the trace"
        );

        let mutated_trace: &[Action] = &[
            Action::Append(2),
            Action::Remove(1),
            Action::BatchAppend(0),
            Action::BatchCreate(1),
            Action::BatchApply,
            Action::Snapshot(0b100),
        ];
        let rules = Rules {
            commit_free_creation_gate: false,
            ..SPEC
        };
        assert!(
            run_trace(mutated_trace, &rules).is_err(),
            "checker missed the widened commit-free gate"
        );
    }

    /// Disabling the never-split group expansion must let a selective commit
    /// capture one blob of an applied batch while leaving the other's part
    /// uncommitted (I6).
    #[test]
    fn mutation_batch_split_detected() {
        let rules = Rules {
            respect_groups: false,
            ..SPEC
        };
        assert!(
            check(BATCH, 8, 2, &rules).is_err(),
            "checker missed a split batch"
        );
    }

    /// A removal resolves its own part of an applied batch, and a later
    /// recreation of the slot must not resurrect that part for never-split
    /// counting: an unrelated selective commit that captures no surviving
    /// member leaves the batch entirely unresolved, which is legal.
    /// Counting the removal-nulled part as included would flag this
    /// history as a split batch (a spurious I6 violation).
    #[test]
    fn removed_then_recreated_part_not_counted() {
        let trace: &[Action] = &[
            Action::BatchAppend(0),
            Action::BatchAppend(1),
            Action::BatchApply,
            Action::Remove(0),
            Action::Recreate(0),
            Action::Append(2),
            Action::Snapshot(0b100),
            Action::WriteMeta,
            Action::FsyncOk,
        ];
        assert!(
            run_trace(trace, &SPEC).is_ok(),
            "spec must allow an unrelated commit after remove and recreate"
        );
    }

    /// A batch may join a CLEAN blob for membership alongside a staged
    /// removal: the apply's in-step commit resolves the removal while the
    /// clean member has nothing to commit — no obligation, no split.
    /// Recording a member obligation regardless of dirt made this shape a
    /// phantom I6 violation (found by the deep conformance walk when the
    /// prune menu re-seeded it).
    #[test]
    fn clean_member_removal_apply_allowed() {
        let trace: &[Action] = &[
            Action::BatchRemove(1),
            Action::BatchSync(0),
            Action::BatchApply,
            Action::WriteMeta,
            Action::FsyncOk,
            Action::Crash,
        ];
        assert!(
            run_trace(trace, &SPEC).is_ok(),
            "spec must allow a clean member beside a staged removal"
        );
    }

    /// The never-split checker must stay sensitive on a freshly recreated
    /// blob. A removal's commit confirms while the recreation happens
    /// mid-flight, resolving the slot at the removal's pubseq. A recreation
    /// that reset the publish-sequence bookkeeping would let that stale
    /// resolution dominate the first batch applied to the new incarnation,
    /// counting its part as already resolved. With group expansion disabled,
    /// a selective commit capturing only the sibling is a split batch and
    /// must be flagged (I6).
    #[test]
    fn mutation_recreated_blob_split_detected() {
        let spec_trace: &[Action] = &[
            Action::Remove(0),
            Action::Snapshot(ALL),
            Action::Recreate(0),
            Action::WriteMeta,
            Action::FsyncOk,
            Action::BatchAppend(0),
            Action::BatchAppend(1),
            Action::BatchApply,
            // Under SPEC the group expands the capture to both members.
            Action::Snapshot(0b010),
            Action::WriteMeta,
            Action::FsyncOk,
        ];
        assert!(
            run_trace(spec_trace, &SPEC).is_ok(),
            "spec must allow the trace"
        );

        let mutated_trace: &[Action] = &[
            Action::Remove(0),
            Action::Snapshot(ALL),
            Action::Recreate(0),
            Action::WriteMeta,
            Action::FsyncOk,
            Action::BatchAppend(0),
            Action::BatchAppend(1),
            Action::BatchApply,
            Action::Snapshot(0b010),
        ];
        let rules = Rules {
            respect_groups: false,
            ..SPEC
        };
        assert!(
            run_trace(mutated_trace, &rules).is_err(),
            "checker missed the split batch on the recreated blob"
        );
    }

    /// Disabling staged-write invisibility must let a snapshot capture
    /// staged-but-unpublished bytes: the recorded table vouches for state
    /// the API never published (and that no manifest verifies), surfacing
    /// as an I2 mismatch or a verification failure after recovery.
    #[test]
    fn mutation_stage_visibility_detected() {
        let rules = Rules {
            stage_invisible: false,
            ..SPEC
        };
        assert!(
            check(BATCH, 8, 2, &rules).is_err(),
            "checker missed the staged-visibility leak"
        );
    }

    /// Run a fixed action sequence under `rules`, asserting it stays legal
    /// until its end. Crash steps explore every outcome; other steps must be
    /// enabled and deterministic.
    fn run_trace(trace: &[Action], rules: &Rules) -> Result<(), Violation> {
        let mut states = vec![initial_state(trace.len() as u8, 1)];
        for (i, &action) in trace.iter().enumerate() {
            let mut next = Vec::new();
            for state in &states {
                match step(state, action, rules, &trace[..=i])? {
                    Some(successors) => next.extend(successors),
                    None => panic!("action {action:?} disabled at step {i}"),
                }
            }
            states = next;
        }
        Ok(())
    }

    /// Freeing an overwrite's dropped extent at the NEXT commit (instead of
    /// gating it on a commit that captures the blob) recycles a block the
    /// confirmed table still references: the next table write lands in it
    /// and a crash exposes the clobber. The violating interleaving sits
    /// deeper than the BFS budgets, so it is pinned as a directed trace.
    /// Blob 0 commits a FULL block first — a partial (shadowed) tail block
    /// would be healed by the shadow splice.
    #[test]
    fn mutation_capture_gated_frees_detected() {
        let trace: &[Action] = &[
            // Commit a full block for blob 0 so its content has no shadow.
            Action::Append(0),
            Action::Append(0),
            Action::Snapshot(0b01),
            Action::WriteMeta,
            Action::FsyncOk,
            // COW blob 0's committed block (dropping the old block), then
            // confirm a commit that does NOT capture blob 0.
            Action::Overwrite(0),
            Action::Append(1),
            Action::Snapshot(0b10),
            Action::WriteMeta,
            Action::FsyncOk,
            // The next commit allocates the (wrongly freed) block for its
            // table and a crash exposes the clobbered fallback.
            Action::Snapshot(0b01),
            Action::WriteMeta,
            Action::Crash,
        ];
        assert!(run_trace(trace, &SPEC).is_ok(), "spec must allow the trace");
        let rules = Rules {
            capture_gated_frees: false,
            ..SPEC
        };
        assert!(
            run_trace(trace, &rules).is_err(),
            "checker missed the capture-gated free"
        );
    }

    /// Releasing a prune's dropped extents at the NEXT commit (instead of
    /// gating them on a commit that CAPTURES the blob) recycles blocks
    /// the confirmed table still references through the blob's
    /// served-verbatim entry: the next table write lands in one and a
    /// crash exposes the clobber. Mirrors
    /// `mutation_capture_gated_frees_detected` with the drop coming from
    /// a prune instead of a COW overwrite.
    #[test]
    fn mutation_prune_capture_gated_detected() {
        let trace: &[Action] = &[
            // Commit a full block for blob 0 (a partial shadowed tail
            // would be healed by the shadow splice).
            Action::Append(0),
            Action::Append(0),
            Action::Snapshot(0b01),
            Action::WriteMeta,
            Action::FsyncOk,
            // Prune the committed block away, then confirm a commit that
            // does NOT capture blob 0: its old entry (floor 0, runs
            // intact) is served verbatim while the mutation releases the
            // pruned block.
            Action::Prune(0),
            Action::Append(1),
            Action::Snapshot(0b10),
            Action::WriteMeta,
            Action::FsyncOk,
            // The next commit allocates the (wrongly freed) block for its
            // table and a crash exposes the clobbered fallback.
            Action::Snapshot(0b01),
            Action::WriteMeta,
            Action::Crash,
        ];
        assert!(run_trace(trace, &SPEC).is_ok(), "spec must allow the trace");
        let rules = Rules {
            prune_capture_gated: false,
            ..SPEC
        };
        assert!(
            run_trace(trace, &rules).is_err(),
            "checker missed the prematurely released prune free"
        );
    }

    /// A floor whose pruning commit never landed must regress at recovery
    /// to the adopted commit's floor. Restoring the crashed process's
    /// live floor instead (modeling a floor persisted outside the commit
    /// protocol) makes the prune durable without its commit and trips the
    /// floor invariant (I7).
    #[test]
    fn mutation_floor_restore_detected() {
        let trace: &[Action] = &[
            Action::Append(0),
            Action::Append(0),
            Action::Snapshot(0b01),
            Action::WriteMeta,
            Action::FsyncOk,
            Action::Prune(0),
            Action::Crash,
        ];
        assert!(run_trace(trace, &SPEC).is_ok(), "spec must allow the trace");
        let rules = Rules {
            floor_from_commit: false,
            ..SPEC
        };
        assert!(
            run_trace(trace, &rules).is_err(),
            "checker missed the floor persisted without its commit"
        );
    }

    /// Disabling snapshot-time freezing must reintroduce the panel's fatal
    /// finding: a post-snapshot in-place overwrite of a manifested chunk
    /// rolls back a confirmed commit.
    #[test]
    fn mutation_freeze_at_snapshot_detected() {
        let rules = Rules {
            freeze_at_snapshot: false,
            ..SPEC
        };
        assert!(
            check(CORE, 9, 2, &rules).is_err(),
            "checker missed the freeze bug"
        );
    }

    /// A commit whose dirt avoids the tail block still writes a FRESH
    /// shadow, and recovery's splice is a raw byte copy: without the tail
    /// block in the manifest, the crash outcome that tears exactly the
    /// shadow (every other commit write landed) is adopted and the splice
    /// destroys the intact committed tail (I3). Under SPEC the manifested
    /// tail block forces shadow verification, rejecting the candidate and
    /// rolling back the one unacknowledged commit.
    #[test]
    fn mutation_manifest_fresh_shadow_detected() {
        let trace: &[Action] = &[
            // Size 3: block 0 full, block 1 a partial (shadowed) tail.
            Action::Append(0),
            Action::Append(0),
            Action::Append(0),
            Action::Snapshot(ALL),
            Action::WriteMeta,
            Action::FsyncOk,
            // Dirty ONLY block 0 (COW), then crash with the commit's
            // metadata written but unsynced: one outcome lands everything
            // except the fresh shadow, which tears.
            Action::Overwrite(0),
            Action::Snapshot(ALL),
            Action::WriteMeta,
            Action::Crash,
        ];
        assert!(run_trace(trace, &SPEC).is_ok(), "spec must allow the trace");
        let rules = Rules {
            manifest_fresh_shadow: false,
            ..SPEC
        };
        assert!(
            run_trace(trace, &rules).is_err(),
            "checker missed the unverified shadow splice"
        );
    }

    /// Disabling shadow tails must reintroduce shared-tail-block loss.
    #[test]
    fn mutation_shadow_tails_detected() {
        let rules = Rules {
            shadow_tails: false,
            ..SPEC
        };
        assert!(
            check(CORE, 9, 2, &rules).is_err(),
            "checker missed tail tearing"
        );
    }

    /// Disabling losing-slot zeroing must reintroduce stale-slot
    /// resurrection.
    #[test]
    fn mutation_zero_losing_slot_detected() {
        let rules = Rules {
            zero_losing_slot: false,
            ..SPEC
        };
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
        let rules = Rules {
            deferred_frees: false,
            ..SPEC
        };
        let core = check(CORE, 9, 2, &rules);
        let recycle = check(RECYCLE, 8, 2, &rules);
        assert!(
            core.is_err() || recycle.is_err(),
            "checker missed premature reuse"
        );
    }

    /// Disabling the failure latch must surface a durability lie: a later
    /// successful commit re-captures the blob and vouches (via its entry's
    /// expected content) for a block whose write the failed fsync silently
    /// lost. Committed-entry serving heals the shallow variants (a clean
    /// blob's entry no longer re-references live state, and rewrites of the
    /// lost block re-materialize it), so the surviving lie needs a deeper
    /// interleaving than the BFS budget: the blob re-dirties in a DIFFERENT
    /// block and is re-captured, carrying the lost block's entry along.
    /// Pinned as a directed trace. Under SPEC the latch blocks the trace at
    /// the post-failure append, which is exactly the protection.
    #[test]
    fn mutation_latch_detected() {
        let trace: &[Action] = &[
            // Fill blob 0's first block and lose it to fsyncgate.
            Action::Append(0),
            Action::Append(0),
            Action::Snapshot(ALL),
            Action::WriteMeta,
            Action::FsyncFail,
            // Re-dirty blob 0 in its second block; the next commit's entry
            // vouches for the lost first block without rewriting it.
            Action::Append(0),
            Action::Snapshot(ALL),
            Action::WriteMeta,
            Action::FsyncOk,
            Action::Crash,
        ];
        let rules = Rules {
            latch_on_failure: false,
            ..SPEC
        };
        assert!(
            run_trace(trace, &rules).is_err(),
            "checker missed the latch leak"
        );
    }

    /// Disabling the superblock->table binding (the stored table CRC) must
    /// reintroduce recycled-table-block aliasing: a dropped table write over
    /// a recycled block exposes an older valid table, rolling back a
    /// confirmed commit. This bug was FOUND by this model.
    #[test]
    fn mutation_table_binding_detected() {
        let rules = Rules {
            bind_table: false,
            ..SPEC
        };
        assert!(
            check(CORE, 9, 2, &rules).is_err(),
            "checker missed table aliasing"
        );
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
            Block::Super {
                seq: 0,
                table: RESERVED,
                bound: Table::default(),
            },
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
