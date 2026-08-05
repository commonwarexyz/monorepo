//! The segment-backed [`crate::LogStorage`]: all logs of a family live as
//! extents inside shared append-only segment files.
//!
//! # Layout
//!
//! A store owns one directory of its [Medium]. A family named `f` is its
//! `f.manifest` (identity plus two root slots) and its segment files
//! `f.segment-NNNNNN` (a header page, then records). Exactly one segment --
//! the one the governing root names as active -- accepts appends; every
//! other segment file is sealed and immutable: rotated-out payload segments,
//! dedicated segments holding one oversized transaction, cleaning's copy
//! segments, and the current checkpoint. The name form is deliberately
//! uniform: the root, not the file name, is the authority on which segment
//! is active, so sealing is a root flip rather than a rename protocol with
//! its own crash windows. `f.staging` is the staging name every new file is
//! written under and `f.condemned` a durable destroy intent. Family names
//! cannot contain `.`, so the first dot splits a file name unambiguously.
//! Each file is staged, synced, and renamed into place; a directory barrier
//! makes its entry durable BEFORE anything references it (the reachability
//! rule, written once in [publish]). Opening a family sweeps files the
//! governing root does not reference: torn checkpoint, rotation, and
//! cleaning attempts, superseded checkpoints, and retired segments whose
//! unlink was lost.
//!
//! # Commit
//!
//! [`crate::LogTransaction::start_commit`] folds the staged state into net
//! operations and validates them into a frame (admission: an error changes
//! nothing, and it fails closed with [`Error::FamilyFull`] while the
//! family's metadata still fits a checkpoint, its uncheckpointed span still
//! fits under the replay ceilings, and free space stays above the cleaner's
//! reserve), then writes the frame at the active segment's tail, issues ONE
//! fdatasync barrier -- the frame's checksum is the commit decision -- and
//! folds it into the committed [Index] through [Index::apply]. A transaction
//! whose frame would exceed the segment target instead gets a dedicated
//! sealed segment, published under the reachability rule and made
//! authoritative by the checkpoint that immediately follows; frame semantics
//! are unchanged. Any failure after admission poisons the family and reports
//! through the handle. The whole pipeline runs before the handle is
//! returned; pipelining admission ahead of durability needs an executor,
//! which arrives with the runtime integration.
//!
//! # Maintenance
//!
//! Checkpoints, segment rotation, and cleaning run inline after the commit
//! that made them due, while the transaction still holds the writer (the v1
//! posture: one writer, no background tasks), and again at open when a
//! loaded family is already past the checkpoint trigger -- see
//! [super::maintenance] for the pipeline and its crash story. A maintenance
//! failure poisons the family, and admission fails closed once the
//! uncheckpointed span nears the replay ceilings, so repeated
//! failure/recover cycles can never grow the span past what recovery
//! accepts.
//!
//! # Reserve
//!
//! Cleaning must be able to run exactly when the disk fills, so admission
//! refuses new frames ([`Error::FamilyFull`]) once free space -- when the
//! medium reports it -- would drop below the cleaner's reserve, first giving
//! the cleaner one inline chance to free space. The reserve covers the
//! cleaner's own writes: one oversized frame, one copy output segment, one
//! checkpoint at the family caps, and rotation's header page ([Limits]
//! documents the derivation). Reads and the cleaner itself keep working
//! below the admission floor.
//!
//! # Recovery
//!
//! Opening a family selects the highest valid root ([format] owns the
//! fallback rule), rebuilds the committed [Index] from its checkpoint, and
//! replays the active segment past the root's replay offset --
//! [LogStorage::replay] owns the mechanism. Four invariants govern it:
//!
//! - The governing root is made durable (one manifest barrier) before the
//!   sweep or any new commit acts on it.
//! - Every replayed frame runs through the same [Index::apply] fold as live
//!   commits, so the two can never disagree.
//! - Replay stops at the first torn record; a tear buried under a valid
//!   successor frame, like replay ending before the root's transaction
//!   watermark, is hard corruption, never silent truncation.
//! - Everything replay adopts -- truncation and unsynced frames, plus a
//!   fresh root when frames passed the watermark -- is durable before the
//!   open completes.
//!
//! # Reads
//!
//! Reads are planned under the state lock against the committed index and
//! executed outside it, fetching from whichever segments own the touched
//! extents. Every touched block's checksum is verified; a failure is
//! [`Error::FamilyCorrupt`] and poisons the family, exactly like a failed
//! commit, and reopening recovers from durable state under a fresh session.
//! An in-flight read pins the segments it touches, so maintenance never
//! unlinks a file under a live read.

pub use super::super::family::Draft;
use super::{
    super::{
        Bounds,
        family::{Control, DraftLog, Host, Liveness, Permit, Staged, Staging, fill},
    },
    format::{
        Checkpoint, CheckpointLocator, Decoded, Expect, Identity, Incarnation, LogId, LogOffset,
        MAX_BLOCK_BYTES, MAX_CHECKPOINT_BYTES, MAX_CHECKPOINT_EXTENTS, MAX_CHECKPOINT_LOGS,
        MAX_LOG_NAME_LEN, MAX_LOGS_TOUCHED, MAX_RECORD_BYTES, MAX_TRANSACTION_OPS,
        MAX_TRANSACTION_PAYLOAD, ManifestHeader, NetOp, PAGE, ROOT_OFFSETS, Record, Root,
        SEGMENT_RECORDS, Salt, SegmentHeader, SegmentOffset, SegmentSeq, TxnSeq, ValidatedTxn,
        block_crc, buried_tear, checkpoint_bytes_bound, frame_bytes_bound,
    },
    index::{Extent, Index, LogState, ReadStep},
    maintenance::{Metrics, maintain},
    medium::{Claim, File, Medium},
    publish::{flip_root, publish},
};
use crate::{BufferPool, Error, Handle, IoBufs, IoBufsMut};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_utils::sync::{AsyncMutex, Mutex};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

/// A family's manifest file.
fn manifest_name(family: &str) -> String {
    format!("{family}.manifest")
}

/// A family's segment file. The governing root, not the name, says which one
/// is active.
pub(super) fn segment_name(family: &str, seq: SegmentSeq) -> String {
    format!("{family}.segment-{:06}", seq.0)
}

/// The staging name new files are written under before their rename.
pub(super) fn staging_name(family: &str) -> String {
    format!("{family}.staging")
}

/// The durable destroy intent: the manifest, renamed here, retires the family.
fn condemned_name(family: &str) -> String {
    format!("{family}.condemned")
}

/// Uncheckpointed active-segment bytes that trigger a checkpoint. A plain 64
/// MiB for now; the plan's adaptive candidate (4x metadata size) waits for
/// Phase 4 measurement.
const CHECKPOINT_TRIGGER_BYTES: u64 = 64 << 20;

/// Uncheckpointed transactions that trigger a checkpoint, bounding replay
/// work when transactions are tiny.
const CHECKPOINT_TRIGGER_TXNS: u64 = 1 << 16;

/// Hard ceiling on the byte range recovery replays. An honest store stays
/// under trigger + one maximal frame; a longer range is damage. Checkpoints
/// land inline and poison on failure, and admission fails closed before the
/// span could outgrow this, so the ceiling is never exceeded.
const MAX_REPLAY_BYTES: u64 = 1 << 30;

/// Hard ceiling on the transactions recovery replays.
const MAX_REPLAY_TRANSACTIONS: u64 = 1 << 20;

/// Upper bound on a frame's encoded size beyond its payload (how
/// [MAX_RECORD_BYTES] is derived from the payload cap), letting admission
/// bound a frame's size before it is encoded.
const MAX_FRAME_OVERHEAD: u64 = MAX_RECORD_BYTES - MAX_TRANSACTION_PAYLOAD;

/// The operational segment target, frozen for Phase 3: when the active
/// segment's records reach it, the commit that got them there pays for a
/// rotation, and a single frame larger than it gets a dedicated segment. An
/// active segment therefore holds at most one target of records plus one
/// admitted frame.
const SEGMENT_TARGET_BYTES: u64 = 256 << 20;

/// The cleaner's reserve: admission stops accepting frames once free space
/// (when the medium reports it) would fall below this, so cleaning can still
/// write inside it. 2 GiB comfortably covers [Limits::min_reserve] at the
/// frozen caps (about 1.6 GiB).
const CLEANER_RESERVE_BYTES: u64 = 2 << 30;

const _: () = assert!(CHECKPOINT_TRIGGER_BYTES + MAX_RECORD_BYTES <= MAX_REPLAY_BYTES);
const _: () = assert!(CHECKPOINT_TRIGGER_TXNS < MAX_REPLAY_TRANSACTIONS);
// An eligible victim's copy cost is at most half a record's bytes, so one
// output segment always fits the whole copy: no victim can be eligible yet
// permanently over the per-pass budget.
const _: () = assert!(MAX_RECORD_BYTES / 2 <= SEGMENT_TARGET_BYTES);

/// The values maintenance and admission run on: the checkpoint triggers
/// (soft policy: when a maintenance pass becomes due), the family-capacity
/// ceilings admission and recovery enforce (hard: exceeding one is refusal
/// or corruption), and the two hard safety controls (the segment target and
/// the cleaner reserve). Internal (the no-knob rule; public exposure is a
/// Phase 4+ decision); tests shrink them to hit each gate cheaply.
#[derive(Clone, Copy)]
pub(super) struct Limits {
    /// Soft policy: uncheckpointed active-segment bytes past which the next
    /// maintenance pass checkpoints ([CHECKPOINT_TRIGGER_BYTES]).
    pub checkpoint_trigger_bytes: u64,
    /// Soft policy: uncheckpointed transactions past which the next
    /// maintenance pass checkpoints ([CHECKPOINT_TRIGGER_TXNS]).
    pub checkpoint_trigger_txns: u64,
    /// Hard ceiling: committed logs a checkpoint may hold
    /// ([MAX_CHECKPOINT_LOGS]).
    pub checkpoint_logs: usize,
    /// Hard ceiling: committed extents a checkpoint may hold
    /// ([MAX_CHECKPOINT_EXTENTS]).
    pub checkpoint_extents: u64,
    /// Hard ceiling: bytes recovery will replay ([MAX_REPLAY_BYTES]).
    pub replay_bytes: u64,
    /// Hard ceiling: transactions recovery will replay
    /// ([MAX_REPLAY_TRANSACTIONS]).
    pub replay_txns: u64,
    /// Active-segment record bytes that trigger rotation, and the frame size
    /// past which a transaction gets a dedicated segment
    /// ([SEGMENT_TARGET_BYTES]).
    pub segment_target_bytes: u64,
    /// Free bytes admission keeps in reserve for the cleaner
    /// ([CLEANER_RESERVE_BYTES]).
    pub cleaner_reserve_bytes: u64,
}

impl Limits {
    /// The production values.
    pub(super) const DEFAULT: Self = Self {
        checkpoint_trigger_bytes: CHECKPOINT_TRIGGER_BYTES,
        checkpoint_trigger_txns: CHECKPOINT_TRIGGER_TXNS,
        checkpoint_logs: MAX_CHECKPOINT_LOGS,
        checkpoint_extents: MAX_CHECKPOINT_EXTENTS as u64,
        replay_bytes: MAX_REPLAY_BYTES,
        replay_txns: MAX_REPLAY_TRANSACTIONS,
        segment_target_bytes: SEGMENT_TARGET_BYTES,
        cleaner_reserve_bytes: CLEANER_RESERVE_BYTES,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Limits {
    /// The smallest reserve under which the cleaner can always run below the
    /// admission floor: one oversized frame in its dedicated segment (header
    /// page plus the largest frame `bounds` admits), one full copy output
    /// segment, one checkpoint at these limits' caps (each extent
    /// conservatively in its own referenced segment), and rotation's fresh
    /// header page. The constructor asserts the reserve covers it -- without
    /// the copy and checkpoint terms, cleaning could not start exactly when
    /// it is needed.
    const fn min_reserve(&self, bounds: &Bounds) -> u64 {
        let frame = frame_bytes_bound(
            bounds.max_transaction_bytes,
            bounds.max_transaction_logs as u64,
            bounds.max_log_name_len as u64,
        );
        let checkpoint =
            checkpoint_bytes_bound(self.checkpoint_logs as u64, self.checkpoint_extents);
        (PAGE as u64 + frame)
            + (PAGE as u64 + self.segment_target_bytes)
            + (PAGE as u64 + checkpoint)
            + PAGE as u64
    }

    /// The free-space level below which admission may be refusing frames:
    /// the reserve plus the largest single admission `bounds` allows, plus
    /// one segment target of slack. The cleaner treats free space below this
    /// as reserve pressure, so any admission the gate refuses implies
    /// pressure and the inline cleaning retry can actually run.
    pub(super) const fn admission_floor(&self, bounds: &Bounds) -> u64 {
        self.cleaner_reserve_bytes
            + PAGE as u64
            + frame_bytes_bound(
                bounds.max_transaction_bytes,
                bounds.max_transaction_logs as u64,
                bounds.max_log_name_len as u64,
            )
            + self.segment_target_bytes
    }
}

/// Admission's family-capacity gate: whether admitting `txn` keeps the family
/// checkpointable (log and extent caps) and its uncheckpointed span -- the
/// given committed `span_bytes`/`span_txns` plus this frame -- under the
/// replay ceilings, so state recovery would refuse can never commit.
/// Conservative on purpose: removals refund nothing (the checkpoint that
/// collects the refund has not happened), and the frame's encoded size is
/// bounded by its payload plus the frozen framing allowance.
fn fits_family(
    index: &Index,
    span_bytes: u64,
    span_txns: u64,
    txn: &ValidatedTxn,
    limits: &Limits,
) -> bool {
    let creates = txn
        .ops()
        .iter()
        .filter(|(_, op)| matches!(op, NetOp::Create { .. }))
        .count();
    if index.logs.len() + creates > limits.checkpoint_logs {
        return false;
    }
    let mut blocks: u64 = 0;
    let mut payload: u64 = 0;
    for (_, op) in txn.ops() {
        if let NetOp::Create { run, .. } | NetOp::Mutate { run, .. } = op {
            blocks += run.len().div_ceil(MAX_BLOCK_BYTES) as u64;
            payload += run.len() as u64;
        }
    }
    if index.extent_count + blocks > limits.checkpoint_extents {
        return false;
    }
    if span_bytes + payload + MAX_FRAME_OVERHEAD > limits.replay_bytes {
        return false;
    }
    span_txns < limits.replay_txns
}

pub(super) fn corrupt(name: &str, reason: impl Into<String>) -> Error {
    Error::FamilyCorrupt(name.into(), reason.into())
}

/// Reads one full page, reporting a short file as family damage.
async fn read_page<F: File>(file: &F, name: &str, at: u64) -> Result<Vec<u8>, Error> {
    match file.read_at(at, PAGE).await {
        Err(Error::LogInsufficientLength) => Err(corrupt(name, "page is short")),
        other => other,
    }
}

/// Segment-backed log storage over a [Medium].
#[derive(Clone)]
pub struct LogStorage<M: Medium> {
    medium: M,
    /// The one directory of the medium this store owns.
    dir: String,
    /// Entropy for incarnation minting; see [LogStorage::new].
    seed: [u8; 16],
    /// Incarnations minted so far, separating mints under one seed.
    minted: Arc<AtomicU64>,
    /// Family registry: serializes `open_family` and `destroy_family`; a
    /// poisoned family's recovery runs outside it.
    families: Arc<AsyncMutex<BTreeMap<String, Arc<Shared<M>>>>>,
    pool: BufferPool,
    bounds: Bounds,
    /// Copied into each family at open.
    limits: Limits,
}

/// A sealed payload segment: immutable, so its open handle and size are
/// shareable facts. Live extents keep it referenced; maintenance retires it
/// once none remain.
pub(super) struct Sealed<F> {
    pub file: F,
    /// Total file bytes, fixed at seal.
    pub bytes: u64,
}

/// A family's state rebuilt from (or created as) its durable files.
struct Loaded<M: Medium> {
    incarnation: Incarnation,
    salt: Salt,
    manifest: M::File,
    /// The governing root.
    root: Root,
    active_seq: SegmentSeq,
    active: M::File,
    tail: SegmentOffset,
    index: Index,
    /// Sealed payload segments the checkpoint references, opened and
    /// size-validated.
    sealed: BTreeMap<SegmentSeq, Sealed<M::File>>,
    /// Next unused segment sequence (maintenance and dedicated segments mint
    /// from here).
    next_segment: SegmentSeq,
}

impl<M: Medium> LogStorage<M> {
    /// Creates a store owning directory `dir` of `medium`, enforcing `bounds`
    /// on every transaction. Each bound is clamped to its frozen format cap,
    /// so staging enforces the clamped values and admission can never reject
    /// a transaction staging accepted.
    ///
    /// `seed` feeds incarnation minting: uniqueness of recreated-family
    /// incarnations across process restarts rests on the caller supplying
    /// fresh entropy per store instance.
    pub fn new(
        medium: M,
        dir: impl Into<String>,
        seed: [u8; 16],
        pool: BufferPool,
        bounds: Bounds,
    ) -> Self {
        let bounds = Bounds {
            max_transaction_bytes: bounds.max_transaction_bytes.min(MAX_TRANSACTION_PAYLOAD),
            max_transaction_logs: bounds.max_transaction_logs.min(MAX_LOGS_TOUCHED),
            max_log_name_len: bounds.max_log_name_len.min(MAX_LOG_NAME_LEN),
        };
        // Belt for the clamp: a transaction within these bounds always
        // encodes (the fold emits at most two descriptors per touched log).
        debug_assert!(bounds.max_transaction_bytes <= MAX_TRANSACTION_PAYLOAD);
        debug_assert!(2 * bounds.max_transaction_logs <= MAX_TRANSACTION_OPS);
        debug_assert!(bounds.max_log_name_len <= MAX_LOG_NAME_LEN);
        let limits = Limits::default();
        // The reserve must cover the cleaner's own writes, or cleaning could
        // not start exactly when it is needed (see Limits::min_reserve).
        debug_assert!(limits.cleaner_reserve_bytes >= limits.min_reserve(&bounds));
        // The soft triggers must land a checkpoint before the hard replay
        // ceilings, or admission wedges. Asserted over the actual values, not
        // just the production constants.
        debug_assert!(limits.checkpoint_trigger_bytes + MAX_RECORD_BYTES <= limits.replay_bytes);
        debug_assert!(limits.checkpoint_trigger_txns < limits.replay_txns);
        Self {
            medium,
            dir: dir.into(),
            seed,
            minted: Arc::new(AtomicU64::new(0)),
            families: Arc::new(AsyncMutex::new(BTreeMap::new())),
            pool,
            bounds,
            limits,
        }
    }

    /// Mints a fresh family identity. It must never equal the incarnation of
    /// any file that can still exist under the family's name: the counter
    /// separates mints within this store, and the seed separates store
    /// instances (a crash-torn destroy or creation can leave old files for a
    /// later process to clear).
    fn mint_incarnation(&self, name: &str) -> Incarnation {
        let count = self.minted.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        let digest = Sha256::hash(&[&self.seed, &count, name.as_bytes()]);
        Incarnation(digest.0[..16].try_into().unwrap())
    }

    /// The medium's file names under this family's prefix.
    async fn family_files(&self, name: &str) -> Result<Vec<String>, Error> {
        let prefix = format!("{name}.");
        Ok(self
            .medium
            .list(&self.dir)
            .await?
            .unwrap_or_default()
            .into_iter()
            .filter(|file| file.starts_with(&prefix))
            .collect())
    }

    /// Loads a family from its durable files, or returns None if no manifest
    /// exists (the family does not exist).
    async fn load_family(&self, name: &str) -> Result<Option<Loaded<M>>, Error> {
        let Some(manifest) = self.medium.open(&self.dir, &manifest_name(name)).await? else {
            return Ok(None);
        };
        let page = read_page(&manifest, name, 0).await?;
        let header = ManifestHeader::decode(&page).map_err(|reason| corrupt(name, reason))?;
        let mut governing: Option<Root> = None;
        for (slot, &offset) in ROOT_OFFSETS.iter().enumerate() {
            let page = read_page(&manifest, name, offset).await?;
            if let Some(root) = Root::decode(&page, &header.incarnation, slot)
                .map_err(|reason| corrupt(name, reason))?
                && governing.as_ref().is_none_or(|g| g.seq < root.seq)
            {
                governing = Some(root);
            }
        }
        let Some(root) = governing else {
            return Err(corrupt(name, "no valid root"));
        };
        // The sweep below and every commit this open admits act on the
        // governing root, so it must be durable first: an in-process reopen
        // after a failed root flip can select a root that reached only the
        // write cache, and without this barrier a later crash would revert to
        // the predecessor root -- whose checkpoint the sweep just removed.
        // One barrier per open makes a cache-adopted root durable (a no-op
        // when it already was).
        manifest.sync().await?;

        let salt = Salt::new(&header.incarnation, root.epoch);
        let index = match &root.checkpoint {
            None => Index {
                next_log: root.next_log,
                next_txn: root.replay_from,
                ..Index::default()
            },
            Some(locator) => {
                self.load_checkpoint(name, &header.incarnation, &salt, &root, locator)
                    .await?
            }
        };
        let sealed = self
            .open_sealed(name, &header.incarnation, &root, &index)
            .await?;

        // Sweep files the governing root does not reference: torn
        // checkpoint, rotation, and cleaning attempts (a staging file, or a
        // complete file whose root flip never landed), superseded
        // checkpoints, and retired segments whose unlink was lost to a
        // crash. Removal durability rides later barriers; a resurrected
        // leftover is simply swept again.
        let mut keep = vec![manifest_name(name), segment_name(name, root.active_segment)];
        if let Some(locator) = &root.checkpoint {
            keep.push(segment_name(name, locator.segment));
        }
        keep.extend(sealed.keys().map(|&seq| segment_name(name, seq)));
        for file in self.family_files(name).await? {
            if !keep.contains(&file) {
                self.medium.remove(&self.dir, &file).await?;
            }
        }

        self.replay(
            name,
            header.incarnation,
            salt,
            manifest,
            root,
            index,
            sealed,
        )
        .await
        .map(Some)
    }

    /// Opens every sealed segment `index` references, validating each header
    /// and that every extent lies within its file, so a missing or short
    /// sealed segment fails the open instead of a later read.
    async fn open_sealed(
        &self,
        name: &str,
        incarnation: &Incarnation,
        root: &Root,
        index: &Index,
    ) -> Result<BTreeMap<SegmentSeq, Sealed<M::File>>, Error> {
        // The farthest byte any extent reaches, per sealed segment.
        let mut ends: BTreeMap<SegmentSeq, u64> = BTreeMap::new();
        for log in index.logs.values() {
            for extent in log.extents.values() {
                if extent.segment == root.active_segment {
                    continue;
                }
                // Offsets validated overflow-free at checkpoint load.
                let end = (extent.payload.0 + extent.len).max(extent.crc.0 + 4);
                let entry = ends.entry(extent.segment).or_insert(0);
                *entry = (*entry).max(end);
            }
        }
        let mut sealed = BTreeMap::new();
        for (&seq, &end) in &ends {
            let file_name = segment_name(name, seq);
            let Some(file) = self.medium.open(&self.dir, &file_name).await? else {
                return Err(corrupt(name, "referenced segment is missing"));
            };
            let page = read_page(&file, name, 0).await?;
            SegmentHeader::decode(&page, incarnation, seq)
                .map_err(|reason| corrupt(name, reason))?;
            let bytes = file.size().await?;
            if end > bytes {
                return Err(corrupt(name, "extent past the sealed segment end"));
            }
            sealed.insert(seq, Sealed { file, bytes });
        }
        Ok(sealed)
    }

    /// Loads and verifies the checkpoint a valid root names, rebuilding the
    /// committed index it describes. Publication order (checkpoint durable
    /// before the root) means a valid root proves its checkpoint was
    /// complete, so every failure here is hard corruption, never a fallback.
    async fn load_checkpoint(
        &self,
        name: &str,
        incarnation: &Incarnation,
        salt: &Salt,
        root: &Root,
        locator: &CheckpointLocator,
    ) -> Result<Index, Error> {
        if locator.len > MAX_CHECKPOINT_BYTES {
            return Err(corrupt(name, "checkpoint length exceeds its cap"));
        }
        let file_name = segment_name(name, locator.segment);
        let Some(file) = self.medium.open(&self.dir, &file_name).await? else {
            return Err(corrupt(name, "checkpoint segment is missing"));
        };
        let page = read_page(&file, name, 0).await?;
        SegmentHeader::decode(&page, incarnation, locator.segment)
            .map_err(|reason| corrupt(name, reason))?;
        let bytes = match file.read_at(locator.start.0, locator.len as usize).await {
            Err(Error::LogInsufficientLength) => return Err(corrupt(name, "checkpoint is short")),
            other => other?,
        };
        let ident = Identity {
            salt: *salt,
            segment: locator.segment,
        };
        let checkpoint = Checkpoint::decode(&bytes, &ident, locator.seq)
            .map_err(|reason| corrupt(name, reason))?;
        if checkpoint.end().hash != locator.hash {
            return Err(corrupt(name, "checkpoint hash does not match the root"));
        }
        if checkpoint.next_log() != root.next_log || checkpoint.next_txn() != root.replay_from {
            return Err(corrupt(
                name,
                "checkpoint minting floors do not match the root",
            ));
        }
        // Every extent must live in a segment the checkpoint claims (which
        // also rejects extents under an empty segment list). Extents in the
        // active segment must lie entirely below the located replay
        // boundary: everything a checkpoint maps was durable when the root
        // named it, so a row reaching past that boundary is damage, caught
        // here rather than as a read error later. Sealed-segment extents are
        // checked against their file once it is opened.
        let segments: Vec<SegmentSeq> = checkpoint.segments().copied().collect();
        for extent in checkpoint.extents() {
            if !segments.contains(&extent.segment) {
                return Err(corrupt(name, "extent outside the checkpoint's segments"));
            }
            let (Some(payload_end), Some(crc_end)) = (
                extent.start.0.checked_add(extent.len),
                extent.crc.0.checked_add(4),
            ) else {
                return Err(corrupt(name, "extent offsets overflow"));
            };
            if extent.segment == root.active_segment
                && (payload_end > root.replay_at.0 || crc_end > root.replay_at.0)
            {
                return Err(corrupt(name, "extent past the replay boundary"));
            }
        }
        let index = Index::from_checkpoint(
            checkpoint.rows(),
            checkpoint.extents(),
            root.next_log,
            root.replay_from,
        )
        .map_err(|reason| corrupt(name, reason))?;
        // The list is derived from live extents, so no honest checkpoint
        // pads it with segments nothing references.
        for segment in &segments {
            if !index.live.contains_key(segment) {
                return Err(corrupt(name, "checkpoint claims a segment with no extents"));
            }
        }
        Ok(index)
    }

    /// Extends `index` (the checkpoint's committed state, or empty) by
    /// replaying the active segment from the root's replay offset, then
    /// truncates the tail to the last valid record boundary, durably, before
    /// appends may resume.
    #[allow(clippy::too_many_arguments)]
    async fn replay(
        &self,
        name: &str,
        incarnation: Incarnation,
        salt: Salt,
        manifest: M::File,
        mut root: Root,
        mut index: Index,
        sealed: BTreeMap<SegmentSeq, Sealed<M::File>>,
    ) -> Result<Loaded<M>, Error> {
        let file_name = segment_name(name, root.active_segment);
        let Some(segment) = self.medium.open(&self.dir, &file_name).await? else {
            // Creation makes the segment durable before the manifest can name
            // it (reachability), so a missing segment is damage.
            return Err(corrupt(name, "active segment is missing"));
        };
        let page = read_page(&segment, name, 0).await?;
        SegmentHeader::decode(&page, &incarnation, root.active_segment)
            .map_err(|reason| corrupt(name, reason))?;

        // Everything below the replay offset was durable when the root was
        // published, and every replayed byte is bounded by the checkpoint
        // trigger; a range breaching the ceiling is damage.
        let size = segment.size().await?;
        let start = root.replay_at.0;
        if start < PAGE as u64 || start > size {
            return Err(corrupt(name, "replay offset outside the active segment"));
        }
        if size - start > self.limits.replay_bytes {
            return Err(corrupt(name, "replay range exceeds its ceiling"));
        }
        let len = usize::try_from(size - start).map_err(|_| Error::Unsupported)?;
        // One allocation holds the whole replay span, bounded by the ceiling
        // just checked; streaming decode arrives if a deployment ever needs
        // it.
        let body = segment.read_at(start, len).await?;
        let ident = Identity {
            salt,
            segment: root.active_segment,
        };
        let mut pos = 0;
        let mut frames = 0u64;
        loop {
            match Record::decode(&body[pos..], &ident, Expect::Frame(index.next_txn)) {
                Decoded::Record(record, consumed) => {
                    let Record::TransactionFrame(txn) = record else {
                        return Err(corrupt(name, "record kind not valid in this segment"));
                    };
                    frames += 1;
                    if frames > self.limits.replay_txns {
                        return Err(corrupt(name, "replay exceeds its transaction ceiling"));
                    }
                    let at = SegmentOffset(start + pos as u64);
                    index
                        .apply(&txn, &txn.block_sites(consumed), root.active_segment, at)
                        .map_err(|reason| corrupt(name, reason))?;
                    pos += consumed;
                }
                Decoded::TornTail => {
                    // A frame is written only after its predecessor's barrier,
                    // so a valid frame at any claimed-length hop past the tear
                    // proves the torn frame was acknowledged: damage, not a
                    // crash artifact. The probe's residual blindness: a
                    // damaged length prefix hiding every successor, a
                    // mid-stream zeroed first length byte (reads as a clean
                    // end), and damage extending through the final
                    // acknowledged frame.
                    if buried_tear(&body[pos..], &ident, index.next_txn) {
                        return Err(corrupt(name, "acknowledged frame is damaged"));
                    }
                    break;
                }
                Decoded::CleanEnd => break,
                Decoded::Corrupt(reason) => return Err(corrupt(name, reason)),
            }
        }
        // next_txn is the anti-truncation watermark: every frame the root
        // promises must be present.
        if index.next_txn < root.next_txn {
            return Err(corrupt(
                name,
                "replay ended before the root's transaction watermark",
            ));
        }
        let boundary = start + pos as u64;
        if size > boundary {
            segment.set_len(boundary).await?;
        }
        // One barrier adopts what replay accepted: frames a failed session
        // wrote but never synced, and the truncation above, become durable
        // before any reader can observe them. It also keeps the
        // successor-proves-predecessor rule sound across sessions: without
        // it, an adopted-unsynced frame N under a new commit N+1 could later
        // settle torn-N-under-valid-N+1, and the probe would report an
        // honest store corrupt.
        segment.sync().await?;
        // Frames past the root's watermark were adopted above: publish a
        // fresh root pinning the new watermark, extending the
        // anti-truncation protection to them before the open completes.
        // Everything else stays: the checkpoint locator, the replay anchor,
        // and `next_log`, which is the minting floor AT the anchor -- the
        // next replay re-reads the same frames, so advancing it would make
        // it reject their mints. Failure fails the open; the family stays
        // unrecovered.
        if index.next_txn > root.next_txn {
            root = Root {
                seq: root.seq + 1,
                next_txn: index.next_txn,
                ..root
            };
            flip_root(&manifest, &incarnation, &root).await?;
        }
        let next_segment = SegmentSeq(
            root.active_segment
                .0
                .max(root.checkpoint.map_or(0, |c| c.segment.0))
                .max(sealed.keys().last().map_or(0, |seq| seq.0))
                + 1,
        );
        Ok(Loaded {
            incarnation,
            salt,
            manifest,
            root,
            active_seq: root.active_segment,
            active: segment,
            tail: SegmentOffset(boundary),
            index,
            sealed,
            next_segment,
        })
    }

    /// Creates a family durably, honoring the reachability rule: the segment
    /// is staged, synced, renamed, and its directory entry made durable
    /// BEFORE the manifest -- whose root names that segment -- is written; a
    /// second directory barrier then publishes the manifest.
    async fn create_family(&self, name: &str) -> Result<Loaded<M>, Error> {
        // No durable manifest means every file under this family's name is
        // leftover from a torn creation or destroy; clear them. The removals
        // become durable with the first directory barrier below.
        for file in self.family_files(name).await? {
            self.medium.remove(&self.dir, &file).await?;
        }

        // The segment's dentry must be durable before the manifest -- whose
        // root names it -- exists; publish provides exactly that order.
        let incarnation = self.mint_incarnation(name);
        let seq = SegmentSeq(1);
        let segment = publish(
            &self.medium,
            &self.dir,
            &staging_name(name),
            &segment_name(name, seq),
            SegmentHeader { incarnation, seq }.encode(),
        )
        .await?;

        let root = Root {
            seq: 0,
            epoch: 0,
            checkpoint: None,
            active_segment: seq,
            replay_from: TxnSeq(0),
            replay_at: SEGMENT_RECORDS,
            next_log: LogId(0),
            next_txn: TxnSeq(0),
        };
        let mut pages = ManifestHeader { incarnation }.encode();
        pages.extend_from_slice(&root.encode(&incarnation));
        pages.resize(3 * PAGE, 0); // header + two root slots; slot 1 never written
        let manifest = publish(
            &self.medium,
            &self.dir,
            &staging_name(name),
            &manifest_name(name),
            pages,
        )
        .await?;
        self.medium.sync_root().await?;
        Ok(Loaded {
            incarnation,
            salt: Salt::new(&incarnation, 0),
            manifest,
            root,
            active_seq: seq,
            active: segment,
            tail: SEGMENT_RECORDS,
            index: Index::default(),
            sealed: BTreeMap::new(),
            next_segment: SegmentSeq(2),
        })
    }
}

impl<M: Medium> crate::LogStorage for LogStorage<M> {
    type Family = Family<M>;

    async fn open_family(&self, name: &str) -> Result<Family<M>, Error> {
        crate::storage::validate_name(name)?;
        loop {
            let mut families = self.families.lock().await;
            let shared = match families.get(name) {
                Some(shared) => {
                    let poisoned =
                        matches!(shared.state.lock().control.liveness, Liveness::Poisoned);
                    if !poisoned {
                        // A plain reopen: same session, interchangeable
                        // handles.
                        let session = shared.state.lock().control.session;
                        return Ok(Family {
                            shared: shared.clone(),
                            session,
                            pool: self.pool.clone(),
                            bounds: self.bounds,
                        });
                    }
                    // Recovery: rebuild from durable state over the same
                    // incarnation and mint a fresh session; handles from
                    // before it fail Closed from now on. Taking the writer
                    // first means no commit I/O from the failed session can
                    // land after replay. The registry lock is released while
                    // recovery runs, so it never stalls opens of unrelated
                    // families; liveness is re-validated after the wait.
                    let shared = shared.clone();
                    drop(families);
                    let permit = Permit::acquire_for_recovery(&shared).await?;
                    let liveness = shared.state.lock().control.liveness;
                    match liveness {
                        // Another opener recovered it while we waited.
                        Liveness::Open => {
                            let session = shared.state.lock().control.session;
                            drop(permit);
                            return Ok(Family {
                                shared,
                                session,
                                pool: self.pool.clone(),
                                bounds: self.bounds,
                            });
                        }
                        // Destroyed while we waited: the registry entry is
                        // gone, so retry from the top (open racing destroy
                        // waits, then opens fresh).
                        Liveness::Destroyed => continue,
                        Liveness::Poisoned => {}
                    }
                    let loaded = self
                        .load_family(name)
                        .await?
                        .ok_or_else(|| corrupt(name, "manifest is missing"))?;
                    if loaded.incarnation != shared.incarnation {
                        return Err(corrupt(name, "incarnation changed under a live family"));
                    }
                    let session = {
                        let mut state = shared.state.lock();
                        state.index = loaded.index;
                        state.manifest = loaded.manifest;
                        state.root = loaded.root;
                        state.active = loaded.active;
                        state.active_seq = loaded.active_seq;
                        state.tail = loaded.tail;
                        state.salt = loaded.salt;
                        state.sealed = loaded.sealed;
                        state.next_segment = loaded.next_segment;
                        // Pins and retirements belong to the dead session;
                        // stale pin guards see the session bump and stand
                        // down. The swept files' handles stay readable for
                        // any still-running old-session read.
                        state.pins.clear();
                        state.retired.clear();
                        state.control.fail_next_commit = false;
                        state.control.poison_next_maintenance = false;
                        state.control.session += 1;
                        state.control.liveness = Liveness::Open;
                        state.control.session
                    };
                    // Maintenance-on-open (the writer is still held): a
                    // loaded family already past the checkpoint trigger
                    // checkpoints now, so admission can never stay wedged at
                    // the replay ceilings.
                    maintain(&shared, session, false).await?;
                    drop(permit);
                    return Ok(Family {
                        shared,
                        session,
                        pool: self.pool.clone(),
                        bounds: self.bounds,
                    });
                }
                None => {
                    let loaded = match self.load_family(name).await? {
                        Some(loaded) => loaded,
                        None => self.create_family(name).await?,
                    };
                    let shared = Arc::new(Shared::new(name, self, loaded));
                    families.insert(name.into(), shared.clone());
                    shared
                }
            };
            drop(families);
            // Maintenance-on-open for a freshly loaded family, through the
            // normal writer queue (a concurrent opener may already hold a
            // transaction).
            let session = shared.state.lock().control.session;
            let permit = Permit::acquire(&shared, session).await?;
            maintain(&shared, session, false).await?;
            drop(permit);
            return Ok(Family {
                shared,
                session,
                pool: self.pool.clone(),
                bounds: self.bounds,
            });
        }
    }

    async fn scan_families(&self) -> Result<Vec<String>, Error> {
        Ok(self
            .medium
            .list(&self.dir)
            .await?
            .unwrap_or_default()
            .into_iter()
            .filter_map(|file| file.strip_suffix(".manifest").map(str::to_string))
            // Junk like `a.b.manifest` strips to an invalid family name.
            .filter(|name| crate::storage::validate_name(name).is_ok())
            .collect())
    }

    async fn destroy_family(&self, name: &str) -> Result<(), Error> {
        // Racing an in-flight checkpoint can orphan a staging file until the
        // next open's sweep clears it (accepted).
        crate::storage::validate_name(name)?;
        let mut families = self.families.lock().await;
        if let Some(shared) = families.remove(name) {
            let mut state = shared.state.lock();
            state.control.liveness = Liveness::Destroyed;
            // Handles and the live transaction discover destruction through
            // the liveness.
            state.control.writer.close_waiters();
            state.index.names.clear();
            state.index.logs.clear();
        }
        let files = self.family_files(name).await?;
        if files.is_empty() {
            return Ok(());
        }
        let manifest = manifest_name(name);
        let condemned = condemned_name(name);
        // Durable destroy intent first: retire the manifest name by renaming
        // it to the condemned marker. From that barrier on the family does
        // not exist, and every remaining file under its name is garbage that
        // this pass -- or a later open, after a crash -- clears.
        let had_manifest = files.contains(&manifest);
        if had_manifest {
            self.medium.rename(&self.dir, &manifest, &condemned).await?;
            self.medium.sync_dir(&self.dir).await?;
        }
        for file in &files {
            if *file != manifest && *file != condemned {
                self.medium.remove(&self.dir, file).await?;
            }
        }
        self.medium.sync_dir(&self.dir).await?;
        // The intent marker goes last: until here, a crash re-runs the
        // removal instead of leaving orphans a future creation could trip on.
        if had_manifest || files.contains(&condemned) {
            self.medium.remove(&self.dir, &condemned).await?;
            self.medium.sync_dir(&self.dir).await?;
        }
        Ok(())
    }
}

/// State shared by every handle into one family incarnation.
///
/// A `Shared` value *is* one incarnation: destroy-then-recreate mints a new
/// `Shared`, so handles into the old incarnation can never observe the new
/// one.
pub(super) struct Shared<M: Medium> {
    pub name: String,
    /// The store directory holding this family's files.
    pub dir: String,
    pub medium: M,
    pub incarnation: Incarnation,
    pub limits: Limits,
    /// The store's (clamped) transaction bounds, sizing the admission floor.
    pub bounds: Bounds,
    pub state: Mutex<State<M>>,
}

impl<M: Medium> Shared<M> {
    fn new(name: &str, store: &LogStorage<M>, loaded: Loaded<M>) -> Self {
        Self {
            name: name.into(),
            dir: store.dir.clone(),
            medium: store.medium.clone(),
            incarnation: loaded.incarnation,
            limits: store.limits,
            bounds: store.bounds,
            state: Mutex::new(State {
                control: Control::default(),
                index: loaded.index,
                manifest: loaded.manifest,
                root: loaded.root,
                active: loaded.active,
                active_seq: loaded.active_seq,
                tail: loaded.tail,
                salt: loaded.salt,
                sealed: loaded.sealed,
                next_segment: loaded.next_segment,
                pins: BTreeMap::new(),
                retired: Vec::new(),
                metrics: Metrics::default(),
            }),
        }
    }
}

impl<M: Medium> Host for Shared<M> {
    fn name(&self) -> &str {
        &self.name
    }

    fn with_control<R>(&self, f: impl FnOnce(&mut Control<Self>) -> R) -> R {
        f(&mut self.state.lock().control)
    }
}

/// Mutable state of one family incarnation.
pub(super) struct State<M: Medium> {
    /// Handle validity, liveness, the fault fuse, and the writer queue.
    pub control: Control<Shared<M>>,
    /// The committed state: logical logs and where their bytes live.
    pub index: Index,
    /// The manifest, kept open for root flips.
    pub manifest: M::File,
    /// The governing root; its replay fields anchor the uncheckpointed span.
    pub root: Root,
    /// The one segment accepting appends.
    pub active: M::File,
    pub active_seq: SegmentSeq,
    /// First unwritten byte of the active segment: where the next frame lands.
    pub tail: SegmentOffset,
    /// Checksum salt of the governing root's epoch.
    pub salt: Salt,
    /// Sealed payload segments, open for reads and measured for cleaning.
    pub sealed: BTreeMap<SegmentSeq, Sealed<M::File>>,
    /// Next unused segment sequence (maintenance and dedicated segments mint
    /// from here).
    pub next_segment: SegmentSeq,
    /// Reader pin counts by segment: an in-flight read holds one pin per
    /// touched segment, and maintenance defers unlinking a pinned segment.
    pub pins: BTreeMap<SegmentSeq, u64>,
    /// Segments no durable root references anymore, awaiting an unpinned
    /// unlink.
    pub retired: Vec<SegmentSeq>,
    /// Maintenance counters, read by tests.
    pub metrics: Metrics,
}

/// Handle to a family.
#[derive(Clone)]
pub struct Family<M: Medium> {
    shared: Arc<Shared<M>>,
    /// The session this handle was minted in; recovery invalidates it.
    session: u64,
    pool: BufferPool,
    bounds: Bounds,
}

impl<M: Medium> Family<M> {
    /// Validate this handle against the current family state.
    fn ensure_open(&self) -> Result<(), Error> {
        self.shared
            .state
            .lock()
            .control
            .ensure_open(&self.shared.name, self.session)
    }
}

impl<M: Medium> crate::LogFamily for Family<M> {
    type Log = Log<M>;
    type Transaction = Transaction<M>;

    async fn open(&self, name: &[u8]) -> Result<Option<Log<M>>, Error> {
        let state = self.shared.state.lock();
        state.control.ensure_open(&self.shared.name, self.session)?;
        Ok(state.index.names.get(name).map(|&id| Log {
            shared: self.shared.clone(),
            session: self.session,
            id,
            pool: self.pool.clone(),
        }))
    }

    async fn scan(&self) -> Result<Vec<Vec<u8>>, Error> {
        let state = self.shared.state.lock();
        state.control.ensure_open(&self.shared.name, self.session)?;
        Ok(state.index.names.keys().cloned().collect())
    }

    async fn transaction(&self) -> Result<Transaction<M>, Error> {
        let permit = Permit::acquire(&self.shared, self.session).await?;
        Ok(Transaction {
            family: self.clone(),
            permit,
            staging: Staging::new(self.bounds),
        })
    }
}

/// Pins held by one in-flight read: one per touched segment, so maintenance
/// never unlinks a file under a live read. Dropping the guard releases them;
/// a guard outliving its session stands down (recovery reset the pin table).
/// Invariant: never drop a Pins guard while holding the family state lock --
/// Drop takes that lock.
struct Pins<M: Medium> {
    shared: Arc<Shared<M>>,
    session: u64,
    seqs: Vec<SegmentSeq>,
}

impl<M: Medium> Drop for Pins<M> {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock();
        if state.control.session != self.session {
            return;
        }
        for seq in &self.seqs {
            let pins = state.pins.get_mut(seq).expect("pinned at plan time");
            *pins -= 1;
            if *pins == 0 {
                state.pins.remove(seq);
            }
        }
    }
}

/// A planned, verified fetch of committed bytes, built under the state lock
/// and executed outside it. Extents are immutable once written and the plan
/// pins every touched segment, so a plan stays valid after the lock drops;
/// `session` detects the planned state being replaced (recovery or
/// destruction) while the reads run.
struct Fetch<M: Medium> {
    steps: Vec<ReadStep>,
    /// Open handle per touched segment.
    files: BTreeMap<SegmentSeq, M::File>,
    salt: Salt,
    session: u64,
    /// Released when the fetch completes or is cancelled.
    #[allow(dead_code)]
    pins: Pins<M>,
}

/// Plans a committed read of `[offset, offset + len)` of log `id`, pinning
/// every touched segment.
fn plan_fetch<M: Medium>(
    shared: &Arc<Shared<M>>,
    state: &mut State<M>,
    id: LogId,
    offset: u64,
    len: u64,
) -> Result<Fetch<M>, Error> {
    let log = state.index.logs.get(&id).ok_or(Error::Closed)?;
    let end = offset.checked_add(len).ok_or(Error::OffsetOverflow)?;
    if end > log.committed {
        return Err(Error::LogInsufficientLength);
    }
    let steps = log.plan(offset, len);
    // Resolve every touched segment first (fallible), then pin (infallible),
    // so an error never leaves pins behind.
    let mut files: BTreeMap<SegmentSeq, M::File> = BTreeMap::new();
    for step in &steps {
        let seq = step.extent.segment;
        if files.contains_key(&seq) {
            continue;
        }
        let file = if seq == state.active_seq {
            state.active.clone()
        } else if let Some(sealed) = state.sealed.get(&seq) {
            sealed.file.clone()
        } else {
            // The index only ever references open segments; fail stop.
            state.control.liveness = Liveness::Poisoned;
            return Err(corrupt(&shared.name, "extent in an unknown segment"));
        };
        files.insert(seq, file);
    }
    let seqs: Vec<SegmentSeq> = files.keys().copied().collect();
    for seq in &seqs {
        *state.pins.entry(*seq).or_insert(0) += 1;
    }
    Ok(Fetch {
        steps,
        files,
        salt: state.salt,
        session: state.control.session,
        pins: Pins {
            shared: shared.clone(),
            session: state.control.session,
            seqs,
        },
    })
}

/// How reading one committed block failed; the caller owns the policy.
pub(super) enum BlockFault {
    /// The medium failed the read.
    Io(Error),
    /// The block's bytes are missing: a planned extent read hit EOF. Damage,
    /// not a reader race -- plans come from the committed index and extents
    /// are immutable.
    Short,
    /// The block's checksum does not match its (log, offset) binding.
    Mismatch,
}

/// Reads `extent`'s whole block from `file` and verifies it against its
/// (log, at) binding. Two reads: a block's checksum lives in the table at
/// its record's end, not adjacent to the payload. Failure policy stays with
/// the caller.
pub(super) async fn read_verified_block<F: File>(
    file: &F,
    salt: &Salt,
    log: LogId,
    at: LogOffset,
    extent: &Extent,
) -> Result<Vec<u8>, BlockFault> {
    let read = async {
        let block = file.read_at(extent.payload.0, extent.len as usize).await?;
        let sum = file.read_at(extent.crc.0, 4).await?;
        Ok::<_, Error>((block, sum))
    };
    let (block, sum) = match read.await {
        Ok(read) => read,
        Err(Error::LogInsufficientLength) => return Err(BlockFault::Short),
        Err(error) => return Err(BlockFault::Io(error)),
    };
    if sum != block_crc(salt, log, at, &block) {
        return Err(BlockFault::Mismatch);
    }
    Ok(block)
}

/// Executes a planned fetch, verifying every touched block's checksum.
///
/// Failures resolve under the state lock against the plan's session: if the
/// family recovered or was destroyed while the reads ran, the read fails
/// [Error::Closed] and changes nothing (the failure belongs to a state that
/// no longer exists); otherwise a short read or checksum mismatch is
/// corruption -- it poisons the family -- and an I/O error propagates as-is.
async fn fetch<M: Medium>(
    shared: &Arc<Shared<M>>,
    log: LogId,
    fetch: Fetch<M>,
) -> Result<Vec<u8>, Error> {
    let mut data = Vec::with_capacity(fetch.steps.iter().map(|s| s.take as usize).sum());
    for step in &fetch.steps {
        let file = &fetch.files[&step.extent.segment];
        let block = match read_verified_block(file, &fetch.salt, log, step.at, &step.extent).await {
            Ok(block) => block,
            Err(fault) => {
                let mut state = shared.state.lock();
                if state.control.session != fetch.session
                    || matches!(state.control.liveness, Liveness::Destroyed)
                {
                    return Err(Error::Closed);
                }
                let reason = match fault {
                    BlockFault::Io(error) => return Err(error),
                    BlockFault::Short => "extent read past the segment end",
                    BlockFault::Mismatch => "payload block checksum mismatch",
                };
                if matches!(state.control.liveness, Liveness::Open) {
                    state.control.liveness = Liveness::Poisoned;
                }
                return Err(corrupt(&shared.name, reason));
            }
        };
        data.extend_from_slice(&block[step.skip as usize..(step.skip + step.take) as usize]);
    }
    Ok(data)
}

/// Read handle to a committed log.
#[derive(Clone)]
pub struct Log<M: Medium> {
    shared: Arc<Shared<M>>,
    /// The session this handle was minted in; recovery invalidates it.
    session: u64,
    id: LogId,
    pool: BufferPool,
}

impl<M: Medium> crate::Log for Log<M> {
    fn len(&self) -> Result<u64, Error> {
        let state = self.shared.state.lock();
        state.control.ensure_open(&self.shared.name, self.session)?;
        let log = state.index.logs.get(&self.id).ok_or(Error::Closed)?;
        Ok(log.committed)
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.read_at_buf(offset, len, self.pool.alloc(len)).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let planned = {
            let mut state = self.shared.state.lock();
            state.control.ensure_open(&self.shared.name, self.session)?;
            plan_fetch(&self.shared, &mut state, self.id, offset, len as u64)?
        };
        let data = fetch(&self.shared, self.id, planned).await?;
        Ok(fill(bufs, &data))
    }
}

/// The family's single write transaction.
pub struct Transaction<M: Medium> {
    family: Family<M>,
    /// Held for the transaction's lifetime; dropping it (abort or commit)
    /// hands the writer to the next waiter.
    #[allow(dead_code)]
    permit: Permit<Shared<M>>,
    /// Staged mutations and drafts, with bounds accounting.
    staging: Staging<LogId>,
}

impl<M: Medium> Transaction<M> {
    /// Validate `log` as a target of this transaction under `state` and
    /// return its committed form.
    fn committed<'a>(&self, state: &'a State<M>, log: &Log<M>) -> Result<&'a LogState, Error> {
        // Family identity first: ids and sessions are per-incarnation, so a
        // foreign log's id could collide with a local one.
        if !Arc::ptr_eq(&log.shared, &self.family.shared) {
            return Err(Error::InvalidTransaction("log from another family".into()));
        }
        state
            .control
            .ensure_open(&self.family.shared.name, self.family.session)?;
        if log.session != self.family.session {
            return Err(Error::Closed);
        }
        let committed = state.index.logs.get(&log.id).ok_or(Error::Closed)?;
        self.staging.ensure_unremoved(log.id)?;
        Ok(committed)
    }

    /// [`Transaction::committed`], returning just the committed length.
    fn committed_len(&self, log: &Log<M>) -> Result<u64, Error> {
        let state = self.family.shared.state.lock();
        Ok(self.committed(&state, log)?.committed)
    }
}

impl<M: Medium> crate::LogTransaction for Transaction<M> {
    type Log = Log<M>;
    type Draft = Draft;

    fn create(&mut self, name: &[u8]) -> Result<Draft, Error> {
        let taken = {
            let state = self.family.shared.state.lock();
            state
                .control
                .ensure_open(&self.family.shared.name, self.family.session)?;
            state.index.names.contains_key(name)
        };
        self.staging.create(name, taken)
    }

    fn append(&mut self, log: &Log<M>, data: impl Into<IoBufs>) -> Result<u64, Error> {
        let committed = self.committed_len(log)?;
        self.staging.append(log.id, committed, data.into())
    }

    fn rewind(&mut self, log: &Log<M>, len: u64) -> Result<(), Error> {
        let committed = self.committed_len(log)?;
        self.staging.rewind(log.id, committed, len)
    }

    fn remove(&mut self, log: &Log<M>) -> Result<(), Error> {
        self.committed_len(log)?;
        self.staging.remove(log.id)
    }

    fn len(&self, log: &Log<M>) -> u64 {
        let committed = self.committed_len(log).expect("invalid log target");
        self.staging.len(log.id, committed)
    }

    async fn read_at(&self, log: &Log<M>, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.read_at_buf(log, offset, len, self.family.pool.alloc(len))
            .await
    }

    async fn read_at_buf(
        &self,
        log: &Log<M>,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        // The staged view: committed bytes below `keep`, then `appended`.
        let (planned, staged) = {
            let mut state = self.family.shared.state.lock();
            let committed = self.committed(&state, log)?.committed;
            let (keep, appended) = self.staging.view(log.id, committed);
            let end = offset
                .checked_add(len as u64)
                .ok_or(Error::OffsetOverflow)?;
            if end > keep + appended.len() as u64 {
                return Err(Error::LogInsufficientLength);
            }
            let staged = if end > keep {
                let from = offset.max(keep) - keep;
                appended[from as usize..(end - keep) as usize].to_vec()
            } else {
                Vec::new()
            };
            let planned = plan_fetch(
                &self.family.shared,
                &mut state,
                log.id,
                offset.min(keep),
                end.min(keep) - offset.min(keep),
            )?;
            (planned, staged)
        };
        let mut data = fetch(&self.family.shared, log.id, planned).await?;
        data.extend_from_slice(&staged);
        Ok(fill(bufs, &data))
    }

    fn append_draft(&mut self, log: &Draft, data: impl Into<IoBufs>) -> Result<u64, Error> {
        self.family.ensure_open()?;
        self.staging.append_draft(log, data.into())
    }

    fn rewind_draft(&mut self, log: &Draft, len: u64) -> Result<(), Error> {
        self.family.ensure_open()?;
        self.staging.rewind_draft(log, len)
    }

    fn len_draft(&self, log: &Draft) -> u64 {
        self.staging.len_draft(log)
    }

    async fn read_draft_at(
        &self,
        log: &Draft,
        offset: u64,
        len: usize,
    ) -> Result<IoBufsMut, Error> {
        self.read_draft_at_buf(log, offset, len, self.family.pool.alloc(len))
            .await
    }

    async fn read_draft_at_buf(
        &self,
        log: &Draft,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.family.ensure_open()?;
        let data = self.staging.read_draft(log, offset, len)?;
        Ok(fill(bufs, data))
    }

    fn discard(&mut self, log: Draft) -> Result<(), Error> {
        self.family.ensure_open()?;
        self.staging.discard(log)
    }

    async fn start_commit(mut self) -> Result<Handle<()>, Error> {
        let (staged, drafts) = self.staging.take();
        let shared = self.family.shared.clone();
        let session = self.family.session;

        // Reserve gate: refuse admission while free space (when the medium
        // reports it) could not hold this frame on top of the cleaner's
        // reserve -- after giving the cleaner one inline chance to free
        // space, which it can, because its own writes fit inside the
        // reserve. Estimated from the staged state, so it can only
        // overshoot; freshness is best-effort (another store on the medium
        // may consume space concurrently), which the reserve's slack
        // absorbs.
        shared
            .state
            .lock()
            .control
            .ensure_open(&shared.name, session)?;
        let payload: u64 = staged
            .values()
            .map(|entry| match entry {
                Staged::Edit { appended, .. } => appended.len() as u64,
                Staged::Removal => 0,
            })
            .sum::<u64>()
            + drafts
                .iter()
                .flatten()
                .map(|draft| draft.content.len() as u64)
                .sum::<u64>();
        let touched = (staged.len() + drafts.iter().flatten().count()) as u64;
        if touched > 0 {
            let need = shared.limits.cleaner_reserve_bytes
                + PAGE as u64
                + frame_bytes_bound(payload, touched, self.family.bounds.max_log_name_len as u64);
            let gated = |free: Option<u64>| free.is_some_and(|free| free < need);
            if gated(shared.medium.free_bytes().await?) {
                maintain(&shared, session, false).await?;
                if gated(shared.medium.free_bytes().await?) {
                    return Err(Error::FamilyFull(shared.name.clone()));
                }
            }
        }

        // Admission: fold the staged state into net operations and validate
        // them against the committed index. An error here changes nothing.
        let (admission, txn) = {
            let mut state = shared.state.lock();
            state.control.ensure_open(&shared.name, session)?;
            // Fault fuse: fail after admission, poisoning the family. The
            // transaction is lost, modeling a frame that never became
            // durable.
            if state.control.fail_next_commit {
                state.control.fail_next_commit = false;
                state.control.liveness = Liveness::Poisoned;
                drop(state);
                let name = shared.name.clone();
                drop(self);
                return Ok(Handle::ready(Err(Error::FamilyPoisoned(name))));
            }
            let ops = net_ops(&state.index, staged, drafts);
            if ops.is_empty() {
                // Nothing to persist: no frame, no barrier.
                drop(state);
                drop(self);
                return Ok(Handle::ready(Ok(())));
            }
            let txn = ValidatedTxn::new(state.salt.epoch(), state.index.next_txn, ops)?;
            // Fail closed while the family still fits a checkpoint and its
            // uncheckpointed span still fits under the replay ceilings: state
            // that could never be checkpointed or replayed must never commit.
            let span_bytes = state.tail.0 - state.root.replay_at.0;
            let span_txns = state.index.next_txn.0 - state.root.replay_from.0;
            if !fits_family(&state.index, span_bytes, span_txns, &txn, &shared.limits) {
                return Err(Error::FamilyFull(shared.name.clone()));
            }
            // A frame past the segment target gets its own sealed segment,
            // made authoritative by the checkpoint maintenance writes below.
            let admission = if txn.frame_bound() > shared.limits.segment_target_bytes {
                let seq = state.next_segment;
                state.next_segment = SegmentSeq(seq.0 + 1);
                Admission::Dedicated {
                    seq,
                    salt: state.salt,
                }
            } else {
                Admission::Active(Admitted {
                    session,
                    active: state.active.clone(),
                    active_seq: state.active_seq,
                    tail: state.tail,
                    salt: state.salt,
                })
            };
            (admission, txn)
        };
        // Durability and activation: from here on, failure poisons the
        // family and reports through the handle.
        let (mut result, force_checkpoint) = match admission {
            Admission::Active(admitted) => (commit_frame(&shared, admitted, txn).await, false),
            Admission::Dedicated { seq, salt } => (
                commit_dedicated(&shared, session, seq, salt, txn).await,
                true,
            ),
        };
        if result.is_ok() {
            // Due maintenance -- checkpoint, rotation, cleaning -- lands
            // inline, before the writer is released (the v1 posture: no
            // background task). Failure poisons, so the replay ceilings are
            // never exceeded; a durable frame is then recovery's to adopt.
            // A dedicated segment forces the checkpoint that makes it
            // authoritative.
            result = maintain(&shared, session, force_checkpoint).await;
        }
        // Dropping the transaction releases the writer, so the handle
        // resolves only after the next waiter can proceed.
        drop(self);
        Ok(Handle::ready(result))
    }
}

/// Folds a transaction's staged state and drafts into net operations against
/// the committed `index`, in canonical ascending-log-id order. Pure: applying
/// the result through [Index::apply] is the transaction's entire effect.
fn net_ops(
    index: &Index,
    staged: BTreeMap<LogId, Staged>,
    drafts: Vec<Option<DraftLog>>,
) -> Vec<(LogId, NetOp)> {
    let mut ops = Vec::new();
    for (id, entry) in staged {
        let log = index.logs.get(&id).expect("validated at staging");
        match entry {
            Staged::Edit { keep, appended } => {
                // Staged back to the committed length with nothing appended:
                // a net no-op.
                if keep == log.committed && appended.is_empty() {
                    continue;
                }
                ops.push((
                    id,
                    NetOp::Mutate {
                        generation: log.generation,
                        committed: log.committed,
                        rewind_to: (keep < log.committed).then_some(keep),
                        run: appended,
                    },
                ));
            }
            Staged::Removal => ops.push((
                id,
                NetOp::Remove {
                    generation: log.generation,
                    committed: log.committed,
                },
            )),
        }
    }
    // Created logs mint the next ids, so ops stay in ascending order.
    let mut minted = index.next_log;
    for draft in drafts.into_iter().flatten() {
        ops.push((
            minted,
            NetOp::Create {
                name: draft.name,
                run: draft.content,
            },
        ));
        minted = minted.next();
    }
    ops
}

/// How an admitted transaction becomes durable: appended to the active
/// segment (the steady state) or as its own dedicated sealed segment (a
/// frame past the segment target).
enum Admission<M: Medium> {
    Active(Admitted<M>),
    Dedicated { seq: SegmentSeq, salt: Salt },
}

/// A commit's reservation, snapshotted at admission under the state lock. The
/// transaction holds the writer, so nothing else can move the tail.
struct Admitted<M: Medium> {
    session: u64,
    active: M::File,
    active_seq: SegmentSeq,
    tail: SegmentOffset,
    salt: Salt,
}

/// The effectful tail of a commit: encode the frame, write it at the reserved
/// tail, issue the one barrier, then activate it in the committed index.
async fn commit_frame<M: Medium>(
    shared: &Arc<Shared<M>>,
    admitted: Admitted<M>,
    txn: ValidatedTxn,
) -> Result<(), Error> {
    let ident = Identity {
        salt: admitted.salt,
        segment: admitted.active_seq,
    };
    let mut frame = Vec::new();
    txn.encode_frame(&ident, &mut frame);
    let sites = txn.block_sites(frame.len());
    let len = frame.len() as u64;

    if admitted
        .active
        .write_at(admitted.tail.0, frame)
        .await
        .is_err()
    {
        return Err(poison(shared));
    }
    if admitted.active.sync().await.is_err() {
        return Err(poison(shared));
    }
    debug_assert!(shared.medium.covered(&Claim::FileBytes {
        dir: &shared.dir,
        name: &segment_name(&shared.name, admitted.active_seq),
        start: admitted.tail.0,
        end: admitted.tail.0 + len,
    }));

    // Activation: the frame is durable; fold it into the committed index.
    // On a refusal the durable frame is recovery's to judge. ensure_open
    // checks the session before the poison state, unlike the checks it
    // replaced, but the session cannot change while the writer is held.
    // TODO(logstore): the refusal branches below need interleaving tests
    // (poison + recovery during in-flight commit I/O); they require task
    // scheduling the Sim medium cannot express alone.
    let mut state = shared.state.lock();
    state.control.ensure_open(&shared.name, admitted.session)?;
    if let Err(reason) = state
        .index
        .apply(&txn, &sites, admitted.active_seq, admitted.tail)
    {
        state.control.liveness = Liveness::Poisoned;
        return Err(Error::FamilyCorrupt(shared.name.clone(), reason));
    }
    state.tail.0 += len;
    Ok(())
}

/// The dedicated-segment commit: publish the frame as its own sealed segment
/// under the reachability rule, then activate it. Activation precedes the
/// forced checkpoint that makes the segment authoritative -- mirroring how
/// [commit_frame] activates before the handle resolves -- so a crash inside
/// that window loses only this unacknowledged transaction, which the sweep
/// then clears.
async fn commit_dedicated<M: Medium>(
    shared: &Arc<Shared<M>>,
    session: u64,
    seq: SegmentSeq,
    salt: Salt,
    txn: ValidatedTxn,
) -> Result<(), Error> {
    let ident = Identity { salt, segment: seq };
    let mut bytes = SegmentHeader {
        incarnation: shared.incarnation,
        seq,
    }
    .encode();
    txn.encode_frame(&ident, &mut bytes);
    let frame_len = bytes.len() - SEGMENT_RECORDS.0 as usize;
    let sites = txn.block_sites(frame_len);
    let total = bytes.len() as u64;
    let name = segment_name(&shared.name, seq);
    let staging = staging_name(&shared.name);
    let Ok(file) = publish(&shared.medium, &shared.dir, &staging, &name, bytes).await else {
        return Err(poison(shared));
    };

    let mut state = shared.state.lock();
    state.control.ensure_open(&shared.name, session)?;
    if let Err(reason) = state.index.apply(&txn, &sites, seq, SEGMENT_RECORDS) {
        state.control.liveness = Liveness::Poisoned;
        return Err(Error::FamilyCorrupt(shared.name.clone(), reason));
    }
    state.sealed.insert(seq, Sealed { file, bytes: total });
    state.metrics.dedicated_segments += 1;
    Ok(())
}

/// Poisons the family after uncertain mutable I/O and returns the error the
/// commit handle reports.
pub(super) fn poison<M: Medium>(shared: &Arc<Shared<M>>) -> Error {
    let mut state = shared.state.lock();
    match state.control.liveness {
        Liveness::Destroyed => Error::Closed,
        _ => {
            state.control.liveness = Liveness::Poisoned;
            Error::FamilyPoisoned(shared.name.clone())
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::{
        super::{
            format::{CatalogRow, ExtentRow},
            medium::Sim,
        },
        *,
    };
    use crate::{
        BufferPoolConfig, Log as _, LogFamily as _, LogStorage as _, LogTransaction as _,
        storage::logstore::tests::run_log_storage_tests, telemetry::metrics::Registry,
    };

    pub(in super::super) const DIR: &str = "store";

    pub(in super::super) fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    /// Small bounds so conformance tests can hit every limit cheaply.
    pub(in super::super) fn test_bounds() -> Bounds {
        Bounds {
            max_transaction_bytes: 1024,
            max_transaction_logs: 8,
            max_log_name_len: 64,
        }
    }

    /// A store over `sim` with per-instance mint entropy: [LogStorage::new]
    /// requires fresh entropy per instance, and the crash tests treat every
    /// store as one process lifetime.
    pub(in super::super) fn seeded_store(sim: &Sim, entropy: u8) -> LogStorage<Sim> {
        LogStorage::new(sim.clone(), DIR, [entropy; 16], test_pool(), test_bounds())
    }

    pub(in super::super) fn test_store(sim: &Sim) -> LogStorage<Sim> {
        seeded_store(sim, 7)
    }

    /// Limits that checkpoint after every nonempty commit.
    pub(in super::super) const EVERY_COMMIT: Limits = Limits {
        checkpoint_trigger_bytes: 1,
        checkpoint_trigger_txns: 1,
        ..Limits::DEFAULT
    };

    /// A store with shrunken limits, so the checkpoint triggers, the
    /// admission gates, and the replay ceilings are reachable cheaply.
    /// Deliberately unasserted (unlike [LogStorage::new]): the wedge tests
    /// construct configurations production would refuse.
    pub(in super::super) fn limited_store(
        sim: &Sim,
        entropy: u8,
        limits: Limits,
    ) -> LogStorage<Sim> {
        let mut storage = seeded_store(sim, entropy);
        storage.limits = limits;
        storage
    }

    /// Reads the family's governing root straight off the manifest.
    pub(in super::super) async fn governing_root(sim: &Sim, family: &str) -> Root {
        let manifest = sim
            .open(DIR, &manifest_name(family))
            .await
            .unwrap()
            .unwrap();
        let header = ManifestHeader::decode(&manifest.read_at(0, PAGE).await.unwrap()).unwrap();
        let mut governing: Option<Root> = None;
        for (slot, &offset) in ROOT_OFFSETS.iter().enumerate() {
            let page = manifest.read_at(offset, PAGE).await.unwrap();
            if let Some(root) = Root::decode(&page, &header.incarnation, slot).unwrap()
                && governing.as_ref().is_none_or(|g| g.seq < root.seq)
            {
                governing = Some(root);
            }
        }
        governing.unwrap()
    }

    /// The family's sealed segment files: every segment file except the one
    /// the governing root names active.
    pub(in super::super) async fn sealed_segments(sim: &Sim, family: &str) -> Vec<String> {
        let active = segment_name(family, governing_root(sim, family).await.active_segment);
        let prefix = format!("{family}.segment-");
        sim.list(DIR)
            .await
            .unwrap()
            .unwrap_or_default()
            .into_iter()
            .filter(|f| f.starts_with(&prefix) && *f != active)
            .collect()
    }

    /// The family's live shared state, for tests inspecting internals
    /// (metrics, pins, retirements).
    pub(in super::super) fn family_shared(
        storage: &LogStorage<Sim>,
        family: &str,
    ) -> Arc<Shared<Sim>> {
        storage.families.try_lock().unwrap()[family].clone()
    }

    /// Arm the fault fuse: the next admitted commit in `family` fails,
    /// poisoning it.
    fn fail_next_commit(storage: &LogStorage<Sim>, family: &str) {
        storage.families.try_lock().unwrap()[family]
            .state
            .lock()
            .control
            .fail_next_commit = true;
    }

    /// Create a log named `name` holding `data` in one committed transaction
    /// and return its handle.
    pub(in super::super) async fn commit_log(
        family: &Family<Sim>,
        name: &[u8],
        data: &[u8],
    ) -> Log<Sim> {
        let mut txn = family.transaction().await.unwrap();
        let draft = txn.create(name).unwrap();
        if !data.is_empty() {
            txn.append_draft(&draft, data.to_vec()).unwrap();
        }
        txn.commit().await.unwrap();
        family.open(name).await.unwrap().unwrap()
    }

    /// Append `data` to `log` in one committed transaction.
    pub(in super::super) async fn commit_append(family: &Family<Sim>, log: &Log<Sim>, data: &[u8]) {
        let mut txn = family.transaction().await.unwrap();
        txn.append(log, data.to_vec()).unwrap();
        txn.commit().await.unwrap();
    }

    /// Read the log's full committed content.
    pub(in super::super) async fn read_all(log: &Log<Sim>) -> Vec<u8> {
        let len = log.len().unwrap();
        log.read_at(0, len as usize)
            .await
            .unwrap()
            .coalesce()
            .as_ref()
            .to_vec()
    }

    #[tokio::test]
    async fn test_segment_log_storage() {
        let sim = Sim::new(7);
        let storage = test_store(&sim);
        let fuse = storage.clone();
        run_log_storage_tests(storage, test_bounds(), move |family| {
            fail_next_commit(&fuse, family)
        })
        .await;
    }

    /// Committed state survives a drop of the store and a crash: reopening
    /// rebuilds the exact logical image by replay, including multi-extent
    /// logs, rewound tails, and removed-then-recreated names, and the family
    /// keeps accepting transactions.
    #[tokio::test]
    async fn test_recovery_round_trip() {
        let sim = Sim::new(11);
        {
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            // "a" spans three frames: two appends, then a rewind into the
            // middle of the second extent plus a reappend.
            let a = commit_log(&family, b"a", b"hello").await;
            commit_append(&family, &a, b" world").await;
            let mut txn = family.transaction().await.unwrap();
            txn.rewind(&a, 8).unwrap();
            txn.append(&a, b"XYZ").unwrap();
            txn.commit().await.unwrap();
            // "b" is removed and recreated; "empty" holds nothing.
            let b = commit_log(&family, b"b", b"0123456789").await;
            let mut txn = family.transaction().await.unwrap();
            txn.remove(&b).unwrap();
            txn.commit().await.unwrap();
            commit_log(&family, b"b", b"fresh").await;
            commit_log(&family, b"empty", b"").await;
        }
        sim.crash(); // everything was synced; the durable image is complete

        let storage = test_store(&sim);
        let family = storage.open_family("fam").await.unwrap();
        assert_eq!(
            family.scan().await.unwrap(),
            vec![b"a".to_vec(), b"b".to_vec(), b"empty".to_vec()]
        );
        let a = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&a).await, b"hello woXYZ");
        let b = family.open(b"b").await.unwrap().unwrap();
        assert_eq!(read_all(&b).await, b"fresh");
        let empty = family.open(b"empty").await.unwrap().unwrap();
        assert_eq!(empty.len().unwrap(), 0);
        // Appends continue where replay left the tail.
        commit_append(&family, &a, b"!").await;
        assert_eq!(read_all(&a).await, b"hello woXYZ!");
    }

    /// Garbage past the last valid record models a torn frame: replay stops
    /// there, truncates the tail durably, and appends resume at the boundary.
    #[tokio::test]
    async fn test_torn_tail_truncated() {
        let sim = Sim::new(3);
        {
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            commit_log(&family, b"a", b"hello").await;
        }
        let file = sim
            .open(DIR, &segment_name("fam", SegmentSeq(1)))
            .await
            .unwrap()
            .unwrap();
        let valid = file.size().await.unwrap();
        file.write_at(valid, vec![0x5Au8; 37]).await.unwrap();
        file.sync().await.unwrap();

        let storage = test_store(&sim);
        let family = storage.open_family("fam").await.unwrap();
        assert_eq!(file.size().await.unwrap(), valid);
        let log = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&log).await, b"hello");
        commit_append(&family, &log, b" world").await;
        assert_eq!(read_all(&log).await, b"hello world");

        // Truncation was durable and reopening is idempotent.
        drop((storage, family, log));
        sim.crash();
        let storage = test_store(&sim);
        let family = storage.open_family("fam").await.unwrap();
        let log = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&log).await, b"hello world");
    }

    /// A payload byte flipped behind the store's back fails the block
    /// checksum on read: the read reports corruption and the family poisons.
    #[tokio::test]
    async fn test_read_corruption_poisons() {
        let sim = Sim::new(5);
        let storage = test_store(&sim);
        let family = storage.open_family("fam").await.unwrap();
        let log = commit_log(&family, b"a", &[0x77; 64]).await;

        // Re-derive the committed frame's encoding and corrupt its one
        // payload block where block_sites locates it.
        let manifest = sim.open(DIR, &manifest_name("fam")).await.unwrap().unwrap();
        let header = ManifestHeader::decode(&manifest.read_at(0, PAGE).await.unwrap()).unwrap();
        let ident = Identity {
            salt: Salt::new(&header.incarnation, 0),
            segment: SegmentSeq(1),
        };
        let txn = ValidatedTxn::new(
            0,
            TxnSeq(0),
            vec![(
                LogId(0),
                NetOp::Create {
                    name: b"a".to_vec(),
                    run: vec![0x77; 64],
                },
            )],
        )
        .unwrap();
        let mut frame = Vec::new();
        txn.encode_frame(&ident, &mut frame);
        let site = &txn.block_sites(frame.len())[0];
        let file = sim
            .open(DIR, &segment_name("fam", SegmentSeq(1)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(file.read_at(PAGE as u64, frame.len()).await.unwrap(), frame);
        let at = PAGE as u64 + site.payload as u64;
        file.write_at(at, vec![0x78]).await.unwrap();

        assert!(matches!(
            log.read_at(0, 64).await,
            Err(Error::FamilyCorrupt(..))
        ));
        assert!(matches!(family.scan().await, Err(Error::FamilyPoisoned(_))));
        assert!(matches!(log.len(), Err(Error::FamilyPoisoned(_))));
    }

    /// Every protocol holds at its pinned barrier count, so a protocol
    /// change surfaces here as a count change. Creation and destroy are
    /// measured as the smallest fuse each protocol outlives, because
    /// [Sim::sync_count] counts only file barriers while the fuse burns on
    /// directory and root barriers too.
    #[tokio::test]
    async fn test_barrier_counts() {
        // A steady-state commit is exactly one barrier (the frame's
        // fdatasync); an empty transaction persists nothing.
        let sim = Sim::new(9);
        let storage = test_store(&sim);
        let family = storage.open_family("fam").await.unwrap();
        let log = commit_log(&family, b"a", b"x").await;

        let before = sim.sync_count();
        let mut txn = family.transaction().await.unwrap();
        let draft = txn.create(b"b").unwrap();
        txn.append_draft(&draft, b"data").unwrap();
        txn.append(&log, b"more").unwrap();
        txn.commit().await.unwrap();
        assert_eq!(sim.sync_count(), before + 1);

        let before = sim.sync_count();
        let txn = family.transaction().await.unwrap();
        txn.commit().await.unwrap();
        assert_eq!(sim.sync_count(), before);

        // create_family is five barriers: the staged segment's data sync,
        // the directory barrier for the segment dentry, the staged
        // manifest's data sync, the directory barrier for the manifest
        // dentry, and the root barrier for the directory itself.
        let mut create_barriers = None;
        for fuse in 0..8 {
            let sim = Sim::new(0);
            sim.fail_syncs_after(fuse);
            if test_store(&sim).open_family("fam").await.is_ok() {
                create_barriers = Some(fuse);
                break;
            }
        }
        assert_eq!(create_barriers, Some(5), "create_family barriers changed");

        // destroy_family is three barriers: the intent (the manifest renamed
        // to the condemned marker), the data-file removals, and the
        // condemned-marker removal.
        let mut destroy_barriers = None;
        for fuse in 0..8 {
            let sim = Sim::new(0);
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            commit_log(&family, b"a", b"x").await;
            sim.fail_syncs_after(fuse);
            if storage.destroy_family("fam").await.is_ok() {
                destroy_barriers = Some(fuse);
                break;
            }
        }
        assert_eq!(destroy_barriers, Some(3), "destroy_family barriers changed");
    }

    /// A root promising more transactions than the segment holds: replay
    /// ending early is hard corruption, never a clean stop.
    #[tokio::test]
    async fn test_replay_short_of_watermark_is_corrupt() {
        let sim = Sim::new(13);
        {
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            commit_log(&family, b"a", b"x").await;
        }
        let manifest = sim.open(DIR, &manifest_name("fam")).await.unwrap().unwrap();
        let page = manifest.read_at(0, PAGE).await.unwrap();
        let header = ManifestHeader::decode(&page).unwrap();
        let root = Root {
            seq: 2,
            epoch: 0,
            checkpoint: None,
            active_segment: SegmentSeq(1),
            replay_from: TxnSeq(0),
            replay_at: SEGMENT_RECORDS,
            next_log: LogId(0),
            next_txn: TxnSeq(5),
        };
        manifest
            .write_at(ROOT_OFFSETS[0], root.encode(&header.incarnation))
            .await
            .unwrap();

        let storage = test_store(&sim);
        assert!(matches!(
            storage.open_family("fam").await,
            Err(Error::FamilyCorrupt(..))
        ));
    }

    /// A barrier that really fails (not the fuse) poisons the family; after a
    /// crash, recovery serves a committed prefix -- with or without the
    /// indeterminate transaction, never a partial application.
    #[tokio::test]
    async fn test_failed_barrier_poisons_and_recovery_serves_a_prefix() {
        let sim = Sim::new(17);
        {
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            let log = commit_log(&family, b"a", b"hello").await;

            sim.fail_syncs_after(0);
            let mut txn = family.transaction().await.unwrap();
            txn.append(&log, b" world").unwrap();
            let handle = txn.start_commit().await.unwrap();
            assert!(matches!(handle.await, Err(Error::FamilyPoisoned(_))));
        }
        sim.crash(); // clears the fuse; the unsynced frame settles arbitrarily

        let storage = test_store(&sim);
        let family = storage.open_family("fam").await.unwrap();
        let log = family.open(b"a").await.unwrap().unwrap();
        let content = read_all(&log).await;
        assert!(
            content == b"hello" || content == b"hello world",
            "recovery must serve a committed prefix, got {content:?}"
        );
    }

    /// A write that fails (not the fuse-modeled barrier) poisons the family
    /// through the commit handle; in-process recovery over the same
    /// incarnation then serves the committed prefix and kills old handles.
    #[tokio::test]
    async fn test_failed_write_poisons_and_recovers() {
        let sim = Sim::new(19);
        let storage = test_store(&sim);
        let family = storage.open_family("fam").await.unwrap();
        let log = commit_log(&family, b"a", b"hello").await;

        sim.fail_writes_after(0);
        let mut txn = family.transaction().await.unwrap();
        txn.append(&log, b" world").unwrap();
        let handle = txn.start_commit().await.unwrap();
        assert!(matches!(handle.await, Err(Error::FamilyPoisoned(_))));
        assert!(matches!(family.scan().await, Err(Error::FamilyPoisoned(_))));

        // Heal the device first: recovery itself writes (the fresh watermark
        // root) and the still-armed fuse would fail it.
        sim.fail_writes_after(u64::MAX);
        // The failed frame never reached the segment, so recovery serves the
        // committed prefix.
        let recovered = storage.open_family("fam").await.unwrap();
        let log = recovered.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&log).await, b"hello");
        // Handles minted before recovery are dead.
        assert!(matches!(family.scan().await, Err(Error::Closed)));
    }

    /// The net-state fold: an edit reduces to at most one rewind plus one
    /// run, a no-op edit vanishes, removals carry their expectations, and
    /// drafts (minus discards) mint ascending ids after every staged target.
    #[test]
    fn test_net_ops_fold() {
        let mut index = Index::default();
        for (id, committed) in [(0u64, 5u64), (1, 3), (2, 4)] {
            index.logs.insert(
                LogId(id),
                LogState {
                    name: vec![id as u8],
                    generation: 7,
                    committed,
                    extents: BTreeMap::new(),
                },
            );
        }
        index.next_log = LogId(3);

        let staged = BTreeMap::from([
            (
                LogId(0),
                Staged::Edit {
                    keep: 2,
                    appended: b"xy".to_vec(),
                },
            ),
            // Staged back to the committed length: a net no-op.
            (
                LogId(1),
                Staged::Edit {
                    keep: 3,
                    appended: Vec::new(),
                },
            ),
            (LogId(2), Staged::Removal),
        ]);
        let drafts = vec![
            Some(DraftLog {
                name: b"d".to_vec(),
                content: b"z".to_vec(),
            }),
            None, // discarded
            Some(DraftLog {
                name: b"e".to_vec(),
                content: Vec::new(),
            }),
        ];
        assert_eq!(
            net_ops(&index, staged, drafts),
            vec![
                (
                    LogId(0),
                    NetOp::Mutate {
                        generation: 7,
                        committed: 5,
                        rewind_to: Some(2),
                        run: b"xy".to_vec(),
                    },
                ),
                (
                    LogId(2),
                    NetOp::Remove {
                        generation: 7,
                        committed: 4,
                    },
                ),
                (
                    LogId(3),
                    NetOp::Create {
                        name: b"d".to_vec(),
                        run: b"z".to_vec(),
                    },
                ),
                (
                    LogId(4),
                    NetOp::Create {
                        name: b"e".to_vec(),
                        run: Vec::new(),
                    },
                ),
            ]
        );
    }

    /// Bounds beyond the frozen format caps clamp at construction: staging
    /// rejects at the cap, so admission can never reject what staging
    /// accepted, and the transaction stays usable after the rejection.
    #[tokio::test]
    async fn test_bounds_clamp_to_format_caps() {
        let sim = Sim::new(23);
        let oversized = Bounds {
            max_transaction_bytes: u64::MAX,
            max_transaction_logs: usize::MAX,
            max_log_name_len: usize::MAX,
        };
        let storage = LogStorage::new(sim.clone(), DIR, [1; 16], test_pool(), oversized);
        let family = storage.open_family("fam").await.unwrap();
        let mut txn = family.transaction().await.unwrap();
        assert!(matches!(
            txn.create(&vec![b'n'; MAX_LOG_NAME_LEN + 1]),
            Err(Error::InvalidTransaction(_))
        ));
        let mut drafts = Vec::new();
        for i in 0..MAX_LOGS_TOUCHED as u32 {
            drafts.push(txn.create(&i.to_be_bytes()).unwrap());
        }
        // One log over the cap fails at staging; the transaction is intact.
        assert!(matches!(
            txn.create(b"one-too-many"),
            Err(Error::TransactionTooLarge(_))
        ));
        txn.append_draft(&drafts[0], b"still usable").unwrap();
        txn.commit().await.unwrap();
        assert_eq!(family.scan().await.unwrap().len(), MAX_LOGS_TOUCHED);
    }

    /// With no durable manifest, files under a family's name are leftovers of
    /// a torn creation: opening the family clears them and creates fresh.
    #[tokio::test]
    async fn test_creation_leftovers_cleared() {
        let sim = Sim::new(1);
        sim.create(DIR, &staging_name("fam")).await.unwrap();
        sim.create(DIR, &segment_name("fam", SegmentSeq(1)))
            .await
            .unwrap();
        // Junk with a manifest suffix strips to an invalid family name and
        // must not list.
        sim.create(DIR, "a.b.manifest").await.unwrap();

        let storage = test_store(&sim);
        let family = storage.open_family("fam").await.unwrap();
        assert!(family.scan().await.unwrap().is_empty());
        assert_eq!(storage.scan_families().await.unwrap(), vec!["fam"]);
        let log = commit_log(&family, b"a", b"works").await;
        assert_eq!(read_all(&log).await, b"works");
    }

    /// Destruction survives a crash: the family stays gone (its checkpoint
    /// segments included), and recreating it yields a fresh, empty family.
    #[tokio::test]
    async fn test_destroy_is_durable() {
        let sim = Sim::new(21);
        {
            let storage = limited_store(&sim, 7, EVERY_COMMIT);
            let family = storage.open_family("fam").await.unwrap();
            commit_log(&family, b"a", b"data").await;
            assert_eq!(sealed_segments(&sim, "fam").await.len(), 1);
            storage.destroy_family("fam").await.unwrap();
            assert!(storage.scan_families().await.unwrap().is_empty());
            // Every family file is gone, the checkpoint segment included.
            let files = sim.list(DIR).await.unwrap().unwrap_or_default();
            assert!(!files.iter().any(|f| f.starts_with("fam.")), "{files:?}");
        }
        sim.crash();

        let storage = test_store(&sim);
        assert!(storage.scan_families().await.unwrap().is_empty());
        let family = storage.open_family("fam").await.unwrap();
        assert!(family.open(b"a").await.unwrap().is_none());
    }

    /// A destroy that crashed after its intent became durable: the family is
    /// already gone, and the next open clears the leftovers and creates
    /// fresh.
    #[tokio::test]
    async fn test_torn_destroy_completes_on_open() {
        let sim = Sim::new(2);
        {
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            commit_log(&family, b"a", b"data").await;
        }
        // The intent: the manifest renamed to the condemned marker, durably.
        sim.rename(DIR, &manifest_name("fam"), &condemned_name("fam"))
            .await
            .unwrap();
        sim.sync_dir(DIR).await.unwrap();
        sim.crash();

        let storage = test_store(&sim);
        assert!(storage.scan_families().await.unwrap().is_empty());
        let family = storage.open_family("fam").await.unwrap();
        assert!(family.open(b"a").await.unwrap().is_none());
        let files = sim.list(DIR).await.unwrap().unwrap();
        assert_eq!(
            files,
            vec![manifest_name("fam"), segment_name("fam", SegmentSeq(1))]
        );
    }

    /// A removal failing inside destroy_family is a clean error, not a
    /// poison: the durable intent already retired the family, so a retry (or
    /// a later open) completes the removals and recreation is fresh.
    #[tokio::test]
    async fn test_destroy_removal_failure_retries() {
        let sim = Sim::new(51);
        let storage = test_store(&sim);
        let family = storage.open_family("fam").await.unwrap();
        commit_log(&family, b"a", b"data").await;

        sim.fail_removes_after(0);
        assert!(storage.destroy_family("fam").await.is_err());
        // The intent landed before the failed removal: the family is gone.
        assert!(storage.scan_families().await.unwrap().is_empty());

        sim.fail_removes_after(u64::MAX);
        storage.destroy_family("fam").await.unwrap();
        let files = sim.list(DIR).await.unwrap().unwrap_or_default();
        assert!(!files.iter().any(|f| f.starts_with("fam.")), "{files:?}");
        let family = storage.open_family("fam").await.unwrap();
        assert!(family.open(b"a").await.unwrap().is_none());
    }

    /// A removal failing inside the open-time sweep fails the open cleanly;
    /// the next open completes the removal and serves the committed state.
    #[tokio::test]
    async fn test_sweep_removal_failure_fails_open() {
        let sim = Sim::new(52);
        {
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            commit_log(&family, b"a", b"data").await;
        }
        // An unreferenced leftover for the sweep to remove.
        let leftover = segment_name("fam", SegmentSeq(9));
        sim.create(DIR, &leftover).await.unwrap();

        sim.fail_removes_after(0);
        let storage = seeded_store(&sim, 2);
        assert!(storage.open_family("fam").await.is_err());

        sim.fail_removes_after(u64::MAX);
        let family = storage.open_family("fam").await.unwrap();
        let log = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&log).await, b"data");
        assert!(!sim.list(DIR).await.unwrap().unwrap().contains(&leftover));
    }

    /// Log name -> full content: one family state, compared byte-for-byte.
    pub(in super::super) type Model = BTreeMap<Vec<u8>, Vec<u8>>;

    /// Reads a family's entire committed state.
    pub(in super::super) async fn read_state(family: &Family<Sim>) -> Model {
        let mut state = Model::new();
        for name in family.scan().await.unwrap() {
            let log = family.open(&name).await.unwrap().unwrap();
            let content = read_all(&log).await;
            state.insert(name, content);
        }
        state
    }

    /// The commits the crash enumerations drive. Every step appends to "a";
    /// "b" is created, edited, removed, and recreated, so consecutive prefix
    /// states differ in shape, not just length. The runs are sized for the
    /// maintenance grids: "b" is big and dies at step 2, step 1's rewind
    /// leaves step 0's small run as a straddled survivor, so step 0's
    /// segment becomes a mostly-dead victim with one cheap live copy, and
    /// the cumulative bytes make rotation reachable under a small target.
    const SCRIPT_STEPS: usize = 4;

    /// The run steps 0 and 3 append to "a".
    const A_RUN: [u8; 10] = [0xAA; 10];

    /// The content "b" is created with at steps 0 and 3.
    const B_CONTENT: [u8; 200] = [0xBB; 200];

    /// Folds scripted commit `step` into `model`. Mirrors [stage_step].
    fn step_model(model: &mut Model, step: usize) {
        match step {
            0 => {
                let a = model.get_mut(b"a".as_slice()).unwrap();
                a.extend_from_slice(&A_RUN);
                model.insert(b"b".to_vec(), B_CONTENT.to_vec());
            }
            1 => {
                let a = model.get_mut(b"a".as_slice()).unwrap();
                a.truncate(6);
                a.extend_from_slice(b"XY");
                model.get_mut(b"b".as_slice()).unwrap().push(b'!');
            }
            2 => {
                let a = model.get_mut(b"a".as_slice()).unwrap();
                a.extend_from_slice(b"-s2");
                model.remove(b"b".as_slice());
            }
            3 => {
                let a = model.get_mut(b"a".as_slice()).unwrap();
                a.extend_from_slice(&A_RUN);
                model.insert(b"b".to_vec(), B_CONTENT.to_vec());
            }
            _ => unreachable!("the script has {SCRIPT_STEPS} steps"),
        }
    }

    /// Stages scripted commit `step` onto `txn`. Mirrors [step_model].
    async fn stage_step(family: &Family<Sim>, txn: &mut Transaction<Sim>, step: usize) {
        let a = family.open(b"a").await.unwrap().unwrap();
        match step {
            0 => {
                txn.append(&a, A_RUN.to_vec()).unwrap();
                let b = txn.create(b"b").unwrap();
                txn.append_draft(&b, B_CONTENT.to_vec()).unwrap();
            }
            1 => {
                txn.rewind(&a, 6).unwrap();
                txn.append(&a, b"XY".to_vec()).unwrap();
                let b = family.open(b"b").await.unwrap().unwrap();
                txn.append(&b, b"!".to_vec()).unwrap();
            }
            2 => {
                txn.append(&a, b"-s2".to_vec()).unwrap();
                let b = family.open(b"b").await.unwrap().unwrap();
                txn.remove(&b).unwrap();
            }
            3 => {
                txn.append(&a, A_RUN.to_vec()).unwrap();
                let b = txn.create(b"b").unwrap();
                txn.append_draft(&b, B_CONTENT.to_vec()).unwrap();
            }
            _ => unreachable!("the script has {SCRIPT_STEPS} steps"),
        }
    }

    /// Which operation the commit enumerations fail.
    #[derive(Clone, Copy, Debug)]
    pub(in super::super) enum Fault {
        /// The fused barrier fails: the frame is written but never synced.
        Sync,
        /// The fused write fails: the frame never reaches the segment.
        Write,
    }

    /// What one crash scenario observed before the crash: acknowledged
    /// commits, how many indeterminate commits recovery adopted (0 or 1),
    /// and the maintenance activity the scenario drove, for the grids'
    /// coverage meta-assertions.
    pub(in super::super) struct CrashOutcome {
        pub acked: usize,
        pub adopted: usize,
        pub rotations: u64,
        pub cleanings: u64,
        pub dedicated: u64,
        pub unlinked: u64,
    }

    /// One crash scenario over the scripted commits: after `fuse` successful
    /// operations of `fault`'s kind, every further one fails. Drives the
    /// script on a store with `limits` until a commit fails. With
    /// `continue_after_poison` the fault then heals, the family recovers in
    /// process, and the script runs to completion before the crash;
    /// otherwise the crash lands at the poisoned commit. Reopens after the
    /// crash and requires the recovered family to be a committed prefix:
    /// every acknowledged commit, in order and byte-for-byte, possibly
    /// extended by the indeterminate one -- never a strict subset of one
    /// transaction -- then commits once more to prove the family functional.
    pub(in super::super) async fn run_crash_scenario(
        fault: Fault,
        fuse: u64,
        seed: u64,
        limits: Limits,
        continue_after_poison: bool,
    ) -> CrashOutcome {
        let ctx = format!("{fault:?} fuse {fuse} seed {seed}");
        // The states the crash property allows: exactly one of these
        // prefixes, never a hybrid. "c" is written at setup and never
        // touched again, so every comparison also proves bystander logs
        // survive intact.
        let mut states = vec![Model::from([
            (b"a".to_vec(), b"base".to_vec()),
            (b"c".to_vec(), b"keep".to_vec()),
        ])];
        for step in 0..SCRIPT_STEPS {
            let mut next = states[step].clone();
            step_model(&mut next, step);
            states.push(next);
        }

        let sim = Sim::new(seed);
        let (acked, indeterminate, activity) = {
            let storage = limited_store(&sim, 1, limits);
            let family = storage.open_family("fam").await.unwrap();
            commit_log(&family, b"a", b"base").await;
            commit_log(&family, b"c", b"keep").await;

            match fault {
                Fault::Sync => sim.fail_syncs_after(fuse),
                Fault::Write => sim.fail_writes_after(fuse),
            }
            let mut acked = 0;
            let mut indeterminate = 0;
            for step in 0..SCRIPT_STEPS {
                let mut txn = family.transaction().await.unwrap();
                stage_step(&family, &mut txn, step).await;
                let handle = txn
                    .start_commit()
                    .await
                    .unwrap_or_else(|error| panic!("{ctx}: admission failed: {error:?}"));
                match handle.await {
                    Ok(()) => acked += 1,
                    Err(Error::FamilyPoisoned(_)) => {
                        indeterminate = 1;
                        break;
                    }
                    Err(error) => panic!("{ctx}: commit failed with {error:?}"),
                }
            }
            if indeterminate == 1 {
                // Everything after the failure is rejected before admission
                // and can never appear in the recovered state.
                assert!(
                    matches!(family.transaction().await, Err(Error::FamilyPoisoned(_))),
                    "{ctx}: poisoned family admitted a transaction"
                );
            }
            let (acked, indeterminate) = if indeterminate == 1 && continue_after_poison {
                // The fault heals long enough for in-process recovery to
                // resolve the indeterminate commit into a committed prefix,
                // then re-arms with the same budget: the second fault can
                // land inside a post-recovery protocol -- e.g. after the
                // directory barrier that makes the sweep's removals durable
                // but before the root flip -- which is exactly where a
                // recovery that trusted a non-durable root gets caught.
                sim.fail_syncs_after(u64::MAX);
                sim.fail_writes_after(u64::MAX);
                let family = storage
                    .open_family("fam")
                    .await
                    .unwrap_or_else(|error| panic!("{ctx}: in-process recovery failed: {error:?}"));
                let recovered = read_state(&family).await;
                let resume = (acked..=acked + 1)
                    .find(|&j| recovered == states[j])
                    .unwrap_or_else(|| {
                        panic!("{ctx}: in-process recovery is no committed prefix: {recovered:?}")
                    });
                match fault {
                    Fault::Sync => sim.fail_syncs_after(fuse),
                    Fault::Write => sim.fail_writes_after(fuse),
                }
                let mut acked = resume;
                let mut indeterminate = 0;
                for step in resume..SCRIPT_STEPS {
                    let mut txn = family.transaction().await.unwrap();
                    stage_step(&family, &mut txn, step).await;
                    let handle = txn.start_commit().await.unwrap_or_else(|error| {
                        panic!("{ctx}: post-recovery admission failed: {error:?}")
                    });
                    match handle.await {
                        Ok(()) => acked += 1,
                        Err(Error::FamilyPoisoned(_)) => {
                            indeterminate = 1;
                            break;
                        }
                        Err(error) => panic!("{ctx}: post-recovery step {step}: {error:?}"),
                    }
                }
                (acked, indeterminate)
            } else {
                (acked, indeterminate)
            };
            let activity = {
                let shared = family_shared(&storage, "fam");
                let state = shared.state.lock();
                [
                    state.metrics.rotations,
                    state.metrics.cleanings,
                    state.metrics.dedicated_segments,
                    state.metrics.unlinked_segments,
                ]
            };
            (acked, indeterminate, activity)
        };
        sim.crash(); // clears the fuse; the unsynced frame settles per the seed

        let storage = limited_store(&sim, 2, limits);
        let family = storage
            .open_family("fam")
            .await
            .unwrap_or_else(|error| panic!("{ctx}: recovery failed: {error:?}"));
        let recovered = read_state(&family).await;
        let adopted = (acked..=acked + indeterminate)
            .find(|&j| recovered == states[j])
            .unwrap_or_else(|| {
                panic!(
                    "{ctx}: recovered state is no committed prefix: got {recovered:?}, \
                     acked {acked}, allowed {:?}",
                    &states[acked..=acked + indeterminate]
                )
            })
            - acked;

        // The recovered family accepts new commits and reads them back.
        let log = family.open(b"a").await.unwrap().unwrap();
        let mut txn = family
            .transaction()
            .await
            .unwrap_or_else(|error| panic!("{ctx}: post-recovery transaction: {error:?}"));
        txn.append(&log, b"+post".to_vec()).unwrap();
        txn.commit()
            .await
            .unwrap_or_else(|error| panic!("{ctx}: post-recovery commit: {error:?}"));
        let mut expected = states[acked + adopted][b"a".as_slice()].clone();
        expected.extend_from_slice(b"+post");
        assert_eq!(read_all(&log).await, expected, "{ctx}: post-recovery read");
        CrashOutcome {
            acked,
            adopted,
            rotations: activity[0],
            cleanings: activity[1],
            dedicated: activity[2],
            unlinked: activity[3],
        }
    }

    /// Barrier-fuse x seed enumeration over commit: whichever commit's
    /// barrier fails, recovery serves every acknowledged transaction in
    /// commit order, possibly extended by the indeterminate one, and nothing
    /// else. The grid must observe both allowed recoveries (the
    /// indeterminate frame adopted and not), or it is not exercising the
    /// property.
    #[tokio::test]
    async fn test_commit_crash_enumeration() {
        let (mut kept, mut adopted) = (false, false);
        for fuse in 0..=SCRIPT_STEPS as u64 {
            for seed in 0..16 {
                let outcome =
                    run_crash_scenario(Fault::Sync, fuse, seed, Limits::default(), false).await;
                // One barrier per commit under the default trigger, so the
                // fuse names the failing commit directly.
                assert_eq!(
                    outcome.acked as u64,
                    fuse.min(SCRIPT_STEPS as u64),
                    "fuse {fuse} seed {seed}: expected one barrier per commit"
                );
                match outcome.adopted {
                    0 => kept = true,
                    _ => adopted = true,
                }
            }
        }
        assert!(
            kept && adopted,
            "the enumeration never saw both allowed recoveries"
        );
    }

    /// The commit enumeration under failing writes instead of failing
    /// barriers: a failed write poisons the family, and since the frame
    /// never reached the segment, recovery serves exactly the acknowledged
    /// prefix.
    #[tokio::test]
    async fn test_commit_write_failure_crash_enumeration() {
        for fuse in 0..=SCRIPT_STEPS as u64 {
            for seed in 0..16 {
                let outcome =
                    run_crash_scenario(Fault::Write, fuse, seed, Limits::default(), false).await;
                assert_eq!(
                    outcome.acked as u64,
                    fuse.min(SCRIPT_STEPS as u64),
                    "fuse {fuse} seed {seed}: expected one write per commit"
                );
                assert_eq!(
                    outcome.adopted, 0,
                    "fuse {fuse} seed {seed}: a frame whose write failed was adopted"
                );
            }
        }
    }

    /// One family-creation crash scenario with the barrier fuse armed at
    /// `fuse`. Returns whether creation was acknowledged. Property: after
    /// the crash the family either exists empty and fully functional or is
    /// recreated fresh -- never a half state -- leftovers are never adopted,
    /// and a sibling family is untouched.
    async fn run_create_crash(fuse: u64, seed: u64) -> bool {
        let ctx = format!("create fuse {fuse} seed {seed}");
        let sim = Sim::new(seed);
        // A durable sibling makes the directory itself durable, so a torn
        // creation's leftovers can survive the crash for reopen to face.
        {
            let storage = seeded_store(&sim, 1);
            let other = storage.open_family("other").await.unwrap();
            commit_log(&other, b"o", b"keep").await;
        }

        sim.fail_syncs_after(fuse);
        let created = seeded_store(&sim, 2).open_family("fam").await.is_ok();
        sim.crash();

        // The staging dentry is renamed away before either directory
        // barrier, so it can never be durable.
        let files = sim.list(DIR).await.unwrap().unwrap_or_default();
        assert!(
            !files.contains(&staging_name("fam")),
            "{ctx}: a staging entry became durable"
        );

        let storage = seeded_store(&sim, 3);
        let listed = storage
            .scan_families()
            .await
            .unwrap()
            .contains(&"fam".to_string());
        assert!(
            !created || listed,
            "{ctx}: acknowledged creation lost by the crash"
        );
        let family = storage
            .open_family("fam")
            .await
            .unwrap_or_else(|error| panic!("{ctx}: reopen failed: {error:?}"));
        assert!(
            family.scan().await.unwrap().is_empty(),
            "{ctx}: leftover state adopted into a fresh family"
        );
        let mut txn = family
            .transaction()
            .await
            .unwrap_or_else(|error| panic!("{ctx}: post-crash transaction: {error:?}"));
        let draft = txn.create(b"x").unwrap();
        txn.append_draft(&draft, b"works".to_vec()).unwrap();
        txn.commit()
            .await
            .unwrap_or_else(|error| panic!("{ctx}: post-crash commit: {error:?}"));
        let log = family.open(b"x").await.unwrap().unwrap();
        assert_eq!(read_all(&log).await, b"works", "{ctx}: post-crash read");

        let other = storage.open_family("other").await.unwrap();
        let o = other.open(b"o").await.unwrap().unwrap();
        assert_eq!(read_all(&o).await, b"keep", "{ctx}: sibling family damaged");
        created
    }

    /// Barrier-fuse x seed enumeration over family creation: whichever
    /// barrier fails, the family either exists empty or is recreated clean.
    /// The fuse space is discovered, not guessed: the enumeration stops at
    /// the first fuse the whole protocol outlives.
    #[tokio::test]
    async fn test_create_family_crash_enumeration() {
        let mut created = false;
        for fuse in 0..16 {
            for seed in 0..16 {
                created = run_create_crash(fuse, seed).await;
            }
            if created {
                break;
            }
        }
        assert!(created, "family creation never completed");
    }

    /// One destroy crash scenario with the barrier fuse armed at `fuse`.
    /// Returns whether the destroy was acknowledged. Property: after the
    /// crash the family is either fully present with every committed byte
    /// intact or absent and recreatable fresh; a condemned marker always
    /// resolves to absent; old bytes are never readable under a new
    /// identity.
    async fn run_destroy_crash(fuse: u64, seed: u64, limits: Limits) -> bool {
        let ctx = format!("destroy fuse {fuse} seed {seed}");
        let sim = Sim::new(seed);
        let storage = limited_store(&sim, 1, limits);
        let family = storage.open_family("fam").await.unwrap();
        commit_log(&family, b"a", b"alpha").await;
        commit_log(&family, b"b", b"beta").await;
        let expected = read_state(&family).await;

        sim.fail_syncs_after(fuse);
        let destroyed = storage.destroy_family("fam").await.is_ok();
        sim.crash();

        // The manifest name is the family's existence, and the rename that
        // retires it is atomic: it never coexists with the condemned marker.
        let files = sim.list(DIR).await.unwrap().unwrap_or_default();
        let manifest = files.contains(&manifest_name("fam"));
        assert!(
            !(manifest && files.contains(&condemned_name("fam"))),
            "{ctx}: manifest and condemned marker coexist"
        );

        let storage = seeded_store(&sim, 2);
        let listed = storage
            .scan_families()
            .await
            .unwrap()
            .contains(&"fam".to_string());
        assert_eq!(
            listed, manifest,
            "{ctx}: listing disagrees with the manifest"
        );
        assert!(
            !destroyed || !listed,
            "{ctx}: acknowledged destroy survived the crash"
        );
        let family = storage
            .open_family("fam")
            .await
            .unwrap_or_else(|error| panic!("{ctx}: reopen failed: {error:?}"));
        if listed {
            // Fully present: every committed byte intact.
            assert_eq!(
                read_state(&family).await,
                expected,
                "{ctx}: a partial destroy is visible"
            );
        } else {
            // Absent: recreated fresh, the condemned marker resolved, and
            // the old bytes unreachable under the new identity.
            assert!(
                family.scan().await.unwrap().is_empty(),
                "{ctx}: old data readable after destroy"
            );
            let mut txn = family
                .transaction()
                .await
                .unwrap_or_else(|error| panic!("{ctx}: post-destroy transaction: {error:?}"));
            let draft = txn.create(b"a").unwrap();
            txn.append_draft(&draft, b"fresh".to_vec()).unwrap();
            txn.commit()
                .await
                .unwrap_or_else(|error| panic!("{ctx}: post-destroy commit: {error:?}"));
            let log = family.open(b"a").await.unwrap().unwrap();
            assert_eq!(read_all(&log).await, b"fresh", "{ctx}: recreated log read");
        }
        destroyed
    }

    /// Barrier-fuse x seed enumeration over destroy_family: whichever
    /// barrier fails, the family resolves fully present or fully absent.
    /// The fuse space is discovered, not guessed.
    #[tokio::test]
    async fn test_destroy_family_crash_enumeration() {
        let mut destroyed = false;
        for fuse in 0..16 {
            for seed in 0..16 {
                destroyed = run_destroy_crash(fuse, seed, Limits::default()).await;
            }
            if destroyed {
                break;
            }
        }
        assert!(destroyed, "family destroy never completed");
    }

    /// The destroy enumeration again with checkpoint segments present, so
    /// their removal sits inside every crash window.
    #[tokio::test]
    async fn test_destroy_family_with_checkpoints_crash_enumeration() {
        let mut destroyed = false;
        for fuse in 0..16 {
            for seed in 0..16 {
                destroyed = run_destroy_crash(fuse, seed, EVERY_COMMIT).await;
            }
            if destroyed {
                break;
            }
        }
        assert!(destroyed, "family destroy never completed");
    }

    /// The conformance suite with a checkpoint after every commit, so
    /// checkpoints interleave with every contract scenario.
    #[tokio::test]
    async fn test_segment_log_storage_with_frequent_checkpoints() {
        let sim = Sim::new(7);
        let storage = limited_store(&sim, 7, EVERY_COMMIT);
        let fuse = storage.clone();
        run_log_storage_tests(storage, test_bounds(), move |family| {
            fail_next_commit(&fuse, family)
        })
        .await;
    }

    /// Under a checkpoint-every-commit trigger the root advances once per
    /// commit, exactly one sealed checkpoint segment survives, a crash-reopen
    /// rebuilds the identical state from the checkpoint, and replay no longer
    /// reads pre-checkpoint frames at all.
    #[tokio::test]
    async fn test_checkpoint_round_trip() {
        let sim = Sim::new(29);
        let expected = {
            let storage = limited_store(&sim, 1, EVERY_COMMIT);
            let family = storage.open_family("fam").await.unwrap();
            let a = commit_log(&family, b"a", b"hello").await;
            commit_append(&family, &a, b" world").await;
            let mut txn = family.transaction().await.unwrap();
            txn.rewind(&a, 8).unwrap();
            txn.append(&a, b"XYZ").unwrap();
            txn.commit().await.unwrap();
            let b = commit_log(&family, b"b", b"0123456789").await;
            let mut txn = family.transaction().await.unwrap();
            txn.remove(&b).unwrap();
            txn.commit().await.unwrap();
            commit_log(&family, b"b", b"fresh").await;
            commit_log(&family, b"empty", b"").await;
            read_state(&family).await
        };
        let root = governing_root(&sim, "fam").await;
        assert_eq!(root.seq, 7, "seven commits, seven flips");
        let locator = root.checkpoint.unwrap();
        assert_eq!(root.replay_from, root.next_txn);
        assert_eq!(
            sealed_segments(&sim, "fam").await,
            vec![segment_name("fam", locator.segment)],
            "superseded checkpoints must be gone"
        );

        sim.crash();
        {
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            assert_eq!(read_state(&family).await, expected);
        }

        // Replay starts after the checkpoint: garbage every pre-checkpoint
        // byte of the active segment and recovery still succeeds -- history
        // is dead weight to it.
        let segment = sim
            .open(DIR, &segment_name("fam", root.active_segment))
            .await
            .unwrap()
            .unwrap();
        let garbage = vec![0x5A; root.replay_at.0 as usize - PAGE];
        segment.write_at(PAGE as u64, garbage).await.unwrap();
        segment.sync().await.unwrap();
        let storage = seeded_store(&sim, 2);
        let family = storage.open_family("fam").await.unwrap();
        assert_eq!(
            family.scan().await.unwrap(),
            vec![b"a".to_vec(), b"b".to_vec(), b"empty".to_vec()]
        );
        let a = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(a.len().unwrap(), 11);
        let fresh = commit_log(&family, b"new", b"post").await;
        assert_eq!(read_all(&fresh).await, b"post");
        // The garbaged payload itself is caught lazily, by block checksums.
        assert!(matches!(
            a.read_at(0, 11).await,
            Err(Error::FamilyCorrupt(..))
        ));
    }

    /// Checkpoints triggered by transaction count: recovery reads the
    /// checkpoint plus only post-checkpoint frames, proven by garbaging every
    /// earlier frame and recovering anyway -- the strongest honest signal
    /// that history no longer participates.
    #[tokio::test]
    async fn test_recovery_cost_independent_of_history() {
        let sim = Sim::new(31);
        {
            let storage = limited_store(
                &sim,
                1,
                Limits {
                    checkpoint_trigger_bytes: u64::MAX,
                    checkpoint_trigger_txns: 4,
                    ..Limits::DEFAULT
                },
            );
            let family = storage.open_family("fam").await.unwrap();
            let log = commit_log(&family, b"a", b"0").await;
            for i in 1..14u32 {
                commit_append(&family, &log, format!("-{i}").as_bytes()).await;
            }
        }
        // Three checkpoints landed; two commits remain to replay.
        let root = governing_root(&sim, "fam").await;
        assert_eq!(root.seq, 3);
        assert_eq!(root.replay_from, TxnSeq(12));
        assert_eq!(sealed_segments(&sim, "fam").await.len(), 1);

        let segment = sim
            .open(DIR, &segment_name("fam", root.active_segment))
            .await
            .unwrap()
            .unwrap();
        let garbage = vec![0x5A; root.replay_at.0 as usize - PAGE];
        segment.write_at(PAGE as u64, garbage).await.unwrap();

        let storage = seeded_store(&sim, 2);
        let family = storage.open_family("fam").await.unwrap();
        let log = family.open(b"a").await.unwrap().unwrap();
        let len = log.len().unwrap();
        assert_eq!(len, 31);
        // The replayed frames' payload still reads.
        let tail = log.read_at(len - 6, 6).await.unwrap().coalesce();
        assert_eq!(tail, b"-12-13");
        commit_append(&family, &log, b"+post").await;
        assert!(matches!(
            log.read_at(0, 4).await,
            Err(Error::FamilyCorrupt(..))
        ));
    }

    /// Five acked commits with a checkpoint after the third; returns the
    /// active-segment window [start, end) of each commit's frame.
    async fn checkpointed_history(sim: &Sim) -> Vec<(u64, u64)> {
        let storage = limited_store(
            sim,
            1,
            Limits {
                checkpoint_trigger_bytes: u64::MAX,
                checkpoint_trigger_txns: 3,
                ..Limits::DEFAULT
            },
        );
        let family = storage.open_family("fam").await.unwrap();
        let segment = sim
            .open(DIR, &segment_name("fam", SegmentSeq(1)))
            .await
            .unwrap()
            .unwrap();
        // The checkpoint lands after the third commit; "junk"'s payload is
        // pre-checkpoint, "keep" spans it.
        let mut bounds = vec![segment.size().await.unwrap()];
        commit_log(&family, b"junk", &[0x77; 64]).await;
        bounds.push(segment.size().await.unwrap());
        let keep = commit_log(&family, b"keep", b"base").await;
        bounds.push(segment.size().await.unwrap());
        for suffix in [b"-c3", b"-c4", b"-c5"] {
            commit_append(&family, &keep, suffix).await;
            bounds.push(segment.size().await.unwrap());
        }
        bounds.windows(2).map(|w| (w[0], w[1])).collect()
    }

    /// The anti-truncation teeth: a bit flip in an acknowledged
    /// post-checkpoint frame with acknowledged successors is detected as
    /// corruption on reopen, never silently truncated -- the valid successor
    /// frame proves the torn one was durable.
    #[tokio::test]
    async fn test_acknowledged_frame_damage_is_corrupt() {
        let sim = Sim::new(53);
        let windows = checkpointed_history(&sim).await;
        let root = governing_root(&sim, "fam").await;
        assert_eq!(root.replay_from, TxnSeq(3));
        assert_eq!(root.replay_at.0, windows[3].0);

        // Flip one bit inside the fourth commit's frame (past its length
        // prefix); the fifth, acknowledged, sits beyond it.
        let segment = sim
            .open(DIR, &segment_name("fam", SegmentSeq(1)))
            .await
            .unwrap()
            .unwrap();
        let at = windows[3].0 + 6;
        let byte = segment.read_at(at, 1).await.unwrap();
        segment.write_at(at, vec![byte[0] ^ 1]).await.unwrap();
        assert!(matches!(
            seeded_store(&sim, 2).open_family("fam").await,
            Err(Error::FamilyCorrupt(..))
        ));
    }

    /// The boundary of those teeth: the same flip in the LAST acknowledged
    /// frame is indistinguishable from a crash-torn tail and truncates -- the
    /// residual risk the design accepts.
    #[tokio::test]
    async fn test_last_frame_damage_truncates() {
        let sim = Sim::new(59);
        let windows = checkpointed_history(&sim).await;
        let segment = sim
            .open(DIR, &segment_name("fam", SegmentSeq(1)))
            .await
            .unwrap()
            .unwrap();
        let at = windows[4].0 + 6;
        let byte = segment.read_at(at, 1).await.unwrap();
        segment.write_at(at, vec![byte[0] ^ 1]).await.unwrap();

        let storage = seeded_store(&sim, 2);
        let family = storage.open_family("fam").await.unwrap();
        let keep = family.open(b"keep").await.unwrap().unwrap();
        assert_eq!(read_all(&keep).await, b"base-c3-c4");
    }

    /// A bit flip in a pre-checkpoint frame leaves recovery untouched:
    /// replay never reads it.
    #[tokio::test]
    async fn test_pre_checkpoint_damage_does_not_affect_recovery() {
        let sim = Sim::new(61);
        let windows = checkpointed_history(&sim).await;
        let segment = sim
            .open(DIR, &segment_name("fam", SegmentSeq(1)))
            .await
            .unwrap()
            .unwrap();
        let at = windows[0].0 + 6;
        let byte = segment.read_at(at, 1).await.unwrap();
        segment.write_at(at, vec![byte[0] ^ 1]).await.unwrap();

        let storage = seeded_store(&sim, 2);
        let family = storage.open_family("fam").await.unwrap();
        let keep = family.open(b"keep").await.unwrap().unwrap();
        assert_eq!(read_all(&keep).await, b"base-c3-c4-c5");
        commit_append(&family, &keep, b"+post").await;
    }

    /// A valid root whose named checkpoint is damaged or missing is hard
    /// corruption, never a fallback. Constructed manually: publication order
    /// means no crash can produce this state.
    #[tokio::test]
    async fn test_valid_root_with_bad_checkpoint_is_corrupt() {
        for remove in [false, true] {
            let sim = Sim::new(67);
            {
                let storage = limited_store(&sim, 1, EVERY_COMMIT);
                let family = storage.open_family("fam").await.unwrap();
                commit_log(&family, b"a", b"data").await;
            }
            let locator = governing_root(&sim, "fam").await.checkpoint.unwrap();
            let name = segment_name("fam", locator.segment);
            if remove {
                sim.remove(DIR, &name).await.unwrap();
            } else {
                let file = sim.open(DIR, &name).await.unwrap().unwrap();
                let at = locator.start.0 + locator.len / 2;
                let byte = file.read_at(at, 1).await.unwrap();
                file.write_at(at, vec![byte[0] ^ 1]).await.unwrap();
            }
            assert!(matches!(
                seeded_store(&sim, 2).open_family("fam").await,
                Err(Error::FamilyCorrupt(..))
            ));
        }
    }

    /// A torn publication of a newer root (its slot fails its own checksum)
    /// falls back to the surviving root and its full replay.
    #[tokio::test]
    async fn test_torn_root_slot_falls_back() {
        let sim = Sim::new(71);
        {
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            commit_log(&family, b"a", b"data").await;
        }
        let manifest = sim.open(DIR, &manifest_name("fam")).await.unwrap().unwrap();
        manifest
            .write_at(ROOT_OFFSETS[1], vec![0xA5; PAGE])
            .await
            .unwrap();

        let storage = seeded_store(&sim, 2);
        let family = storage.open_family("fam").await.unwrap();
        let log = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&log).await, b"data");
    }

    /// A checkpointing commit is three file barriers (frame, checkpoint
    /// staging, root flip) and one directory barrier, both pinned.
    #[tokio::test]
    async fn test_checkpoint_barrier_counts() {
        let sim = Sim::new(43);
        let storage = limited_store(&sim, 1, EVERY_COMMIT);
        let family = storage.open_family("fam").await.unwrap();
        let before = sim.sync_count();
        commit_log(&family, b"a", b"x").await;
        assert_eq!(sim.sync_count(), before + 3);

        // The full protocol, directory barrier included, measured as the
        // smallest fuse a checkpointing commit outlives.
        let mut barriers = None;
        for fuse in 0..8 {
            let sim = Sim::new(0);
            let storage = limited_store(&sim, 1, EVERY_COMMIT);
            let family = storage.open_family("fam").await.unwrap();
            sim.fail_syncs_after(fuse);
            let mut txn = family.transaction().await.unwrap();
            let draft = txn.create(b"b").unwrap();
            txn.append_draft(&draft, b"y").unwrap();
            if txn.commit().await.is_ok() {
                barriers = Some(fuse);
                break;
            }
        }
        assert_eq!(barriers, Some(4), "checkpointing commit barriers changed");
    }

    /// Torn checkpoint attempts -- a staging file, or a complete checkpoint
    /// whose root flip never landed -- are swept when the family opens.
    #[tokio::test]
    async fn test_checkpoint_leftovers_swept_on_open() {
        let sim = Sim::new(47);
        {
            let storage = limited_store(&sim, 1, EVERY_COMMIT);
            let family = storage.open_family("fam").await.unwrap();
            commit_log(&family, b"a", b"data").await;
        }
        sim.create(DIR, &staging_name("fam")).await.unwrap();
        sim.create(DIR, &segment_name("fam", SegmentSeq(9)))
            .await
            .unwrap();

        let storage = seeded_store(&sim, 2);
        let family = storage.open_family("fam").await.unwrap();
        assert_eq!(
            sim.list(DIR).await.unwrap().unwrap(),
            vec![
                manifest_name("fam"),
                segment_name("fam", SegmentSeq(1)),
                segment_name("fam", SegmentSeq(2)),
            ]
        );
        // The referenced checkpoint stayed and the family still works.
        let log = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&log).await, b"data");
        commit_append(&family, &log, b"+more").await;
    }

    /// The open path holds at its pinned barrier counts: one manifest
    /// barrier makes the governing root durable before the sweep, one
    /// segment barrier adopts what replay accepted, and -- only when frames
    /// were adopted past the watermark -- one more manifest barrier
    /// publishes the fresh watermark root.
    #[tokio::test]
    async fn test_open_barrier_counts() {
        // Default trigger: no checkpoint lands, so a reopen adopts every
        // frame and must publish a watermark root: three barriers.
        let sim = Sim::new(37);
        {
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            commit_log(&family, b"a", b"data").await;
        }
        let before = sim.sync_count();
        seeded_store(&sim, 2).open_family("fam").await.unwrap();
        assert_eq!(
            sim.sync_count(),
            before + 3,
            "adopting open: durable-root, adoption, and watermark-root barriers"
        );
        let root = governing_root(&sim, "fam").await;
        assert_eq!(root.seq, 1, "the watermark root supersedes creation's");
        assert_eq!(root.next_txn, TxnSeq(1));
        assert_eq!(root.next_log, LogId(0), "the anchor floor must not move");
        assert_eq!(root.replay_from, TxnSeq(0));

        // A second reopen adopts nothing new: two barriers, no root flip.
        let before = sim.sync_count();
        seeded_store(&sim, 3).open_family("fam").await.unwrap();
        assert_eq!(
            sim.sync_count(),
            before + 2,
            "current-watermark open: durable-root and adoption barriers"
        );
        assert_eq!(governing_root(&sim, "fam").await.seq, 1);

        // A checkpoint-per-commit family reopens with a current root: two
        // barriers, no flip.
        let sim = Sim::new(38);
        {
            let storage = limited_store(&sim, 1, EVERY_COMMIT);
            let family = storage.open_family("fam").await.unwrap();
            commit_log(&family, b"a", b"data").await;
        }
        let seq = governing_root(&sim, "fam").await.seq;
        let before = sim.sync_count();
        limited_store(&sim, 2, EVERY_COMMIT)
            .open_family("fam")
            .await
            .unwrap();
        assert_eq!(
            sim.sync_count(),
            before + 2,
            "checkpointed open: durable-root and adoption barriers"
        );
        assert_eq!(governing_root(&sim, "fam").await.seq, seq);
    }

    /// The family-capacity admission gate fails closed with
    /// [Error::FamilyFull] at the checkpoint caps -- committed logs and
    /// extents -- and the family keeps working: nothing changed, no poison.
    #[tokio::test]
    async fn test_family_capacity_admission_gate() {
        // Log cap: a third committed log cannot be admitted.
        let sim = Sim::new(41);
        let storage = limited_store(
            &sim,
            1,
            Limits {
                checkpoint_logs: 2,
                ..Limits::default()
            },
        );
        let family = storage.open_family("fam").await.unwrap();
        commit_log(&family, b"a", b"x").await;
        commit_log(&family, b"b", b"y").await;
        let mut txn = family.transaction().await.unwrap();
        txn.create(b"c").unwrap();
        assert!(matches!(
            txn.start_commit().await,
            Err(Error::FamilyFull(_))
        ));
        // Not poisoned: a transaction within the caps still commits.
        let a = family.open(b"a").await.unwrap().unwrap();
        commit_append(&family, &a, b"+more").await;

        // Extent cap: each small append adds one extent.
        let sim = Sim::new(42);
        let storage = limited_store(
            &sim,
            1,
            Limits {
                checkpoint_extents: 2,
                ..Limits::default()
            },
        );
        let family = storage.open_family("fam").await.unwrap();
        let a = commit_log(&family, b"a", b"one").await;
        commit_append(&family, &a, b"two").await;
        let mut txn = family.transaction().await.unwrap();
        txn.append(&a, b"three".to_vec()).unwrap();
        assert!(matches!(
            txn.start_commit().await,
            Err(Error::FamilyFull(_))
        ));
        // Removals refund extents at the next checkpoint, never at the gate,
        // but a pure removal carries no blocks and is always admissible.
        let mut txn = family.transaction().await.unwrap();
        txn.remove(&a).unwrap();
        txn.commit().await.unwrap();
    }

    /// Admission fails closed when the uncheckpointed span plus this frame
    /// would breach a replay ceiling, so failed-checkpoint/recover cycles
    /// can never grow the span past what recovery accepts.
    #[tokio::test]
    async fn test_replay_span_admission_gate() {
        // Transaction ceiling: the span may reach it, never pass it.
        let sim = Sim::new(43);
        let storage = limited_store(
            &sim,
            1,
            Limits {
                replay_txns: 3,
                ..Limits::default()
            },
        );
        let family = storage.open_family("fam").await.unwrap();
        let a = commit_log(&family, b"a", b"x").await;
        commit_append(&family, &a, b"y").await;
        commit_append(&family, &a, b"z").await;
        let mut txn = family.transaction().await.unwrap();
        txn.append(&a, b"!".to_vec()).unwrap();
        assert!(matches!(
            txn.start_commit().await,
            Err(Error::FamilyFull(_))
        ));

        // Byte ceiling: admission charges the frame's payload plus the
        // frozen framing allowance against the remaining span.
        let sim = Sim::new(44);
        let storage = limited_store(
            &sim,
            1,
            Limits {
                replay_bytes: MAX_FRAME_OVERHEAD + 256,
                ..Limits::default()
            },
        );
        let family = storage.open_family("fam").await.unwrap();
        let a = commit_log(&family, b"a", &[7u8; 64]).await;
        let mut admitted = 0;
        loop {
            let mut txn = family.transaction().await.unwrap();
            txn.append(&a, vec![7u8; 64]).unwrap();
            match txn.start_commit().await {
                Ok(handle) => {
                    handle.await.unwrap();
                    admitted += 1;
                    assert!(admitted < 10, "the byte gate never engaged");
                }
                Err(Error::FamilyFull(_)) => break,
                Err(error) => panic!("unexpected admission error: {error:?}"),
            }
        }
        assert!(admitted >= 1, "the byte gate engaged before any commit fit");
    }

    /// A durable image whose replay span exceeds a ceiling -- admission
    /// fails closed, so only damage or a forged root can produce one -- is
    /// hard corruption at open, for each ceiling. (Written under default
    /// limits, reopened under shrunken ones: the cheap stand-in for a root
    /// whose replay range outgrew the frozen ceilings.)
    #[tokio::test]
    async fn test_replay_over_ceiling_is_corrupt() {
        let sim = Sim::new(45);
        {
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            let a = commit_log(&family, b"a", b"0").await;
            for _ in 0..3 {
                commit_append(&family, &a, b"x").await;
            }
        }
        let shrunken = limited_store(
            &sim,
            2,
            Limits {
                replay_txns: 3,
                ..Limits::default()
            },
        );
        assert!(matches!(
            shrunken.open_family("fam").await,
            Err(Error::FamilyCorrupt(..))
        ));
        let shrunken = limited_store(
            &sim,
            3,
            Limits {
                replay_bytes: 16,
                ..Limits::default()
            },
        );
        assert!(matches!(
            shrunken.open_family("fam").await,
            Err(Error::FamilyCorrupt(..))
        ));
    }

    /// Committed bytes missing from the segment -- a planned extent read
    /// hitting EOF -- are corruption: the read poisons the family instead of
    /// surfacing a length error the caller would blame on its own offset.
    #[tokio::test]
    async fn test_short_extent_read_is_corrupt() {
        let sim = Sim::new(46);
        let storage = test_store(&sim);
        let family = storage.open_family("fam").await.unwrap();
        let log = commit_log(&family, b"a", &[7u8; 64]).await;
        // Truncate the active segment behind the store's back.
        let file = sim
            .open(DIR, &segment_name("fam", SegmentSeq(1)))
            .await
            .unwrap()
            .unwrap();
        let size = file.size().await.unwrap();
        file.set_len(size - 32).await.unwrap();
        assert!(matches!(
            log.read_at(0, 64).await,
            Err(Error::FamilyCorrupt(..))
        ));
        assert!(matches!(family.scan().await, Err(Error::FamilyPoisoned(_))));
    }

    /// Re-publishes the family's checkpoint with `mutate` applied to its
    /// rows, extents, and segments, as a fresh checkpoint segment under a
    /// fresh root. The result is format-valid (encoded through the real
    /// funnel), so only the semantic extent validation at open can reject
    /// it.
    async fn republish_checkpoint(
        sim: &Sim,
        family: &str,
        mutate: impl FnOnce(&mut Vec<CatalogRow>, &mut Vec<ExtentRow>, &mut Vec<SegmentSeq>),
    ) {
        let manifest = sim
            .open(DIR, &manifest_name(family))
            .await
            .unwrap()
            .unwrap();
        let header = ManifestHeader::decode(&manifest.read_at(0, PAGE).await.unwrap()).unwrap();
        let root = governing_root(sim, family).await;
        let locator = root.checkpoint.unwrap();
        let salt = Salt::new(&header.incarnation, root.epoch);

        let old = sim
            .open(DIR, &segment_name(family, locator.segment))
            .await
            .unwrap()
            .unwrap();
        let bytes = old
            .read_at(locator.start.0, locator.len as usize)
            .await
            .unwrap();
        let ident = Identity {
            salt,
            segment: locator.segment,
        };
        let checkpoint = Checkpoint::decode(&bytes, &ident, locator.seq).unwrap();
        let mut rows: Vec<CatalogRow> = checkpoint.rows().cloned().collect();
        let mut extents: Vec<ExtentRow> = checkpoint.extents().cloned().collect();
        let mut segments: Vec<SegmentSeq> = checkpoint.segments().copied().collect();
        mutate(&mut rows, &mut extents, &mut segments);

        let segment = SegmentSeq(locator.segment.0 + 1);
        let forged = Checkpoint::new(
            locator.seq,
            rows,
            extents,
            segments,
            root.next_log,
            root.replay_from,
        )
        .unwrap();
        let ident = Identity { salt, segment };
        let mut bytes = SegmentHeader {
            incarnation: header.incarnation,
            seq: segment,
        }
        .encode();
        forged.encode(&ident, &mut bytes);
        let len = (bytes.len() - PAGE) as u64;
        let file = sim
            .create(DIR, &segment_name(family, segment))
            .await
            .unwrap();
        file.write_at(0, bytes).await.unwrap();
        file.sync().await.unwrap();
        sim.sync_dir(DIR).await.unwrap();
        let forged_root = Root {
            seq: root.seq + 1,
            checkpoint: Some(CheckpointLocator {
                segment,
                start: SEGMENT_RECORDS,
                len,
                seq: locator.seq,
                hash: forged.end().hash,
            }),
            ..root
        };
        manifest
            .write_at(
                ROOT_OFFSETS[(forged_root.seq & 1) as usize],
                forged_root.encode(&header.incarnation),
            )
            .await
            .unwrap();
        manifest.sync().await.unwrap();
    }

    /// Format-valid checkpoints whose extent rows are semantically
    /// impossible -- a segment outside the checkpoint's set, an empty
    /// segment set with extents present, or bytes reaching past the located
    /// replay boundary -- are hard corruption at open.
    #[tokio::test]
    async fn test_forged_checkpoint_extent_rows_are_corrupt() {
        type Mutate = fn(&mut Vec<CatalogRow>, &mut Vec<ExtentRow>, &mut Vec<SegmentSeq>);
        let cases: [Mutate; 4] = [
            |_, extents, _| extents[0].segment = SegmentSeq(9),
            |_, _, segments| segments.clear(),
            |_, extents, _| extents[0].start = SegmentOffset(1 << 40),
            |_, extents, _| extents[0].crc = SegmentOffset(u64::MAX - 1),
        ];
        for (i, mutate) in cases.into_iter().enumerate() {
            let sim = Sim::new(101 + i as u64);
            {
                let storage = limited_store(&sim, 1, EVERY_COMMIT);
                let family = storage.open_family("fam").await.unwrap();
                commit_log(&family, b"a", b"data").await;
            }
            republish_checkpoint(&sim, "fam", mutate).await;
            assert!(
                matches!(
                    seeded_store(&sim, 2).open_family("fam").await,
                    Err(Error::FamilyCorrupt(..))
                ),
                "case {i}"
            );
        }
    }

    /// The iterated buried-tear probe at the store level: damage to TWO
    /// consecutive acknowledged post-checkpoint frames under an intact
    /// acknowledged successor is detected as corruption on reopen, never
    /// silently truncated.
    #[tokio::test]
    async fn test_consecutive_damaged_frames_are_corrupt() {
        let sim = Sim::new(63);
        {
            let storage = limited_store(
                &sim,
                1,
                Limits {
                    checkpoint_trigger_bytes: u64::MAX,
                    checkpoint_trigger_txns: 4,
                    ..Limits::DEFAULT
                },
            );
            let family = storage.open_family("fam").await.unwrap();
            let segment = sim
                .open(DIR, &segment_name("fam", SegmentSeq(1)))
                .await
                .unwrap()
                .unwrap();
            let keep = commit_log(&family, b"keep", b"base").await;
            commit_append(&family, &keep, b"-c2").await;
            commit_append(&family, &keep, b"-c3").await;
            // The one checkpoint lands after this fourth commit; the next
            // three commits stay under the trigger, so all of them replay.
            commit_append(&family, &keep, b"-c4").await;
            let mut bounds = vec![segment.size().await.unwrap()];
            for suffix in [b"-c5", b"-c6", b"-c7"] {
                commit_append(&family, &keep, suffix).await;
                bounds.push(segment.size().await.unwrap());
            }
            assert_eq!(governing_root(&sim, "fam").await.replay_at.0, bounds[0]);
            // Flip a body bit in the fifth and sixth commits' frames; the
            // seventh is intact, so the probe's walk proves both tears sit
            // in acknowledged history.
            for at in [bounds[0] + 6, bounds[1] + 6] {
                let byte = segment.read_at(at, 1).await.unwrap();
                segment.write_at(at, vec![byte[0] ^ 1]).await.unwrap();
            }
        }
        assert!(matches!(
            seeded_store(&sim, 2).open_family("fam").await,
            Err(Error::FamilyCorrupt(..))
        ));
    }

    /// Barrier-fuse x seed enumeration over the commit + checkpoint + root
    /// flip protocol: whichever barrier fails, recovery serves a committed
    /// prefix under whichever root survived. Both allowed recoveries (the
    /// indeterminate commit adopted and not) must be observed.
    #[tokio::test]
    async fn test_checkpoint_crash_enumeration() {
        let (mut kept, mut adopted) = (false, false);
        // Each checkpointing commit burns up to four barriers.
        for fuse in 0..=(4 * SCRIPT_STEPS as u64) {
            for seed in 0..8 {
                let outcome =
                    run_crash_scenario(Fault::Sync, fuse, seed, EVERY_COMMIT, false).await;
                match outcome.adopted {
                    0 => kept = true,
                    _ => adopted = true,
                }
            }
        }
        assert!(
            kept && adopted,
            "the enumeration never saw both allowed recoveries"
        );
    }

    /// The poison-continue-crash grid: at every checkpoint-protocol barrier,
    /// force the failure, poison, recover IN PROCESS, finish the script,
    /// crash, and reopen. This is the grid that catches a recovery trusting
    /// a non-durable root: the recovered session sweeps and commits against
    /// the root it selected, and the final reopen must still land on the one
    /// committed prefix over a durable root.
    #[tokio::test]
    async fn test_poison_recover_continue_crash_enumeration() {
        for fuse in 0..=(4 * SCRIPT_STEPS as u64) {
            for seed in 0..8 {
                run_crash_scenario(Fault::Sync, fuse, seed, EVERY_COMMIT, true).await;
            }
        }
    }

    /// One adopting-open crash scenario: every commit is acknowledged, so no
    /// open outcome -- however its barriers fail -- may ever lose or regress
    /// state. Returns whether the fused open succeeded. `limits` shapes the
    /// fused open (a due trigger makes it checkpoint-on-open, widening the
    /// window under test).
    async fn run_open_crash(fuse: u64, seed: u64, limits: Limits) -> bool {
        let ctx = format!("open fuse {fuse} seed {seed}");
        let sim = Sim::new(seed);
        {
            let storage = test_store(&sim);
            let family = storage.open_family("fam").await.unwrap();
            let log = commit_log(&family, b"a", b"hello").await;
            commit_append(&family, &log, b" world").await;
        }
        sim.crash();

        sim.fail_syncs_after(fuse);
        let opened = limited_store(&sim, 2, limits)
            .open_family("fam")
            .await
            .is_ok();
        sim.crash(); // heals the fuse; unsynced open work settles per seed

        let storage = seeded_store(&sim, 3);
        let family = storage
            .open_family("fam")
            .await
            .unwrap_or_else(|error| panic!("{ctx}: healthy reopen failed: {error:?}"));
        let log = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&log).await, b"hello world", "{ctx}: state lost");
        commit_append(&family, &log, b"!").await;
        opened
    }

    /// Barrier-fuse x seed enumeration over adopting opens (to-do (a)):
    /// whichever open barrier fails -- the durable-root barrier, adoption,
    /// the watermark flip, or (with a due trigger) the checkpoint-on-open
    /// publication -- a later healthy open serves every acknowledged byte.
    /// The fuse space is discovered, not guessed.
    #[tokio::test]
    async fn test_open_crash_enumeration() {
        for limits in [Limits::default(), EVERY_COMMIT] {
            let mut opened = false;
            for fuse in 0..16 {
                for seed in 0..8 {
                    opened = run_open_crash(fuse, seed, limits).await;
                }
                if opened {
                    break;
                }
            }
            assert!(opened, "the open never completed");
        }
    }

    /// The frozen reserve covers its derivation at the frozen caps and
    /// default bounds (the constructor's debug assertion, exercised
    /// explicitly).
    #[test]
    fn test_default_reserve_covers_derivation() {
        let limits = Limits::default();
        let bounds = Bounds::default();
        assert!(limits.cleaner_reserve_bytes >= limits.min_reserve(&bounds));
        assert!(limits.admission_floor(&bounds) > limits.cleaner_reserve_bytes);
    }

    /// An in-flight read pins the segments it touches: cleaning retires a
    /// pinned victim but defers its unlink until the pin drops.
    #[tokio::test]
    async fn test_pins_defer_unlink() {
        let sim = Sim::new(97);
        let limits = Limits {
            checkpoint_logs: 64,
            checkpoint_extents: 256,
            segment_target_bytes: 1024,
            cleaner_reserve_bytes: 64 << 10,
            ..Limits::default()
        };
        let storage = limited_store(&sim, 1, limits);
        let family = storage.open_family("fam").await.unwrap();
        // Six 384-byte appends: each triple crosses the target, so segments
        // 1 and 2 seal with three extents each.
        let a = commit_log(&family, b"a", &[7u8; 384]).await;
        for _ in 0..5 {
            commit_append(&family, &a, &[7u8; 384]).await;
        }
        let shared = family_shared(&storage, "fam");
        assert_eq!(shared.state.lock().metrics.rotations, 2);
        let sealed = segment_name("fam", SegmentSeq(1));
        assert!(sim.list(DIR).await.unwrap().unwrap().contains(&sealed));

        // Plan (and hold) a read touching segment 1.
        let held = {
            let mut state = shared.state.lock();
            plan_fetch(&shared, &mut state, LogId(0), 0, 10).unwrap()
        };
        assert!(shared.state.lock().pins.contains_key(&SegmentSeq(1)));

        // Rewind to 100: segment 1 keeps one straddled live extent (a
        // profitable copy), segment 2 goes dead, and the reclaimable gain
        // crosses the target, so this commit cleans -- copying segment 1's
        // survivor and retiring both victims. The unpinned one unlinks
        // immediately; the pinned one waits.
        let mut txn = family.transaction().await.unwrap();
        txn.rewind(&a, 100).unwrap();
        txn.commit().await.unwrap();
        {
            let state = shared.state.lock();
            assert_eq!(state.metrics.cleanings, 1);
            assert_eq!(state.metrics.relocated_extents, 1);
            assert_eq!(state.metrics.relocated_bytes, 384);
            assert_eq!(state.metrics.unlinked_segments, 1);
            assert_eq!(state.retired, vec![SegmentSeq(1)], "pinned: not unlinked");
        }
        assert!(sim.list(DIR).await.unwrap().unwrap().contains(&sealed));
        // The relocated bytes read back through the copy segment.
        assert_eq!(read_all(&a).await, vec![7u8; 100]);

        // Release the pin; the next maintenance drains the retirement.
        drop(held);
        assert!(shared.state.lock().pins.is_empty());
        commit_append(&family, &a, b"x").await;
        assert!(shared.state.lock().retired.is_empty());
        assert!(!sim.list(DIR).await.unwrap().unwrap().contains(&sealed));
        assert_eq!(shared.state.lock().metrics.unlinked_segments, 2);
    }
}
