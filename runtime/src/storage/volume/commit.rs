//! The commit: snapshot -> write -> fsync -> finalize.
//!
//! Commits serialize on `Ready::commit_lock` and are SELECTIVE: a commit
//! captures only the blobs it is rooted at (the synced blob — pooled with
//! every concurrently queued sync's blob by [`commit`]'s coalescing — a
//! batch's blobs, a removal's ids), expanded across applied-batch groups so
//! an applied batch is never split across commits. Every other blob's table
//! entry is served verbatim from its cached committed encoding; uncaptured
//! dirty state (dirty marks, manifest chunks, content frees) stays pending
//! for a later commit that captures the blob.
//!
//! The snapshot briefly takes each captured blob's write lock (in id order)
//! to capture a coherent entry and raise its freeze boundary; writers never
//! block on the fsync itself. A clean sync returns immediately. Any failure
//! during the write or fsync phase permanently poisons the volume (see
//! `Ready::poisoned`): a failed fsync is a volume-wide (physical) event, so
//! the latch covers every blob, captured or not.

use super::{
    alloc::{block_align, Extent},
    chunk::{chunk_of, ChunkCrc, ChunkMap},
    layout::{ChecksumRef, Entry, Run, Superblock, Table},
    paging::{load_committed_refs, window_value, CrcWindow},
    state::{BlobCore, BlobInner, Ready},
    BLOCK,
};
use crate::{Blob as _, Error, IoBuf};
use commonware_cryptography::Crc32;
use commonware_utils::sync::Notify;
use std::{
    collections::BTreeSet,
    sync::{Arc, OnceLock},
};

/// Cap on a blob's checksum refs: an append-shaped commit that would exceed
/// it rewrites the full array as one ref instead (compaction). Bounds the
/// table entry's ref list and the block-alignment slack of small delta
/// extents, while amortizing full-array rewrites to at most one per this
/// many append-shaped commits.
pub(super) const MAX_CHECKSUM_REFS: usize = 16;

/// Convert a table's encoded length to the on-disk superblock field without
/// truncation. A commit must fail before acknowledgement if its table cannot
/// be represented: recovery reads exactly this many bytes for the CRC binding.
pub(super) fn checked_table_len(len: usize) -> Result<u32, Error> {
    len.try_into().map_err(|_| Error::OffsetOverflow)
}

/// Convert a checksum extent's value count to the on-disk ref field.
pub(super) fn checked_checksum_count(bytes: usize) -> Result<u32, Error> {
    debug_assert!(bytes.is_multiple_of(4));
    (bytes / 4).try_into().map_err(|_| Error::OffsetOverflow)
}

/// A planned write for the commit's WRITE phase.
struct MetaWrite {
    physical: u64,
    bytes: IoBuf,
}

/// A commit whose logical state and metadata writes are fixed, but whose
/// writes have not yet passed the volume-file durability barrier.
struct PreparedCommit {
    seq: u64,
    table_extent: Extent,
    writes: Vec<MetaWrite>,
    /// (blob core, its new committed entry) for every captured dirty blob.
    committed: Vec<(Arc<BlobCore>, Entry)>,
    /// The capture set (groups it covers are cleared at finalize).
    capture: BTreeSet<u64>,
}

/// A prepared commit whose metadata writes and superblock have completed the
/// volume-file durability barrier. Only this state may be finalized in RAM.
struct DurableCommit(PreparedCommit);

impl PreparedCommit {
    /// Write every prepared extent and cross the one durability barrier that
    /// makes this commit eligible for publication.
    async fn write_and_sync<S: crate::Storage>(
        self,
        ready: &Ready<S>,
    ) -> Result<DurableCommit, Error> {
        let end = self
            .writes
            .iter()
            .map(|write| write.physical + write.bytes.len() as u64)
            .max()
            .expect("a commit writes at least its table");
        super::state::ensure_provisioned(ready, end).await?;
        futures::future::try_join_all(
            self.writes
                .iter()
                .map(|write| ready.file.write_at(write.physical, write.bytes.clone())),
        )
        .await?;
        // The cfg is a mutation-testing negative control. The assurance gate
        // must prove that omitting this durability barrier breaks a test.
        #[cfg(not(commonware_volume_mutation_skip_commit_sync))]
        {
            // Wall-clock fsync timing (metrics only; wasm32 has no monotonic
            // clock).
            #[cfg(not(target_arch = "wasm32"))]
            let start = std::time::Instant::now();
            ready.file.sync().await?;
            #[cfg(not(target_arch = "wasm32"))]
            ready
                .metrics
                .fsync_duration
                .observe(start.elapsed().as_secs_f64());
        }
        #[cfg(commonware_volume_mutation_skip_commit_sync)]
        let _ = &ready.metrics.fsync_duration;
        Ok(DurableCommit(self))
    }
}

/// A registration in the pending-commit pool: the shared result of the
/// coalesced commit that will cover the registered roots. Callers OBSERVE
/// tickets ([`TicketState::wait`]) and driver tasks resolve them — a
/// commit's progress never depends on any observer being polled.
pub(super) type Ticket = Arc<TicketState>;

/// A ticket's resolution cell plus the notification observers await.
pub(super) struct TicketState {
    result: OnceLock<Result<(), Error>>,
    /// Fired (wake-all) once `result` is set.
    notify: Notify,
}

/// Capture roots pooled by commit registrations, with the completion latch
/// their commit resolves.
///
/// Whichever driver task acquires the commit lock first drains the pool and
/// commits the UNION, so one fsync acknowledges every pooled registration
/// (commit coalescing, see `commit::commit`). The ticket is swapped out
/// atomically with the roots at drain: a ticket therefore resolves exactly
/// when a commit whose snapshot began after every covered registration
/// completes, and a failed commit resolves it with the poisoning error
/// (every pooled registration was promised durability).
pub(super) struct PendingCommit {
    pub roots: BTreeSet<u64>,
    pub ticket: Ticket,
}

impl Default for PendingCommit {
    fn default() -> Self {
        Self {
            roots: BTreeSet::new(),
            ticket: new_ticket(),
        }
    }
}

/// A fresh unresolved ticket.
pub(super) fn new_ticket() -> Ticket {
    Arc::new(TicketState {
        result: OnceLock::new(),
        notify: Notify::new(),
    })
}

impl TicketState {
    /// The result, if resolved.
    pub fn get(&self) -> Option<&Result<(), Error>> {
        self.result.get()
    }

    /// Resolve with `result` and wake every observer. Asserts single
    /// resolution: only the leader that drained this ticket resolves it.
    pub fn resolve(&self, result: Result<(), Error>) {
        self.result
            .set(result)
            .expect("only the draining leader resolves a ticket");
        self.notify.notify_waiters();
    }

    /// Resolve with [`Error::Aborted`] if still unresolved (the
    /// cancellation guard's drop path, which may race nothing but must
    /// tolerate an already-resolved ticket).
    fn abort(&self) {
        let _ = self.result.set(Err(Error::Aborted));
        self.notify.notify_waiters();
    }

    /// Wait for the resolution. Never blocks the resolver: observers hold
    /// only this shared state, so dropping or parking a waiting future is
    /// always benign.
    pub async fn wait(&self) -> Result<(), Error> {
        loop {
            if let Some(result) = self.result.get() {
                return result.clone();
            }
            // Register before re-checking: a resolution landing between
            // the check and the await wakes this registration.
            let notified = self.notify.notified();
            if let Some(result) = self.result.get() {
                return result.clone();
            }
            notified.await;
        }
    }
}

/// Poisons the volume and fails the drained ticket if the leader's driver
/// task is dropped mid-flight. Commits execute only in driver tasks, so
/// this fires exclusively when the runtime tears down with a commit in
/// flight — caller-side futures are pure ticket observers and cannot
/// cancel a commit (pinned by the conformance cancellation injector).
///
/// A leader dropped mid-commit has already swapped the pool's ticket and
/// may have consumed snapshot state (dirty marks, deferred frees, cached
/// entry encodings) or issued metadata
/// writes. The half-driven commit can neither be completed nor unwound
/// from a `Drop` impl, and a later commit would vouch for state it cannot
/// prove landed — so the abort latches the same poison as a failed
/// commit, and every observer sees the error through the ticket. Tasks
/// dropped BEFORE leadership (still queued on the commit lock) never arm
/// this guard and stay benign.
struct CancelGuard<'a, S: crate::Storage> {
    ready: &'a Ready<S>,
    ticket: Option<Ticket>,
}

impl<S: crate::Storage> CancelGuard<'_, S> {
    /// Disarm the guard and resolve the drained ticket with the commit's
    /// result.
    fn resolve(mut self, result: Result<(), Error>) {
        let ticket = self.ticket.take().expect("guard resolves once");
        ticket.resolve(result);
    }
}

impl<S: crate::Storage> Drop for CancelGuard<'_, S> {
    fn drop(&mut self) {
        let Some(ticket) = self.ticket.take() else {
            return;
        };
        tracing::error!("volume commit task dropped mid-commit; storage poisoned until restart");
        self.ready.poison(Error::Aborted);
        ticket.abort();
    }
}

/// Poisons the volume if dropped while armed: guards a commit's mutation
/// span against its driver task being dropped mid-flight (the runtime
/// tearing down).
///
/// [`commit_locked`] runs inside the removal and batch-apply driver tasks
/// with no pooled ticket, so [`CancelGuard`] never sees them. Once the
/// snapshot starts consuming state — dirty marks, deferred frees, cached
/// encodings — a dropped task can neither complete
/// the commit nor unwind it, and the next confirming commit would publish
/// the half-snapshot (a durable table referencing never-written extents).
/// The batch apply task arms one across its publish for the same reason
/// (a half-published batch splits the group).
pub(super) struct PoisonOnCancel<'a, S: crate::Storage> {
    ready: &'a Ready<S>,
    armed: bool,
}

impl<'a, S: crate::Storage> PoisonOnCancel<'a, S> {
    pub const fn arm(ready: &'a Ready<S>) -> Self {
        Self { ready, armed: true }
    }

    /// The guarded span completed (or failed and latched its own poison).
    pub fn disarm(mut self) {
        self.armed = false;
    }
}

impl<S: crate::Storage> Drop for PoisonOnCancel<'_, S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        tracing::error!("volume commit future dropped mid-flight; storage poisoned until restart");
        self.ready.poison(Error::Aborted);
    }
}

/// Register `roots` in the pending-commit pool under the CURRENT ticket:
/// the first leader to drain the pool after this point covers these roots
/// and resolves the returned ticket with the union commit's result.
pub(super) fn register<S: crate::Storage>(ready: &Ready<S>, roots: &[u64]) -> Ticket {
    ready.metrics.sync_requests.inc();
    let mut pending = ready.pending.lock();
    pending.roots.extend(roots.iter().copied());
    pending.ticket.clone()
}

/// Resolve a registration: lead-or-observe, inside a driver task. Queues
/// on the commit lock and, if a leader's commit already resolved `ticket`
/// while queued, returns its result. Otherwise this task is the leader: it
/// drains the pool (the registered roots plus everything registered since
/// the previous drain) and commits the UNION, so one fsync acknowledges
/// every pooled caller.
pub(super) async fn drive<S: crate::Storage>(
    ready: &Ready<S>,
    ticket: Ticket,
) -> Result<(), Error> {
    let _commit = ready.commit_lock.lock().await;
    // Resolved while queued: a leader's commit already covered our roots.
    if let Some(result) = ticket.get() {
        return result.clone();
    }
    // Leader: an unresolved ticket is still the pool's current ticket (a
    // leader swaps the ticket out only while holding the commit lock and
    // resolves it before releasing — including on cancellation, via
    // `CancelGuard`), so draining returns it.
    let (union, ticket) = {
        let mut pending = ready.pending.lock();
        let union: Vec<u64> = std::mem::take(&mut pending.roots).into_iter().collect();
        let drained = std::mem::replace(&mut pending.ticket, new_ticket());
        assert!(
            Arc::ptr_eq(&ticket, &drained),
            "unresolved ticket must be the pool's current ticket"
        );
        (union, drained)
    };
    // Leadership is assumed: from here, dropping this future mid-commit
    // must poison instead of silently vanishing (see [`CancelGuard`]).
    let guard = CancelGuard {
        ready,
        ticket: Some(ticket),
    };
    let result = commit_locked(ready, &union).await;
    guard.resolve(result.clone());
    result
}

/// Request a commit covering `roots`: register in the pending pool and
/// schedule a driver task ([`drive`]) for the pool's ticket. The returned
/// ticket is the observation point — the commit's progress never depends
/// on the caller polling anything, so a dropped or parked observer is
/// benign (the commit still runs to completion).
pub(super) fn request<S: crate::Storage>(ready: &Arc<Ready<S>>, roots: &[u64]) -> Ticket {
    let ticket = register(ready, roots);
    spawn_drive(ready, ticket.clone());
    ticket
}

/// Schedule a driver task for `ticket`: queue on the commit lock and
/// lead-or-observe, exactly one spawned task per durability request (the
/// same queue depth the caller-driven design produced). The task's result
/// reaches observers through the ticket, and failures additionally latch
/// the poison.
pub(super) fn spawn_drive<S: crate::Storage>(ready: &Arc<Ready<S>>, ticket: Ticket) {
    let driven = ready.clone();
    ready.driver.spawn(async move {
        let _ = drive(&driven, ticket).await;
    });
}

/// Commit the dirty state of the blobs rooted at `roots` (expanded across
/// applied-batch groups), coalescing with concurrent syncs: callers pool
/// their roots ([`register`]), and whichever driver task acquires the
/// commit lock first drains the pool and commits the UNION ([`drive`]), so
/// one fsync acknowledges every pooled caller. Each caller's durability
/// promise is met exactly — the union's snapshot begins after every pooled
/// registration — and a failed union commit fails every pooled caller (they
/// were promised durability, and the poison latch stands for everyone).
/// Returns without I/O when the captured state is clean.
///
/// Coalescing is keyed off the commit-lock queue alone (no timers): under
/// the deterministic runtime, driver tasks schedule like any other task,
/// so identical schedules produce identical commit grouping.
pub(super) async fn commit<S: crate::Storage>(
    ready: &Arc<Ready<S>>,
    roots: &[u64],
) -> Result<(), Error> {
    request(ready, roots).wait().await
}

/// [`commit`] with `Ready::commit_lock` already held by the caller.
pub(super) async fn commit_locked<S: crate::Storage>(
    ready: &Ready<S>,
    roots: &[u64],
) -> Result<(), Error> {
    ready.check_poisoned()?;

    let capture = {
        let state = ready.state.lock();
        let capture = state.expand_capture(roots);
        if state.clean_for(&capture) {
            return Ok(());
        }
        capture
    };

    // From here the commit consumes state, so cancellation must poison
    // (see [`PoisonOnCancel`]).
    let guard = PoisonOnCancel::arm(ready);
    let prepared = match prepare_commit(ready, capture).await {
        Ok(s) => s,
        Err(e) => {
            // Snapshot allocates extents and mutates freeze/dirty state; a
            // failure mid-way leaves the volume inconsistent with its
            // bookkeeping. Poison (consistent with the workspace rule that
            // mutable storage-op failures are fatal).
            tracing::error!(
                error = %e,
                "volume commit preparation failed; storage poisoned until restart"
            );
            ready.poison(e.clone());
            guard.disarm();
            return Err(e);
        }
    };

    // WRITE + FSYNC phase: provision once for the commit's furthest write,
    // then issue every metadata write concurrently. The writes land in
    // disjoint extents and all precede the one fsync, so issue order is
    // free (the crash model already resolves each dirtied block
    // independently); a small commit pays one write round-trip instead of
    // one per write.
    let durable = match prepared.write_and_sync(ready).await {
        Ok(durable) => durable,
        Err(e) => {
            tracing::error!(
                error = %e,
                "volume commit write/fsync failed; storage poisoned until restart"
            );
            // The cfg is a mutation-testing negative control. The assurance gate
            // must prove that losing this fatal latch breaks a test.
            #[cfg(not(commonware_volume_mutation_skip_commit_poison))]
            ready.poison(e.clone());
            guard.disarm();
            return Err(e);
        }
    };

    finalize(ready, durable);
    guard.disarm();
    ready.metrics.commits.inc();
    Ok(())
}

/// Chunk coverage a blob's checksum refs must provide: every backed chunk
/// below the frontier, plus the frontier itself when it is a FULL chunk (a
/// partial frontier is served by `tail_crc`, so coverage stops below it).
/// Hole positions inside the covered range are never consulted (holes are
/// identified from the runs, not the array).
fn covered_end(inner: &BlobInner) -> u64 {
    let last_backed = inner
        .runs()
        .iter()
        .next_back()
        .map(|(&l, r)| chunk_of(l + r.len - 1));
    last_backed.map_or(0, |last| {
        let (_, span) = inner.chunk_span(last).expect("backed chunk");
        if span == BLOCK {
            last + 1
        } else {
            last
        }
    })
}

/// A captured chunk's exact CRC: its resident value, or the committed
/// value preloaded from the old extents. Holes encode 0 (never consulted).
fn resolve_crc(crcs: &ChunkMap, preloaded: &[CrcWindow], chunk: u64) -> u32 {
    crcs.get(chunk).map_or(0, |s| match s.crc {
        ChunkCrc::Ready(crc) => crc,
        // Finalized before encoding (every pending chunk is resident).
        ChunkCrc::Pending => unreachable!("pending CRC at capture"),
        // Untouched since hydration, so within the old coverage the
        // full-rewrite preload read above.
        ChunkCrc::Unloaded => {
            window_value(preloaded, chunk).expect("unloaded chunk is preloaded at capture")
        }
    })
}

/// Capture the commit's content and allocate/encode its metadata writes,
/// in four phases per captured blob: plan the checksum-ref shape
/// ([`plan_refs`]), capture the value snapshot under the write lock
/// ([`capture_blob`]), allocate and stage its metadata ([`stage_meta`]),
/// then assemble the table over every entry ([`assemble_table`]).
async fn prepare_commit<S: crate::Storage>(
    ready: &Ready<S>,
    capture: BTreeSet<u64>,
) -> Result<PreparedCommit, Error> {
    // Assign the seq and advance the freeze epoch before touching blobs:
    // writes racing the snapshot land with `born > snapshot_seq` and are
    // exempt from freezing only until their blob's capture below, which
    // re-stamps every run it references (a racing run captured by this
    // commit is NOT invisible to it — only runs created after the capture
    // are). Uncaptured dirty blobs lose the exemption entirely (their young
    // extents are not referenced by any table): conservatively over-frozen,
    // which costs an extra COW on a later in-place rewrite but is always
    // safe.
    let (seq, dirty_ids) = {
        let mut state = ready.state.lock();
        let seq = state.begin_snapshot();
        let dirty_ids = state.dirty_in(&capture);
        (seq, dirty_ids)
    };

    let mut writes = Vec::new();
    let mut committed = Vec::new();
    let mut manifest = Vec::new();

    for id in dirty_ids {
        let Some(blob) = ready.state.lock().open_blob(id) else {
            continue; // removed with no handles: nothing to snapshot
        };
        // Serialize against writers so the captured entry is coherent with
        // issued bytes; released before any I/O below (the capture is a
        // value snapshot, and the freeze boundary protects it thereafter).
        let write_guard = blob.write_lock.lock().await;
        let Some((plan, preloaded)) = plan_refs(ready, &blob).await? else {
            ready.state.lock().clear_dirty(id);
            continue;
        };
        let captured = capture_blob(ready, &blob, seq, plan, &preloaded);
        drop(write_guard);
        let entry = stage_meta(ready, seq, captured, &mut writes, &mut manifest)?;
        committed.push((blob, entry));
    }

    let table_extent = assemble_table(ready, seq, &mut committed, &mut manifest, &mut writes)?;

    Ok(PreparedCommit {
        seq,
        table_extent,
        writes,
        committed,
        capture,
    })
}

/// The checksum-ref shape decided for one capture: extend coverage with
/// one new delta ref, or rewrite the whole array as a single ref from
/// chunk 0.
#[derive(Clone, Copy)]
enum RefPlan {
    /// Retain the old refs and append coverage from `prev_end`.
    Delta { prev_end: u64 },
    /// Replace every old ref with one compacted array.
    Rewrite,
}

/// Decide the checksum-ref shape ONCE, and preload what a full rewrite
/// needs. Append-shaped dirt leaves every previously covered chunk's CRC
/// valid: extend coverage with one NEW delta ref and keep the prior refs
/// (and their extents) untouched, so a bulk-load sync stops rewriting the
/// blob's whole array. Anything else — dirt below the covered frontier
/// (overwrite, COW, shrink), coverage shrinking (rewind), or a full ref
/// list — rewrites the array as a single ref, which also keeps refs
/// disjoint and contiguous from chunk 0 (compaction). A full rewrite
/// re-encodes every covered chunk's CRC, and chunks untouched this
/// process hold theirs only on disk: preload those values from the OLD
/// extents (a read-modify-write of the checksum array). The capture
/// ([`capture_blob`]) reuses this decision — its inputs (runs coverage,
/// the committed refs, the dirty set) are stable under the write lock and
/// the commit lock, capture-time run merging preserves chunk coverage
/// exactly, and the old extents cannot be recycled underneath the read
/// (their frees are queued by this capture at the earliest and applied
/// only once this commit confirms). A removed blob carries no plan.
async fn plan_refs<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
) -> Result<Option<(RefPlan, Vec<CrcWindow>)>, Error> {
    let decision = {
        let inner = blob.inner.lock();
        if inner.removed() {
            None
        } else {
            let covered_end = covered_end(&inner);
            let prev_refs = inner
                .committed_entry()
                .map_or(&[][..], |e| &e.checksums[..]);
            let prev_end = prev_refs
                .last()
                .map_or(0, |r| r.first_chunk + r.count as u64);
            let delta = covered_end >= prev_end
                && prev_refs.len() < MAX_CHECKSUM_REFS
                && inner.first_dirty_chunk().is_none_or(|c| c >= prev_end);
            let floor_chunk = chunk_of(inner.floor());
            let load = (!delta
                && inner
                    .crcs()
                    .has_unloaded(floor_chunk, covered_end.min(prev_end)))
            .then(|| prev_refs.to_vec());
            Some((delta, prev_end, load))
        }
    };
    let Some((delta, prev_end, load)) = decision else {
        return Ok(None);
    };
    let preloaded = match load {
        // Boxed: the cold streaming loader would otherwise deepen
        // every commit future's layout.
        Some(refs) => Box::pin(load_committed_refs(ready, blob, &refs)).await?,
        None => Vec::new(),
    };
    let plan = if delta {
        RefPlan::Delta { prev_end }
    } else {
        RefPlan::Rewrite
    };
    Ok(Some((plan, preloaded)))
}

/// One blob's capture: the entry to encode plus the metadata bytes and
/// extent movements the staging step turns into allocations and writes.
struct Captured {
    entry: Entry,
    /// Chunks whose content changed since the last capture, sorted.
    dirty_chunks: Vec<u64>,
    /// First chunk the new checksum array covers.
    array_start: u64,
    /// The new checksum array's encoded values (empty: no new ref).
    cksum_bytes: Vec<u8>,
    /// The frontier chunk's span for the shadow block, when partial.
    shadow_bytes: Option<Vec<u8>>,
    /// Extents the new entry stops referencing (freed on confirmation).
    superseded: Vec<Extent>,
}

/// Capture one blob's value snapshot under its write lock (held by the
/// caller): raise the freeze boundary, finalize deferred CRCs, freeze and
/// merge the captured runs, take the dirty set, and encode the new
/// checksum array. The commit lock keeps the blob live from planning
/// through this capture.
fn capture_blob<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    seq: u64,
    plan: RefPlan,
    preloaded: &[CrcWindow],
) -> Captured {
    let id = blob.id;
    let mut state = ready.state.lock();
    let mut inner = blob.inner.lock();
    debug_assert!(!inner.removed(), "planned blob removed under commit lock");

    inner.freeze_for_capture(seq);
    let dirty_chunks = inner.take_dirty_chunks();
    state.clear_dirty(id);

    // Content frees of a captured blob resolve when this commit
    // confirms: its new entry stops referencing them.
    let pending = inner.drain_pending_frees();
    for extent in pending {
        state.defer_free(extent, seq);
    }

    let last_backed = inner
        .runs()
        .iter()
        .next_back()
        .map(|(&l, r)| chunk_of(l + r.len - 1));

    // Chunk coverage the checksum refs must provide (see
    // [`covered_end`]). Unchanged by the run merging above, which
    // preserves chunk coverage exactly.
    let covered_end = covered_end(&inner);

    // The ref shape decided at preload (inputs stable, see
    // [`plan_refs`]). The commit lock prevents removal before capture.
    let floor_chunk = chunk_of(inner.floor());
    let live_ref = |r: &ChecksumRef| r.first_chunk + r.count as u64 > floor_chunk;
    let prev_refs = inner
        .committed_entry()
        .map_or(&[][..], |e| &e.checksums[..]);
    let (array_start, checksums) = match plan {
        RefPlan::Delta { prev_end } => {
            // Refs wholly below the pruned floor drop (their extents
            // supersede below); a straddling ref stays with its low values
            // unused, so pruning never rewrites the array.
            let live: Vec<ChecksumRef> =
                prev_refs.iter().filter(|r| live_ref(r)).copied().collect();
            // The new array continues the retained coverage. With nothing
            // retained (no previous refs, or the floor passed them all), it
            // restarts at the floor's chunk: chunks below it are unbacked and
            // never loaded, and no ref may end at or below the floor chunk.
            let start = if live.is_empty() {
                floor_chunk
            } else {
                prev_end
            };
            (start, live)
        }
        RefPlan::Rewrite => (floor_chunk, Vec::new()),
    };
    let cksum_bytes: Vec<u8> = {
        let mut bytes = Vec::with_capacity((covered_end.saturating_sub(array_start) * 4) as usize);
        for c in array_start..covered_end {
            bytes.extend_from_slice(&resolve_crc(inner.crcs(), preloaded, c).to_be_bytes());
        }
        bytes
    };

    // Shadow: the frontier chunk's span, when partial (post-commit
    // appends will write into its block in place; recovery restores
    // the frozen span from the shadow). The shadow bytes come from
    // the tail buffer, whose invariant — it always describes the
    // last BACKED chunk — every mutation path maintains; the model
    // derives the shadow from the captured runs directly, so a
    // desynced tail cache here would durably record a wrong shadow:
    // assert coherence instead of writing one.
    let shadow_bytes = last_backed.and_then(|last| {
        let (_, span) = inner.chunk_span(last).expect("backed chunk");
        (span < BLOCK).then(|| {
            assert_eq!(inner.tail_chunk(), last, "tail buffer desynced from runs");
            assert_eq!(
                inner.tail().len() as u64,
                span,
                "tail span desynced from runs"
            );
            inner.tail().to_vec()
        })
    });

    // The final backed chunk's CRC, recorded whether the chunk is
    // full or partial: hydration verifies the frontier against it
    // without touching the checksum extents.
    let tail_crc = last_backed.map_or(0, |last| resolve_crc(inner.crcs(), preloaded, last));

    let runs: Vec<Run> = inner
        .runs()
        .iter()
        .map(|(&logical, r)| Run {
            logical,
            physical: r.physical,
            len: r.len,
        })
        .collect();

    // Extents the new entry stops referencing, freed once this
    // commit confirms: the previous shadow always (each commit that
    // needs one writes a fresh block), the previous checksum
    // extents only on a full rewrite (a delta commit keeps
    // referencing them).
    let mut superseded: Vec<Extent> = Vec::new();
    superseded.extend(
        inner
            .committed_entry()
            .and_then(|entry| entry.shadow.map(|offset| Extent { offset, len: BLOCK })),
    );
    match plan {
        RefPlan::Delta { .. } => {
            // Extents of refs dropped below the floor supersede even in a
            // delta commit. Retained refs remain owned by the new entry.
            for r in prev_refs {
                if !live_ref(r) {
                    superseded.push(r.extent());
                }
            }
        }
        RefPlan::Rewrite => superseded.extend(prev_refs.iter().map(ChecksumRef::extent)),
    }

    let entry = Entry {
        id,
        partition: 0, // resolved during table assembly
        name: blob.name.clone(),
        version: blob.version,
        size: inner.size(),
        floor: inner.floor(),
        runs,
        checksums, // retained refs (a new delta/full ref is pushed below)
        tail_crc,
        shadow: None, // filled after allocation below
    };

    Captured {
        entry,
        dirty_chunks,
        array_start,
        cksum_bytes,
        shadow_bytes,
        superseded,
    }
}

/// Allocate and stage one captured blob's metadata writes — the new
/// checksum ref (when the capture encoded one), the shadow block, and the
/// delta-manifest entries. Returns the entry, completed with its allocations,
/// for table assembly.
fn stage_meta<S: crate::Storage>(
    ready: &Ready<S>,
    seq: u64,
    captured: Captured,
    writes: &mut Vec<MetaWrite>,
    manifest: &mut Vec<(u64, u64)>,
) -> Result<Entry, Error> {
    let Captured {
        mut entry,
        dirty_chunks,
        array_start,
        cksum_bytes,
        shadow_bytes,
        superseded,
    } = captured;
    let id = entry.id;
    let wrote_checksum_ref = !cksum_bytes.is_empty();
    if wrote_checksum_ref {
        let count = checked_checksum_count(cksum_bytes.len())?;
        let extent = {
            let mut state = ready.state.lock();
            state.allocate(block_align(cksum_bytes.len() as u64))
        };
        entry.checksums.push(ChecksumRef {
            first_chunk: array_start,
            count,
            offset: extent.offset,
            crc: Crc32::checksum(&cksum_bytes),
        });
        writes.push(MetaWrite {
            physical: extent.offset,
            bytes: IoBuf::from(cksum_bytes),
        });
    }
    if let Some(shadow) = shadow_bytes {
        let extent = {
            let mut state = ready.state.lock();
            state.allocate(BLOCK)
        };
        entry.shadow = Some(extent.offset);
        writes.push(MetaWrite {
            physical: extent.offset,
            bytes: IoBuf::from(shadow),
        });
    }
    // A fresh shadow is a metadata write this commit may tear, and
    // recovery's splice is a raw byte copy that cannot tell a torn
    // shadow from a valid one: manifest the frontier chunk so
    // verification checks the shadow's content against `tail_crc`
    // before adoption, even when no dirt touched the frontier (see
    // the model's `manifest_fresh_shadow` rule).
    if entry.shadow.is_some() {
        let frontier = entry
            .runs
            .last()
            .map(|r| chunk_of(r.logical + r.len - 1))
            .expect("shadow requires a backed chunk");
        if dirty_chunks.binary_search(&frontier).is_err() {
            manifest.push((id, frontier));
        }
    }
    for chunk in dirty_chunks {
        manifest.push((id, chunk));
    }
    // Recovery guard-verifies the last checksum ref of every blob named by
    // the manifest. A metadata-only compaction (for example, a sparse grow
    // after reaching the ref cap) writes a fresh ref without changing or
    // shadowing any content chunk. Give that blob a manifest group anyway:
    // the chunk may be a hole, but the group still makes recovery verify the
    // newly referenced extent before adopting the candidate.
    if wrote_checksum_ref && manifest.iter().all(|&(blob, _)| blob != id) {
        manifest.push((id, array_start));
    }
    {
        let mut state = ready.state.lock();
        for extent in superseded {
            state.defer_free(extent, seq);
        }
    }
    Ok(entry)
}

/// Assemble the table — captured blobs re-encode; everything else is
/// served from its cached encoded entry (encoded lazily on first use), so
/// assembly is O(captured + concatenation) — and stage the table and
/// superblock writes (into the NON-sacred slot). Returns the previous
/// confirmed table extent and the new table's.
fn assemble_table<S: crate::Storage>(
    ready: &Ready<S>,
    seq: u64,
    committed: &mut [(Arc<BlobCore>, Entry)],
    manifest: &mut [(u64, u64)],
    writes: &mut Vec<MetaWrite>,
) -> Result<Extent, Error> {
    let mut state = ready.state.lock();
    let (partitions, entries) = state.table_entries(committed);
    manifest.sort_unstable();
    let bytes = Table::assemble(seq, state.next_id(), &partitions, entries, manifest);
    let table_len = checked_table_len(bytes.len())?;
    let extent = state.allocate(block_align(bytes.len() as u64));
    let superblock_offset = state.standby_slot().offset();
    let sb = Superblock {
        seq,
        table_offset: extent.offset,
        table_len,
        table_crc: Crc32::checksum(&bytes),
    };
    writes.push(MetaWrite {
        physical: extent.offset,
        bytes: IoBuf::from(bytes),
    });
    writes.push(MetaWrite {
        physical: superblock_offset,
        bytes: IoBuf::from(sb.encode()),
    });
    Ok(extent)
}

/// Publish a confirmed commit.
fn finalize<S: crate::Storage>(ready: &Ready<S>, durable: DurableCommit) {
    let DurableCommit(prepared) = durable;
    // Swing each captured blob's committed entry BEFORE releasing frees:
    // committed-CRC loads validate their ref against the entry after
    // reading (see `load_committed_page`), so an extent must never become
    // reusable while an entry referencing it is still visible.
    let captured_ids: Vec<u64> = prepared.committed.iter().map(|(blob, _)| blob.id).collect();
    for (blob, entry) in prepared.committed {
        blob.inner.lock().publish_committed(entry);
    }

    let mut state = ready.state.lock();
    let resolved_members = state.confirm(prepared.seq, prepared.table_extent, &prepared.capture);
    state.apply_frees();
    // Captured blobs whose last handle dropped mid-commit could not demote
    // then (their next entry lived only in this snapshot), and clean
    // resolved-group members (for example batch-created blobs whose handle
    // dropped before apply) have no later drop to demote them: demote both
    // now.
    for id in captured_ids.into_iter().chain(resolved_members) {
        state.maybe_demote(id);
    }
    ready.metrics.observe_state(&mut state);
}
