//! Cross-blob write batches: stage now, publish (and commit) atomically.
//!
//! Staging is two-phase and efficiency-first:
//!
//! 1. STAGE: [`Batch::write_at`] / [`Batch::resize`] plan and write through
//!    to the volume file immediately — one inner write per contiguous
//!    stretch with a streaming CRC pass, the identical I/O profile of
//!    unbatched writes. All resulting state (run splices, chunk CRCs, the
//!    staged size and tail) accumulates in the batch's per-blob overlays,
//!    NOT in the blobs' published state: readers, commits, and snapshots
//!    cannot observe staged bytes. Placement follows the batch rule proven
//!    by the model: in place only where no snapshot can capture the bytes
//!    (batch-private extents, or at/beyond BOTH the blob's published size
//!    and its freeze boundary — the shared tail block's committed bytes
//!    stay covered by the shadow mechanism); staged overwrites of any
//!    published byte relocate to fresh extents nothing references yet.
//! 2. PUBLISH: [`Batch::apply`] swings sizes, runs, CRCs, and dirty marks
//!    under the commit lock — pure RAM, O(ops), no I/O — and records the
//!    blobs as one applied-batch group. From then on any commit capturing
//!    one of them captures all of them (never-split), until a commit
//!    resolves the group. [`Batch::apply_sync`] additionally commits the
//!    group immediately.
//!
//! A batch dropped without apply never happened: its bytes live in extents
//! no table references, returned through the ordinary deferred-free path.
//! A crash before apply likewise discards the batch wholesale.
//!
//! # Writer exclusivity
//!
//! While a batch holds staged content for a blob, the batch is that blob's
//! ONE writer: mutating the blob outside the batch before apply rewrites
//! bytes whose staged expected content the overlay already recorded (found
//! by the model). This is the [`crate::Blob`] contract's writer exclusivity
//! applied to the batch as a deferred writer.
//!
//! # Removals and creations
//!
//! [`Batch::remove`] stages namespace removals and [`Batch::create`] stages
//! blob creations. Both land atomically with the publish. Removals require
//! [`Batch::apply_sync`]: a removal published without an immediate commit
//! could be committed by an unrelated sync while the batch's writes stay
//! uncommitted (an entry drop is global, so the never-split group cannot
//! defer it). A creation staged alongside anything else requires
//! [`Batch::apply_sync`] for the symmetric reason: table assembly emits an
//! entry for every live blob, so a published-but-uncommitted creation would
//! be persisted by any unrelated commit without the batch's other members.
//! [`Batch::apply_sync`] publishes and commits under one hold of the commit
//! lock, so no such commit can interleave. A batch staging ONLY creations
//! is exempt and publishes with plain [`Batch::apply`], commit-free: every
//! member is an empty creation, so whatever commit comes next emits all of
//! their entries together — and a crash before any commit erases them
//! together (proven in the model's commit-free carve-out).

use super::{
    alloc::{block_align, Extent},
    commit,
    core::{
        chunk_of, load_committed_page, stage_write, BlobCore, BlobInner, ChunkCrc, ChunkState,
        Ready, RunMeta, StagedBlob, StagedRun,
    },
    unlink, Blob, HandleTracker, Shared, BLOCK,
};
use crate::{Blob as _, Error, Handle, IoBuf, IoBufs, DEFAULT_BLOB_VERSION};
use commonware_cryptography::Crc32;
use commonware_formatting::hex;
use commonware_utils::sync::{AsyncMutex, Mutex};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// One blob's staged state within a batch.
struct Staged {
    core: Arc<BlobCore>,
    overlay: StagedBlob,
    /// Batch-allocated extents no longer referenced by the overlay (staged
    /// shrink): freed at apply, or at drop with the rest.
    discarded: Vec<Extent>,
    /// Whether the blob was staged for membership only ([`Batch::sync`]).
    touched_only: bool,
}

/// A staged blob creation: the namespace entry publishes at apply.
struct Creation {
    partition: String,
    name: Vec<u8>,
    core: Arc<BlobCore>,
}

/// A batch of writes spanning multiple blobs of one volume, staged
/// write-through and published atomically. See the module docs.
pub struct Batch<S: crate::Storage> {
    shared: Arc<Shared<S>>,
    ready: Arc<Ready<S>>,
    staged: BTreeMap<u64, Staged>,
    removals: Vec<(String, Option<Vec<u8>>)>,
    creations: Vec<Creation>,
    applied: bool,
}

impl<S: crate::Storage> Batch<S> {
    pub(super) const fn new(shared: Arc<Shared<S>>, ready: Arc<Ready<S>>) -> Self {
        Self {
            shared,
            ready,
            staged: BTreeMap::new(),
            removals: Vec::new(),
            creations: Vec::new(),
            applied: false,
        }
    }

    /// The staged entry for `blob`, created (at the blob's published size)
    /// on first touch.
    fn staged_mut(&mut self, blob: &Blob<S>) -> &mut Staged {
        self.staged.entry(blob.core.id).or_insert_with(|| {
            let mut inner = blob.core.inner.lock();
            // Gates capture-time run merging until apply or drop: the
            // overlay references base runs by key.
            inner.staged_batches += 1;
            Staged {
                core: blob.core.clone(),
                overlay: StagedBlob::new(inner.size),
                discarded: Vec::new(),
                touched_only: true,
            }
        })
    }

    /// Stage a write of `bufs` at `offset`, writing through to disk.
    pub async fn write_at(
        &mut self,
        blob: &Blob<S>,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        let data = bufs.into().coalesce();
        if data.is_empty() {
            return Ok(());
        }
        let ready = self.ready.clone();
        let core = blob.core.clone();
        let staged = self.staged_mut(blob);
        staged.touched_only = false;
        let _guard = core.write_lock.lock().await;
        stage_write(&ready, &core, &mut staged.overlay, offset, data).await
    }

    /// Stage a resize to `len`.
    pub async fn resize(&mut self, blob: &Blob<S>, len: u64) -> Result<(), Error> {
        self.ready.check_poisoned()?;
        let ready = self.ready.clone();
        let core = blob.core.clone();
        let staged = self.staged_mut(blob);
        staged.touched_only = false;
        let _guard = core.write_lock.lock().await;

        if len >= staged.overlay.size {
            // Zero extension: physically zero the backed portion of the
            // boundary chunk (merged view) through the staged write path;
            // unbacked regions become holes.
            let size = staged.overlay.size;
            let zero_to = {
                let inner = core.inner.lock();
                let boundary = chunk_of(size);
                match staged.overlay.chunk_span(&inner, boundary) {
                    Some(_) if !size.is_multiple_of(BLOCK) => ((boundary + 1) * BLOCK).min(len),
                    _ => size,
                }
            };
            if zero_to > size {
                let zeros = IoBuf::copy_from_slice(&vec![0u8; (zero_to - size) as usize]);
                stage_write(&ready, &core, &mut staged.overlay, size, zeros).await?;
            }
            staged.overlay.size = staged.overlay.size.max(len);
            return Ok(());
        }

        // Staged shrink: trim the overlay so apply publishes the truncated
        // view; base extents dropped from coverage are replaced at apply.
        // Mirrors `core::resize_locked`: the staged tail is refreshed to
        // the post-shrink FRONTIER (the last merged backed chunk, which may
        // sit below hole chunks), and the fallible read-back runs BEFORE
        // any overlay state changes (clean unwind).

        /// How the staged tail is refreshed (see `core::resize_locked`).
        enum Frontier {
            Empty,
            Keep {
                chunk: u64,
                bytes: Vec<u8>,
            },
            Read {
                chunk: u64,
                phys: u64,
                span: u64,
                expected: Option<u32>,
            },
        }

        let mut loaded_crc: Option<(u64, u32)> = None;
        let frontier = loop {
            let outcome = {
                let mut inner = core.inner.lock();
                let overlay = &staged.overlay;
                // The last merged (overlay-over-base) run surviving the
                // shrink.
                let overlay_last = overlay
                    .runs
                    .range(..len)
                    .next_back()
                    .map(|(&l, sr)| (l, sr.meta));
                let base_last = inner
                    .runs
                    .range(..len)
                    .rev()
                    .find(|(l, _)| !overlay.removed.contains(l) && !overlay.runs.contains_key(l))
                    .map(|(&l, r)| (l, *r));
                let last = match (overlay_last, base_last) {
                    (Some(a), Some(b)) => Some(if a.0 >= b.0 { a } else { b }),
                    (a, b) => a.or(b),
                };
                let Some((l, run)) = last else {
                    break Frontier::Empty;
                };
                let post_len = run.len.min(len - l);
                let chunk = chunk_of(l + post_len - 1);
                let chunk_start = chunk * BLOCK;
                let phys = run.physical + (chunk_start - l);
                let span = l + post_len - chunk_start;
                if post_len < run.len {
                    // Trimmed mid-chunk: recompute from an unchecked
                    // read-back.
                    break Frontier::Read {
                        chunk,
                        phys,
                        span,
                        expected: None,
                    };
                }
                // Untrimmed frontier: bytes and CRC are unchanged. Prefer
                // in-memory sources (the staged tail, then — for chunks the
                // batch has not staged over — the published tail or overlay
                // entry), falling back to a verified disk read-back.
                if let Some((tail_chunk, bytes)) = &staged.overlay.tail {
                    if *tail_chunk == chunk && bytes.len() as u64 == span {
                        break Frontier::Keep {
                            chunk,
                            bytes: bytes.clone(),
                        };
                    }
                }
                let staged_crc = staged.overlay.crcs.get(&chunk).copied();
                if staged_crc.is_none() {
                    if inner.tail_chunk == chunk && inner.tail.len() as u64 == span {
                        break Frontier::Keep {
                            chunk,
                            bytes: inner.tail.clone(),
                        };
                    }
                    if let Some(bytes) = inner.overlay_get(chunk) {
                        if bytes.len() as u64 == span {
                            break Frontier::Keep {
                                chunk,
                                bytes: bytes.to_vec(),
                            };
                        }
                    }
                }
                let crc = staged_crc
                    .or_else(|| inner.crcs.get(chunk))
                    .expect("covered chunk has crc")
                    .crc;
                match crc {
                    ChunkCrc::Ready(expected) => {
                        break Frontier::Read {
                            chunk,
                            phys,
                            span,
                            expected: Some(expected),
                        }
                    }
                    // Pending chunks are overlay-resident with a full-span
                    // entry, caught above.
                    ChunkCrc::Pending => unreachable!("pending chunk without overlay entry"),
                    ChunkCrc::Unloaded => {
                        let known = loaded_crc
                            .filter(|&(c, _)| c == chunk)
                            .map(|(_, crc)| crc)
                            .or_else(|| inner.crc_cache.get(chunk));
                        match known {
                            Some(expected) => {
                                break Frontier::Read {
                                    chunk,
                                    phys,
                                    span,
                                    expected: Some(expected),
                                }
                            }
                            None => chunk,
                        }
                    }
                }
            };
            if let Some((first, values)) =
                Box::pin(load_committed_page(&ready, &core, outcome)).await?
            {
                loaded_crc = Some((outcome, values[(outcome - first) as usize]));
            }
        };

        // Perform the read-back (the only fallible step) before mutating
        // the overlay.
        let tail = match frontier {
            Frontier::Empty => None,
            Frontier::Keep { chunk, bytes } => Some((chunk, bytes, None)),
            Frontier::Read {
                chunk,
                phys,
                span,
                expected,
            } => {
                let bytes = ready.file.read_at(phys, span as usize).await?.coalesce();
                if let Some(expected) = expected {
                    // The span is unchanged by the shrink, so its bytes
                    // must still match the chunk's CRC.
                    if Crc32::checksum(bytes.as_ref()) != expected {
                        ready.metrics.corruptions.inc();
                        return Err(Error::BlobCorrupt(
                            core.partition.clone(),
                            hex(&core.name),
                            format!("chunk {chunk} checksum mismatch"),
                        ));
                    }
                }
                let recompute = expected.is_none();
                Some((
                    chunk,
                    bytes.as_ref().to_vec(),
                    recompute.then(|| {
                        // Recomputed from an unchecked read-back: the
                        // frontier chunk stays unverified (see
                        // `ChunkState`).
                        ChunkState {
                            crc: ChunkCrc::Ready(Crc32::checksum(bytes.as_ref())),
                            verified: false,
                        }
                    }),
                ))
            }
        };

        // Publish the staged shrink (pure RAM, infallible).
        {
            let inner = core.inner.lock();
            let overlay = &mut staged.overlay;

            let dropped: Vec<u64> = overlay.runs.range(len..).map(|(&l, _)| l).collect();
            for l in dropped {
                let sr = overlay.runs.remove(&l).expect("listed key");
                let extent = Extent {
                    offset: sr.meta.physical,
                    len: sr.meta.capacity,
                };
                if sr.private {
                    // Batch-allocated: nothing will ever reference it.
                    overlay.fresh.retain(|e| e.offset != extent.offset);
                    staged.discarded.push(extent);
                } else {
                    // The base run underneath drops with the overlay.
                    overlay.removed.insert(l);
                    overlay.replaced.push(extent);
                }
            }
            for (&l, r) in inner.runs.range(len..) {
                if overlay.removed.contains(&l) {
                    continue;
                }
                overlay.removed.insert(l);
                overlay.replaced.push(Extent {
                    offset: r.physical,
                    len: r.capacity,
                });
            }
            // Trim the boundary run in the overlay, splitting off the
            // capacity slack exactly as a published shrink would: every
            // run must keep `capacity == block_align(len)`, or a later
            // staged COW of the boundary chunk orphans the slack
            // (`cow_remap_staged` frees only the chunk's block) and a
            // publish installs a run whose slack no capture records —
            // found by the conformance extent-accounting audit. Private
            // slack is carved out of the batch's fresh extent (freed at
            // apply or drop). Base slack joins the replaced extents,
            // freed only at apply — a dropped batch reclaims nothing the
            // published run still owns.
            if len > 0 {
                if let Some((l, run, private)) = overlay.covering(&inner, len - 1) {
                    if l + run.len > len {
                        let keep_len = len - l;
                        let keep_cap = block_align(keep_len);
                        if run.capacity > keep_cap {
                            let slack = Extent {
                                offset: run.physical + keep_cap,
                                len: run.capacity - keep_cap,
                            };
                            if private {
                                for extent in overlay.fresh.iter_mut() {
                                    if extent.offset == run.physical {
                                        extent.len = keep_cap;
                                    }
                                }
                                staged.discarded.push(slack);
                            } else {
                                overlay.replaced.push(slack);
                            }
                        }
                        overlay.runs.insert(
                            l,
                            StagedRun {
                                meta: RunMeta {
                                    len: keep_len,
                                    capacity: keep_cap,
                                    ..run
                                },
                                private,
                            },
                        );
                    }
                }
            }
            match tail {
                None => {
                    overlay.crcs.clear();
                    overlay.tail = Some((0, Vec::new()));
                }
                Some((chunk, bytes, recomputed)) => {
                    overlay.crcs.retain(|&c, _| c <= chunk);
                    if let Some(state) = recomputed {
                        overlay.crcs.insert(chunk, state);
                    }
                    overlay.tail = Some((chunk, bytes));
                }
            }
            overlay.relocated = true;
            overlay.size = len;
        }
        Ok(())
    }

    /// Include `blob` in the batch's atomic group without staging content:
    /// its (directly written) dirty state commits with the batch.
    pub fn sync(&mut self, blob: &Blob<S>) {
        self.staged_mut(blob);
    }

    /// Stage a namespace removal (a blob, or a whole partition when `name`
    /// is `None`), validated and applied atomically at [`Self::apply_sync`].
    pub fn remove(&mut self, partition: &str, name: Option<&[u8]>) {
        self.removals
            .push((partition.into(), name.map(<[u8]>::to_vec)));
    }

    /// Stage the creation of a NEW (empty) blob, returning a handle to it.
    /// The name is validated at apply, where the namespace entry publishes
    /// atomically with the rest of the batch (and, under
    /// [`Self::apply_sync`], commits with it). Until then the blob is
    /// invisible to opens, scans, and commits, and the returned handle must
    /// not be used. The created blob carries
    /// [`crate::DEFAULT_BLOB_VERSION`]: a versioned reopen must include
    /// that version in its range.
    pub fn create(&mut self, partition: &str, name: &[u8]) -> Result<Blob<S>, Error> {
        super::super::validate_partition_name(partition)?;
        self.ready.check_poisoned()?;
        let (id, core) = {
            let mut state = self.ready.state.lock();
            let id = state.next_id;
            state.next_id += 1;
            // Register the handle count now so the returned handle's tracker
            // works whether or not the batch ever applies.
            *state.handles.entry(id).or_insert(0) += 1;
            let core = Arc::new(BlobCore {
                id,
                partition: partition.into(),
                name: name.to_vec(),
                version: DEFAULT_BLOB_VERSION,
                write_lock: AsyncMutex::new(()),
                inner: Mutex::new(BlobInner {
                    committed_entry: None,
                    ..Default::default()
                }),
            });
            (id, core)
        };
        self.creations.push(Creation {
            partition: partition.into(),
            name: name.to_vec(),
            core: core.clone(),
        });
        Ok(Blob {
            ready: self.ready.clone(),
            core,
            _tracker: Arc::new(HandleTracker {
                ready: self.ready.clone(),
                id,
            }),
        })
    }

    /// Publish the staged state: pure RAM, under the commit lock, O(ops).
    /// The touched blobs form one applied-batch group that later commits
    /// capture all-or-nothing. A crash before the group commits discards
    /// the batch wholesale.
    ///
    /// A batch staging ONLY creations publishes commit-free: the next
    /// commit — whichever blob roots it — emits every created blob's
    /// entry, so the creations become durable together, and a crash before
    /// any commit erases them together.
    ///
    /// # Panics
    ///
    /// Panics if removals were staged, or if creations were staged
    /// alongside any other operation (both require [`Self::apply_sync`]).
    pub async fn apply(mut self) -> Result<(), Error> {
        self.assert_publishable();
        let handle = self.apply_inner(ApplyMode::Publish).await?;
        debug_assert!(handle.is_none(), "publish returns no handle");
        Ok(())
    }

    /// [`Self::apply`] plus an immediate commit of the batch's group (one
    /// selective commit covering exactly the touched blobs and removals).
    pub async fn apply_sync(mut self) -> Result<(), Error> {
        let handle = self.apply_inner(ApplyMode::Commit).await?;
        debug_assert!(handle.is_none(), "a blocking commit returns no handle");
        Ok(())
    }

    /// [`Self::apply`] plus a STARTED commit of the batch's group: the
    /// staged state publishes before this returns (the batch's root is
    /// readable), and the returned [`Handle`] resolves once a commit
    /// covering the group lands — a later sync's coalesced union, or the
    /// commit the handle itself lead-drives when awaited (see
    /// `commit::drive`). The handle must be observed: a commit failure is
    /// reported only through it (and permanently poisons the volume), and
    /// awaiting it is what guarantees a commit runs without depending on
    /// unrelated traffic. A polled handle must then be driven to
    /// completion or dropped — parked it can hold the commit lock, and
    /// dropped mid-commit it poisons the volume (see
    /// `commit::CancelGuard`). A crash before a covering commit discards
    /// the published batch wholesale, exactly like a batch published with
    /// [`Self::apply`].
    ///
    /// # Panics
    ///
    /// Panics if removals were staged, or if creations were staged
    /// alongside any other operation (both require [`Self::apply_sync`]:
    /// entry drops and creations land globally with ANY commit, so an
    /// unrelated commit interleaving before the group's own commit would
    /// split the batch).
    pub async fn apply_start_sync(mut self) -> Result<Handle<()>, Error> {
        self.assert_publishable();
        let handle = self.apply_inner(ApplyMode::StartCommit).await?;
        Ok(handle.expect("a started commit returns its handle"))
    }

    /// Assert the constraints shared by the publish-without-immediate-commit
    /// paths ([`Self::apply`] and [`Self::apply_start_sync`]).
    fn assert_publishable(&self) {
        assert!(
            self.removals.is_empty(),
            "staged removals require apply_sync"
        );
        assert!(
            self.creations.is_empty() || self.staged.is_empty(),
            "creations staged alongside writes require apply_sync"
        );
    }

    async fn apply_inner(&mut self, mode: ApplyMode) -> Result<Option<Handle<()>>, Error> {
        self.ready.check_poisoned()?;
        // Namespace changes serialize on the same lock (and in the same
        // order relative to the commit lock) as open/remove.
        let _ns = if self.removals.is_empty() && self.creations.is_empty() {
            None
        } else {
            Some(self.shared.ns_lock.lock().await)
        };
        let _commit = self.ready.commit_lock.lock().await;
        self.ready.check_poisoned()?;

        // Validate every staged removal and creation against a simulation of
        // the namespace BEFORE publishing anything: an invalid batch applies
        // nothing (Drop returns its extents). Removals simulate first, so a
        // batch may remove a name and recreate it.
        if !self.removals.is_empty() || !self.creations.is_empty() {
            let state = self.ready.state.lock();
            let mut sim: BTreeMap<&String, BTreeSet<&Vec<u8>>> = state
                .partitions
                .iter()
                .map(|(partition, blobs)| (partition, blobs.keys().collect()))
                .collect();
            for (partition, name) in &self.removals {
                match name {
                    Some(name) => {
                        let blobs = sim
                            .get_mut(partition)
                            .ok_or_else(|| Error::PartitionMissing(partition.clone()))?;
                        if !blobs.remove(name) {
                            return Err(Error::BlobMissing(partition.clone(), hex(name)));
                        }
                    }
                    None => {
                        sim.remove(partition)
                            .ok_or_else(|| Error::PartitionMissing(partition.clone()))?;
                    }
                }
            }
            for creation in &self.creations {
                if !sim
                    .entry(&creation.partition)
                    .or_default()
                    .insert(&creation.name)
                {
                    return Err(Error::BlobExists(
                        creation.partition.clone(),
                        hex(&creation.name),
                    ));
                }
            }
        }

        // Publish staged creations first (their namespace entries must exist
        // before any staged overlay against them publishes), then each
        // blob's overlay (blob-id order; the commit lock keeps any snapshot
        // from observing a partial publish).
        //
        // The publish (and, for apply_sync, its commit) is one cancellation
        // domain: the per-blob loop awaits write locks, so the caller's
        // future can be dropped with the batch half-published — group and
        // dirty bookkeeping unrecorded, staged-batch counters leaked, and
        // the staged extents neither referenced nor reclaimable. A `Drop`
        // impl cannot finish or unwind the publish, so cancellation poisons
        // (found by the conformance cancellation injector).
        let guard = commit::PoisonOnCancel::arm(&self.ready);
        let staged = std::mem::take(&mut self.staged);
        let mut roots: Vec<u64> = Vec::with_capacity(self.creations.len() + staged.len());
        if !self.creations.is_empty() {
            let mut state = self.ready.state.lock();
            for creation in std::mem::take(&mut self.creations) {
                let id = creation.core.id;
                if !state.partitions.contains_key(&creation.partition) {
                    state.partition_epoch += 1;
                }
                state
                    .partitions
                    .entry(creation.partition)
                    .or_default()
                    .insert(creation.name, id);
                state.open.insert(id, creation.core);
                state.meta_dirty = true;
                roots.push(id);
            }
        }
        for (id, st) in staged {
            roots.push(id);
            let _guard = st.core.write_lock.lock().await;
            let mut state = self.ready.state.lock();
            let seq = state.seq;
            for extent in st.discarded {
                state.defer_free(extent, seq, None);
            }
            let mut inner = st.core.inner.lock();
            inner.staged_batches -= 1;
            if !st.touched_only {
                publish_overlay(&mut inner, st.overlay);
                state.dirty.insert(id);
            }
        }
        {
            let mut state = self.ready.state.lock();
            state.merge_group(roots.iter().copied());
        }
        self.applied = true;

        // Namespace removals (validated above; cannot fail).
        if !self.removals.is_empty() {
            let mut state = self.ready.state.lock();
            for (partition, name) in std::mem::take(&mut self.removals) {
                let blobs = state.partitions.get(&partition).expect("validated");
                let ids: Vec<u64> = name.as_ref().map_or_else(
                    || blobs.values().copied().collect(),
                    |name| vec![*blobs.get(name).expect("validated")],
                );
                for &id in &ids {
                    unlink(&mut state, id);
                }
                roots.extend(ids);
                match name {
                    Some(name) => {
                        state
                            .partitions
                            .get_mut(&partition)
                            .expect("validated")
                            .remove(&name);
                    }
                    None => {
                        state.partitions.remove(&partition);
                        state.partition_epoch += 1;
                    }
                }
                state.meta_dirty = true;
            }
        }

        match mode {
            ApplyMode::Publish => {
                guard.disarm();
                Ok(None)
            }
            ApplyMode::Commit => {
                let result = commit::commit_locked(&self.ready, &roots).await;
                // A failed commit latched its own poison, and a
                // cancelled one fires the commit's inner guard.
                guard.disarm();
                result.map(|()| None)
            }
            ApplyMode::StartCommit => {
                // Register while still holding the commit lock: the next
                // leader to drain the pool (or the handle itself, whichever
                // acquires the lock first) covers the group's roots.
                let ticket = commit::register(&self.ready, &roots);
                let ready = self.ready.clone();
                guard.disarm();
                Ok(Some(Handle::from_future(async move {
                    commit::drive(&ready, ticket).await
                })))
            }
        }
    }
}

/// How [`Batch::apply_inner`] resolves the published group's durability.
enum ApplyMode {
    /// Publish only: durability comes from whatever commit next captures a
    /// group member.
    Publish,
    /// Publish and commit the group under the same hold of the commit lock.
    Commit,
    /// Publish and register the group in the pending-commit pool, returning
    /// a handle that lead-drives (or observes) the covering commit.
    StartCommit,
}

/// Swing a blob's published state to the staged overlay. Caller holds the
/// commit lock, the blob's write lock, and the blob's state lock.
fn publish_overlay(inner: &mut BlobInner, overlay: StagedBlob) {
    if overlay.size < inner.size {
        // Staged shrink: mirror the published resize bookkeeping.
        if overlay.size == 0 {
            inner.crcs.clear();
            inner.dirty_chunks.clear();
        } else {
            let boundary = chunk_of(overlay.size - 1);
            inner.crcs.truncate(boundary);
            inner.dirty_chunks.retain(|&c| c <= boundary);
            inner.dirty_chunks.insert(boundary);
        }
    }
    for l in &overlay.removed {
        inner.runs.remove(l);
    }
    for (l, sr) in overlay.runs {
        inner.runs.insert(l, sr.meta);
    }
    for (&chunk, &state) in &overlay.crcs {
        inner.crcs.insert(chunk, state);
        inner.dirty_chunks.insert(chunk);
    }
    inner.size = overlay.size;
    if let Some((chunk, bytes)) = overlay.tail {
        inner.tail_chunk = chunk;
        inner.tail = bytes;
    }
    if overlay.relocated {
        inner.generation += 1;
    }
    inner.pending_frees.extend(overlay.replaced);

    // Staged state supersedes the blob's overlay bytes for every chunk it
    // touched (and a staged shrink may have moved spans): keep only entries
    // that still back a pending CRC.
    let BlobInner {
        crcs,
        overlay: blob_overlay,
        ..
    } = inner;
    blob_overlay.retain(|&chunk, _| crcs.get(chunk).is_some_and(|s| s.crc == ChunkCrc::Pending));
}

impl<S: crate::Storage> Drop for Batch<S> {
    fn drop(&mut self) {
        if self.applied {
            return;
        }
        // Dropped without apply: nothing references the staged extents;
        // return them through the ordinary deferred-free path.
        let mut state = self.ready.state.lock();
        let seq = state.seq;
        for st in self.staged.values_mut() {
            st.core.inner.lock().staged_batches -= 1;
            for extent in st.overlay.fresh.drain(..) {
                state.defer_free(extent, seq, None);
            }
            for extent in st.discarded.drain(..) {
                state.defer_free(extent, seq, None);
            }
        }
    }
}
