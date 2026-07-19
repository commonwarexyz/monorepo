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
    chunk::{chunk_of, ChunkCrc, ChunkState, RunMeta},
    commit,
    paging::load_committed_page,
    state::{
        chunk_mismatch, BlobCore, BlobInner, HandleTracker, Ready, Shared, StagedBlob, StagedRun,
    },
    write::stage_write,
    Blob, BLOCK,
};
use crate::{Blob as _, Error, Handle, IoBufs, DEFAULT_BLOB_VERSION};
use commonware_cryptography::Crc32;
use commonware_formatting::hex;
use commonware_utils::{
    channel::oneshot,
    sync::{AsyncMutex, Mutex},
};
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
        // Caller contract: the blob belongs to this batch's volume. Blob
        // ids are per-volume counters, so a foreign blob would silently
        // cross-wire two volumes' allocator, file, and group state.
        assert!(
            Arc::ptr_eq(&self.ready, &blob.ready),
            "blob belongs to a different volume"
        );
        self.staged.entry(blob.core.id).or_insert_with(|| {
            let mut inner = blob.core.inner.lock();
            // Gates capture-time run merging until apply or drop: the
            // overlay references base runs by key.
            inner.stage_batch();
            Staged {
                core: blob.core.clone(),
                overlay: StagedBlob::new(inner.size()),
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
        let _guard = core.write_lock.lock().await;
        if staged.touched_only {
            staged.touched_only = false;
            // A membership-only touch snapshots a base the blob may have
            // legally outgrown through direct writes: staging begins NOW,
            // against the blob's current size.
            staged.overlay.rebase(core.inner.lock().size());
        }
        stage_write(&ready, &core, &mut staged.overlay, offset, data).await
    }

    /// Stage a resize to `len`.
    pub async fn resize(&mut self, blob: &Blob<S>, len: u64) -> Result<(), Error> {
        self.ready.check_poisoned()?;
        // Chunk-end representability, as in `write::write_locked`.
        if len > u64::MAX - BLOCK {
            return Err(Error::OffsetOverflow);
        }
        let ready = self.ready.clone();
        let core = blob.core.clone();
        let staged = self.staged_mut(blob);
        let _guard = core.write_lock.lock().await;
        if staged.touched_only {
            staged.touched_only = false;
            // Staging begins now, against the blob's current size (see
            // [`Self::write_at`]).
            staged.overlay.rebase(core.inner.lock().size());
        }

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
                let zeros = ready.pool.alloc_zeroed((zero_to - size) as usize).freeze();
                stage_write(&ready, &core, &mut staged.overlay, size, zeros).await?;
            }
            staged.overlay.size = staged.overlay.size.max(len);
            return Ok(());
        }

        // Staged shrink: trim the overlay so apply publishes the truncated
        // view; base extents dropped from coverage are replaced at apply.
        // Mirrors `resize::resize_locked`: the staged tail is refreshed to
        // the post-shrink FRONTIER (the last merged backed chunk, which may
        // sit below hole chunks), and the fallible read-back runs BEFORE
        // any overlay state changes (clean unwind).

        /// How the staged tail is refreshed (see `resize::resize_locked`).
        enum Frontier {
            Empty,
            /// An in-memory copy holds the frontier chunk's span,
            /// unchanged by the shrink: keep it.
            Keep {
                chunk: u64,
                bytes: Vec<u8>,
            },
            /// An in-memory copy holds the chunk's full current span and
            /// the shrink trims it mid-chunk: slice the surviving prefix
            /// and recompute its CRC (no I/O, no re-check).
            Trim {
                chunk: u64,
                bytes: Vec<u8>,
                verified: bool,
            },
            /// Read the chunk's current span (`old_span`) back from disk
            /// and check it against `expected` before slicing the
            /// surviving prefix (see `resize::resize_locked`'s Read arm).
            Read {
                chunk: u64,
                phys: u64,
                span: u64,
                old_span: u64,
                expected: u32,
                verified: bool,
                resident: bool,
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
                    .runs()
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
                let old_span = (l + run.len - chunk_start).min(BLOCK);
                let trimmed = span < old_span;

                // The merged CRC state (a Trim's provenance, the Read
                // arms' expected value).
                let staged_crc = overlay.crcs.get(&chunk).copied();
                let state = staged_crc.or_else(|| inner.crcs().get(chunk));

                // In-memory sources first: a copy of the chunk's full
                // current span needs no read and no re-check. The staged
                // tail wins; published sources serve only chunks the
                // batch has not staged over.
                let mem = overlay
                    .tail
                    .as_ref()
                    .filter(|(tail_chunk, bytes)| {
                        *tail_chunk == chunk && bytes.len() as u64 == old_span
                    })
                    .map(|(_, bytes)| bytes.clone())
                    .or_else(|| {
                        if staged_crc.is_some() {
                            return None;
                        }
                        if inner.tail_chunk() == chunk && inner.tail().len() as u64 == old_span {
                            return Some(inner.tail().to_vec());
                        }
                        inner
                            .overlay_get(chunk)
                            .filter(|bytes| bytes.len() as u64 == old_span)
                            .map(<[u8]>::to_vec)
                    });
                if let Some(bytes) = mem {
                    if !trimmed {
                        break Frontier::Keep { chunk, bytes };
                    }
                    let verified = state.expect("covered chunk has crc").verified;
                    break Frontier::Trim {
                        chunk,
                        bytes: bytes[..span as usize].to_vec(),
                        verified,
                    };
                }
                let state = state.expect("covered chunk has crc");
                match state.crc {
                    ChunkCrc::Ready(expected) => {
                        break Frontier::Read {
                            chunk,
                            phys,
                            span,
                            old_span,
                            expected,
                            verified: state.verified,
                            resident: true,
                        }
                    }
                    // Pending chunks are overlay-resident with a full-span
                    // entry, caught above.
                    ChunkCrc::Pending => unreachable!("pending chunk without overlay entry"),
                    // Untouched since hydration: the expected CRC is the
                    // committed value — the authoritative one, so checking
                    // the read-back against it IS the chunk's
                    // verification.
                    ChunkCrc::Unloaded => {
                        let known = loaded_crc
                            .filter(|&(c, _)| c == chunk)
                            .map(|(_, crc)| crc)
                            .or_else(|| inner.crc_cache_mut().get(chunk));
                        match known {
                            Some(expected) => {
                                break Frontier::Read {
                                    chunk,
                                    phys,
                                    span,
                                    old_span,
                                    expected,
                                    verified: true,
                                    resident: false,
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
            Frontier::Trim {
                chunk,
                bytes,
                verified,
            } => {
                let state = ChunkState {
                    crc: ChunkCrc::Ready(Crc32::checksum(&bytes)),
                    verified,
                };
                Some((chunk, bytes, Some(state)))
            }
            Frontier::Read {
                chunk,
                phys,
                span,
                old_span,
                expected,
                verified,
                resident,
            } => {
                let read = ready
                    .file
                    .read_at(phys, old_span as usize)
                    .await?
                    .coalesce();
                // The chunk's current span must match its expected CRC:
                // rot in it surfaces loudly here, never laundered under
                // the recomputed prefix CRC.
                if Crc32::checksum(read.as_ref()) != expected {
                    return Err(chunk_mismatch(&ready, &core, chunk));
                }
                let bytes = read.as_ref()[..span as usize].to_vec();
                let trimmed = span < old_span;
                // (Re)install the frontier state when the span changed or
                // the checked value was never resident (see
                // `resize::resize_locked`).
                let state = (trimmed || !resident).then(|| ChunkState {
                    crc: ChunkCrc::Ready(if trimmed {
                        Crc32::checksum(&bytes)
                    } else {
                        expected
                    }),
                    verified,
                });
                Some((chunk, bytes, state))
            }
        };

        // Publish the staged shrink (pure RAM, infallible).
        {
            let inner = core.inner.lock();
            let overlay = &mut staged.overlay;

            let dropped: Vec<u64> = overlay.runs.range(len..).map(|(&l, _)| l).collect();
            for l in dropped {
                let sr = overlay.runs.remove(&l).expect("listed key");
                let extent = sr.meta.extent();
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
            for (&l, r) in inner.runs().range(len..) {
                if overlay.removed.contains(&l) {
                    continue;
                }
                overlay.removed.insert(l);
                overlay.replaced.push(r.extent());
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
                Some((chunk, bytes, refreshed)) => {
                    overlay.crcs.retain(|&c, _| c <= chunk);
                    if let Some(state) = refreshed {
                        overlay.crcs.insert(chunk, state);
                    }
                    overlay.tail = Some((chunk, bytes));
                }
            }
            overlay.relocated = true;
            overlay.size = len;
            overlay.min_size = overlay.min_size.min(len);
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
            let id = state.reserve_blob_id();
            // Register the handle count now so the returned handle's tracker
            // works whether or not the batch ever applies.
            state.count_handle(id);
            let core = Arc::new(BlobCore {
                id,
                partition: partition.into(),
                name: name.to_vec(),
                version: DEFAULT_BLOB_VERSION,
                write_lock: AsyncMutex::new(()),
                inner: Mutex::new(BlobInner::default()),
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
    /// readable), and the group's commit is scheduled on the runtime's
    /// driver immediately — it lands on its own (or coalesced into an
    /// earlier pooled commit), never depending on the returned [`Handle`].
    /// The handle only OBSERVES that commit's result: a failure is
    /// reported through it (and permanently poisons the volume, so even
    /// an unobserved handle cannot hide one), and dropping or parking it
    /// is always benign. A crash before the commit lands discards the
    /// published batch wholesale, exactly like a batch published with
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
        // The publish (and, per `mode`, its commit) runs in a driver task
        // that owns the staged state — including the cleanup when
        // validation fails — so the caller only observes: dropping this
        // future mid-await leaves the task to complete the apply, never a
        // half-published batch.
        let shared = self.shared.clone();
        let ready = self.ready.clone();
        let staged = std::mem::take(&mut self.staged);
        let removals = std::mem::take(&mut self.removals);
        let creations = std::mem::take(&mut self.creations);
        self.applied = true;
        let (tx, rx) = oneshot::channel();
        let driver = ready.driver.clone();
        driver.spawn(async move {
            let _ = tx.send(apply_task(shared, ready, staged, removals, creations, mode).await);
        });
        rx.await.unwrap_or(Err(Error::Aborted))?.map_or_else(
            || Ok(None),
            |ticket| {
                Ok(Some(Handle::from_future(
                    async move { ticket.wait().await },
                )))
            },
        )
    }
}

/// The apply body, run inside a driver task: validate, publish, and (per
/// `mode`) commit or register the group's commit, under one hold of the
/// commit lock. Owns the staged state: a validation (or poison) failure
/// discards it exactly as an unapplied drop would.
async fn apply_task<S: crate::Storage>(
    shared: Arc<Shared<S>>,
    ready: Arc<Ready<S>>,
    staged: BTreeMap<u64, Staged>,
    removals: Vec<(String, Option<Vec<u8>>)>,
    creations: Vec<Creation>,
    mode: ApplyMode,
) -> Result<Option<commit::Ticket>, Error> {
    // Namespace changes serialize on the same lock (and in the same
    // order relative to the commit lock) as open/remove.
    let _ns = if removals.is_empty() && creations.is_empty() {
        None
    } else {
        Some(shared.ns_lock.lock().await)
    };
    let _commit = ready.commit_lock.lock().await;
    if let Err(e) = ready.check_poisoned() {
        discard_staged(&ready, staged);
        return Err(e);
    }

    // Validate every staged removal and creation against a simulation of
    // the namespace BEFORE publishing anything: an invalid batch applies
    // nothing (its staged extents return through the drop path). Removals
    // simulate first, so a batch may remove a name and recreate it.
    let validated = (|| {
        if removals.is_empty() && creations.is_empty() {
            return Ok(());
        }
        let state = ready.state.lock();
        let mut sim: BTreeMap<&String, BTreeSet<&Vec<u8>>> = state
            .partitions()
            .iter()
            .map(|(partition, blobs)| (partition, blobs.keys().collect()))
            .collect();
        for (partition, name) in &removals {
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
        for creation in &creations {
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
        Ok(())
    })();
    if let Err(e) = validated {
        discard_staged(&ready, staged);
        return Err(e);
    }

    // Publish in the simulation's order: removals first (resolving
    // names against the SAME pre-publish namespace the validation
    // checked — a creation may rebind a removed name, and the removal
    // must never unlink the recreated blob), then staged creations
    // (their namespace entries must exist before any staged overlay
    // against them publishes), then each blob's overlay (blob-id
    // order; the commit lock keeps any snapshot from observing a
    // partial publish).
    //
    // The publish (and, per `mode`, its commit) is one mutation span this
    // task must complete: once it consumes state, an abort (runtime
    // shutdown dropping this task mid-flight) can neither finish nor
    // unwind it, so the guard poisons on the way down.
    let guard = commit::PoisonOnCancel::arm(&ready);
    let mut removed: Vec<u64> = Vec::new();
    if !removals.is_empty() {
        let mut state = ready.state.lock();
        for (partition, name) in removals {
            let ids = state
                .remove_named(&partition, name.as_deref())
                .expect("validated");
            removed.extend(ids);
        }
    }
    let mut roots: Vec<u64> = Vec::with_capacity(creations.len() + staged.len());
    if !creations.is_empty() {
        let mut state = ready.state.lock();
        for creation in creations {
            let id = creation.core.id;
            state.publish_named(&creation.partition, creation.name, creation.core);
            roots.push(id);
        }
    }
    for (id, st) in staged {
        let _guard = st.core.write_lock.lock().await;
        let mut state = ready.state.lock();
        let seq = state.seq();
        for extent in st.discarded {
            state.defer_free(extent, seq, None);
        }
        let mut inner = st.core.inner.lock();
        inner.unstage_batch();
        // Removed mid-batch (a removal staged in THIS batch, or an
        // outside removal): the overlay must not publish into a dead
        // blob. Its fresh extents are unreferenced — the drop path's
        // treatment — and the base extents it replaced were already
        // freed by the unlink.
        if inner.removed() {
            for extent in st.overlay.fresh {
                state.defer_free(extent, seq, None);
            }
            continue;
        }
        roots.push(id);
        if !st.touched_only {
            publish_overlay(&mut inner, st.overlay);
            state.mark_dirty(id);
        }
    }
    {
        let mut state = ready.state.lock();
        state.merge_group(roots.iter().copied());
    }

    // Removed ids root the commit (never captured — every commit drops
    // their entries — but their applied-batch groups must land with the
    // removal), exactly as `Storage::remove` roots its own commit.
    roots.extend(removed);

    match mode {
        ApplyMode::Publish => {
            guard.disarm();
            Ok(None)
        }
        ApplyMode::Commit => {
            // One durability request served by the commit below (see
            // `metrics::Metrics::sync_requests`).
            ready.metrics.sync_requests.inc();
            let result = commit::commit_locked(&ready, &roots).await;
            // A failed commit latched its own poison, and an aborted
            // one fires the commit's inner guard.
            guard.disarm();
            result.map(|()| None)
        }
        ApplyMode::StartCommit => {
            // Register while still holding the commit lock (an unrelated
            // commit must not interleave between the publish and the
            // group's registration) and schedule its driver task: the
            // commit begins now, and the returned ticket only observes.
            let ticket = commit::register(&ready, &roots);
            commit::spawn_drive(&ready, ticket.clone());
            guard.disarm();
            Ok(Some(ticket))
        }
    }
}

/// Return an unapplied batch's staged extents through the deferred-free
/// path and release its run-merge gates: the drop path, also taken when
/// the apply task fails validation (the task owns the staged state).
fn discard_staged<S: crate::Storage>(ready: &Ready<S>, staged: BTreeMap<u64, Staged>) {
    let mut state = ready.state.lock();
    let seq = state.seq();
    for st in staged.into_values() {
        st.core.inner.lock().unstage_batch();
        for extent in st.overlay.fresh {
            state.defer_free(extent, seq, None);
        }
        for extent in st.discarded {
            state.defer_free(extent, seq, None);
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
    /// Publish and register the group in the pending-commit pool,
    /// scheduling its driver task and returning a handle that observes the
    /// covering commit.
    StartCommit,
}

/// Swing a blob's published state to the staged overlay. Caller holds the
/// commit lock, the blob's write lock, and the blob's state lock.
fn publish_overlay(inner: &mut BlobInner, overlay: StagedBlob) {
    if overlay.min_size < inner.size() {
        // Staged shrink: mirror the published resize bookkeeping, at the
        // DEEPEST staged size. A shrink drops base coverage that a later
        // staged regrow does not restore, so truncating at the final size
        // would keep vacated chunk states alive past their runs; the
        // regrown coverage's states reinstall from the overlay below.
        if overlay.min_size == 0 {
            inner.crcs_mut().clear();
            inner.retain_dirty_chunks(|_| false);
        } else {
            let boundary = chunk_of(overlay.min_size - 1);
            inner.crcs_mut().truncate(boundary);
            inner.retain_dirty_chunks(|&c| c <= boundary);
            inner.mark_chunk_dirty(boundary);
        }
    }
    for l in &overlay.removed {
        inner.remove_run(*l);
    }
    for (l, sr) in overlay.runs {
        inner.install_run(l, sr.meta);
    }
    for (&chunk, &state) in &overlay.crcs {
        inner.crcs_mut().insert(chunk, state);
        inner.mark_chunk_dirty(chunk);
    }
    inner.set_size(overlay.size);
    if let Some((chunk, bytes)) = overlay.tail {
        inner.set_tail(chunk, bytes);
    }
    if overlay.relocated {
        inner.bump_generation();
    }
    for extent in overlay.replaced {
        inner.defer_content_free(extent);
    }

    // Staged state supersedes the blob's overlay bytes for every chunk it
    // touched (and a staged shrink may have moved spans).
    inner.prune_overlay();
}

impl<S: crate::Storage> Drop for Batch<S> {
    fn drop(&mut self) {
        if self.applied {
            return;
        }
        // Dropped without apply: nothing references the staged extents.
        discard_staged(&self.ready, std::mem::take(&mut self.staged));
    }
}
