//! The write path: plan a stretch, write it through, publish its state.
//!
//! Write placement follows the freeze rule (see the module docs): bytes
//! covered by the last confirmed table or the in-flight snapshot are never
//! rewritten in place — writes touching them relocate the chunk
//! (copy-on-write). Chunks whose backing extent was allocated after the
//! last snapshot are exempt (invisible to every durable table), as are
//! bytes at or beyond the freeze boundary (appends into the shared tail
//! chunk; the shadow block covers its frozen prefix against tearing).
//!
//! Every mutation runs under the blob's `write_lock` (see `state`). A
//! batch stages the same plans into a [`StagedBlob`] overlay instead of
//! publishing them ([`stage_write`]), so plan and publish are shared and
//! the staged/base split happens only at the edges.

use super::{
    alloc::{block_align, Extent},
    chunk::{chunk_of, ChunkCrc, ChunkState, RunMeta},
    paging::load_committed_page,
    state::{
        check_not_removed, chunk_mismatch, ensure_provisioned, zeroed, BlobCore, BlobInner, Ready,
        StagedBlob, StagedRun,
    },
    BLOCK,
};
use crate::{Blob as _, Error, IoBuf, IoBufs};
use bytes::BufMut as _;
use commonware_cryptography::{Crc32, Hasher as _};

/// One chunk's checksum outcome for a planned stretch.
enum CrcUpdate {
    /// Computed eagerly (with its verified-by-construction bit). Publish
    /// drops any overlay entry for the chunk (its bytes were rewritten
    /// without an overlay refresh).
    Ready(ChunkState),
    /// Deferred: `bytes` becomes (or refreshes) the chunk's overlay entry —
    /// the authoritative span — and the CRC is finalized later. `verified`
    /// is the bit the finalized chunk will carry. Base mode only.
    Pending { bytes: Vec<u8>, verified: bool },
    /// Overlay fast path: splice `data` at span offset `at` into the
    /// chunk's resident entry and mark its CRC pending (the chunk's
    /// verified bit is unchanged: the splice is written through, and the
    /// rest of the span keeps its provenance). Base mode only.
    Splice { at: usize, data: IoBuf },
}

/// One planned stretch: a single inner write plus its state updates,
/// published only after the write completes (a failed write publishes
/// nothing; its bytes land in space no table references).
struct Stretch {
    /// First logical byte NOT covered by this stretch.
    end: u64,
    /// Physical write position.
    physical: u64,
    /// Write payload, issued verbatim at `physical`: the caller's slice(s)
    /// passed zero-copy, plus any pool-allocated zero-fill or COW assembly.
    bytes: IoBufs,
    /// Run insert/replace: (logical start, run).
    run: (u64, RunMeta),
    /// Chunk checksum updates, ascending by chunk.
    crcs: Vec<(u64, CrcUpdate)>,
    /// Bytes of the final affected chunk's written span (chunk, span bytes),
    /// used to refresh the tail buffer when this stretch reaches the blob's
    /// write frontier. `None` only for an overlay fast-path stretch, whose
    /// span is derived from the spliced overlay entry at publish.
    last_span: Option<(u64, Vec<u8>)>,
    /// COW: the replaced chunk's block to defer-free (+ generation bump).
    replaced: Option<Extent>,
    /// Extent allocated for this stretch (Fresh/COW), for staged-overlay
    /// bookkeeping. Unused by the publish path (the run records it).
    allocated: Option<Extent>,
    /// Staged mode: whether the written extent is batch-private.
    private: bool,
}

/// Write `data` at `offset`. The blob's `write_lock` MUST be held.
pub(super) async fn write_locked<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    offset: u64,
    data: IoBuf,
) -> Result<(), Error> {
    ready.check_poisoned()?;
    check_not_removed(blob)?;
    if data.is_empty() {
        return Ok(());
    }
    // The per-chunk planning below computes chunk-end offsets
    // ((chunk + 1) * BLOCK): keep the last touched chunk's end
    // representable.
    let end = offset
        .checked_add(data.len() as u64)
        .filter(|&end| end <= u64::MAX - BLOCK)
        .ok_or(Error::OffsetOverflow)?;

    let mut cursor = offset;
    while cursor < end {
        let stretch = plan_stretch(ready, blob, None, cursor, end, &data, offset).await?;
        if stretch.replaced.is_some() {
            ready.metrics.cow_bytes.inc_by(stretch.bytes.len() as u64);
        }
        let provisioned =
            ensure_provisioned(ready, stretch.physical + stretch.bytes.len() as u64).await;
        let written = match provisioned {
            Ok(()) => {
                ready
                    .file
                    .write_at(stretch.physical, stretch.bytes.clone())
                    .await
            }
            Err(e) => Err(e),
        };
        if let Err(e) = written {
            // The unpublished stretch's fresh extent would otherwise strand
            // until restart: return it through the deferred-free path.
            free_unpublished(ready, stretch.allocated);
            return Err(e);
        }
        cursor = stretch.end;
        publish_stretch(ready, blob, stretch);
    }

    // Publish the size extension once all stretches landed (unless a
    // removal raced the write, see `publish_stretch`).
    let mut state = ready.state.lock();
    let mut inner = blob.inner.lock();
    if !inner.removed {
        if end > inner.size {
            inner.size = end;
        }
        state.dirty.insert(blob.id);
    }
    Ok(())
}

/// Stage `data` at `offset` into a batch overlay: the same planning and
/// write-through as [`write_locked`], but every state change accumulates in
/// `staged` instead of the blob's published state. The blob's `write_lock`
/// MUST be held.
pub(super) async fn stage_write<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: &mut StagedBlob,
    offset: u64,
    data: IoBuf,
) -> Result<(), Error> {
    ready.check_poisoned()?;
    check_not_removed(blob)?;
    if data.is_empty() {
        return Ok(());
    }
    // Chunk-end representability, as in `write_locked`.
    let end = offset
        .checked_add(data.len() as u64)
        .filter(|&end| end <= u64::MAX - BLOCK)
        .ok_or(Error::OffsetOverflow)?;

    let mut cursor = offset;
    while cursor < end {
        let stretch = plan_stretch(ready, blob, Some(staged), cursor, end, &data, offset).await?;
        if stretch.replaced.is_some() {
            ready.metrics.cow_bytes.inc_by(stretch.bytes.len() as u64);
        }
        let provisioned =
            ensure_provisioned(ready, stretch.physical + stretch.bytes.len() as u64).await;
        let written = match provisioned {
            Ok(()) => {
                ready
                    .file
                    .write_at(stretch.physical, stretch.bytes.clone())
                    .await
            }
            Err(e) => Err(e),
        };
        if let Err(e) = written {
            // Not yet recorded in the staged overlay, so the batch's drop
            // path cannot reclaim it either: free it here.
            free_unpublished(ready, stretch.allocated);
            return Err(e);
        }
        cursor = stretch.end;
        let inner = blob.inner.lock();
        publish_staged(&inner, staged, stretch);
    }
    staged.size = staged.size.max(end);
    Ok(())
}

/// How a COW sources the old span it splices into.
enum CowSource {
    /// Disk read-back, checked against the span's expected CRC.
    Disk { expected: u32 },
    /// The chunk's overlay bytes: its current content (process memory,
    /// written through), needing no read and no re-check.
    Overlay(Vec<u8>),
}

/// Write in place within an existing run's extent, extending it as far as
/// `stretch_end` (bounded by the extent capacity). Includes zero-fill of
/// `[fill_from, cursor)` (unwritten gap below the write inside the run's
/// frontier chunk).
struct InPlace {
    stretch_end: u64,
    run_logical: u64,
    run: RunMeta,
    fill_from: u64,
    private: bool,
}

/// Overlay fast path: a rewrite of an overlay-resident chunk, fully inside
/// its written span. The payload is written at its exact offset and
/// spliced into the overlay entry — no read-back, no CRC pass (the chunk's
/// CRC goes pending).
struct OverlayWrite {
    stretch_end: u64,
    physical: u64,
    run_logical: u64,
    run: RunMeta,
    private: bool,
}

/// Fresh extent for `[chunk_base, stretch_end)` (zero-lead below the
/// write; the chunk base is unbacked).
struct Fresh {
    stretch_end: u64,
    extent: Extent,
    chunk_base: u64,
    seq: u64,
}

/// The cursor's chunk may not be written in place: COW its backed span.
struct Cow {
    stretch_end: u64,
    span_physical: u64,
    span_len: u64,
    extent: Extent,
    seq: u64,
    source: CowSource,
}

/// A write placement decided by [`plan_stretch`]'s planning loop and
/// materialized into a [`Stretch`] by the arm named for it.
enum Plan {
    InPlace(InPlace),
    Overlay(OverlayWrite),
    Fresh(Fresh),
    Cow(Cow),
}

/// Plan the next stretch starting at `cursor` (performing any COW/CRC
/// read-backs needed to make the plan self-contained).
///
/// With `staged` set, planning runs against the merged overlay-over-base
/// view and follows the batch placement rule: batch-private extents are
/// writable in place; published extents only at or beyond BOTH the
/// published size and the freeze boundary (bytes no snapshot can capture);
/// everything else relocates to a fresh extent published only at apply.
/// Staged stretches always compute CRCs eagerly (deferral is base-only).
async fn plan_stretch<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    cursor: u64,
    end: u64,
    data: &IoBuf,
    data_base: u64,
) -> Result<Stretch, Error> {
    /// A planning attempt: a plan, or a committed CRC to load first.
    enum Outcome {
        Plan(Plan),
        NeedCrc(u64),
    }

    // The COW of a chunk untouched since hydration needs its committed CRC
    // (the read-back check): loaded outside the locks, memoized, and the
    // plan re-derived. The target chunk is fixed by `cursor`, so the memo
    // guarantees the second attempt resolves.
    let mut loaded_crc: Option<(u64, u32)> = None;
    let plan = loop {
        let outcome = 'plan: {
            let mut state = ready.state.lock();
            let mut inner = blob.inner.lock();
            let chunk = chunk_of(cursor);
            let chunk_start = chunk * BLOCK;

            // Merged coverage and placement: the base view for published
            // writes, the overlay-over-base view for staged writes.
            let covering = staged.map_or_else(
                || {
                    inner
                        .covering(chunk_start)
                        .map(|(logical, run)| (logical, run, false))
                },
                |st| st.covering(&inner, chunk_start),
            );
            match covering {
                Some((run_logical, run, private)) => {
                    let backed_end = run_logical + run.len;
                    let writable = match staged {
                        // Base freeze rule: young extents are exempt; otherwise
                        // only bytes at or beyond the freeze boundary.
                        None => run.born > state.snapshot_seq || cursor >= inner.freeze_size,
                        // Batch placement rule: private extents always; a
                        // published extent only for bytes no snapshot can
                        // capture (at or beyond BOTH the published size and the
                        // freeze boundary; the born exemption does not apply —
                        // young extents are still published to readers).
                        Some(_) => private || cursor >= inner.size.max(inner.freeze_size),
                    };
                    if !writable {
                        let (span_physical, span_len) = staged
                            .map_or_else(
                                || inner.chunk_span(chunk),
                                |st| st.chunk_span(&inner, chunk),
                            )
                            .expect("covered chunk has a span");
                        // Source the old span from the overlay when it is valid
                        // for the merged view (base content the batch has not
                        // staged over), otherwise from a checked disk read-back
                        // whose expected CRC pairs with the merged view that
                        // produced the span (staged overlays win).
                        let staged_crc = staged.and_then(|st| st.crcs.get(&chunk)).copied();
                        let resident = match staged_crc {
                            None => inner.overlay_get(chunk).map(<[u8]>::to_vec),
                            Some(_) => None,
                        };
                        let source = match resident {
                            Some(bytes) => {
                                debug_assert_eq!(bytes.len() as u64, span_len);
                                CowSource::Overlay(bytes)
                            }
                            None => {
                                let crc = staged_crc
                                    .or_else(|| inner.crcs.get(chunk))
                                    .expect("covered chunk has crc")
                                    .crc;
                                let expected = match crc {
                                    ChunkCrc::Ready(expected) => expected,
                                    // Pending chunks are overlay-resident, and
                                    // residency was checked above.
                                    ChunkCrc::Pending => {
                                        unreachable!("pending chunk without overlay entry")
                                    }
                                    // Untouched since hydration: the expected
                                    // CRC is the committed value.
                                    ChunkCrc::Unloaded => {
                                        let known = loaded_crc
                                            .filter(|&(c, _)| c == chunk)
                                            .map(|(_, crc)| crc)
                                            .or_else(|| inner.crc_cache.get(chunk));
                                        match known {
                                            Some(expected) => expected,
                                            None => break 'plan Outcome::NeedCrc(chunk),
                                        }
                                    }
                                };
                                CowSource::Disk { expected }
                            }
                        };
                        let extent = state.alloc.allocate(BLOCK);
                        Outcome::Plan(Plan::Cow(Cow {
                            stretch_end: end.min(chunk_start + BLOCK),
                            span_physical,
                            span_len,
                            extent,
                            seq: state.seq,
                            source,
                        }))
                    } else {
                        // In place. The write may start beyond the backed end
                        // (a gap inside this run's frontier chunk): zero-fill
                        // from the backed end. It may extend past the backing
                        // but only within the extent's capacity.
                        let fill_from = cursor.min(backed_end);
                        let stretch_end = end.min(run_logical + run.capacity);
                        debug_assert!(stretch_end > cursor);
                        // Overlay fast path (base mode): the write stays inside
                        // this chunk's written span and the span is resident.
                        let chunk_end = chunk_start + BLOCK;
                        let span_end = chunk_end.min(backed_end);
                        if staged.is_none()
                            && end.min(chunk_end) <= span_end
                            && inner.overlay_get(chunk).is_some()
                        {
                            let (span_physical, _) =
                                inner.chunk_span(chunk).expect("covered chunk has a span");
                            Outcome::Plan(Plan::Overlay(OverlayWrite {
                                stretch_end: end.min(chunk_end),
                                physical: span_physical + (cursor - chunk_start),
                                run_logical,
                                run,
                                private,
                            }))
                        } else {
                            Outcome::Plan(Plan::InPlace(InPlace {
                                stretch_end,
                                run_logical,
                                run,
                                fill_from,
                                private,
                            }))
                        }
                    }
                }
                None => {
                    // Unbacked chunk: fresh extent from this chunk's base to the
                    // end of the write (or the next backed run, which must not
                    // be overlapped).
                    let next_backed = staged
                        .map_or_else(
                            || inner.runs.range(chunk_start..).next().map(|(&l, _)| l),
                            |st| st.next_backed(&inner, chunk_start),
                        )
                        .unwrap_or(u64::MAX);
                    let stretch_end = end.min(next_backed);
                    let len = block_align(stretch_end - chunk_start);
                    let extent = state.alloc.allocate(len);
                    Outcome::Plan(Plan::Fresh(Fresh {
                        stretch_end,
                        extent,
                        chunk_base: chunk_start,
                        seq: state.seq,
                    }))
                }
            }
        };
        match outcome {
            Outcome::Plan(plan) => break plan,
            Outcome::NeedCrc(chunk) => {
                if let Some((first, values)) =
                    Box::pin(load_committed_page(ready, blob, chunk)).await?
                {
                    loaded_crc = Some((chunk, values[(chunk - first) as usize]));
                }
            }
        }
    };

    match plan {
        Plan::Overlay(p) => Ok(materialize_overlay(cursor, data, data_base, p)),
        Plan::InPlace(p) => {
            materialize_in_place(ready, blob, staged, cursor, data, data_base, p).await
        }
        Plan::Fresh(p) => Ok(materialize_fresh(ready, staged, cursor, data, data_base, p)),
        Plan::Cow(p) => materialize_cow(ready, blob, staged, cursor, data, data_base, p).await,
    }
}

/// Materialize an [`OverlayWrite`] plan: the payload at its exact offset,
/// spliced into the overlay entry.
fn materialize_overlay(cursor: u64, data: &IoBuf, data_base: u64, plan: OverlayWrite) -> Stretch {
    let OverlayWrite {
        stretch_end,
        physical,
        run_logical,
        run,
        private,
    } = plan;
    let d0 = (cursor - data_base) as usize;
    let d1 = (stretch_end - data_base) as usize;
    let payload = data.slice(d0..d1);
    let at = (cursor % BLOCK) as usize;
    Stretch {
        end: stretch_end,
        physical,
        bytes: payload.clone().into(),
        run: (run_logical, run),
        crcs: vec![(chunk_of(cursor), CrcUpdate::Splice { at, data: payload })],
        last_span: None,
        replaced: None,
        allocated: None,
        private,
    }
}

/// Materialize an [`InPlace`] plan.
///
/// Each affected chunk's CRC covers its full written span: the first
/// chunk may have a prefix below `fill_from`, and the last chunk may have
/// a suffix beyond `stretch_end` (an in-place overwrite inside a longer
/// span). Only `[fill_from, stretch_end)` — the gap zero-fill and the new
/// data — is written back, at its exact offset: the caller's payload
/// slice passed zero-copy, preceded by a pooled zero-fill buffer when the
/// gap is nonempty. CRCs stream over the logical pieces — no assembly of
/// the payload.
async fn materialize_in_place<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    cursor: u64,
    data: &IoBuf,
    data_base: u64,
    plan: InPlace,
) -> Result<Stretch, Error> {
    let InPlace {
        stretch_end,
        run_logical,
        run,
        fill_from,
        private,
    } = plan;
    let d0 = (cursor - data_base) as usize;
    let d1 = (stretch_end - data_base) as usize;
    let first_chunk = chunk_of(fill_from);
    let last_chunk = chunk_of(stretch_end - 1);
    let base = first_chunk * BLOCK;

    let span_end = (run_logical + run.len).max(stretch_end);
    let chunk_cap = (last_chunk + 1) * BLOCK;
    let suffix_end = span_end.min(chunk_cap);

    let (prefix, prefix_verified) =
        read_span_prefix(ready, blob, staged, &run, run_logical, base, fill_from).await?;
    let has_suffix = suffix_end > stretch_end;
    let (suffix, suffix_verified) = if has_suffix {
        read_span_suffix(
            ready,
            blob,
            staged,
            &run,
            run_logical,
            stretch_end,
            suffix_end,
        )
        .await?
    } else {
        (Vec::new(), true)
    };
    let gap = (cursor - fill_from) as usize;
    let zeros = (gap > 0).then(|| zeroed(&ready.pool, gap));
    let payload = data.slice(d0..d1);

    // The logical pieces of `[base, suffix_end)`, in order.
    let pieces: [(u64, &[u8]); 4] = [
        (base, &prefix),
        (fill_from, zeros.as_ref().map_or(&[][..], |z| z.as_ref())),
        (cursor, payload.as_ref()),
        (stretch_end, &suffix),
    ];

    // A chunk assembled from process memory (payload, gap zeros,
    // tail-buffer or overlay-sourced prefix/suffix) is verified by
    // construction; a checked disk read-back confers its expected CRC's
    // provenance (see [`expected_span_crc`]). The edge chunks whose spans
    // keep bytes beyond the write are splice-rewrite candidates.
    let (crcs, last_span) = assemble_crcs(
        &pieces,
        first_chunk,
        last_chunk,
        suffix_end,
        staged.is_some(),
        |chunk| (chunk == first_chunk && !prefix.is_empty()) || (chunk == last_chunk && has_suffix),
        |chunk| {
            (chunk != first_chunk || prefix_verified) && (chunk != last_chunk || suffix_verified)
        },
    );

    let bytes = match zeros {
        Some(zeros) => IoBufs::from(vec![zeros, payload]),
        None => payload.into(),
    };
    let new_len = (stretch_end - run_logical).max(run.len);
    Ok(Stretch {
        end: stretch_end,
        physical: run.physical + (fill_from - run_logical),
        bytes,
        run: (
            run_logical,
            RunMeta {
                len: new_len,
                ..run
            },
        ),
        crcs,
        last_span,
        replaced: None,
        allocated: None,
        private,
    })
}

/// Materialize a [`Fresh`] plan: the caller's payload slice is issued
/// zero-copy, preceded by a pooled zero-lead when the write starts past
/// the (unbacked) chunk base. CRCs stream over the same bytes — no
/// assembly.
fn materialize_fresh<S: crate::Storage>(
    ready: &Ready<S>,
    staged: Option<&StagedBlob>,
    cursor: u64,
    data: &IoBuf,
    data_base: u64,
    plan: Fresh,
) -> Stretch {
    let Fresh {
        stretch_end,
        extent,
        chunk_base,
        seq,
    } = plan;
    let d0 = (cursor - data_base) as usize;
    let d1 = (stretch_end - data_base) as usize;
    let lead = (cursor - chunk_base) as usize;
    let zeros = (lead > 0).then(|| zeroed(&ready.pool, lead));
    let payload = data.slice(d0..d1);
    let pieces: [(u64, &[u8]); 2] = [
        (chunk_base, zeros.as_ref().map_or(&[][..], |z| z.as_ref())),
        (cursor, payload.as_ref()),
    ];

    let first_chunk = chunk_of(chunk_base);
    let last_chunk = chunk_of(stretch_end - 1);
    // Assembled purely from process memory (lead zeros + the payload):
    // verified by construction. A chunk written from a sub-block lead
    // (base mode) is a splice-rewrite candidate.
    let (crcs, last_span) = assemble_crcs(
        &pieces,
        first_chunk,
        last_chunk,
        stretch_end,
        staged.is_some(),
        |chunk| chunk == first_chunk && lead > 0,
        |_| true,
    );

    let bytes = match zeros {
        Some(zeros) => IoBufs::from(vec![zeros, payload]),
        None => payload.into(),
    };
    Stretch {
        end: stretch_end,
        physical: extent.offset,
        bytes,
        run: (
            chunk_base,
            RunMeta {
                physical: extent.offset,
                len: stretch_end - chunk_base,
                capacity: extent.len,
                born: seq,
            },
        ),
        crcs,
        last_span,
        replaced: None,
        allocated: Some(extent),
        private: true,
    }
}

/// Materialize a [`Cow`] plan: assemble the chunk's new span from the old
/// span (overlay bytes, or a checked disk read-back) plus the payload, on
/// a fresh extent.
async fn materialize_cow<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    cursor: u64,
    data: &IoBuf,
    data_base: u64,
    plan: Cow,
) -> Result<Stretch, Error> {
    let Cow {
        stretch_end,
        span_physical,
        span_len,
        extent,
        seq,
        source,
    } = plan;
    let chunk = chunk_of(cursor);
    let chunk_start = chunk * BLOCK;
    let w0 = (cursor - chunk_start) as usize;
    let w1 = (stretch_end - chunk_start) as usize;
    let d0 = (cursor - data_base) as usize;
    let d1 = (stretch_end - data_base) as usize;
    let exact = (span_len as usize).max(w1);
    let mut buf = ready.pool.alloc(exact);
    match source {
        // The overlay bytes ARE the span's current content.
        CowSource::Overlay(bytes) => buf.put_slice(&bytes),
        // Read the old span (stable: frozen extents are never
        // rewritten, and deferred frees keep them allocated until
        // the next commit confirms) and check it before splicing.
        // The read-back is the whole span, so the check is one CRC
        // pass over bytes already in hand: it surfaces rot loudly
        // at the COW instead of laundering it under a fresh CRC,
        // and it keeps the relocated chunk verified by
        // construction.
        CowSource::Disk { expected } => {
            let checked = async {
                let old = ready
                    .file
                    .read_at(span_physical, span_len as usize)
                    .await?
                    .coalesce();
                if Crc32::checksum(old.as_ref()) != expected {
                    return Err(chunk_mismatch(ready, blob, chunk));
                }
                Ok(old)
            };
            match checked.await {
                Ok(old) => buf.put_slice(old.as_ref()),
                Err(e) => {
                    free_unpublished(ready, Some(extent));
                    return Err(e);
                }
            }
        }
    }
    buf.put_bytes(0, exact - span_len as usize);
    buf.as_mut()[w0..w1].copy_from_slice(data.slice(d0..d1).as_ref());

    // A partial rewrite is a splice candidate: keep the relocated
    // span in the overlay and defer its CRC (base mode). Every byte
    // lands on the fresh extent, so the chunk is verified by
    // construction either way.
    let span_bytes = buf.as_ref().to_vec();
    let partial = w0 > 0 || w1 < exact;
    let update = if partial && staged.is_none() {
        CrcUpdate::Pending {
            bytes: span_bytes.clone(),
            verified: true,
        }
    } else {
        CrcUpdate::Ready(ChunkState {
            crc: ChunkCrc::Ready(Crc32::checksum(buf.as_ref())),
            verified: true,
        })
    };
    let last_span = Some((chunk, span_bytes));

    Ok(Stretch {
        end: stretch_end,
        physical: extent.offset,
        run: (
            chunk_start,
            RunMeta {
                physical: extent.offset,
                len: exact as u64,
                capacity: extent.len,
                born: seq,
            },
        ),
        crcs: vec![(chunk, update)],
        last_span,
        bytes: buf.freeze().into(),
        replaced: Some(Extent {
            offset: span_physical - (span_physical % BLOCK),
            len: BLOCK,
        }),
        allocated: Some(extent),
        private: true,
    })
}

/// Return a freshly allocated but never-published extent through the
/// deferred-free path (a failed stretch or COW read-back: nothing
/// references it, but only restart would otherwise rebuild it into the
/// allocator).
fn free_unpublished<S: crate::Storage>(ready: &Ready<S>, extent: Option<Extent>) {
    let Some(extent) = extent else { return };
    let mut state = ready.state.lock();
    let seq = state.seq;
    state.defer_free(extent, seq, None);
}

/// CRC32C over `[start, end)` of a logical range assembled from `pieces`:
/// `(piece start, piece bytes)` entries, contiguous and in order. Streams
/// the intersecting slices — no assembly buffer.
fn crc_over(pieces: &[(u64, &[u8])], start: u64, end: u64) -> u32 {
    let mut hasher = Crc32::new();
    let mut covered = 0;
    for &(piece_start, bytes) in pieces {
        let lo = start.max(piece_start);
        let hi = end.min(piece_start + bytes.len() as u64);
        if hi > lo {
            hasher.update(&bytes[(lo - piece_start) as usize..(hi - piece_start) as usize]);
            covered += hi - lo;
        }
    }
    debug_assert_eq!(covered, end - start, "pieces must cover the range");
    hasher.finalize().as_u32()
}

/// The bytes of `[start, end)` assembled from `pieces` (see [`crc_over`]).
fn copy_over(pieces: &[(u64, &[u8])], start: u64, end: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity((end - start) as usize);
    for &(piece_start, bytes) in pieces {
        let lo = start.max(piece_start);
        let hi = end.min(piece_start + bytes.len() as u64);
        if hi > lo {
            out.extend_from_slice(&bytes[(lo - piece_start) as usize..(hi - piece_start) as usize]);
        }
    }
    debug_assert_eq!(out.len() as u64, end - start, "pieces must cover the range");
    out
}

/// A stretch's chunk CRC updates plus its last chunk's span bytes.
type CrcAssembly = (Vec<(u64, CrcUpdate)>, Option<(u64, Vec<u8>)>);

/// Stream the CRC updates for chunks `[first, last]` of a stretch whose
/// logical content is `pieces` (contiguous `(start, bytes)` spans ending
/// at `span_end`). A chunk `spliced` in base mode keeps its span in the
/// overlay and defers its CRC ([`CrcUpdate::Pending`]); every other chunk
/// computes eagerly, carrying its by-construction `verified` provenance.
/// Returns the updates plus the last chunk's span bytes.
fn assemble_crcs(
    pieces: &[(u64, &[u8])],
    first: u64,
    last: u64,
    span_end: u64,
    staged: bool,
    spliced: impl Fn(u64) -> bool,
    verified: impl Fn(u64) -> bool,
) -> CrcAssembly {
    let mut crcs = Vec::new();
    let mut last_span = None;
    for chunk in first..=last {
        let lo = chunk * BLOCK;
        let hi = span_end.min(lo + BLOCK);
        let verified = verified(chunk);
        let update = if spliced(chunk) && !staged {
            CrcUpdate::Pending {
                bytes: copy_over(pieces, lo, hi),
                verified,
            }
        } else {
            CrcUpdate::Ready(ChunkState {
                crc: ChunkCrc::Ready(crc_over(pieces, lo, hi)),
                verified,
            })
        };
        crcs.push((chunk, update));
        if chunk == last {
            last_span = Some((chunk, copy_over(pieces, lo, hi)));
        }
    }
    (crcs, last_span)
}

/// The expected CRC of `chunk`'s current span under the merged view — the
/// staged CRC when the batch staged over the chunk, else the resident
/// state, else the committed value (loaded on demand) — plus the verified
/// provenance a checked read-back of the span confers. A committed value
/// is the chunk's authoritative CRC, so a successful check against it IS
/// the chunk's verification (see [`ChunkState`]); a resident value passes
/// its own bit through.
async fn expected_span_crc<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    chunk: u64,
) -> Result<(u32, bool), Error> {
    loop {
        {
            let mut inner = blob.inner.lock();
            let state = staged
                .and_then(|st| st.crcs.get(&chunk))
                .copied()
                .or_else(|| inner.crcs.get(chunk))
                .expect("covered chunk has crc");
            match state.crc {
                ChunkCrc::Ready(expected) => return Ok((expected, state.verified)),
                // Pending chunks are overlay-resident, and the caller
                // exhausted the in-memory sources before falling back.
                ChunkCrc::Pending => unreachable!("pending chunk without overlay entry"),
                ChunkCrc::Unloaded => {
                    if let Some(expected) = inner.crc_cache.get(chunk) {
                        return Ok((expected, true));
                    }
                }
            }
        }
        // Unloaded with no cached value: load the committed page and
        // re-derive (a None load means the chunk became resident).
        Box::pin(load_committed_page(ready, blob, chunk)).await?;
    }
}

/// Read `chunk`'s whole current span `[chunk_start, span_end)` back from
/// disk and check it against the chunk's expected CRC — the COW
/// read-back's discipline — so rot in the span surfaces loudly at the
/// operation instead of being laundered under a freshly assembled CRC.
/// Returns the span bytes plus the verified provenance they confer.
async fn read_span_checked<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    chunk: u64,
    phys: u64,
    span_len: usize,
) -> Result<(Vec<u8>, bool), Error> {
    let (expected, verified) = expected_span_crc(ready, blob, staged, chunk).await?;
    let span = ready.file.read_at(phys, span_len).await?.coalesce();
    if Crc32::checksum(span.as_ref()) != expected {
        return Err(chunk_mismatch(ready, blob, chunk));
    }
    Ok((span.as_ref().to_vec(), verified))
}

/// Source the first affected chunk's current prefix `[base, fill_from)`:
/// from an in-memory tail buffer or overlay entry when one describes this
/// chunk, otherwise a checked read-back of the chunk's whole span (rare:
/// the first splice into a chunk the overlay does not hold).
///
/// The second element reports the provenance the assembled chunk inherits:
/// tail buffers are trusted process memory, overlay bytes carry their
/// chunk's verified bit, and a disk read-back — checked against the
/// chunk's expected CRC — confers the CRC's own provenance (see
/// [`expected_span_crc`]).
async fn read_span_prefix<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    run: &RunMeta,
    run_logical: u64,
    base: u64,
    fill_from: u64,
) -> Result<(Vec<u8>, bool), Error> {
    let prefix_len = (fill_from - base) as usize;
    if prefix_len == 0 {
        return Ok((Vec::new(), true));
    }
    let chunk = chunk_of(base);
    {
        let mut inner = blob.inner.lock();
        // The staged tail wins for chunks the batch touched; published
        // sources are valid only for chunks the batch has not staged over.
        if let Some(st) = staged {
            if let Some((tail_chunk, tail)) = &st.tail {
                if *tail_chunk == chunk && tail.len() >= prefix_len {
                    return Ok((tail[..prefix_len].to_vec(), true));
                }
            }
        }
        if staged.is_none_or(|st| !st.crcs.contains_key(&chunk)) {
            if inner.tail_chunk == chunk && inner.tail.len() >= prefix_len {
                return Ok((inner.tail[..prefix_len].to_vec(), true));
            }
            let verified = inner.crcs.get(chunk).is_some_and(|s| s.verified);
            if let Some(bytes) = inner.overlay_get(chunk) {
                if bytes.len() >= prefix_len {
                    return Ok((bytes[..prefix_len].to_vec(), verified));
                }
            }
        }
    }
    let span_end = (run_logical + run.len).min(base + BLOCK);
    let phys = run.physical + (base - run_logical);
    // Boxed: the cold checked read-back would otherwise deepen every
    // write future's layout (as the committed-CRC loaders are, see
    // [`load_committed_page`]).
    let (mut span, verified) = Box::pin(read_span_checked(
        ready,
        blob,
        staged,
        chunk,
        phys,
        (span_end - base) as usize,
    ))
    .await?;
    span.truncate(prefix_len);
    Ok((span, verified))
}

/// Source the last affected chunk's trailing span `[stretch_end,
/// suffix_end)` (an in-place overwrite inside a longer span): from an
/// in-memory tail buffer or overlay entry when one describes this chunk,
/// otherwise a checked read-back of the chunk's whole span. Provenance as
/// for [`read_span_prefix`].
async fn read_span_suffix<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    run: &RunMeta,
    run_logical: u64,
    stretch_end: u64,
    suffix_end: u64,
) -> Result<(Vec<u8>, bool), Error> {
    let chunk = chunk_of(stretch_end - 1);
    let chunk_start = chunk * BLOCK;
    let s = (stretch_end - chunk_start) as usize;
    let e = (suffix_end - chunk_start) as usize;
    {
        let mut inner = blob.inner.lock();
        if let Some(st) = staged {
            if let Some((tail_chunk, tail)) = &st.tail {
                if *tail_chunk == chunk && tail.len() >= e {
                    return Ok((tail[s..e].to_vec(), true));
                }
            }
        }
        if staged.is_none_or(|st| !st.crcs.contains_key(&chunk)) {
            if inner.tail_chunk == chunk && inner.tail.len() >= e {
                return Ok((inner.tail[s..e].to_vec(), true));
            }
            let verified = inner.crcs.get(chunk).is_some_and(|st| st.verified);
            if let Some(bytes) = inner.overlay_get(chunk) {
                if bytes.len() >= e {
                    return Ok((bytes[s..e].to_vec(), verified));
                }
            }
        }
    }
    // A suffix exists only when the run extends past the write, so the
    // chunk's span ends exactly at `suffix_end`.
    let phys = run.physical + (chunk_start - run_logical);
    // Boxed, as in `read_span_prefix`.
    let (span, verified) = Box::pin(read_span_checked(ready, blob, staged, chunk, phys, e)).await?;
    Ok((span[s..e].to_vec(), verified))
}

/// Publish a completed stretch. Caller holds the blob write lock.
fn publish_stretch<S: crate::Storage>(ready: &Ready<S>, blob: &BlobCore, stretch: Stretch) {
    let mut state = ready.state.lock();
    let mut inner = blob.inner.lock();

    // A removal raced this write (`write_locked` rejects removed blobs at
    // entry, but remove does not take the write lock): the blob's extents
    // are already queued for reuse, so adopt nothing — a fresh extent
    // would leak until restart and a COW's replaced block would later
    // double-free. Mutating a removed blob is unspecified by the trait.
    if inner.removed {
        drop(inner);
        drop(state);
        free_unpublished(ready, stretch.allocated);
        return;
    }
    let (logical, run) = stretch.run;

    if let Some(replaced) = stretch.replaced {
        cow_remap(&mut inner, logical, run);
        inner.pending_frees.push(replaced);
        inner.generation += 1;
    } else {
        match inner.runs.get_mut(&logical) {
            Some(existing) if existing.physical == run.physical => {
                existing.len = existing.len.max(run.len);
            }
            _ => {
                inner.runs.insert(logical, run);
            }
        }
    }

    let last_chunk = stretch
        .crcs
        .last()
        .map(|&(chunk, _)| chunk)
        .expect("stretch affects at least one chunk");
    for (chunk, update) in stretch.crcs {
        match update {
            CrcUpdate::Ready(chunk_state) => {
                inner.crcs.insert(chunk, chunk_state);
                // The chunk's bytes were rewritten without an overlay
                // refresh: any resident entry is stale.
                inner.overlay_remove(chunk);
            }
            CrcUpdate::Pending { bytes, verified } => {
                inner.crcs.insert(
                    chunk,
                    ChunkState {
                        crc: ChunkCrc::Pending,
                        verified,
                    },
                );
                inner.overlay_insert(chunk, bytes);
            }
            CrcUpdate::Splice { at, data } => {
                inner.overlay_splice(chunk, at, data.as_ref());
                inner.crcs.make_pending(chunk);
            }
        }
        inner.dirty_chunks.insert(chunk);
    }
    // Refresh the tail buffer if this stretch reaches the write frontier
    // (an overlay fast-path stretch derives its span from the spliced
    // overlay entry on the rare frontier hit).
    if stretch.end >= inner.size || last_chunk >= inner.tail_chunk {
        inner.tail = match stretch.last_span {
            Some((chunk, span)) => {
                debug_assert_eq!(chunk, last_chunk);
                span
            }
            None => inner
                .overlay_get(last_chunk)
                .expect("fast-path chunk is resident")
                .to_vec(),
        };
        inner.tail_chunk = last_chunk;
    }
    state.dirty.insert(blob.id);
}

/// Record a completed stretch in a batch overlay. Caller holds the blob
/// write lock.
fn publish_staged(inner: &BlobInner, staged: &mut StagedBlob, stretch: Stretch) {
    let (logical, run) = stretch.run;
    if let Some(extent) = stretch.allocated {
        staged.fresh.push(extent);
    }
    if let Some(replaced) = stretch.replaced {
        cow_remap_staged(inner, staged, logical, run);
        staged.replaced.push(replaced);
        staged.relocated = true;
    } else {
        match staged.runs.get_mut(&logical) {
            Some(existing) if existing.meta.physical == run.physical => {
                existing.meta.len = existing.meta.len.max(run.len);
            }
            _ => {
                staged.runs.insert(
                    logical,
                    StagedRun {
                        meta: run,
                        private: stretch.private,
                    },
                );
            }
        }
    }

    for (chunk, update) in stretch.crcs {
        match update {
            CrcUpdate::Ready(chunk_state) => {
                staged.crcs.insert(chunk, chunk_state);
            }
            // Deferral is base-only (see `plan_stretch`).
            CrcUpdate::Pending { .. } | CrcUpdate::Splice { .. } => {
                unreachable!("staged stretches compute CRCs eagerly")
            }
        }
    }
    // Refresh the staged tail if this stretch reaches the staged frontier.
    let (chunk, span) = stretch
        .last_span
        .expect("staged stretches carry a last span");
    let tail_chunk = staged.tail.as_ref().map(|(c, _)| *c);
    if stretch.end >= staged.size || chunk >= tail_chunk.unwrap_or(inner.tail_chunk) {
        staged.tail = Some((chunk, span));
    }
}

/// The surviving halves of a split run: the prefix, then the suffix.
type SplitRun = (Option<(u64, RunMeta)>, Option<(u64, RunMeta)>);

/// Split the run covering one chunk around that chunk: the surviving
/// prefix `[old_logical, chunk_start)` keeps the extent with its capacity
/// ending where the chunk begins (the chunk's old block is deferred-freed
/// separately), and the surviving suffix `[chunk_start + BLOCK, old_end)`
/// keeps the remainder. Either half is `None` when empty.
fn split_run(old_logical: u64, old_run: RunMeta, chunk_start: u64) -> SplitRun {
    let old_end = old_logical + old_run.len;
    let chunk_end = chunk_start + BLOCK;
    let prefix = (old_logical < chunk_start).then(|| {
        (
            old_logical,
            RunMeta {
                len: chunk_start - old_logical,
                capacity: chunk_start - old_logical,
                ..old_run
            },
        )
    });
    let suffix = (old_end > chunk_end).then(|| {
        (
            chunk_end,
            RunMeta {
                physical: old_run.physical + (chunk_end - old_logical),
                len: old_end - chunk_end,
                capacity: old_run.capacity.saturating_sub(chunk_end - old_logical),
                born: old_run.born,
            },
        )
    });
    (prefix, suffix)
}

/// Remap one staged-COW'd chunk: split the merged covering run around it in
/// the overlay (mirrors [`cow_remap`] without touching published state).
fn cow_remap_staged(inner: &BlobInner, staged: &mut StagedBlob, chunk_start: u64, fresh: RunMeta) {
    let (old_logical, old_run, old_private) = staged
        .covering(inner, chunk_start)
        .expect("COW of unbacked chunk");
    debug_assert!(!old_private, "private chunks are written in place");
    let (prefix, suffix) = split_run(old_logical, old_run, chunk_start);

    // Detach the source run from the merged view (a base run detaches by
    // supersession).
    if staged.runs.remove(&old_logical).is_none() {
        staged.removed.insert(old_logical);
    }
    for (logical, meta) in prefix.into_iter().chain(suffix) {
        staged.runs.insert(
            logical,
            StagedRun {
                meta,
                private: old_private,
            },
        );
    }
    staged.runs.insert(
        chunk_start,
        StagedRun {
            meta: fresh,
            private: true,
        },
    );
}

/// Remap one COW'd chunk: split the covering run around it.
fn cow_remap(inner: &mut BlobInner, chunk_start: u64, fresh: RunMeta) {
    let (old_logical, old_run) = inner.covering(chunk_start).expect("COW of unbacked chunk");
    let (prefix, suffix) = split_run(old_logical, old_run, chunk_start);
    inner.runs.remove(&old_logical);
    for (logical, meta) in prefix.into_iter().chain(suffix) {
        inner.runs.insert(logical, meta);
    }
    inner.runs.insert(chunk_start, fresh);
}
