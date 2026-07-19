//! The verified read path.
//!
//! Readers take no locks across I/O: they snapshot backing + checksum
//! state (per-chunk CRC and verified bit) and a relocation `generation`,
//! read, verify what needs verifying, and retry if the generation moved.
//! Chunks with a deferred (pending) CRC are served from the blob's
//! in-memory overlay under the state lock instead of from disk. Chunks
//! already verified this process are read exactly and skip the CRC pass,
//! so the generation is re-checked after the read (a relocated extent may
//! have been recycled mid-read). Unverified chunks are read as whole
//! block-aligned spans — coalesced with adjacent bytes into one inner read
//! — and verified in passing, so every read doubles as verification
//! progress. In-place rewrites (uncommitted bytes, young extents) move no
//! generation, so on a mismatch with an unchanged generation the reader
//! briefly takes the write lock and re-verifies the quiesced chunk before
//! reporting corruption. Extent reuse or an in-place rewrite under an
//! in-flight read causes a retry, never a false corruption report.

use super::{
    chunk::{chunk_of, ChunkCrc, RunMeta},
    paging::{insert_window, load_committed_page, window_value},
    state::{BlobCore, BlobInner, Ready},
    BLOCK,
};
use crate::{Blob as _, Error, IoBuf, IoBufsMut};
use commonware_cryptography::Crc32;
use commonware_formatting::hex;

/// Cap on one coalesced inner read issued by [`read_verified`].
const MAX_READ_SPAN: u64 = 1 << 20;

/// One coalesced inner read: a physically and logically contiguous byte
/// range covering the requested slices of verified chunks (read exactly)
/// and the whole written spans of unverified chunks (block-aligned at both
/// ends within the run), so a single read serves the request and carries
/// everything needed to verify every unverified chunk it touches.
struct ReadGroup {
    /// Physical read position.
    physical: u64,
    /// Logical position of the first byte read.
    logical: u64,
    /// Read length in bytes.
    len: u64,
    /// Chunks this read verifies: (chunk logical start, span len, expected
    /// CRC), ascending. Each span lies fully inside the read.
    checks: Vec<(u64, u64, u32)>,
}

impl ReadGroup {
    /// Whether every chunk this group reads is CRC-checked. When false,
    /// some bytes are served on the strength of a prior verification and a
    /// relocation racing the read (whose extent may have been recycled)
    /// forces a retry.
    const fn all_checked(&self) -> bool {
        let chunks = chunk_of(self.logical + self.len - 1) - chunk_of(self.logical) + 1;
        self.checks.len() as u64 == chunks
    }
}

/// A derived read plan: the coalesced inner reads (with the chunks each
/// verifies), overlay copies of the requested slices of pending chunks, and
/// the relocation generation the plan is valid against.
struct ReadPlan {
    generation: u64,
    /// The first coalesced read. Held out of `rest` so the by-far-common
    /// single-read plan allocates nothing.
    head: Option<ReadGroup>,
    /// Further coalesced reads (fragmented plans only).
    rest: Vec<ReadGroup>,
    /// Overlay copies of pending chunks: (logical start, bytes).
    splices: Vec<(u64, Vec<u8>)>,
}

/// A [`plan_read`] outcome: a servable plan, or the chunks whose committed
/// CRCs must be loaded from disk before one can be derived.
enum Planned {
    Plan(ReadPlan),
    Missing(Vec<u64>),
}

/// Derive the read plan for `[offset, end)` under the blob's state lock.
///
/// Runs and chunk states are walked with two linear range scans in logical
/// order — no per-chunk point queries. Verified chunks contribute exactly
/// the requested bytes of their span (their CRC is never consulted).
/// Unverified chunks contribute their whole written span, block-aligned
/// within the run, which the read then CRC-verifies: every read doubles as
/// verification progress. An unverified chunk's expected CRC comes from
/// its resident value, the caller's loaded windows, or the committed-CRC
/// cache. Chunks with none yield [`Planned::Missing`] and the caller loads
/// their pages from the checksum extents before re-planning. Segments
/// coalesce into one read whenever physically and logically contiguous —
/// verified and unverified alike — bounded by [`MAX_READ_SPAN`].
///
/// With `paranoid` set, verified chunks are planned like unverified ones
/// (whole span, CRC-checked): a fully checked read stands regardless of
/// concurrent relocations, so this bounds the generation-retry loop (see
/// [`read_verified`]).
fn plan_read(
    inner: &mut BlobInner,
    offset: u64,
    end: u64,
    loaded: &[(u64, Vec<u32>)],
    paranoid: bool,
) -> Planned {
    // Steady-state fast path: a request covered by one run whose every
    // chunk is verified with a ready CRC is a single exact read — no
    // chunk-state walk at all. Proven volume-wide in O(1) when every
    // backed chunk is verified, or per span otherwise (word-at-a-time over
    // the requested chunks), so never-read ranges elsewhere in the blob do
    // not tax reads of verified territory. Other shapes (holes, run
    // boundaries, unverified or pending chunks in the span) take the full
    // scan.
    let first = chunk_of(offset);
    let last = chunk_of(end - 1);
    if let Some((l, r)) = inner.covering(offset) {
        if !paranoid
            && end <= l + r.len
            && (inner.crcs.all_verified() || inner.crcs.span_verified(first, last))
        {
            return Planned::Plan(ReadPlan {
                generation: inner.generation,
                head: Some(ReadGroup {
                    physical: r.physical + (offset - l),
                    logical: offset,
                    len: end - offset,
                    checks: Vec::new(),
                }),
                rest: Vec::new(),
                splices: Vec::new(),
            });
        }
    }
    let mut head: Option<ReadGroup> = None;
    let mut rest: Vec<ReadGroup> = Vec::new();
    // Requested slices of pending chunks: (logical start, copy end).
    let mut pending: Vec<(u64, u64)> = Vec::new();
    // Unverified chunks whose expected CRC is not in RAM.
    let mut missing: Vec<u64> = Vec::new();
    {
        // The chunk-state walk borrows the map while the committed-CRC
        // cache is consulted mutably (LRU stamps): split the fields.
        let BlobInner {
            runs: all_runs,
            crcs,
            crc_cache,
            ..
        } = inner;
        // Track the covering run alongside the chunk walk: start at the run
        // at or before the first chunk and advance as chunks pass.
        let start = all_runs
            .range(..=first * BLOCK)
            .next_back()
            .map_or(first * BLOCK, |(&l, _)| l);
        let mut runs = all_runs.range(start..);
        let mut run: Option<(u64, RunMeta)> = None;
        for (chunk, state) in crcs.iter_range(first, last) {
            let chunk_start = chunk * BLOCK;
            while run.is_none_or(|(l, r)| l + r.len <= chunk_start) {
                match runs.next() {
                    Some((&l, &r)) => run = Some((l, r)),
                    None => break,
                }
            }
            // Runs and chunk states are updated together under the state
            // lock: a chunk state without a covering run is a bug, never a
            // reachable disk state.
            let Some((l, r)) = run.filter(|&(l, r)| l <= chunk_start && chunk_start < l + r.len)
            else {
                unreachable!("chunk state without a covering run")
            };
            let span = (l + r.len - chunk_start).min(BLOCK);
            let lo = offset.max(chunk_start);
            let hi = end.min(chunk_start + span);
            if state.crc == ChunkCrc::Pending {
                // Pending chunk: the overlay is authoritative (there is no
                // finalized CRC to verify a disk read against), so serve
                // its bytes directly. Bytes past the span within the chunk
                // are holes (zeros already in place).
                if hi > lo {
                    pending.push((lo, hi));
                }
                continue;
            }
            let (seg_lo, seg_hi, check) = if state.verified && !paranoid {
                // Bytes past the span within the chunk are holes (zeros
                // already in place). The request may fall entirely in them.
                if hi <= lo {
                    continue;
                }
                (lo, hi, None)
            } else {
                let crc = match state.crc {
                    ChunkCrc::Ready(crc) => Some(crc),
                    ChunkCrc::Unloaded => {
                        window_value(loaded, chunk).or_else(|| crc_cache.get(chunk))
                    }
                    ChunkCrc::Pending => unreachable!("pending chunks are handled above"),
                };
                let Some(crc) = crc else {
                    missing.push(chunk);
                    continue;
                };
                (
                    chunk_start,
                    chunk_start + span,
                    Some((chunk_start, span, crc)),
                )
            };
            let physical = r.physical + (seg_lo - l);
            let tail = if rest.is_empty() {
                head.as_mut()
            } else {
                rest.last_mut()
            };
            match tail {
                Some(g)
                    if g.physical + g.len == physical
                        && g.logical + g.len == seg_lo
                        && g.len + (seg_hi - seg_lo) <= MAX_READ_SPAN =>
                {
                    g.len += seg_hi - seg_lo;
                    g.checks.extend(check);
                }
                _ => {
                    let group = ReadGroup {
                        physical,
                        logical: seg_lo,
                        len: seg_hi - seg_lo,
                        checks: check.into_iter().collect(),
                    };
                    if head.is_none() {
                        head = Some(group);
                    } else {
                        rest.push(group);
                    }
                }
            }
        }
    }
    if !missing.is_empty() {
        return Planned::Missing(missing);
    }
    // Copy the pending slices out of the overlay under the same lock as the
    // plan (coherent regardless of racing writers). A separate mutable pass:
    // overlay reads refresh LRU stamps.
    let splices = pending
        .into_iter()
        .map(|(lo, hi)| {
            let chunk = chunk_of(lo);
            let base = chunk * BLOCK;
            let bytes = inner
                .overlay_get(chunk)
                .expect("pending chunk is overlay-resident");
            (
                lo,
                bytes[(lo - base) as usize..(hi - base) as usize].to_vec(),
            )
        })
        .collect();
    Planned::Plan(ReadPlan {
        generation: inner.generation,
        head,
        rest,
        splices,
    })
}

/// Publish the chunks a read verified — only where the state each was
/// checked against still stands — and decide whether the read's outcome is
/// servable. Returns false when a relocation (whose extent may have been
/// recycled) raced the read under bytes served unchecked: the caller must
/// retry. A read whose every byte was CRC-checked stands regardless — a
/// matching checksum proves the planned content.
fn publish_read(blob: &BlobCore, generation: u64, checked: &[(u64, u32)], unchecked: bool) -> bool {
    let mut inner = blob.inner.lock();
    if inner.generation != generation {
        return !unchecked;
    }
    for &(chunk, crc) in checked {
        inner.crcs.mark_verified(chunk, crc);
    }
    true
}

/// Verified read of `[offset, offset + len)`.
///
/// The plan (see [`plan_read`]) reads verified chunks exactly and
/// unverified chunks as whole block-aligned spans, verifying them
/// opportunistically. When the whole request is served by ONE inner read
/// with no widening, the read is zero-copy: the inner read buffer is
/// returned directly, or the caller's buffers (the
/// [`crate::Blob::read_at_buf`] path) are passed straight to the inner
/// blob's `read_at_buf` and any CRC checks run in place. Every other shape
/// reads into pool scratch and copies into the caller's buffers once at
/// the end. The returned buffers always hold exactly `len` bytes with the
/// chunk layout preserved (holes read as zeros).
///
/// Reads take no locks across I/O. A CRC mismatch under an unchanged
/// generation quiesces the (single) writer and re-verifies the chunk
/// before reporting corruption: in-place rewrites of uncommitted bytes are
/// legal and move no generation. Extent reuse or an in-place rewrite under
/// an in-flight read causes a retry, never a false corruption report.
pub(super) async fn read_verified<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    offset: u64,
    len: usize,
    mut caller: Option<IoBufsMut>,
) -> Result<IoBufsMut, Error> {
    ready.check_poisoned()?;
    let end = offset
        .checked_add(len as u64)
        .ok_or(Error::OffsetOverflow)?;

    // Committed-CRC windows loaded for this read (see below), kept across
    // retries: an unloaded chunk's committed value is immutable, so the
    // windows stay valid whatever the retry re-plans.
    let mut loaded: Vec<(u64, Vec<u32>)> = Vec::new();
    // Retries caused by concurrent relocations (generation moves under
    // bytes served unchecked). Sustained relocation churn could otherwise
    // starve the reader indefinitely: past the limit, the plan CRC-checks
    // every chunk it reads, which stands regardless of the generation and
    // ends the loop in one extra verification pass.
    const GENERATION_RETRY_LIMIT: u32 = 3;
    let mut invalidated: u32 = 0;
    'retry: loop {
        let paranoid = invalidated >= GENERATION_RETRY_LIMIT;
        let planned = {
            let mut inner = blob.inner.lock();
            if end > inner.size {
                return Err(Error::BlobInsufficientLength);
            }
            if len == 0 {
                return Ok(caller.take().map_or_else(IoBufsMut::default, |mut bufs| {
                    // SAFETY: zero bytes need no initialization.
                    unsafe { bufs.set_len(0) };
                    bufs
                }));
            }
            plan_read(&mut inner, offset, end, &loaded, paranoid)
        };
        let plan = match planned {
            Planned::Plan(plan) => plan,
            // Unverified chunks whose expected CRC is neither resident nor
            // cached: load their committed pages, then re-plan.
            Planned::Missing(chunks) => {
                for chunk in chunks {
                    if window_value(&loaded, chunk).is_some() {
                        continue;
                    }
                    if let Some(window) = Box::pin(load_committed_page(ready, blob, chunk)).await? {
                        insert_window(&mut loaded, window);
                    }
                }
                continue 'retry;
            }
        };
        let generation = plan.generation;

        // Fast path: ONE inner read serving exactly the request (no
        // widening, no overlay splices). The read lands directly in the
        // caller's buffers (or the inner read buffer is returned as is) and
        // unverified chunks are CRC-checked in place. Checks need one
        // contiguous view, so multi-buffer callers with checks take the
        // pooled path below.
        if let (Some(group), []) = (&plan.head, plan.rest.as_slice()) {
            let exact = group.logical == offset && group.len == len as u64;
            let contiguous = caller.as_ref().is_none_or(IoBufsMut::is_single);
            if plan.splices.is_empty() && exact && (group.checks.is_empty() || contiguous) {
                let from_caller = caller.is_some();
                let bufs = match caller.take() {
                    Some(bufs) => ready.file.read_at_buf(group.physical, len, bufs).await?,
                    None => ready.file.read_at(group.physical, len).await?,
                };
                // An inner `read_at` may return a multi-buffer result:
                // coalesce it for the CRC pass (single buffers are free).
                let bufs = if group.checks.is_empty() || bufs.is_single() {
                    bufs
                } else {
                    IoBufsMut::from(bufs.coalesce())
                };
                let mut ok = true;
                let mut checked: Vec<(u64, u32)> = Vec::with_capacity(group.checks.len());
                if !group.checks.is_empty() {
                    let view = bufs.as_single().expect("coalesced above").as_ref();
                    for &(chunk_start, span, crc) in &group.checks {
                        let at = (chunk_start - group.logical) as usize;
                        if Crc32::checksum(&view[at..at + span as usize]) != crc {
                            ok = false;
                            break;
                        }
                        checked.push((chunk_of(chunk_start), crc));
                    }
                }
                if ok {
                    if publish_read(blob, generation, &checked, !group.all_checked()) {
                        return Ok(bufs);
                    }
                    // The backing relocated (and may have been recycled)
                    // while the read was in flight: re-derive the plan (the
                    // new backing may no longer qualify for this path).
                    // Re-issuing into the same caller buffers is fine: only
                    // the returned state matters.
                    invalidated += 1;
                    if from_caller {
                        caller = Some(bufs);
                    }
                    continue 'retry;
                }
                // A CRC mismatch (a racing in-place writer, or corruption):
                // fall through to the pooled path, whose quiesce protocol
                // settles which.
                if from_caller {
                    caller = Some(bufs);
                }
            }
        }

        let mut out = ready.pool.alloc_zeroed(len);
        // Chunks this read verified, with the CRC each was checked against
        // (published under the state lock below).
        let mut checked: Vec<(u64, u32)> = Vec::new();
        let mut unchecked = false;
        for group in plan.head.iter().chain(&plan.rest) {
            let bytes = ready
                .file
                .read_at(group.physical, group.len as usize)
                .await?
                .coalesce()
                .freeze();
            // Copy the requested intersection in one pass (verified slices
            // and the requested parts of checked chunks alike). Bytes
            // outside the request — unverified-span widening — serve
            // verification only.
            let r0 = offset.max(group.logical);
            let r1 = end.min(group.logical + group.len);
            if r1 > r0 {
                out.as_mut()[(r0 - offset) as usize..(r1 - offset) as usize].copy_from_slice(
                    &bytes.as_ref()[(r0 - group.logical) as usize..(r1 - group.logical) as usize],
                );
            }
            unchecked |= !group.all_checked();
            for &(chunk_start, span, crc) in &group.checks {
                let at = (chunk_start - group.logical) as usize;
                if Crc32::checksum(&bytes.as_ref()[at..at + span as usize]) == crc {
                    checked.push((chunk_of(chunk_start), crc));
                    continue;
                }
                {
                    let inner = blob.inner.lock();
                    if inner.generation != generation {
                        invalidated += 1;
                        continue 'retry;
                    }
                }
                // Not a relocation. A writer may legally have rewritten
                // this chunk in place (uncommitted bytes and young extents
                // are not frozen), which moves neither the generation nor,
                // mid-write, the expected CRC: quiesce the (single) writer
                // and re-verify the chunk against its now-stable state
                // before reporting corruption.
                let chunk = chunk_of(chunk_start);
                let _quiesce = blob.write_lock.lock().await;
                /// A quiesced chunk's stable content source.
                enum Stable {
                    Disk { phys: u64, span: u64, crc: u32 },
                    Ram(Vec<u8>),
                }
                let source = loop {
                    let need_load = {
                        let mut inner = blob.inner.lock();
                        if inner.generation != generation {
                            invalidated += 1;
                            continue 'retry;
                        }
                        match inner.chunk_span(chunk) {
                            None => break None,
                            Some((phys, span)) => {
                                let state = inner.crcs.get(chunk).expect("backed chunk has crc");
                                match state.crc {
                                    ChunkCrc::Ready(crc) => {
                                        break Some(Stable::Disk { phys, span, crc })
                                    }
                                    // The racing writer left the chunk
                                    // pending: its overlay entry is the
                                    // stable content.
                                    ChunkCrc::Pending => {
                                        break Some(Stable::Ram(
                                            inner
                                                .overlay_get(chunk)
                                                .expect("pending chunk is overlay-resident")
                                                .to_vec(),
                                        ))
                                    }
                                    // Untouched since hydration: the stable
                                    // CRC is the committed value.
                                    ChunkCrc::Unloaded => {
                                        match window_value(&loaded, chunk)
                                            .or_else(|| inner.crc_cache.get(chunk))
                                        {
                                            Some(crc) => {
                                                break Some(Stable::Disk { phys, span, crc })
                                            }
                                            None => true,
                                        }
                                    }
                                }
                            }
                        }
                    };
                    debug_assert!(need_load);
                    if let Some(window) = Box::pin(load_committed_page(ready, blob, chunk)).await? {
                        insert_window(&mut loaded, window);
                    }
                };
                let stable: IoBuf = match source {
                    None => {
                        invalidated += 1;
                        continue 'retry;
                    }
                    Some(Stable::Disk {
                        phys,
                        span: stable_span,
                        crc: stable_crc,
                    }) => {
                        let reread = ready
                            .file
                            .read_at(phys, stable_span as usize)
                            .await?
                            .coalesce()
                            .freeze();
                        if Crc32::checksum(reread.as_ref()) != stable_crc {
                            ready.metrics.corruptions.inc();
                            return Err(Error::BlobCorrupt(
                                blob.partition.clone(),
                                hex(&blob.name),
                                format!("chunk {chunk} checksum mismatch"),
                            ));
                        }
                        checked.push((chunk, stable_crc));
                        reread
                    }
                    // Served from process memory: nothing was verified
                    // against the disk.
                    Some(Stable::Ram(stable_bytes)) => IoBuf::from(stable_bytes),
                };
                // Replace what the group copy installed for this chunk: the
                // corrected requested slice, and zeros where the stable
                // span ends short of the copied extent.
                let c0 = offset.max(chunk_start);
                let c1 = end.min(chunk_start + stable.len() as u64).max(c0);
                let copied_hi = end.min(chunk_start + span).max(c0);
                if c1 > c0 {
                    out.as_mut()[(c0 - offset) as usize..(c1 - offset) as usize].copy_from_slice(
                        &stable.as_ref()[(c0 - chunk_start) as usize..(c1 - chunk_start) as usize],
                    );
                }
                if copied_hi > c1 {
                    out.as_mut()[(c1 - offset) as usize..(copied_hi - offset) as usize].fill(0);
                }
            }
        }

        // Serve pending chunks from their overlay copies.
        for (lo, bytes) in &plan.splices {
            let at = (lo - offset) as usize;
            out.as_mut()[at..at + bytes.len()].copy_from_slice(bytes);
        }

        if !publish_read(blob, generation, &checked, unchecked) {
            invalidated += 1;
            continue 'retry;
        }
        return Ok(match caller.take() {
            Some(mut bufs) => {
                // SAFETY: `len` bytes are filled via copy_from_slice below.
                unsafe { bufs.set_len(len) };
                bufs.copy_from_slice(out.as_ref());
                bufs
            }
            None => out.into(),
        });
    }
}
