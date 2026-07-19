//! Resize: growth zero-fills through the write path; shrink classifies the
//! surviving frontier chunk, reads back from disk only when the frontier's
//! bytes are not already in RAM (checking against the chunk's expected
//! CRC), and republishes the truncated state.

use super::{
    alloc::{block_align, Extent},
    chunk::{chunk_of, ChunkCrc, ChunkState},
    paging::load_committed_page,
    state::{check_not_removed, chunk_mismatch, zeroed, BlobCore, Ready},
    write::write_locked,
    BLOCK,
};
use crate::{Blob as _, Error};
use commonware_cryptography::Crc32;

/// Resize to `len`. The blob's `write_lock` MUST be held.
pub(super) async fn resize_locked<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    len: u64,
) -> Result<(), Error> {
    ready.check_poisoned()?;
    check_not_removed(blob)?;
    // Chunk-end representability, as in `write_locked`.
    if len > u64::MAX - BLOCK {
        return Err(Error::OffsetOverflow);
    }
    let old_size = blob.inner.lock().size();

    if len >= old_size {
        // Zero extension: physically zero the backed portion of the
        // boundary chunk in [old_size, len) through the normal write path
        // (the residue there is arbitrary and the table would otherwise
        // vouch for zeros it never wrote); unbacked regions become holes.
        let zero_to = {
            let inner = blob.inner.lock();
            let boundary = chunk_of(old_size);
            match inner.chunk_span(boundary) {
                Some(_) if !old_size.is_multiple_of(BLOCK) => ((boundary + 1) * BLOCK).min(len),
                _ => old_size,
            }
        };
        if zero_to > old_size {
            let zeros = zeroed(&ready.pool, (zero_to - old_size) as usize);
            write_locked(ready, blob, old_size, zeros).await?;
        }
        let mut state = ready.state.lock();
        let mut inner = blob.inner.lock();
        // A removal raced the resize: adopt nothing (see `publish_stretch`).
        if !inner.removed() {
            inner.grow_to(len);
            state.mark_dirty(blob.id);
        }
        return Ok(());
    }

    // Shrink: drop runs beyond the new size, trim the boundary run, refresh
    // the tail buffer to the post-shrink FRONTIER (the last backed chunk,
    // which may sit below unbacked hole chunks when the new size lands in a
    // hole) and the frontier chunk's CRC. Dropped extents are capture-gated:
    // the confirmed table may still reference them through this blob's
    // cached committed entry.
    //
    // The fallible read-back runs BEFORE any state is published: a failure
    // leaves the blob exactly as it was (clean unwind, never a poisonous
    // half-shrink).

    /// How the tail buffer is refreshed for the post-shrink frontier.
    enum Frontier {
        /// No backed chunk survives: clear the tail.
        Empty,
        /// The tail buffer already describes the frontier chunk and its
        /// span is unchanged by the shrink: keep it (process memory).
        Keep { chunk: u64 },
        /// The tail buffer holds the frontier chunk's full current span
        /// and the shrink trims it mid-chunk: slice the surviving prefix
        /// from process memory and recompute its CRC (no I/O, no
        /// re-check).
        Trim {
            chunk: u64,
            span: u64,
            verified: bool,
        },
        /// Read the frontier chunk's CURRENT span (`old_span`) back from
        /// disk and check it against `expected` — rot in the span
        /// surfaces loudly here, never laundered under the recomputed
        /// prefix CRC. The surviving `span` is the read's prefix.
        /// `verified` is the provenance the post-shrink state carries
        /// (the expected CRC's own, see [`expected_span_crc`]); a state
        /// installs when the span changed or the checked value was never
        /// resident (the frontier's CRC must be resolvable at capture).
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

    // The COW-style memo for an unloaded frontier CRC (see `plan_stretch`).
    let mut loaded_crc: Option<(u64, u32)> = None;
    let frontier = loop {
        let outcome = {
            let mut inner = blob.inner.lock();
            // Deferred CRCs do not survive the shrink bookkeeping below:
            // finalize every pending chunk now so the frontier's CRC state
            // is resolvable (the overlay itself is dropped at publish).
            inner.overlay_finalize();

            // The last run surviving the shrink (runs at or beyond `len`
            // drop; a run below `len` survives, trimmed to `len - l`).
            let Some((&l, run)) = inner.runs().range(..len).next_back() else {
                break Frontier::Empty;
            };
            let post_len = run.len.min(len - l);
            let chunk = chunk_of(l + post_len - 1);
            let chunk_start = chunk * BLOCK;
            let phys = run.physical + (chunk_start - l);
            let span = l + post_len - chunk_start;
            let old_span = (l + run.len - chunk_start).min(BLOCK);
            // The tail buffer holding the chunk's full current span needs
            // no read and no re-check (its bytes are the span's
            // authoritative content), trimmed or not.
            if inner.tail_chunk() == chunk && inner.tail().len() as u64 == old_span {
                if span == old_span {
                    break Frontier::Keep { chunk };
                }
                let verified = inner
                    .crcs()
                    .get(chunk)
                    .expect("backed chunk has crc")
                    .verified;
                break Frontier::Trim {
                    chunk,
                    span,
                    verified,
                };
            }
            // No overlay probe here, unlike the staged shrink in
            // `Batch::resize`: the tail buffer's invariant — it always
            // describes the frontier chunk — covers the dominant shape,
            // and a mid-blob chunk becomes the frontier only through this
            // very shrink. That rare overlay-resident case falls through
            // to the CHECKED read-back below (correct, one extra read).
            // The staged sibling serves its overlay too because staged
            // chunks are routinely overlay-backed.
            let state = inner.crcs().get(chunk).expect("backed chunk has crc");
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
                // Pending chunks were finalized above.
                ChunkCrc::Pending => unreachable!("pending CRC after overlay finalize"),
                // Untouched since hydration: the expected CRC is the
                // committed value — the authoritative one, so checking
                // the read-back against it IS the chunk's verification.
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
        if let Some((first, values)) = Box::pin(load_committed_page(ready, blob, outcome)).await? {
            loaded_crc = Some((outcome, values[(outcome - first) as usize]));
        }
    };

    // Perform the read-back (the only fallible step) before publishing.
    let tail = match frontier {
        Frontier::Empty => None,
        Frontier::Keep { chunk } => {
            let inner = blob.inner.lock();
            Some((chunk, inner.tail().to_vec(), None))
        }
        Frontier::Trim {
            chunk,
            span,
            verified,
        } => {
            let inner = blob.inner.lock();
            let bytes = inner.tail()[..span as usize].to_vec();
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
            let bytes = ready
                .file
                .read_at(phys, old_span as usize)
                .await?
                .coalesce();
            // The chunk's current span must match its expected CRC: rot
            // in it surfaces loudly here, never laundered under the
            // recomputed prefix CRC.
            if Crc32::checksum(bytes.as_ref()) != expected {
                return Err(chunk_mismatch(ready, blob, chunk));
            }
            let bytes = bytes.as_ref()[..span as usize].to_vec();
            let trimmed = span < old_span;
            // (Re)install the frontier state when the span changed or the
            // checked value was never resident: the frontier chunk's CRC
            // must be resolvable at capture without a preload.
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

    // Publish the shrink (pure RAM, infallible).
    {
        let mut state = ready.state.lock();
        let mut inner = blob.inner.lock();

        // A removal raced the resize: adopt nothing (see
        // `publish_stretch`).
        if inner.removed() {
            return Ok(());
        }

        // Overlay entries do not survive a shrink (spans at and beyond the
        // boundary move); their pending CRCs were finalized above.
        inner.clear_overlay();

        for run in inner.split_runs_from(len).into_values() {
            inner.defer_content_free(Extent {
                offset: run.physical,
                len: run.capacity,
            });
        }
        if let Some((l, mut run)) = inner.covering(len.saturating_sub(1)).filter(|_| len > 0) {
            if l + run.len > len {
                run.len = len - l;
                let keep = block_align(run.len);
                if run.capacity > keep {
                    let trimmed = Extent {
                        offset: run.physical + keep,
                        len: run.capacity - keep,
                    };
                    run.capacity = keep;
                    inner.defer_content_free(trimmed);
                }
                inner.install_run(l, run);
            }
        }
        match tail {
            None => {
                inner.crcs_mut().clear();
                inner.retain_dirty_chunks(|_| false);
                inner.set_tail(0, Vec::new());
            }
            Some((chunk, bytes, refreshed)) => {
                inner.crcs_mut().truncate(chunk);
                if let Some(state) = refreshed {
                    inner.crcs_mut().insert(chunk, state);
                }
                // The (possibly newly partial) frontier must re-commit: its
                // shadow changes even when its bytes do not.
                inner.retain_dirty_chunks(|&c| c <= chunk);
                inner.mark_chunk_dirty(chunk);
                inner.set_tail(chunk, bytes);
            }
        }
        inner.bump_generation();
        inner.set_size(len);
        state.mark_dirty(blob.id);
    }
    Ok(())
}
