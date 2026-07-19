//! Lazy loading of committed chunk checksums from a blob's checksum
//! extents.
//!
//! Hydration seeds chunk state without values (see
//! [`ChunkCrc::Unloaded`]), and the first read to verify a chunk loads the
//! covering page from the blob's committed checksum extents — the extent's
//! guard CRC is verified on the first touch of each ref — into a bounded
//! per-blob cache. A fully verified blob therefore holds bitmaps, not its
//! checksum array.

use super::{
    chunk::{ChunkCrc, CRC_PAGE_CHUNKS},
    layout::ChecksumRef,
    state::{BlobCore, BlobInner, Ready},
};
use crate::{Blob as _, Error};
use commonware_cryptography::{Crc32, Hasher as _};
use commonware_formatting::hex;

/// Decode a checksum extent's big-endian CRC values.
pub(super) fn decode_crcs(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
}

/// Read the value window `[w0, w1)` (chunk indexes relative to
/// `r.first_chunk`) of committed checksum extent `r`. With `verify` set,
/// the WHOLE extent is streamed to compute its guard CRC, returned for the
/// caller to check. Otherwise only the window's bytes are read.
async fn read_ref_window<S: crate::Storage>(
    ready: &Ready<S>,
    r: &ChecksumRef,
    w0: u64,
    w1: u64,
    verify: bool,
) -> Result<(Vec<u32>, Option<u32>), Error> {
    if !verify {
        let bytes = ready
            .file
            .read_at(r.offset + w0 * 4, ((w1 - w0) * 4) as usize)
            .await?
            .coalesce();
        return Ok((decode_crcs(bytes.as_ref()).collect(), None));
    }
    /// Streaming step for guard verification of large extents.
    const STEP: u64 = 1 << 22;
    let mut hasher = Crc32::new();
    let mut values = Vec::with_capacity((w1 - w0) as usize);
    let total = r.count as u64 * 4;
    let mut pos = 0;
    while pos < total {
        let len = STEP.min(total - pos);
        let bytes = ready.file.read_at(r.offset + pos, len as usize).await?;
        let bytes = bytes.coalesce();
        hasher.update(bytes.as_ref());
        // Capture the window's intersection with this step.
        let lo = (w0 * 4).max(pos);
        let hi = (w1 * 4).min(pos + len);
        if hi > lo {
            values.extend(decode_crcs(
                &bytes.as_ref()[(lo - pos) as usize..(hi - pos) as usize],
            ));
        }
        pos += len;
    }
    Ok((values, Some(hasher.finalize().as_u32())))
}

/// Record and report a checksum extent whose guard CRC failed: counted in
/// the corruption metric, loud like every mismatch (fused so no report can
/// forget the counter).
fn ref_mismatch<S: crate::Storage>(ready: &Ready<S>, blob: &BlobCore, r: &ChecksumRef) -> Error {
    ready.metrics.corruptions.inc();
    Error::BlobCorrupt(
        blob.partition.clone(),
        hex(&blob.name),
        format!(
            "checksum extent mismatch (chunks {}..{} at offset {})",
            r.first_chunk,
            r.first_chunk + r.count as u64,
            r.offset
        ),
    )
}

/// Load the committed-CRC page covering `chunk` from the blob's checksum
/// extents into its cache, returning the loaded window as
/// `(first chunk, values)`.
///
/// Returns `Ok(None)` when the chunk no longer holds an unloaded CRC
/// (rewritten or shrunk away meanwhile): the caller re-derives its plan.
///
/// The extent's guard CRC is verified on the first touch of each ref (the
/// whole extent is streamed once). Later loads from the same ref read just
/// the page window. Loads race commits, which swap the committed entry and
/// release superseded extents for reuse: like the data path's generation
/// protocol, the ref is re-checked against the then-current committed
/// entry after the read, and `commit::finalize` swaps entries BEFORE
/// applying frees, so a ref that is still referenced was never freed
/// during the read. A removed blob's extents are gated on its open handles
/// (every caller reaches this through one).
///
/// Callers box this future (a cold path): inlining its streaming reads
/// would deepen every read and write future's layout.
pub(super) async fn load_committed_page<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    chunk: u64,
) -> Result<Option<(u64, Vec<u32>)>, Error> {
    loop {
        let (r, verify) = {
            let inner = blob.inner.lock();
            match inner.crcs().get(chunk).map(|s| s.crc) {
                Some(ChunkCrc::Unloaded) => {}
                _ => return Ok(None),
            }
            let covering = inner.committed_entry().and_then(|e| {
                e.checksums
                    .iter()
                    .find(|r| r.first_chunk <= chunk && chunk < r.first_chunk + r.count as u64)
            });
            let Some(r) = covering else {
                // Hydration validates that the committed refs cover every
                // committed chunk, and residency is never revoked: an
                // unloaded chunk outside the refs is a bug, never a
                // reachable disk state.
                unreachable!("unloaded chunk outside committed checksum coverage")
            };
            (*r, !inner.crc_guarded().contains(r))
        };
        let page = chunk / CRC_PAGE_CHUNKS;
        let w0 = (page * CRC_PAGE_CHUNKS).max(r.first_chunk) - r.first_chunk;
        let w1 = ((page + 1) * CRC_PAGE_CHUNKS).min(r.first_chunk + r.count as u64) - r.first_chunk;
        let (values, guard) = read_ref_window(ready, &r, w0, w1, verify).await?;
        {
            let mut inner = blob.inner.lock();
            // A commit swapped the entry mid-read (the extent may have been
            // recycled): retry against the current refs.
            if !inner
                .committed_entry()
                .is_some_and(|e| e.checksums.contains(&r))
            {
                continue;
            }
            if let Some(guard) = guard {
                if guard != r.crc {
                    return Err(ref_mismatch(ready, blob, &r));
                }
                inner.record_guarded(r);
            }
            inner
                .crc_cache_mut()
                .insert(r.first_chunk + w0, values.clone());
        }
        return Ok(Some((r.first_chunk + w0, values)));
    }
}

/// The COW-style memo for one chunk's committed CRC: loaded outside the
/// locks, memoized, and the caller's plan re-derived. The target chunk is
/// fixed by the caller's position, so the memo guarantees the second
/// attempt resolves even if the bounded CRC cache evicts the loaded page
/// meanwhile.
pub(super) struct CrcMemo(Option<(u64, u32)>);

impl CrcMemo {
    pub const fn new() -> Self {
        Self(None)
    }

    /// The chunk's expected committed CRC when known: the memo (exact
    /// chunk only), else the blob's committed-CRC cache.
    pub fn lookup(&self, inner: &mut BlobInner, chunk: u64) -> Option<u32> {
        self.0
            .filter(|&(c, _)| c == chunk)
            .map(|(_, crc)| crc)
            .or_else(|| inner.crc_cache_mut().get(chunk))
    }

    /// Load the committed page covering `chunk` and memoize its value (a
    /// no-op when the chunk stopped being unloaded meanwhile). Boxed
    /// internally: the cold streaming loader must not deepen the calling
    /// future's layout.
    pub async fn load<S: crate::Storage>(
        &mut self,
        ready: &Ready<S>,
        blob: &BlobCore,
        chunk: u64,
    ) -> Result<(), Error> {
        if let Some((first, values)) = Box::pin(load_committed_page(ready, blob, chunk)).await? {
            self.0 = Some((chunk, values[(chunk - first) as usize]));
        }
        Ok(())
    }
}

/// Load the full contents of the committed checksum refs `refs`
/// (guard-verified) for a capture's read-modify-write of a full checksum
/// rewrite: chunks untouched this process keep their CRC only on disk, and
/// re-encoding the array needs every value. The caller must hold the
/// commit lock and the blob's write lock, under which the refs' extents
/// stay referenced (their frees are queued by this capture at the earliest
/// and applied only once this commit confirms).
pub(super) async fn load_committed_refs<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    refs: &[ChecksumRef],
) -> Result<Vec<(u64, Vec<u32>)>, Error> {
    let mut out = Vec::with_capacity(refs.len());
    for r in refs {
        let (values, guard) = read_ref_window(ready, r, 0, r.count as u64, true).await?;
        if guard.expect("full reads verify") != r.crc {
            return Err(ref_mismatch(ready, blob, r));
        }
        let mut inner = blob.inner.lock();
        inner.record_guarded(*r);
        out.push((r.first_chunk, values));
    }
    Ok(out)
}

/// The committed value of `chunk` within loaded windows (sorted by first
/// chunk, non-overlapping).
pub(super) fn window_value(windows: &[(u64, Vec<u32>)], chunk: u64) -> Option<u32> {
    let i = windows.partition_point(|(first, _)| *first <= chunk);
    let (first, values) = &windows[i.checked_sub(1)?];
    values.get((chunk - first) as usize).copied()
}

/// Insert `window` into a sorted window list (replacing an identical
/// start).
pub(super) fn insert_window(windows: &mut Vec<(u64, Vec<u32>)>, window: (u64, Vec<u32>)) {
    let i = windows.partition_point(|(first, _)| *first < window.0);
    if windows.get(i).is_some_and(|(first, _)| *first == window.0) {
        windows[i] = window;
    } else {
        windows.insert(i, window);
    }
}
