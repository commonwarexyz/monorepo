//! The blob handle: translates blob offsets to chunk offsets in the volume file.
//!
//! All handles to one name share one [Core], so clones and independently opened handles
//! observe each other's writes immediately (a superset of the per-file backends'
//! guarantees, which the trait permits).
//!
//! Locking: a blob's state lock is held only to resolve offsets, stage changes, and pin
//! chunks; never across I/O. Payload I/O happens against pinned chunks, so a concurrent
//! shrink or delete can free them without any risk of the allocator handing them to
//! another blob mid-syscall.

use super::{
    committer::Request,
    state::{Core, PinGuard},
    volume::Volume,
};
use crate::{Error, Handle, IoBufs, IoBufsMut, WriteOptions};
use bytes::Buf as _;
use commonware_formatting::hex;
use commonware_utils::channel::oneshot;
use std::sync::{Arc, atomic::Ordering};

/// A blob stored inside a volume.
pub struct Blob<S: crate::Storage> {
    volume: Volume<S>,
    core: Arc<Core>,
}

impl<S: crate::Storage> Clone for Blob<S> {
    fn clone(&self) -> Self {
        Self {
            volume: self.volume.clone(),
            core: self.core.clone(),
        }
    }
}

/// One contiguous piece of a blob range: a chunk-file range, or zeros where no chunk is
/// mapped (or the mapped chunk's bytes were never written).
struct Span {
    /// Offset in the volume file, or `None` for zeros.
    phys: Option<u64>,
    len: usize,
}

impl<S: crate::Storage> Blob<S> {
    pub(super) const fn new(volume: Volume<S>, core: Arc<Core>) -> Self {
        Self { volume, core }
    }

    fn missing(&self) -> Error {
        Error::BlobMissing(self.volume.shared.partition.clone(), hex(&self.core.name))
    }

    fn poisoned(&self) -> Error {
        Error::BlobSyncFailed(
            self.volume.shared.partition.clone(),
            hex(&self.core.name),
            Arc::new(std::io::Error::other(
                "volume poisoned by an earlier commit failure",
            )),
        )
    }

    /// Resolve `[offset, offset + len)` into spans, pinning every touched chunk.
    ///
    /// Fails if the range extends past the blob's length.
    fn resolve(&self, offset: u64, len: usize) -> Result<(Vec<Span>, PinGuard), Error> {
        let geometry = self.volume.shared.geometry;
        let state = self.core.state.lock();
        let end = offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;
        if end > state.len {
            return Err(Error::BlobInsufficientLength);
        }

        let mut spans = Vec::new();
        let mut chunks = Vec::new();
        let mut pos = offset;
        while pos < end {
            let slot = geometry.slot_of(pos);
            let within = pos - slot * u64::from(geometry.chunk_size);
            let span_len = ((end - pos).min(u64::from(geometry.chunk_size) - within)) as usize;
            let phys = state.map.get(&(slot as u32)).map(|&chunk| {
                chunks.push(chunk);
                geometry.chunk_offset(chunk) + within
            });
            spans.push(Span {
                phys,
                len: span_len,
            });
            pos += span_len as u64;
        }
        let guard = self.volume.shared.pins.pin(chunks);
        Ok((spans, guard))
    }

    /// Enqueue a durability request for this blob.
    fn request(&self) -> Result<oneshot::Receiver<Result<(), Error>>, Error> {
        if self.core.state.lock().removed {
            return Err(self.missing());
        }
        if self.volume.shared.poisoned.load(Ordering::Acquire) {
            return Err(self.poisoned());
        }
        let (done, receiver) = oneshot::channel();
        self.volume
            .requests
            .send(Request::Sync {
                core: self.core.clone(),
                done,
            })
            .map_err(|_| self.poisoned())?;
        Ok(receiver)
    }
}

impl<S: crate::Storage> crate::Blob for Blob<S> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.read_at_buf(offset, len, crate::IoBufMut::with_capacity(len))
            .await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let mut bufs = bufs.into();
        let (spans, guard) = self.resolve(offset, len)?;
        let shared = &self.volume.shared;
        let high_water = shared.high_water.get();

        // Fast path: one mapped span, fully below the high-water mark, into a single
        // buffer reads straight from the file with no copy.
        if let [
            Span {
                phys: Some(phys),
                len: span_len,
            },
        ] = spans[..]
        {
            debug_assert_eq!(span_len, len);
            if phys + len as u64 <= high_water && bufs.is_single() {
                let result = shared.file.read_at_buf(phys, len, bufs).await;
                drop(guard);
                return result;
            }
        }

        // General path: assemble into a scratch buffer (zeros fill unmapped spans and
        // anything above the high-water mark), then copy into the caller's layout.
        let mut scratch = vec![0u8; len];
        let mut pos = 0usize;
        for span in spans {
            if let Some(phys) = span.phys {
                let readable = (high_water.saturating_sub(phys).min(span.len as u64)) as usize;
                if readable > 0 {
                    let read = shared.file.read_at(phys, readable).await?.coalesce();
                    scratch[pos..pos + readable].copy_from_slice(read.as_ref());
                }
            }
            pos += span.len;
        }
        drop(guard);

        // SAFETY: `copy_from_slice` fills exactly `len` bytes below.
        unsafe { bufs.set_len(len) };
        bufs.copy_from_slice(&scratch);
        Ok(bufs)
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let mut bufs = bufs.into();
        if !bufs.has_remaining() {
            return Ok(());
        }
        let shared = &self.volume.shared;
        if shared.poisoned.load(Ordering::Acquire) {
            return Err(self.poisoned());
        }
        let geometry = shared.geometry;
        let end = offset
            .checked_add(bufs.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        if geometry.slot_of(end - 1) > u64::from(u32::MAX) {
            return Err(Error::OffsetOverflow);
        }

        // Stage: allocate chunks for untouched slots, extend the length, split the
        // payload at chunk seams, and pin everything before releasing the lock.
        let (writes, guard) = {
            let mut state = self.core.state.lock();
            if state.removed {
                return Err(self.missing());
            }

            let first = geometry.slot_of(offset) as u32;
            let last = geometry.slot_of(end - 1) as u32;
            let missing: Vec<u32> = (first..=last)
                .filter(|slot| !state.map.contains_key(slot))
                .collect();
            // Bounding a blob's mapped slots keeps its snapshot row within one record.
            if state.map.len() + missing.len() > super::format::MAX_MAPPED_SLOTS {
                return Err(Error::OffsetOverflow);
            }
            let chunks = shared.allocator.lock().allocate(missing.len());
            for (&slot, &chunk) in missing.iter().zip(&chunks) {
                state.map.insert(slot, chunk);
                state.staged_mappings.push((slot, chunk));
            }
            state.len = state.len.max(end);

            let mut writes = Vec::with_capacity((last - first + 1) as usize);
            let mut touched = Vec::with_capacity(writes.capacity());
            let mut pos = offset;
            while pos < end {
                let slot = geometry.slot_of(pos);
                let within = pos - slot * u64::from(geometry.chunk_size);
                let span_len = (end - pos).min(u64::from(geometry.chunk_size) - within);
                let chunk = state.map[&(slot as u32)];
                let phys = geometry.chunk_offset(chunk) + within;
                touched.push(chunk);
                writes.push((phys, span_len, bufs.split_to(span_len as usize)));
                pos += span_len;
            }
            (writes, shared.pins.pin(touched))
        };

        let inner_options = options.without(WriteOptions::SYNC);
        for (phys, span_len, payload) in writes {
            shared.file.write_at(phys, payload, inner_options).await?;
            shared.high_water.extend(phys + span_len);
        }
        drop(guard);

        if options.contains(WriteOptions::SYNC) {
            self.sync().await?;
        }
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let shared = &self.volume.shared;
        if shared.poisoned.load(Ordering::Acquire) {
            return Err(self.poisoned());
        }
        let geometry = shared.geometry;
        // Slot indices must fit u32 (the same bound `write_at` enforces); reads rely
        // on the length never exceeding it.
        if len > 0 && geometry.slot_of(len - 1) > u64::from(u32::MAX) {
            return Err(Error::OffsetOverflow);
        }
        let within = len % u64::from(geometry.chunk_size);

        // A shrink that keeps part of a mapped boundary chunk replaces that chunk: the
        // retained prefix is copied into a fresh (durably zero) chunk before anything
        // becomes visible, so the invariant that a mapped chunk's bytes at or beyond
        // the blob's length are zero holds structurally — with no in-place zeroing
        // whose loss or reordering a reader or a crash could observe. Nothing mutates
        // until the publish step below, so a future dropped mid-copy changes no state
        // (at worst one fresh chunk is stranded until the next open re-derives it).
        let copied = {
            let state = self.core.state.lock();
            if state.removed {
                return Err(self.missing());
            }
            if len < state.len && within != 0 {
                state
                    .map
                    .get(&(geometry.slot_of(len) as u32))
                    .map(|&old| (old, shared.pins.pin(vec![old])))
            } else {
                None
            }
        };
        let replacement = match copied {
            None => None,
            Some((old, guard)) => {
                let fresh = shared.allocator.lock().allocate(1)[0];
                let src = geometry.chunk_offset(old);
                let dst = geometry.chunk_offset(fresh);
                // Clamp like any read: bytes above the high-water mark are zeros, and
                // the fresh chunk already holds zeros.
                let readable = (shared.high_water.get().saturating_sub(src)).min(within) as usize;
                if readable > 0 {
                    let prefix = shared.file.read_at(src, readable).await?;
                    shared
                        .file
                        .write_at(dst, prefix.freeze(), WriteOptions::default())
                        .await?;
                    // The copy must be durable before its remap can be journaled: the
                    // remap redirects previously acknowledged bytes, and a crash could
                    // keep the record while dropping an unbarriered copy, replaying
                    // acknowledged data into zeros. A failed barrier leaves the file's
                    // cache state unknowable, so it poisons the volume like any other.
                    if let Err(error) = shared.file.sync().await {
                        shared.poisoned.store(true, Ordering::Release);
                        return Err(error);
                    }
                    shared.high_water.extend(dst + readable as u64);
                }
                drop(guard);
                Some((old, fresh))
            }
        };

        // Publish. Everything below is one critical section; state may have moved while
        // copying (concurrent mutations of one blob have unspecified content), so the
        // replacement applies only if the boundary still holds the chunk it was copied
        // from and this is still a shrink.
        let (unused, removed) = {
            let mut state = self.core.state.lock();
            let mut unused = replacement.map(|(_, fresh)| fresh);
            if state.removed {
                (unused, true)
            } else {
                if len < state.len {
                    state.staged_floor = state.staged_floor.min(len);
                    // A cut past u32 means no slot is wholly beyond the new length.
                    if let Ok(cut) = u32::try_from(geometry.slots_of_len(len)) {
                        let freed = state.map.split_off(&cut);
                        state.staged_mappings.retain(|(slot, _)| *slot < cut);
                        state.staged_free.extend(freed.into_values());
                    }

                    if let Some((old, fresh)) = replacement {
                        let slot = geometry.slot_of(len) as u32;
                        if state.map.get(&slot) == Some(&old) {
                            state.map.insert(slot, fresh);
                            state.staged_free.push(old);
                            state.staged_mappings.retain(|(s, _)| *s != slot);
                            state.staged_mappings.push((slot, fresh));
                            unused = None;
                        }
                    }
                }
                state.len = len;
                (unused, false)
            }
        };
        if let Some(fresh) = unused {
            // The copy went stale (or was never a shrink by publish time). The chunk
            // was never mapped or journaled, but it is no longer zero.
            shared.allocator.lock().release(fresh);
        }
        if removed {
            return Err(self.missing());
        }
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let receiver = self.request()?;
        receiver.await.map_err(|_| self.poisoned())?
    }

    async fn start_sync(&self) -> Handle<()> {
        match self.request() {
            Ok(receiver) => Handle::from_receiver(receiver),
            Err(error) => Handle::ready(Err(error)),
        }
    }
}
