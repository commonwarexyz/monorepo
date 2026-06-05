//! Point reads, batched reads, and replay over a snapshot. Bounds are frozen at creation;
//! every in-bounds position stays readable for the reader's life, and a concurrent rewind
//! surfaces as a clean error, never torn bytes.

use super::Journal;
use crate::journal::contiguous::snapshot::{first_in_blob, BlobHandle, Snapshot};
use crate::{
    journal::{contiguous::metrics::FixedMetrics as Metrics, Error},
    Context,
};
use commonware_codec::{CodecFixedShared, DecodeExt as _, ReadExt as _};
use commonware_runtime::{
    buffer::paged::{self, Replay},
    Blob, Buf,
};
use commonware_utils::NZUsize;
use futures::{
    stream::{self, Stream},
    StreamExt,
};
use std::{
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

/// An owned snapshot of the journal. Bounds are frozen at creation and every position within
/// `bounds()` remains readable, including across a concurrent prune. A concurrent rewind below
/// the snapshot may surface as a read error, never as torn data.
pub struct Reader<E: Context, A> {
    pub(super) snapshot: Snapshot<E::Blob>,
    pub(super) items_per_blob: NonZeroU64,
    pub(super) metrics: Arc<Metrics<E>>,
    pub(super) _phantom: PhantomData<A>,
}

impl<E: Context, A: CodecFixedShared> Reader<E, A> {
    /// Resolve `pos` to its read handle and byte offset within the blob.
    fn locate(&self, pos: u64) -> Result<(BlobHandle<'_, E::Blob>, u64), Error> {
        self.snapshot.check_readable(pos)?;
        let items_per_blob = self.items_per_blob.get();
        let blob = pos / items_per_blob;
        let pos_in_blob =
            pos - first_in_blob(self.snapshot.pruning_boundary, blob, items_per_blob)?;
        let offset = Journal::<E, A>::items_to_bytes(pos_in_blob)?;
        let handle = self
            .snapshot
            .handle(blob)
            .ok_or_else(|| Error::Corruption(format!("blob {blob} missing from snapshot")))?;
        Ok((handle, offset))
    }

    /// Read the item at position `pos` in the journal.
    ///
    /// # Errors
    ///
    ///  - [Error::ItemPruned] if the item at position `pos` is pruned.
    ///  - [Error::ItemOutOfRange] if the item at position `pos` does not exist.
    async fn read_inner(&self, pos: u64) -> Result<A, Error> {
        let (handle, offset) = self.locate(pos)?;
        let bufs = handle.read_at(offset, A::SIZE).await?;
        A::decode(bufs.coalesce()).map_err(Error::Codec)
    }

    /// Read an item if it can be done synchronously (e.g. without I/O), returning `None`
    /// otherwise.
    fn try_read_sync_inner(&self, pos: u64) -> Option<A> {
        let mut buf = vec![0u8; A::SIZE];
        self.try_read_sync_into(pos, &mut buf)
    }

    /// Read an item synchronously using caller-provided buffer.
    fn try_read_sync_into(&self, pos: u64, buf: &mut [u8]) -> Option<A> {
        let (handle, offset) = self.locate(pos).ok()?;
        let buf = &mut buf[..A::SIZE];
        if !handle.try_read_sync(offset, buf) {
            return None;
        }
        A::decode(&buf[..]).ok()
    }
}

impl<E: Context, A: CodecFixedShared> crate::journal::contiguous::Reader for Reader<E, A> {
    type Item = A;

    fn bounds(&self) -> std::ops::Range<u64> {
        self.snapshot.bounds()
    }

    async fn read(&self, pos: u64) -> Result<A, Error> {
        let _timer = self.metrics.read_timer();
        self.metrics.read_calls.inc();

        // Serve from the page cache synchronously when possible, avoiding the async storage path.
        if let Some(item) = self.try_read_sync_inner(pos) {
            self.metrics.record_cache_hits(1);
            self.metrics.items_read.inc();
            return Ok(item);
        }
        self.metrics.record_cache_misses(1);

        let item = self.read_inner(pos).await?;
        self.metrics.items_read.inc();
        Ok(item)
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<A>, Error> {
        if positions.is_empty() {
            return Ok(Vec::new());
        }
        let _timer = self.metrics.read_many_timer();
        self.metrics.read_many_calls.inc();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "positions must be strictly increasing"
        );
        for &pos in positions {
            self.snapshot.check_readable(pos)?;
        }

        let items_per_blob = self.items_per_blob.get();
        let pruning_boundary = self.snapshot.pruning_boundary;
        let chunk_size = A::SIZE;

        // Phase 1: drain page-cache hits synchronously; record the misses.
        let mut result: Vec<Option<A>> = Vec::with_capacity(positions.len());
        let mut misses: Vec<Miss> = Vec::new();
        let mut sync_buf = vec![0u8; chunk_size];
        for (i, &pos) in positions.iter().enumerate() {
            if let Some(item) = self.try_read_sync_into(pos, &mut sync_buf) {
                result.push(Some(item));
            } else {
                result.push(None);
                misses.push(Miss {
                    result_index: i,
                    position: pos,
                });
            }
        }

        if misses.is_empty() {
            self.metrics.record_cache_hits(positions.len() as u64);
            self.metrics.items_read.inc_by(positions.len() as u64);
            return Ok(result.into_iter().map(|r| r.unwrap()).collect());
        }
        self.metrics
            .record_cache_hits((positions.len() - misses.len()) as u64);
        self.metrics.record_cache_misses(misses.len() as u64);

        // Phase 2: read the misses, batched per blob.
        let mut reusable_buf = vec![0u8; misses.len() * chunk_size];
        for group in group_by_blob(&misses, items_per_blob) {
            let blob = group[0].position / items_per_blob;
            let first_position = first_in_blob(pruning_boundary, blob, items_per_blob)?;
            let blob_offsets: Vec<u64> = group
                .iter()
                .map(|miss| Journal::<E, A>::items_to_bytes(miss.position - first_position))
                .collect::<Result<_, _>>()?;

            let handle = self
                .snapshot
                .handle(blob)
                .ok_or_else(|| Error::Corruption(format!("blob {blob} missing from snapshot")))?;
            let buf = &mut reusable_buf[..group.len() * chunk_size];
            handle
                .read_many_into(buf, &blob_offsets, NZUsize!(chunk_size))
                .await?;

            for (miss, slice) in group.iter().zip(buf.chunks_exact(chunk_size)) {
                let item = A::decode(slice).map_err(Error::Codec)?;
                result[miss.result_index] = Some(item);
            }
        }

        self.metrics.items_read.inc_by(positions.len() as u64);
        Ok(result.into_iter().map(|r| r.unwrap()).collect())
    }

    fn try_read_sync(&self, pos: u64) -> Option<A> {
        self.try_read_sync_inner(pos).map_or_else(
            || {
                self.metrics.record_cache_misses(1);
                None
            },
            |item| {
                self.metrics.record_cache_hits(1);
                self.metrics.try_read_sync_hits.inc();
                self.metrics.items_read.inc();
                Some(item)
            },
        )
    }

    async fn replay(
        &self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> Result<impl Stream<Item = Result<(u64, A), Error>> + Send, Error> {
        let items_per_blob = self.items_per_blob.get();
        let pruning_boundary = self.snapshot.pruning_boundary;
        let chunk_size = A::SIZE;
        let chunk_size_u64 = Journal::<E, A>::CHUNK_SIZE_U64;

        self.snapshot.check_cursor(start_pos)?;

        let start_blob = start_pos / items_per_blob;
        let start_pos_in_blob =
            start_pos - first_in_blob(pruning_boundary, start_blob, items_per_blob)?;

        // Check all middle blobs (not oldest, not tail) in range are complete. Sealed blob
        // sizes are known synchronously.
        let base = self.snapshot.base_blob;
        let tail_blob = self.snapshot.tail_blob();
        let first_to_check = base
            .checked_add(1)
            .map_or(tail_blob, |after_oldest| start_blob.max(after_oldest));
        for blob in first_to_check..tail_blob {
            let idx = (blob - base) as usize;
            let len = self.snapshot.sealed[idx].size() / chunk_size_u64;
            if len < items_per_blob {
                return Err(Error::Corruption(format!(
                    "blob {blob} incomplete: expected {items_per_blob} items, got {len}"
                )));
            }
        }

        // Seed each sealed blob's `Replay` upfront so the returned stream borrows nothing
        // from `self`. The tail is streamed through the snapshot's read handle instead: a
        // `Replay` reads physical pages from the blob and would miss the tail's buffered bytes.
        let mut per_blob_replays: Vec<(u64, Replay<E::Blob>, u64)> = Vec::new();
        for blob in start_blob..tail_blob.min(self.snapshot.size / items_per_blob) {
            let idx = (blob - base) as usize;
            let sealed = &self.snapshot.sealed[idx];
            let mut replay = sealed.replay(buffer).map_err(Error::Runtime)?;
            let initial_offset = if blob == start_blob {
                let start_byte = Journal::<E, A>::items_to_bytes(start_pos_in_blob)?;
                if start_byte > sealed.size() {
                    return Err(Error::ItemOutOfRange(start_pos));
                }
                replay.seek_to(start_byte).map_err(Error::Runtime)?;
                start_pos_in_blob
            } else {
                0
            };
            let blob_first = first_in_blob(pruning_boundary, blob, items_per_blob)?;
            per_blob_replays.push((blob_first, replay, initial_offset));
        }

        // Stream the sealed blobs in ascending order, fully draining each before the next.
        let sealed_stream =
            stream::iter(per_blob_replays).flat_map(move |(blob_first, replay, initial_position)| {
                // `unfold` repeatedly calls the closure below, threading `BlobReplayState`
                // through each call, to turn one blob's byte `Replay` into a stream of items.
                // Each call returns a *batch* of items (decoding several buffered items per await
                // is cheaper than one await per item); the trailing `flat_map(stream::iter)` then
                // flattens those batches back into a stream of individual items.
                stream::unfold(
                    BlobReplayState {
                        blob_first,
                        replay,
                        position: initial_position,
                        done: false,
                    },
                    move |mut state| async move {
                        // A previous call hit the blob's end or an error and set `done`.
                        // Returning `None` terminates this blob's stream.
                        if state.done {
                            return None;
                        }

                        let mut batch: Vec<Result<(u64, A), Error>> = Vec::new();
                        loop {
                            // Pull more bytes from the blob until at least one whole item is
                            // buffered (or the blob ends / a read fails).
                            match state.replay.ensure(chunk_size).await {
                                // At least one item's worth of bytes is buffered; decode below.
                                Ok(true) => {}
                                // Blob fully drained. Emit any items decoded so far, then stop.
                                Ok(false) => {
                                    state.done = true;
                                    return if batch.is_empty() {
                                        None
                                    } else {
                                        Some((batch, state))
                                    };
                                }
                                // Read failure: surface it as the blob's final item, then stop.
                                Err(err) => {
                                    batch.push(Err(Error::Runtime(err)));
                                    state.done = true;
                                    return Some((batch, state));
                                }
                            }

                            // Decode every whole item currently buffered.
                            while state.replay.remaining() >= chunk_size {
                                match A::read(&mut state.replay) {
                                    Ok(item) => {
                                        // Translate the item's index within this blob into its
                                        // absolute position in the journal.
                                        let global_pos = state
                                            .blob_first
                                            .checked_add(state.position)
                                            .ok_or(Error::OffsetOverflow);
                                        match global_pos {
                                            Ok(pos) => {
                                                batch.push(Ok((pos, item)));
                                                state.position += 1;
                                            }
                                            // Position overflow: emit the error and stop.
                                            Err(err) => {
                                                batch.push(Err(err));
                                                state.done = true;
                                                return Some((batch, state));
                                            }
                                        }
                                    }
                                    // Corrupt bytes: surface the decode error and stop the
                                    // blob.
                                    Err(err) => {
                                        batch.push(Err(Error::Codec(err)));
                                        state.done = true;
                                        return Some((batch, state));
                                    }
                                }
                            }

                            // Yield the decoded items. `ensure(chunk_size)` returning `Ok(true)`
                            // guarantees we decoded at least one, so `batch` is non-empty here;
                            // the guard simply keeps the loop from yielding an empty batch.
                            if !batch.is_empty() {
                                return Some((batch, state));
                            }
                        }
                    },
                )
                .flat_map(stream::iter)
            });

        // Stream the tail in `buffer`-sized batches, bounded by the snapshot `size`.
        let tail_first = first_in_blob(pruning_boundary, tail_blob, items_per_blob)?;
        let tail_start = if start_blob == tail_blob {
            start_pos
        } else {
            tail_first
        };
        let tail_state = TailReplayState {
            reader: self.snapshot.tail_reader.clone(),
            next_pos: tail_start.max(tail_first),
            end_pos: self.snapshot.size,
            tail_first,
        };
        let batch_items = (buffer.get() / chunk_size).max(1);
        let tail_stream = stream::unfold(tail_state, move |mut state| async move {
            if state.next_pos >= state.end_pos {
                return None;
            }
            let count = ((state.end_pos - state.next_pos) as usize).min(batch_items);
            let mut buf = vec![0u8; count * chunk_size];
            let byte_offset = match Journal::<E, A>::items_to_bytes(state.next_pos - state.tail_first)
            {
                Ok(offset) => offset,
                Err(err) => {
                    state.end_pos = state.next_pos;
                    return Some((vec![Err(err)], state));
                }
            };
            if let Err(err) = state.reader.read_into(&mut buf, byte_offset).await {
                state.end_pos = state.next_pos;
                return Some((vec![Err(Error::Runtime(err))], state));
            }
            let mut batch: Vec<Result<(u64, A), Error>> = Vec::with_capacity(count);
            for i in 0..count {
                let slice = &buf[i * chunk_size..(i + 1) * chunk_size];
                match A::decode(slice) {
                    Ok(item) => batch.push(Ok((state.next_pos + i as u64, item))),
                    Err(err) => {
                        batch.push(Err(Error::Codec(err)));
                        state.end_pos = state.next_pos;
                        return Some((batch, state));
                    }
                }
            }
            state.next_pos += count as u64;
            Some((batch, state))
        })
        .flat_map(stream::iter);

        Ok(sealed_stream.chain(tail_stream))
    }
}

/// A cache miss from `read_many`'s first phase: where the item goes and where it lives.
struct Miss {
    result_index: usize,
    position: u64,
}

/// Split the position-sorted misses into maximal runs sharing one blob.
fn group_by_blob(misses: &[Miss], items_per_blob: u64) -> impl Iterator<Item = &[Miss]> {
    misses.chunk_by(move |a, b| a.position / items_per_blob == b.position / items_per_blob)
}

/// State threaded through the `unfold` that replays a single sealed blob.
struct BlobReplayState<B: Blob> {
    /// First retained position in the blob; origin for emitted positions. Loop-invariant.
    blob_first: u64,
    /// Sequential reader over the blob's logical bytes.
    replay: Replay<B>,
    /// Index of the next item to emit, relative to `blob_first`.
    position: u64,
    /// Set once the blob is exhausted or an error was emitted; every later call returns `None`,
    /// terminating this blob's stream.
    done: bool,
}

/// State for the `unfold` that replays the tail through the snapshot's read handle.
struct TailReplayState<B: Blob> {
    reader: paged::Reader<B>,
    /// Next position to emit.
    next_pos: u64,
    /// One past the last position to emit: the snapshot's size. Set to `next_pos` after an
    /// error so every later call returns `None`, terminating the stream.
    end_pos: u64,
    /// First retained position in the tail; origin for byte offsets.
    tail_first: u64,
}
