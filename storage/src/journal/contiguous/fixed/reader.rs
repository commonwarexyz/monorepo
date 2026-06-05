//! The snapshot consumer: point reads, batched reads, and replay.

use super::{
    first_in_blob,
    state::{Shared, Snapshot},
    Journal,
};
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
    num::NonZeroUsize,
    sync::{atomic::Ordering, Arc},
};

/// An owned snapshot of the journal. Bounds are frozen at creation and every position within
/// `bounds()` remains readable, including across a concurrent prune. A concurrent rewind below
/// the snapshot may surface as a read error, never as torn data.
pub struct Reader<E: Context, A> {
    pub(super) snapshot: Snapshot<E::Blob>,
    pub(super) metrics: Arc<Metrics<E>>,
    pub(super) shared: Arc<Shared<E::Blob>>,
    pub(super) _phantom: PhantomData<A>,
}

impl<E: Context, A> Drop for Reader<E, A> {
    fn drop(&mut self) {
        self.shared.readers.fetch_sub(1, Ordering::Release);
    }
}

impl<E: Context, A: CodecFixedShared> Reader<E, A> {
    /// Read the item at position `pos` in the journal.
    ///
    /// # Errors
    ///
    ///  - [Error::ItemPruned] if the item at position `pos` is pruned.
    ///  - [Error::ItemOutOfRange] if the item at position `pos` does not exist.
    async fn read_inner(&self, pos: u64) -> Result<A, Error> {
        let (handle, offset) = self.snapshot.locate(pos, Journal::<E, A>::CHUNK_SIZE_U64)?;
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
        let (handle, offset) = self
            .snapshot
            .locate(pos, Journal::<E, A>::CHUNK_SIZE_U64)
            .ok()?;
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
        // Validate all positions.
        for &pos in positions {
            if pos >= self.snapshot.size {
                return Err(Error::ItemOutOfRange(pos));
            }
            if pos < self.snapshot.table.pruning_boundary {
                return Err(Error::ItemPruned(pos));
            }
        }

        let items_per_blob = self.snapshot.items_per_blob.get();
        let pruning_boundary = self.snapshot.table.pruning_boundary;
        let chunk_size = A::SIZE;
        let chunk_size_u64 = Journal::<E, A>::CHUNK_SIZE_U64;

        // Phase 1: Drain page-cache hits synchronously.
        let mut result: Vec<Option<A>> = Vec::with_capacity(positions.len());
        let mut miss_indices: Vec<usize> = Vec::new();
        let mut miss_positions: Vec<u64> = Vec::new();

        let mut sync_buf = vec![0u8; chunk_size];
        for (i, &pos) in positions.iter().enumerate() {
            if let Some(item) = self.try_read_sync_into(pos, &mut sync_buf) {
                result.push(Some(item));
            } else {
                result.push(None);
                miss_indices.push(i);
                miss_positions.push(pos);
            }
        }

        if miss_positions.is_empty() {
            self.metrics.record_cache_hits(positions.len() as u64);
            self.metrics.items_read.inc_by(positions.len() as u64);
            return Ok(result.into_iter().map(|r| r.unwrap()).collect());
        }
        self.metrics
            .record_cache_hits((positions.len() - miss_positions.len()) as u64);
        self.metrics
            .record_cache_misses(miss_positions.len() as u64);

        // Phase 2: Read cache misses grouped by blob (sequential).
        let mut reusable_buf = vec![0u8; miss_positions.len() * chunk_size];
        let mut disk_offset = 0;

        let mut group_start = 0;
        while group_start < miss_positions.len() {
            let blob = miss_positions[group_start] / items_per_blob;

            let mut group_end = group_start + 1;
            while group_end < miss_positions.len()
                && miss_positions[group_end] / items_per_blob == blob
            {
                group_end += 1;
            }

            let group_len = group_end - group_start;
            let first_position = first_in_blob(pruning_boundary, blob, items_per_blob)?;
            let blob_offsets: Vec<u64> = miss_positions[group_start..group_end]
                .iter()
                .map(|&pos| {
                    (pos - first_position)
                        .checked_mul(chunk_size_u64)
                        .ok_or(Error::OffsetOverflow)
                })
                .collect::<Result<_, _>>()?;

            let handle =
                self.snapshot.table.handle(blob).ok_or_else(|| {
                    Error::Corruption(format!("blob {blob} missing from snapshot"))
                })?;
            let buf = &mut reusable_buf[..group_len * chunk_size];
            handle
                .read_many_into(buf, &blob_offsets, NZUsize!(chunk_size))
                .await?;

            for i in 0..group_len {
                let slice = &buf[i * chunk_size..(i + 1) * chunk_size];
                let item = A::decode(slice).map_err(Error::Codec)?;
                result[miss_indices[disk_offset + i]] = Some(item);
            }

            disk_offset += group_len;
            group_start = group_end;
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
        let items_per_blob = self.snapshot.items_per_blob.get();
        let pruning_boundary = self.snapshot.table.pruning_boundary;
        let chunk_size = A::SIZE;
        let chunk_size_u64 = Journal::<E, A>::CHUNK_SIZE_U64;

        // Validate bounds.
        if start_pos > self.snapshot.size {
            return Err(Error::ItemOutOfRange(start_pos));
        }
        if start_pos < pruning_boundary {
            return Err(Error::ItemPruned(start_pos));
        }

        let start_blob = start_pos / items_per_blob;
        let start_pos_in_blob =
            start_pos - first_in_blob(pruning_boundary, start_blob, items_per_blob)?;

        // Check all middle blobs (not oldest, not tail) in range are complete. Sealed blob
        // sizes are known synchronously.
        let base = self.snapshot.table.base_blob;
        let tail_blob = self.snapshot.table.tail_blob();
        let first_to_check = base
            .checked_add(1)
            .map_or(tail_blob, |after_oldest| start_blob.max(after_oldest));
        for blob in first_to_check..tail_blob {
            let idx = (blob - base) as usize;
            let len = self.snapshot.table.sealed[idx].size() / chunk_size_u64;
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
            let sealed = &self.snapshot.table.sealed[idx];
            let mut replay = sealed.replay(buffer).map_err(Error::Runtime)?;
            let initial_offset = if blob == start_blob {
                let start_byte = start_pos_in_blob
                    .checked_mul(chunk_size_u64)
                    .ok_or(Error::OffsetOverflow)?;
                if start_byte > sealed.size() {
                    return Err(Error::ItemOutOfRange(start_pos));
                }
                replay.seek_to(start_byte).map_err(Error::Runtime)?;
                start_pos_in_blob
            } else {
                0
            };
            per_blob_replays.push((blob, replay, initial_offset));
        }

        // Stream the sealed blobs in ascending order, fully draining each before the next.
        let sealed_stream =
            stream::iter(per_blob_replays).flat_map(move |(blob, replay, initial_position)| {
                // `unfold` repeatedly calls the closure below, threading `BlobReplayState`
                // through each call, to turn one blob's byte `Replay` into a stream of items.
                // Each call returns a *batch* of items (decoding several buffered items per await
                // is cheaper than one await per item); the trailing `flat_map(stream::iter)` then
                // flattens those batches back into a stream of individual items.
                stream::unfold(
                    BlobReplayState {
                        blob,
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
                                        let global_pos = first_in_blob(
                                            pruning_boundary,
                                            state.blob,
                                            items_per_blob,
                                        )
                                        .and_then(|first| {
                                            first
                                                .checked_add(state.position)
                                                .ok_or(Error::OffsetOverflow)
                                        });
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
            reader: self.snapshot.table.tail_reader.clone(),
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
            let byte_offset = match (state.next_pos - state.tail_first)
                .checked_mul(chunk_size_u64)
                .ok_or(Error::OffsetOverflow)
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

/// State threaded through the `unfold` that replays a single sealed blob.
struct BlobReplayState<B: Blob> {
    /// The blob being replayed.
    blob: u64,
    /// Sequential reader over the blob's logical bytes.
    replay: Replay<B>,
    /// Index of the next item to emit, relative to the blob's first retained item. Added to the
    /// blob's first position to recover the item's absolute journal position.
    position: u64,
    /// Set once the blob is exhausted or an error was emitted; the next call returns `None`.
    done: bool,
}

/// State for the `unfold` that replays the tail through the snapshot's read handle.
struct TailReplayState<B: Blob> {
    reader: paged::Reader<B>,
    /// Next position to emit.
    next_pos: u64,
    /// One past the last position to emit: the snapshot's size.
    end_pos: u64,
    /// First retained position in the tail; origin for byte offsets.
    tail_first: u64,
}
