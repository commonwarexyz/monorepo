use crate::{buffer::tip::Buffer, Blob, Buf, BufferPool, BufferPooler, Error, IoBufs};
use commonware_utils::sync::AsyncRwLock;
use std::{num::NonZeroUsize, sync::Arc};

/// Shared writer state.
struct State<B: Blob> {
    /// The underlying blob to write to.
    blob: B,

    /// Buffered bytes at the logical tip of the blob.
    buffer: Buffer,

    /// Whether a prior plain mutation must be persisted with [`Blob::sync`].
    ///
    /// [`State::write_at_sync`] uses [`Blob::write_at_sync`] only when this is
    /// false, otherwise it must use [`Blob::sync`] to cover earlier unsynced
    /// mutations.
    needs_sync: bool,
}

impl<B: Blob> State<B> {
    /// Read bytes from the underlying blob.
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        Ok(self.blob.read_at(offset, len).await?.freeze())
    }

    /// Write bytes to the underlying blob and mark them as needing sync.
    async fn write_at(&mut self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        self.blob.write_at(offset, bufs).await?;
        self.needs_sync = true;
        Ok(())
    }

    /// Write bytes to the underlying blob and make them durable.
    ///
    /// Uses [`Blob::write_at_sync`] when there are no earlier unsynced
    /// mutations. Otherwise, writes the bytes and then syncs the blob.
    async fn write_at_sync(
        &mut self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        if self.needs_sync {
            self.write_at(offset, bufs).await?;
            self.sync().await
        } else {
            // If `write_at_sync` fails, a later sync must not treat the drained
            // buffer as durable.
            self.needs_sync = true;
            self.blob.write_at_sync(offset, bufs).await?;
            self.needs_sync = false;
            Ok(())
        }
    }

    /// Resize the underlying blob and mark the resize as needing sync.
    async fn resize(&mut self, len: u64) -> Result<(), Error> {
        self.blob.resize(len).await?;
        self.needs_sync = true;
        Ok(())
    }

    /// Sync the underlying blob if there are unsynced mutations.
    async fn sync(&mut self) -> Result<(), Error> {
        if !self.needs_sync {
            return Ok(());
        }
        self.blob.sync().await?;
        self.needs_sync = false;
        Ok(())
    }
}

/// A writer that buffers the raw content of a [Blob] to optimize the performance of appending or
/// updating data.
///
/// # Allocation Semantics
///
/// - [Self::new] starts with a detached tip buffer and allocates backing on first buffered write.
/// - Subsequent writes reuse that backing, copy-on-write allocation only occurs when buffered data
///   is shared (for example, after handing out immutable views) or a merge needs more capacity.
/// - Sparse writes merged into tip extend logical length and zero-fill any gap in-buffer.
/// - Flush paths ([Self::sync], [Self::resize], overlap flushes in [Self::write_at]) hand drained
///   bytes to the blob and leave the tip detached until the next buffered write.
///
/// # Concurrent Access
///
/// [Write] owns mutation ordering and durability bookkeeping for the wrapped [Blob]. Cloned
/// [Write] handles are safe to use concurrently because they share the same state. Raw [Blob]
/// handles cloned before wrapping observe only flushed data and may not see the latest buffered
/// writes until [Self::sync], [Self::resize], or an overlapping [Self::write_at] flushes them.
/// Those raw handles must not be used to write, resize, or otherwise mutate the blob while a
/// [Write] exists. External mutations bypass the buffer state and [Self::sync] may use
/// [Blob::write_at_sync], which is not a durability barrier for those external mutations.
///
/// # Example
///
/// ```
/// use commonware_runtime::{Runner, BufferPooler, buffer::{Write, Read}, Blob, Error, Storage, deterministic};
/// use commonware_utils::NZUsize;
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Open a blob for writing
///     let (blob, size) = context.open("my_partition", b"my_data").await.expect("unable to open blob");
///     assert_eq!(size, 0);
///
///     // Create a buffered writer with 16-byte buffer
///     let mut blob = Write::from_pooler(&context, blob, 0, NZUsize!(16));
///     blob.write_at(0, b"hello").await.expect("write failed");
///     blob.sync().await.expect("sync failed");
///
///     // Write more data in multiple flushes
///     blob.write_at(5, b" world").await.expect("write failed");
///     blob.write_at(11, b"!").await.expect("write failed");
///     blob.sync().await.expect("sync failed");
///
///     // Read back the data to verify
///     let (blob, size) = context.open("my_partition", b"my_data").await.expect("unable to reopen blob");
///     let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(8));
///     let buf = reader.read(size as usize).await.expect("read failed");
///     assert_eq!(buf.coalesce().as_ref(), b"hello world!");
/// });
/// ```
#[derive(Clone)]
pub struct Write<B: Blob> {
    /// Shared blob, tip buffer, and durability state.
    state: Arc<AsyncRwLock<State<B>>>,
}

impl<B: Blob> Write<B> {
    /// Creates a new [Write] that buffers up to `capacity` bytes of data to be appended to the tip
    /// of `blob` with the provided `size`.
    pub fn new(blob: B, size: u64, capacity: NonZeroUsize, pool: BufferPool) -> Self {
        Self {
            state: Arc::new(AsyncRwLock::new(State {
                blob,
                buffer: Buffer::new(size, capacity.get(), pool),
                needs_sync: true, // ensure pending writes on the wrapped blob are synced
            })),
        }
    }

    /// Creates a new [Write], extracting the storage [BufferPool] from a [BufferPooler].
    pub fn from_pooler(
        pooler: &impl BufferPooler,
        blob: B,
        size: u64,
        capacity: NonZeroUsize,
    ) -> Self {
        Self::new(blob, size, capacity, pooler.storage_buffer_pool().clone())
    }

    /// Returns the current logical size of the blob including any buffered data.
    ///
    /// This represents the total size of data that would be present after flushing.
    pub async fn size(&self) -> u64 {
        let state = self.state.read().await;
        state.buffer.size()
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        // Ensure the read doesn't overflow.
        let end_offset = offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Acquire a read lock on the buffer state.
        let state = self.state.read().await;
        let buffer = &state.buffer;

        // If the data required is beyond the size of the blob, return an error.
        if end_offset > buffer.size() {
            return Err(Error::BlobInsufficientLength);
        }

        // Keep the zero-length fast path after the bounds check so offset > size still preserves
        // the BlobInsufficientLength contract.
        if len == 0 {
            return Ok(IoBufs::default());
        }

        // Entirely in buffered tip.
        if offset >= buffer.offset {
            let start = (offset - buffer.offset) as usize;
            let end = start + len;
            return Ok(buffer.slice(start..end).into());
        }

        // Entirely in blob.
        if end_offset <= buffer.offset {
            return state.read_at(offset, len).await;
        }

        // Overlaps blob and buffered tip.
        let blob_len = (buffer.offset - offset) as usize;
        let tip_len = len - blob_len;
        let tip = buffer.slice(..tip_len);

        let mut blob = state.read_at(offset, blob_len).await?;
        blob.append(tip);
        Ok(blob)
    }

    /// Write bytes from `buf` at `offset`.
    ///
    /// Data is merged into the in-memory tip buffer when possible, otherwise buffered data may be
    /// flushed and chunks are written directly to the underlying blob.
    ///
    /// Returns [Error::OffsetOverflow] when `offset + bufs.len()` overflows.
    pub async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let mut bufs = bufs.into();

        // Ensure the write doesn't overflow.
        offset
            .checked_add(bufs.remaining() as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Acquire a write lock on the buffer state.
        let mut state = self.state.write().await;

        // Process each chunk of the input buffer, attempting to merge into the tip buffer
        // or writing directly to the underlying blob.
        let mut current_offset = offset;
        while bufs.has_remaining() {
            let chunk = bufs.chunk();
            let chunk_len = chunk.len();

            // Chunk falls entirely within the buffer's current range and can be merged.
            if state.buffer.merge(chunk, current_offset) {
                bufs.advance(chunk_len);
                current_offset += chunk_len as u64;
                continue;
            }

            // Chunk cannot be merged, so flush the buffer if the range overlaps, and check
            // if merge is possible after.
            let chunk_end = current_offset + chunk_len as u64;
            if state.buffer.offset < chunk_end {
                if let Some((old_buf, old_offset)) = state.buffer.take() {
                    state.write_at(old_offset, old_buf).await?;
                    if state.buffer.merge(chunk, current_offset) {
                        bufs.advance(chunk_len);
                        current_offset += chunk_len as u64;
                        continue;
                    }
                }
            }

            // Chunk could not be merged (exceeds buffer capacity or outside its range), so
            // write directly. Note that we may end up writing an intersecting range twice:
            // once when the buffer is flushed above, then again when we write the chunk
            // below. Removing this inefficiency may not be worth the additional complexity.
            let direct = bufs.split_to(chunk_len);
            state.write_at(current_offset, direct).await?;
            current_offset += chunk_len as u64;

            // Maintain the "buffer at tip" invariant by advancing offset to the end of this
            // write if it extended the underlying blob.
            state.buffer.offset = state.buffer.offset.max(current_offset);
        }

        Ok(())
    }

    /// Resize the logical blob to `len`.
    ///
    /// If buffered data exists and the resize extends beyond current size, buffered data is flushed
    /// before resizing the underlying blob.
    pub async fn resize(&self, len: u64) -> Result<(), Error> {
        // Acquire a write lock on the buffer state.
        let mut state = self.state.write().await;

        // Flush buffered data to the underlying blob.
        //
        // This can only happen if the new size is greater than the current size.
        if let Some((buf, offset)) = state.buffer.resize(len) {
            state.write_at(offset, buf).await?;
        }

        // Resize the underlying blob.
        state.resize(len).await?;

        Ok(())
    }

    /// Flush buffered bytes and durably sync mutations tracked by this writer.
    pub async fn sync(&self) -> Result<(), Error> {
        let mut state = self.state.write().await;
        if let Some((buf, offset)) = state.buffer.take() {
            return state.write_at_sync(offset, buf).await;
        }

        state.sync().await
    }

    /// Releases the buffer backing once this blob is no longer the active append tip.
    ///
    /// Buffered bytes are drained to the blob (without an extra sync); [`Buffer::take`] resets the
    /// tip to a detached, empty state so no write-buffer backing is retained. The drained bytes are
    /// still made durable by a later [`Self::sync`].
    pub async fn seal(&self) -> Result<(), Error> {
        let mut state = self.state.write().await;
        if let Some((buf, offset)) = state.buffer.take() {
            state.write_at(offset, buf).await?;
        }
        Ok(())
    }
}
