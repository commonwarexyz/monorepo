use crate::{
    BatchOperation, Blob, Buf, BufferPool, BufferPooler, Error, Handle, IoBufs,
    buffer::{SyncState, tip::Buffer},
};
use std::num::NonZeroUsize;

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
/// # Access
///
/// [Write] is a single-owner buffered handle that owns mutation ordering and durability
/// bookkeeping for the wrapped [Blob]. Raw [Blob] handles cloned before wrapping observe only
/// flushed data and may not see the latest buffered writes until [Self::sync], [Self::resize], or
/// an overlapping [Self::write_at] flushes them. Those raw handles must not be used to write,
/// resize, or otherwise mutate the blob while a [Write] exists. External mutations bypass the
/// buffer state and [Self::sync] may use [Blob::write_at_sync], which is not a durability barrier
/// for those external mutations.
///
/// # Cancellation safety
///
/// An error or cancellation during a physical write or resize can leave the writer poisoned. Once
/// poisoned, fallible operations return [Error::Aborted]; drop the writer and reopen the blob.
/// [Self::size] still reports the staged in-memory tip and must not be used to infer the recovered
/// size of a poisoned writer.
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
pub struct Write<B: Blob> {
    /// The underlying blob to write to.
    blob: B,

    /// Buffered bytes at the logical tip of the blob.
    buffer: Buffer,

    /// Durability state for plain writes and range-sync writes.
    sync_state: SyncState,

    /// Whether a shrink must be made durable before a later mutation can reuse truncated bytes.
    needs_sync_before_write: bool,

    /// Whether cancellation or failure interrupted a non-retryable mutation.
    poisoned: bool,
}

impl<B: Blob> Write<B> {
    /// Creates a new [Write] that buffers up to `capacity` bytes of data to be appended to the tip
    /// of `blob` with the provided `size`.
    pub fn new(blob: B, size: u64, capacity: NonZeroUsize, pool: BufferPool) -> Self {
        Self {
            blob,
            buffer: Buffer::new(size, capacity.get(), pool),
            // Existing blob contents may not be durable yet.
            sync_state: SyncState::Dirty,

            // A pre-wrap shrink may still be volatile: a replay repair dropped between its
            // resize and sync, followed by in-process re-initialization, wraps a fresh writer
            // over an unsynced truncation that re-init found nothing to repair for. The first
            // physical write reuses that range before any sync runs, so without this barrier a
            // crash could stitch the surviving old bytes and new bytes into a valid-looking
            // tail that recovery adopts.
            needs_sync_before_write: true,
            poisoned: false,
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
    pub const fn size(&self) -> u64 {
        self.buffer.size()
    }

    /// Reject reuse after a mutation that may have partially changed the blob.
    const fn ensure_usable(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Aborted);
        }
        Ok(())
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        self.ensure_usable()?;

        // Ensure the read doesn't overflow.
        let end_offset = offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;

        // If the data required is beyond the size of the blob, return an error.
        if end_offset > self.buffer.size() {
            return Err(Error::BlobInsufficientLength);
        }

        // Keep the zero-length fast path after the bounds check so offset > size still preserves
        // the BlobInsufficientLength contract.
        if len == 0 {
            return Ok(IoBufs::default());
        }

        // Entirely in buffered tip.
        if offset >= self.buffer.offset {
            let start = (offset - self.buffer.offset) as usize;
            let end = start + len;
            return Ok(self.buffer.slice(start..end).into());
        }

        // Entirely in blob.
        if end_offset <= self.buffer.offset {
            return self.read_blob(offset, len).await;
        }

        // Overlaps blob and buffered tip.
        let blob_len = (self.buffer.offset - offset) as usize;
        let tip_len = len - blob_len;
        let tip = self.buffer.slice(..tip_len);

        let mut blob = self.read_blob(offset, blob_len).await?;
        blob.append(tip);
        Ok(blob)
    }

    /// Read bytes from the underlying blob.
    async fn read_blob(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        Ok(self.blob.read_at(offset, len).await?.freeze())
    }

    /// Make a prior shrink durable before another mutation can reuse truncated bytes.
    async fn prepare_write(&mut self) -> Result<(), Error> {
        if self.needs_sync_before_write {
            self.sync_state.sync(&self.blob).await?;
            self.needs_sync_before_write = false;
        }
        Ok(())
    }

    /// Write bytes to the underlying blob after making any prior shrink durable.
    async fn write_blob(
        &mut self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.poisoned = true;
        self.prepare_write().await?;
        self.sync_state.write_at(&self.blob, offset, bufs).await?;
        self.poisoned = false;
        Ok(())
    }

    /// Resize the underlying blob, rejecting reuse until the mutation completes.
    async fn resize_blob(&mut self, len: u64) -> Result<(), Error> {
        self.poisoned = true;
        self.sync_state.resize(&self.blob, len).await?;
        self.poisoned = false;
        Ok(())
    }

    /// Write bytes from `buf` at `offset`.
    ///
    /// Data is merged into the in-memory tip buffer when possible, otherwise buffered data may be
    /// flushed and chunks are written directly to the underlying blob.
    ///
    /// Returns [Error::OffsetOverflow] when `offset + bufs.len()` overflows.
    pub async fn write_at(
        &mut self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.ensure_usable()?;
        let mut bufs = bufs.into();

        // Ensure the write doesn't overflow.
        offset
            .checked_add(bufs.remaining() as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Process each chunk of the input buffer, attempting to merge into the tip buffer
        // or writing directly to the underlying blob.
        let mut current_offset = offset;
        while bufs.has_remaining() {
            let chunk = bufs.chunk();
            let chunk_len = chunk.len();

            // Chunk falls entirely within the buffer's current range and can be merged.
            if self.buffer.merge(chunk, current_offset) {
                bufs.advance(chunk_len);
                current_offset += chunk_len as u64;
                continue;
            }

            // Chunk cannot be merged, so flush the buffer if the range overlaps, and check
            // if merge is possible after.
            let chunk_end = current_offset + chunk_len as u64;
            if self.buffer.offset < chunk_end
                && let Some((old_buf, old_offset)) = self.buffer.take()
            {
                self.write_blob(old_offset, old_buf).await?;
                if self.buffer.merge(chunk, current_offset) {
                    bufs.advance(chunk_len);
                    current_offset += chunk_len as u64;
                    continue;
                }
            }

            // Chunk could not be merged (exceeds buffer capacity or outside its range), so
            // write directly. Note that we may end up writing an intersecting range twice:
            // once when the buffer is flushed above, then again when we write the chunk
            // below. Removing this inefficiency may not be worth the additional complexity.
            let direct = bufs.split_to(chunk_len);
            self.write_blob(current_offset, direct).await?;
            current_offset += chunk_len as u64;

            // Maintain the "buffer at tip" invariant by advancing offset to the end of this
            // write if it extended the underlying blob.
            self.buffer.offset = self.buffer.offset.max(current_offset);
        }

        Ok(())
    }

    /// Resize the logical blob to `len`.
    ///
    /// If buffered data exists and the resize extends beyond current size, buffered data is flushed
    /// before resizing the underlying blob.
    /// Before a later write or growth reuses truncated bytes, the writer makes the shrink durable.
    pub async fn resize(&mut self, len: u64) -> Result<(), Error> {
        self.ensure_usable()?;
        let old_size = self.buffer.size();
        if len > old_size {
            self.prepare_write().await?;
        }

        // Flush buffered data to the underlying blob.
        //
        // This can only happen if the new size is greater than the current size.
        if let Some((buf, offset)) = self.buffer.resize(len) {
            self.write_blob(offset, buf).await?;
        }

        self.resize_blob(len).await?;
        if len < old_size {
            self.needs_sync_before_write = true;
        }

        Ok(())
    }

    /// Prepare a shrink for an atomic storage batch.
    ///
    /// Pending writes are made durable before the resize is appended to `batch`. The writer's
    /// logical state is updated immediately, but the underlying blob is not resized until the
    /// batch is applied. The caller must apply the batch immediately and treat failure as fatal;
    /// continuing to use the writer after a failed batch is unsupported.
    pub async fn resize_into(
        &mut self,
        len: u64,
        batch: &mut Vec<BatchOperation<B>>,
    ) -> Result<(), Error> {
        self.ensure_usable()?;
        let old_size = self.buffer.size();
        if len > old_size {
            return Err(Error::BlobInsufficientLength);
        }

        self.sync().await?;
        if len == old_size {
            return Ok(());
        }

        let pending = self.buffer.resize(len);
        debug_assert!(pending.is_none(), "sync must drain the buffered tip");
        batch.push(BatchOperation::Resize {
            blob: self.blob.clone(),
            len,
        });
        Ok(())
    }

    /// Flush buffered bytes and durably sync mutations tracked by this writer.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.ensure_usable()?;
        if let Some((buf, offset)) = self.buffer.take() {
            return self.write_blob_sync(offset, buf).await;
        }

        self.sync_blob().await
    }

    /// Flush buffered bytes and begin durably syncing mutations tracked by this writer.
    ///
    /// Awaiting the returned [`Handle`] waits for the same durability guarantee as [`Self::sync`]
    /// for the state flushed by this call. Later calls to [`Self::sync`] and writer methods that
    /// mutate the blob wait before issuing blob operations.
    pub async fn start_sync(&mut self) -> Handle<()> {
        if let Err(err) = self.ensure_usable() {
            return Handle::ready(Err(err));
        }
        if let Some((buf, offset)) = self.buffer.take()
            && let Err(err) = self.write_blob(offset, buf).await
        {
            return Handle::ready(Err(err));
        }

        self.sync_state.start_sync(&self.blob).await
    }

    /// Wait for any started sync to complete without starting a new sync.
    pub async fn wait_for_sync(&mut self) -> Result<(), Error> {
        self.ensure_usable()?;
        self.sync_state.wait_for_pending().await?;
        if matches!(self.sync_state, SyncState::Clean) {
            self.needs_sync_before_write = false;
        }
        Ok(())
    }

    /// Write bytes to the underlying blob and make them durable.
    ///
    /// Uses [`Blob::write_at_sync`] when there are no earlier unsynced mutations. Otherwise, writes
    /// the bytes and then syncs the blob.
    async fn write_blob_sync(
        &mut self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.poisoned = true;
        self.prepare_write().await?;
        self.sync_state
            .write_at_sync(&self.blob, offset, bufs)
            .await?;
        self.poisoned = false;
        Ok(())
    }

    /// Sync the underlying blob if there are unsynced mutations.
    async fn sync_blob(&mut self) -> Result<(), Error> {
        self.sync_state.sync(&self.blob).await?;
        self.needs_sync_before_write = false;
        Ok(())
    }
}
