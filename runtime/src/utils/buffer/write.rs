use crate::{
    Blob, Buf, BufferPool, BufferPooler, Error, Handle, IoBuf, IoBufs, WriteOptions,
    buffer::{SyncState, tip::Buffer},
};
use std::{num::NonZeroUsize, ops::Range};

/// An owned, immutable logical view of a buffered [`Write`].
///
/// Constructing a view with [`Write::view`] is synchronous and constant-time: it clones the blob
/// handle and shares the writer's immutable tip buffer. Capturing a view does not flush or sync the
/// writer. Appends and updates within the captured tip use the buffer's existing copy-on-write
/// path, so the view continues to expose the bytes and logical size present at capture.
///
/// Blob-backed bytes below the captured tip remain subject to mutations made through the writer.
/// Callers that retain a view must not resize or overwrite that prefix. Removing the blob by name
/// is safe because the view owns a blob handle and inherits [`crate::Storage`]'s read-after-remove
/// guarantee.
#[derive(Clone)]
pub struct OwnedView<B: Blob> {
    blob: B,
    size: u64,
    tail_offset: u64,
    tail: IoBuf,
}

impl<B: Blob> OwnedView<B> {
    /// Returns the logical size captured by this view.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        read_at(self, offset, len).await
    }
}

/// Logical state needed by the shared buffered-read algorithm.
trait ReadView {
    type Blob: Blob;

    fn blob(&self) -> &Self::Blob;
    fn size(&self) -> u64;
    fn tail_offset(&self) -> u64;
    fn tail_slice(&self, range: Range<usize>) -> IoBuf;
}

/// Read against a fixed logical size and tail boundary.
async fn read_at<V: ReadView>(view: &V, offset: u64, len: usize) -> Result<IoBufs, Error> {
    let end_offset = offset
        .checked_add(len as u64)
        .ok_or(Error::OffsetOverflow)?;
    if end_offset > view.size() {
        return Err(Error::BlobInsufficientLength);
    }

    // Keep the zero-length fast path after the bounds check so offset > size preserves the
    // BlobInsufficientLength contract.
    if len == 0 {
        return Ok(IoBufs::default());
    }

    let tail_offset = view.tail_offset();
    if offset >= tail_offset {
        let start = (offset - tail_offset) as usize;
        return Ok(view.tail_slice(start..start + len).into());
    }

    if end_offset <= tail_offset {
        return Ok(view.blob().read_at(offset, len).await?.freeze());
    }

    let blob_len = (tail_offset - offset) as usize;
    let mut blob = view.blob().read_at(offset, blob_len).await?.freeze();
    blob.append(view.tail_slice(0..len - blob_len));
    Ok(blob)
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
/// # Access
///
/// [Write] is a single-owner buffered handle that owns mutation ordering and durability
/// bookkeeping for the wrapped [Blob]. Raw [Blob] handles cloned before wrapping observe only
/// flushed data and may not see the latest buffered writes until [Self::sync], [Self::resize], or
/// an overlapping [Self::write_at] flushes them. Those raw handles must not be used to write,
/// resize, or otherwise mutate the blob while a [Write] exists. External mutations bypass the
/// buffer state and [Self::sync] may use [Blob::write_at] with [WriteOptions::SYNC], which is
/// not a durability barrier for those external mutations.
///
/// [`Self::view`] captures an owned read handle without flushing. Captured tip bytes are shared
/// immutably and later tip mutations use copy-on-write.
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

    /// Capture an owned immutable view of the current logical bytes.
    ///
    /// This operation is synchronous and constant-time. It does not flush or sync the writer.
    #[must_use]
    pub fn view(&self) -> OwnedView<B> {
        OwnedView {
            blob: self.blob.clone(),
            size: self.buffer.size(),
            tail_offset: self.buffer.offset,
            tail: self.buffer.slice(..),
        }
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        read_at(self, offset, len).await
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
                self.sync_state
                    .write_at(&self.blob, old_offset, old_buf, WriteOptions::default())
                    .await?;
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
            self.sync_state
                .write_at(&self.blob, current_offset, direct, WriteOptions::default())
                .await?;
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
    pub async fn resize(&mut self, len: u64) -> Result<(), Error> {
        // Flush buffered data to the underlying blob.
        //
        // This can only happen if the new size is greater than the current size.
        if let Some((buf, offset)) = self.buffer.resize(len) {
            self.sync_state
                .write_at(&self.blob, offset, buf, WriteOptions::default())
                .await?;
        }

        self.sync_state.resize(&self.blob, len).await?;

        Ok(())
    }

    /// Flush buffered bytes and durably sync mutations tracked by this writer.
    pub async fn sync(&mut self) -> Result<(), Error> {
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
        if let Some((buf, offset)) = self.buffer.take()
            && let Err(err) = self
                .sync_state
                .write_at(&self.blob, offset, buf, WriteOptions::default())
                .await
        {
            return Handle::ready(Err(err));
        }

        self.sync_state.start_sync(&self.blob).await
    }

    /// Wait for any started sync to complete without starting a new sync.
    pub async fn wait_for_sync(&mut self) -> Result<(), Error> {
        self.sync_state.wait_for_pending().await
    }

    /// Write bytes to the underlying blob and make them durable.
    ///
    /// Uses [`Blob::write_at`] with [`WriteOptions::SYNC`] when there are no earlier unsynced
    /// mutations. Otherwise, writes the bytes and then syncs the blob.
    async fn write_blob_sync(
        &mut self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.sync_state
            .write_at(&self.blob, offset, bufs, WriteOptions::SYNC)
            .await
    }

    /// Sync the underlying blob if there are unsynced mutations.
    async fn sync_blob(&mut self) -> Result<(), Error> {
        self.sync_state.sync(&self.blob).await
    }
}

impl<B: Blob> ReadView for Write<B> {
    type Blob = B;

    fn blob(&self) -> &Self::Blob {
        &self.blob
    }

    fn size(&self) -> u64 {
        self.buffer.size()
    }

    fn tail_offset(&self) -> u64 {
        self.buffer.offset
    }

    fn tail_slice(&self, range: Range<usize>) -> IoBuf {
        self.buffer.slice(range)
    }
}

impl<B: Blob> ReadView for OwnedView<B> {
    type Blob = B;

    fn blob(&self) -> &Self::Blob {
        &self.blob
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn tail_offset(&self) -> u64 {
        self.tail_offset
    }

    fn tail_slice(&self, range: Range<usize>) -> IoBuf {
        self.tail.slice(range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IoBufsMut, Runner as _, Spawner as _, Storage as _, Supervisor as _, WriteOptions,
        deterministic,
    };
    use commonware_utils::NZUsize;
    use std::sync::{Arc, Weak};

    /// Blob wrapper whose lifetime proves view-owned handles are released.
    #[derive(Clone)]
    struct TrackedBlob<B: Blob> {
        inner: B,
        _lifetime: Arc<()>,
    }

    impl<B: Blob> TrackedBlob<B> {
        fn new(inner: B) -> (Self, Weak<()>) {
            let lifetime = Arc::new(());
            let weak = Arc::downgrade(&lifetime);
            (
                Self {
                    inner,
                    _lifetime: lifetime,
                },
                weak,
            )
        }
    }

    impl<B: Blob> Blob for TrackedBlob<B> {
        async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
            self.inner.read_at(offset, len).await
        }

        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at_buf(offset, len, bufs).await
        }

        async fn write_at(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
            options: WriteOptions,
        ) -> Result<(), Error> {
            self.inner.write_at(offset, bufs, options).await
        }

        async fn resize(&self, len: u64) -> Result<(), Error> {
            self.inner.resize(len).await
        }

        async fn sync(&self) -> Result<(), Error> {
            self.inner.sync().await
        }

        async fn start_sync(&self) -> Handle<()> {
            self.inner.start_sync().await
        }
    }

    #[test]
    fn test_owned_view_freezes_buffered_tip() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, size) = context
                .open("test_partition", b"raw_view_tip")
                .await
                .unwrap();
            let mut writer = Write::from_pooler(&context, blob, size, NZUsize!(16));

            writer.write_at(0, b"hello").await.unwrap();
            let view = writer.view();
            assert_eq!(view.size(), 5);

            // Updating shared tip bytes and extending the writer both use copy-on-write.
            writer.write_at(0, b"HELLO later").await.unwrap();
            assert_eq!(
                view.read_at(0, 5).await.unwrap().coalesce().as_ref(),
                b"hello"
            );
            assert!(matches!(
                view.read_at(0, 6).await,
                Err(Error::BlobInsufficientLength)
            ));
            assert_eq!(
                writer.read_at(0, 11).await.unwrap().coalesce().as_ref(),
                b"HELLO later"
            );
        });
    }

    #[test]
    fn test_owned_view_survives_remove_spawn_and_releases_blob() {
        fn assert_send_static<T: Send + 'static>(_: &T) {}

        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let name = b"raw_view_remove";
            let (blob, size) = context.open("test_partition", name).await.unwrap();
            let (blob, lifetime) = TrackedBlob::new(blob);
            let mut writer = Write::from_pooler(&context, blob, size, NZUsize!(8));

            // The first write bypasses the small buffer; the second remains in the tip.
            writer.write_at(0, b"persisted").await.unwrap();
            writer.write_at(9, b"-tail").await.unwrap();
            let view = writer.view();
            assert_send_static(&view);
            drop(writer);

            context.remove("test_partition", Some(name)).await.unwrap();
            let read = context
                .child("owned_view_read")
                .spawn(move |_| async move { view.read_at(0, 14).await.unwrap().coalesce() })
                .await
                .unwrap();
            assert_eq!(read.as_ref(), b"persisted-tail");
            assert!(
                lifetime.upgrade().is_none(),
                "completed view task must release its blob clone"
            );
        });
    }
}
