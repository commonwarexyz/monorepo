use super::Checksum;
use crate::{Blob, Error, Handle, IoBuf, IoBufsMut, ReadOptions};
use bytes::{BufMut, Bytes, BytesMut, TryGetError};
use commonware_codec::{Buf, FixedSize};
use commonware_utils::Widen;
use futures::FutureExt as _;
use std::{collections::VecDeque, num::NonZeroU16, ops::Range, sync::Arc};
use tracing::error;

/// Buffered pages from storage or a frozen logical tail.
///
/// Storage batches contain pages with interleaved CRCs. The frozen tail contains one partial
/// logical page without CRCs. Navigation uses offsets rather than separate `Bytes` slices per page.
pub(super) struct BufferState {
    /// Page bytes, with interleaved CRCs when read from storage.
    buffer: Bytes,
    /// Number of pages in this buffer.
    num_pages: usize,
    /// Logical length of the last page (may be partial).
    last_page_len: usize,
}

/// Batches kept in flight ahead of the one being decoded.
///
/// The replay buffer fixes the bytes in flight. The depth decides how many requests they are
/// split into, which the buffer cannot. One request at a time leaves the device idle for a
/// request latency at every batch boundary, while many small requests pay a fixed cost each.
const MAX_READ_AHEAD: usize = 3;

/// A batch started ahead of the decoder.
struct Inflight {
    /// First page of the batch.
    first_page: u64,
    /// Number of pages in the batch.
    pages: usize,
    /// The started read of the batch's pages, as one range.
    read: Handle<Vec<IoBufsMut>>,
}

impl Inflight {
    /// The page after the batch's last page.
    fn end(&self) -> u64 {
        self.first_page + Widen::widen(self.pages)
    }

    /// Wait for the batch's bytes.
    async fn wait(self) -> Result<IoBufsMut, Error> {
        self.read.await?.pop().ok_or(Error::ReadFailed)
    }
}

/// Async I/O component that prefetches pages and validates CRCs.
///
/// Pages are read in batches of `batch_pages` pages, each started through
/// [`Blob::start_read_many`] and held as a [`Handle`] until the decoder reaches it, with up to
/// [`MAX_READ_AHEAD`] batches after the one being decoded in flight so the device works while
/// the decoder does. The batches in flight and the one being decoded together span the replay
/// buffer, each rounded up to whole pages, so they exceed it by less than one page each.
///
/// The decoder's position advances only after a batch passes checksum validation, so a corrupt
/// page fails the fill that reaches it and no later page is yielded. When the batch at that
/// position is missing from the queue or its read failed, the queue is discarded and the batch
/// is read on demand. A failed or dropped fill therefore costs the reads ahead of it and nothing
/// else.
pub(super) struct PageReader<B: Blob> {
    /// The underlying blob to read from.
    blob: Arc<B>,
    /// Physical page size (page_size + CHECKSUM_SIZE).
    physical_page_size: usize,
    /// Logical page size (data bytes per page, not including CRC).
    page_size: usize,
    /// Physical bytes to read from storage, excluding the frozen partial page.
    physical_blob_size: u64,
    /// The size of the blob.
    logical_blob_size: u64,
    /// Immutable logical bytes of the final partial page.
    partial_page: Option<Bytes>,
    /// Next page index to hand to the decoder.
    blob_page: u64,
    /// Number of pages per batch.
    batch_pages: usize,
    /// The batches read ahead of the decoder, contiguous and in page order. The first starts at
    /// `blob_page` unless a fill failed or was dropped after taking the batch before it.
    inflight: VecDeque<Inflight>,
    /// Options applied to every blob read.
    read_options: ReadOptions,
}

impl<B: Blob> PageReader<B> {
    /// Creates a new PageReader.
    ///
    /// The `physical_blob_size` must already exclude any trailing invalid data
    /// (e.g., junk pages from an interrupted write). Each physical page is the same
    /// size on disk, but the CRC record indicates how much logical data it contains.
    /// Every stored page must validate at least the bytes the reader exposes from it: a
    /// whole page, unless `logical_blob_size` ends inside it. A page validating fewer
    /// bytes fails the fill that reaches it with `Error::InvalidChecksum`.
    ///
    /// A frozen `partial_page` contains exactly the logical bytes of the final partial page.
    /// Its physical page is included in `physical_blob_size` but is not read from storage.
    pub(super) fn new(
        blob: Arc<B>,
        mut physical_blob_size: u64,
        logical_blob_size: u64,
        partial_page: Option<IoBuf>,
        buffer_pages: usize,
        page_size: NonZeroU16,
        read_options: ReadOptions,
    ) -> Self {
        let page_size = page_size.get() as usize;
        let physical_page_size = page_size + Checksum::SIZE;
        let physical_pages = physical_blob_size / physical_page_size as u64;
        let logical_pages = if logical_blob_size == 0 {
            0
        } else {
            ((logical_blob_size - 1) / page_size as u64) + 1
        };
        assert_eq!(physical_blob_size % physical_page_size as u64, 0);
        assert_eq!(physical_pages, logical_pages);
        if let Some(partial_page) = &partial_page {
            assert!(
                !partial_page.is_empty()
                    && Widen::widen(partial_page.len())
                        == logical_blob_size % Widen::widen(page_size),
                "frozen tail must match the final partial page"
            );
            physical_blob_size -= Widen::widen(physical_page_size);
        }

        Self {
            blob,
            physical_page_size,
            page_size,
            physical_blob_size,
            logical_blob_size,
            partial_page: partial_page.map(Bytes::from),
            blob_page: 0,
            batch_pages: buffer_pages.div_ceil(MAX_READ_AHEAD + 1),
            inflight: VecDeque::new(),
            read_options,
        }
    }

    /// Position the reader at `page`, discarding the batches read ahead.
    fn seek_to_page(&mut self, page: u64) {
        self.blob_page = page;
        self.inflight.clear();
    }

    /// Start batches after the queued ones, or after `consumed_end` when none is queued, until
    /// [`MAX_READ_AHEAD`] are in flight or the blob ends.
    async fn top_up(&mut self, consumed_end: u64) -> Result<(), Error> {
        let mut next = self.inflight.back().map_or(consumed_end, Inflight::end);
        while self.inflight.len() < MAX_READ_AHEAD {
            let Some(batch) = self.start_batch(next).await? else {
                break;
            };
            next = batch.end();
            self.inflight.push_back(batch);
        }
        Ok(())
    }

    /// Start a read of up to `batch_pages` consecutive physical pages from `first_page`, or
    /// `None` when no stored page remains there.
    async fn start_batch(&self, first_page: u64) -> Result<Option<Inflight>, Error> {
        let physical_page_size: u64 = Widen::widen(self.physical_page_size);
        let start = first_page
            .checked_mul(physical_page_size)
            .ok_or(Error::OffsetOverflow)?;
        if start >= self.physical_blob_size {
            return Ok(None);
        }
        let pages = ((self.physical_blob_size - start) / physical_page_size)
            .min(Widen::widen(self.batch_pages)) as usize;
        let len = pages * self.physical_page_size;

        // Boxing keeps the blob's start future out of the replay's state machine. With it
        // inlined, the decoders' hot loops compiled differently and the variable decoder ran 8%
        // slower.
        let read = self
            .blob
            .start_read_many(&[(start, len)], self.read_options)
            .boxed()
            .await;
        Ok(Some(Inflight {
            first_page,
            pages,
            read,
        }))
    }

    /// Returns the size of the blob.
    pub(super) const fn blob_size(&self) -> u64 {
        self.logical_blob_size
    }

    /// Returns the physical page size.
    pub(super) const fn physical_page_size(&self) -> usize {
        self.physical_page_size
    }

    /// Returns the logical page size.
    pub(super) const fn page_size(&self) -> usize {
        self.page_size
    }

    /// Read the batch at the decoder's position, taking the one read ahead for it when its read
    /// lands and reading on demand otherwise.
    ///
    /// A batch read ahead whose read failed, or a queue that does not start at the decoder's
    /// position, is discarded before the demand read is started and the queue topped up again.
    /// The read ahead may have failed because whoever started it is gone, and nothing queued may
    /// stand between the decoder and the bytes it needs.
    async fn read_batch(&mut self) -> Result<(usize, IoBufsMut), Error> {
        if let Some(batch) = self
            .inflight
            .pop_front_if(|batch| batch.first_page == self.blob_page)
        {
            let pages = batch.pages;
            self.top_up(batch.end()).await?;
            if let Ok(bufs) = batch.wait().await {
                return Ok((pages, bufs));
            }
        }

        self.inflight.clear();
        let batch = self
            .start_batch(self.blob_page)
            .await?
            .expect("pages remain to be issued");
        let pages = batch.pages;
        self.top_up(batch.end()).await?;
        Ok((pages, batch.wait().await?))
    }

    /// Fills a buffer with the next batch of pages.
    ///
    /// Returns `Some((BufferState, logical_bytes))` if data was loaded,
    /// `None` if no more data available.
    pub(super) async fn fill(&mut self) -> Result<Option<(BufferState, usize)>, Error> {
        // Calculate physical read offset
        let start_offset = match self.blob_page.checked_mul(self.physical_page_size as u64) {
            Some(o) => o,
            None => return Err(Error::OffsetOverflow),
        };
        if start_offset == self.physical_blob_size
            && let Some(partial_page) = &self.partial_page
        {
            self.blob_page += 1;
            let len = partial_page.len();
            return Ok(Some((
                BufferState {
                    buffer: partial_page.clone(),
                    num_pages: 1,
                    last_page_len: len,
                },
                len,
            )));
        }
        if start_offset >= self.physical_blob_size {
            return Ok(None); // No more data
        }

        let (pages_to_read, physical_buf) = self.read_batch().await?;
        let physical_buf = Bytes::from(physical_buf.coalesce().freeze());

        // Validate CRCs and compute total logical bytes
        let mut total_logical = 0usize;
        let mut last_len = 0usize;
        for page_idx in 0..pages_to_read {
            let page_start = page_idx * self.physical_page_size;
            let page_slice =
                &physical_buf.as_ref()[page_start..page_start + self.physical_page_size];
            let Some(checksum) = Checksum::validate_page(page_slice) else {
                error!(page = self.blob_page + page_idx as u64, "CRC mismatch");
                return Err(Error::InvalidChecksum);
            };
            let len = checksum.len as usize;

            // Only the final stored page may validate fewer bytes than a page, and only down to
            // the logical end.
            let logical_start = (self.blob_page + Widen::widen(page_idx))
                .checked_mul(Widen::widen(self.page_size))
                .ok_or(Error::OffsetOverflow)?;
            let logical_remaining = self.logical_blob_size.saturating_sub(logical_start);
            let exposed_len = usize::try_from(logical_remaining.min(Widen::widen(self.page_size)))
                .expect("exposed length must not exceed page_size");
            if len < exposed_len {
                error!(
                    page = self.blob_page + Widen::widen(page_idx),
                    expected = exposed_len,
                    actual = len,
                    "page validates fewer bytes than the replay reads"
                );
                return Err(Error::InvalidChecksum);
            }

            total_logical += exposed_len;
            last_len = exposed_len;
        }
        self.blob_page += Widen::widen(pages_to_read);

        let state = BufferState {
            buffer: physical_buf,
            num_pages: pages_to_read,
            last_page_len: last_len,
        };

        Ok(Some((state, total_logical)))
    }
}

/// Sync buffering component that implements the `Buf` trait.
///
/// This accumulates `BufferState` from multiple fills and provides navigation
/// across pages while skipping CRCs. Consumed buffers are cleaned up in
/// `advance()`.
struct ReplayBuf {
    /// Physical page size (page_size + CHECKSUM_SIZE).
    physical_page_size: usize,
    /// Logical page size (data bytes per page, not including CRC).
    page_size: usize,
    /// Accumulated buffers from fills.
    buffers: VecDeque<BufferState>,
    /// Current page index within the front buffer.
    current_page: usize,
    /// Current offset within the current page's logical data.
    offset_in_page: usize,
    /// Total remaining logical bytes across all buffers.
    remaining: usize,
}

impl ReplayBuf {
    /// Creates a new ReplayBuf.
    const fn new(physical_page_size: usize, page_size: usize) -> Self {
        Self {
            physical_page_size,
            page_size,
            buffers: VecDeque::new(),
            current_page: 0,
            offset_in_page: 0,
            remaining: 0,
        }
    }

    /// Clears the buffer and resets the read offset to 0.
    fn clear(&mut self) {
        self.buffers.clear();
        self.current_page = 0;
        self.offset_in_page = 0;
        self.remaining = 0;
    }

    /// Adds a buffer from a fill operation.
    fn push(&mut self, state: BufferState, logical_bytes: usize) {
        // If buffers is empty, this is the first fill after a seek.
        // Skip bytes before the seek offset (offset_in_page).
        let skip = if self.buffers.is_empty() {
            self.offset_in_page
        } else {
            0
        };
        self.buffers.push_back(state);
        self.remaining += logical_bytes.saturating_sub(skip);
    }

    /// Returns the logical length of the given page in the given buffer.
    const fn page_len(buf: &BufferState, page_idx: usize, page_size: usize) -> usize {
        if page_idx + 1 == buf.num_pages {
            buf.last_page_len
        } else {
            page_size
        }
    }

    /// Returns the front buffer and the physical range of the current page's unread logical
    /// bytes, which is empty once the page is consumed, or `None` when no page is buffered.
    fn chunk_range(&self) -> Option<(&BufferState, Range<usize>)> {
        let buf = self.buffers.front()?;
        if self.current_page >= buf.num_pages {
            return None;
        }
        let page_len = Self::page_len(buf, self.current_page, self.page_size);
        let page_start = self.current_page * self.physical_page_size;
        Some((buf, page_start + self.offset_in_page..page_start + page_len))
    }
}

impl Buf for ReplayBuf {}

impl bytes::Buf for ReplayBuf {
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        assert!(len <= self.remaining, "copy_to_bytes out of bounds");
        if len == 0 {
            return Bytes::new();
        }
        if let Some((buf, range)) = self.chunk_range()
            && len <= range.len()
        {
            let bytes = buf.buffer.slice(range.start..range.start + len);
            self.advance(len);
            return bytes;
        }

        // A field spanning pages must be coalesced around the interleaved checksums
        let mut bytes = BytesMut::with_capacity(len);
        bytes.put(self.take(len));
        bytes.freeze()
    }

    fn remaining(&self) -> usize {
        self.remaining
    }

    #[inline(always)]
    fn try_copy_to_slice(&mut self, mut dst: &mut [u8]) -> Result<(), TryGetError> {
        if dst.len() > self.remaining {
            return Err(TryGetError {
                requested: dst.len(),
                available: self.remaining,
            });
        }

        // Fast path: the request ends strictly inside the current page, so the cursor
        // stays on this page and no page or buffer transition is needed.
        let chunk = self.chunk();
        if dst.len() < chunk.len() {
            dst.copy_from_slice(&chunk[..dst.len()]);
            self.offset_in_page += dst.len();
            self.remaining -= dst.len();
            return Ok(());
        }

        while !dst.is_empty() {
            let src = self.chunk();
            let cnt = usize::min(src.len(), dst.len());
            dst[..cnt].copy_from_slice(&src[..cnt]);
            dst = &mut dst[cnt..];
            self.advance(cnt);
        }
        Ok(())
    }

    fn chunk(&self) -> &[u8] {
        self.chunk_range()
            .map_or(&[], |(buf, range)| &buf.buffer.as_ref()[range])
    }

    fn advance(&mut self, mut cnt: usize) {
        self.remaining = self.remaining.saturating_sub(cnt);

        while cnt > 0 {
            let Some(buf) = self.buffers.front() else {
                break;
            };

            // Advance within current buffer
            while cnt > 0 && self.current_page < buf.num_pages {
                let page_len = Self::page_len(buf, self.current_page, self.page_size);
                let available = page_len - self.offset_in_page;
                if cnt < available {
                    self.offset_in_page += cnt;
                    return;
                }
                cnt -= available;
                self.current_page += 1;
                self.offset_in_page = 0;
            }

            // Current buffer exhausted, move to next
            if self.current_page >= buf.num_pages {
                self.buffers.pop_front();
                self.current_page = 0;
                self.offset_in_page = 0;
            }
        }
    }
}

/// Replays logical data from a blob containing pages with interleaved CRCs.
///
/// This combines async I/O (`PageReader`) with sync buffering (`ReplayBuf`)
/// to provide an `ensure(n)` + `Buf` interface for codec decoding.
///
/// Nonempty byte fields within one page share the allocation backing the entire prefetched batch.
/// Retaining such a field keeps that allocation alive after the replay advances or is dropped,
/// delaying its release. Fields spanning pages are copied into separate allocations.
pub struct Replay<B: Blob> {
    /// Async I/O component.
    reader: PageReader<B>,
    /// Sync buffering component.
    buffer: ReplayBuf,
    /// Whether the blob has been fully read.
    exhausted: bool,
}

impl<B: Blob> Replay<B> {
    /// Creates a new Replay from a PageReader.
    pub(super) const fn new(reader: PageReader<B>) -> Self {
        let physical_page_size = reader.physical_page_size();
        let page_size = reader.page_size();
        Self {
            reader,
            buffer: ReplayBuf::new(physical_page_size, page_size),
            exhausted: false,
        }
    }

    /// Returns the size of the blob.
    pub const fn blob_size(&self) -> u64 {
        self.reader.blob_size()
    }

    /// Returns true if the reader has been exhausted (no more pages to read).
    ///
    /// When exhausted, the buffer may still contain data that hasn't been consumed.
    /// Callers should check `remaining()` to see if there's data left to process.
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Ensures at least `n` bytes are available in the buffer.
    ///
    /// This method fills the buffer from the blob until either:
    /// - At least `n` bytes are available (returns `Ok(true)`)
    /// - The blob is exhausted with fewer than `n` bytes (returns `Ok(false)`)
    /// - A read error occurs (returns `Err`)
    ///
    /// When `Ok(false)` is returned, callers should still attempt to process
    /// the remaining bytes in the buffer (check `remaining()`), as they may
    /// contain valid data that doesn't require the full `n` bytes.
    pub async fn ensure(&mut self, n: usize) -> Result<bool, Error> {
        while self.buffer.remaining < n && !self.exhausted {
            match self.reader.fill().await? {
                Some((state, logical_bytes)) => {
                    self.buffer.push(state, logical_bytes);
                }
                None => {
                    self.exhausted = true;
                }
            }
        }
        Ok(self.buffer.remaining >= n)
    }

    /// Seeks to `offset` in the blob, returning `Err(BlobInsufficientLength)` if `offset` exceeds
    /// the blob size.
    pub fn seek_to(&mut self, offset: u64) -> Result<(), Error> {
        if offset > self.reader.blob_size() {
            return Err(Error::BlobInsufficientLength);
        }

        self.buffer.clear();
        self.exhausted = false;

        let page_size = self.reader.page_size as u64;
        self.reader.seek_to_page(offset / page_size);
        self.buffer.current_page = 0;
        self.buffer.offset_in_page = (offset % page_size) as usize;

        Ok(())
    }
}

impl<B: Blob> Buf for Replay<B> {}

impl<B: Blob> bytes::Buf for Replay<B> {
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        self.buffer.copy_to_bytes(len)
    }

    fn remaining(&self) -> usize {
        self.buffer.remaining()
    }

    #[inline(always)]
    fn try_copy_to_slice(&mut self, dst: &mut [u8]) -> Result<(), TryGetError> {
        self.buffer.try_copy_to_slice(dst)
    }

    fn chunk(&self) -> &[u8] {
        self.buffer.chunk()
    }

    fn advance(&mut self, cnt: usize) {
        self.buffer.advance(cnt);
    }
}

#[cfg(test)]
mod tests {
    use super::{super::writer::Writer, *};
    use crate::{
        Handle, IoBufs, Runner as _, Storage as _, WriteOptions,
        buffer::paged::{CacheRef, Sealed},
        deterministic,
    };
    use bytes::Buf as _;
    use commonware_macros::test_traced;
    use commonware_utils::{NZU16, NZUsize, channel::oneshot, sync::Mutex};
    use futures::task::noop_waker_ref;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll},
    };

    /// Every read in call order. Each records whether it was a started read, which every replay
    /// batch must be, and its ranges.
    type Calls = Arc<Mutex<Vec<(bool, Vec<(u64, usize)>)>>>;

    /// How a [GroupingBlob] serves the reads it records.
    #[derive(Default)]
    struct Reads {
        /// Fail reads at or past this offset.
        fail_from: Option<u64>,
        /// Times each read yields after being recorded, before it completes.
        yields: usize,
        /// Fail every started read after it has read its bytes.
        trailing_error: bool,
        /// Hold every started read until the test releases its offset through [Gates].
        gated: bool,
        /// Serve started reads only while holding one of these permits, in request order, and
        /// fail the first read at offset 0. The counter records the attempts at that offset.
        admission: Option<(Arc<tokio::sync::Semaphore>, Arc<AtomicUsize>)>,
        /// Fail the first read at this offset only. The counter records the attempts there.
        fail_once: Option<(u64, Arc<AtomicUsize>)>,
    }

    /// The offset of a read held by a [GroupingBlob] and the release that completes it.
    type Gate = (u64, oneshot::Sender<()>);

    /// Reads held by a [GroupingBlob] until released.
    #[derive(Clone, Default)]
    struct Gates(Arc<Mutex<Vec<Gate>>>);

    impl Gates {
        /// Release the read at `offset` that is still awaited.
        fn release(&self, offset: u64) {
            let mut gates = self.0.lock();
            let i = gates
                .iter()
                .position(|(o, release)| *o == offset && !release.is_closed())
                .unwrap();
            let _ = gates.remove(i).1.send(());
        }

        /// Offsets of the held reads that are still awaited.
        fn open(&self) -> Vec<u64> {
            self.0
                .lock()
                .iter()
                .filter(|(_, release)| !release.is_closed())
                .map(|(offset, _)| *offset)
                .collect()
        }
    }

    /// Records every read and serves it as its [Reads] say.
    struct GroupingBlob<B> {
        inner: B,
        calls: Calls,
        reads: Reads,
        gates: Gates,
    }

    impl<B> GroupingBlob<B> {
        /// Record a read and yield `yields` times so a test can observe it before it completes.
        async fn begin(&self, many: bool, ranges: &[(u64, usize)]) -> Result<(), Error> {
            self.record(many, ranges)?;
            for _ in 0..self.reads.yields {
                crate::reschedule().await;
            }
            Ok(())
        }

        fn record(&self, many: bool, ranges: &[(u64, usize)]) -> Result<(), Error> {
            self.calls.lock().push((many, ranges.to_vec()));
            if self
                .reads
                .fail_once
                .as_ref()
                .is_some_and(|(offset, attempts)| {
                    ranges[0].0 == *offset && attempts.fetch_add(1, Ordering::SeqCst) == 0
                })
            {
                return Err(Error::ReadFailed);
            }
            if self
                .reads
                .fail_from
                .is_some_and(|fail| ranges.iter().any(|(offset, _)| *offset >= fail))
            {
                return Err(Error::ReadFailed);
            }
            Ok(())
        }
    }

    impl<B: Blob> Blob for GroupingBlob<B> {
        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.begin(false, &[(offset, len)]).await?;
            self.inner.read_at_buf(offset, len, bufs, options).await
        }

        async fn read_at(
            &self,
            offset: u64,
            len: usize,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.begin(false, &[(offset, len)]).await?;
            self.inner.read_at(offset, len, options).await
        }

        /// Start the read as the [Reads] say: record it, fail it outright, or hand back bytes
        /// that land only once the test releases their gate, a permit admits them, and they
        /// have yielded.
        async fn start_read_many(
            &self,
            ranges: &[(u64, usize)],
            options: ReadOptions,
        ) -> Handle<Vec<IoBufsMut>> {
            if let Err(err) = self.record(true, ranges) {
                return Handle::ready(Err(err));
            }
            let bytes = self.inner.start_read_many(ranges, options).await;
            let offset = ranges[0].0;
            let gate = self.reads.gated.then(|| {
                let (release, released) = oneshot::channel();
                self.gates.0.lock().push((offset, release));
                released
            });
            let admission = self.reads.admission.clone();
            let yields = self.reads.yields;
            let trailing_error = self.reads.trailing_error;
            Handle::from_future(async move {
                if let Some(released) = gate {
                    let _ = released.await;
                }
                let _permit = match &admission {
                    Some((permits, _)) => Some(permits.acquire().await.unwrap()),
                    None => None,
                };
                if let Some((_, attempts)) = &admission {
                    let fail = offset == 0 && attempts.fetch_add(1, Ordering::SeqCst) == 0;
                    crate::reschedule().await;
                    crate::reschedule().await;
                    if fail {
                        return Err(Error::ReadFailed);
                    }
                }
                for _ in 0..yields {
                    crate::reschedule().await;
                }
                let bufs = bytes.await?;
                if trailing_error {
                    return Err(Error::ReadFailed);
                }
                Ok(bufs)
            })
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

    /// The pipelining tests use 64-byte pages and a replay buffer of 64 pages, split into
    /// [MAX_READ_AHEAD] + 1 batches, over a blob of [PIPE_BLOB_BATCHES] batches plus a partial
    /// page.
    const PIPE_PAGE_SIZE: NonZeroU16 = NZU16!(64);
    const PIPE_PHYSICAL_PAGE: usize = 64 + Checksum::SIZE;
    const PIPE_BUFFER_PAGES: usize = 64;
    const PIPE_BUFFER_BYTES: usize = PIPE_BUFFER_PAGES * PIPE_PHYSICAL_PAGE;
    const PIPE_BATCH_PAGES: usize = PIPE_BUFFER_PAGES / (MAX_READ_AHEAD + 1);
    const PIPE_BATCH_BYTES: usize = PIPE_BATCH_PAGES * PIPE_PHYSICAL_PAGE;
    const PIPE_BATCH_LOGICAL: usize = PIPE_BATCH_PAGES * 64;
    const PIPE_BLOB_BATCHES: usize = MAX_READ_AHEAD + 2;
    const PIPE_BLOB_BYTES: usize = PIPE_BLOB_BATCHES * PIPE_BATCH_LOGICAL + 10;

    /// Write `len` patterned bytes through a recording blob with `page_size` pages and a write
    /// buffer of `buffer` bytes that serves reads as `reads` say, and return its sealed view, the
    /// recorded reads, and the bytes.
    async fn recorded_blob(
        context: &deterministic::Context,
        name: &[u8],
        page_size: NonZeroU16,
        buffer: usize,
        len: usize,
        reads: Reads,
    ) -> (
        Sealed<GroupingBlob<<deterministic::Context as crate::Storage>::Blob>>,
        Calls,
        Vec<u8>,
        Gates,
    ) {
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let gates = Gates::default();
        let (blob, size) = context.open("pipelining", name).await.unwrap();
        let blob = GroupingBlob {
            inner: blob,
            calls: calls.clone(),
            reads,
            gates: gates.clone(),
        };
        let cache = CacheRef::new(page_size, NZUsize!(4));
        let writer = Writer::new(blob, size, buffer, cache).await.unwrap();
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let (writer, _) = writer.append(&data).await.unwrap();
        let (_, sealed) = writer.snapshot().await.unwrap();
        calls.lock().clear();
        (sealed, calls, data, gates)
    }

    /// A [recorded_blob] of [PIPE_BLOB_BYTES] bytes with the pipelining tests' sizes.
    async fn piped_blob(
        context: &deterministic::Context,
        name: &[u8],
        reads: Reads,
    ) -> (
        Sealed<GroupingBlob<<deterministic::Context as crate::Storage>::Blob>>,
        Calls,
        Vec<u8>,
        Gates,
    ) {
        recorded_blob(
            context,
            name,
            PIPE_PAGE_SIZE,
            PIPE_BUFFER_BYTES,
            PIPE_BLOB_BYTES,
            reads,
        )
        .await
    }

    /// The reads a replay of [PIPE_BLOB_BYTES] bytes starts, one per batch.
    fn piped_calls(batches: std::ops::Range<usize>) -> Vec<(bool, Vec<(u64, usize)>)> {
        batches
            .map(|i| {
                (
                    true,
                    vec![((i * PIPE_BATCH_BYTES) as u64, PIPE_BATCH_BYTES)],
                )
            })
            .collect()
    }

    /// The reads the first fill of a replay issues with batches of `batch` pipelining-test pages,
    /// one for the decoder and [MAX_READ_AHEAD] ahead of it.
    fn first_fill_calls(batch: usize) -> Vec<(bool, Vec<(u64, usize)>)> {
        let len = batch * PIPE_PHYSICAL_PAGE;
        (0..=MAX_READ_AHEAD)
            .map(|i| (true, vec![((i * len) as u64, len)]))
            .collect()
    }

    /// Consume `expected.len()` buffered bytes, checking them against `expected`.
    async fn take<B: Blob>(replay: &mut Replay<B>, expected: &[u8]) {
        assert!(replay.ensure(expected.len()).await.unwrap());
        assert_eq!(replay.copy_to_bytes(expected.len()).as_ref(), expected);
    }

    /// Holding reads in flight must not cost the replay its `Sync` bound.
    #[test]
    fn test_replay_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Replay<<deterministic::Context as crate::Storage>::Blob>>();
    }

    /// A read ahead that fails is read again on demand, so the replay sees every byte.
    #[test]
    fn test_failed_read_ahead_is_read_again_on_demand() {
        deterministic::Runner::default().start(|context| async move {
            let reads = Reads {
                fail_once: Some((PIPE_BATCH_BYTES as u64, Arc::new(AtomicUsize::new(0)))),
                ..Reads::default()
            };
            let (sealed, calls, data, _) =
                piped_blob(&context, b"speculative-failure", reads).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();
            take(&mut replay, &data[..PIPE_BATCH_LOGICAL]).await;
            take(&mut replay, &data[PIPE_BATCH_LOGICAL..]).await;
            assert!(!replay.ensure(1).await.unwrap());
            assert_eq!(
                calls
                    .lock()
                    .iter()
                    .filter(|(_, ranges)| ranges[0].0 == PIPE_BATCH_BYTES as u64)
                    .count(),
                2
            );
        });
    }

    /// A blob whose started reads take turns only while their handles are polled models reads
    /// ahead that can no longer complete, so a retry must not wait on them.
    #[rstest::rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    #[case(4)]
    fn test_retry_does_not_wait_on_queued_reads(
        #[case] permits: usize,
        #[values(false, true)] cancel: bool,
    ) {
        use crate::Clock as _;
        deterministic::Runner::default().start(|context| async move {
            let admission = Arc::new(tokio::sync::Semaphore::new(permits));
            let attempts = Arc::new(AtomicUsize::new(0));
            let reads = Reads {
                admission: Some((admission, attempts.clone())),
                ..Reads::default()
            };
            let (sealed, _, data, _) = piped_blob(&context, b"permit-retry", reads).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();
            if cancel {
                let mut first = Box::pin(replay.ensure(1));
                assert!(
                    first
                        .as_mut()
                        .poll(&mut Context::from_waker(noop_waker_ref()))
                        .is_pending()
                );
                drop(first);
            } else {
                assert!(matches!(replay.ensure(1).await, Err(Error::ReadFailed)));
            }
            assert!(attempts.load(Ordering::SeqCst) >= 1);
            commonware_macros::select! {
                result = replay.ensure(1) => assert!(result.unwrap()),
                _ = context.sleep(std::time::Duration::from_secs(1)) => {
                    panic!("retry hung with {permits} permits, cancellation {cancel}");
                },
            }
            take(&mut replay, &data[..PIPE_BATCH_LOGICAL]).await;
        });
    }

    #[test_traced]
    fn test_batches_split_the_buffer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // A buffer splits into MAX_READ_AHEAD + 1 batches, each rounded up to whole pages, so
            // a buffer of fewer pages than batches keeps single pages in flight.
            let full = MAX_READ_AHEAD + 1;
            for (pages, batch) in [
                (1, 1),
                (full - 1, 1),
                (full, 1),
                (full + 1, 2),
                (2 * full - 1, 2),
                (2 * full + 1, 3),
                (PIPE_BUFFER_PAGES, PIPE_BATCH_PAGES),
            ] {
                let (sealed, calls, _, _) = recorded_blob(
                    &context,
                    format!("depth-{pages}").as_bytes(),
                    PIPE_PAGE_SIZE,
                    pages * PIPE_PHYSICAL_PAGE,
                    PIPE_BLOB_BYTES,
                    Reads::default(),
                )
                .await;
                let mut replay = sealed
                    .replay(NZUsize!(pages * PIPE_PHYSICAL_PAGE), ReadOptions::default())
                    .unwrap();
                assert!(replay.ensure(1).await.unwrap());
                assert_eq!(*calls.lock(), first_fill_calls(batch), "{pages} pages");
            }
        });
    }

    #[test_traced]
    fn test_fill_keeps_batches_in_flight() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (sealed, calls, data, _) =
                piped_blob(&context, b"pipeline", Reads::default()).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();

            // The first fill issues the first batch and MAX_READ_AHEAD more before waiting, all
            // of which fit within the buffer together.
            let ahead = MAX_READ_AHEAD;
            assert!(replay.ensure(1).await.unwrap());
            assert_eq!(*calls.lock(), piped_calls(0..ahead + 1));

            // Decoding a batch issues nothing, and reaching the next batch tops the queue up.
            take(&mut replay, &data[..PIPE_BATCH_LOGICAL]).await;
            assert_eq!(calls.lock().len(), ahead + 1);
            take(
                &mut replay,
                &data[PIPE_BATCH_LOGICAL..2 * PIPE_BATCH_LOGICAL],
            )
            .await;
            assert_eq!(*calls.lock(), piped_calls(0..ahead + 2));
            take(
                &mut replay,
                &data[2 * PIPE_BATCH_LOGICAL..PIPE_BLOB_BATCHES * PIPE_BATCH_LOGICAL],
            )
            .await;
            assert_eq!(*calls.lock(), piped_calls(0..PIPE_BLOB_BATCHES));

            // The frozen partial page needs no read.
            take(&mut replay, &data[PIPE_BLOB_BATCHES * PIPE_BATCH_LOGICAL..]).await;
            assert!(!replay.ensure(1).await.unwrap());
            assert!(replay.is_exhausted());
        });
    }

    #[test_traced]
    fn test_seek_discards_the_batches_in_flight() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Reads complete only when released, so the batches read ahead stay in flight until
            // the seek discards them.
            let reads = Reads {
                gated: true,
                ..Reads::default()
            };
            let (sealed, calls, data, gates) = piped_blob(&context, b"seek", reads).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();
            let ahead = MAX_READ_AHEAD;
            {
                let mut fill = Box::pin(replay.ensure(1));
                assert!(
                    fill.as_mut()
                        .poll(&mut Context::from_waker(noop_waker_ref()))
                        .is_pending()
                );
                gates.release(0);
                assert!(fill.await.unwrap());
            }
            assert_eq!(calls.lock().len(), ahead + 1);
            let in_flight: Vec<u64> = (1..=ahead).map(|i| (i * PIPE_BATCH_BYTES) as u64).collect();
            assert_eq!(gates.open(), in_flight);

            // Seeking into the second-to-last batch discards the batches in flight, which
            // nothing awaits any more, and reads from there.
            let batch = PIPE_BLOB_BATCHES - 2;
            let offset = batch * PIPE_BATCH_LOGICAL + 5;
            replay.seek_to(offset as u64).unwrap();
            assert!(gates.open().is_empty());
            {
                let mut fill = Box::pin(replay.ensure(1));
                assert!(
                    fill.as_mut()
                        .poll(&mut Context::from_waker(noop_waker_ref()))
                        .is_pending()
                );
                for i in batch..PIPE_BLOB_BATCHES {
                    gates.release((i * PIPE_BATCH_BYTES) as u64);
                }
                assert!(fill.await.unwrap());
            }
            take(&mut replay, &data[offset..]).await;
            assert!(!replay.ensure(1).await.unwrap());
            assert_eq!(
                calls.lock()[ahead + 1..],
                piped_calls(batch..PIPE_BLOB_BATCHES)
            );
        });
    }

    #[test_traced]
    fn test_failed_fill_reads_the_same_batch_again() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let fail_from = Some(PIPE_BATCH_BYTES as u64);
            let reads = Reads {
                fail_from,
                ..Reads::default()
            };
            let (sealed, calls, data, _) = piped_blob(&context, b"retry", reads).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();
            take(&mut replay, &data[..PIPE_BATCH_LOGICAL]).await;

            // A failed speculative read is reissued on demand. Persistent errors leave the
            // decoder's position unchanged for a subsequent fill.
            for _ in 0..2 {
                assert!(matches!(replay.ensure(1).await, Err(Error::ReadFailed)));
            }
            let ahead = MAX_READ_AHEAD;
            let mut expected = piped_calls(0..ahead + 2);
            expected.extend(piped_calls(1..ahead + 2));
            expected.extend(piped_calls(1..ahead + 2));
            assert_eq!(*calls.lock(), expected);
        });
    }

    #[test_traced]
    fn test_dropped_fill_reads_the_same_batch_again() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Reads yield before completing, so a fill can be dropped while it waits on one.
            let reads = Reads {
                yields: 2,
                ..Reads::default()
            };
            let (sealed, calls, data, _) = piped_blob(&context, b"dropped", reads).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();

            // Drop a fill while its batch is still being read.
            {
                let mut fill = Box::pin(replay.ensure(1));
                assert!(
                    fill.as_mut()
                        .poll(&mut Context::from_waker(noop_waker_ref()))
                        .is_pending()
                );
            }
            let ahead = MAX_READ_AHEAD;
            assert_eq!(*calls.lock(), piped_calls(0..ahead + 1));

            // The next fill discards the queued reads and starts again at the decoder's
            // position, so the decoder sees the right bytes.
            take(&mut replay, &data[..2 * PIPE_BATCH_LOGICAL]).await;
            let mut expected = piped_calls(0..ahead + 1);
            expected.extend(piped_calls(0..ahead + 2));
            assert_eq!(*calls.lock(), expected);
        });
    }

    #[test_traced]
    fn test_batches_landing_before_and_after_their_wait_are_served() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Reads complete only when released, so a batch read ahead can land before the
            // decoder asks for it or while the decoder is already waiting on it.
            let reads = Reads {
                gated: true,
                ..Reads::default()
            };
            let (sealed, calls, data, gates) = piped_blob(&context, b"gated", reads).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();

            // The first fill issues the first batch and MAX_READ_AHEAD more, then waits on the
            // first. Releasing the second before the first lands it while nobody awaits it.
            {
                let mut fill = Box::pin(replay.ensure(1));
                assert!(
                    fill.as_mut()
                        .poll(&mut Context::from_waker(noop_waker_ref()))
                        .is_pending()
                );
                assert_eq!(calls.lock().len(), MAX_READ_AHEAD + 1);
                gates.release(PIPE_BATCH_BYTES as u64);
                gates.release(0);
                assert!(fill.await.unwrap());
            }
            take(&mut replay, &data[..PIPE_BATCH_LOGICAL]).await;

            // The landed second batch is served without another read.
            take(
                &mut replay,
                &data[PIPE_BATCH_LOGICAL..2 * PIPE_BATCH_LOGICAL],
            )
            .await;
            assert_eq!(calls.lock().len(), MAX_READ_AHEAD + 2);

            // The third is released while a fill waits on it with the decoder's waker, which
            // the completion must wake.
            let wakes = Arc::new(Wakes::default());
            let waker = futures::task::waker(wakes.clone());
            {
                let mut fill = Box::pin(replay.ensure(1));
                assert!(
                    fill.as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                gates.release(2 * PIPE_BATCH_BYTES as u64);
                assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
                assert!(matches!(
                    fill.as_mut().poll(&mut Context::from_waker(&waker)),
                    Poll::Ready(Ok(true))
                ));
            }
            take(
                &mut replay,
                &data[2 * PIPE_BATCH_LOGICAL..3 * PIPE_BATCH_LOGICAL],
            )
            .await;
        });
    }

    /// Counts the wakes a pending fill receives.
    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl futures::task::ArcWake for Wakes {
        fn wake_by_ref(wakes: &Arc<Self>) {
            wakes.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test_traced]
    fn test_read_error_after_the_batch_fails_the_fill() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // A started read that reads its bytes and then fails has failed.
            let reads = Reads {
                trailing_error: true,
                ..Reads::default()
            };
            let (sealed, _, _, _) = piped_blob(&context, b"late-error", reads).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();
            assert!(matches!(replay.ensure(1).await, Err(Error::ReadFailed)));
        });
    }

    #[test]
    fn test_replay_buf_bytes_share_pages() {
        let source = bytes::Bytes::from_static(b"abcd............efgh............");
        let range = source.as_ptr_range();
        let mut replay = ReplayBuf::new(16, 4);
        replay.push(
            BufferState {
                buffer: source,
                num_pages: 2,
                last_page_len: 4,
            },
            8,
        );

        let first = replay.copy_to_bytes(3);
        assert_eq!(first.as_ref(), b"abc");
        assert!(range.contains(&first.as_ptr()));

        let crossing = replay.copy_to_bytes(3);
        assert_eq!(crossing.as_ref(), b"def");
        assert!(!range.contains(&crossing.as_ptr()));

        let last = replay.copy_to_bytes(2);
        assert_eq!(last.as_ref(), b"gh");
        assert!(range.contains(&last.as_ptr()));
        assert_eq!(replay.remaining(), 0);
    }

    #[test]
    fn test_replay_buf_copy_to_slice_page_boundaries() {
        let source = bytes::Bytes::from_static(b"abcd............efgh............ijkl............");
        let mut replay = ReplayBuf::new(16, 4);
        replay.push(
            BufferState {
                buffer: source,
                num_pages: 3,
                last_page_len: 4,
            },
            12,
        );

        // Ends inside the first page.
        let mut inside = [0u8; 3];
        replay.try_copy_to_slice(&mut inside).unwrap();
        assert_eq!(&inside, b"abc");
        assert_eq!(replay.chunk(), b"d");
        assert_eq!(replay.remaining(), 9);

        // Ends exactly at the end of a non-final page.
        let mut boundary = [0u8; 1];
        replay.try_copy_to_slice(&mut boundary).unwrap();
        assert_eq!(&boundary, b"d");
        assert_eq!(replay.chunk(), b"efgh");
        assert_eq!(replay.remaining(), 8);

        // Spans the page boundary.
        let mut spanning = [0u8; 6];
        replay.try_copy_to_slice(&mut spanning).unwrap();
        assert_eq!(&spanning, b"efghij");
        assert_eq!(replay.chunk(), b"kl");
        assert_eq!(replay.remaining(), 2);

        // Ends exactly at the end of the last page.
        let mut tail = [0u8; 2];
        replay.try_copy_to_slice(&mut tail).unwrap();
        assert_eq!(&tail, b"kl");
        assert_eq!(replay.chunk(), b"");
        assert_eq!(replay.remaining(), 0);

        let err = replay.try_copy_to_slice(&mut [0u8; 1]).unwrap_err();
        assert_eq!(err.requested, 1);
        assert_eq!(err.available, 0);
    }

    const PAGE_SIZE: NonZeroU16 = NZU16!(103);
    const BUFFER_PAGES: usize = 2;

    #[test_traced("DEBUG")]
    fn test_replay_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref = super::super::CacheRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let mut append = Writer::new(blob, blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data spanning multiple pages
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            (append, _) = append.append(&data).await.unwrap();
            append = append.sync().await.unwrap();

            // Create Replay
            let (_, mut replay) = append
                .replay(NZUsize!(BUFFER_PAGES), ReadOptions::default())
                .await
                .unwrap();

            // Ensure all data is available
            replay.ensure(300).await.unwrap();

            // Verify we got all the data
            assert_eq!(replay.remaining(), 300);

            // Read all data via Buf interface
            let mut collected = Vec::new();
            while replay.remaining() > 0 {
                let chunk = replay.chunk();
                collected.extend_from_slice(chunk);
                let len = chunk.len();
                replay.advance(len);
            }
            assert_eq!(collected, data);
        });
    }

    #[test_traced("DEBUG")]
    fn test_replay_partial_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();

            let cache_ref = super::super::CacheRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let mut append = Writer::new(blob, blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data that doesn't fill the last page
            let data: Vec<u8> = (1u8..=(PAGE_SIZE.get() + 10) as u8).collect();
            (append, _) = append.append(&data).await.unwrap();
            append = append.sync().await.unwrap();

            let (_, mut replay) = append
                .replay(NZUsize!(BUFFER_PAGES), ReadOptions::default())
                .await
                .unwrap();

            // Ensure all data is available
            replay.ensure(data.len()).await.unwrap();

            assert_eq!(replay.remaining(), data.len());
        });
    }

    #[test_traced("DEBUG")]
    fn test_replay_cross_buffer_boundary() {
        // Use a one-page buffer to force separate BufferStates per page.
        // This tests navigation across multiple BufferStates in the VecDeque.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref = super::super::CacheRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let mut append = Writer::new(blob, blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data spanning 4 pages (4 * 103 = 412 bytes, with last page partial)
            let data: Vec<u8> = (0u8..=255).cycle().take(400).collect();
            (append, _) = append.append(&data).await.unwrap();
            append = append.sync().await.unwrap();

            // Create Replay with a buffer that holds one page, so every batch is one page.
            // Physical page size = 103 + 12 = 115 bytes.
            // Buffer size of 115 gives 115/115 = 1 page.
            let (_, mut replay) = append
                .replay(NZUsize!(115), ReadOptions::default())
                .await
                .unwrap();

            // Load all four logical pages with one-page prefetches and a frozen partial tail.
            assert!(replay.ensure(400).await.unwrap());
            assert_eq!(replay.remaining(), 400);

            // Read all data via Buf interface, verifying navigation across BufferStates.
            let mut collected = Vec::new();
            let mut chunks_read = 0;
            while replay.remaining() > 0 {
                let chunk = replay.chunk();
                assert!(
                    !chunk.is_empty(),
                    "chunk() returned empty but remaining > 0"
                );
                collected.extend_from_slice(chunk);
                let len = chunk.len();
                replay.advance(len);
                chunks_read += 1;
            }

            assert_eq!(collected, data);

            // With one-page batches and 4 pages, we expect at least 4 chunks
            // (one per page, though partial reads could result in more).
            assert!(
                chunks_read >= 4,
                "Expected at least 4 chunks for 4 pages, got {}",
                chunks_read
            );
        });
    }

    #[test_traced("DEBUG")]
    fn test_replay_empty_blob() {
        // Test that replaying an empty blob works correctly.
        // ensure() should return Ok(false) when no data is available.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref = super::super::CacheRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Writer::new(blob, blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Don't write any data - blob remains empty
            assert_eq!(append.size(), 0);

            // Create Replay on empty blob
            let (_, mut replay) = append
                .replay(NZUsize!(BUFFER_PAGES), ReadOptions::default())
                .await
                .unwrap();

            // Verify initial state - remaining is 0, but not yet marked exhausted
            // (exhausted is set after first fill attempt)
            assert_eq!(replay.remaining(), 0);

            // ensure(0) should succeed (we have >= 0 bytes)
            assert!(replay.ensure(0).await.unwrap());

            // ensure(1) should return Ok(false) - not enough data, and marks exhausted
            assert!(!replay.ensure(1).await.unwrap());

            // Now should be marked as exhausted after the fill attempt
            assert!(replay.is_exhausted());

            // chunk() should return empty slice
            assert!(replay.chunk().is_empty());

            // remaining should still be 0
            assert_eq!(replay.remaining(), 0);
        });
    }

    #[test_traced("DEBUG")]
    fn test_replay_seek_to() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();

            let cache_ref = super::super::CacheRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let mut append = Writer::new(blob, blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data spanning multiple pages
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            (append, _) = append.append(&data).await.unwrap();
            append = append.sync().await.unwrap();

            let (_, mut replay) = append
                .replay(NZUsize!(BUFFER_PAGES), ReadOptions::default())
                .await
                .unwrap();

            // Seek forward, read, then seek backward
            replay.seek_to(150).unwrap();
            replay.ensure(50).await.unwrap();
            assert_eq!(replay.get_u8(), data[150]);

            // Seek back to start
            replay.seek_to(0).unwrap();
            replay.ensure(1).await.unwrap();
            assert_eq!(replay.get_u8(), data[0]);

            // Seek beyond blob size should error
            assert!(replay.seek_to(data.len() as u64 + 1).is_err());

            // Seek into the blob, then drain the remaining bytes and verify their exact contents.
            let seek_offset = 150usize;
            replay.seek_to(seek_offset as u64).unwrap();
            let expected_remaining = data.len() - seek_offset;
            let mut collected = Vec::new();
            loop {
                // Load more data if needed
                if !replay.ensure(1).await.unwrap() {
                    break; // No more data available
                }
                let chunk = replay.chunk();
                if chunk.is_empty() {
                    break;
                }
                collected.extend_from_slice(chunk);
                let len = chunk.len();
                replay.advance(len);
            }
            assert_eq!(
                collected.len(),
                expected_remaining,
                "After seeking to {}, should read {} bytes but got {}",
                seek_offset,
                expected_remaining,
                collected.len()
            );
            assert_eq!(collected, &data[seek_offset..]);

            // Seeking into the frozen tail must work after exhaustion, including at EOF.
            for offset in [data.len(), 250, 299] {
                replay.seek_to(Widen::widen(offset)).unwrap();
                let remaining = data.len() - offset;
                assert!(!replay.ensure(remaining + 1).await.unwrap());
                assert_eq!(replay.copy_to_bytes(remaining).as_ref(), &data[offset..]);
            }
        });
    }
}
