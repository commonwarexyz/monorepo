use super::Checksum;
use crate::{Blob, Error, IoBuf, IoBufsMut, ReadOptions};
use bytes::{BufMut, Bytes, BytesMut, TryGetError};
use commonware_codec::{Buf, FixedSize};
use commonware_utils::Widen;
use futures::{StreamExt as _, future::BoxFuture, task::noop_waker_ref};
use std::{
    collections::VecDeque,
    num::NonZeroU16,
    ops::Range,
    sync::Arc,
    task::{Context, Poll},
};
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

/// Smallest batch read through [`Blob::read_many`] rather than [`Blob::read_at`].
///
/// On tokio/Linux a `DONT_CACHE` batch read through `read_many` is direct I/O, which gets no
/// kernel readahead: a batch this large keeps the device busy on its own, while smaller batches
/// replay faster through the OS page cache, where readahead runs ahead of them.
const DIRECT_BATCH_BYTES: usize = 128 << 10;

/// Most batches kept in flight ahead of the decoder.
///
/// A read costs a blocking-thread or AIO round trip whose latency a fast decoder does not cover
/// while it works on one batch, so several are read ahead. A batch is `1 / (MAX_READ_AHEAD + 1)`
/// of the replay buffer, so the batches in flight and the one being decoded together fill the
/// buffer. A buffer too small for that many pages reads ahead fewer, down to one page at a time.
const MAX_READ_AHEAD: usize = 3;

/// The physical bytes of one batch.
type Batch = BoxFuture<'static, Result<IoBufsMut, Error>>;

/// A batch issued ahead of the decoder.
struct Inflight {
    /// First page of the batch.
    page: u64,
    /// Number of pages in the batch.
    pages: usize,
    /// The read.
    state: State,
}

/// Progress of an issued batch.
enum State {
    /// Still being read.
    Reading(Batch),
    /// Landed before the decoder reached it.
    Landed(Result<IoBufsMut, Error>),
}

impl Inflight {
    /// Start reading the batch. A future does nothing until polled, so poll it once now: the
    /// blob begins the read on that poll, and it progresses while the decoder works on the batch
    /// before this one.
    fn start(mut self) -> Self {
        if let State::Reading(batch) = &mut self.state
            && let Poll::Ready(result) = batch
                .as_mut()
                .poll(&mut Context::from_waker(noop_waker_ref()))
        {
            self.state = State::Landed(result);
        }
        self
    }

    /// Wait for the batch's bytes.
    async fn wait(self) -> Result<IoBufsMut, Error> {
        match self.state {
            State::Reading(batch) => batch.await,
            State::Landed(result) => result,
        }
    }
}

/// Async I/O component that prefetches pages and validates CRCs.
///
/// Pages are read in batches of `batch_pages` pages. Up to `read_ahead` batches after the one
/// being decoded are kept in flight so the device works while the decoder does; they and the
/// batch being decoded together fill the replay buffer, and an item straddling two batches keeps
/// the earlier one as well. Batches of at least [`DIRECT_BATCH_BYTES`] are read through
/// [`Blob::read_many`] and smaller ones through [`Blob::read_at`]. A batch is validated when it
/// is handed to the decoder, so a bad page fails the fill that reaches it, and a failed read
/// fails the fill that reaches its batch. A failed or dropped fill leaves the decoder's position
/// unchanged, so the next fill reads the same pages again; the batches queued after them stay
/// in flight.
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
    /// Most batches kept in flight ahead of the decoder.
    read_ahead: usize,
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
    /// The last page may be logically partial (CRC length < logical page size), but
    /// all preceding pages must be logically full. A logically partial non-last page
    /// indicates corruption and will cause an `Error::InvalidChecksum`.
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

        let read_ahead = buffer_pages.saturating_sub(1).clamp(1, MAX_READ_AHEAD);
        Self {
            blob,
            physical_page_size,
            page_size,
            physical_blob_size,
            logical_blob_size,
            partial_page: partial_page.map(Bytes::from),
            blob_page: 0,
            batch_pages: (buffer_pages / (read_ahead + 1)).max(1),
            read_ahead,
            inflight: VecDeque::with_capacity(read_ahead),
            read_options,
        }
    }

    /// Position the reader at `page`, discarding the batches read ahead.
    fn seek_to_page(&mut self, page: u64) {
        self.blob_page = page;
        self.inflight.clear();
    }

    /// Issue batches after the queued ones, or after `consumed_end` when none is queued, until
    /// `read_ahead` are in flight or the blob ends.
    fn top_up(&mut self, consumed_end: u64) -> Result<(), Error> {
        let mut next = self
            .inflight
            .back()
            .map_or(consumed_end, |batch| batch.page + Widen::widen(batch.pages));
        while self.inflight.len() < self.read_ahead {
            let Some(batch) = self.issue(next)? else {
                break;
            };
            next = batch.page + Widen::widen(batch.pages);
            self.inflight.push_back(batch.start());
        }
        Ok(())
    }

    /// Issue the batch starting at `page`, or `None` when no page remains there.
    fn issue(&self, page: u64) -> Result<Option<Inflight>, Error> {
        let physical_page_size: u64 = Widen::widen(self.physical_page_size);
        let start = page
            .checked_mul(physical_page_size)
            .ok_or(Error::OffsetOverflow)?;
        if start >= self.physical_blob_size {
            return Ok(None);
        }
        let pages = ((self.physical_blob_size - start) / physical_page_size)
            .min(Widen::widen(self.batch_pages)) as usize;

        let blob = self.blob.clone();
        let read_options = self.read_options;
        let len = pages * self.physical_page_size;
        let batch = Box::pin(async move {
            if len < DIRECT_BATCH_BYTES {
                return blob.read_at(start, len, read_options).await;
            }
            // The one range is yielded exactly once (see Blob::read_many).
            let ranges = [(start, len)];
            let mut reads = std::pin::pin!(blob.read_many(&ranges, read_options));
            let (_, bufs) = reads.next().await.ok_or(Error::ReadFailed)??;
            Ok(bufs)
        });
        Ok(Some(Inflight {
            page,
            pages,
            state: State::Reading(batch),
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

        // Take the first batch read ahead when it is the one the decoder needs, and read from
        // the decoder's position otherwise: a fill that failed or was dropped leaves that
        // position behind the batch it took, while the batches after it stay queued. Then top
        // the queue up before waiting so the device works through the wait and the decode.
        let batch = match self.inflight.front() {
            Some(front) if front.page == self.blob_page => {
                self.inflight.pop_front().expect("front exists")
            }
            _ => self
                .issue(self.blob_page)?
                .expect("pages remain to be issued"),
        };
        self.top_up(batch.page + Widen::widen(batch.pages))?;
        let physical_buf = Bytes::from(batch.wait().await?.coalesce().freeze());

        // Keep the total page count in u64 and narrow only the bounded batch.
        let max_pages =
            (self.physical_blob_size - start_offset) / Widen::widen(self.physical_page_size);
        let pages_to_read = physical_buf.len() / self.physical_page_size;
        assert!(
            pages_to_read > 0 && Widen::widen(pages_to_read) <= max_pages,
            "a batch covers pages the reader issued"
        );

        // Validate CRCs and compute total logical bytes
        let mut total_logical = 0usize;
        let mut last_len = 0usize;
        let is_final_batch = Widen::widen(pages_to_read) == max_pages;
        for page_idx in 0..pages_to_read {
            let page_start = page_idx * self.physical_page_size;
            let page_slice =
                &physical_buf.as_ref()[page_start..page_start + self.physical_page_size];
            let Some(checksum) = Checksum::validate_page(page_slice) else {
                error!(page = self.blob_page + page_idx as u64, "CRC mismatch");
                return Err(Error::InvalidChecksum);
            };
            let len = checksum.len as usize;

            // Only the final page in the blob may have partial length
            let is_last_page_in_blob =
                self.partial_page.is_none() && is_final_batch && page_idx + 1 == pages_to_read;
            if !is_last_page_in_blob && len != self.page_size {
                error!(
                    page = self.blob_page + page_idx as u64,
                    expected = self.page_size,
                    actual = len,
                    "non-last page has partial length"
                );
                return Err(Error::InvalidChecksum);
            }

            let logical_start = (self.blob_page + page_idx as u64)
                .checked_mul(self.page_size as u64)
                .ok_or(Error::OffsetOverflow)?;
            let logical_remaining = self.logical_blob_size.saturating_sub(logical_start);
            let logical_remaining_in_page = logical_remaining.min(self.page_size as u64) as usize;
            let exposed_len = len.min(logical_remaining_in_page);

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
    /// bytes, or `None` when no page is readable.
    fn chunk_range(&self) -> Option<(&BufferState, Range<usize>)> {
        let buf = self.buffers.front()?;
        if self.current_page >= buf.num_pages {
            return None;
        }
        let page_len = Self::page_len(buf, self.current_page, self.page_size);
        let page_start = self.current_page * self.physical_page_size;
        Some((buf, page_start + self.offset_in_page..page_start + page_len))
    }

    /// Returns the current chunk as a view sharing the allocation backing its page, without
    /// advancing.
    fn chunk_bytes(&self) -> Bytes {
        self.chunk_range()
            .map_or_else(Bytes::new, |(buf, range)| buf.buffer.slice(range))
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
/// delaying reuse of pooled buffers. Fields spanning pages are copied into separate allocations.
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

    /// Returns the bytes [`bytes::Buf::chunk`] would return as a view sharing the allocation
    /// backing the current page, without advancing.
    ///
    /// The view ends at the current page's logical end. A decoder can take it once, decode many
    /// fields from it, and then [`bytes::Buf::advance`] past what it consumed, which costs one
    /// page lookup instead of one per field. Byte fields retained from the view keep that
    /// allocation alive exactly as fields read through this replay do.
    pub fn chunk_bytes(&self) -> Bytes {
        self.buffer.chunk_bytes()
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
        Handle, IoBufs, Runner as _, Storage as _, WriteOptions, buffer::paged::CacheRef,
        deterministic,
    };
    use bytes::Buf as _;
    use commonware_macros::test_traced;
    use commonware_utils::{NZU16, NZUsize, sync::Mutex};
    use futures::stream;

    /// Every read, in call order: whether it was a `read_many` call, and its ranges.
    type Calls = Arc<Mutex<Vec<(bool, Vec<(u64, usize)>)>>>;

    /// Records every read and fails reads at or past an offset.
    struct GroupingBlob<B> {
        inner: B,
        calls: Calls,
        fail_from: Option<u64>,
    }

    impl<B> GroupingBlob<B> {
        fn record(&self, many: bool, ranges: &[(u64, usize)]) -> Result<(), Error> {
            self.calls.lock().push((many, ranges.to_vec()));
            if self
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
            self.record(false, &[(offset, len)])?;
            self.inner.read_at_buf(offset, len, bufs, options).await
        }

        async fn read_at(
            &self,
            offset: u64,
            len: usize,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.record(false, &[(offset, len)])?;
            self.inner.read_at(offset, len, options).await
        }

        fn read_many(
            &self,
            ranges: &[(u64, usize)],
            options: ReadOptions,
        ) -> impl futures::Stream<Item = Result<(usize, IoBufsMut), Error>> + Send {
            if let Err(err) = self.record(true, ranges) {
                return stream::iter([Err(err)]).left_stream();
            }
            self.inner.read_many(ranges, options).right_stream()
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

    /// Pages and batches of the pipelining tests: 64-byte pages, a replay buffer of 64 pages,
    /// so batches of 16 pages with three read ahead, and a blob of five batches plus a partial
    /// page. The read sequences below assume that depth.
    const _: () = assert!(MAX_READ_AHEAD == 3);
    const PIPE_PAGE_SIZE: NonZeroU16 = NZU16!(64);
    const PIPE_PHYSICAL_PAGE: usize = 64 + Checksum::SIZE;
    const PIPE_BUFFER_PAGES: usize = 64;
    const PIPE_BUFFER_BYTES: usize = PIPE_BUFFER_PAGES * PIPE_PHYSICAL_PAGE;
    const PIPE_BATCH_PAGES: usize = PIPE_BUFFER_PAGES / (MAX_READ_AHEAD + 1);
    const PIPE_BATCH_BYTES: usize = PIPE_BATCH_PAGES * PIPE_PHYSICAL_PAGE;
    const PIPE_BATCH_LOGICAL: usize = PIPE_BATCH_PAGES * 64;
    const PIPE_BLOB_BYTES: usize = 5 * PIPE_BATCH_LOGICAL + 10;

    /// Write `len` patterned bytes through a recording blob with `page_size` pages and a write
    /// buffer of `buffer` bytes, and return its sealed view, the recorded reads, and the bytes.
    async fn recorded_blob(
        context: &deterministic::Context,
        name: &[u8],
        page_size: NonZeroU16,
        buffer: usize,
        len: usize,
        fail_from: Option<u64>,
    ) -> (
        super::super::Sealed<GroupingBlob<<deterministic::Context as crate::Storage>::Blob>>,
        Calls,
        Vec<u8>,
    ) {
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let (blob, size) = context.open("pipelining", name).await.unwrap();
        let blob = GroupingBlob {
            inner: blob,
            calls: calls.clone(),
            fail_from,
        };
        let cache = CacheRef::from_pooler(context, page_size, NZUsize!(4));
        let writer = Writer::new(blob, size, buffer, cache).await.unwrap();
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let (writer, _) = writer.append(&data).await.unwrap();
        let (_, sealed) = writer.snapshot().await.unwrap();
        calls.lock().clear();
        (sealed, calls, data)
    }

    /// A [recorded_blob] of [PIPE_BLOB_BYTES] bytes with the pipelining tests' sizes.
    async fn piped_blob(
        context: &deterministic::Context,
        name: &[u8],
        fail_from: Option<u64>,
    ) -> (
        super::super::Sealed<GroupingBlob<<deterministic::Context as crate::Storage>::Blob>>,
        Calls,
        Vec<u8>,
    ) {
        recorded_blob(
            context,
            name,
            PIPE_PAGE_SIZE,
            PIPE_BUFFER_BYTES,
            PIPE_BLOB_BYTES,
            fail_from,
        )
        .await
    }

    /// The reads a replay of [PIPE_BLOB_BYTES] bytes issues: one small `read_at` per batch.
    fn piped_calls(batches: std::ops::Range<usize>) -> Vec<(bool, Vec<(u64, usize)>)> {
        batches
            .map(|i| {
                (
                    false,
                    vec![((i * PIPE_BATCH_BYTES) as u64, PIPE_BATCH_BYTES)],
                )
            })
            .collect()
    }

    /// Consume `expected.len()` buffered bytes, checking them against `expected`.
    async fn take<B: Blob>(replay: &mut Replay<B>, expected: &[u8]) {
        assert!(replay.ensure(expected.len()).await.unwrap());
        assert_eq!(replay.copy_to_bytes(expected.len()).as_ref(), expected);
    }

    #[test_traced]
    fn test_fill_keeps_batches_in_flight() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (sealed, calls, data) = piped_blob(&context, b"pipeline", None).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();

            // The first fill issues the first batch and three more before waiting: a quarter of
            // the buffer each, so all four fit within it.
            assert!(replay.ensure(1).await.unwrap());
            assert_eq!(*calls.lock(), piped_calls(0..4));

            // Decoding a batch issues nothing; reaching the next batch tops the queue up.
            take(&mut replay, &data[..PIPE_BATCH_LOGICAL]).await;
            assert_eq!(calls.lock().len(), 4);
            take(
                &mut replay,
                &data[PIPE_BATCH_LOGICAL..2 * PIPE_BATCH_LOGICAL],
            )
            .await;
            assert_eq!(*calls.lock(), piped_calls(0..5));
            take(
                &mut replay,
                &data[2 * PIPE_BATCH_LOGICAL..5 * PIPE_BATCH_LOGICAL],
            )
            .await;
            assert_eq!(*calls.lock(), piped_calls(0..5));

            // The frozen partial page needs no read.
            take(&mut replay, &data[5 * PIPE_BATCH_LOGICAL..]).await;
            assert!(!replay.ensure(1).await.unwrap());
            assert!(replay.is_exhausted());
        });
    }

    #[test_traced]
    fn test_seek_discards_the_batches_in_flight() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (sealed, calls, data) = piped_blob(&context, b"seek", None).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();
            assert!(replay.ensure(1).await.unwrap());
            assert_eq!(calls.lock().len(), 4);

            // Seeking into the fourth batch reads from there, never awaiting the ones in flight.
            let offset = 3 * PIPE_BATCH_LOGICAL + 5;
            replay.seek_to(offset as u64).unwrap();
            take(&mut replay, &data[offset..]).await;
            assert!(!replay.ensure(1).await.unwrap());
            assert_eq!(calls.lock()[4..], piped_calls(3..5));
        });
    }

    #[test_traced]
    fn test_failed_fill_reads_the_same_batch_again() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let fail_from = PIPE_BATCH_BYTES as u64;
            let (sealed, calls, data) = piped_blob(&context, b"retry", Some(fail_from)).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();
            take(&mut replay, &data[..PIPE_BATCH_LOGICAL]).await;

            // The fill that reaches the failed second batch tops the queue up with the fifth
            // before it fails. Every later fill reads the second batch again from the decoder's
            // position, never skipping to the batches still queued after it.
            for _ in 0..2 {
                assert!(matches!(replay.ensure(1).await, Err(Error::ReadFailed)));
            }
            let mut expected = piped_calls(0..4);
            expected.extend(piped_calls(4..5));
            expected.extend(piped_calls(1..2));
            assert_eq!(*calls.lock(), expected);
        });
    }

    #[test_traced]
    fn test_dropped_fill_reads_the_same_batch_again() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Reads yield once before completing, so a fill can be dropped while it waits.
            let calls: Calls = Arc::new(Mutex::new(Vec::new()));
            let (blob, size) = context.open("pipelining", b"dropped").await.unwrap();
            let blob = GroupingBlob {
                inner: crate::mocks::MigratingReadBlob::new(blob, false),
                calls: calls.clone(),
                fail_from: None,
            };
            let cache = CacheRef::from_pooler(&context, PIPE_PAGE_SIZE, NZUsize!(4));
            let writer = Writer::new(blob, size, PIPE_BUFFER_BYTES, cache)
                .await
                .unwrap();
            let data: Vec<u8> = (0..PIPE_BLOB_BYTES).map(|i| (i % 251) as u8).collect();
            let (writer, _) = writer.append(&data).await.unwrap();
            let (_, sealed) = writer.snapshot().await.unwrap();
            calls.lock().clear();
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
            assert_eq!(*calls.lock(), piped_calls(0..4));

            // The next fill reads the first batch again while the three read ahead stay queued,
            // reaching the second batch tops the queue up, and the decoder sees the right bytes.
            take(&mut replay, &data[..2 * PIPE_BATCH_LOGICAL]).await;
            let mut expected = piped_calls(0..4);
            expected.extend(piped_calls(0..1));
            expected.extend(piped_calls(4..5));
            assert_eq!(*calls.lock(), expected);
        });
    }

    #[test_traced]
    fn test_large_batches_read_through_read_many() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Pages of 4 KiB and a buffer of 128 of them make batches of exactly the direct size.
            let page_size = super::super::page_size(4096);
            let physical: usize = 4096;
            let buffer = (MAX_READ_AHEAD + 1) * 32 * physical;
            let batch = buffer / (MAX_READ_AHEAD + 1);
            assert_eq!(batch, DIRECT_BATCH_BYTES);
            let logical = 32 * usize::from(page_size.get());
            let (sealed, calls, data) = recorded_blob(
                &context,
                b"direct",
                page_size,
                buffer,
                3 * logical + 7,
                None,
            )
            .await;
            let mut replay = sealed
                .replay(NZUsize!(buffer), ReadOptions::DONT_CACHE)
                .unwrap();
            assert!(replay.ensure(1).await.unwrap());
            assert_eq!(
                *calls.lock(),
                vec![
                    (true, vec![(0, batch)]),
                    (true, vec![(batch as u64, batch)]),
                    (true, vec![(2 * batch as u64, batch)]),
                ]
            );
            take(&mut replay, &data).await;
            assert!(!replay.ensure(1).await.unwrap());
            assert_eq!(calls.lock().len(), 3);
        });
    }

    #[test_traced]
    fn test_failed_read_fails_the_fill_that_reaches_its_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let fail_from = PIPE_BATCH_BYTES as u64;
            let (sealed, _, data) = piped_blob(&context, b"fail", Some(fail_from)).await;
            let mut replay = sealed
                .replay(NZUsize!(PIPE_BUFFER_BYTES), ReadOptions::default())
                .unwrap();

            // The first batch decodes in full before the second batch's failure surfaces.
            take(&mut replay, &data[..PIPE_BATCH_LOGICAL]).await;
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
    fn test_replay_buf_chunk_bytes_views_the_current_page() {
        let source = bytes::Bytes::from_static(b"abcd............efgh............ij..............");
        let range = source.as_ptr_range();
        let mut replay = ReplayBuf::new(16, 4);
        assert!(replay.chunk_bytes().is_empty());
        replay.push(
            BufferState {
                buffer: source,
                num_pages: 3,
                last_page_len: 2,
            },
            10,
        );

        // The view is the chunk, shares the batch allocation, and does not advance.
        let page = replay.chunk_bytes();
        assert_eq!(page.as_ref(), b"abcd");
        assert_eq!(page.as_ref(), replay.chunk());
        assert!(range.contains(&page.as_ptr()));
        assert_eq!(replay.remaining(), 10);

        // Advancing within the page shortens the view; crossing into the next page moves it,
        // and the view never spans a checksum.
        replay.advance(3);
        assert_eq!(replay.chunk_bytes().as_ref(), b"d");
        replay.advance(1);
        assert_eq!(replay.chunk_bytes().as_ref(), b"efgh");
        replay.advance(4);
        assert_eq!(replay.chunk_bytes().as_ref(), b"ij");
        replay.advance(2);
        assert!(replay.chunk_bytes().is_empty());
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

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
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

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
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
        // Use prefetch_count=1 to force separate BufferStates per page.
        // This tests navigation across multiple BufferStates in the VecDeque.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let mut append = Writer::new(blob, blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data spanning 4 pages (4 * 103 = 412 bytes, with last page partial)
            let data: Vec<u8> = (0u8..=255).cycle().take(400).collect();
            (append, _) = append.append(&data).await.unwrap();
            append = append.sync().await.unwrap();

            // Create Replay with buffer size that results in prefetch_count=1.
            // Physical page size = 103 + 12 = 115 bytes.
            // Buffer size of 115 gives prefetch_pages = 115/115 = 1.
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

            // With prefetch_count=1 and 4 pages, we expect at least 4 chunks
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

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
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

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
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
