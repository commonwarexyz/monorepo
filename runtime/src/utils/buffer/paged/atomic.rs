//! Append-only checked pages over an [`AtomicBlob`].
//!
//! Unlike [`super::Writer`], this writer never rewrites a partial page. Full logical pages carry
//! one trailing CRC32C checksum, while a final partial page remains raw and stores its checksum in
//! the atomic blob's root tag:
//!
//! ```text
//! ([page bytes][CRC32C: u32 big-endian])* [partial page bytes]?
//! ```
//!
//! The first 60 bytes of the root tag are an application-owned marker. This codec owns the final
//! four bytes and updates them whenever the partial page changes. Full pages are validated when
//! read; opening validates only the bounded partial tail.

use crate::{ATOMIC_BLOB_TAG_LEN, AtomicBlob, Buf, Error, Handle, IoBuf, IoBufs};
use commonware_cryptography::{Crc32, Hasher as _};
use futures::FutureExt as _;
use std::{
    collections::VecDeque,
    future::Future,
    num::{NonZeroU16, NonZeroUsize},
};

const CRC_LEN: usize = size_of::<u32>();
/// Number of application-owned marker bytes in an atomic checked-page tag.
pub const ATOMIC_MARKER_LEN: usize = ATOMIC_BLOB_TAG_LEN - CRC_LEN;

const CRC_OFFSET: usize = ATOMIC_MARKER_LEN;
const _: () = assert!(ATOMIC_MARKER_LEN + CRC_LEN == ATOMIC_BLOB_TAG_LEN);

/// Return the logical page size whose atomic physical page occupies `physical_page_size` bytes.
///
/// Atomic checked pages use one four-byte CRC32C footer, so `atomic_page_size(4096)` returns
/// `4092`. Choosing a power-of-two physical size keeps every full page aligned with storage-page
/// boundaries when the V2 payload itself is aligned.
///
/// # Panics
///
/// Panics if `physical_page_size` is not a power of two, cannot hold a CRC footer plus one byte,
/// or yields a logical size that does not fit in `u16`.
pub const fn atomic_page_size(physical_page_size: u32) -> NonZeroU16 {
    assert!(
        physical_page_size.is_power_of_two(),
        "physical page size must be a power of two"
    );
    assert!(
        physical_page_size as usize > CRC_LEN,
        "physical page size must exceed the CRC footer"
    );
    let logical = physical_page_size as usize - CRC_LEN;
    assert!(
        logical <= u16::MAX as usize,
        "logical page size must fit in u16"
    );
    match NonZeroU16::new(logical as u16) {
        Some(size) => size,
        None => unreachable!(),
    }
}

fn checksum(parts: &[&[u8]]) -> u32 {
    let mut hasher = Crc32::default();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().1.as_u32()
}

fn tag(marker: [u8; ATOMIC_MARKER_LEN], tail: &[u8]) -> [u8; ATOMIC_BLOB_TAG_LEN] {
    let mut tag = [0; ATOMIC_BLOB_TAG_LEN];
    tag[..ATOMIC_MARKER_LEN].copy_from_slice(&marker);
    if !tail.is_empty() {
        tag[CRC_OFFSET..].copy_from_slice(&Crc32::checksum(tail).to_be_bytes());
    }
    tag
}

fn marker(tag: &[u8; ATOMIC_BLOB_TAG_LEN]) -> [u8; ATOMIC_MARKER_LEN] {
    tag[..ATOMIC_MARKER_LEN]
        .try_into()
        .expect("marker length is fixed")
}

fn tagged_crc(tag: &[u8; ATOMIC_BLOB_TAG_LEN]) -> u32 {
    u32::from_be_bytes(tag[CRC_OFFSET..].try_into().expect("CRC length is fixed"))
}

fn validate_full_page(page: &[u8], page_size: usize) -> Result<(), Error> {
    let expected_len = page_size
        .checked_add(CRC_LEN)
        .ok_or(Error::OffsetOverflow)?;
    if page.len() != expected_len {
        return Err(Error::InvalidChecksum);
    }
    let expected = u32::from_be_bytes(
        page[page_size..]
            .try_into()
            .expect("full page footer has a fixed length"),
    );
    if Crc32::checksum(&page[..page_size]) != expected {
        return Err(Error::InvalidChecksum);
    }
    Ok(())
}

/// Adapt a backend read to the `Sync` future required by read-only journal interfaces.
fn shared_read<B: AtomicBlob>(
    blob: &B,
    offset: u64,
    len: usize,
) -> impl Future<Output = Result<IoBuf, Error>> + Send + Sync + 'static {
    let blob = blob.clone();
    async move { Ok(blob.read_at(offset, len).await?.coalesce().freeze()) }
        .boxed()
        .shared()
}

/// Immutable point-in-time read view of an [`AtomicWriter`].
///
/// Appends made after the snapshot do not extend its logical size. As with ordinary paged
/// snapshots, rewinding the originating writer into this snapshot's range makes subsequent reads
/// from the snapshot unspecified.
#[derive(Clone)]
pub struct AtomicSnapshot<B: AtomicBlob> {
    blob: B,
    page_size: NonZeroU16,
    size: u64,
    physical_size: u64,
    tail: IoBuf,
    marker: [u8; ATOMIC_MARKER_LEN],
}

impl<B: AtomicBlob> AtomicSnapshot<B> {
    /// Return the logical byte length captured by this snapshot.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Return the underlying physical byte length captured by this snapshot.
    pub const fn physical_size(&self) -> u64 {
        self.physical_size
    }

    /// Return the application-owned marker captured by this snapshot.
    pub const fn marker(&self) -> [u8; ATOMIC_MARKER_LEN] {
        self.marker
    }

    fn view(&self) -> AtomicView<'_, B> {
        AtomicView {
            blob: &self.blob,
            page_size: self.page_size,
            size: self.size,
            tail: self.tail.as_ref(),
        }
    }

    /// Read exactly `len` logical bytes beginning at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        self.view().read_at(offset, len).await
    }

    /// Read logical bytes into `buf` beginning at `offset`.
    pub async fn read_into(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        self.view().read_into(buf, offset).await
    }

    /// Read fixed-size items at sorted, non-overlapping logical offsets.
    ///
    /// `buf` must contain exactly one `item_size` slot per offset. The return value is the number
    /// of items served entirely from the retained partial tail without blob I/O.
    pub async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<usize, Error> {
        self.view().read_many_into(buf, offsets, item_size).await
    }

    /// Create a streaming replay over this snapshot.
    pub fn replay(&self, buffer_size: NonZeroUsize) -> AtomicReplay<B> {
        AtomicReplay::new(self.clone(), buffer_size)
    }
}

#[derive(Clone, Copy)]
struct AtomicView<'a, B: AtomicBlob> {
    blob: &'a B,
    page_size: NonZeroU16,
    size: u64,
    tail: &'a [u8],
}

impl<B: AtomicBlob> AtomicView<'_, B> {
    const fn tail_offset(&self) -> u64 {
        self.size - self.tail.len() as u64
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        let mut out = vec![0; len];
        self.read_into(&mut out, offset).await?;
        Ok(out.into())
    }

    async fn read_into(&self, out: &mut [u8], offset: u64) -> Result<(), Error> {
        let out_len = u64::try_from(out.len()).map_err(|_| Error::OffsetOverflow)?;
        let end = offset.checked_add(out_len).ok_or(Error::OffsetOverflow)?;
        if end > self.size {
            return Err(Error::BlobInsufficientLength);
        }
        if out.is_empty() {
            return Ok(());
        }

        let page_size = u64::from(self.page_size.get());
        let physical_page_size = page_size
            .checked_add(CRC_LEN as u64)
            .ok_or(Error::OffsetOverflow)?;
        let tail_offset = self.tail_offset();
        let stored_end = end.min(tail_offset);

        if offset < stored_end {
            let first_page = offset / page_size;
            let last_page = (stored_end - 1) / page_size;
            let page_count = last_page
                .checked_sub(first_page)
                .and_then(|count| count.checked_add(1))
                .ok_or(Error::OffsetOverflow)?;
            let physical_offset = first_page
                .checked_mul(physical_page_size)
                .ok_or(Error::OffsetOverflow)?;
            let physical_len = page_count
                .checked_mul(physical_page_size)
                .ok_or(Error::OffsetOverflow)?;
            let physical_len = usize::try_from(physical_len).map_err(|_| Error::OffsetOverflow)?;
            let pages = shared_read(self.blob, physical_offset, physical_len).await?;
            let pages = pages.as_ref();
            let physical_page_size =
                usize::try_from(physical_page_size).map_err(|_| Error::OffsetOverflow)?;
            let page_size = usize::from(self.page_size.get());

            for page_index in 0..usize::try_from(page_count).map_err(|_| Error::OffsetOverflow)? {
                let physical_start = page_index
                    .checked_mul(physical_page_size)
                    .ok_or(Error::OffsetOverflow)?;
                let physical_end = physical_start
                    .checked_add(physical_page_size)
                    .ok_or(Error::OffsetOverflow)?;
                let page = pages
                    .get(physical_start..physical_end)
                    .ok_or(Error::InvalidChecksum)?;
                validate_full_page(page, page_size)?;

                let logical_page = first_page
                    .checked_add(page_index as u64)
                    .ok_or(Error::OffsetOverflow)?;
                let logical_start = logical_page
                    .checked_mul(page_size as u64)
                    .ok_or(Error::OffsetOverflow)?;
                let copy_start = offset.max(logical_start);
                let copy_end = stored_end.min(logical_start + page_size as u64);
                let src_start = usize::try_from(copy_start - logical_start)
                    .map_err(|_| Error::OffsetOverflow)?;
                let copy_len =
                    usize::try_from(copy_end - copy_start).map_err(|_| Error::OffsetOverflow)?;
                let dst_start =
                    usize::try_from(copy_start - offset).map_err(|_| Error::OffsetOverflow)?;
                out[dst_start..dst_start + copy_len]
                    .copy_from_slice(&page[src_start..src_start + copy_len]);
            }
        }

        if end > tail_offset {
            let copy_start = offset.max(tail_offset);
            let src_start =
                usize::try_from(copy_start - tail_offset).map_err(|_| Error::OffsetOverflow)?;
            let dst_start =
                usize::try_from(copy_start - offset).map_err(|_| Error::OffsetOverflow)?;
            let copy_len = usize::try_from(end - copy_start).map_err(|_| Error::OffsetOverflow)?;
            out[dst_start..dst_start + copy_len]
                .copy_from_slice(&self.tail[src_start..src_start + copy_len]);
        }

        Ok(())
    }

    async fn read_many_into(
        &self,
        mut out: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<usize, Error> {
        let ranges = || offsets.iter().map(|&offset| (offset, item_size.get()));
        super::validate_read_ranges(out.len(), ranges(), self.size)?;
        let tail_offset = self.tail_offset();
        let mut tail_reads = 0;
        for &offset in offsets {
            let (slot, rest) = out.split_at_mut(item_size.get());
            out = rest;
            self.read_into(slot, offset).await?;
            if offset >= tail_offset {
                tail_reads += 1;
            }
        }
        Ok(tail_reads)
    }
}

/// Streaming reader over an [`AtomicSnapshot`].
///
/// Each loaded historical page is CRC-validated before its logical bytes become visible through
/// [`Buf`].
pub struct AtomicReplay<B: AtomicBlob> {
    snapshot: AtomicSnapshot<B>,
    buffer_size: NonZeroUsize,
    buffers: VecDeque<IoBuf>,
    next_offset: u64,
    remaining: usize,
}

impl<B: AtomicBlob> AtomicReplay<B> {
    const fn new(snapshot: AtomicSnapshot<B>, buffer_size: NonZeroUsize) -> Self {
        Self {
            snapshot,
            buffer_size,
            buffers: VecDeque::new(),
            next_offset: 0,
            remaining: 0,
        }
    }

    /// Return the total logical size of the replayed snapshot.
    pub const fn size(&self) -> u64 {
        self.snapshot.size
    }

    /// Return whether all bytes have been loaded from the snapshot.
    pub const fn is_exhausted(&self) -> bool {
        self.next_offset == self.snapshot.size
    }

    /// Ensure at least `needed` bytes are buffered, or return `false` if EOF is reached first.
    pub async fn ensure(&mut self, needed: usize) -> Result<bool, Error> {
        while self.remaining < needed && !self.is_exhausted() {
            let needed_now = needed - self.remaining;
            let request = self.buffer_size.get().max(needed_now);
            let available = self.snapshot.size - self.next_offset;
            let len = usize::try_from(available.min(request as u64))
                .map_err(|_| Error::OffsetOverflow)?;
            let bytes = self
                .snapshot
                .read_at(self.next_offset, len)
                .await?
                .coalesce();
            self.next_offset = self
                .next_offset
                .checked_add(len as u64)
                .ok_or(Error::OffsetOverflow)?;
            self.remaining = self
                .remaining
                .checked_add(len)
                .ok_or(Error::OffsetOverflow)?;
            if !bytes.is_empty() {
                self.buffers.push_back(bytes);
            }
        }
        Ok(self.remaining >= needed)
    }

    /// Seek to a logical byte offset, discarding any buffered bytes.
    pub fn seek_to(&mut self, offset: u64) -> Result<(), Error> {
        if offset > self.snapshot.size {
            return Err(Error::BlobInsufficientLength);
        }
        self.buffers.clear();
        self.next_offset = offset;
        self.remaining = 0;
        Ok(())
    }
}

impl<B: AtomicBlob> Buf for AtomicReplay<B> {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        self.buffers.front().map_or(&[], AsRef::as_ref)
    }

    fn advance(&mut self, mut count: usize) {
        assert!(count <= self.remaining, "advance exceeds buffered bytes");
        self.remaining -= count;
        while count != 0 {
            let front = self
                .buffers
                .front_mut()
                .expect("remaining bytes require a front buffer");
            let advance = count.min(front.len());
            front.advance(advance);
            count -= advance;
            if front.is_empty() {
                self.buffers.pop_front();
            }
        }
    }
}

/// Single-owner append-only checked-page writer over an [`AtomicBlob`].
///
/// Every append reaches the underlying blob before returning. Durability remains controlled by the
/// atomic blob's sync or batch-publication APIs. Mutations consume and return the writer so a
/// cancelled or failed operation cannot leave reusable cached lengths or partial-tail state.
pub struct AtomicWriter<B: AtomicBlob> {
    blob: B,
    page_size: NonZeroU16,
    size: u64,
    physical_size: u64,
    tail: IoBuf,
    marker: [u8; ATOMIC_MARKER_LEN],
}

impl<B: AtomicBlob> AtomicWriter<B> {
    /// Open an atomic checked-page blob with its exact underlying physical length.
    ///
    /// This derives the logical length in constant time. If a partial page exists, it reads and
    /// validates only that tail against the root tag. Historical full pages are validated lazily
    /// when read.
    pub async fn new(blob: B, physical_size: u64, page_size: NonZeroU16) -> Result<Self, Error> {
        let page_size_u64 = u64::from(page_size.get());
        let physical_page_size = page_size_u64
            .checked_add(CRC_LEN as u64)
            .ok_or(Error::OffsetOverflow)?;
        let full_pages = physical_size / physical_page_size;
        let partial_len = physical_size % physical_page_size;
        if partial_len >= page_size_u64 {
            return Err(Error::InvalidChecksum);
        }

        let root_tag = blob.tag().await?;
        if partial_len == 0 && tagged_crc(&root_tag) != 0 {
            return Err(Error::InvalidChecksum);
        }
        let tail = if partial_len == 0 {
            IoBuf::default()
        } else {
            let tail_offset = full_pages
                .checked_mul(physical_page_size)
                .ok_or(Error::OffsetOverflow)?;
            let tail = blob
                .read_at(
                    tail_offset,
                    usize::try_from(partial_len).map_err(|_| Error::OffsetOverflow)?,
                )
                .await?
                .coalesce()
                .freeze();
            if Crc32::checksum(tail.as_ref()) != tagged_crc(&root_tag) {
                return Err(Error::InvalidChecksum);
            }
            tail
        };
        let size = full_pages
            .checked_mul(page_size_u64)
            .and_then(|size| size.checked_add(partial_len))
            .ok_or(Error::OffsetOverflow)?;

        Ok(Self {
            blob,
            page_size,
            size,
            physical_size,
            tail,
            marker: marker(&root_tag),
        })
    }

    /// Return the logical byte length.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Return the underlying atomic blob's physical byte length.
    pub const fn physical_size(&self) -> u64 {
        self.physical_size
    }

    /// Return the application-owned marker bytes.
    pub const fn marker(&self) -> [u8; ATOMIC_MARKER_LEN] {
        self.marker
    }

    /// Return the complete root tag staged by this writer.
    pub fn tag(&self) -> [u8; ATOMIC_BLOB_TAG_LEN] {
        tag(self.marker, self.tail.as_ref())
    }

    /// Borrow the underlying atomic blob, for sync or batch publication.
    pub const fn blob(&self) -> &B {
        &self.blob
    }

    /// Consume the writer and return its underlying atomic blob.
    pub fn into_inner(self) -> B {
        self.blob
    }

    fn view(&self) -> AtomicView<'_, B> {
        AtomicView {
            blob: &self.blob,
            page_size: self.page_size,
            size: self.size,
            tail: self.tail.as_ref(),
        }
    }

    /// Stage new application marker bytes without changing the physical or logical length.
    ///
    /// The writer is returned only after its cached marker matches the underlying blob.
    pub async fn set_marker(mut self, marker: [u8; ATOMIC_MARKER_LEN]) -> Result<Self, Error> {
        if marker == self.marker {
            return Ok(self);
        }
        self.blob.set_tag(tag(marker, self.tail.as_ref())).await?;
        self.marker = marker;
        Ok(self)
    }

    /// Append borrowed bytes, copying them into owned storage for the asynchronous write.
    pub async fn append(self, bytes: &[u8]) -> Result<(Self, u64), Error> {
        self.append_owned(IoBuf::copy_from_slice(bytes)).await
    }

    /// Append owned bytes and return the updated writer and starting logical offset.
    ///
    /// Complete logical pages from `bytes` are passed to the atomic blob as zero-copy slices,
    /// interleaved with their four-byte CRC footers. At most the final partial page is copied for
    /// retention by the writer.
    pub async fn append_owned(mut self, bytes: IoBuf) -> Result<(Self, u64), Error> {
        let offset = self.size;
        if bytes.is_empty() {
            return Ok((self, offset));
        }

        let page_size = usize::from(self.page_size.get());
        let combined = self
            .tail
            .len()
            .checked_add(bytes.len())
            .ok_or(Error::OffsetOverflow)?;
        let completed_pages = combined / page_size;
        let footer_bytes = completed_pages
            .checked_mul(CRC_LEN)
            .ok_or(Error::OffsetOverflow)?;
        let physical_append_len = bytes
            .len()
            .checked_add(footer_bytes)
            .ok_or(Error::OffsetOverflow)?;
        let physical_append_len =
            u64::try_from(physical_append_len).map_err(|_| Error::OffsetOverflow)?;
        let new_physical_size = self
            .physical_size
            .checked_add(physical_append_len)
            .ok_or(Error::OffsetOverflow)?;
        let bytes_len = u64::try_from(bytes.len()).map_err(|_| Error::OffsetOverflow)?;
        let new_size = self
            .size
            .checked_add(bytes_len)
            .ok_or(Error::OffsetOverflow)?;

        let new_tail_len = combined % page_size;
        let new_tail = if new_tail_len == 0 {
            IoBuf::default()
        } else if completed_pages == 0 {
            let mut tail = Vec::with_capacity(new_tail_len);
            tail.extend_from_slice(self.tail.as_ref());
            tail.extend_from_slice(bytes.as_ref());
            IoBuf::from(tail)
        } else {
            IoBuf::copy_from_slice(&bytes.as_ref()[bytes.len() - new_tail_len..])
        };

        // Keep all footer bytes in one allocation. Each footer is then exposed as a cheap IoBuf
        // slice, preserving vectored zero-copy payload writes without allocating once per page.
        let mut footer_bytes_buf = Vec::with_capacity(footer_bytes);
        let mut cursor = 0;
        if !self.tail.is_empty() {
            let fill = page_size - self.tail.len();
            let take = fill.min(bytes.len());
            if take == fill {
                let page_crc = checksum(&[self.tail.as_ref(), &bytes.as_ref()[..take]]);
                footer_bytes_buf.extend_from_slice(&page_crc.to_be_bytes());
            }
            cursor = take;
        }

        while bytes.len() - cursor >= page_size {
            let page_crc = Crc32::checksum(&bytes.as_ref()[cursor..cursor + page_size]);
            footer_bytes_buf.extend_from_slice(&page_crc.to_be_bytes());
            cursor += page_size;
        }
        debug_assert_eq!(footer_bytes_buf.len(), footer_bytes);

        let footers = IoBuf::from(footer_bytes_buf);
        let mut footer_cursor = 0;
        let mut physical = Vec::with_capacity(completed_pages.saturating_mul(2) + 1);
        let mut cursor = 0;
        if !self.tail.is_empty() {
            let fill = page_size - self.tail.len();
            let take = fill.min(bytes.len());
            if take != 0 {
                physical.push(bytes.slice(..take));
            }
            if take == fill {
                physical.push(footers.slice(footer_cursor..footer_cursor + CRC_LEN));
                footer_cursor += CRC_LEN;
            }
            cursor = take;
        }
        while bytes.len() - cursor >= page_size {
            physical.push(bytes.slice(cursor..cursor + page_size));
            physical.push(footers.slice(footer_cursor..footer_cursor + CRC_LEN));
            footer_cursor += CRC_LEN;
            cursor += page_size;
        }
        if cursor != bytes.len() {
            physical.push(bytes.slice(cursor..));
        }
        debug_assert_eq!(footer_cursor, footer_bytes);

        let physical_offset = self
            .blob
            .append_tagged(IoBufs::from(physical), tag(self.marker, new_tail.as_ref()))
            .await?;
        if physical_offset != self.physical_size {
            return Err(Error::InvalidChecksum);
        }

        self.size = new_size;
        self.physical_size = new_physical_size;
        self.tail = new_tail;
        Ok((self, offset))
    }

    /// Rewind to `size` logical bytes and return the updated writer.
    ///
    /// Rewinding into a historical full page reads and validates that one page before retaining its
    /// prefix as the new partial tail. No other page is read.
    pub async fn rewind(mut self, size: u64) -> Result<Self, Error> {
        if size > self.size {
            return Err(Error::BlobInsufficientLength);
        }
        if size == self.size {
            return Ok(self);
        }

        let page_size = u64::from(self.page_size.get());
        let physical_page_size = page_size
            .checked_add(CRC_LEN as u64)
            .ok_or(Error::OffsetOverflow)?;
        let full_pages = size / page_size;
        let partial_len = size % page_size;
        let current_full_pages = (self.size - self.tail.len() as u64) / page_size;

        let new_tail = if partial_len == 0 {
            IoBuf::default()
        } else if full_pages == current_full_pages {
            self.tail
                .slice(..usize::try_from(partial_len).map_err(|_| Error::OffsetOverflow)?)
        } else {
            let physical_offset = full_pages
                .checked_mul(physical_page_size)
                .ok_or(Error::OffsetOverflow)?;
            let page = self
                .blob
                .read_at(
                    physical_offset,
                    usize::try_from(physical_page_size).map_err(|_| Error::OffsetOverflow)?,
                )
                .await?
                .coalesce()
                .freeze();
            validate_full_page(page.as_ref(), self.page_size.get() as usize)?;
            page.slice(..usize::try_from(partial_len).map_err(|_| Error::OffsetOverflow)?)
        };
        let physical_size = full_pages
            .checked_mul(physical_page_size)
            .and_then(|size| size.checked_add(partial_len))
            .ok_or(Error::OffsetOverflow)?;
        let new_tag = tag(self.marker, new_tail.as_ref());

        self.blob.rewind_tagged(physical_size, new_tag).await?;
        self.size = size;
        self.physical_size = physical_size;
        self.tail = new_tail;
        Ok(self)
    }

    /// Read exactly `len` logical bytes beginning at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        self.view().read_at(offset, len).await
    }

    /// Read logical bytes into `buf` beginning at `offset`.
    pub async fn read_into(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        self.view().read_into(buf, offset).await
    }

    /// Read fixed-size items at sorted, non-overlapping logical offsets.
    ///
    /// The return value is the number of items served entirely from the retained partial tail.
    pub async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<usize, Error> {
        self.view().read_many_into(buf, offsets, item_size).await
    }

    /// Capture an immutable read view without flushing or copying full pages.
    pub fn snapshot(&self) -> AtomicSnapshot<B> {
        AtomicSnapshot {
            blob: self.blob.clone(),
            page_size: self.page_size,
            size: self.size,
            physical_size: self.physical_size,
            tail: self.tail.clone(),
            marker: self.marker,
        }
    }

    /// Create a streaming replay of the current logical contents.
    pub fn replay(&self, buffer_size: NonZeroUsize) -> AtomicReplay<B> {
        self.snapshot().replay(buffer_size)
    }

    /// Make all pending physical bytes, length, and tag durable.
    pub async fn sync(&self) -> Result<(), Error> {
        self.blob.sync().await
    }

    /// Begin making all pending physical bytes, length, and tag durable.
    pub async fn start_sync(&self) -> Handle<()> {
        self.blob.start_sync().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AtomicStorage as _, Blob as _, IoBufsMut, Runner as _, Storage as _, WriteOptions,
        deterministic,
    };
    use commonware_macros::test_traced;
    use commonware_utils::{NZU16, NZUsize, channel::oneshot, sync::Mutex};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    const PAGE_SIZE: NonZeroU16 = NZU16!(16);

    #[derive(Clone, Default)]
    struct MutationGate {
        entered: Arc<AtomicBool>,
        receiver: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    }

    impl MutationGate {
        fn arm(&self) -> oneshot::Sender<()> {
            self.entered.store(false, Ordering::SeqCst);
            let (sender, receiver) = oneshot::channel();
            assert!(
                self.receiver.lock().replace(receiver).is_none(),
                "mutation gate already armed"
            );
            sender
        }

        async fn wait(&self) {
            let receiver = self.receiver.lock().take();
            if let Some(receiver) = receiver {
                self.entered.store(true, Ordering::SeqCst);
                receiver.await.unwrap();
            }
        }
    }

    #[derive(Clone)]
    struct GatedMutationBlob<B> {
        inner: B,
        gate: MutationGate,
    }

    impl<B: AtomicBlob> crate::Blob for GatedMutationBlob<B> {
        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at_buf(offset, len, bufs).await
        }

        async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
            self.inner.read_at(offset, len).await
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

    impl<B: AtomicBlob> AtomicBlob for GatedMutationBlob<B> {
        async fn tag(&self) -> Result<[u8; ATOMIC_BLOB_TAG_LEN], Error> {
            self.inner.tag().await
        }

        async fn set_tag(&self, tag: [u8; ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
            self.inner.set_tag(tag).await
        }

        async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, Error> {
            let offset = self.inner.append(data).await?;
            self.gate.wait().await;
            Ok(offset)
        }

        async fn append_tagged(
            &self,
            data: impl Into<IoBufs> + Send,
            tag: [u8; ATOMIC_BLOB_TAG_LEN],
        ) -> Result<u64, Error> {
            let offset = self.inner.append_tagged(data, tag).await?;
            self.gate.wait().await;
            Ok(offset)
        }

        async fn rewind(&self, len: u64) -> Result<(), Error> {
            self.inner.rewind(len).await?;
            self.gate.wait().await;
            Ok(())
        }

        async fn rewind_tagged(
            &self,
            len: u64,
            tag: [u8; ATOMIC_BLOB_TAG_LEN],
        ) -> Result<(), Error> {
            self.inner.rewind_tagged(len, tag).await?;
            self.gate.wait().await;
            Ok(())
        }
    }

    async fn reopen_gated(
        context: &deterministic::Context,
        partition: &str,
        gate: MutationGate,
    ) -> Result<
        AtomicWriter<
            GatedMutationBlob<<deterministic::Context as crate::AtomicStorage>::AtomicBlob>,
        >,
        Error,
    > {
        let (blob, physical_size) = context.open_atomic(partition, b"blob").await?;
        AtomicWriter::new(
            GatedMutationBlob { inner: blob, gate },
            physical_size,
            PAGE_SIZE,
        )
        .await
    }

    #[test_traced("DEBUG")]
    fn append_reopen_snapshot_and_replay() {
        deterministic::Runner::default().start(|context| async move {
            let (blob, physical_size) = context
                .open_atomic("atomic_paged_append", b"blob")
                .await
                .unwrap();
            let mut writer = AtomicWriter::new(blob, physical_size, PAGE_SIZE)
                .await
                .unwrap();
            let data: Vec<u8> = (0..37).collect();

            let (next, offset) = writer.append(&data[..7]).await.unwrap();
            writer = next;
            assert_eq!(offset, 0);
            let (next, offset) = writer
                .append_owned(IoBuf::from(data[7..].to_vec()))
                .await
                .unwrap();
            writer = next;
            assert_eq!(offset, 7);
            assert_eq!(writer.size(), 37);
            assert_eq!(writer.physical_size(), 2 * (16 + 4) + 5);
            assert_eq!(
                writer.read_at(0, data.len()).await.unwrap().coalesce(),
                data.as_slice()
            );

            let mut many = [0; 6];
            assert_eq!(
                writer
                    .read_many_into(&mut many, &[2, 18, 34], NZUsize!(2))
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(many, [2, 3, 18, 19, 34, 35]);

            let snapshot = writer.snapshot();
            (writer, _) = writer.append(b"later").await.unwrap();
            assert_eq!(snapshot.size(), 37);
            assert_eq!(
                snapshot.read_at(32, 5).await.unwrap().coalesce(),
                &data[32..]
            );

            let mut replay = snapshot.replay(NZUsize!(7));
            assert!(replay.ensure(data.len()).await.unwrap());
            let mut replayed = Vec::new();
            while replay.remaining() != 0 {
                let chunk = replay.chunk();
                replayed.extend_from_slice(chunk);
                let len = chunk.len();
                replay.advance(len);
            }
            assert_eq!(replayed, data);

            writer.sync().await.unwrap();
            let expected = [data, b"later".to_vec()].concat();
            drop(writer);
            let (blob, physical_size) = context
                .open_atomic("atomic_paged_append", b"blob")
                .await
                .unwrap();
            let reopened = AtomicWriter::new(blob, physical_size, PAGE_SIZE)
                .await
                .unwrap();
            assert_eq!(reopened.size(), expected.len() as u64);
            assert_eq!(
                reopened
                    .read_at(0, expected.len())
                    .await
                    .unwrap()
                    .coalesce(),
                expected.as_slice()
            );
        });
    }

    #[test_traced("DEBUG")]
    fn marker_change_preserves_partial_checksum() {
        deterministic::Runner::default().start(|context| async move {
            let (blob, physical_size) = context
                .open_atomic("atomic_paged_marker", b"blob")
                .await
                .unwrap();
            let mut writer = AtomicWriter::new(blob, physical_size, PAGE_SIZE)
                .await
                .unwrap();
            (writer, _) = writer.append(b"partial").await.unwrap();
            let before_size = writer.physical_size();
            let before_crc = writer.tag()[CRC_OFFSET..].to_vec();

            let marker =
                std::array::from_fn(|index| (index as u8).wrapping_mul(13).wrapping_add(7));
            writer = writer.set_marker(marker).await.unwrap();
            assert_eq!(writer.physical_size(), before_size);
            assert_eq!(&writer.tag()[CRC_OFFSET..], before_crc);
            assert_eq!(writer.marker(), marker);
            writer.sync().await.unwrap();
            drop(writer);

            let (blob, physical_size) = context
                .open_atomic("atomic_paged_marker", b"blob")
                .await
                .unwrap();
            let reopened = AtomicWriter::new(blob, physical_size, PAGE_SIZE)
                .await
                .unwrap();
            assert_eq!(reopened.marker(), marker);
            assert_eq!(reopened.read_at(0, 7).await.unwrap().coalesce(), b"partial");
        });
    }

    #[test_traced("DEBUG")]
    fn rewind_maps_logical_tail_and_recomputes_crc() {
        deterministic::Runner::default().start(|context| async move {
            let (blob, physical_size) = context
                .open_atomic("atomic_paged_rewind", b"blob")
                .await
                .unwrap();
            let mut writer = AtomicWriter::new(blob, physical_size, PAGE_SIZE)
                .await
                .unwrap();
            let data: Vec<u8> = (0..39).collect();
            (writer, _) = writer.append_owned(data.clone().into()).await.unwrap();
            writer.sync().await.unwrap();

            let marker =
                std::array::from_fn(|index| (index as u8).wrapping_mul(29).wrapping_add(5));
            writer = writer.set_marker(marker).await.unwrap();

            writer = writer.rewind(19).await.unwrap();
            assert_eq!(writer.size(), 19);
            assert_eq!(writer.physical_size(), 16 + 4 + 3);
            assert_eq!(tagged_crc(&writer.tag()), Crc32::checksum(&data[16..19]));
            writer.sync().await.unwrap();
            (writer, _) = writer.append(b"xyz").await.unwrap();
            let expected = [&data[..19], b"xyz"].concat();
            assert_eq!(
                writer.read_at(0, 22).await.unwrap().coalesce(),
                expected.as_slice()
            );
            writer.sync().await.unwrap();
            drop(writer);

            let (blob, physical_size) = context
                .open_atomic("atomic_paged_rewind", b"blob")
                .await
                .unwrap();
            let reopened = AtomicWriter::new(blob, physical_size, PAGE_SIZE)
                .await
                .unwrap();
            assert_eq!(reopened.size(), 22);
            assert_eq!(reopened.marker(), marker);
            assert_eq!(
                reopened.read_at(16, 6).await.unwrap().coalesce(),
                [16, 17, 18, b'x', b'y', b'z']
            );
        });
    }

    #[test_traced("DEBUG")]
    fn open_defers_historical_crc_validation_until_read() {
        deterministic::Runner::default().start(|context| async move {
            let (plain, _) = context.open("atomic_paged_corrupt", b"blob").await.unwrap();
            let mut physical = vec![1; PAGE_SIZE.get() as usize];
            physical.extend_from_slice(&0u32.to_be_bytes());
            physical.extend_from_slice(b"tail");
            plain
                .write_at(0, physical, WriteOptions::default())
                .await
                .unwrap();
            plain.sync().await.unwrap();
            context.migrate_atomic(plain).await.unwrap();

            let (blob, _physical_size) = context
                .open_atomic("atomic_paged_corrupt", b"blob")
                .await
                .unwrap();
            blob.set_tag(tag([0; ATOMIC_MARKER_LEN], b"tail"))
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);

            let (blob, physical_size) = context
                .open_atomic("atomic_paged_corrupt", b"blob")
                .await
                .unwrap();
            let writer = AtomicWriter::new(blob, physical_size, PAGE_SIZE)
                .await
                .unwrap();
            assert_eq!(writer.read_at(16, 4).await.unwrap().coalesce(), b"tail");
            assert!(matches!(
                writer.read_at(0, 1).await,
                Err(Error::InvalidChecksum)
            ));
        });
    }

    #[test_traced("DEBUG")]
    fn open_rejects_invalid_remainder_and_partial_crc() {
        deterministic::Runner::default().start(|context| async move {
            let (plain, _) = context
                .open("atomic_paged_bad_remainder", b"blob")
                .await
                .unwrap();
            plain
                .write_at(
                    0,
                    vec![0; PAGE_SIZE.get() as usize],
                    WriteOptions::default(),
                )
                .await
                .unwrap();
            plain.sync().await.unwrap();
            context.migrate_atomic(plain).await.unwrap();
            let (blob, physical_size) = context
                .open_atomic("atomic_paged_bad_remainder", b"blob")
                .await
                .unwrap();
            assert!(matches!(
                AtomicWriter::new(blob, physical_size, PAGE_SIZE).await,
                Err(Error::InvalidChecksum)
            ));

            let (plain, _) = context
                .open("atomic_paged_bad_tail", b"blob")
                .await
                .unwrap();
            plain
                .write_at(0, b"partial", WriteOptions::default())
                .await
                .unwrap();
            plain.sync().await.unwrap();
            context.migrate_atomic(plain).await.unwrap();
            let (blob, physical_size) = context
                .open_atomic("atomic_paged_bad_tail", b"blob")
                .await
                .unwrap();
            assert!(matches!(
                AtomicWriter::new(blob, physical_size, PAGE_SIZE).await,
                Err(Error::InvalidChecksum)
            ));

            let (blob, physical_size) = context
                .open_atomic("atomic_paged_bad_empty_crc", b"blob")
                .await
                .unwrap();
            let mut invalid_tag = [0; ATOMIC_BLOB_TAG_LEN];
            invalid_tag[CRC_OFFSET..].copy_from_slice(&1u32.to_be_bytes());
            blob.set_tag(invalid_tag).await.unwrap();
            assert!(matches!(
                AtomicWriter::new(blob, physical_size, PAGE_SIZE).await,
                Err(Error::InvalidChecksum)
            ));
        });
    }

    #[test_traced("DEBUG")]
    fn concurrent_publication_cannot_split_append_from_tail_tag() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "atomic_paged_append_publication";
            let gate = MutationGate::default();
            let (blob, physical_size) = context.open_atomic(partition, b"blob").await.unwrap();
            let mut writer = AtomicWriter::new(
                GatedMutationBlob {
                    inner: blob,
                    gate: gate.clone(),
                },
                physical_size,
                PAGE_SIZE,
            )
            .await
            .unwrap();
            let publisher = writer.blob().clone();

            let release = gate.arm();
            {
                let append = writer.append(b"partial");
                let mut append = std::pin::pin!(append);
                assert!(futures::poll!(append.as_mut()).is_pending());
                assert!(gate.entered.load(Ordering::SeqCst));
                publisher.sync().await.unwrap();
                release.send(()).unwrap();
                (writer, _) = append.as_mut().await.unwrap();
            }
            drop(publisher);
            drop(writer);

            let reopened = reopen_gated(&context, partition, gate).await.unwrap();
            assert_eq!(reopened.size(), 7);
            assert_eq!(reopened.read_at(0, 7).await.unwrap().coalesce(), b"partial");
        });
    }

    #[test_traced("DEBUG")]
    fn concurrent_publication_cannot_split_rewind_from_tail_tag() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "atomic_paged_rewind_publication";
            let gate = MutationGate::default();
            let (blob, physical_size) = context.open_atomic(partition, b"blob").await.unwrap();
            let mut writer = AtomicWriter::new(
                GatedMutationBlob {
                    inner: blob,
                    gate: gate.clone(),
                },
                physical_size,
                PAGE_SIZE,
            )
            .await
            .unwrap();
            (writer, _) = writer.append(b"abcdefghij").await.unwrap();
            writer.sync().await.unwrap();
            let publisher = writer.blob().clone();

            let release = gate.arm();
            {
                let rewind = writer.rewind(5);
                let mut rewind = std::pin::pin!(rewind);
                assert!(futures::poll!(rewind.as_mut()).is_pending());
                assert!(gate.entered.load(Ordering::SeqCst));
                publisher.sync().await.unwrap();
                release.send(()).unwrap();
                writer = rewind.as_mut().await.unwrap();
            }
            drop(publisher);
            drop(writer);

            let reopened = reopen_gated(&context, partition, gate).await.unwrap();
            assert_eq!(reopened.size(), 5);
            assert_eq!(reopened.read_at(0, 5).await.unwrap().coalesce(), b"abcde");
        });
    }

    #[test_traced("DEBUG")]
    fn cancelled_mutations_require_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let append_partition = "atomic_paged_cancelled_append";
            let append_gate = MutationGate::default();
            let (blob, physical_size) = context
                .open_atomic(append_partition, b"blob")
                .await
                .unwrap();
            let writer = AtomicWriter::new(
                GatedMutationBlob {
                    inner: blob,
                    gate: append_gate.clone(),
                },
                physical_size,
                PAGE_SIZE,
            )
            .await
            .unwrap();
            let publisher = writer.blob().clone();

            let release = append_gate.arm();
            {
                let append = writer.append(b"partial");
                let mut append = std::pin::pin!(append);
                assert!(futures::poll!(append.as_mut()).is_pending());
                assert!(append_gate.entered.load(Ordering::SeqCst));
            }
            assert!(release.send(()).is_err());
            assert_eq!(
                publisher.read_at(0, 7).await.unwrap().coalesce(),
                b"partial"
            );
            assert!(publisher.read_at(7, 1).await.is_err());
            publisher.sync().await.unwrap();
            drop(publisher);

            let reopened = reopen_gated(&context, append_partition, append_gate)
                .await
                .unwrap();
            assert_eq!(reopened.size(), 7);
            assert_eq!(reopened.read_at(0, 7).await.unwrap().coalesce(), b"partial");

            let rewind_partition = "atomic_paged_cancelled_rewind";
            let rewind_gate = MutationGate::default();
            let (blob, physical_size) = context
                .open_atomic(rewind_partition, b"blob")
                .await
                .unwrap();
            let mut writer = AtomicWriter::new(
                GatedMutationBlob {
                    inner: blob,
                    gate: rewind_gate.clone(),
                },
                physical_size,
                PAGE_SIZE,
            )
            .await
            .unwrap();
            (writer, _) = writer.append(b"0123456789abcdefghij").await.unwrap();
            writer.sync().await.unwrap();
            let publisher = writer.blob().clone();

            let release = rewind_gate.arm();
            {
                let rewind = writer.rewind(3);
                let mut rewind = std::pin::pin!(rewind);
                assert!(futures::poll!(rewind.as_mut()).is_pending());
                assert!(rewind_gate.entered.load(Ordering::SeqCst));
            }
            assert!(release.send(()).is_err());
            assert_eq!(publisher.read_at(0, 3).await.unwrap().coalesce(), b"012");
            assert!(publisher.read_at(3, 1).await.is_err());
            publisher.sync().await.unwrap();
            drop(publisher);

            let reopened = reopen_gated(&context, rewind_partition, rewind_gate)
                .await
                .unwrap();
            assert_eq!(reopened.size(), 3);
            assert_eq!(reopened.read_at(0, 3).await.unwrap().coalesce(), b"012");
        });
    }
}
