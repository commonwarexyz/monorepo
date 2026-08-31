//! Blob wrappers for reading and writing data with integrity guarantees, plus a page cache that
//! manages read caching over the data.
//!
//! # Page-oriented structure
//!
//! Blob data is stored in _pages_ having a _logical page size_ dictated by the managing page
//! cache: the payload bytes stored per page. A _physical page_ is what a page occupies on disk:
//! the logical page followed by a 12-byte _CRC record_ containing:
//!
//! ```text
//! | len1 (2 bytes) |  crc1 (4 bytes) | len2 (2 bytes) | crc2 (4 bytes) |
//! ```
//!
//! Throughout this module, an unqualified page size always denotes the logical size (matching
//! the configured value); only physical sizes carry a qualified `physical_page_size` name.
//!
//! # Storage-page alignment
//!
//! Physical page `p` begins at blob offset `p * physical_page_size`, and a newly created blob
//! begins its data on a 4096-byte boundary. Choosing a logical page size such that the physical
//! page size is a power of two (see [page_size]) therefore makes every physical page either fit
//! within a single 4096-byte storage page or start on a 4096-byte boundary and span whole
//! storage pages. Blobs created before the aligned layout begin their data at offset 8 and never
//! align, regardless of the page size chosen.
//!
//! Alignment is a performance property, not a correctness requirement: any page size works, but
//! physical pages that straddle storage-page boundaries amplify cold random reads.
//!
//! Two checksums are stored so that re-writing a partial page cannot destroy the valid checksum
//! for its last durable contents. Each rewrite covers the whole physical page: the new checksum
//! lands in the slot not protecting the durable contents, while the durable prefix and its
//! protected checksum are resubmitted byte-identically, leaving their durable bytes unchanged
//! even if the write tears. A checksum over a page is computed over the first [0,len) bytes in
//! the page, with all other bytes in the page ignored. Ordinary partial-page payload writes
//! 0-pad the range [len, page_size), but recovery does not depend on bytes outside [0,len). A
//! checksum with length 0 is never considered valid. If both checksums are valid for the page,
//! the one with the larger `len` is considered authoritative. Partial-page shrink first makes
//! the shorter checksum durable in the alternate slot, then invalidates the old longer checksum.
//!
//! A _full_ page is one whose crc stores a len equal to the logical page size. Otherwise the page
//! is called _partial_. All pages in a blob are full except for the very last page, which can be
//! full or partial. A partial page's durable prefix remains recoverable while it is rewritten.

use crate::{Blob, Buf, BufMut, Error, IoBuf, ReadOptions};
#[cfg(any(test, feature = "test-utils"))]
use crate::{Storage, WriteOptions};
use commonware_codec::{EncodeFixed, FixedSize, Read as CodecRead, ReadExt, Write};
use commonware_cryptography::{Crc32, crc32};
use std::num::NonZeroU16;

mod cache;
mod read;
mod sealed;
mod view;
mod writer;

pub use cache::CacheRef;
pub use read::Replay;
pub use sealed::Sealed;
use tracing::{debug, error};
pub use writer::Writer;

/// Size in bytes of the checksum record appended to each logical page.
pub const CHECKSUM_SIZE: u64 = Checksum::SIZE as u64;

/// The storage-page granularity physical pages should align to (see the module docs).
pub(crate) const STORAGE_PAGE_SIZE: u64 = 4096;
// The alignment reasoning above assumes newly created blobs place their data on a
// storage-page boundary.
const _: () = assert!(
    crate::storage::Layout::V1
        .data_offset()
        .is_multiple_of(STORAGE_PAGE_SIZE)
);

const CHECKSUM_SLOT_LEN_SIZE: usize = u16::SIZE;
const CHECKSUM_SLOT_SIZE: usize = CHECKSUM_SLOT_LEN_SIZE + crc32::Digest::SIZE;

/// The logical page size whose physical page occupies exactly `physical_page_size` bytes on disk
/// (see the module docs on storage-page alignment).
///
/// This selects a page size for a store. It is not a migration path: a store that already holds
/// data cannot be reopened under a different page size, as the mismatched pages fail their
/// integrity check and reopening for writing silently truncates them. Changing page size is a
/// destructive format migration.
///
/// # Panics
///
/// Panics if `physical_page_size` is not a power of two, does not exceed the CRC record size,
/// or yields a logical size that does not fit a `u16`, so misconfiguration is caught at
/// construction (or compile time, in const contexts).
pub const fn page_size(physical_page_size: u32) -> NonZeroU16 {
    assert!(
        physical_page_size.is_power_of_two(),
        "physical page size must be a power of two"
    );
    assert!(
        physical_page_size as u64 > CHECKSUM_SIZE,
        "physical page size must exceed the CRC record size"
    );
    let logical = physical_page_size as u64 - CHECKSUM_SIZE;
    assert!(
        logical <= u16::MAX as u64,
        "logical page size must fit in a u16"
    );
    match NonZeroU16::new(logical as u16) {
        Some(size) => size,
        None => unreachable!(),
    }
}

/// Validate a physical page's CRC record, exposing [Checksum::validate_page] to tests elsewhere
/// in the crate.
#[cfg(test)]
pub(crate) fn validate_page_for_tests(page: &[u8]) -> bool {
    Checksum::validate_page(page).is_some()
}

/// Flip one byte inside physical page `page` of the blob at `name`, leaving every other page
/// valid. Models a torn interior page: a crash during an in-flight fsync can lose an interior
/// page while later pages persist. Physical pages are the logical page plus the checksum record.
#[cfg(any(test, feature = "test-utils"))]
pub async fn corrupt_page(
    storage: &impl Storage,
    partition: &str,
    name: &[u8],
    page: u64,
    logical_page_size: u64,
) {
    // Every valid checksum slot covers byte zero, including a shorter fallback slot.
    let physical_page_size = logical_page_size + CHECKSUM_SIZE;
    let offset = page * physical_page_size;
    let (blob, size) = storage.open(partition, name).await.unwrap();
    assert!(
        size.checked_sub(physical_page_size)
            .is_some_and(|remaining| offset < remaining),
        "corruption target must be an interior page"
    );
    let byte = blob
        .read_at(offset, 1, ReadOptions::default())
        .await
        .unwrap()
        .coalesce();
    blob.write_at(
        offset,
        vec![byte.as_ref()[0] ^ 0xFF],
        WriteOptions::default(),
    )
    .await
    .unwrap();
    blob.sync().await.unwrap();
}

/// Ensure every requested range lies within the blob's size.
///
/// # Panics
///
/// Panics if `buf` does not hold one slot per range totaling its length, or if ranges are not
/// sorted and non-overlapping.
fn validate_read_ranges(
    buf_len: usize,
    ranges: impl Iterator<Item = (u64, usize)>,
    size: u64,
) -> Result<(), Error> {
    let mut expected_len = 0usize;
    let mut previous_end = None;
    for (offset, len) in ranges {
        expected_len = expected_len
            .checked_add(len)
            .expect("buf must hold one slot per range totaling its length");
        let end = offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;
        if let Some(previous_end) = previous_end {
            assert!(
                offset >= previous_end,
                "ranges must be sorted and non-overlapping"
            );
        }
        if end > size {
            return Err(Error::BlobInsufficientLength);
        }
        previous_end = Some(end);
    }
    assert_eq!(
        buf_len, expected_len,
        "buf must hold one slot per range totaling its length"
    );
    Ok(())
}

/// Partition a batch of variable-length range reads into bytes copied from the in-memory tail
/// and ranges that need cache/blob reads.
///
/// `buf` holds one slot per range, back to back (validated by [validate_read_ranges]). `tail`
/// holds the logical bytes at `[tail_offset, tail_offset + tail.len())`; for [Writer] this is the
/// tip buffer, for [Sealed] the partial last page. Ranges entirely within `tail` are copied into
/// place. Ranges fully or partially below `tail_offset` are returned as `(dest_slice, offset)`
/// pairs for the caller to read from the page cache or blob. `split_at_mut` yields disjoint
/// per-range slots, so returned slices never alias.
fn split_read_ranges<'a>(
    mut buf: &'a mut [u8],
    ranges: impl ExactSizeIterator<Item = (u64, usize)>,
    tail_offset: u64,
    tail: &[u8],
) -> Vec<(&'a mut [u8], u64)> {
    let mut cache_ranges = Vec::with_capacity(ranges.len());
    for (offset, len) in ranges {
        let (slot, rest) = buf.split_at_mut(len);
        buf = rest;
        if len == 0 {
            continue;
        }
        let end = offset + len as u64;
        if end <= tail_offset {
            // Entirely below the tail bytes, so this needs a cache/blob read.
            cache_ranges.push((slot, offset));
        } else if offset >= tail_offset {
            // Entirely within the tail bytes.
            let src = (offset - tail_offset) as usize;
            slot.copy_from_slice(&tail[src..src + len]);
        } else {
            // Straddles the boundary: copy the suffix from the tail bytes, record the prefix
            // for a cache/blob read.
            let prefix_len = (tail_offset - offset) as usize;
            let (prefix, suffix) = slot.split_at_mut(prefix_len);
            suffix.copy_from_slice(&tail[..len - prefix_len]);
            cache_ranges.push((prefix, offset));
        }
    }
    cache_ranges
}

/// Read the designated page from the underlying blob and return its logical bytes as a vector if it
/// passes the integrity check, returning error otherwise. Safely handles partial pages. Caller can
/// check the length of the returned vector to determine if the page was partial vs full.
async fn get_page_from_blob(
    blob: &impl Blob,
    page_num: u64,
    page_size: u64,
    read_options: ReadOptions,
) -> Result<IoBuf, Error> {
    let (page, _) =
        get_page_with_checksum_from_blob(blob, page_num, page_size, read_options).await?;
    Ok(page)
}

/// Read the designated page and return both its logical bytes and validated checksum.
async fn get_page_with_checksum_from_blob(
    blob: &impl Blob,
    page_num: u64,
    page_size: u64,
    read_options: ReadOptions,
) -> Result<(IoBuf, ActiveChecksum), Error> {
    let physical_page_size = page_size
        .checked_add(CHECKSUM_SIZE)
        .ok_or(Error::OffsetOverflow)?;
    let physical_page_start = page_num
        .checked_mul(physical_page_size)
        .ok_or(Error::OffsetOverflow)?;

    let page = blob
        .read_at(
            physical_page_start,
            physical_page_size as usize,
            read_options,
        )
        .await?
        .coalesce();

    let Some(checksum) = Checksum::validate_page(page.as_ref()) else {
        return Err(Error::InvalidChecksum);
    };

    Ok((page.freeze().slice(..checksum.len as usize), checksum))
}

/// One of a page footer's two CRC slots, laid out back to back after the page data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slot {
    First,
    Second,
}

impl Slot {
    /// Byte offset of this slot within the page's CRC footer.
    const fn offset(self) -> usize {
        match self {
            Self::First => 0,
            Self::Second => CHECKSUM_SLOT_SIZE,
        }
    }

    /// The other slot.
    const fn other(self) -> Self {
        match self {
            Self::First => Self::Second,
            Self::Second => Self::First,
        }
    }
}

/// The checksum covering a page's logical bytes and the footer slot that holds it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveChecksum {
    slot: Slot,
    len: u16,
    crc: u32,
}

impl ActiveChecksum {
    const fn new(slot: Slot, len: u16, crc: u32) -> Self {
        Self { slot, len, crc }
    }
}

/// Describes a CRC record stored at the end of a page.
///
/// The CRC with the larger length is authoritative. Two slots let a partial-page rewrite preserve
/// the checksum covering the previously committed bytes while writing the new checksum elsewhere.
struct Checksum {
    len1: u16,
    crc1: u32,
    len2: u16,
    crc2: u32,
}

impl Checksum {
    /// Create a new CRC record with the given length and CRC.
    /// The new CRC is stored in the first slot (len1/crc1), with the second slot zeroed.
    const fn new(len: u16, crc: u32) -> Self {
        Self {
            len1: len,
            crc1: crc,
            len2: 0,
            crc2: 0,
        }
    }

    /// The slot holding the authoritative (longer) CRC; the first slot wins ties.
    const fn authoritative(&self) -> Slot {
        if self.len1 >= self.len2 {
            Slot::First
        } else {
            Slot::Second
        }
    }

    /// Return the active checksum if the page is valid. The provided slice is assumed to be exactly
    /// the size of a physical page.
    fn validate_page(buf: &[u8]) -> Option<ActiveChecksum> {
        let physical_page_size = buf.len() as u64;
        if physical_page_size < CHECKSUM_SIZE {
            error!(
                physical_page_size,
                required = CHECKSUM_SIZE,
                "read page smaller than CRC record"
            );
            return None;
        }

        // Decode the CRC record from the page footer. The size guard above guarantees all of its
        // bytes are present, and every bit pattern decodes, so the read cannot fail.
        let crc_start_idx = (physical_page_size - CHECKSUM_SIZE) as usize;
        let mut crc_bytes = &buf[crc_start_idx..];
        let crc_record = Self::read(&mut crc_bytes).expect("CRC record read should not fail");

        // Prefer the authoritative slot: when both slots are valid, it covers the most recently
        // committed contents of the page.
        let authoritative = crc_record.authoritative();
        if let Some(checksum) = crc_record.validate_slot(authoritative, buf, crc_start_idx) {
            return Some(checksum);
        }

        // An interrupted write can corrupt only the slot it was rewriting. The other slot still
        // covers the page's previously committed contents.
        debug!("Invalid authoritative CRC, using fallback CRC");
        let checksum = crc_record.validate_slot(authoritative.other(), buf, crc_start_idx);
        if checksum.is_none() {
            debug!("Invalid fallback CRC");
        }
        checksum
    }

    /// Validate one slot independently of the footer's authority ordering.
    fn validate_slot(
        &self,
        slot: Slot,
        buf: &[u8],
        crc_start_idx: usize,
    ) -> Option<ActiveChecksum> {
        let (len, crc) = self.get_slot(slot);
        let len_usize = len as usize;

        // A zero length marks an inactive checksum slot (committed pages are never empty).
        // This also rejects zero-filled physical pages from unwritten storage.
        if len_usize == 0 {
            return None;
        }

        // The checksum must cover only logical page bytes, not the checksum footer itself.
        if len_usize > crc_start_idx {
            return None;
        }

        // The recorded checksum must match the claimed logical prefix.
        if Crc32::checksum(&buf[..len_usize]) != crc {
            return None;
        }
        Some(ActiveChecksum::new(slot, len, crc))
    }

    /// Return one checksum slot without considering authority.
    const fn get_slot(&self, slot: Slot) -> (u16, u32) {
        match slot {
            Slot::First => (self.len1, self.crc1),
            Slot::Second => (self.len2, self.crc2),
        }
    }

    /// Returns the CRC record in its storage representation.
    fn to_bytes(&self) -> [u8; CHECKSUM_SIZE as usize] {
        self.encode_fixed()
    }

    /// Encode a whole checksum slot (`[len: u16][crc: u32]`) in its storage representation.
    ///
    /// A page footer holds two slots; recovery treats the one with the larger `len` as
    /// authoritative. A `len` of 0 is never authoritative.
    fn slot_bytes(len: u16, crc: u32) -> [u8; CHECKSUM_SLOT_SIZE] {
        let mut bytes = [0; CHECKSUM_SLOT_SIZE];
        let mut buf = bytes.as_mut_slice();
        len.write(&mut buf);
        crc.write(&mut buf);
        bytes
    }

    /// Encode just a slot's leading `len` field (the first [`CHECKSUM_SLOT_LEN_SIZE`] bytes of
    /// [`Self::slot_bytes`]).
    ///
    /// Because `len` decides which slot is authoritative, rewriting only this field commits a
    /// previously staged slot without disturbing its already-durable CRC. Retiring a slot must
    /// instead zero it entirely with [`Self::slot_bytes`]: a zero length with a durable CRC left
    /// behind could be reassembled into the retired checksum by a later torn rewrite.
    fn slot_len_bytes(len: u16) -> [u8; CHECKSUM_SLOT_LEN_SIZE] {
        let mut bytes = [0; CHECKSUM_SLOT_LEN_SIZE];
        let mut buf = bytes.as_mut_slice();
        len.write(&mut buf);
        bytes
    }
}

impl Write for Checksum {
    fn write(&self, buf: &mut impl BufMut) {
        self.len1.write(buf);
        self.crc1.write(buf);
        self.len2.write(buf);
        self.crc2.write(buf);
    }
}

impl CodecRead for Checksum {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            len1: u16::read(buf)?,
            crc1: u32::read(buf)?,
            len2: u16::read(buf)?,
            crc2: u32::read(buf)?,
        })
    }
}

impl FixedSize for Checksum {
    const SIZE: usize = 2 * u16::SIZE + 2 * crc32::Digest::SIZE;
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Checksum {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            len1: u.arbitrary()?,
            crc1: u.arbitrary()?,
            len2: u.arbitrary()?,
            crc2: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    #[should_panic(expected = "corruption target must be an interior page")]
    fn test_corrupt_page_rejects_short_blob() {
        use crate::Runner as _;
        crate::deterministic::Runner::default().start(|context| async move {
            corrupt_page(&context, "short-blob", b"blob", 0, 64).await;
        });
    }

    enum ValidationExpectation {
        Ok,
        OffsetOverflow,
        BlobInsufficientLength,
    }

    #[rstest]
    #[case::ok(12, vec![(0, 4), (4, 8)], 16, ValidationExpectation::Ok)]
    #[case::empty_ranges_are_a_noop(0, vec![], 0, ValidationExpectation::Ok)]
    #[case::zero_length_range(4, vec![(0, 0), (0, 4)], 16, ValidationExpectation::Ok)]
    #[case::offset_overflow(4, vec![(u64::MAX, 4)], 16, ValidationExpectation::OffsetOverflow)]
    #[case::insufficient_length(4, vec![(14, 4)], 16, ValidationExpectation::BlobInsufficientLength)]
    #[case::range_may_end_exactly_at_logical_size(4, vec![(12, 4)], 16, ValidationExpectation::Ok)]
    fn test_validate_read_ranges(
        #[case] buf_len: usize,
        #[case] ranges: Vec<(u64, usize)>,
        #[case] size: u64,
        #[case] expected: ValidationExpectation,
    ) {
        let result = validate_read_ranges(buf_len, ranges.iter().copied(), size);

        match expected {
            ValidationExpectation::Ok => assert!(result.is_ok()),
            ValidationExpectation::OffsetOverflow => {
                assert!(matches!(result, Err(Error::OffsetOverflow)))
            }
            ValidationExpectation::BlobInsufficientLength => {
                assert!(matches!(result, Err(Error::BlobInsufficientLength)))
            }
        }
    }

    #[test]
    #[should_panic(expected = "buf must hold one slot per range totaling its length")]
    fn test_validate_read_ranges_rejects_buffer_len_mismatch() {
        let _ = validate_read_ranges(7, [(0, 4), (4, 4)].into_iter(), 16);
    }

    #[test]
    #[should_panic(expected = "ranges must be sorted and non-overlapping")]
    fn test_validate_read_ranges_rejects_overlapping_ranges() {
        let _ = validate_read_ranges(8, [(0, 4), (2, 4)].into_iter(), 16);
    }

    #[test]
    #[should_panic(expected = "ranges must be sorted and non-overlapping")]
    fn test_validate_read_ranges_rejects_unsorted_ranges() {
        let _ = validate_read_ranges(8, [(8, 4), (4, 4)].into_iter(), 16);
    }

    #[test]
    #[should_panic(expected = "buf must hold one slot per range totaling its length")]
    fn test_validate_read_ranges_rejects_length_overflow() {
        let _ = validate_read_ranges(
            usize::MAX,
            [(0, usize::MAX), (u64::MAX, 1)].into_iter(),
            u64::MAX,
        );
    }

    #[test]
    fn test_crc_record_encode_read_roundtrip() {
        let record = Checksum {
            len1: 0x1234,
            crc1: 0xAABBCCDD,
            len2: 0x5678,
            crc2: 0x11223344,
        };

        let bytes = record.to_bytes();
        let restored = Checksum::read(&mut &bytes[..]).unwrap();

        assert_eq!(restored.len1, 0x1234);
        assert_eq!(restored.crc1, 0xAABBCCDD);
        assert_eq!(restored.len2, 0x5678);
        assert_eq!(restored.crc2, 0x11223344);
    }

    #[test]
    fn test_crc_record_encoding() {
        let record = Checksum {
            len1: 0x0102,
            crc1: 0x03040506,
            len2: 0x0708,
            crc2: 0x090A0B0C,
        };

        let bytes = record.to_bytes();
        // Verify big-endian encoding
        assert_eq!(
            bytes,
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
            ]
        );
    }

    #[test]
    fn test_crc_record_authoritative_len1_larger() {
        let record = Checksum {
            len1: 200,
            crc1: 0xAAAAAAAA,
            len2: 100,
            crc2: 0xBBBBBBBB,
        };

        assert_eq!(record.authoritative(), Slot::First);
    }

    #[test]
    fn test_crc_record_authoritative_len2_larger() {
        let record = Checksum {
            len1: 100,
            crc1: 0xAAAAAAAA,
            len2: 200,
            crc2: 0xBBBBBBBB,
        };

        assert_eq!(record.authoritative(), Slot::Second);
    }

    #[test]
    fn test_crc_record_authoritative_equal_lengths() {
        // The first slot wins ties.
        let record = Checksum {
            len1: 100,
            crc1: 0xAAAAAAAA,
            len2: 100,
            crc2: 0xBBBBBBBB,
        };

        assert_eq!(record.authoritative(), Slot::First);
    }

    #[test]
    fn test_validate_page_valid() {
        let page_size = 64usize;
        let physical_page_size = page_size + Checksum::SIZE;
        let mut page = vec![0u8; physical_page_size];

        // Write some data
        let data = b"hello world";
        page[..data.len()].copy_from_slice(data);

        // Compute CRC of the data portion
        let crc = Crc32::checksum(&page[..data.len()]);
        let record = Checksum::new(data.len() as u16, crc);

        // Write the CRC record at the end
        let crc_start = physical_page_size - Checksum::SIZE;
        page[crc_start..].copy_from_slice(&record.to_bytes());

        // Validate - should return the active checksum
        let validated = Checksum::validate_page(&page);
        assert!(validated.is_some());
        assert_eq!(validated.unwrap().len as usize, data.len());
    }

    #[test]
    fn test_validate_page_invalid_crc() {
        let page_size = 64usize;
        let physical_page_size = page_size + Checksum::SIZE;
        let mut page = vec![0u8; physical_page_size];

        // Write some data
        let data = b"hello world";
        page[..data.len()].copy_from_slice(data);

        // Write a record with wrong CRC
        let wrong_crc = 0xBADBADBA;
        let record = Checksum::new(data.len() as u16, wrong_crc);

        let crc_start = physical_page_size - Checksum::SIZE;
        page[crc_start..].copy_from_slice(&record.to_bytes());

        // Should fail validation (return None)
        let validated = Checksum::validate_page(&page);
        assert!(validated.is_none());
    }

    #[test]
    fn test_validate_page_corrupted_data() {
        let page_size = 64usize;
        let physical_page_size = page_size + Checksum::SIZE;
        let mut page = vec![0u8; physical_page_size];

        // Write some data and compute correct CRC
        let data = b"hello world";
        page[..data.len()].copy_from_slice(data);
        let crc = Crc32::checksum(&page[..data.len()]);
        let record = Checksum::new(data.len() as u16, crc);

        let crc_start = physical_page_size - Checksum::SIZE;
        page[crc_start..].copy_from_slice(&record.to_bytes());

        // Corrupt the data
        page[0] = 0xFF;

        // Should fail validation (return None)
        let validated = Checksum::validate_page(&page);
        assert!(validated.is_none());
    }

    #[test]
    fn test_validate_page_uses_larger_len() {
        let page_size = 64usize;
        let physical_page_size = page_size + Checksum::SIZE;
        let mut page = vec![0u8; physical_page_size];

        // Write data and compute CRC for the larger portion
        let data = b"hello world, this is longer";
        page[..data.len()].copy_from_slice(data);
        let crc = Crc32::checksum(&page[..data.len()]);

        // Create a record where len2 has the valid CRC for longer data
        let record = Checksum {
            len1: 5,
            crc1: 0xDEADBEEF, // Invalid CRC for shorter data
            len2: data.len() as u16,
            crc2: crc,
        };

        let crc_start = physical_page_size - Checksum::SIZE;
        page[crc_start..].copy_from_slice(&record.to_bytes());

        // Should validate using len2/crc2 since len2 > len1
        let validated = Checksum::validate_page(&page);
        assert!(validated.is_some());
        assert_eq!(validated.unwrap().len as usize, data.len());
    }

    #[test]
    fn test_validate_page_uses_fallback() {
        let page_size = 64usize;
        let physical_page_size = page_size + Checksum::SIZE;
        let mut page = vec![0u8; physical_page_size];

        // Write data
        let data = b"fallback data";
        page[..data.len()].copy_from_slice(data);
        let valid_crc = Crc32::checksum(&page[..data.len()]);
        let valid_len = data.len() as u16;

        // Create a record where:
        // len1 is larger (primary) but INVALID
        // len2 is smaller (fallback) but VALID
        let record = Checksum {
            len1: valid_len + 10, // Larger, so it's primary
            crc1: 0xBAD1DEA,      // Invalid CRC
            len2: valid_len,      // Smaller, so it's fallback
            crc2: valid_crc,      // Valid CRC
        };

        let crc_start = physical_page_size - Checksum::SIZE;
        page[crc_start..].copy_from_slice(&record.to_bytes());

        // Should validate using the fallback (len2)
        let validated = Checksum::validate_page(&page);

        assert!(validated.is_some(), "Should have validated using fallback");
        let validated = validated.unwrap();
        assert_eq!(
            validated,
            ActiveChecksum::new(Slot::Second, valid_len, valid_crc)
        );
    }

    #[test]
    fn test_validate_page_no_fallback_available() {
        let page_size = 64usize;
        let physical_page_size = page_size + Checksum::SIZE;
        let mut page = vec![0u8; physical_page_size];

        // Write some data
        let data = b"some data";
        page[..data.len()].copy_from_slice(data);

        // Create a record where:
        // len1 > 0 (primary) but with INVALID CRC
        // len2 = 0 (no fallback available)
        let record = Checksum {
            len1: data.len() as u16,
            crc1: 0xBAD1DEA, // Invalid CRC
            len2: 0,         // No fallback
            crc2: 0,
        };

        let crc_start = physical_page_size - Checksum::SIZE;
        page[crc_start..].copy_from_slice(&record.to_bytes());

        // Should fail validation since primary is invalid and no fallback exists
        let validated = Checksum::validate_page(&page);
        assert!(
            validated.is_none(),
            "Should fail when primary is invalid and fallback has len=0"
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Checksum>,
        }
    }
}
