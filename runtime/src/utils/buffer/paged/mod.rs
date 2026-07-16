//! Blob wrappers for buffered writing and page-cached reading.
//!
//! # Page-oriented structure
//!
//! Blob data is stored as raw logical bytes: the physical offset of a byte equals its logical
//! offset, and the blob's size is the number of logical bytes it holds. Pages exist only as a
//! read-caching granularity: reads are cached in units of `page_size` bytes dictated by the
//! managing page cache, and writers buffer appends so bytes reach the blob in page-aligned
//! writes where possible.
//!
//! All pages in a blob are full except for the very last page, which can be full or partial. A
//! partial last page occupies exactly its logical bytes on the blob. Integrity and
//! crash-atomicity are the storage backend's responsibility (see [`crate::storage::volume`]),
//! so this layer performs no checksumming and never rewrites previously written bytes: appends
//! reach the blob as physically append-only writes.

use crate::Error;

mod cache;
mod read;
mod sealed;
mod view;
mod writer;

pub use cache::CacheRef;
pub use read::Replay;
pub use sealed::Sealed;
pub use writer::Writer;

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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

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
}
