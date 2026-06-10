//! A non-contiguous, read-only [Buf] implementation over borrowed page slices, allowing codec
//! types to be decoded directly from cached page slots without copying.

use bytes::Buf;

/// Maximum number of page slices gathered for a single decode. Bounds both the inline storage and
/// the work done under the cache read lock.
pub(super) const MAX_GATHER_PAGES: usize = 8;

/// A non-contiguous, read-only view over up to [MAX_GATHER_PAGES] borrowed byte slices, in logical
/// order.
pub(super) struct PagedBuf<'a> {
    /// The gathered slices, in logical order. Only the first `count` entries are populated, and
    /// populated entries are never empty (preserving the [Buf] invariant that `chunk()` is
    /// non-empty while `remaining() > 0`).
    slices: [&'a [u8]; MAX_GATHER_PAGES],

    /// Number of populated entries in `slices`.
    count: usize,

    /// Index of the slice the cursor is in.
    idx: usize,

    /// Byte position of the cursor within `slices[idx]`.
    pos: usize,

    /// Total bytes remaining from the cursor to the end of the last slice.
    remaining: usize,

    /// Total bytes pushed, including any already consumed.
    len: usize,

    /// True if gathering stopped before the requested range was covered, due to a non-resident
    /// page or the [MAX_GATHER_PAGES] cap. When a decode fails against a truncated buffer the
    /// caller must fall back to an authoritative read rather than report an error.
    truncated: bool,
}

impl<'a> PagedBuf<'a> {
    /// Returns an empty, non-truncated buffer.
    pub(super) const fn new() -> Self {
        Self {
            slices: [&[]; MAX_GATHER_PAGES],
            count: 0,
            idx: 0,
            pos: 0,
            remaining: 0,
            len: 0,
            truncated: false,
        }
    }

    /// Appends a non-empty slice, returning false (without modification) if the buffer already
    /// holds [MAX_GATHER_PAGES] slices.
    ///
    /// # Panics
    ///
    /// Panics if `slice` is empty.
    pub(super) fn push(&mut self, slice: &'a [u8]) -> bool {
        assert!(!slice.is_empty(), "cannot push an empty slice");
        if self.count == MAX_GATHER_PAGES {
            return false;
        }
        self.slices[self.count] = slice;
        self.count += 1;
        self.remaining += slice.len();
        self.len += slice.len();
        true
    }

    /// Total bytes gathered, including any already consumed.
    pub(super) const fn len(&self) -> usize {
        self.len
    }

    /// Whether gathering stopped before covering the requested range.
    pub(super) const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Marks the buffer as truncated.
    pub(super) const fn set_truncated(&mut self) {
        self.truncated = true;
    }

    /// Bytes consumed from the front of the buffer so far.
    pub(super) const fn consumed(&self) -> usize {
        self.len - self.remaining
    }
}

impl Buf for PagedBuf<'_> {
    #[inline]
    fn remaining(&self) -> usize {
        self.remaining
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        if self.remaining == 0 {
            return &[];
        }
        &self.slices[self.idx][self.pos..]
    }

    #[inline]
    fn advance(&mut self, mut cnt: usize) {
        assert!(
            cnt <= self.remaining,
            "cannot advance past the end of the buffer"
        );
        self.remaining -= cnt;
        while cnt > 0 {
            let available = self.slices[self.idx].len() - self.pos;
            if cnt < available {
                self.pos += cnt;
                return;
            }
            cnt -= available;
            self.idx += 1;
            self.pos = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Error, ReadExt};

    #[test]
    fn test_empty() {
        let buf = PagedBuf::new();
        assert_eq!(buf.remaining(), 0);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.consumed(), 0);
        assert!(!buf.truncated());
        assert!(buf.chunk().is_empty());
    }

    #[test]
    fn test_single_slice() {
        let data = [1u8, 2, 3];
        let mut buf = PagedBuf::new();
        assert!(buf.push(&data));
        assert_eq!(buf.remaining(), 3);
        assert_eq!(buf.chunk(), &data);
        buf.advance(3);
        assert_eq!(buf.remaining(), 0);
        assert!(buf.chunk().is_empty());
        assert_eq!(buf.consumed(), 3);
    }

    #[test]
    fn test_push_cap() {
        let data = [0u8; 1];
        let mut buf = PagedBuf::new();
        for _ in 0..MAX_GATHER_PAGES {
            assert!(buf.push(&data));
        }
        assert!(!buf.push(&data));
        assert_eq!(buf.len(), MAX_GATHER_PAGES);
        assert_eq!(buf.remaining(), MAX_GATHER_PAGES);
    }

    #[test]
    #[should_panic(expected = "cannot push an empty slice")]
    fn test_push_empty_panics() {
        let mut buf = PagedBuf::new();
        buf.push(&[]);
    }

    #[test]
    #[should_panic(expected = "cannot advance past the end of the buffer")]
    fn test_advance_past_end_panics() {
        let data = [1u8, 2, 3];
        let mut buf = PagedBuf::new();
        assert!(buf.push(&data));
        buf.advance(4);
    }

    #[test]
    fn test_reads_across_boundaries() {
        // Split a 12-byte payload across three slices and verify primitive reads that cross
        // slice boundaries match reads over the contiguous payload.
        let payload: Vec<u8> = (1u8..=12).collect();
        let mut buf = PagedBuf::new();
        assert!(buf.push(&payload[..5]));
        assert!(buf.push(&payload[5..7]));
        assert!(buf.push(&payload[7..]));
        assert_eq!(buf.len(), 12);

        assert_eq!(buf.get_u8(), 1);
        assert_eq!(buf.consumed(), 1);
        // Crosses the first and second boundaries.
        assert_eq!(
            buf.get_u32(),
            u32::from_be_bytes(payload[1..5].try_into().unwrap())
        );
        let mut out = [0u8; 7];
        buf.copy_to_slice(&mut out);
        assert_eq!(out, payload[5..]);
        assert_eq!(buf.remaining(), 0);
        assert_eq!(buf.consumed(), 12);
    }

    #[test]
    fn test_advance_across_boundaries() {
        let payload: Vec<u8> = (0u8..10).collect();
        let mut buf = PagedBuf::new();
        assert!(buf.push(&payload[..4]));
        assert!(buf.push(&payload[4..8]));
        assert!(buf.push(&payload[8..]));

        // Advance to exactly a slice boundary; the next chunk must be non-empty.
        buf.advance(4);
        assert_eq!(buf.chunk(), &payload[4..8]);
        // Advance across a boundary into the middle of the last slice.
        buf.advance(5);
        assert_eq!(buf.chunk(), &payload[9..]);
        assert_eq!(buf.remaining(), 1);
        buf.advance(1);
        assert!(buf.chunk().is_empty());
    }

    #[test]
    fn test_chunk_non_empty_invariant() {
        let payload = [7u8; 6];
        let mut buf = PagedBuf::new();
        assert!(buf.push(&payload[..3]));
        assert!(buf.push(&payload[3..]));
        while buf.remaining() > 0 {
            assert!(!buf.chunk().is_empty());
            buf.advance(1);
        }
        assert!(buf.chunk().is_empty());
    }

    #[test]
    fn test_codec_decode_across_slices() {
        // Decoding a codec type split across two slices must equal decoding it from the
        // contiguous concatenation.
        let value = 0x0102030405060708u64;
        let encoded = value.to_be_bytes();
        for split in 1..encoded.len() {
            let mut buf = PagedBuf::new();
            assert!(buf.push(&encoded[..split]));
            assert!(buf.push(&encoded[split..]));
            assert_eq!(u64::read(&mut buf).unwrap(), value);
            assert_eq!(buf.consumed(), encoded.len());
        }

        // A fixed-size array read split across slices.
        let payload: [u8; 6] = [1, 2, 3, 4, 5, 6];
        let mut buf = PagedBuf::new();
        assert!(buf.push(&payload[..2]));
        assert!(buf.push(&payload[2..]));
        assert_eq!(<[u8; 6]>::read(&mut buf).unwrap(), payload);
    }

    #[test]
    fn test_codec_decode_short_buffer() {
        // A decode that needs more bytes than gathered must fail with EndOfBuffer rather
        // than panic.
        let encoded = 42u64.to_be_bytes();
        let mut buf = PagedBuf::new();
        assert!(buf.push(&encoded[..4]));
        assert!(matches!(u64::read(&mut buf), Err(Error::EndOfBuffer)));
    }
}
