//! A non-contiguous, read-only [Buf] implementation over refcounted page slices, allowing codec
//! types to be decoded directly from cached pages after the cache lock is released.

use crate::IoBuf;
use bytes::Buf;

/// Maximum number of page slices gathered for a single decode. Bounds both the inline storage and
/// the work done under the cache read lock.
pub(super) const MAX_GATHER_PAGES: usize = 8;

/// A non-contiguous, read-only view over up to [MAX_GATHER_PAGES] page slices, in logical order.
///
/// Each slice is a refcounted view of a cached page, so the buffer owns the bytes it reads:
/// a concurrent eviction or replacement of the underlying cache entry leaves them untouched.
pub(super) struct PagedBuf {
    /// The gathered slices, in logical order. Only the first `count` entries are populated, and
    /// populated entries are never empty (preserving the [Buf] invariant that `chunk()` is
    /// non-empty while `remaining() > 0`).
    slices: [IoBuf; MAX_GATHER_PAGES],

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

impl PagedBuf {
    /// Returns an empty, non-truncated buffer.
    pub(super) fn new() -> Self {
        Self {
            slices: Default::default(),
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
    pub(super) fn push(&mut self, slice: IoBuf) -> bool {
        assert!(!slice.is_empty(), "cannot push an empty slice");
        if self.count == MAX_GATHER_PAGES {
            return false;
        }
        self.remaining += slice.len();
        self.len += slice.len();
        self.slices[self.count] = slice;
        self.count += 1;
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

impl Buf for PagedBuf {
    #[inline]
    fn remaining(&self) -> usize {
        self.remaining
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        if self.remaining == 0 {
            return &[];
        }
        &self.slices[self.idx].as_ref()[self.pos..]
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

    fn buf_from(bytes: &[u8]) -> IoBuf {
        IoBuf::from(bytes.to_vec())
    }

    #[test]
    fn test_brute_force_against_contiguous() {
        // Exhaustively compare PagedBuf against a contiguous slice for every split of an
        // 8-byte payload into slices and every two-step advance sequence.
        let payload: Vec<u8> = (10u8..18).collect();
        let n = payload.len();
        // Enumerate split points via bitmask: bit i set => split after byte i.
        for mask in 0u32..(1 << (n - 1)) {
            let mut slices: Vec<&[u8]> = Vec::new();
            let mut start = 0;
            for i in 0..n - 1 {
                if mask & (1 << i) != 0 {
                    slices.push(&payload[start..=i]);
                    start = i + 1;
                }
            }
            slices.push(&payload[start..]);
            if slices.len() > MAX_GATHER_PAGES {
                continue;
            }
            // For every starting advance a (0..=n) then a second advance b (0..=n-a),
            // verify remaining/consumed/chunk prefix agreement.
            for a in 0..=n {
                for b in 0..=(n - a) {
                    let mut buf = PagedBuf::new();
                    for s in &slices {
                        assert!(buf.push(buf_from(s)));
                    }
                    assert_eq!(buf.len(), n);
                    buf.advance(a);
                    assert_eq!(buf.consumed(), a, "mask={mask} a={a}");
                    buf.advance(b);
                    let consumed = a + b;
                    assert_eq!(buf.consumed(), consumed, "mask={mask} a={a} b={b}");
                    assert_eq!(buf.remaining(), n - consumed);
                    // chunk() must be a non-empty prefix of the rest while remaining > 0.
                    if buf.remaining() > 0 {
                        let chunk = buf.chunk();
                        assert!(!chunk.is_empty(), "mask={mask} a={a} b={b}");
                        assert_eq!(
                            chunk,
                            &payload[consumed..consumed + chunk.len()],
                            "mask={mask} a={a} b={b}"
                        );
                    } else {
                        assert!(buf.chunk().is_empty());
                    }
                    // Drain the rest with copy_to_slice and compare to the contiguous tail.
                    let mut rest = vec![0u8; n - consumed];
                    buf.copy_to_slice(&mut rest);
                    assert_eq!(rest, &payload[consumed..], "mask={mask} a={a} b={b}");
                    assert_eq!(buf.remaining(), 0);
                    assert_eq!(buf.consumed(), n);
                }
            }
        }
    }

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
        assert!(buf.push(buf_from(&data)));
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
            assert!(buf.push(buf_from(&data)));
        }
        assert!(!buf.push(buf_from(&data)));
        assert_eq!(buf.len(), MAX_GATHER_PAGES);
        assert_eq!(buf.remaining(), MAX_GATHER_PAGES);
    }

    #[test]
    #[should_panic(expected = "cannot push an empty slice")]
    fn test_push_empty_panics() {
        let mut buf = PagedBuf::new();
        buf.push(IoBuf::default());
    }

    #[test]
    #[should_panic(expected = "cannot advance past the end of the buffer")]
    fn test_advance_past_end_panics() {
        let data = [1u8, 2, 3];
        let mut buf = PagedBuf::new();
        assert!(buf.push(buf_from(&data)));
        buf.advance(4);
    }

    #[test]
    fn test_reads_across_boundaries() {
        // Split a 12-byte payload across three slices and verify primitive reads that cross
        // slice boundaries match reads over the contiguous payload.
        let payload: Vec<u8> = (1u8..=12).collect();
        let mut buf = PagedBuf::new();
        assert!(buf.push(buf_from(&payload[..5])));
        assert!(buf.push(buf_from(&payload[5..7])));
        assert!(buf.push(buf_from(&payload[7..])));
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
        assert!(buf.push(buf_from(&payload[..4])));
        assert!(buf.push(buf_from(&payload[4..8])));
        assert!(buf.push(buf_from(&payload[8..])));

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
        assert!(buf.push(buf_from(&payload[..3])));
        assert!(buf.push(buf_from(&payload[3..])));
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
            assert!(buf.push(buf_from(&encoded[..split])));
            assert!(buf.push(buf_from(&encoded[split..])));
            assert_eq!(u64::read(&mut buf).unwrap(), value);
            assert_eq!(buf.consumed(), encoded.len());
        }

        // A fixed-size array read split across slices.
        let payload: [u8; 6] = [1, 2, 3, 4, 5, 6];
        let mut buf = PagedBuf::new();
        assert!(buf.push(buf_from(&payload[..2])));
        assert!(buf.push(buf_from(&payload[2..])));
        assert_eq!(<[u8; 6]>::read(&mut buf).unwrap(), payload);
    }

    #[test]
    fn test_codec_decode_short_buffer() {
        // A decode that needs more bytes than gathered must fail with EndOfBuffer rather
        // than panic.
        let encoded = 42u64.to_be_bytes();
        let mut buf = PagedBuf::new();
        assert!(buf.push(buf_from(&encoded[..4])));
        assert!(matches!(u64::read(&mut buf), Err(Error::EndOfBuffer)));
    }
}
