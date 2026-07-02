use crate::{BufferPool, IoBuf, IoBufMut};
use bytes::BufMut;
use std::ops::{Bound, RangeBounds};

/// A buffer for caching data written to the tip of a blob.
///
/// The buffer always represents data at the "tip" of the logical blob, starting at `offset` and
/// extending for `len` bytes.
///
/// # Allocation Semantics
///
/// - Backing storage starts detached in [Self::new] and is allocated on first write.
/// - Logical data length is tracked separately from backing view length.
/// - Draining paths ([Self::take] and grow-resize in [Self::resize]) hand buffered bytes to the
///   caller and reset the tip to a detached empty state.
/// - Subsequent writes are copy-on-write: [Self::writable] recovers mutable ownership when
///   backing is unique, otherwise allocates from the pool and copies existing bytes.
/// - Prefix drains in [Self::drop_prefix] update the logical view and preserve backing whenever
///   possible.
pub(super) struct Buffer {
    /// The data to be written to the blob.
    ///
    /// Bytes in `[0,len)` are logically buffered.
    data: IoBuf,

    /// Number of logical buffered bytes in `data`.
    len: usize,

    /// The offset in the blob where the buffered data starts.
    ///
    /// This represents the logical position in the blob where `data[0]` would be written. The
    /// buffer is maintained at the "tip" to support efficient size calculation and appends.
    pub(super) offset: u64,

    /// The maximum size of the buffer.
    pub(super) capacity: usize,

    /// Pool used to allocate backing buffers.
    pool: BufferPool,
}

impl Buffer {
    /// Creates a new buffer with the provided `offset` and `capacity`.
    ///
    /// The buffer starts detached, mutable, and allocates backing on first write.
    pub(super) fn new(offset: u64, capacity: usize, pool: BufferPool) -> Self {
        Self::from(offset, IoBuf::default(), capacity, pool)
    }

    /// Creates a new buffer seeded with existing logical bytes.
    pub(super) fn from(offset: u64, data: IoBuf, capacity: usize, pool: BufferPool) -> Self {
        let len = data.len();
        Self {
            data,
            len,
            offset,
            capacity,
            pool,
        }
    }

    /// Returns the current logical size of the blob including any buffered data.
    pub(super) const fn size(&self) -> u64 {
        self.offset + self.len as u64
    }

    /// Returns the logical number of buffered bytes.
    pub(super) const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the buffer is empty.
    pub(super) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns immutable logical bytes for `range`.
    ///
    /// # Panics
    ///
    /// Panics if `range` falls outside `[0, len()]`.
    pub(super) fn slice(&self, range: impl RangeBounds<usize>) -> IoBuf {
        let start = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.checked_add(1).expect("range start overflow"),
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&n) => n.checked_add(1).expect("range end overflow"),
            Bound::Excluded(&n) => n,
            Bound::Unbounded => self.len,
        };
        assert!(start <= end, "slice start must be <= end");
        assert!(end <= self.len, "slice out of bounds");
        self.data.slice(start..end)
    }

    /// Discards the first `n` bytes of the buffer and advances the offset by `n`.
    ///
    /// # Panics
    ///
    /// Panics if `n` is greater than the length of the buffer.
    pub(super) fn advance(&mut self, n: usize) {
        assert!(n <= self.len);
        match n {
            0 => {}
            n if n == self.len => {
                self.data = IoBuf::default();
                self.len = 0;
            }
            n => {
                self.data = self.data.slice(n..self.len);
                self.len -= n;
            }
        }
        self.offset += n as u64;
    }

    /// Shrinks the logical blob size ([Self::size]) to `len`. Buffered bytes below `len` are
    /// kept; the rest are discarded.
    ///
    /// # Panics
    ///
    /// Panics if `len` does not shrink the blob.
    pub(super) fn truncate(&mut self, len: u64) {
        assert!(len < self.size(), "truncate must shrink the blob");

        if len <= self.offset {
            // All buffered bytes are at or beyond `len`: drop them and restart at the new end.
            self.len = 0;
            self.offset = len;
        } else {
            // Keep only the buffered bytes below `len`.
            self.len = (len - self.offset) as usize;
        }
    }

    /// Returns the buffered data and its blob offset, or returns `None` if the buffer is already
    /// empty.
    ///
    /// This hands ownership of the buffered bytes to the caller, resets the tip to empty, and
    /// advances offset to the end of the drained range.
    pub(super) fn take(&mut self) -> Option<(IoBuf, u64)> {
        if self.is_empty() {
            return None;
        }

        // Clear the logical length up front so the tip is empty even if the returned buffer
        // still aliases the old backing.
        let len = std::mem::take(&mut self.len);
        let offset = self.offset;
        self.offset += len as u64;

        // Hand the buffered prefix to the caller without copying. If `data` retained extra
        // capacity or trailing bytes, `split_to` leaves them behind in the discarded remainder.
        let mut data = std::mem::take(&mut self.data);
        Some((data.split_to(len), offset))
    }

    /// Returns a mutable tip buffer with capacity for at least `needed` bytes.
    ///
    /// This consumes current backing and preserves existing contents.
    ///
    /// - If backing is uniquely owned and has enough capacity, no allocation occurs.
    /// - If backing is shared (for example, because a flushed/read view is still alive) or too
    ///   small, a new pooled allocation is created and existing bytes are copied.
    fn writable(&mut self, needed: usize) -> IoBufMut {
        let current = std::mem::take(&mut self.data);
        let source = match current.try_into_mut() {
            Ok(mut writable) => {
                writable.truncate(self.len);
                if writable.capacity() >= needed {
                    return writable;
                }
                writable.freeze()
            }
            Err(shared) => shared,
        };

        let target = needed.max(self.capacity);
        let mut grown = self.pool.alloc(target);
        grown.put_slice(&source.as_ref()[..self.len]);
        grown
    }

    /// Merges the provided `data` into the buffer at the provided blob `offset` if it falls
    /// entirely within the range `[buffer.offset,buffer.offset+capacity)`.
    ///
    /// The buffer will be expanded if necessary to accommodate the new data, and any gaps that
    /// may result are filled with zeros. Returns `true` if the merge was performed, otherwise the
    /// caller is responsible for continuing to manage the data.
    pub(super) fn merge(&mut self, data: &[u8], offset: u64) -> bool {
        let end_offset = offset
            .checked_add(data.len() as u64)
            .expect("end_offset overflow");
        let can_merge_into_buffer =
            offset >= self.offset && end_offset <= self.offset + self.capacity as u64;
        if !can_merge_into_buffer {
            return false;
        }
        let start = (offset - self.offset) as usize;
        let end = start + data.len();

        let mut writable = self.writable(end);
        let prev = writable.len();

        // Extend logical length to end, zero-filling any gap.
        if end > prev {
            writable.put_bytes(0, end - prev);
        }

        // Copy the provided data into the buffer.
        writable.as_mut()[start..end].copy_from_slice(data.as_ref());
        self.len = writable.len();
        self.data = writable.freeze();

        true
    }

    /// Replaces the buffered contents with `data` positioned at blob offset `offset`, without
    /// copying. The capacity and pool are preserved; a later mutation recovers or reallocates
    /// backing via [Self::writable].
    pub(super) fn replace(&mut self, offset: u64, data: IoBuf) {
        self.len = data.len();
        self.data = data;
        self.offset = offset;
    }

    /// Appends the provided `data` to the buffer, and returns `true` if the buffer is over capacity
    /// after the append.
    ///
    /// If the buffer is above capacity, the caller is responsible for using `take` to bring it back
    /// under. Further appends are safe, but will continue growing the buffer beyond its capacity.
    pub(super) fn append(&mut self, data: &[u8]) -> bool {
        let end = self.len + data.len();
        let mut writable = self.writable(end);
        writable.put_slice(data);
        let over_capacity = writable.len() > self.capacity;
        self.len = writable.len();
        self.data = writable.freeze();
        over_capacity
    }

    /// Removes `len` leading bytes from the buffered data while preserving the remaining suffix.
    ///
    /// The remaining suffix stays as a logical prefix in the updated view.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds current buffer length.
    pub(super) fn drop_prefix(&mut self, len: usize) {
        assert!(len <= self.len);
        if len == 0 {
            return;
        }
        let current_len = self.len;
        if len == current_len {
            self.len = 0;
            return;
        }
        self.data = self.data.slice(len..current_len);
        self.len = current_len - len;
    }

    /// Clears buffered data while preserving offset.
    ///
    /// This resets logical length and keeps backing allocation for reuse.
    pub(super) const fn clear(&mut self) {
        self.len = 0;
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.data.as_ref()[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::metrics::Registry;

    fn test_pool() -> crate::BufferPool {
        let mut registry = Registry::default();
        crate::BufferPool::new(crate::BufferPoolConfig::for_storage(), &mut registry)
    }

    #[test]
    fn test_tip_append() {
        let pool = test_pool();
        let mut buffer = Buffer::new(50, 100, pool);
        assert_eq!(buffer.size(), 50);
        assert!(buffer.is_empty());
        assert!(buffer.take().is_none());

        // Add some data to the buffer.
        assert!(!buffer.append(&[1, 2, 3]));
        assert_eq!(buffer.size(), 53);
        assert!(!buffer.is_empty());

        // Confirm `take()` works as intended.
        let taken = buffer.take().unwrap();
        assert_eq!(taken.0.as_ref(), &[1, 2, 3]);
        assert_eq!(taken.1, 50);
        assert_eq!(buffer.size(), 53);
        assert!(buffer.take().is_none());

        // Fill the buffer to capacity.
        let mut buf = vec![42; 100];
        assert!(!buffer.append(&buf));
        assert_eq!(buffer.size(), 153);

        // Add one more byte, which should push it over capacity. The byte should still be appended.
        assert!(buffer.append(&[43]));
        assert_eq!(buffer.size(), 154);
        buf.push(43);
        let taken = buffer.take().unwrap();
        assert_eq!(taken.0.as_ref(), buf.as_slice());
        assert_eq!(taken.1, 53);
    }

    #[test]
    fn test_tip_truncate() {
        let pool = test_pool();
        let mut buffer = Buffer::new(60, 100, pool);
        buffer.append(&[4, 5, 6]);
        assert_eq!(buffer.size(), 63);

        // Truncate into the buffered bytes: the prefix below the new size survives.
        buffer.truncate(61);
        assert_eq!(buffer.size(), 61);
        let taken = buffer.take().unwrap();
        assert_eq!(taken.0.as_ref(), &[4]);
        assert_eq!(taken.1, 60);
        assert_eq!(buffer.size(), 61);

        buffer.append(&[7, 8, 9]);

        // Truncate below the buffer's offset of 61: all buffered bytes are dropped and the
        // empty buffer restarts at the new size.
        buffer.truncate(59);
        assert_eq!(buffer.size(), 59);
        assert!(buffer.take().is_none());
        assert_eq!(buffer.size(), 59);
    }

    #[test]
    #[should_panic(expected = "truncate must shrink the blob")]
    fn test_tip_truncate_rejects_grow() {
        let pool = test_pool();
        let mut buffer = Buffer::new(50, 100, pool);
        buffer.append(&[1, 2, 3]);
        buffer.truncate(60);
    }

    #[test]
    fn test_tip_first_merge_from_empty() {
        let pool = test_pool();
        let mut buffer = Buffer::new(0, 16, pool);
        assert!(buffer.data.is_empty());

        assert!(buffer.merge(b"abc", 0));
        assert_eq!(buffer.data.as_ref(), b"abc");
    }

    #[test]
    fn test_tip_slice_uses_resolved_bounds() {
        let pool = test_pool();
        let mut buffer = Buffer::new(0, 16, pool);

        buffer.append(b"stale");
        let _ = buffer.take().expect("buffer should contain data");

        assert!(buffer.slice(..).is_empty());
        assert!(buffer.slice(0..).is_empty());
    }

    #[test]
    fn test_tip_writable_copies_when_slice_is_live() {
        let pool = test_pool();
        let mut buffer = Buffer::new(0, 16, pool);

        assert!(!buffer.append(b"abc"));
        let snapshot = buffer.slice(..);

        let mut writable = buffer.writable(6);
        assert_eq!(writable.as_ref(), b"abc");
        assert_ne!(writable.as_ref().as_ptr(), snapshot.as_ref().as_ptr());

        writable.put_slice(b"def");
        writable.as_mut()[0] = b'X';

        assert_eq!(snapshot.as_ref(), b"abc");
        assert_eq!(writable.as_ref(), b"Xbcdef");
    }

    #[test]
    fn test_tip_from_preserves_seed_bytes_until_mutated() {
        let pool = test_pool();
        let mut buffer = Buffer::from(7, IoBuf::from(&b"abc"[..]), 16, pool);

        assert_eq!(buffer.offset, 7);
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.as_ref(), b"abc");

        assert!(!buffer.append(b"def"));
        assert_eq!(buffer.as_ref(), b"abcdef");
    }
}
