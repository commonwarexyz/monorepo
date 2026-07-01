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
/// - Draining paths hand buffered bytes to the blob using [Self::slice], then commit the drain
///   with [Self::commit_prefix] only after the blob operation succeeds.
/// - Subsequent writes are copy-on-write: [Self::writable] recovers mutable ownership when
///   backing is unique, otherwise allocates from the pool and copies existing bytes.
/// - Successful prefix drains use [Self::commit_prefix] to update the logical view.
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

    /// Commits a successful flush of `len` leading bytes.
    ///
    /// Callers should use [Self::slice] to hand bytes to storage before this method. This keeps the
    /// tip recoverable if the storage future is dropped before completion.
    pub(super) fn commit_prefix(&mut self, len: usize) {
        assert!(len <= self.len);
        if len == 0 {
            return;
        }

        if len == self.len {
            self.len = 0;
            self.data = IoBuf::default();
        } else {
            self.data = self.data.slice(len..self.len);
            self.len -= len;
        }
        self.offset += len as u64;
    }

    /// Adjusts the tip after a blob resize has succeeded.
    ///
    /// # Panics
    ///
    /// Panics if the tip holds bytes at or above `len`: callers must flush and commit buffered
    /// data before a resize that does not shrink below it.
    pub(super) fn commit_resize(&mut self, len: u64) {
        if self.is_empty() {
            self.offset = len;
            return;
        }

        assert!(
            len < self.size(),
            "resize over buffered bytes must flush first"
        );
        if len >= self.offset {
            self.len = (len - self.offset) as usize;
        } else {
            self.len = 0;
            self.data = IoBuf::default();
            self.offset = len;
        }
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
    /// If the buffer is above capacity, the caller is responsible for flushing and committing a
    /// prefix. Further appends are safe, but will continue growing the buffer beyond its capacity.
    pub(super) fn append(&mut self, data: &[u8]) -> bool {
        let end = self.len + data.len();
        let mut writable = self.writable(end);
        writable.put_slice(data);
        let over_capacity = writable.len() > self.capacity;
        self.len = writable.len();
        self.data = writable.freeze();
        over_capacity
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
        buffer.commit_prefix(0);

        // Add some data to the buffer.
        assert!(!buffer.append(&[1, 2, 3]));
        assert_eq!(buffer.size(), 53);
        assert!(!buffer.is_empty());

        // Confirm successful prefix commits detach flushed bytes.
        let flushed = buffer.slice(..);
        assert_eq!(flushed.as_ref(), &[1, 2, 3]);
        buffer.commit_prefix(3);
        assert_eq!(buffer.size(), 53);
        assert!(buffer.is_empty());

        // Fill the buffer to capacity.
        let mut buf = vec![42; 100];
        assert!(!buffer.append(&buf));
        assert_eq!(buffer.size(), 153);

        // Add one more byte, which should push it over capacity. The byte should still be appended.
        assert!(buffer.append(&[43]));
        assert_eq!(buffer.size(), 154);
        buf.push(43);
        let flushed = buffer.slice(..);
        assert_eq!(flushed.as_ref(), buf.as_slice());
        buffer.commit_prefix(buf.len());
        assert!(buffer.is_empty());
        assert_eq!(buffer.size(), 154);
    }

    #[test]
    fn test_tip_resize() {
        let pool = test_pool();
        let mut buffer = Buffer::new(50, 100, pool);
        buffer.append(&[1, 2, 3]);
        assert_eq!(buffer.size(), 53);

        // A grow resize first flushes and commits buffered data, then publishes the new size.
        let flushed = buffer.slice(..);
        assert_eq!(flushed.as_ref(), &[1, 2, 3]);
        buffer.commit_prefix(3);
        buffer.commit_resize(60);
        assert_eq!(buffer.size(), 60);
        assert!(buffer.is_empty());

        buffer.append(&[4, 5, 6]);
        assert_eq!(buffer.size(), 63);

        // Resize the buffer down to size 61.
        buffer.commit_resize(61);
        assert_eq!(buffer.size(), 61);
        assert_eq!(buffer.as_ref(), &[4]);
        buffer.commit_prefix(1);
        assert_eq!(buffer.size(), 61);

        buffer.append(&[7, 8, 9]);

        // Resize the buffer prior to the current offset of 61. This should simply reset the buffer
        // at the new size.
        buffer.commit_resize(59);
        assert_eq!(buffer.size(), 59);
        assert!(buffer.is_empty());
        assert_eq!(buffer.size(), 59);
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
        buffer.commit_prefix(5);

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
