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
/// - Backing storage is allocated eagerly in [Self::new] at `capacity` bytes.
/// - Logical data length is tracked separately from backing view length.
/// - Flushing paths ([Self::take] and grow-resize in [Self::resize]) return a cloned `IoBuf` view
///   of logical bytes and keep backing allocated for reuse.
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

    /// Whether this buffer should allow new data.
    // TODO(#2371): Use a distinct state-type for immutable vs immutable.
    immutable: bool,

    /// Pool used to allocate backing buffers.
    pool: BufferPool,
}

impl Buffer {
    /// Creates a new buffer with the provided `offset` and `capacity`.
    ///
    /// The backing buffer is allocated eagerly and starts with zero length.
    pub(super) fn new(offset: u64, capacity: usize, pool: BufferPool) -> Self {
        let data = pool.alloc(capacity).freeze();
        Self {
            data,
            len: 0,
            offset,
            capacity,
            immutable: false,
            pool,
        }
    }

    /// Returns the current logical size of the blob including any buffered data.
    pub(super) const fn size(&self) -> u64 {
        self.offset + self.len as u64
    }

    /// Returns true if the buffer is empty.
    pub(super) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns true if the buffer is immutable.
    pub(super) const fn is_immutable(&self) -> bool {
        self.immutable
    }

    /// Set the buffer immutable.
    ///
    /// If `compact` is true, backing storage is compacted to the current logical length.
    /// This is idempotent for both state and compaction behavior.
    pub(super) fn set_immutable(&mut self, compact: bool) {
        self.immutable = true;
        if !compact {
            return;
        }
        if self.len == 0 {
            self.data = IoBuf::default();
            self.len = 0;
            return;
        }
        let mut shrunk = self.pool.alloc(self.len);
        shrunk.put_slice(self.as_ref());
        self.data = shrunk.freeze();
    }

    /// Set the buffer mutable.
    pub(super) const fn set_mutable(&mut self) {
        self.immutable = false;
    }

    /// Returns the logical number of buffered bytes.
    pub(super) const fn len(&self) -> usize {
        self.len
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
        self.data.slice(range)
    }

    /// Adjust the buffer to correspond to resizing the logical blob to size `len`.
    ///
    /// If the new size is greater than the current size, a clone of the existing buffered bytes is
    /// returned (to be flushed to the underlying blob), and logical length is reset to zero while
    /// preserving backing allocation for reuse. (The returned data is what would be returned by a
    /// call to [Self::take].)
    ///
    /// If the new size is less than the current size (but still greater than current offset), the
    /// buffer is truncated to the new size.
    ///
    /// If the new size is less than the current offset, the buffer is reset to the empty state with
    /// an updated offset positioned at the end of the logical blob.
    pub(super) fn resize(&mut self, len: u64) -> Option<(IoBuf, u64)> {
        // Handle case where the buffer is empty.
        if self.is_empty() {
            self.offset = len;
            return None;
        }

        // Handle case where there is some data in the buffer.
        if len >= self.size() {
            let previous = (self.data.slice(..self.len), self.offset);
            self.len = 0;
            self.offset = len;
            Some(previous)
        } else if len >= self.offset {
            self.len = (len - self.offset) as usize;
            None
        } else {
            self.len = 0;
            self.offset = len;
            None
        }
    }

    /// Returns the buffered data and its blob offset, or returns `None` if the buffer is already
    /// empty.
    ///
    /// This returns a cloned `IoBuf` view of logical bytes, resets logical length to zero, and
    /// advances offset to the end of the drained range.
    pub(super) fn take(&mut self) -> Option<(IoBuf, u64)> {
        if self.is_empty() {
            return None;
        }
        let buf = self.data.slice(..self.len);
        self.len = 0;
        let offset = self.offset;
        self.offset += buf.len() as u64;
        Some((buf, offset))
    }

    /// Returns a mutable tip buffer with capacity for at least `needed` bytes.
    ///
    /// This consumes current immutable backing and preserves existing contents.
    ///
    /// - If backing is uniquely owned and has enough capacity, no allocation occurs.
    /// - If backing is shared (for example, because a flushed/read view is still alive) or too
    ///   small, a new pooled allocation is created and existing bytes are copied.
    fn writable(&mut self, needed: usize) -> IoBufMut {
        let logical_len = self.len;
        let current = std::mem::take(&mut self.data);
        match current.try_into_mut() {
            Ok(mut writable) => {
                writable.truncate(logical_len);
                if writable.capacity() >= needed {
                    return writable;
                }
                let target = needed.max(self.capacity);
                let mut grown = self.pool.alloc(target);
                grown.put_slice(writable.as_ref());
                grown
            }
            Err(shared) => {
                let target = needed.max(self.capacity);
                let mut grown = self.pool.alloc(target);
                grown.put_slice(&shared.as_ref()[..logical_len]);
                grown
            }
        }
    }

    fn append_zeros(dst: &mut IoBufMut, len: usize) {
        const ZERO_CHUNK: [u8; 256] = [0; 256];
        let mut remaining = len;
        while remaining > 0 {
            let take = remaining.min(ZERO_CHUNK.len());
            dst.put_slice(&ZERO_CHUNK[..take]);
            remaining -= take;
        }
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

        // Expand buffer if necessary (fills with zeros).
        if end > prev {
            Self::append_zeros(&mut writable, end - prev);
        }

        // Copy the provided data into the buffer.
        writable.as_mut()[start..end].copy_from_slice(data.as_ref());
        self.len = writable.len();
        self.data = writable.freeze();

        true
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
    use prometheus_client::registry::Registry;

    #[test]
    fn test_tip_append() {
        let mut registry = Registry::default();
        let pool = crate::BufferPool::new(crate::BufferPoolConfig::for_storage(), &mut registry);
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
    fn test_tip_resize() {
        let mut registry = Registry::default();
        let pool = crate::BufferPool::new(crate::BufferPoolConfig::for_storage(), &mut registry);
        let mut buffer = Buffer::new(50, 100, pool);
        buffer.append(&[1, 2, 3]);
        assert_eq!(buffer.size(), 53);

        // Resize the buffer to correspond to a blob resized to size 60. The returned buffer should
        // match exactly what we'd expect to be returned by `take` since 60 is greater than the
        // current size of 53.
        let resized = buffer.resize(60).unwrap();
        assert_eq!(resized.0.as_ref(), &[1, 2, 3]);
        assert_eq!(resized.1, 50);
        assert_eq!(buffer.size(), 60);
        assert!(buffer.take().is_none());

        buffer.append(&[4, 5, 6]);
        assert_eq!(buffer.size(), 63);

        // Resize the buffer down to size 61.
        assert!(buffer.resize(61).is_none());
        assert_eq!(buffer.size(), 61);
        let taken = buffer.take().unwrap();
        assert_eq!(taken.0.as_ref(), &[4]);
        assert_eq!(taken.1, 60);
        assert_eq!(buffer.size(), 61);

        buffer.append(&[7, 8, 9]);

        // Resize the buffer prior to the current offset of 61. This should simply reset the buffer
        // at the new size.
        assert!(buffer.resize(59).is_none());
        assert_eq!(buffer.size(), 59);
        assert!(buffer.take().is_none());
        assert_eq!(buffer.size(), 59);
    }

    #[test]
    fn test_tip_first_merge_from_empty() {
        let mut registry = Registry::default();
        let pool = crate::BufferPool::new(crate::BufferPoolConfig::for_storage(), &mut registry);
        let mut buffer = Buffer::new(0, 16, pool);
        assert!(buffer.data.is_empty());

        assert!(buffer.merge(b"abc", 0));
        assert_eq!(buffer.data.as_ref(), b"abc");
    }
}
