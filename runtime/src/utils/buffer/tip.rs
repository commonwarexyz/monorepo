use crate::{BufferPool, IoBuf, IoBufMut};
use bytes::BufMut;

/// A buffer for caching data written to the tip of a blob.
///
/// The buffer always represents data at the "tip" of the logical blob, starting at `offset` and
/// extending for `data.len()` bytes.
pub(super) struct Buffer {
    /// The data to be written to the blob.
    pub(super) data: IoBuf,

    /// The offset in the blob where the buffered data starts.
    ///
    /// This represents the logical position in the blob where `data[0]` would be written. The
    /// buffer is maintained at the "tip" to support efficient size calculation and appends.
    pub(super) offset: u64,

    /// The maximum size of the buffer.
    pub(super) capacity: usize,

    /// Whether this buffer should allow new data.
    // TODO(#2371): Use a distinct state-type for immutable vs immutable.
    pub(super) immutable: bool,

    /// Pool used to allocate backing buffers.
    pool: BufferPool,
}

impl Buffer {
    /// Creates a new buffer with the provided `offset` and `capacity`.
    ///
    /// The backing buffer starts empty and is allocated lazily on first write.
    pub(super) fn new(offset: u64, capacity: usize, pool: BufferPool) -> Self {
        Self {
            data: IoBuf::default(),
            offset,
            capacity,
            immutable: false,
            pool,
        }
    }

    /// Returns the current logical size of the blob including any buffered data.
    pub(super) fn size(&self) -> u64 {
        self.offset + self.data.len() as u64
    }

    /// Returns true if the buffer is empty.
    pub(super) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Adjust the buffer to correspond to resizing the logical blob to size `len`.
    ///
    /// If the new size is greater than the current size, the existing buffer is returned (to be
    /// flushed to the underlying blob) and the buffer is reset to the empty state with an updated
    /// offset positioned at the end of the logical blob. (The "existing buffer" is what would have
    /// been returned by a call to [Self::take].)
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
            let previous = (std::mem::take(&mut self.data), self.offset);
            self.offset = len;
            Some(previous)
        } else if len >= self.offset {
            self.data = self.data.slice(..(len - self.offset) as usize);
            None
        } else {
            self.data = IoBuf::default();
            self.offset = len;
            None
        }
    }

    /// Returns the buffered data and its blob offset, or returns `None` if the buffer is already
    /// empty.
    ///
    /// The buffer is reset to the empty state with an updated offset positioned at the end of the
    /// logical blob.
    pub(super) fn take(&mut self) -> Option<(IoBuf, u64)> {
        if self.is_empty() {
            return None;
        }
        let buf = std::mem::take(&mut self.data);
        let offset = self.offset;
        self.offset += buf.len() as u64;
        Some((buf, offset))
    }

    fn growth_target(&self, current: usize, needed: usize) -> usize {
        if current == 0 {
            return self.capacity.max(needed);
        }
        let mut next = current.max(self.capacity);
        while next < needed {
            next = next.checked_mul(2).unwrap_or(needed);
        }
        next
    }

    fn mutable_for_write(&mut self, needed: usize) -> IoBufMut {
        let current = std::mem::take(&mut self.data);
        let current_len = current.len();
        match current.try_into_mut() {
            Ok(writable) => {
                if writable.capacity() >= needed {
                    return writable;
                }
                let target = self.growth_target(writable.capacity(), needed);
                let mut grown = self.pool.alloc(target);
                grown.put_slice(writable.as_ref());
                grown
            }
            Err(shared) => {
                let target = self.growth_target(current_len, needed);
                let mut grown = self.pool.alloc(target);
                grown.put_slice(shared.as_ref());
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

        let mut writable = self.mutable_for_write(end);
        let prev = writable.len();

        // Expand buffer if necessary (fills with zeros).
        if end > prev {
            Self::append_zeros(&mut writable, end - prev);
        }

        // Copy the provided data into the buffer.
        writable.as_mut()[start..end].copy_from_slice(data.as_ref());
        self.data = writable.freeze();

        true
    }

    /// Appends the provided `data` to the buffer, and returns `true` if the buffer is over capacity
    /// after the append.
    ///
    /// If the buffer is above capacity, the caller is responsible for using `take` to bring it back
    /// under. Further appends are safe, but will continue growing the buffer beyond its capacity.
    pub(super) fn append(&mut self, data: &[u8]) -> bool {
        let end = self.data.len() + data.len();
        let mut writable = self.mutable_for_write(end);
        writable.put_slice(data);
        let over_capacity = writable.len() > self.capacity;
        self.data = writable.freeze();
        over_capacity
    }

    /// Removes `len` leading bytes from the buffered data while preserving the remaining suffix.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds current buffer length.
    pub(super) fn drop_prefix(&mut self, len: usize) {
        assert!(len <= self.data.len());
        if len == 0 {
            return;
        }
        let current_len = self.data.len();
        if len == current_len {
            self.data = IoBuf::default();
            return;
        }
        self.data = self.data.slice(len..current_len);
    }

    /// Clears buffered data while preserving offset.
    pub(super) fn clear(&mut self) {
        self.data = IoBuf::default();
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
    fn test_tip_lazy_allocation_on_first_merge() {
        let mut registry = Registry::default();
        let pool = crate::BufferPool::new(crate::BufferPoolConfig::for_storage(), &mut registry);
        let mut buffer = Buffer::new(0, 16, pool);
        assert!(buffer.data.is_empty());

        assert!(buffer.merge(b"abc", 0));
        assert_eq!(buffer.data.as_ref(), b"abc");
    }
}
