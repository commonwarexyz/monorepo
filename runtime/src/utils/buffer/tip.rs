use crate::{BufferPool, IoBufMut};

/// A buffer for caching data written to the tip of a blob.
///
/// The buffer always represents data at the "tip" of the logical blob, starting at `offset` and
/// extending for `data.len()` bytes.
pub(super) struct Buffer {
    /// The data to be written to the blob.
    pub(super) data: IoBufMut,

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
    pub(super) fn new(offset: u64, capacity: usize, pool: BufferPool) -> Self {
        let data = pool.alloc(capacity);
        Self {
            data,
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
    pub(super) fn resize(&mut self, len: u64) -> Option<(IoBufMut, u64)> {
        // Handle case where the buffer is empty.
        if self.is_empty() {
            self.offset = len;
            return None;
        }

        // Handle case where there is some data in the buffer.
        if len >= self.size() {
            let replacement = self.pool.alloc(self.capacity);
            let previous = (std::mem::replace(&mut self.data, replacement), self.offset);
            self.offset = len;
            Some(previous)
        } else if len >= self.offset {
            self.data.truncate((len - self.offset) as usize);
            None
        } else {
            self.data.clear();
            self.offset = len;
            None
        }
    }

    /// Returns the buffered data and its blob offset, or returns `None` if the buffer is already
    /// empty.
    ///
    /// The buffer is reset to the empty state with an updated offset positioned at the end of the
    /// logical blob.
    pub(super) fn take(&mut self) -> Option<(IoBufMut, u64)> {
        if self.is_empty() {
            return None;
        }
        let replacement = self.pool.alloc(self.capacity);
        let buf = std::mem::replace(&mut self.data, replacement);
        let offset = self.offset;
        self.offset += buf.len() as u64;
        Some((buf, offset))
    }

    /// Extract and return any data from the blob range `[offset,offset+buf.len)` that is contained
    /// in the buffer, returning the number of bytes that could not be extracted. (Any bytes
    /// that could not be extracted must reside at the beginning of the range.)
    ///
    /// # Panics
    ///
    /// Panics if the end offset of the requested data falls outside the range of the logical blob.
    pub(super) fn extract(&self, buf: &mut [u8], offset: u64) -> usize {
        let end_offset = offset
            .checked_add(buf.len() as u64)
            .expect("end_offset overflow");
        assert!(end_offset <= self.size());
        if end_offset <= self.offset {
            // Range does not overlap with the buffer.
            return buf.len();
        }

        let (start, remaining) = if offset < self.offset {
            // Some data is before the buffer.
            (0, (self.offset - offset) as usize)
        } else {
            // Can read entirely from the buffer.
            ((offset - self.offset) as usize, 0)
        };

        let end = start + buf.len() - remaining;
        assert!(end <= self.data.len());

        // Copy the requested buffered data into the appropriate part of the user-provided slice.
        buf[remaining..].copy_from_slice(&self.data.as_ref()[start..end]);

        remaining
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

        // Expand buffer if necessary (fills with zeros).
        if end > self.data.len() {
            if end > self.data.capacity() {
                // Grow backing buffer while preserving existing bytes.
                let mut grown = self.pool.alloc(end);
                // SAFETY: We immediately initialize all bytes in 0..current_len.
                unsafe { grown.set_len(self.data.len()) };
                grown.as_mut()[..self.data.len()].copy_from_slice(self.data.as_ref());
                self.data = grown;
            }
            let prev = self.data.len();
            // SAFETY: We initialize the newly exposed bytes below.
            unsafe { self.data.set_len(end) };
            self.data.as_mut()[prev..end].fill(0);
        }

        // Copy the provided data into the buffer.
        self.data.as_mut()[start..end].copy_from_slice(data.as_ref());

        true
    }

    /// Appends the provided `data` to the buffer, and returns `true` if the buffer is over capacity
    /// after the append.
    ///
    /// If the buffer is above capacity, the caller is responsible for using `take` to bring it back
    /// under. Further appends are safe, but will continue growing the buffer beyond its capacity.
    pub(super) fn append(&mut self, data: &[u8]) -> bool {
        let start = self.data.len();
        let end = start + data.len();
        if end > self.data.capacity() {
            let mut grown = self.pool.alloc(end);
            // SAFETY: We initialize the copied range right away.
            unsafe { grown.set_len(start) };
            grown.as_mut()[..start].copy_from_slice(self.data.as_ref());
            self.data = grown;
        }
        // SAFETY: We initialize the appended range right away.
        unsafe { self.data.set_len(end) };
        self.data.as_mut()[start..end].copy_from_slice(data);

        self.over_capacity()
    }

    /// Whether the buffer is over capacity and should be taken & flushed to the underlying blob.
    fn over_capacity(&self) -> bool {
        self.data.len() > self.capacity
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
            self.data.clear();
            return;
        }
        self.data.as_mut().copy_within(len..current_len, 0);
        self.data.truncate(current_len - len);
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
}
