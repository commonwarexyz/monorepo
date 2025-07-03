/// A buffer for caching data written to the tip of a blob.
///
/// The buffer always represents data at the "tip" of the logical blob, starting at `offset` and
/// extending for `data.len()` bytes.
pub(super) struct Buffer {
    /// The data to be written to the blob.
    pub(super) data: Vec<u8>,

    /// The offset in the blob where the buffered data starts.
    ///
    /// This represents the logical position in the blob where `data[0]` would be written. The
    /// buffer is maintained at the "tip" to support efficient size calculation and appends.
    pub(super) offset: u64,

    /// The maximum size of the buffer.
    pub(super) capacity: usize,
}

impl Buffer {
    /// Creates a new buffer with the provided `size` and `capacity`.
    pub(super) fn new(size: u64, capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            offset: size,
            capacity,
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

    /// Resizes the buffer to the provided `len`.
    ///
    /// If the new size is greater than the current size, the existing buffer is
    /// returned (to be flushed to the underlying blob) and the buffer is reset to
    /// the empty state with an updated offset positioned at the end of the logical
    /// blob.
    ///
    /// If the new size is less than the current size (but still greater than current
    /// offset), the buffer is truncated to the new size.
    ///
    /// If the new size is less than the current offset, the buffer is reset to the empty
    /// state with an updated offset positioned at the end of the logical blob.
    pub(super) fn resize(&mut self, len: u64) -> Option<(Vec<u8>, u64)> {
        // Handle case where the buffer is empty.
        if self.is_empty() {
            self.offset = len;
            return None;
        }

        // Handle case where there is some data in the buffer.
        if len >= self.size() {
            let previous = (
                std::mem::replace(&mut self.data, Vec::with_capacity(self.capacity)),
                self.offset,
            );
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

    /// Returns the buffered data and its blob offset, or returns `None` if the buffer is
    /// already empty.
    ///
    /// The buffer is reset to the empty state with an updated offset positioned at
    /// the end of the logical blob.
    pub(super) fn take(&mut self) -> Option<(Vec<u8>, u64)> {
        if self.is_empty() {
            return None;
        }
        let buf = std::mem::replace(&mut self.data, Vec::with_capacity(self.capacity));
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
        assert!(offset + buf.len() as u64 <= self.size());
        if offset + buf.len() as u64 <= self.offset {
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
        buf[remaining..].copy_from_slice(&self.data[start..end]);

        remaining
    }

    /// Merges the provided `data` into the buffer at the provided blob `offset` if it falls
    /// entirely within the range `[buffer.offset,buffer.offset+capacity)`.
    ///
    /// The buffer will be expanded if necessary to accommodate the new data, and any gaps that
    /// may result are filled with zeros. Returns `true` if the merge was performed, otherwise the
    /// caller is responsible for continuing to manage the data.
    pub(super) fn merge(&mut self, data: &[u8], offset: u64) -> bool {
        let end_offset = offset + data.len() as u64;
        let can_merge_into_buffer =
            offset >= self.offset && end_offset <= self.offset + self.capacity as u64;
        if !can_merge_into_buffer {
            return false;
        }
        let start = (offset - self.offset) as usize;
        let end = start + data.len();

        // Expand buffer if necessary (fills with zeros).
        if end > self.data.len() {
            self.data.resize(end, 0);
        }

        // Copy the provided data into the buffer.
        self.data[start..end].copy_from_slice(data.as_ref());

        true
    }

    /// Appends the provided `data` to the buffer, and returns `true` if the buffer is now above
    /// capacity. If above capacity, the caller is responsible for using `take` to bring it back
    /// under.
    pub(super) fn append(&mut self, data: &[u8]) -> bool {
        self.data.extend_from_slice(data);
        self.data.len() > self.capacity
    }
}
