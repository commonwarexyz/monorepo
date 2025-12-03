use std::num::NonZeroUsize;

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
    pub(super) fn new(size: u64, capacity: NonZeroUsize) -> Self {
        Self {
            data: Vec::with_capacity(capacity.get()),
            offset: size,
            capacity: capacity.get(),
        }
    }

    /// Returns the current logical size of the blob including any buffered data.
    pub(super) const fn size(&self) -> u64 {
        self.offset + self.data.len() as u64
    }

    /// Returns true if the buffer is empty.
    pub(super) const fn is_empty(&self) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZUsize;

    #[test]
    fn test_tip_append() {
        let mut buffer = Buffer::new(50, NZUsize!(100));
        assert_eq!(buffer.size(), 50);
        assert!(buffer.is_empty());
        assert_eq!(buffer.take(), None);

        // Add some data to the buffer.
        assert!(!buffer.append(&[1, 2, 3]));
        assert_eq!(buffer.size(), 53);
        assert!(!buffer.is_empty());

        // Confirm `take()` works as intended.
        assert_eq!(buffer.take(), Some((vec![1, 2, 3], 50)));
        assert_eq!(buffer.size(), 53);
        assert_eq!(buffer.take(), None);

        // Fill the buffer to capacity.
        let mut buf = vec![42; 100];
        assert!(!buffer.append(&buf));
        assert_eq!(buffer.size(), 153);

        // Add one more byte, which should push it over capacity. The byte should still be appended.
        assert!(buffer.append(&[43]));
        assert_eq!(buffer.size(), 154);
        buf.push(43);
        assert_eq!(buffer.take(), Some((buf, 53)));
    }

    #[test]
    fn test_tip_resize() {
        let mut buffer = Buffer::new(50, NZUsize!(100));
        buffer.append(&[1, 2, 3]);
        assert_eq!(buffer.size(), 53);

        // Resize the buffer to correspond to a blob resized to size 60. The returned buffer should
        // match exactly what we'd expect to be returned by `take` since 60 is greater than the
        // current size of 53.
        assert_eq!(buffer.resize(60), Some((vec![1, 2, 3], 50)));
        assert_eq!(buffer.size(), 60);
        assert_eq!(buffer.take(), None);

        buffer.append(&[4, 5, 6]);
        assert_eq!(buffer.size(), 63);

        // Resize the buffer down to size 61.
        assert_eq!(buffer.resize(61), None);
        assert_eq!(buffer.size(), 61);
        assert_eq!(buffer.take(), Some((vec![4], 60)));
        assert_eq!(buffer.size(), 61);

        buffer.append(&[7, 8, 9]);

        // Resize the buffer prior to the current offset of 61. This should simply reset the buffer
        // at the new size.
        assert_eq!(buffer.resize(59), None);
        assert_eq!(buffer.size(), 59);
        assert_eq!(buffer.take(), None);
        assert_eq!(buffer.size(), 59);
    }
}
