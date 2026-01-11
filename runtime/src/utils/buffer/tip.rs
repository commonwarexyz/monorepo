use bytes::Bytes;
use std::collections::VecDeque;

/// A buffer for caching data written to the tip of a blob.
///
/// The buffer always represents data at the "tip" of the logical blob, starting at `offset` and
/// extending for the total length of all chunks.
///
/// Data is stored as a sequence of immutable `Bytes` chunks, enabling zero-copy reads via
/// `extract_bytes`. Each `append` call creates a new chunk.
pub(super) struct Buffer {
    /// The data chunks to be written to the blob, in order.
    pub(super) chunks: VecDeque<Bytes>,

    /// Total bytes across all chunks.
    pub(super) total_len: usize,

    /// The offset in the blob where the buffered data starts.
    ///
    /// This represents the logical position in the blob where the first chunk would be written.
    /// The buffer is maintained at the "tip" to support efficient size calculation and appends.
    pub(super) offset: u64,

    /// The maximum total size of the buffer.
    pub(super) capacity: usize,

    /// Whether this buffer should allow new data.
    // TODO(#2371): Use a distinct state-type for immutable vs immutable.
    pub(super) immutable: bool,
}

impl Buffer {
    /// Creates a new buffer with the provided `offset` and `capacity`.
    pub(super) const fn new(offset: u64, capacity: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            total_len: 0,
            offset,
            capacity,
            immutable: false,
        }
    }

    /// Creates a new buffer with initial data from a `Vec<u8>`.
    pub(super) fn with_data(data: Vec<u8>, offset: u64, capacity: usize) -> Self {
        let total_len = data.len();
        let chunks = if data.is_empty() {
            VecDeque::new()
        } else {
            VecDeque::from([Bytes::from(data)])
        };
        Self {
            chunks,
            total_len,
            offset,
            capacity,
            immutable: false,
        }
    }

    /// Collects all chunks into a contiguous `Vec<u8>`.
    ///
    /// This is used when we need a contiguous view of the buffer data, such as
    /// for computing CRCs or caching pages.
    pub(super) fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_len);
        for chunk in &self.chunks {
            result.extend_from_slice(chunk);
        }
        result
    }

    /// Attempts to merge a write at the given offset into this buffer.
    ///
    /// Returns `true` if the write was merged, `false` otherwise.
    ///
    /// A write can be merged if:
    /// - The write falls entirely within or at the end of the buffer's range
    /// - The resulting buffer doesn't exceed capacity
    pub(super) fn merge(&mut self, data: &[u8], write_offset: u64) -> bool {
        if data.is_empty() {
            return true;
        }

        let write_end = write_offset.saturating_add(data.len() as u64);
        let buffer_end = self.size();

        // Check if write starts within or at the end of the buffer
        if write_offset < self.offset || write_offset > buffer_end {
            return false;
        }

        // Check capacity: if extending, ensure we don't exceed capacity
        let new_end = write_end.max(buffer_end);
        let new_len = (new_end - self.offset) as usize;
        if new_len > self.capacity {
            return false;
        }

        // If write is at the end (append), just add a new chunk
        if write_offset == buffer_end {
            self.chunks.push_back(Bytes::copy_from_slice(data));
            self.total_len += data.len();
            return true;
        }

        // Write overlaps with existing data - need to merge
        // Collect existing chunks, apply the write, and store as single chunk
        let mut buf = self.to_vec();
        let start_in_buf = (write_offset - self.offset) as usize;
        let end_in_buf = start_in_buf + data.len();

        // Extend buf if the write goes beyond current data
        if end_in_buf > buf.len() {
            buf.resize(end_in_buf, 0);
        }

        // Apply the write
        buf[start_in_buf..end_in_buf].copy_from_slice(data);

        // Replace chunks with single merged chunk
        self.chunks.clear();
        self.total_len = buf.len();
        self.chunks.push_back(Bytes::from(buf));

        true
    }

    /// Shrinks the internal storage to fit the current data.
    pub(super) fn shrink_to_fit(&mut self) {
        self.chunks.shrink_to_fit();
    }

    /// Replaces the buffer contents with new data, clearing existing chunks.
    pub(super) fn set_data(&mut self, data: Vec<u8>) {
        self.chunks.clear();
        self.total_len = data.len();
        if !data.is_empty() {
            self.chunks.push_back(Bytes::from(data));
        }
    }

    /// Removes the first `count` bytes from the buffer, updating the offset accordingly.
    pub(super) fn drain(&mut self, count: usize) {
        if count == 0 {
            return;
        }

        let mut remaining = count;
        while remaining > 0 {
            let Some(front) = self.chunks.front_mut() else {
                break;
            };

            if remaining < front.len() {
                // Partial drain of the front chunk
                *front = front.slice(remaining..);
                remaining = 0;
            } else {
                // Drain entire front chunk
                remaining -= front.len();
                self.chunks.pop_front();
            }
        }

        self.total_len -= count;
        self.offset += count as u64;
    }

    /// Returns the current logical size of the blob including any buffered data.
    pub(super) const fn size(&self) -> u64 {
        self.offset + self.total_len as u64
    }

    /// Returns true if the buffer is empty.
    pub(super) const fn is_empty(&self) -> bool {
        self.total_len == 0
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
    pub(super) fn resize(&mut self, len: u64) -> Option<(VecDeque<Bytes>, u64)> {
        // Handle case where the buffer is empty.
        if self.is_empty() {
            self.offset = len;
            return None;
        }

        // Handle case where there is some data in the buffer.
        if len >= self.size() {
            let previous = (std::mem::take(&mut self.chunks), self.offset);
            self.total_len = 0;
            self.offset = len;
            Some(previous)
        } else if len >= self.offset {
            // Truncate to the new size
            let target_len = (len - self.offset) as usize;
            self.truncate_to(target_len);
            None
        } else {
            self.chunks.clear();
            self.total_len = 0;
            self.offset = len;
            None
        }
    }

    /// Truncate the buffer to contain at most `target_len` bytes.
    fn truncate_to(&mut self, target_len: usize) {
        let mut remaining = target_len;
        let mut new_chunks = VecDeque::new();

        for chunk in self.chunks.drain(..) {
            if remaining == 0 {
                break;
            }
            if chunk.len() <= remaining {
                remaining -= chunk.len();
                new_chunks.push_back(chunk);
            } else {
                // Slice this chunk to fit
                new_chunks.push_back(chunk.slice(..remaining));
                remaining = 0;
            }
        }

        self.chunks = new_chunks;
        self.total_len = target_len;
    }

    /// Returns the buffered data and its blob offset, or returns `None` if the buffer is already
    /// empty.
    ///
    /// The buffer is reset to the empty state with an updated offset positioned at the end of the
    /// logical blob.
    pub(super) fn take(&mut self) -> Option<(VecDeque<Bytes>, u64)> {
        if self.is_empty() {
            return None;
        }
        let chunks = std::mem::take(&mut self.chunks);
        let offset = self.offset;
        self.offset += self.total_len as u64;
        self.total_len = 0;
        Some((chunks, offset))
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
        assert!(end <= self.total_len);

        // Copy the requested buffered data into the appropriate part of the user-provided slice.
        self.copy_range_to(&mut buf[remaining..], start, end - start);

        remaining
    }

    /// Copy `len` bytes starting at `start` offset within the buffer to `dest`.
    fn copy_range_to(&self, dest: &mut [u8], start: usize, len: usize) {
        let mut chunk_offset = 0;
        let mut dest_offset = 0;
        let end = start + len;

        for chunk in &self.chunks {
            let chunk_end = chunk_offset + chunk.len();

            // Skip chunks before the start
            if chunk_end <= start {
                chunk_offset = chunk_end;
                continue;
            }

            // Stop if we've copied everything
            if chunk_offset >= end {
                break;
            }

            // Calculate the overlap
            let copy_start = start.saturating_sub(chunk_offset);
            let copy_end = (end - chunk_offset).min(chunk.len());
            let copy_len = copy_end - copy_start;

            dest[dest_offset..dest_offset + copy_len].copy_from_slice(&chunk[copy_start..copy_end]);
            dest_offset += copy_len;
            chunk_offset = chunk_end;
        }
    }

    /// Appends the provided `data` to the buffer, and returns `true` if the buffer is over capacity
    /// after the append.
    ///
    /// If the buffer is above capacity, the caller is responsible for using `take` to bring it back
    /// under. Further appends are safe, but will continue growing the buffer beyond its capacity.
    pub(super) fn append(&mut self, data: &[u8]) -> bool {
        if !data.is_empty() {
            self.chunks.push_back(Bytes::copy_from_slice(data));
            self.total_len += data.len();
        }
        self.over_capacity()
    }

    /// Returns `Bytes` slices for any data in the requested range that overlaps with this buffer,
    /// along with the number of bytes before the buffer that must be read from disk.
    ///
    /// Returns `None` if the requested range does not overlap with the buffer at all.
    /// The returned `VecDeque<Bytes>` contains zero-copy slices of the buffered data.
    ///
    /// # Panics
    ///
    /// Panics if the end offset of the requested data falls outside the range of the logical blob.
    pub(super) fn extract_bytes(
        &self,
        offset: u64,
        len: usize,
    ) -> Option<(VecDeque<Bytes>, usize)> {
        let end_offset = offset.checked_add(len as u64).expect("end_offset overflow");
        assert!(end_offset <= self.size());

        if end_offset <= self.offset {
            // Range does not overlap with the buffer.
            return None;
        }

        let (start, bytes_before_buffer) = if offset < self.offset {
            // Some data is before the buffer.
            (0, (self.offset - offset) as usize)
        } else {
            // Can read entirely from the buffer.
            ((offset - self.offset) as usize, 0)
        };

        let end = start + len - bytes_before_buffer;
        assert!(end <= self.total_len);

        // Extract zero-copy slices from chunks
        let slices = self.slice_range(start, end - start);
        Some((slices, bytes_before_buffer))
    }

    /// Returns zero-copy `Bytes` slices covering `len` bytes starting at `start` within the buffer.
    fn slice_range(&self, start: usize, len: usize) -> VecDeque<Bytes> {
        let mut result = VecDeque::new();
        let mut chunk_offset = 0;
        let end = start + len;

        for chunk in &self.chunks {
            let chunk_end = chunk_offset + chunk.len();

            // Skip chunks before the start
            if chunk_end <= start {
                chunk_offset = chunk_end;
                continue;
            }

            // Stop if we've collected everything
            if chunk_offset >= end {
                break;
            }

            // Calculate the overlap and slice
            let slice_start = start.saturating_sub(chunk_offset);
            let slice_end = (end - chunk_offset).min(chunk.len());

            result.push_back(chunk.slice(slice_start..slice_end));
            chunk_offset = chunk_end;
        }

        result
    }

    /// Whether the buffer is over capacity and should be taken & flushed to the underlying blob.
    const fn over_capacity(&self) -> bool {
        self.total_len > self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tip_append() {
        let mut buffer = Buffer::new(50, 100);
        assert_eq!(buffer.size(), 50);
        assert!(buffer.is_empty());
        assert_eq!(buffer.take(), None);

        // Add some data to the buffer.
        assert!(!buffer.append(&[1, 2, 3]));
        assert_eq!(buffer.size(), 53);
        assert!(!buffer.is_empty());

        // Confirm `take()` works as intended.
        let (chunks, offset) = buffer.take().unwrap();
        assert_eq!(offset, 50);
        let data: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(data, vec![1, 2, 3]);
        assert_eq!(buffer.size(), 53);
        assert_eq!(buffer.take(), None);

        // Fill the buffer to capacity.
        let buf = vec![42; 100];
        assert!(!buffer.append(&buf));
        assert_eq!(buffer.size(), 153);

        // Add one more byte, which should push it over capacity. The byte should still be appended.
        assert!(buffer.append(&[43]));
        assert_eq!(buffer.size(), 154);
        let (chunks, offset) = buffer.take().unwrap();
        assert_eq!(offset, 53);
        let data: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        let mut expected = buf;
        expected.push(43);
        assert_eq!(data, expected);
    }

    #[test]
    fn test_tip_resize() {
        let mut buffer = Buffer::new(50, 100);
        buffer.append(&[1, 2, 3]);
        assert_eq!(buffer.size(), 53);

        // Resize the buffer to correspond to a blob resized to size 60. The returned buffer should
        // match exactly what we'd expect to be returned by `take` since 60 is greater than the
        // current size of 53.
        let (chunks, offset) = buffer.resize(60).unwrap();
        assert_eq!(offset, 50);
        let data: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(data, vec![1, 2, 3]);
        assert_eq!(buffer.size(), 60);
        assert_eq!(buffer.take(), None);

        buffer.append(&[4, 5, 6]);
        assert_eq!(buffer.size(), 63);

        // Resize the buffer down to size 61.
        assert_eq!(buffer.resize(61), None);
        assert_eq!(buffer.size(), 61);
        let (chunks, offset) = buffer.take().unwrap();
        assert_eq!(offset, 60);
        let data: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(data, vec![4]);
        assert_eq!(buffer.size(), 61);

        buffer.append(&[7, 8, 9]);

        // Resize the buffer prior to the current offset of 61. This should simply reset the buffer
        // at the new size.
        assert_eq!(buffer.resize(59), None);
        assert_eq!(buffer.size(), 59);
        assert_eq!(buffer.take(), None);
        assert_eq!(buffer.size(), 59);
    }

    #[test]
    fn test_extract_bytes_zero_copy() {
        let mut buffer = Buffer::new(0, 1000);

        // Append multiple chunks
        buffer.append(&[1, 2, 3, 4, 5]);
        buffer.append(&[6, 7, 8, 9, 10]);
        buffer.append(&[11, 12, 13, 14, 15]);

        // Extract from middle spanning chunks
        let (slices, bytes_before) = buffer.extract_bytes(3, 9).unwrap();
        assert_eq!(bytes_before, 0);

        // Verify the data
        let data: Vec<u8> = slices.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(data, vec![4, 5, 6, 7, 8, 9, 10, 11, 12]);
    }
}
