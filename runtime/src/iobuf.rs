//! Buffer types for I/O operations.
//!
//! - [`IoBuf`]: Immutable byte buffer
//! - [`IoBufMut`]: Mutable byte buffer
//! - [`IoBufs`]: Container for one or more immutable buffers

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{collections::VecDeque, ops::RangeBounds};

/// Immutable byte buffer.
///
/// Cloning is cheap and does not copy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IoBuf {
    inner: Bytes,
}

impl IoBuf {
    /// Number of bytes in the buffer.
    #[inline]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the buffer is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get raw pointer to the buffer data.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }

    /// Returns a slice of self for the provided range (zero-copy).
    #[inline]
    pub fn slice(&self, range: impl RangeBounds<usize>) -> Self {
        Self {
            inner: self.inner.slice(range),
        }
    }
}

impl AsRef<[u8]> for IoBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl Buf for IoBuf {
    #[inline]
    fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.inner.chunk()
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        self.inner.advance(cnt);
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        self.inner.copy_to_bytes(len)
    }
}

impl From<Bytes> for IoBuf {
    fn from(bytes: Bytes) -> Self {
        Self { inner: bytes }
    }
}

impl From<Vec<u8>> for IoBuf {
    fn from(vec: Vec<u8>) -> Self {
        Self {
            inner: Bytes::from(vec),
        }
    }
}

impl From<&[u8]> for IoBuf {
    fn from(slice: &[u8]) -> Self {
        Self {
            inner: Bytes::copy_from_slice(slice),
        }
    }
}

impl<const N: usize> From<[u8; N]> for IoBuf {
    fn from(array: [u8; N]) -> Self {
        Self::from(array.as_ref())
    }
}

/// Mutable byte buffer.
///
/// Use this to build or mutate payloads before freezing into `IoBuf`.
#[derive(Debug, Default)]
pub struct IoBufMut {
    inner: BytesMut,
}

impl IoBufMut {
    /// Create a buffer with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: BytesMut::with_capacity(capacity),
        }
    }

    /// Set the length of the buffer.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `len` bytes starting from the buffer's pointer
    /// have been initialized.
    #[inline]
    pub unsafe fn set_len(&mut self, len: usize) {
        self.inner.set_len(len);
    }

    /// Number of initialized bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Freeze into immutable `IoBuf`.
    #[inline]
    pub fn freeze(self) -> IoBuf {
        self.inner.freeze().into()
    }

    /// Returns the total capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Get raw mutable pointer.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }

    /// Extend with data from a slice.
    #[inline]
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.inner.extend_from_slice(data);
    }
}

impl AsRef<[u8]> for IoBufMut {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl AsMut<[u8]> for IoBufMut {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut()
    }
}

// SAFETY: Delegates to BytesMut which implements BufMut safely.
unsafe impl BufMut for IoBufMut {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.inner.remaining_mut()
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.inner.advance_mut(cnt);
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        self.inner.chunk_mut()
    }
}

impl From<Vec<u8>> for IoBufMut {
    fn from(vec: Vec<u8>) -> Self {
        Self::from(Bytes::from(vec))
    }
}

impl From<&[u8]> for IoBufMut {
    fn from(slice: &[u8]) -> Self {
        Self {
            inner: BytesMut::from(slice),
        }
    }
}

impl<const N: usize> From<[u8; N]> for IoBufMut {
    fn from(array: [u8; N]) -> Self {
        Self::from(array.as_ref())
    }
}

impl From<BytesMut> for IoBufMut {
    fn from(bytes: BytesMut) -> Self {
        Self { inner: bytes }
    }
}

impl From<Bytes> for IoBufMut {
    fn from(bytes: Bytes) -> Self {
        Self {
            inner: BytesMut::from(bytes),
        }
    }
}

impl From<IoBuf> for IoBufMut {
    fn from(buf: IoBuf) -> Self {
        Self::from(buf.inner)
    }
}

/// Container for one or more immutable buffers.
#[derive(Debug)]
pub enum IoBufs {
    /// Single buffer (common case, no VecDeque allocation).
    Single(IoBuf),
    /// Multiple buffers with read cursor.
    Chunked {
        bufs: VecDeque<IoBuf>,
        cursor: usize,
    },
}

impl Default for IoBufs {
    fn default() -> Self {
        Self::Single(IoBuf::default())
    }
}

impl IoBufs {
    /// Number of bytes remaining to read.
    #[inline]
    pub fn len(&self) -> usize {
        self.remaining()
    }

    /// Whether there are no bytes remaining.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Whether this contains a single contiguous buffer.
    ///
    /// When true, `chunk()` returns all remaining bytes.
    #[inline]
    pub const fn is_single(&self) -> bool {
        matches!(self, Self::Single(_))
    }

    /// Prepend a buffer to the front.
    pub fn prepend(&mut self, buf: IoBuf) {
        match std::mem::take(self) {
            Self::Single(existing) => {
                *self = Self::Chunked {
                    bufs: VecDeque::from([buf, existing]),
                    cursor: 0,
                };
            }
            Self::Chunked { mut bufs, cursor } => {
                bufs.push_front(buf);
                *self = Self::Chunked { bufs, cursor };
            }
        }
    }

    /// Append a buffer to the back.
    pub fn append(&mut self, buf: IoBuf) {
        match std::mem::take(self) {
            Self::Single(existing) => {
                *self = Self::Chunked {
                    bufs: VecDeque::from([existing, buf]),
                    cursor: 0,
                };
            }
            Self::Chunked { mut bufs, cursor } => {
                bufs.push_back(buf);
                *self = Self::Chunked { bufs, cursor };
            }
        }
    }

    /// Coalesce all remaining bytes into a single contiguous buffer.
    ///
    /// Zero-copy if only one buffer with all remaining data.
    #[inline]
    pub fn coalesce(mut self) -> IoBuf {
        IoBuf::from(self.copy_to_bytes(self.remaining()))
    }
}

impl Buf for IoBufs {
    fn remaining(&self) -> usize {
        match self {
            Self::Single(buf) => buf.remaining(),
            Self::Chunked { bufs, cursor } => {
                bufs.iter().skip(*cursor).map(|b| b.remaining()).sum()
            }
        }
    }

    fn chunk(&self) -> &[u8] {
        match self {
            Self::Single(buf) => buf.chunk(),
            Self::Chunked { bufs, cursor } => {
                for buf in bufs.iter().skip(*cursor) {
                    if buf.remaining() > 0 {
                        return buf.chunk();
                    }
                }
                &[]
            }
        }
    }

    fn advance(&mut self, mut cnt: usize) {
        let (bufs, cursor) = match self {
            Self::Single(buf) => return buf.advance(cnt),
            Self::Chunked { bufs, cursor } => (bufs, cursor),
        };

        while cnt > 0 && *cursor < bufs.len() {
            let avail = bufs[*cursor].remaining();
            if cnt >= avail {
                bufs[*cursor].advance(avail);
                *cursor += 1;
                cnt -= avail;
            } else {
                bufs[*cursor].advance(cnt);
                return;
            }
        }
        assert!(cnt == 0, "cannot advance past end of buffer");
    }

    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        let (bufs, cursor) = match self {
            Self::Single(buf) => return buf.copy_to_bytes(len),
            Self::Chunked { bufs, cursor } => (bufs, cursor),
        };

        // Skip exhausted buffers
        while *cursor < bufs.len() && bufs[*cursor].remaining() == 0 {
            *cursor += 1;
        }

        // If the first buffer has all the data we need, use its optimized copy_to_bytes
        if *cursor < bufs.len() && bufs[*cursor].remaining() >= len {
            return bufs[*cursor].copy_to_bytes(len);
        }

        // Otherwise, copy from multiple buffers
        let total: usize = bufs.iter().skip(*cursor).map(|b| b.remaining()).sum();
        assert!(total >= len, "IoBufs::copy_to_bytes: not enough data");

        let mut result = BytesMut::with_capacity(len);
        let mut remaining = len;
        while remaining > 0 && *cursor < bufs.len() {
            let avail = bufs[*cursor].remaining();
            let to_copy = remaining.min(avail);
            result.extend_from_slice(&bufs[*cursor].chunk()[..to_copy]);
            bufs[*cursor].advance(to_copy);
            if bufs[*cursor].remaining() == 0 {
                *cursor += 1;
            }
            remaining -= to_copy;
        }

        result.freeze()
    }
}

impl From<IoBuf> for IoBufs {
    fn from(buf: IoBuf) -> Self {
        Self::Single(buf)
    }
}

impl From<Bytes> for IoBufs {
    fn from(bytes: Bytes) -> Self {
        Self::from(IoBuf::from(bytes))
    }
}

impl From<BytesMut> for IoBufs {
    fn from(bytes: BytesMut) -> Self {
        Self::from(IoBuf::from(bytes.freeze()))
    }
}

impl From<Vec<u8>> for IoBufs {
    fn from(vec: Vec<u8>) -> Self {
        Self::from(IoBuf::from(vec))
    }
}

impl From<&[u8]> for IoBufs {
    fn from(slice: &[u8]) -> Self {
        Self::from(IoBuf::from(slice))
    }
}

impl<const N: usize> From<[u8; N]> for IoBufs {
    fn from(array: [u8; N]) -> Self {
        Self::from(array.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iobuf_clone_doesnt_copy() {
        let buf1 = IoBuf::from(vec![1u8; 1000]);
        let buf2 = buf1.clone();
        assert_eq!(buf1.as_ref().as_ptr(), buf2.as_ref().as_ptr());
    }

    #[test]
    fn test_iobuf_buf_trait() {
        let mut buf = IoBuf::from(b"hello".as_slice());
        assert_eq!(buf.remaining(), 5);
        buf.advance(2);
        assert_eq!(buf.chunk(), b"llo");
    }

    #[test]
    fn test_iobuf_empty() {
        let buf = IoBuf::from(Vec::new());
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_iobuf_equality() {
        let buf1 = IoBuf::from(b"hello".as_slice());
        let buf2 = IoBuf::from(b"hello".as_slice());
        let buf3 = IoBuf::from(b"world".as_slice());
        assert_eq!(buf1, buf2);
        assert_ne!(buf1, buf3);
    }

    #[test]
    fn test_iobuf_copy_to_bytes() {
        let mut buf = IoBuf::from(b"hello world".as_slice());
        let first = buf.copy_to_bytes(5);
        assert_eq!(&first[..], b"hello");
        assert_eq!(buf.remaining(), 6);
        let rest = buf.copy_to_bytes(6);
        assert_eq!(&rest[..], b" world");
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_iobuf_slice() {
        let buf = IoBuf::from(b"hello world".as_slice());

        let slice = buf.slice(..5);
        assert_eq!(slice.as_ref(), b"hello");

        let slice = buf.slice(6..);
        assert_eq!(slice.as_ref(), b"world");

        let slice = buf.slice(3..8);
        assert_eq!(slice.as_ref(), b"lo wo");

        let slice = buf.slice(5..5);
        assert!(slice.is_empty());

        assert_eq!(buf.as_ref(), b"hello world");
    }

    #[test]
    #[should_panic(expected = "cannot advance")]
    fn test_iobuf_advance_past_end() {
        let mut buf = IoBuf::from(b"hello".as_slice());
        buf.advance(10);
    }

    #[test]
    fn test_iobuf_mut_build_and_freeze() {
        let mut buf = IoBufMut::with_capacity(100);
        buf.put_slice(b"hello");
        assert_eq!(buf.as_ref(), b"hello");

        buf.extend_from_slice(b" world");
        assert_eq!(buf.as_ref(), b"hello world");

        let frozen = buf.freeze();
        assert_eq!(frozen.as_ref(), b"hello world");
    }

    #[test]
    fn test_iobuf_mut_capacity() {
        let buf = IoBufMut::with_capacity(100);
        assert!(buf.capacity() >= 100);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_iobuf_mut_set_len() {
        let mut buf = IoBufMut::with_capacity(10);
        assert_eq!(buf.len(), 0);
        // SAFETY: 5 bytes were written
        unsafe {
            std::ptr::write_bytes(buf.as_mut_ptr(), 0xAB, 5);
            buf.set_len(5);
        }
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_ref(), &[0xAB; 5]);
    }

    #[test]
    fn test_iobufs_empty() {
        let bufs = IoBufs::from(Vec::new());
        assert!(bufs.is_empty());
        assert_eq!(bufs.len(), 0);
    }

    #[test]
    fn test_iobufs_single_buffer() {
        let mut bufs = IoBufs::from(b"hello world".as_slice());
        assert!(bufs.is_single());

        assert_eq!(bufs.remaining(), 11);
        assert_eq!(bufs.chunk(), b"hello world");

        bufs.advance(6);
        assert_eq!(bufs.remaining(), 5);
        assert_eq!(bufs.chunk(), b"world");

        let bytes = bufs.copy_to_bytes(5);
        assert_eq!(&bytes[..], b"world");
        assert_eq!(bufs.remaining(), 0);
    }

    #[test]
    fn test_iobufs_is_single() {
        let bufs = IoBufs::from(b"hello".as_slice());
        assert!(bufs.is_single());

        let mut bufs = IoBufs::from(b"world".as_slice());
        assert!(bufs.is_single());
        bufs.prepend(IoBuf::from(b"hello ".as_slice()));
        assert!(!bufs.is_single());

        let mut bufs = IoBufs::from(b"hello".as_slice());
        assert!(bufs.is_single());
        bufs.append(IoBuf::from(b" world".as_slice()));
        assert!(!bufs.is_single());

        let bufs = IoBufs::default();
        assert!(bufs.is_single());
    }

    #[test]
    fn test_iobufs_prepend_and_append() {
        let mut bufs = IoBufs::from(b"middle".as_slice());
        bufs.prepend(IoBuf::from(b"start ".as_slice()));
        bufs.append(IoBuf::from(b" end".as_slice()));
        assert_eq!(bufs.coalesce().as_ref(), b"start middle end");
    }

    #[test]
    fn test_iobufs_coalesce_after_advance() {
        let mut bufs = IoBufs::from(IoBuf::from(b"hello".as_slice()));
        bufs.append(IoBuf::from(b" world".as_slice()));

        assert_eq!(bufs.len(), 11);

        bufs.advance(3);
        assert_eq!(bufs.len(), 8);

        assert_eq!(bufs.coalesce().as_ref(), b"lo world");
    }

    #[test]
    fn test_iobufs_with_empty_buffers() {
        let mut bufs = IoBufs::default();
        bufs.append(IoBuf::from(b"hello".as_slice()));
        bufs.append(IoBuf::default());
        bufs.append(IoBuf::from(b" ".as_slice()));
        bufs.append(IoBuf::default());
        bufs.append(IoBuf::from(b"world".as_slice()));

        assert_eq!(bufs.len(), 11);
        assert_eq!(bufs.chunk(), b"hello");

        bufs.advance(5);
        assert_eq!(bufs.chunk(), b" ");

        bufs.advance(1);
        assert_eq!(bufs.chunk(), b"world");

        assert_eq!(bufs.coalesce().as_ref(), b"world");
    }

    #[test]
    fn test_iobufs_copy_to_bytes_single_buffer() {
        let mut bufs = IoBufs::from(b"hello world".as_slice());
        let first = bufs.copy_to_bytes(5);
        assert_eq!(&first[..], b"hello");
        assert_eq!(bufs.remaining(), 6);
    }

    #[test]
    fn test_iobufs_copy_to_bytes_multiple_buffers() {
        let mut bufs = IoBufs::from(b"hello".as_slice());
        bufs.prepend(IoBuf::from(b"say ".as_slice()));

        let first = bufs.copy_to_bytes(7);
        assert_eq!(&first[..], b"say hel");
        assert_eq!(bufs.remaining(), 2);

        let rest = bufs.copy_to_bytes(2);
        assert_eq!(&rest[..], b"lo");
    }

    #[test]
    fn test_iobufs_copy_to_bytes_edge_cases() {
        // Empty first buffer
        let mut iobufs = IoBufs::from(IoBuf::from(b"".as_slice()));
        iobufs.append(IoBuf::from(b"hello".as_slice()));
        let bytes = iobufs.copy_to_bytes(5);
        assert_eq!(&bytes[..], b"hello");

        // Exact buffer boundary
        let mut iobufs = IoBufs::from(IoBuf::from(b"hello".as_slice()));
        iobufs.append(IoBuf::from(b"world".as_slice()));

        let bytes = iobufs.copy_to_bytes(5);
        assert_eq!(&bytes[..], b"hello");
        assert_eq!(iobufs.remaining(), 5);

        let bytes = iobufs.copy_to_bytes(5);
        assert_eq!(&bytes[..], b"world");
        assert_eq!(iobufs.remaining(), 0);
    }

    #[test]
    #[should_panic(expected = "cannot advance past end of buffer")]
    fn test_iobufs_advance_past_end() {
        let mut bufs = IoBufs::from(b"hel".as_slice());
        bufs.append(IoBuf::from(b"lo".as_slice()));
        bufs.advance(10);
    }

    #[test]
    #[should_panic(expected = "not enough data")]
    fn test_iobufs_copy_to_bytes_past_end() {
        let mut bufs = IoBufs::from(b"hel".as_slice());
        bufs.append(IoBuf::from(b"lo".as_slice()));
        bufs.copy_to_bytes(10);
    }

    #[test]
    fn test_iobufs_matches_bytes_chain() {
        let b1 = Bytes::from_static(b"hello");
        let b2 = Bytes::from_static(b" ");
        let b3 = Bytes::from_static(b"world");

        let mut chain = b1.clone().chain(b2.clone()).chain(b3.clone());
        let mut iobufs = IoBufs::from(IoBuf::from(b1.clone()));
        iobufs.append(IoBuf::from(b2.clone()));
        iobufs.append(IoBuf::from(b3.clone()));

        assert_eq!(chain.remaining(), iobufs.remaining());
        assert_eq!(chain.chunk(), iobufs.chunk());

        chain.advance(3);
        iobufs.advance(3);
        assert_eq!(chain.remaining(), iobufs.remaining());
        assert_eq!(chain.chunk(), iobufs.chunk());

        chain.advance(3);
        iobufs.advance(3);
        assert_eq!(chain.remaining(), iobufs.remaining());
        assert_eq!(chain.chunk(), iobufs.chunk());

        // Test copy_to_bytes
        let mut chain = b1.clone().chain(b2.clone()).chain(b3.clone());
        let mut iobufs = IoBufs::from(IoBuf::from(b1));
        iobufs.append(IoBuf::from(b2));
        iobufs.append(IoBuf::from(b3));

        assert_eq!(chain.copy_to_bytes(3), iobufs.copy_to_bytes(3));
        assert_eq!(chain.copy_to_bytes(4), iobufs.copy_to_bytes(4));
        assert_eq!(
            chain.copy_to_bytes(chain.remaining()),
            iobufs.copy_to_bytes(iobufs.remaining())
        );
        assert_eq!(chain.remaining(), 0);
        assert_eq!(iobufs.remaining(), 0);
    }
}
