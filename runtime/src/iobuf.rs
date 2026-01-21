//! Buffer types for I/O operations.
//!
//! - [`IoBuf`]: Immutable byte buffer
//! - [`IoBufMut`]: Mutable byte buffer
//! - [`IoBufs`]: Container for one or more immutable buffers
//! - [`IoBufsMut`]: Container for one or more mutable buffers

use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_codec::{util::at_least, EncodeSize, Error, RangeCfg, Read, Write};
use std::{collections::VecDeque, ops::RangeBounds};

/// Immutable byte buffer.
///
/// Cloning is cheap and does not copy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IoBuf {
    inner: Bytes,
}

impl IoBuf {
    /// Create a buffer by copying data from a slice.
    ///
    /// Use this when you have a non-static `&[u8]` that needs to be converted to an
    /// `IoBuf`. For static slices, prefer `IoBuf::from(b"...")` which is zero-copy.
    pub fn copy_from_slice(data: &[u8]) -> Self {
        Self {
            inner: Bytes::copy_from_slice(data),
        }
    }

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

impl PartialEq<[u8]> for IoBuf {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.as_ref() == other
    }
}

impl PartialEq<&[u8]> for IoBuf {
    #[inline]
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_ref() == *other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for IoBuf {
    #[inline]
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_ref() == other
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for IoBuf {
    #[inline]
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_ref() == *other
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

impl<const N: usize> From<&'static [u8; N]> for IoBuf {
    fn from(array: &'static [u8; N]) -> Self {
        Self {
            inner: Bytes::from_static(array),
        }
    }
}

impl From<&'static [u8]> for IoBuf {
    fn from(slice: &'static [u8]) -> Self {
        Self {
            inner: Bytes::from_static(slice),
        }
    }
}

impl From<IoBuf> for Vec<u8> {
    fn from(buf: IoBuf) -> Self {
        Self::from(buf.inner)
    }
}

impl From<IoBuf> for Bytes {
    fn from(buf: IoBuf) -> Self {
        buf.inner
    }
}

impl Write for IoBuf {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.len().write(buf);
        buf.put_slice(self.as_ref());
    }
}

impl EncodeSize for IoBuf {
    #[inline]
    fn encode_size(&self) -> usize {
        self.len().encode_size() + self.len()
    }
}

impl Read for IoBuf {
    type Cfg = RangeCfg<usize>;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, Error> {
        let len = usize::read_cfg(buf, range)?;
        at_least(buf, len)?;
        Ok(Self::from(buf.copy_to_bytes(len)))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for IoBuf {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let len = u.arbitrary_len::<u8>()?;
        let data: Vec<u8> = u.arbitrary_iter()?.take(len).collect::<Result<_, _>>()?;
        Ok(Self::from(data))
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

    /// Create a buffer of `len` bytes, all initialized to zero.
    ///
    /// Unlike `with_capacity`, this sets both capacity and length to `len`,
    /// making the entire buffer immediately usable for read operations
    /// (e.g., `file.read_exact`).
    pub fn zeroed(len: usize) -> Self {
        Self {
            inner: BytesMut::zeroed(len),
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

    /// Resizes the buffer to `new_len`, filling new bytes with `value`.
    ///
    /// If `new_len` is less than the current length, the buffer is truncated.
    /// If `new_len` is greater, the buffer is extended with `value` bytes.
    #[inline]
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.inner.resize(new_len, value);
    }

    /// Truncates the buffer to `len` bytes.
    ///
    /// If `len` is greater than the current length, this has no effect.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    /// Clears the buffer, setting its length to 0.
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
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

impl PartialEq<[u8]> for IoBufMut {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.as_ref() == other
    }
}

impl PartialEq<&[u8]> for IoBufMut {
    #[inline]
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_ref() == *other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for IoBufMut {
    #[inline]
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_ref() == other
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for IoBufMut {
    #[inline]
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_ref() == *other
    }
}

impl Buf for IoBufMut {
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

impl<const N: usize> From<&[u8; N]> for IoBufMut {
    fn from(array: &[u8; N]) -> Self {
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
    /// Multiple buffers.
    Chunked(VecDeque<IoBuf>),
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
                *self = Self::Chunked(VecDeque::from([buf, existing]));
            }
            Self::Chunked(mut bufs) => {
                bufs.push_front(buf);
                *self = Self::Chunked(bufs);
            }
        }
    }

    /// Append a buffer to the back.
    pub fn append(&mut self, buf: IoBuf) {
        match std::mem::take(self) {
            Self::Single(existing) => {
                *self = Self::Chunked(VecDeque::from([existing, buf]));
            }
            Self::Chunked(mut bufs) => {
                bufs.push_back(buf);
                *self = Self::Chunked(bufs);
            }
        }
    }

    /// Coalesce all remaining bytes into a single contiguous buffer.
    ///
    /// Zero-copy if only one buffer with all remaining data.
    #[inline]
    pub fn coalesce(mut self) -> IoBuf {
        match self {
            Self::Single(buf) => buf,
            Self::Chunked(_) => self.copy_to_bytes(self.remaining()).into(),
        }
    }
}

impl Buf for IoBufs {
    fn remaining(&self) -> usize {
        match self {
            Self::Single(buf) => buf.remaining(),
            Self::Chunked(bufs) => bufs
                .iter()
                .map(|b| b.remaining())
                .fold(0, usize::saturating_add),
        }
    }

    fn chunk(&self) -> &[u8] {
        match self {
            Self::Single(buf) => buf.chunk(),
            Self::Chunked(bufs) => {
                for buf in bufs.iter() {
                    if buf.remaining() > 0 {
                        return buf.chunk();
                    }
                }
                &[]
            }
        }
    }

    fn advance(&mut self, mut cnt: usize) {
        let bufs = match self {
            Self::Single(buf) => return buf.advance(cnt),
            Self::Chunked(bufs) => bufs,
        };

        while cnt > 0 {
            let front = bufs.front_mut().expect("cannot advance past end of buffer");
            let avail = front.remaining();
            if cnt >= avail {
                bufs.pop_front();
                cnt -= avail;
            } else {
                front.advance(cnt);
                return;
            }
        }
    }

    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        let bufs = match self {
            Self::Single(buf) => return buf.copy_to_bytes(len),
            Self::Chunked(bufs) => bufs,
        };

        // Remove exhausted buffers from front
        while bufs.front().is_some_and(|b| b.remaining() == 0) {
            bufs.pop_front();
        }

        // If the first buffer has all the data we need, use its optimized copy_to_bytes
        if let Some(front) = bufs.front_mut() {
            if front.remaining() >= len {
                return front.copy_to_bytes(len);
            }
        }

        // Otherwise, copy from multiple buffers
        let total: usize = bufs
            .iter()
            .map(|b| b.remaining())
            .fold(0, usize::saturating_add);

        assert!(total >= len, "IoBufs::copy_to_bytes: not enough data");

        let mut result = BytesMut::with_capacity(len);
        let mut remaining = len;
        while remaining > 0 {
            let front = bufs.front_mut().unwrap();
            let avail = front.remaining();
            let to_copy = remaining.min(avail);
            result.extend_from_slice(&front.chunk()[..to_copy]);
            front.advance(to_copy);
            if front.remaining() == 0 {
                bufs.pop_front();
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

impl From<IoBufMut> for IoBufs {
    fn from(buf: IoBufMut) -> Self {
        Self::Single(buf.freeze())
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

impl<const N: usize> From<&'static [u8; N]> for IoBufs {
    fn from(array: &'static [u8; N]) -> Self {
        Self::from(IoBuf::from(array))
    }
}

impl From<&'static [u8]> for IoBufs {
    fn from(slice: &'static [u8]) -> Self {
        Self::from(IoBuf::from(slice))
    }
}

/// Container for one or more mutable buffers.
#[derive(Debug)]
pub enum IoBufsMut {
    /// Single buffer (common case, no VecDeque allocation).
    Single(IoBufMut),
    /// Multiple buffers for vectored reads.
    Chunked(VecDeque<IoBufMut>),
}

impl Default for IoBufsMut {
    fn default() -> Self {
        Self::Single(IoBufMut::default())
    }
}

impl IoBufsMut {
    /// Total initialized length across all buffers.
    pub fn len(&self) -> usize {
        match self {
            Self::Single(buf) => buf.len(),
            Self::Chunked(bufs) => bufs.iter().map(|b| b.len()).fold(0, usize::saturating_add),
        }
    }

    /// Whether all buffers are empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this contains a single contiguous buffer.
    #[inline]
    pub const fn is_single(&self) -> bool {
        matches!(self, Self::Single(_))
    }

    /// Freeze into immutable `IoBufs`.
    pub fn freeze(self) -> IoBufs {
        match self {
            Self::Single(buf) => IoBufs::Single(buf.freeze()),
            Self::Chunked(bufs) => {
                let mut result = IoBufs::default();
                for buf in bufs {
                    result.append(buf.freeze());
                }
                result
            }
        }
    }

    /// Coalesce all buffers into a single contiguous `IoBufMut`.
    ///
    /// Zero-copy if only one buffer. Copies if multiple buffers.
    pub fn coalesce(self) -> IoBufMut {
        match self {
            Self::Single(buf) => buf,
            Self::Chunked(bufs) => {
                let total_len: usize = bufs.iter().map(|b| b.len()).fold(0, usize::saturating_add);
                let mut result = IoBufMut::with_capacity(total_len);
                for buf in bufs {
                    result.inner.extend_from_slice(buf.as_ref());
                }
                result
            }
        }
    }

    /// Copy data from a slice into the buffers.
    ///
    /// Panics if the slice length doesn't match the total buffer length.
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        assert_eq!(
            src.len(),
            self.len(),
            "source slice length must match buffer length"
        );
        match self {
            Self::Single(buf) => buf.as_mut().copy_from_slice(src),
            Self::Chunked(bufs) => {
                let mut offset = 0;
                for buf in bufs.iter_mut() {
                    let len = buf.len();
                    buf.as_mut().copy_from_slice(&src[offset..offset + len]);
                    offset += len;
                }
            }
        }
    }
}

impl Buf for IoBufsMut {
    fn remaining(&self) -> usize {
        match self {
            Self::Single(buf) => buf.remaining(),
            Self::Chunked(bufs) => bufs
                .iter()
                .map(|b| b.remaining())
                .fold(0, usize::saturating_add),
        }
    }

    fn chunk(&self) -> &[u8] {
        match self {
            Self::Single(buf) => buf.chunk(),
            Self::Chunked(bufs) => {
                for buf in bufs.iter() {
                    if buf.remaining() > 0 {
                        return buf.chunk();
                    }
                }
                &[]
            }
        }
    }

    fn advance(&mut self, mut cnt: usize) {
        let bufs = match self {
            Self::Single(buf) => return buf.advance(cnt),
            Self::Chunked(bufs) => bufs,
        };

        while cnt > 0 {
            let front = bufs.front_mut().expect("cannot advance past end of buffer");
            let avail = front.remaining();
            if cnt >= avail {
                bufs.pop_front();
                cnt -= avail;
            } else {
                front.advance(cnt);
                return;
            }
        }
    }
}

// SAFETY: Delegates to IoBufMut which implements BufMut safely.
unsafe impl BufMut for IoBufsMut {
    #[inline]
    fn remaining_mut(&self) -> usize {
        match self {
            Self::Single(buf) => buf.remaining_mut(),
            Self::Chunked(bufs) => bufs
                .iter()
                .map(|b| b.remaining_mut())
                .fold(0, usize::saturating_add),
        }
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        match self {
            Self::Single(buf) => buf.advance_mut(cnt),
            Self::Chunked(bufs) => {
                let mut remaining = cnt;
                for buf in bufs.iter_mut() {
                    let avail = buf.remaining_mut();
                    if remaining <= avail {
                        buf.advance_mut(remaining);
                        return;
                    }
                    buf.advance_mut(avail);
                    remaining -= avail;
                }
                panic!("advance_mut overflow");
            }
        }
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        match self {
            Self::Single(buf) => buf.chunk_mut(),
            Self::Chunked(bufs) => {
                for buf in bufs.iter_mut() {
                    if buf.remaining_mut() > 0 {
                        return buf.chunk_mut();
                    }
                }
                bytes::buf::UninitSlice::new(&mut [])
            }
        }
    }
}

impl From<IoBufMut> for IoBufsMut {
    fn from(buf: IoBufMut) -> Self {
        Self::Single(buf)
    }
}

impl From<Vec<u8>> for IoBufsMut {
    fn from(vec: Vec<u8>) -> Self {
        Self::Single(IoBufMut::from(vec))
    }
}

impl From<BytesMut> for IoBufsMut {
    fn from(bytes: BytesMut) -> Self {
        Self::Single(IoBufMut::from(bytes))
    }
}

impl From<Vec<IoBufMut>> for IoBufsMut {
    fn from(bufs: Vec<IoBufMut>) -> Self {
        if bufs.len() == 1 {
            Self::Single(bufs.into_iter().next().unwrap())
        } else {
            Self::Chunked(bufs.into())
        }
    }
}

impl<const N: usize> From<[u8; N]> for IoBufsMut {
    fn from(array: [u8; N]) -> Self {
        Self::Single(IoBufMut::from(array))
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
    fn test_iobuf_copy_from_slice() {
        let data = vec![1u8, 2, 3, 4, 5];
        let buf = IoBuf::copy_from_slice(&data);
        assert_eq!(buf, [1, 2, 3, 4, 5]);
        assert_eq!(buf.len(), 5);

        drop(data);
        assert_eq!(buf, [1, 2, 3, 4, 5]);

        let empty = IoBuf::copy_from_slice(&[]);
        assert!(empty.is_empty());
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
    fn test_iobuf_equality_with_slice() {
        let buf = IoBuf::from(b"hello".as_slice());
        assert_eq!(buf, *b"hello");
        assert_eq!(buf, b"hello");
        assert_ne!(buf, *b"world");
        assert_ne!(buf, b"world");
    }

    #[test]
    fn test_iobuf_codec_roundtrip() {
        use commonware_codec::{Decode, Encode, RangeCfg};

        let cfg: RangeCfg<usize> = (0..=1024).into();

        let original = IoBuf::from(b"hello world".as_slice());
        let encoded = original.encode();
        let decoded = IoBuf::decode_cfg(encoded.as_ref(), &cfg).unwrap();
        assert_eq!(original, decoded);

        let empty = IoBuf::default();
        let encoded = empty.encode();
        let decoded = IoBuf::decode_cfg(encoded.as_ref(), &cfg).unwrap();
        assert_eq!(empty, decoded);

        let large_cfg: RangeCfg<usize> = (0..=20000).into();
        let large = IoBuf::from(vec![42u8; 10000]);
        let encoded = large.encode();
        let decoded = IoBuf::decode_cfg(encoded.as_ref(), &large_cfg).unwrap();
        assert_eq!(large, decoded);
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
        assert_eq!(slice, b"hello");

        let slice = buf.slice(6..);
        assert_eq!(slice, b"world");

        let slice = buf.slice(3..8);
        assert_eq!(slice, b"lo wo");

        let slice = buf.slice(5..5);
        assert!(slice.is_empty());

        assert_eq!(buf, b"hello world");
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
        assert_eq!(buf, b"hello");

        buf.put_slice(b" world");
        assert_eq!(buf, b"hello world");

        let frozen = buf.freeze();
        assert_eq!(frozen, b"hello world");
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
        assert_eq!(buf, &[0xAB; 5]);
    }

    #[test]
    fn test_iobuf_mut_zeroed() {
        let mut buf = IoBufMut::zeroed(10);
        assert_eq!(buf.len(), 10);
        assert!(buf.capacity() >= 10);
        assert_eq!(buf, &[0u8; 10]);

        // Can write into it via as_mut
        buf.as_mut()[..5].copy_from_slice(b"hello");
        assert_eq!(&buf.as_ref()[..5], b"hello");
        assert_eq!(&buf.as_ref()[5..], &[0u8; 5]);

        // Freeze and convert to Vec
        let frozen = buf.freeze();
        assert_eq!(frozen.len(), 10);
        let vec: Vec<u8> = frozen.into();
        assert_eq!(&vec[..5], b"hello");
        assert_eq!(&vec[5..], &[0u8; 5]);
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
        assert_eq!(bufs.coalesce(), b"start middle end");
    }

    #[test]
    fn test_iobufs_coalesce_after_advance() {
        let mut bufs = IoBufs::from(IoBuf::from(b"hello".as_slice()));
        bufs.append(IoBuf::from(b" world".as_slice()));

        assert_eq!(bufs.len(), 11);

        bufs.advance(3);
        assert_eq!(bufs.len(), 8);

        assert_eq!(bufs.coalesce(), b"lo world");
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

        assert_eq!(bufs.coalesce(), b"world");
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

    #[test]
    fn test_iobufsmut_single() {
        let buf = IoBufMut::from(b"hello".as_ref());
        let bufs = IoBufsMut::from(buf);
        assert!(bufs.is_single());
        assert_eq!(bufs.len(), 5);
        assert_eq!(bufs.chunk(), b"hello");
    }

    #[test]
    fn test_iobufsmut_chunked() {
        let buf1 = IoBufMut::from(b"hello".as_ref());
        let buf2 = IoBufMut::from(b" world".as_ref());
        let bufs = IoBufsMut::from(vec![buf1, buf2]);
        assert!(!bufs.is_single());
        assert_eq!(bufs.len(), 11);
        assert_eq!(bufs.chunk(), b"hello");
    }

    #[test]
    fn test_iobufsmut_freeze() {
        let buf = IoBufMut::from(b"hello".as_ref());
        let bufs = IoBufsMut::from(buf);
        let frozen = bufs.freeze();
        assert!(frozen.is_single());
        assert_eq!(frozen.chunk(), b"hello");
    }

    #[test]
    fn test_iobufsmut_coalesce() {
        let buf1 = IoBufMut::from(b"hello".as_ref());
        let buf2 = IoBufMut::from(b" world".as_ref());
        let bufs = IoBufsMut::from(vec![buf1, buf2]);
        let coalesced = bufs.coalesce();
        assert_eq!(coalesced, b"hello world");
    }

    #[test]
    fn test_iobufsmut_from_vec_single() {
        // A Vec with one element should become Single
        let buf = IoBufMut::from(b"test".as_ref());
        let bufs = IoBufsMut::from(vec![buf]);
        assert!(bufs.is_single());
    }

    #[test]
    fn test_iobufsmut_default() {
        let bufs = IoBufsMut::default();
        assert!(bufs.is_single());
        assert!(bufs.is_empty());
        assert_eq!(bufs.len(), 0);
    }

    #[test]
    fn test_iobufsmut_from_array() {
        let bufs = IoBufsMut::from([1u8, 2, 3, 4, 5]);
        assert!(bufs.is_single());
        assert_eq!(bufs.len(), 5);
        assert_eq!(bufs.chunk(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_iobufmut_buf_trait() {
        let mut buf = IoBufMut::from(b"hello world".as_ref());
        assert_eq!(buf.remaining(), 11);
        assert_eq!(buf.chunk(), b"hello world");

        buf.advance(6);
        assert_eq!(buf.remaining(), 5);
        assert_eq!(buf.chunk(), b"world");

        buf.advance(5);
        assert_eq!(buf.remaining(), 0);
        assert!(buf.chunk().is_empty());
    }

    #[test]
    #[should_panic(expected = "cannot advance")]
    fn test_iobufmut_advance_past_end() {
        let mut buf = IoBufMut::from(b"hello".as_ref());
        buf.advance(10);
    }

    #[test]
    fn test_iobufsmut_buf_trait_single() {
        let mut bufs = IoBufsMut::from(IoBufMut::from(b"hello world".as_ref()));
        assert_eq!(bufs.remaining(), 11);
        assert_eq!(bufs.chunk(), b"hello world");

        bufs.advance(6);
        assert_eq!(bufs.remaining(), 5);
        assert_eq!(bufs.chunk(), b"world");
    }

    #[test]
    fn test_iobufsmut_buf_trait_chunked() {
        let buf1 = IoBufMut::from(b"hello".as_ref());
        let buf2 = IoBufMut::from(b" ".as_ref());
        let buf3 = IoBufMut::from(b"world".as_ref());
        let mut bufs = IoBufsMut::from(vec![buf1, buf2, buf3]);

        assert_eq!(bufs.remaining(), 11);
        assert_eq!(bufs.chunk(), b"hello");

        // Advance within first buffer
        bufs.advance(3);
        assert_eq!(bufs.remaining(), 8);
        assert_eq!(bufs.chunk(), b"lo");

        // Advance past first buffer (should pop_front)
        bufs.advance(2);
        assert_eq!(bufs.remaining(), 6);
        assert_eq!(bufs.chunk(), b" ");

        // Advance exactly one buffer
        bufs.advance(1);
        assert_eq!(bufs.remaining(), 5);
        assert_eq!(bufs.chunk(), b"world");

        // Advance to end
        bufs.advance(5);
        assert_eq!(bufs.remaining(), 0);
    }

    #[test]
    fn test_iobufsmut_advance_across_multiple_buffers() {
        let buf1 = IoBufMut::from(b"ab".as_ref());
        let buf2 = IoBufMut::from(b"cd".as_ref());
        let buf3 = IoBufMut::from(b"ef".as_ref());
        let mut bufs = IoBufsMut::from(vec![buf1, buf2, buf3]);

        // Advance across two buffers at once
        bufs.advance(5);
        assert_eq!(bufs.remaining(), 1);
        assert_eq!(bufs.chunk(), b"f");
    }

    #[test]
    #[should_panic(expected = "cannot advance past end of buffer")]
    fn test_iobufsmut_advance_past_end() {
        let buf1 = IoBufMut::from(b"hello".as_ref());
        let buf2 = IoBufMut::from(b" world".as_ref());
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);
        bufs.advance(20);
    }

    #[test]
    fn test_iobufsmut_bufmut_trait_single() {
        let mut bufs = IoBufsMut::from(IoBufMut::with_capacity(20));
        // BytesMut can grow, so remaining_mut is very large
        assert!(bufs.remaining_mut() > 1000);

        bufs.put_slice(b"hello");
        assert_eq!(bufs.chunk(), b"hello");
        assert_eq!(bufs.len(), 5);

        bufs.put_slice(b" world");
        assert_eq!(bufs.coalesce(), b"hello world");
    }

    #[test]
    fn test_iobufsmut_zeroed_write() {
        // Use zeroed buffers which have a fixed length
        let bufs = IoBufsMut::from(IoBufMut::zeroed(20));
        assert_eq!(bufs.len(), 20);

        // Can write using as_mut on coalesced buffer
        let mut coalesced = bufs.coalesce();
        coalesced.as_mut()[..5].copy_from_slice(b"hello");
        assert_eq!(&coalesced.as_ref()[..5], b"hello");
    }

    #[test]
    fn test_iobufsmut_bufmut_put_slice() {
        // Test writing across multiple buffers
        let buf1 = IoBufMut::with_capacity(5);
        let buf2 = IoBufMut::with_capacity(6);
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        // Write data
        bufs.put_slice(b"hello");
        bufs.put_slice(b" world");
        assert_eq!(bufs.coalesce(), b"hello world");
    }

    #[test]
    fn test_iobufs_advance_drains_buffers() {
        let mut bufs = IoBufs::from(IoBuf::from(b"hello".as_slice()));
        bufs.append(IoBuf::from(b" ".as_slice()));
        bufs.append(IoBuf::from(b"world".as_slice()));

        // Advance exactly past first buffer
        bufs.advance(5);
        assert_eq!(bufs.remaining(), 6);
        assert_eq!(bufs.chunk(), b" ");

        // Advance across multiple buffers
        bufs.advance(4);
        assert_eq!(bufs.remaining(), 2);
        assert_eq!(bufs.chunk(), b"ld");
    }

    #[test]
    fn test_iobufs_advance_exactly_to_boundary() {
        let mut bufs = IoBufs::from(IoBuf::from(b"abc".as_slice()));
        bufs.append(IoBuf::from(b"def".as_slice()));

        // Advance exactly to first buffer boundary
        bufs.advance(3);
        assert_eq!(bufs.remaining(), 3);
        assert_eq!(bufs.chunk(), b"def");

        // Advance exactly to end
        bufs.advance(3);
        assert_eq!(bufs.remaining(), 0);
    }

    #[test]
    fn test_iobufsmut_with_empty_buffers() {
        let buf1 = IoBufMut::from(b"hello".as_ref());
        let buf2 = IoBufMut::default();
        let buf3 = IoBufMut::from(b" world".as_ref());
        let mut bufs = IoBufsMut::from(vec![buf1, buf2, buf3]);

        assert_eq!(bufs.remaining(), 11);
        assert_eq!(bufs.chunk(), b"hello");

        // Advance past first buffer
        bufs.advance(5);
        // Empty buffer should be skipped
        assert_eq!(bufs.chunk(), b" world");
        assert_eq!(bufs.remaining(), 6);
    }

    #[test]
    fn test_iobufsmut_coalesce_after_advance() {
        let buf1 = IoBufMut::from(b"hello".as_ref());
        let buf2 = IoBufMut::from(b" world".as_ref());
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        bufs.advance(3);
        assert_eq!(bufs.coalesce(), b"lo world");
    }

    #[test]
    fn test_iobufsmut_copy_to_bytes() {
        let buf1 = IoBufMut::from(b"hello".as_ref());
        let buf2 = IoBufMut::from(b" world".as_ref());
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        let first = bufs.copy_to_bytes(7);
        assert_eq!(&first[..], b"hello w");
        assert_eq!(bufs.remaining(), 4);

        let rest = bufs.copy_to_bytes(4);
        assert_eq!(&rest[..], b"orld");
        assert_eq!(bufs.remaining(), 0);
    }

    #[test]
    fn test_iobufsmut_copy_from_slice_single() {
        let mut bufs = IoBufsMut::from(IoBufMut::zeroed(11));
        bufs.copy_from_slice(b"hello world");
        assert_eq!(bufs.coalesce(), b"hello world");
    }

    #[test]
    fn test_iobufsmut_copy_from_slice_chunked() {
        let buf1 = IoBufMut::zeroed(5);
        let buf2 = IoBufMut::zeroed(6);
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        bufs.copy_from_slice(b"hello world");

        // Verify each chunk was filled correctly
        match &bufs {
            IoBufsMut::Chunked(chunks) => {
                assert_eq!(chunks[0], b"hello");
                assert_eq!(chunks[1], b" world");
            }
            _ => panic!("expected Chunked variant"),
        }
    }

    #[test]
    #[should_panic(expected = "source slice length must match buffer length")]
    fn test_iobufsmut_copy_from_slice_wrong_length() {
        let mut bufs = IoBufsMut::from(IoBufMut::zeroed(5));
        bufs.copy_from_slice(b"hello world"); // 11 bytes into 5-byte buffer
    }

    #[test]
    fn test_iobufsmut_matches_bytesmut_chain() {
        use bytes::BytesMut;

        // Create three BytesMut with capacity
        let mut bm1 = BytesMut::with_capacity(5);
        let mut bm2 = BytesMut::with_capacity(6);
        let mut bm3 = BytesMut::with_capacity(7);

        // Create matching IoBufsMut
        let mut iobufs = IoBufsMut::from(vec![
            IoBufMut::with_capacity(5),
            IoBufMut::with_capacity(6),
            IoBufMut::with_capacity(7),
        ]);

        // Test initial chunk_mut length matches (spare capacity)
        let chain_len = (&mut bm1)
            .chain_mut(&mut bm2)
            .chain_mut(&mut bm3)
            .chunk_mut()
            .len();
        let iobufs_len = iobufs.chunk_mut().len();
        assert_eq!(chain_len, iobufs_len);

        // Write some data
        (&mut bm1)
            .chain_mut(&mut bm2)
            .chain_mut(&mut bm3)
            .put_slice(b"hel");
        iobufs.put_slice(b"hel");

        // Verify chunk_mut matches after partial write
        let chain_len = (&mut bm1)
            .chain_mut(&mut bm2)
            .chain_mut(&mut bm3)
            .chunk_mut()
            .len();
        let iobufs_len = iobufs.chunk_mut().len();
        assert_eq!(chain_len, iobufs_len);

        // Write more data
        (&mut bm1)
            .chain_mut(&mut bm2)
            .chain_mut(&mut bm3)
            .put_slice(b"lo world!");
        iobufs.put_slice(b"lo world!");

        // Verify chunk_mut matches after more writes
        let chain_len = (&mut bm1)
            .chain_mut(&mut bm2)
            .chain_mut(&mut bm3)
            .chunk_mut()
            .len();
        let iobufs_len = iobufs.chunk_mut().len();
        assert_eq!(chain_len, iobufs_len);

        // Verify final content matches
        let frozen = iobufs.freeze().coalesce();
        let mut chain_content = bm1.to_vec();
        chain_content.extend_from_slice(&bm2);
        chain_content.extend_from_slice(&bm3);
        assert_eq!(frozen, chain_content.as_slice());
        assert_eq!(frozen, b"hello world!");
    }

    #[test]
    fn test_iobufsmut_buf_matches_bytes_chain() {
        // Create pre-filled Bytes buffers
        let mut b1 = Bytes::from_static(b"hello");
        let mut b2 = Bytes::from_static(b" world");
        let b3 = Bytes::from_static(b"!");

        // Create matching IoBufsMut
        let mut iobufs = IoBufsMut::from(vec![
            IoBufMut::from(b"hello".as_ref()),
            IoBufMut::from(b" world".as_ref()),
            IoBufMut::from(b"!".as_ref()),
        ]);

        // Test Buf::remaining matches
        let chain_remaining = b1.clone().chain(b2.clone()).chain(b3.clone()).remaining();
        assert_eq!(chain_remaining, iobufs.remaining());

        // Test Buf::chunk matches
        let chain_chunk = b1
            .clone()
            .chain(b2.clone())
            .chain(b3.clone())
            .chunk()
            .to_vec();
        assert_eq!(chain_chunk, iobufs.chunk().to_vec());

        // Advance and test again
        b1.advance(3);
        iobufs.advance(3);

        let chain_remaining = b1.clone().chain(b2.clone()).chain(b3.clone()).remaining();
        assert_eq!(chain_remaining, iobufs.remaining());

        let chain_chunk = b1
            .clone()
            .chain(b2.clone())
            .chain(b3.clone())
            .chunk()
            .to_vec();
        assert_eq!(chain_chunk, iobufs.chunk().to_vec());

        // Advance past first buffer boundary into second
        b1.advance(2);
        iobufs.advance(2);

        let chain_remaining = b1.clone().chain(b2.clone()).chain(b3.clone()).remaining();
        assert_eq!(chain_remaining, iobufs.remaining());

        // Now we should be in the second buffer
        let chain_chunk = b1
            .clone()
            .chain(b2.clone())
            .chain(b3.clone())
            .chunk()
            .to_vec();
        assert_eq!(chain_chunk, iobufs.chunk().to_vec());

        // Advance past second buffer boundary into third
        b2.advance(6);
        iobufs.advance(6);

        let chain_remaining = b1.clone().chain(b2.clone()).chain(b3.clone()).remaining();
        assert_eq!(chain_remaining, iobufs.remaining());

        // Now we should be in the third buffer
        let chain_chunk = b1.chain(b2).chain(b3).chunk().to_vec();
        assert_eq!(chain_chunk, iobufs.chunk().to_vec());

        // Test copy_to_bytes
        let b1 = Bytes::from_static(b"hello");
        let b2 = Bytes::from_static(b" world");
        let b3 = Bytes::from_static(b"!");
        let mut iobufs = IoBufsMut::from(vec![
            IoBufMut::from(b"hello".as_ref()),
            IoBufMut::from(b" world".as_ref()),
            IoBufMut::from(b"!".as_ref()),
        ]);

        let chain_bytes = b1.chain(b2).chain(b3).copy_to_bytes(8);
        let iobufs_bytes = iobufs.copy_to_bytes(8);
        assert_eq!(chain_bytes, iobufs_bytes);
        assert_eq!(chain_bytes.as_ref(), b"hello wo");
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::IoBuf;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<IoBuf>
        }
    }
}
