//! Buffer types for I/O operations.
//!
//! - [`IoBuf`]: Immutable byte buffer
//! - [`IoBufMut`]: Mutable byte buffer
//! - [`IoBufs`]: Container for one or more immutable buffers
//! - [`IoBufsMut`]: Container for one or more mutable buffers
//! - [`BufferPool`]: Pool of reusable, aligned buffers

mod pool;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_codec::{util::at_least, EncodeSize, Error, RangeCfg, Read, Write};
pub use pool::{BufferPool, BufferPoolConfig, PoolError};
use pool::{PooledBuf, PooledBufMut};
use std::{collections::VecDeque, io::IoSlice, ops::RangeBounds};

/// Immutable byte buffer.
///
/// Backed by either [`Bytes`] or a pooled aligned allocation.
///
/// Use this for immutable payloads. To build or mutate data, use
/// [`IoBufMut`] and then [`IoBufMut::freeze`].
///
/// For pooled-backed values, the underlying buffer is returned to the pool
/// when the final reference is dropped.
///
/// All `From<*> for IoBuf` implementations are guaranteed to be non-copy
/// conversions. Use [`IoBuf::copy_from_slice`] when an explicit copy from
/// borrowed data is required.
///
/// Cloning is cheap and does not copy underlying bytes.
#[derive(Clone, Debug)]
pub struct IoBuf {
    inner: IoBufInner,
}

#[derive(Clone, Debug)]
enum IoBufInner {
    Bytes(Bytes),
    Pooled(PooledBuf),
}

impl IoBuf {
    /// Create a buffer by copying data from a slice.
    ///
    /// Use this when you have a non-static `&[u8]` that needs to be converted to an
    /// [`IoBuf`]. For static slices, prefer [`IoBuf::from`] which is zero-copy.
    pub fn copy_from_slice(data: &[u8]) -> Self {
        Self {
            inner: IoBufInner::Bytes(Bytes::copy_from_slice(data)),
        }
    }

    /// Create a buffer from a pooled allocation.
    const fn from_pooled(pooled: PooledBuf) -> Self {
        Self {
            inner: IoBufInner::Pooled(pooled),
        }
    }

    /// Returns `true` if this buffer is tracked by a pool.
    ///
    /// Tracked buffers originate from [`BufferPool`] allocations and are
    /// returned to the pool when the final reference is dropped.
    ///
    /// Buffers backed by [`Bytes`], and untracked fallback allocations from
    /// [`BufferPool::alloc`], return `false`.
    #[inline]
    pub fn is_pooled(&self) -> bool {
        match &self.inner {
            IoBufInner::Bytes(_) => false,
            IoBufInner::Pooled(p) => p.is_tracked(),
        }
    }

    /// Number of bytes remaining in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.remaining()
    }

    /// Whether the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Get raw pointer to the buffer data.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        match &self.inner {
            IoBufInner::Bytes(b) => b.as_ptr(),
            IoBufInner::Pooled(p) => p.as_ptr(),
        }
    }

    /// Returns a slice of self for the provided range (zero-copy).
    ///
    /// For pooled buffers, empty ranges return an empty detached buffer
    /// ([`IoBuf::default`]) so the underlying pooled allocation is not retained.
    #[inline]
    pub fn slice(&self, range: impl RangeBounds<usize>) -> Self {
        match &self.inner {
            IoBufInner::Bytes(b) => Self {
                inner: IoBufInner::Bytes(b.slice(range)),
            },
            IoBufInner::Pooled(p) => p.slice(range).map_or_else(Self::default, Self::from_pooled),
        }
    }

    /// Splits the buffer into two at the given index.
    ///
    /// Afterwards `self` contains bytes `[at, len)`, and the returned [`IoBuf`]
    /// contains bytes `[0, at)`.
    ///
    /// This is an `O(1)` zero-copy operation.
    ///
    /// # Panics
    ///
    /// Panics if `at > len`.
    pub fn split_to(&mut self, at: usize) -> Self {
        if at == 0 {
            return Self::default();
        }

        if at == self.len() {
            return std::mem::take(self);
        }

        match &mut self.inner {
            IoBufInner::Bytes(b) => Self {
                inner: IoBufInner::Bytes(b.split_to(at)),
            },
            IoBufInner::Pooled(p) => Self::from_pooled(p.split_to(at)),
        }
    }

    /// Try to convert this buffer into [`IoBufMut`] without copying.
    ///
    /// Succeeds when `self` holds exclusive ownership of the backing storage
    /// and returns an [`IoBufMut`] with the same contents. Fails and returns
    /// `self` unchanged when ownership is shared.
    ///
    /// For [`Bytes`]-backed buffers, this matches [`Bytes::try_into_mut`]
    /// semantics: succeeds only for uniquely-owned full buffers, and always
    /// fails for [`Bytes::from_owner`] and [`Bytes::from_static`] buffers. For
    /// pooled buffers, this succeeds for any uniquely-owned view (including
    /// slices) and fails when shared.
    pub fn try_into_mut(self) -> Result<IoBufMut, Self> {
        match self.inner {
            IoBufInner::Bytes(bytes) => bytes
                .try_into_mut()
                .map(|mut_bytes| IoBufMut {
                    inner: IoBufMutInner::Bytes(mut_bytes),
                })
                .map_err(|bytes| Self {
                    inner: IoBufInner::Bytes(bytes),
                }),
            IoBufInner::Pooled(pooled) => pooled
                .try_into_mut()
                .map(|mut_pooled| IoBufMut {
                    inner: IoBufMutInner::Pooled(mut_pooled),
                })
                .map_err(|pooled| Self {
                    inner: IoBufInner::Pooled(pooled),
                }),
        }
    }
}

impl AsRef<[u8]> for IoBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match &self.inner {
            IoBufInner::Bytes(b) => b.as_ref(),
            IoBufInner::Pooled(p) => p.as_ref(),
        }
    }
}

impl Default for IoBuf {
    fn default() -> Self {
        Self {
            inner: IoBufInner::Bytes(Bytes::new()),
        }
    }
}

impl PartialEq for IoBuf {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for IoBuf {}

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
        match &self.inner {
            IoBufInner::Bytes(b) => b.remaining(),
            IoBufInner::Pooled(p) => p.remaining(),
        }
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        match &self.inner {
            IoBufInner::Bytes(b) => b.chunk(),
            IoBufInner::Pooled(p) => p.chunk(),
        }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        match &mut self.inner {
            IoBufInner::Bytes(b) => b.advance(cnt),
            IoBufInner::Pooled(p) => p.advance(cnt),
        }
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        match &mut self.inner {
            IoBufInner::Bytes(b) => b.copy_to_bytes(len),
            IoBufInner::Pooled(p) => {
                // Full non-empty drain: transfer ownership so the drained source no
                // longer retains the pooled allocation. Keep len == 0 on the normal
                // path to avoid creating an empty Bytes that still pins pool memory.
                if len != 0 && len == p.remaining() {
                    let inner = std::mem::replace(&mut self.inner, IoBufInner::Bytes(Bytes::new()));
                    match inner {
                        IoBufInner::Pooled(p) => p.into_bytes(),
                        IoBufInner::Bytes(_) => unreachable!(),
                    }
                } else {
                    p.copy_to_bytes(len)
                }
            }
        }
    }
}

impl From<Bytes> for IoBuf {
    fn from(bytes: Bytes) -> Self {
        Self {
            inner: IoBufInner::Bytes(bytes),
        }
    }
}

impl From<Vec<u8>> for IoBuf {
    fn from(vec: Vec<u8>) -> Self {
        Self {
            inner: IoBufInner::Bytes(Bytes::from(vec)),
        }
    }
}

impl<const N: usize> From<&'static [u8; N]> for IoBuf {
    fn from(array: &'static [u8; N]) -> Self {
        Self {
            inner: IoBufInner::Bytes(Bytes::from_static(array)),
        }
    }
}

impl From<&'static [u8]> for IoBuf {
    fn from(slice: &'static [u8]) -> Self {
        Self {
            inner: IoBufInner::Bytes(Bytes::from_static(slice)),
        }
    }
}

/// Convert an [`IoBuf`] into a [`Vec<u8>`].
///
/// This conversion may copy:
/// - [`Bytes`]-backed buffers may reuse allocation when possible
/// - pooled buffers copy readable bytes into a new [`Vec<u8>`]
impl From<IoBuf> for Vec<u8> {
    fn from(buf: IoBuf) -> Self {
        match buf.inner {
            IoBufInner::Bytes(bytes) => Self::from(bytes),
            IoBufInner::Pooled(pooled) => pooled.as_ref().to_vec(),
        }
    }
}

/// Convert an [`IoBuf`] into [`Bytes`] without copying readable data.
///
/// For pooled buffers, this wraps the pooled owner using [`Bytes::from_owner`].
impl From<IoBuf> for Bytes {
    fn from(buf: IoBuf) -> Self {
        match buf.inner {
            IoBufInner::Bytes(bytes) => bytes,
            IoBufInner::Pooled(pooled) => Self::from_owner(pooled),
        }
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
/// Backed by either [`BytesMut`] or a pooled aligned allocation.
///
/// Use this to build or mutate payloads before freezing into [`IoBuf`].
///
/// For pooled-backed values, dropping this buffer returns the underlying
/// allocation to the pool. After [`IoBufMut::freeze`], the frozen `IoBuf`
/// keeps the allocation alive until its final reference is dropped.
#[derive(Debug)]
pub struct IoBufMut {
    inner: IoBufMutInner,
}

#[derive(Debug)]
enum IoBufMutInner {
    Bytes(BytesMut),
    Pooled(PooledBufMut),
}

impl Default for IoBufMut {
    fn default() -> Self {
        Self {
            inner: IoBufMutInner::Bytes(BytesMut::new()),
        }
    }
}

impl IoBufMut {
    /// Create a buffer with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: IoBufMutInner::Bytes(BytesMut::with_capacity(capacity)),
        }
    }

    /// Create a buffer of `len` bytes, all initialized to zero.
    ///
    /// Unlike `with_capacity`, this sets both capacity and length to `len`,
    /// making the entire buffer immediately usable for read operations
    /// (e.g., `file.read_exact`).
    pub fn zeroed(len: usize) -> Self {
        Self {
            inner: IoBufMutInner::Bytes(BytesMut::zeroed(len)),
        }
    }

    /// Create a buffer from a pooled allocation.
    const fn from_pooled(pooled: PooledBufMut) -> Self {
        Self {
            inner: IoBufMutInner::Pooled(pooled),
        }
    }

    /// Returns `true` if this buffer is tracked by a pool.
    ///
    /// Tracked buffers originate from [`BufferPool`] allocations and are
    /// returned to the pool when dropped.
    ///
    /// Buffers backed by [`BytesMut`], and untracked fallback allocations from
    /// [`BufferPool::alloc`], return `false`.
    #[inline]
    pub fn is_pooled(&self) -> bool {
        match &self.inner {
            IoBufMutInner::Bytes(_) => false,
            IoBufMutInner::Pooled(p) => p.is_tracked(),
        }
    }

    /// Sets the length of the buffer.
    ///
    /// This will explicitly set the size of the buffer without actually
    /// modifying the data, so it is up to the caller to ensure that the data
    /// has been initialized.
    ///
    /// # Safety
    ///
    /// Caller must ensure all bytes in `0..len` are initialized before any
    /// read operations.
    ///
    /// # Panics
    ///
    /// Panics if `len > capacity()`.
    #[inline]
    pub unsafe fn set_len(&mut self, len: usize) {
        assert!(
            len <= self.capacity(),
            "set_len({len}) exceeds capacity({})",
            self.capacity()
        );
        match &mut self.inner {
            IoBufMutInner::Bytes(b) => b.set_len(len),
            IoBufMutInner::Pooled(b) => b.set_len(len),
        }
    }

    /// Number of bytes remaining in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.remaining()
    }

    /// Whether the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            IoBufMutInner::Bytes(b) => b.is_empty(),
            IoBufMutInner::Pooled(b) => b.is_empty(),
        }
    }

    /// Freeze into immutable [`IoBuf`].
    #[inline]
    pub fn freeze(self) -> IoBuf {
        match self.inner {
            IoBufMutInner::Bytes(b) => b.freeze().into(),
            IoBufMutInner::Pooled(b) => b.freeze(),
        }
    }

    /// Returns the number of bytes the buffer can hold without reallocating.
    #[inline]
    pub fn capacity(&self) -> usize {
        match &self.inner {
            IoBufMutInner::Bytes(b) => b.capacity(),
            IoBufMutInner::Pooled(b) => b.capacity(),
        }
    }

    /// Returns an unsafe mutable pointer to the buffer's data.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        match &mut self.inner {
            IoBufMutInner::Bytes(b) => b.as_mut_ptr(),
            IoBufMutInner::Pooled(b) => b.as_mut_ptr(),
        }
    }

    /// Truncates the buffer to `len` readable bytes.
    ///
    /// If `len` is greater than the current length, this has no effect.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        match &mut self.inner {
            IoBufMutInner::Bytes(b) => b.truncate(len),
            IoBufMutInner::Pooled(b) => b.truncate(len),
        }
    }

    /// Clears the buffer, removing all data. Existing capacity is preserved.
    #[inline]
    pub fn clear(&mut self) {
        match &mut self.inner {
            IoBufMutInner::Bytes(b) => b.clear(),
            IoBufMutInner::Pooled(b) => b.clear(),
        }
    }
}

impl AsRef<[u8]> for IoBufMut {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match &self.inner {
            IoBufMutInner::Bytes(b) => b.as_ref(),
            IoBufMutInner::Pooled(b) => b.as_ref(),
        }
    }
}

impl AsMut<[u8]> for IoBufMut {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        match &mut self.inner {
            IoBufMutInner::Bytes(b) => b.as_mut(),
            IoBufMutInner::Pooled(b) => b.as_mut(),
        }
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
        match &self.inner {
            IoBufMutInner::Bytes(b) => b.remaining(),
            IoBufMutInner::Pooled(b) => b.remaining(),
        }
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        match &self.inner {
            IoBufMutInner::Bytes(b) => b.chunk(),
            IoBufMutInner::Pooled(b) => b.chunk(),
        }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        match &mut self.inner {
            IoBufMutInner::Bytes(b) => b.advance(cnt),
            IoBufMutInner::Pooled(b) => b.advance(cnt),
        }
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        match &mut self.inner {
            IoBufMutInner::Bytes(b) => b.copy_to_bytes(len),
            IoBufMutInner::Pooled(p) => {
                // Full non-empty drain: transfer ownership so the drained source no
                // longer retains the pooled allocation. Keep len == 0 on the normal
                // path to avoid creating an empty Bytes that still pins pool memory.
                if len != 0 && len == p.remaining() {
                    let inner =
                        std::mem::replace(&mut self.inner, IoBufMutInner::Bytes(BytesMut::new()));
                    match inner {
                        IoBufMutInner::Pooled(p) => p.into_bytes(),
                        IoBufMutInner::Bytes(_) => unreachable!(),
                    }
                } else {
                    p.copy_to_bytes(len)
                }
            }
        }
    }
}

// SAFETY: Delegates to BytesMut or PooledBufMut which implement BufMut safely.
unsafe impl BufMut for IoBufMut {
    #[inline]
    fn remaining_mut(&self) -> usize {
        match &self.inner {
            IoBufMutInner::Bytes(b) => b.remaining_mut(),
            IoBufMutInner::Pooled(b) => b.remaining_mut(),
        }
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        match &mut self.inner {
            IoBufMutInner::Bytes(b) => b.advance_mut(cnt),
            IoBufMutInner::Pooled(b) => b.advance_mut(cnt),
        }
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        match &mut self.inner {
            IoBufMutInner::Bytes(b) => b.chunk_mut(),
            IoBufMutInner::Pooled(b) => b.chunk_mut(),
        }
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
            inner: IoBufMutInner::Bytes(BytesMut::from(slice)),
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
        Self {
            inner: IoBufMutInner::Bytes(bytes),
        }
    }
}

impl From<Bytes> for IoBufMut {
    /// Zero-copy if `bytes` is unique for the entire original buffer (refcount is 1),
    /// copies otherwise. Always copies if the [`Bytes`] was constructed via
    /// [`Bytes::from_owner`] or [`Bytes::from_static`].
    fn from(bytes: Bytes) -> Self {
        Self {
            inner: IoBufMutInner::Bytes(BytesMut::from(bytes)),
        }
    }
}

impl From<IoBuf> for IoBufMut {
    /// Zero-copy when exclusive ownership can be recovered, copies otherwise.
    fn from(buf: IoBuf) -> Self {
        match buf.try_into_mut() {
            Ok(buf) => buf,
            Err(buf) => Self::from(buf.as_ref()),
        }
    }
}

/// Container for one or more immutable buffers.
#[derive(Clone, Debug)]
pub struct IoBufs {
    inner: IoBufsInner,
}

/// Internal immutable representation.
///
/// - Representation is canonical and minimal for readable data:
///   - `Single` is the only representation for empty data and one-chunk data.
///   - `Chunked` is used only when four or more readable chunks remain.
/// - `Pair`, `Triple`, and `Chunked` never store empty chunks.
#[derive(Clone, Debug)]
enum IoBufsInner {
    /// Single buffer (fast path).
    Single(IoBuf),
    /// Two buffers (fast path).
    Pair([IoBuf; 2]),
    /// Three buffers (fast path).
    Triple([IoBuf; 3]),
    /// Four or more buffers.
    Chunked(VecDeque<IoBuf>),
}

impl Default for IoBufs {
    fn default() -> Self {
        Self {
            inner: IoBufsInner::Single(IoBuf::default()),
        }
    }
}

impl IoBufs {
    /// Build canonical immutable chunk storage from readable chunks.
    ///
    /// Empty chunks are removed before representation selection.
    fn from_chunks_iter(chunks: impl IntoIterator<Item = IoBuf>) -> Self {
        let mut iter = chunks.into_iter().filter(|buf| !buf.is_empty());
        let first = match iter.next() {
            Some(first) => first,
            None => return Self::default(),
        };
        let second = match iter.next() {
            Some(second) => second,
            None => {
                return Self {
                    inner: IoBufsInner::Single(first),
                };
            }
        };
        let third = match iter.next() {
            Some(third) => third,
            None => {
                return Self {
                    inner: IoBufsInner::Pair([first, second]),
                };
            }
        };
        let fourth = match iter.next() {
            Some(fourth) => fourth,
            None => {
                return Self {
                    inner: IoBufsInner::Triple([first, second, third]),
                };
            }
        };

        let mut bufs = VecDeque::with_capacity(4);
        bufs.push_back(first);
        bufs.push_back(second);
        bufs.push_back(third);
        bufs.push_back(fourth);
        bufs.extend(iter);

        Self {
            inner: IoBufsInner::Chunked(bufs),
        }
    }

    /// Re-establish canonical immutable representation invariants.
    fn canonicalize(&mut self) {
        let inner = std::mem::replace(&mut self.inner, IoBufsInner::Single(IoBuf::default()));
        self.inner = match inner {
            IoBufsInner::Single(buf) => {
                if buf.is_empty() {
                    IoBufsInner::Single(IoBuf::default())
                } else {
                    IoBufsInner::Single(buf)
                }
            }
            IoBufsInner::Pair([a, b]) => Self::from_chunks_iter([a, b]).inner,
            IoBufsInner::Triple([a, b, c]) => Self::from_chunks_iter([a, b, c]).inner,
            IoBufsInner::Chunked(bufs) => Self::from_chunks_iter(bufs).inner,
        };
    }

    /// Returns a reference to the single contiguous buffer, if present.
    ///
    /// Returns `Some` only when all remaining data is in one contiguous buffer.
    pub const fn as_single(&self) -> Option<&IoBuf> {
        match &self.inner {
            IoBufsInner::Single(buf) => Some(buf),
            _ => None,
        }
    }

    /// Consume this container and return the single buffer if present.
    ///
    /// Returns `Ok(IoBuf)` only when all remaining data is already contained in
    /// a single chunk. Returns `Err(Self)` with the original container
    /// otherwise.
    pub fn try_into_single(self) -> Result<IoBuf, Self> {
        match self.inner {
            IoBufsInner::Single(buf) => Ok(buf),
            inner => Err(Self { inner }),
        }
    }

    /// Number of bytes remaining across all buffers.
    #[inline]
    pub fn len(&self) -> usize {
        self.remaining()
    }

    /// Number of non-empty readable chunks.
    #[inline]
    pub fn chunk_count(&self) -> usize {
        // This assumes canonical form.
        match &self.inner {
            IoBufsInner::Single(buf) => {
                if buf.is_empty() {
                    0
                } else {
                    1
                }
            }
            IoBufsInner::Pair(_) => 2,
            IoBufsInner::Triple(_) => 3,
            IoBufsInner::Chunked(bufs) => bufs.len(),
        }
    }

    /// Whether all buffers are empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Whether this contains a single contiguous buffer.
    ///
    /// When true, `chunk()` returns all remaining bytes.
    #[inline]
    pub const fn is_single(&self) -> bool {
        matches!(self.inner, IoBufsInner::Single(_))
    }

    /// Prepend a buffer to the front.
    ///
    /// Empty input buffers are ignored.
    pub fn prepend(&mut self, buf: IoBuf) {
        if buf.is_empty() {
            return;
        }
        let inner = std::mem::replace(&mut self.inner, IoBufsInner::Single(IoBuf::default()));
        self.inner = match inner {
            IoBufsInner::Single(existing) if existing.is_empty() => IoBufsInner::Single(buf),
            IoBufsInner::Single(existing) => IoBufsInner::Pair([buf, existing]),
            IoBufsInner::Pair([a, b]) => IoBufsInner::Triple([buf, a, b]),
            IoBufsInner::Triple([a, b, c]) => {
                let mut bufs = VecDeque::with_capacity(4);
                bufs.push_back(buf);
                bufs.push_back(a);
                bufs.push_back(b);
                bufs.push_back(c);
                IoBufsInner::Chunked(bufs)
            }
            IoBufsInner::Chunked(mut bufs) => {
                bufs.push_front(buf);
                IoBufsInner::Chunked(bufs)
            }
        };
    }

    /// Append a buffer to the back.
    ///
    /// Empty input buffers are ignored.
    pub fn append(&mut self, buf: IoBuf) {
        if buf.is_empty() {
            return;
        }
        let inner = std::mem::replace(&mut self.inner, IoBufsInner::Single(IoBuf::default()));
        self.inner = match inner {
            IoBufsInner::Single(existing) if existing.is_empty() => IoBufsInner::Single(buf),
            IoBufsInner::Single(existing) => IoBufsInner::Pair([existing, buf]),
            IoBufsInner::Pair([a, b]) => IoBufsInner::Triple([a, b, buf]),
            IoBufsInner::Triple([a, b, c]) => {
                let mut bufs = VecDeque::with_capacity(4);
                bufs.push_back(a);
                bufs.push_back(b);
                bufs.push_back(c);
                bufs.push_back(buf);
                IoBufsInner::Chunked(bufs)
            }
            IoBufsInner::Chunked(mut bufs) => {
                bufs.push_back(buf);
                IoBufsInner::Chunked(bufs)
            }
        };
    }

    /// Splits the buffer(s) into two at the given index.
    ///
    /// Afterwards `self` contains bytes `[at, len)`, and the returned
    /// [`IoBufs`] contains bytes `[0, at)`.
    ///
    /// Whole chunks are moved without copying. If the split point lands inside
    /// a chunk, the chunk is split zero-copy via [`IoBuf::split_to`].
    ///
    /// # Panics
    ///
    /// Panics if `at > len`.
    pub fn split_to(&mut self, at: usize) -> Self {
        if at == 0 {
            return Self::default();
        }

        let remaining = self.remaining();
        assert!(
            at <= remaining,
            "split_to out of bounds: {:?} <= {:?}",
            at,
            remaining,
        );

        if at == remaining {
            return std::mem::take(self);
        }

        let inner = std::mem::replace(&mut self.inner, IoBufsInner::Single(IoBuf::default()));
        match inner {
            IoBufsInner::Single(mut buf) => {
                // Delegate directly and keep remainder as single
                let prefix = buf.split_to(at);
                self.inner = IoBufsInner::Single(buf);
                Self::from(prefix)
            }
            IoBufsInner::Pair([mut a, mut b]) => {
                let a_len = a.remaining();
                if at < a_len {
                    // Split stays entirely in chunk `a`.
                    let prefix = a.split_to(at);
                    self.inner = IoBufsInner::Pair([a, b]);
                    return Self::from(prefix);
                }
                if at == a_len {
                    // Exact chunk boundary: move `a` out, keep `b`.
                    self.inner = IoBufsInner::Single(b);
                    return Self::from(a);
                }

                // Split crosses from `a` into `b`.
                let b_prefix_len = at - a_len;
                let b_prefix = b.split_to(b_prefix_len);
                self.inner = IoBufsInner::Single(b);
                Self {
                    inner: IoBufsInner::Pair([a, b_prefix]),
                }
            }
            IoBufsInner::Triple([mut a, mut b, mut c]) => {
                let a_len = a.remaining();
                if at < a_len {
                    // Split stays entirely in chunk `a`.
                    let prefix = a.split_to(at);
                    self.inner = IoBufsInner::Triple([a, b, c]);
                    return Self::from(prefix);
                }
                if at == a_len {
                    // Exact boundary after `a`.
                    self.inner = IoBufsInner::Pair([b, c]);
                    return Self::from(a);
                }

                let mut remaining = at - a_len;
                let b_len = b.remaining();
                if remaining < b_len {
                    // Split lands inside `b`.
                    let b_prefix = b.split_to(remaining);
                    self.inner = IoBufsInner::Pair([b, c]);
                    return Self {
                        inner: IoBufsInner::Pair([a, b_prefix]),
                    };
                }
                if remaining == b_len {
                    // Exact boundary after `b`.
                    self.inner = IoBufsInner::Single(c);
                    return Self {
                        inner: IoBufsInner::Pair([a, b]),
                    };
                }

                // Split reaches into `c`.
                remaining -= b_len;
                let c_prefix = c.split_to(remaining);
                self.inner = IoBufsInner::Single(c);
                Self {
                    inner: IoBufsInner::Triple([a, b, c_prefix]),
                }
            }
            IoBufsInner::Chunked(mut bufs) => {
                let mut remaining = at;
                let mut out = VecDeque::new();

                while remaining > 0 {
                    let mut front = bufs.pop_front().expect("split_to out of bounds");
                    let avail = front.remaining();
                    if avail == 0 {
                        // Canonical chunked state should not contain empties.
                        continue;
                    }
                    if remaining < avail {
                        // Split inside this chunk: keep suffix in `self`, move prefix to output.
                        let prefix = front.split_to(remaining);
                        out.push_back(prefix);
                        bufs.push_front(front);
                        break;
                    }

                    // Consume this full chunk into the output prefix.
                    out.push_back(front);
                    remaining -= avail;
                }

                self.inner = if bufs.len() >= 4 {
                    IoBufsInner::Chunked(bufs)
                } else {
                    Self::from_chunks_iter(bufs).inner
                };

                if out.len() >= 4 {
                    Self {
                        inner: IoBufsInner::Chunked(out),
                    }
                } else {
                    Self::from_chunks_iter(out)
                }
            }
        }
    }

    /// Coalesce all remaining bytes into a single contiguous [`IoBuf`].
    ///
    /// Zero-copy if only one buffer. Copies if multiple buffers.
    #[inline]
    pub fn coalesce(mut self) -> IoBuf {
        match self.inner {
            IoBufsInner::Single(buf) => buf,
            _ => self.copy_to_bytes(self.remaining()).into(),
        }
    }

    /// Coalesce all remaining bytes into a single contiguous [`IoBuf`], using the pool
    /// for allocation if multiple buffers need to be merged.
    ///
    /// Zero-copy if only one buffer. Uses pool allocation if multiple buffers.
    pub fn coalesce_with_pool(self, pool: &BufferPool) -> IoBuf {
        match self.inner {
            IoBufsInner::Single(buf) => buf,
            IoBufsInner::Pair([a, b]) => {
                let total_len = a.remaining().saturating_add(b.remaining());
                let mut result = pool.alloc(total_len);
                result.put_slice(a.as_ref());
                result.put_slice(b.as_ref());
                result.freeze()
            }
            IoBufsInner::Triple([a, b, c]) => {
                let total_len = a
                    .remaining()
                    .saturating_add(b.remaining())
                    .saturating_add(c.remaining());
                let mut result = pool.alloc(total_len);
                result.put_slice(a.as_ref());
                result.put_slice(b.as_ref());
                result.put_slice(c.as_ref());
                result.freeze()
            }
            IoBufsInner::Chunked(bufs) => {
                let total_len: usize = bufs
                    .iter()
                    .map(|b| b.remaining())
                    .fold(0, usize::saturating_add);
                let mut result = pool.alloc(total_len);
                for buf in bufs {
                    result.put_slice(buf.as_ref());
                }
                result.freeze()
            }
        }
    }
}

impl Buf for IoBufs {
    fn remaining(&self) -> usize {
        match &self.inner {
            IoBufsInner::Single(buf) => buf.remaining(),
            IoBufsInner::Pair([a, b]) => a.remaining().saturating_add(b.remaining()),
            IoBufsInner::Triple([a, b, c]) => a
                .remaining()
                .saturating_add(b.remaining())
                .saturating_add(c.remaining()),
            IoBufsInner::Chunked(bufs) => bufs
                .iter()
                .map(|b| b.remaining())
                .fold(0, usize::saturating_add),
        }
    }

    fn chunk(&self) -> &[u8] {
        match &self.inner {
            IoBufsInner::Single(buf) => buf.chunk(),
            IoBufsInner::Pair([a, b]) => {
                if a.remaining() > 0 {
                    a.chunk()
                } else if b.remaining() > 0 {
                    b.chunk()
                } else {
                    &[]
                }
            }
            IoBufsInner::Triple([a, b, c]) => {
                if a.remaining() > 0 {
                    a.chunk()
                } else if b.remaining() > 0 {
                    b.chunk()
                } else if c.remaining() > 0 {
                    c.chunk()
                } else {
                    &[]
                }
            }
            IoBufsInner::Chunked(bufs) => {
                for buf in bufs.iter() {
                    if buf.remaining() > 0 {
                        return buf.chunk();
                    }
                }
                &[]
            }
        }
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        if dst.is_empty() {
            return 0;
        }

        match &self.inner {
            IoBufsInner::Single(buf) => {
                let chunk = buf.chunk();
                if !chunk.is_empty() {
                    dst[0] = IoSlice::new(chunk);
                    return 1;
                }
                0
            }
            IoBufsInner::Pair([a, b]) => fill_vectored_from_chunks(dst, [a.chunk(), b.chunk()]),
            IoBufsInner::Triple([a, b, c]) => {
                fill_vectored_from_chunks(dst, [a.chunk(), b.chunk(), c.chunk()])
            }
            IoBufsInner::Chunked(bufs) => {
                fill_vectored_from_chunks(dst, bufs.iter().map(|buf| buf.chunk()))
            }
        }
    }

    fn advance(&mut self, cnt: usize) {
        let should_canonicalize = match &mut self.inner {
            IoBufsInner::Single(buf) => {
                buf.advance(cnt);
                false
            }
            IoBufsInner::Pair(pair) => advance_small_chunks(pair.as_mut_slice(), cnt),
            IoBufsInner::Triple(triple) => advance_small_chunks(triple.as_mut_slice(), cnt),
            IoBufsInner::Chunked(bufs) => {
                advance_chunked_front(bufs, cnt);
                bufs.len() <= 3
            }
        };

        if should_canonicalize {
            self.canonicalize();
        }
    }

    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        let (result, needs_canonicalize) = match &mut self.inner {
            IoBufsInner::Single(buf) => return buf.copy_to_bytes(len),
            IoBufsInner::Pair(pair) => {
                copy_to_bytes_small_chunks(pair, len, "IoBufs::copy_to_bytes: not enough data")
            }
            IoBufsInner::Triple(triple) => {
                copy_to_bytes_small_chunks(triple, len, "IoBufs::copy_to_bytes: not enough data")
            }
            IoBufsInner::Chunked(bufs) => {
                copy_to_bytes_chunked(bufs, len, "IoBufs::copy_to_bytes: not enough data")
            }
        };

        if needs_canonicalize {
            self.canonicalize();
        }

        result
    }
}

impl From<IoBuf> for IoBufs {
    fn from(buf: IoBuf) -> Self {
        Self {
            inner: IoBufsInner::Single(buf),
        }
    }
}

impl From<IoBufMut> for IoBufs {
    fn from(buf: IoBufMut) -> Self {
        Self {
            inner: IoBufsInner::Single(buf.freeze()),
        }
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

impl From<Vec<IoBuf>> for IoBufs {
    fn from(bufs: Vec<IoBuf>) -> Self {
        Self::from_chunks_iter(bufs)
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
pub struct IoBufsMut {
    inner: IoBufsMutInner,
}

/// Internal mutable representation.
///
/// - Construction from caller-provided writable chunks keeps chunks with
///   non-zero capacity, even when `remaining() == 0`.
/// - Read-canonicalization paths remove drained chunks (`remaining() == 0`)
///   and collapse shape as readable chunk count shrinks.
#[derive(Debug)]
enum IoBufsMutInner {
    /// Single buffer (common case, no allocation).
    Single(IoBufMut),
    /// Two buffers (fast path, no VecDeque allocation).
    Pair([IoBufMut; 2]),
    /// Three buffers (fast path, no VecDeque allocation).
    Triple([IoBufMut; 3]),
    /// Four or more buffers.
    Chunked(VecDeque<IoBufMut>),
}

impl Default for IoBufsMut {
    fn default() -> Self {
        Self {
            inner: IoBufsMutInner::Single(IoBufMut::default()),
        }
    }
}

impl IoBufsMut {
    /// Build mutable chunk storage from already-filtered chunks.
    ///
    /// This helper intentionally does not filter.
    /// Callers choose filter policy first:
    /// - [`Self::from_writable_chunks_iter`] for construction from writable chunks (`capacity() > 0`)
    /// - [`Self::from_readable_chunks_iter`] for read-canonicalization (`remaining() > 0`)
    fn from_chunks_iter(chunks: impl IntoIterator<Item = IoBufMut>) -> Self {
        let mut iter = chunks.into_iter();
        let first = match iter.next() {
            Some(first) => first,
            None => return Self::default(),
        };
        let second = match iter.next() {
            Some(second) => second,
            None => {
                return Self {
                    inner: IoBufsMutInner::Single(first),
                };
            }
        };
        let third = match iter.next() {
            Some(third) => third,
            None => {
                return Self {
                    inner: IoBufsMutInner::Pair([first, second]),
                };
            }
        };
        let fourth = match iter.next() {
            Some(fourth) => fourth,
            None => {
                return Self {
                    inner: IoBufsMutInner::Triple([first, second, third]),
                };
            }
        };

        let mut bufs = VecDeque::with_capacity(4);
        bufs.push_back(first);
        bufs.push_back(second);
        bufs.push_back(third);
        bufs.push_back(fourth);
        bufs.extend(iter);
        Self {
            inner: IoBufsMutInner::Chunked(bufs),
        }
    }

    /// Build canonical mutable chunk storage from writable chunks.
    ///
    /// Chunks with zero capacity are removed.
    fn from_writable_chunks_iter(chunks: impl IntoIterator<Item = IoBufMut>) -> Self {
        // Keep chunks that can hold data (including len == 0 writable buffers).
        Self::from_chunks_iter(chunks.into_iter().filter(|buf| buf.capacity() > 0))
    }

    /// Build canonical mutable chunk storage from readable chunks.
    ///
    /// Chunks with no remaining readable bytes are removed.
    fn from_readable_chunks_iter(chunks: impl IntoIterator<Item = IoBufMut>) -> Self {
        Self::from_chunks_iter(chunks.into_iter().filter(|buf| buf.remaining() > 0))
    }

    /// Re-establish canonical mutable representation invariants.
    fn canonicalize(&mut self) {
        let inner = std::mem::replace(&mut self.inner, IoBufsMutInner::Single(IoBufMut::default()));
        self.inner = match inner {
            IoBufsMutInner::Single(buf) => IoBufsMutInner::Single(buf),
            IoBufsMutInner::Pair([a, b]) => Self::from_readable_chunks_iter([a, b]).inner,
            IoBufsMutInner::Triple([a, b, c]) => Self::from_readable_chunks_iter([a, b, c]).inner,
            IoBufsMutInner::Chunked(bufs) => Self::from_readable_chunks_iter(bufs).inner,
        };
    }

    #[inline]
    fn for_each_chunk_mut(&mut self, mut f: impl FnMut(&mut IoBufMut)) {
        match &mut self.inner {
            IoBufsMutInner::Single(buf) => f(buf),
            IoBufsMutInner::Pair(pair) => {
                for buf in pair.iter_mut() {
                    f(buf);
                }
            }
            IoBufsMutInner::Triple(triple) => {
                for buf in triple.iter_mut() {
                    f(buf);
                }
            }
            IoBufsMutInner::Chunked(bufs) => {
                for buf in bufs.iter_mut() {
                    f(buf);
                }
            }
        }
    }

    /// Returns a reference to the single contiguous buffer, if present.
    ///
    /// Returns `Some` only when this is currently represented as one chunk.
    pub const fn as_single(&self) -> Option<&IoBufMut> {
        match &self.inner {
            IoBufsMutInner::Single(buf) => Some(buf),
            _ => None,
        }
    }

    /// Returns a mutable reference to the single contiguous buffer, if present.
    ///
    /// Returns `Some` only when this is currently represented as one chunk.
    pub const fn as_single_mut(&mut self) -> Option<&mut IoBufMut> {
        match &mut self.inner {
            IoBufsMutInner::Single(buf) => Some(buf),
            _ => None,
        }
    }

    /// Consume this container and return the single buffer if present.
    ///
    /// Returns `Ok(IoBufMut)` only when readable data is represented as one
    /// chunk. Returns `Err(Self)` with the original container otherwise.
    #[allow(clippy::result_large_err)]
    pub fn try_into_single(self) -> Result<IoBufMut, Self> {
        match self.inner {
            IoBufsMutInner::Single(buf) => Ok(buf),
            inner => Err(Self { inner }),
        }
    }

    /// Number of bytes remaining across all buffers.
    #[inline]
    pub fn len(&self) -> usize {
        self.remaining()
    }

    /// Whether all buffers are empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Whether this contains a single contiguous buffer.
    ///
    /// When true, `chunk()` returns all remaining bytes.
    #[inline]
    pub const fn is_single(&self) -> bool {
        matches!(self.inner, IoBufsMutInner::Single(_))
    }

    /// Freeze into immutable [`IoBufs`].
    pub fn freeze(self) -> IoBufs {
        match self.inner {
            IoBufsMutInner::Single(buf) => IoBufs::from(buf.freeze()),
            IoBufsMutInner::Pair([a, b]) => IoBufs::from_chunks_iter([a.freeze(), b.freeze()]),
            IoBufsMutInner::Triple([a, b, c]) => {
                IoBufs::from_chunks_iter([a.freeze(), b.freeze(), c.freeze()])
            }
            IoBufsMutInner::Chunked(bufs) => {
                IoBufs::from_chunks_iter(bufs.into_iter().map(IoBufMut::freeze))
            }
        }
    }

    fn coalesce_with<F>(self, allocate: F) -> IoBufMut
    where
        F: FnOnce(usize) -> IoBufMut,
    {
        match self.inner {
            IoBufsMutInner::Single(buf) => buf,
            IoBufsMutInner::Pair([a, b]) => {
                let total_len = a.len().saturating_add(b.len());
                let mut result = allocate(total_len);
                result.put_slice(a.as_ref());
                result.put_slice(b.as_ref());
                result
            }
            IoBufsMutInner::Triple([a, b, c]) => {
                let total_len = a.len().saturating_add(b.len()).saturating_add(c.len());
                let mut result = allocate(total_len);
                result.put_slice(a.as_ref());
                result.put_slice(b.as_ref());
                result.put_slice(c.as_ref());
                result
            }
            IoBufsMutInner::Chunked(bufs) => {
                let total_len: usize = bufs.iter().map(|b| b.len()).fold(0, usize::saturating_add);
                let mut result = allocate(total_len);
                for buf in bufs {
                    result.put_slice(buf.as_ref());
                }
                result
            }
        }
    }

    /// Coalesce all buffers into a single contiguous [`IoBufMut`].
    ///
    /// Zero-copy if only one buffer. Copies if multiple buffers.
    pub fn coalesce(self) -> IoBufMut {
        self.coalesce_with(IoBufMut::with_capacity)
    }

    /// Coalesce all buffers into a single contiguous [`IoBufMut`], using the pool
    /// for allocation if multiple buffers need to be merged.
    ///
    /// Zero-copy if only one buffer. Uses pool allocation if multiple buffers.
    pub fn coalesce_with_pool(self, pool: &BufferPool) -> IoBufMut {
        self.coalesce_with(|len| pool.alloc(len))
    }

    /// Coalesce all buffers into a single contiguous [`IoBufMut`] with extra
    /// capacity, using the pool for allocation.
    ///
    /// Zero-copy if single buffer with sufficient spare capacity.
    pub fn coalesce_with_pool_extra(self, pool: &BufferPool, extra: usize) -> IoBufMut {
        match self.inner {
            IoBufsMutInner::Single(buf) if buf.capacity() - buf.len() >= extra => buf,
            IoBufsMutInner::Single(buf) => {
                let mut result = pool.alloc(buf.len() + extra);
                result.put_slice(buf.as_ref());
                result
            }
            IoBufsMutInner::Pair([a, b]) => {
                let total = a.len().saturating_add(b.len());
                let mut result = pool.alloc(total + extra);
                result.put_slice(a.as_ref());
                result.put_slice(b.as_ref());
                result
            }
            IoBufsMutInner::Triple([a, b, c]) => {
                let total = a.len().saturating_add(b.len()).saturating_add(c.len());
                let mut result = pool.alloc(total + extra);
                result.put_slice(a.as_ref());
                result.put_slice(b.as_ref());
                result.put_slice(c.as_ref());
                result
            }
            IoBufsMutInner::Chunked(bufs) => {
                let total: usize = bufs.iter().map(|b| b.len()).fold(0, usize::saturating_add);
                let mut result = pool.alloc(total + extra);
                for buf in bufs {
                    result.put_slice(buf.as_ref());
                }
                result
            }
        }
    }

    /// Returns the total capacity across all buffers.
    pub fn capacity(&self) -> usize {
        match &self.inner {
            IoBufsMutInner::Single(buf) => buf.capacity(),
            IoBufsMutInner::Pair([a, b]) => a.capacity().saturating_add(b.capacity()),
            IoBufsMutInner::Triple([a, b, c]) => a
                .capacity()
                .saturating_add(b.capacity())
                .saturating_add(c.capacity()),
            IoBufsMutInner::Chunked(bufs) => bufs
                .iter()
                .map(|b| b.capacity())
                .fold(0, usize::saturating_add),
        }
    }

    /// Sets the length of the buffer(s) to `len`, distributing across chunks
    /// while preserving the current chunk layout.
    ///
    /// This is useful for APIs that must fill caller-provided buffer structure
    /// in place (for example [`Blob::read_at_buf`](crate::Blob::read_at_buf)).
    ///
    /// # Safety
    ///
    /// Caller must initialize all `len` bytes before the buffer is read.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds total capacity.
    pub(crate) unsafe fn set_len(&mut self, len: usize) {
        let capacity = self.capacity();
        assert!(
            len <= capacity,
            "set_len({len}) exceeds capacity({capacity})"
        );
        let mut remaining = len;
        self.for_each_chunk_mut(|buf| {
            let cap = buf.capacity();
            let to_set = remaining.min(cap);
            buf.set_len(to_set);
            remaining -= to_set;
        });
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
        let mut offset = 0;
        self.for_each_chunk_mut(|buf| {
            let len = buf.len();
            buf.as_mut().copy_from_slice(&src[offset..offset + len]);
            offset += len;
        });
    }
}

impl Buf for IoBufsMut {
    fn remaining(&self) -> usize {
        match &self.inner {
            IoBufsMutInner::Single(buf) => buf.remaining(),
            IoBufsMutInner::Pair([a, b]) => a.remaining().saturating_add(b.remaining()),
            IoBufsMutInner::Triple([a, b, c]) => a
                .remaining()
                .saturating_add(b.remaining())
                .saturating_add(c.remaining()),
            IoBufsMutInner::Chunked(bufs) => bufs
                .iter()
                .map(|b| b.remaining())
                .fold(0, usize::saturating_add),
        }
    }

    fn chunk(&self) -> &[u8] {
        match &self.inner {
            IoBufsMutInner::Single(buf) => buf.chunk(),
            IoBufsMutInner::Pair([a, b]) => {
                if a.remaining() > 0 {
                    a.chunk()
                } else if b.remaining() > 0 {
                    b.chunk()
                } else {
                    &[]
                }
            }
            IoBufsMutInner::Triple([a, b, c]) => {
                if a.remaining() > 0 {
                    a.chunk()
                } else if b.remaining() > 0 {
                    b.chunk()
                } else if c.remaining() > 0 {
                    c.chunk()
                } else {
                    &[]
                }
            }
            IoBufsMutInner::Chunked(bufs) => {
                for buf in bufs.iter() {
                    if buf.remaining() > 0 {
                        return buf.chunk();
                    }
                }
                &[]
            }
        }
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        if dst.is_empty() {
            return 0;
        }

        match &self.inner {
            IoBufsMutInner::Single(buf) => {
                let chunk = buf.chunk();
                if !chunk.is_empty() {
                    dst[0] = IoSlice::new(chunk);
                    return 1;
                }
                0
            }
            IoBufsMutInner::Pair([a, b]) => fill_vectored_from_chunks(dst, [a.chunk(), b.chunk()]),
            IoBufsMutInner::Triple([a, b, c]) => {
                fill_vectored_from_chunks(dst, [a.chunk(), b.chunk(), c.chunk()])
            }
            IoBufsMutInner::Chunked(bufs) => {
                fill_vectored_from_chunks(dst, bufs.iter().map(|buf| buf.chunk()))
            }
        }
    }

    fn advance(&mut self, cnt: usize) {
        let should_canonicalize = match &mut self.inner {
            IoBufsMutInner::Single(buf) => {
                buf.advance(cnt);
                false
            }
            IoBufsMutInner::Pair(pair) => advance_small_chunks(pair.as_mut_slice(), cnt),
            IoBufsMutInner::Triple(triple) => advance_small_chunks(triple.as_mut_slice(), cnt),
            IoBufsMutInner::Chunked(bufs) => {
                advance_chunked_front(bufs, cnt);
                bufs.len() <= 3
            }
        };

        if should_canonicalize {
            self.canonicalize();
        }
    }

    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        let (result, needs_canonicalize) = match &mut self.inner {
            IoBufsMutInner::Single(buf) => return buf.copy_to_bytes(len),
            IoBufsMutInner::Pair(pair) => {
                copy_to_bytes_small_chunks(pair, len, "IoBufsMut::copy_to_bytes: not enough data")
            }
            IoBufsMutInner::Triple(triple) => {
                copy_to_bytes_small_chunks(triple, len, "IoBufsMut::copy_to_bytes: not enough data")
            }
            IoBufsMutInner::Chunked(bufs) => {
                copy_to_bytes_chunked(bufs, len, "IoBufsMut::copy_to_bytes: not enough data")
            }
        };

        if needs_canonicalize {
            self.canonicalize();
        }

        result
    }
}

// SAFETY: Delegates to IoBufMut which implements BufMut safely.
unsafe impl BufMut for IoBufsMut {
    #[inline]
    fn remaining_mut(&self) -> usize {
        match &self.inner {
            IoBufsMutInner::Single(buf) => buf.remaining_mut(),
            IoBufsMutInner::Pair([a, b]) => a.remaining_mut().saturating_add(b.remaining_mut()),
            IoBufsMutInner::Triple([a, b, c]) => a
                .remaining_mut()
                .saturating_add(b.remaining_mut())
                .saturating_add(c.remaining_mut()),
            IoBufsMutInner::Chunked(bufs) => bufs
                .iter()
                .map(|b| b.remaining_mut())
                .fold(0, usize::saturating_add),
        }
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        match &mut self.inner {
            IoBufsMutInner::Single(buf) => buf.advance_mut(cnt),
            IoBufsMutInner::Pair(pair) => {
                let mut remaining = cnt;
                if advance_mut_in_chunks(pair, &mut remaining) {
                    return;
                }
                panic!("cannot advance past end of buffer");
            }
            IoBufsMutInner::Triple(triple) => {
                let mut remaining = cnt;
                if advance_mut_in_chunks(triple, &mut remaining) {
                    return;
                }
                panic!("cannot advance past end of buffer");
            }
            IoBufsMutInner::Chunked(bufs) => {
                let mut remaining = cnt;
                let (first, second) = bufs.as_mut_slices();
                if advance_mut_in_chunks(first, &mut remaining)
                    || advance_mut_in_chunks(second, &mut remaining)
                {
                    return;
                }
                panic!("cannot advance past end of buffer");
            }
        }
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        match &mut self.inner {
            IoBufsMutInner::Single(buf) => buf.chunk_mut(),
            IoBufsMutInner::Pair(pair) => {
                if pair[0].remaining_mut() > 0 {
                    pair[0].chunk_mut()
                } else if pair[1].remaining_mut() > 0 {
                    pair[1].chunk_mut()
                } else {
                    bytes::buf::UninitSlice::new(&mut [])
                }
            }
            IoBufsMutInner::Triple(triple) => {
                if triple[0].remaining_mut() > 0 {
                    triple[0].chunk_mut()
                } else if triple[1].remaining_mut() > 0 {
                    triple[1].chunk_mut()
                } else if triple[2].remaining_mut() > 0 {
                    triple[2].chunk_mut()
                } else {
                    bytes::buf::UninitSlice::new(&mut [])
                }
            }
            IoBufsMutInner::Chunked(bufs) => {
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
        Self {
            inner: IoBufsMutInner::Single(buf),
        }
    }
}

impl From<Vec<u8>> for IoBufsMut {
    fn from(vec: Vec<u8>) -> Self {
        Self {
            inner: IoBufsMutInner::Single(IoBufMut::from(vec)),
        }
    }
}

impl From<BytesMut> for IoBufsMut {
    fn from(bytes: BytesMut) -> Self {
        Self {
            inner: IoBufsMutInner::Single(IoBufMut::from(bytes)),
        }
    }
}

impl From<Vec<IoBufMut>> for IoBufsMut {
    fn from(bufs: Vec<IoBufMut>) -> Self {
        Self::from_writable_chunks_iter(bufs)
    }
}

impl<const N: usize> From<[u8; N]> for IoBufsMut {
    fn from(array: [u8; N]) -> Self {
        Self {
            inner: IoBufsMutInner::Single(IoBufMut::from(array)),
        }
    }
}

/// Drain `len` readable bytes from a small fixed chunk array (`Pair`/`Triple`).
///
/// Returns drained bytes plus whether the caller should canonicalize afterward.
#[inline]
fn copy_to_bytes_small_chunks<B: Buf, const N: usize>(
    chunks: &mut [B; N],
    len: usize,
    not_enough_data_msg: &str,
) -> (Bytes, bool) {
    let total = chunks
        .iter()
        .map(|buf| buf.remaining())
        .fold(0, usize::saturating_add);
    assert!(total >= len, "{not_enough_data_msg}");

    if chunks[0].remaining() >= len {
        let bytes = chunks[0].copy_to_bytes(len);
        return (bytes, chunks[0].remaining() == 0);
    }

    let mut out = BytesMut::with_capacity(len);
    let mut remaining = len;
    for buf in chunks.iter_mut() {
        if remaining == 0 {
            break;
        }
        let to_copy = remaining.min(buf.remaining());
        out.extend_from_slice(&buf.chunk()[..to_copy]);
        buf.advance(to_copy);
        remaining -= to_copy;
    }

    // Slow path always consumes past chunk 0, so canonicalization is required.
    (out.freeze(), true)
}

/// Drain `len` readable bytes from a deque-backed chunk representation.
///
/// Returns drained bytes plus whether the caller should canonicalize afterward.
#[inline]
fn copy_to_bytes_chunked<B: Buf>(
    bufs: &mut VecDeque<B>,
    len: usize,
    not_enough_data_msg: &str,
) -> (Bytes, bool) {
    while bufs.front().is_some_and(|buf| buf.remaining() == 0) {
        bufs.pop_front();
    }

    if bufs.front().is_none() {
        assert_eq!(len, 0, "{not_enough_data_msg}");
        return (Bytes::new(), false);
    }

    if bufs.front().is_some_and(|front| front.remaining() >= len) {
        let front = bufs.front_mut().expect("front checked above");
        let bytes = front.copy_to_bytes(len);
        if front.remaining() == 0 {
            bufs.pop_front();
        }
        return (bytes, bufs.len() <= 3);
    }

    let total = bufs
        .iter()
        .map(|buf| buf.remaining())
        .fold(0, usize::saturating_add);
    assert!(total >= len, "{not_enough_data_msg}");

    let mut out = BytesMut::with_capacity(len);
    let mut remaining = len;
    while remaining > 0 {
        let front = bufs
            .front_mut()
            .expect("remaining > 0 implies non-empty bufs");
        let to_copy = remaining.min(front.remaining());
        out.extend_from_slice(&front.chunk()[..to_copy]);
        front.advance(to_copy);
        if front.remaining() == 0 {
            bufs.pop_front();
        }
        remaining -= to_copy;
    }

    (out.freeze(), bufs.len() <= 3)
}

/// Advance across a [`VecDeque`] of chunks by consuming from the front.
#[inline]
fn advance_chunked_front<B: Buf>(bufs: &mut VecDeque<B>, mut cnt: usize) {
    while cnt > 0 {
        let front = bufs.front_mut().expect("cannot advance past end of buffer");
        let avail = front.remaining();
        if avail == 0 {
            bufs.pop_front();
            continue;
        }
        if cnt < avail {
            front.advance(cnt);
            break;
        }
        front.advance(avail);
        bufs.pop_front();
        cnt -= avail;
    }
}

/// Advance across a small fixed set of chunks (`Pair`/`Triple`).
///
/// Returns `true` when one or more chunks became (or were) empty, so callers
/// can canonicalize once after the operation.
#[inline]
fn advance_small_chunks<B: Buf>(chunks: &mut [B], mut cnt: usize) -> bool {
    let mut idx = 0;
    let mut needs_canonicalize = false;

    while cnt > 0 {
        let chunk = chunks
            .get_mut(idx)
            .expect("cannot advance past end of buffer");
        let avail = chunk.remaining();
        if avail == 0 {
            idx += 1;
            needs_canonicalize = true;
            continue;
        }
        if cnt < avail {
            chunk.advance(cnt);
            return needs_canonicalize;
        }
        chunk.advance(avail);
        cnt -= avail;
        idx += 1;
        needs_canonicalize = true;
    }

    needs_canonicalize
}

/// Advance writable cursors across `chunks` by up to `*remaining` bytes.
///
/// Returns `true` when the full request has been satisfied.
///
/// # Safety
///
/// Forwards to [`BufMut::advance_mut`], so callers must ensure the advanced
/// region has been initialized according to [`BufMut`]'s contract.
#[inline]
unsafe fn advance_mut_in_chunks<B: BufMut>(chunks: &mut [B], remaining: &mut usize) -> bool {
    if *remaining == 0 {
        return true;
    }

    for buf in chunks.iter_mut() {
        let avail = buf.chunk_mut().len();
        if avail == 0 {
            continue;
        }
        if *remaining <= avail {
            // SAFETY: Upheld by this function's safety contract.
            unsafe { buf.advance_mut(*remaining) };
            *remaining = 0;
            return true;
        }
        // SAFETY: Upheld by this function's safety contract.
        unsafe { buf.advance_mut(avail) };
        *remaining -= avail;
    }
    false
}

/// Fill `dst` with `IoSlice`s built from `chunks`.
///
/// Empty chunks are skipped. At most `dst.len()` slices are written.
/// Returns the number of slices written.
#[inline]
fn fill_vectored_from_chunks<'a, I>(dst: &mut [IoSlice<'a>], chunks: I) -> usize
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut written = 0;
    for chunk in chunks
        .into_iter()
        .filter(|chunk| !chunk.is_empty())
        .take(dst.len())
    {
        dst[written] = IoSlice::new(chunk);
        written += 1;
    }
    written
}

/// Extension trait for encoding values into pooled I/O buffers.
///
/// This is useful for hot paths that need to avoid frequent heap allocations
/// when serializing values that implement [`Write`] and [`EncodeSize`].
pub trait EncodeExt: EncodeSize + Write {
    /// Encode this value into an [`IoBufMut`] allocated from `pool`.
    ///
    /// # Panics
    ///
    /// Panics if [`EncodeSize::encode_size`] does not match the number of
    /// bytes written by [`Write::write`].
    fn encode_with_pool_mut(&self, pool: &BufferPool) -> IoBufMut {
        let len = self.encode_size();
        let mut buf = pool.alloc(len);
        self.write(&mut buf);
        assert_eq!(
            buf.len(),
            len,
            "write() did not write expected bytes into pooled buffer"
        );
        buf
    }

    /// Encode this value into an immutable [`IoBuf`] allocated from `pool`.
    ///
    /// # Panics
    ///
    /// Panics if [`EncodeSize::encode_size`] does not match the number of
    /// bytes written by [`Write::write`].
    fn encode_with_pool(&self, pool: &BufferPool) -> IoBuf {
        self.encode_with_pool_mut(pool).freeze()
    }
}

impl<T: EncodeSize + Write> EncodeExt for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::{Decode, Encode, RangeCfg};

    fn test_pool() -> BufferPool {
        cfg_if::cfg_if! {
            if #[cfg(miri)] {
                // Reduce max_per_class to avoid slow atomics under miri.
                let pool_config = BufferPoolConfig {
                    max_per_class: commonware_utils::NZUsize!(32),
                    ..BufferPoolConfig::for_network()
                };
            } else {
                let pool_config = BufferPoolConfig::for_network();
            }
        }
        let mut registry = prometheus_client::registry::Registry::default();
        BufferPool::new(pool_config, &mut registry)
    }

    #[test]
    fn test_iobuf_core_behaviors() {
        // Clone stays zero-copy for immutable buffers.
        let buf1 = IoBuf::from(vec![1u8; 1000]);
        let buf2 = buf1.clone();
        assert_eq!(buf1.as_ref().as_ptr(), buf2.as_ref().as_ptr());

        // copy_from_slice creates an owned immutable buffer.
        let data = vec![1u8, 2, 3, 4, 5];
        let copied = IoBuf::copy_from_slice(&data);
        assert_eq!(copied, [1, 2, 3, 4, 5]);
        assert_eq!(copied.len(), 5);
        let empty = IoBuf::copy_from_slice(&[]);
        assert!(empty.is_empty());

        // Equality works against both arrays and slices.
        let eq = IoBuf::from(b"hello");
        assert_eq!(eq, *b"hello");
        assert_eq!(eq, b"hello");
        assert_ne!(eq, *b"world");
        assert_ne!(eq, b"world");
        assert_eq!(IoBuf::from(b"hello"), IoBuf::from(b"hello"));
        assert_ne!(IoBuf::from(b"hello"), IoBuf::from(b"world"));
        let bytes: Bytes = IoBuf::from(b"bytes").into();
        assert_eq!(bytes.as_ref(), b"bytes");

        // Buf trait operations keep `len()` and `remaining()` in sync.
        let mut buf = IoBuf::from(b"hello world");
        assert_eq!(buf.len(), buf.remaining());
        assert_eq!(buf.as_ref(), buf.chunk());
        assert_eq!(buf.remaining(), 11);
        buf.advance(6);
        assert_eq!(buf.chunk(), b"world");
        assert_eq!(buf.len(), buf.remaining());

        // copy_to_bytes drains in-order and advances the source.
        let first = buf.copy_to_bytes(2);
        assert_eq!(&first[..], b"wo");
        let rest = buf.copy_to_bytes(3);
        assert_eq!(&rest[..], b"rld");
        assert_eq!(buf.remaining(), 0);

        // Slicing remains zero-copy and supports all common range forms.
        let src = IoBuf::from(b"hello world");
        assert_eq!(src.slice(..5), b"hello");
        assert_eq!(src.slice(6..), b"world");
        assert_eq!(src.slice(3..8), b"lo wo");
        assert!(src.slice(5..5).is_empty());
    }

    #[test]
    fn test_iobuf_codec_roundtrip() {
        let cfg: RangeCfg<usize> = (0..=1024).into();

        let original = IoBuf::from(b"hello world");
        let encoded = original.encode();
        let decoded = IoBuf::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(original, decoded);

        let empty = IoBuf::default();
        let encoded = empty.encode();
        let decoded = IoBuf::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(empty, decoded);

        let large_cfg: RangeCfg<usize> = (0..=20000).into();
        let large = IoBuf::from(vec![42u8; 10000]);
        let encoded = large.encode();
        let decoded = IoBuf::decode_cfg(encoded, &large_cfg).unwrap();
        assert_eq!(large, decoded);
    }

    #[test]
    #[should_panic(expected = "cannot advance")]
    fn test_iobuf_advance_past_end() {
        let mut buf = IoBuf::from(b"hello");
        buf.advance(10);
    }

    #[test]
    fn test_iobuf_split_to_consistent_across_backings() {
        let pool = test_pool();
        let mut pooled = pool.try_alloc(256).expect("pooled allocation");
        pooled.put_slice(b"hello world");
        let mut pooled_buf = pooled.freeze();
        let mut bytes_buf = IoBuf::from(b"hello world");

        assert!(pooled_buf.is_pooled());
        assert!(!bytes_buf.is_pooled());

        let pooled_empty = pooled_buf.split_to(0);
        let bytes_empty = bytes_buf.split_to(0);
        assert_eq!(pooled_empty, bytes_empty);
        assert_eq!(pooled_buf, bytes_buf);
        assert!(!pooled_empty.is_pooled());

        let pooled_prefix = pooled_buf.split_to(5);
        let bytes_prefix = bytes_buf.split_to(5);
        assert_eq!(pooled_prefix, bytes_prefix);
        assert_eq!(pooled_buf, bytes_buf);
        assert!(pooled_prefix.is_pooled());

        let pooled_rest = pooled_buf.split_to(pooled_buf.len());
        let bytes_rest = bytes_buf.split_to(bytes_buf.len());
        assert_eq!(pooled_rest, bytes_rest);
        assert_eq!(pooled_buf, bytes_buf);
        assert!(pooled_buf.is_empty());
        assert!(bytes_buf.is_empty());
        assert!(!pooled_buf.is_pooled());
    }

    #[test]
    #[should_panic(expected = "split_to out of bounds")]
    fn test_iobuf_split_to_out_of_bounds() {
        let mut buf = IoBuf::from(b"abc");
        let _ = buf.split_to(4);
    }

    #[test]
    fn test_iobufmut_core_behaviors() {
        // Build mutable buffers incrementally and freeze to immutable.
        let mut buf = IoBufMut::with_capacity(100);
        assert!(buf.capacity() >= 100);
        assert_eq!(buf.len(), 0);
        buf.put_slice(b"hello");
        buf.put_slice(b" world");
        assert_eq!(buf, b"hello world");
        assert_eq!(buf, &b"hello world"[..]);
        assert_eq!(buf.freeze(), b"hello world");

        // `zeroed` creates readable initialized bytes; `set_len` can shrink safely.
        let mut zeroed = IoBufMut::zeroed(10);
        assert_eq!(zeroed, &[0u8; 10]);
        // SAFETY: shrinking readable length to initialized region.
        unsafe { zeroed.set_len(5) };
        assert_eq!(zeroed, &[0u8; 5]);
        zeroed.as_mut()[..5].copy_from_slice(b"hello");
        assert_eq!(&zeroed.as_ref()[..5], b"hello");
        let frozen = zeroed.freeze();
        let vec: Vec<u8> = frozen.into();
        assert_eq!(&vec[..5], b"hello");

        // Exercise pooled branch behavior for `is_empty`.
        let pool = test_pool();
        let mut pooled = pool.alloc(8);
        assert!(pooled.is_empty());
        pooled.put_slice(b"x");
        assert!(!pooled.is_empty());
    }

    #[test]
    fn test_iobufs_shapes_and_read_paths() {
        // Empty construction normalizes to an empty single chunk.
        let empty = IoBufs::from(Vec::<u8>::new());
        assert!(empty.is_empty());
        assert!(empty.is_single());
        assert!(empty.as_single().is_some());

        // Single-buffer read path.
        let mut single = IoBufs::from(b"hello world");
        assert!(single.is_single());
        assert_eq!(single.chunk(), b"hello world");
        single.advance(6);
        assert_eq!(single.chunk(), b"world");
        assert_eq!(single.copy_to_bytes(5).as_ref(), b"world");
        assert_eq!(single.remaining(), 0);

        // Fast-path shapes (Pair/Triple/Chunked).
        let mut pair = IoBufs::from(IoBuf::from(b"a"));
        pair.append(IoBuf::from(b"b"));
        assert!(matches!(pair.inner, IoBufsInner::Pair(_)));
        assert!(pair.as_single().is_none());

        let mut triple = IoBufs::from(IoBuf::from(b"a"));
        triple.append(IoBuf::from(b"b"));
        triple.append(IoBuf::from(b"c"));
        assert!(matches!(triple.inner, IoBufsInner::Triple(_)));

        let mut chunked = IoBufs::from(IoBuf::from(b"a"));
        chunked.append(IoBuf::from(b"b"));
        chunked.append(IoBuf::from(b"c"));
        chunked.append(IoBuf::from(b"d"));
        assert!(matches!(chunked.inner, IoBufsInner::Chunked(_)));

        // prepend + append preserve ordering.
        let mut joined = IoBufs::from(b"middle");
        joined.prepend(IoBuf::from(b"start "));
        joined.append(IoBuf::from(b" end"));
        assert_eq!(joined.coalesce(), b"start middle end");

        // prepending empty is a no-op, and prepending into pair upgrades to triple.
        let mut prepend_noop = IoBufs::from(b"x");
        prepend_noop.prepend(IoBuf::default());
        assert_eq!(prepend_noop.coalesce(), b"x");

        let mut prepend_pair = IoBufs::from(vec![IoBuf::from(b"b"), IoBuf::from(b"c")]);
        prepend_pair.prepend(IoBuf::from(b"a"));
        assert!(matches!(prepend_pair.inner, IoBufsInner::Triple(_)));
        assert_eq!(prepend_pair.coalesce(), b"abc");

        // canonicalizing a non-empty single should keep the same representation.
        let mut canonical_single = IoBufs::from(b"q");
        canonical_single.canonicalize();
        assert!(canonical_single.is_single());
        assert_eq!(canonical_single.coalesce(), b"q");
    }

    #[test]
    fn test_iobufs_split_to_cases() {
        // Zero and full split on a single chunk.
        let mut bufs = IoBufs::from(b"hello");

        let empty = bufs.split_to(0);
        assert!(empty.is_empty());
        assert_eq!(bufs.coalesce(), b"hello");

        let mut bufs = IoBufs::from(b"hello");
        let all = bufs.split_to(5);
        assert_eq!(all.coalesce(), b"hello");
        assert!(bufs.is_single());
        assert!(bufs.is_empty());

        // Single split in the middle.
        let mut single_mid = IoBufs::from(b"hello");
        let single_prefix = single_mid.split_to(2);
        assert!(single_prefix.is_single());
        assert_eq!(single_prefix.coalesce(), b"he");
        assert_eq!(single_mid.coalesce(), b"llo");

        // Pair split paths: in-first, boundary-after-first, crossing-into-second.
        let mut pair = IoBufs::from(vec![IoBuf::from(b"ab"), IoBuf::from(b"cd")]);
        let pair_prefix = pair.split_to(1);
        assert!(pair_prefix.is_single());
        assert_eq!(pair_prefix.coalesce(), b"a");
        assert!(matches!(pair.inner, IoBufsInner::Pair(_)));
        assert_eq!(pair.coalesce(), b"bcd");

        let mut pair = IoBufs::from(vec![IoBuf::from(b"ab"), IoBuf::from(b"cd")]);
        let pair_prefix = pair.split_to(2);
        assert!(pair_prefix.is_single());
        assert_eq!(pair_prefix.coalesce(), b"ab");
        assert!(pair.is_single());
        assert_eq!(pair.coalesce(), b"cd");

        let mut pair = IoBufs::from(vec![IoBuf::from(b"ab"), IoBuf::from(b"cd")]);
        let pair_prefix = pair.split_to(3);
        assert!(matches!(pair_prefix.inner, IoBufsInner::Pair(_)));
        assert_eq!(pair_prefix.coalesce(), b"abc");
        assert!(pair.is_single());
        assert_eq!(pair.coalesce(), b"d");

        // Triple split paths: in-first, boundary-after-first, in-second, boundary-after-second,
        // and reaching into third.
        let mut triple = IoBufs::from(vec![
            IoBuf::from(b"ab"),
            IoBuf::from(b"cd"),
            IoBuf::from(b"ef"),
        ]);
        let triple_prefix = triple.split_to(1);
        assert!(triple_prefix.is_single());
        assert_eq!(triple_prefix.coalesce(), b"a");
        assert!(matches!(triple.inner, IoBufsInner::Triple(_)));
        assert_eq!(triple.coalesce(), b"bcdef");

        let mut triple = IoBufs::from(vec![
            IoBuf::from(b"ab"),
            IoBuf::from(b"cd"),
            IoBuf::from(b"ef"),
        ]);
        let triple_prefix = triple.split_to(2);
        assert!(triple_prefix.is_single());
        assert_eq!(triple_prefix.coalesce(), b"ab");
        assert!(matches!(triple.inner, IoBufsInner::Pair(_)));
        assert_eq!(triple.coalesce(), b"cdef");

        let mut triple = IoBufs::from(vec![
            IoBuf::from(b"ab"),
            IoBuf::from(b"cd"),
            IoBuf::from(b"ef"),
        ]);
        let triple_prefix = triple.split_to(3);
        assert!(matches!(triple_prefix.inner, IoBufsInner::Pair(_)));
        assert_eq!(triple_prefix.coalesce(), b"abc");
        assert!(matches!(triple.inner, IoBufsInner::Pair(_)));
        assert_eq!(triple.coalesce(), b"def");

        let mut triple = IoBufs::from(vec![
            IoBuf::from(b"ab"),
            IoBuf::from(b"cd"),
            IoBuf::from(b"ef"),
        ]);
        let triple_prefix = triple.split_to(4);
        assert!(matches!(triple_prefix.inner, IoBufsInner::Pair(_)));
        assert_eq!(triple_prefix.coalesce(), b"abcd");
        assert!(triple.is_single());
        assert_eq!(triple.coalesce(), b"ef");

        let mut triple = IoBufs::from(vec![
            IoBuf::from(b"ab"),
            IoBuf::from(b"cd"),
            IoBuf::from(b"ef"),
        ]);
        let triple_prefix = triple.split_to(5);
        assert!(matches!(triple_prefix.inner, IoBufsInner::Triple(_)));
        assert_eq!(triple_prefix.coalesce(), b"abcde");
        assert!(triple.is_single());
        assert_eq!(triple.coalesce(), b"f");

        // Chunked split can canonicalize remainder/prefix shapes.
        let mut bufs = IoBufs::from(vec![
            IoBuf::from(b"ab"),
            IoBuf::from(b"cd"),
            IoBuf::from(b"ef"),
            IoBuf::from(b"gh"),
        ]);
        let prefix = bufs.split_to(4);
        assert!(matches!(prefix.inner, IoBufsInner::Pair(_)));
        assert_eq!(prefix.coalesce(), b"abcd");
        assert!(matches!(bufs.inner, IoBufsInner::Pair(_)));
        assert_eq!(bufs.coalesce(), b"efgh");

        // Chunked split inside a chunk.
        let mut bufs = IoBufs::from(vec![
            IoBuf::from(b"ab"),
            IoBuf::from(b"cd"),
            IoBuf::from(b"ef"),
            IoBuf::from(b"gh"),
        ]);
        let prefix = bufs.split_to(5);
        assert!(matches!(prefix.inner, IoBufsInner::Triple(_)));
        assert_eq!(prefix.coalesce(), b"abcde");
        assert!(matches!(bufs.inner, IoBufsInner::Pair(_)));
        assert_eq!(bufs.coalesce(), b"fgh");

        // Chunked split can remain chunked on both sides when both have >= 4 chunks.
        let mut bufs = IoBufs::from(vec![
            IoBuf::from(b"a"),
            IoBuf::from(b"b"),
            IoBuf::from(b"c"),
            IoBuf::from(b"d"),
            IoBuf::from(b"e"),
            IoBuf::from(b"f"),
            IoBuf::from(b"g"),
            IoBuf::from(b"h"),
        ]);
        let prefix = bufs.split_to(4);
        assert!(matches!(prefix.inner, IoBufsInner::Chunked(_)));
        assert_eq!(prefix.coalesce(), b"abcd");
        assert!(matches!(bufs.inner, IoBufsInner::Chunked(_)));
        assert_eq!(bufs.coalesce(), b"efgh");

        // Defensive path: tolerate accidental empty chunks in non-canonical chunked input.
        let mut bufs = IoBufs {
            inner: IoBufsInner::Chunked(VecDeque::from([
                IoBuf::default(),
                IoBuf::from(b"ab"),
                IoBuf::from(b"cd"),
                IoBuf::from(b"ef"),
                IoBuf::from(b"gh"),
            ])),
        };
        let prefix = bufs.split_to(3);
        assert_eq!(prefix.coalesce(), b"abc");
        assert_eq!(bufs.coalesce(), b"defgh");
    }

    #[test]
    #[should_panic(expected = "split_to out of bounds")]
    fn test_iobufs_split_to_out_of_bounds() {
        let mut bufs = IoBufs::from(b"abc");
        let _ = bufs.split_to(4);
    }

    #[test]
    fn test_iobufs_chunk_count() {
        assert_eq!(IoBufs::default().chunk_count(), 0);
        assert_eq!(IoBufs::from(IoBuf::from(b"a")).chunk_count(), 1);
        assert_eq!(
            IoBufs::from(vec![IoBuf::from(b"b"), IoBuf::from(b"c")]).chunk_count(),
            2
        );
        assert_eq!(
            IoBufs::from(vec![
                IoBuf::from(b"a"),
                IoBuf::from(b"b"),
                IoBuf::from(b"c")
            ])
            .chunk_count(),
            3
        );
        assert_eq!(
            IoBufs::from(vec![
                IoBuf::from(b"a"),
                IoBuf::from(b"b"),
                IoBuf::from(b"c"),
                IoBuf::from(b"d")
            ])
            .chunk_count(),
            4
        );
    }

    #[test]
    fn test_iobufs_coalesce_after_advance() {
        let mut bufs = IoBufs::from(IoBuf::from(b"hello"));
        bufs.append(IoBuf::from(b" world"));

        assert_eq!(bufs.len(), 11);

        bufs.advance(3);
        assert_eq!(bufs.len(), 8);

        assert_eq!(bufs.coalesce(), b"lo world");
    }

    #[test]
    fn test_iobufs_coalesce_with_pool() {
        let pool = test_pool();

        // Single buffer: zero-copy (same pointer)
        let buf = IoBuf::from(vec![1u8, 2, 3, 4, 5]);
        let original_ptr = buf.as_ptr();
        let bufs = IoBufs::from(buf);
        let coalesced = bufs.coalesce_with_pool(&pool);
        assert_eq!(coalesced, [1, 2, 3, 4, 5]);
        assert_eq!(coalesced.as_ptr(), original_ptr);

        // Multiple buffers: merged using pool
        let mut bufs = IoBufs::from(IoBuf::from(b"hello"));
        bufs.append(IoBuf::from(b" world"));
        let coalesced = bufs.coalesce_with_pool(&pool);
        assert_eq!(coalesced, b"hello world");

        // Multiple buffers after advance: only remaining data coalesced
        let mut bufs = IoBufs::from(IoBuf::from(b"hello"));
        bufs.append(IoBuf::from(b" world"));
        bufs.advance(3);
        let coalesced = bufs.coalesce_with_pool(&pool);
        assert_eq!(coalesced, b"lo world");

        // Empty buffers in the middle
        let mut bufs = IoBufs::from(IoBuf::from(b"hello"));
        bufs.append(IoBuf::default());
        bufs.append(IoBuf::from(b" world"));
        let coalesced = bufs.coalesce_with_pool(&pool);
        assert_eq!(coalesced, b"hello world");

        // Empty IoBufs
        let bufs = IoBufs::default();
        let coalesced = bufs.coalesce_with_pool(&pool);
        assert!(coalesced.is_empty());

        // 4+ buffers: exercise chunked coalesce-with-pool path.
        let bufs = IoBufs::from(vec![
            IoBuf::from(b"ab"),
            IoBuf::from(b"cd"),
            IoBuf::from(b"ef"),
            IoBuf::from(b"gh"),
        ]);
        let coalesced = bufs.coalesce_with_pool(&pool);
        assert_eq!(coalesced, b"abcdefgh");
        assert!(coalesced.is_pooled());
    }

    #[test]
    fn test_iobufs_empty_chunks_and_copy_to_bytes_paths() {
        // Empty chunks are skipped while reading across multiple chunks.
        let mut bufs = IoBufs::default();
        bufs.append(IoBuf::from(b"hello"));
        bufs.append(IoBuf::default());
        bufs.append(IoBuf::from(b" "));
        bufs.append(IoBuf::default());
        bufs.append(IoBuf::from(b"world"));
        assert_eq!(bufs.len(), 11);
        assert_eq!(bufs.chunk(), b"hello");
        bufs.advance(5);
        assert_eq!(bufs.chunk(), b" ");
        bufs.advance(1);
        assert_eq!(bufs.chunk(), b"world");

        // Single-buffer copy_to_bytes path.
        let mut single = IoBufs::from(b"hello world");
        assert_eq!(single.copy_to_bytes(5).as_ref(), b"hello");
        assert_eq!(single.remaining(), 6);

        // Multi-buffer copy_to_bytes path across boundaries.
        let mut multi = IoBufs::from(b"hello");
        multi.prepend(IoBuf::from(b"say "));
        assert_eq!(multi.copy_to_bytes(7).as_ref(), b"say hel");
        assert_eq!(multi.copy_to_bytes(2).as_ref(), b"lo");
    }

    #[test]
    fn test_iobufs_copy_to_bytes_pair_and_triple() {
        // Pair: crossing one boundary should collapse to the trailing single chunk.
        let mut pair = IoBufs::from(IoBuf::from(b"ab"));
        pair.append(IoBuf::from(b"cd"));
        let first = pair.copy_to_bytes(3);
        assert_eq!(&first[..], b"abc");
        assert!(pair.is_single());
        assert_eq!(pair.chunk(), b"d");

        // Triple: draining across two chunks leaves the final chunk readable.
        let mut triple = IoBufs::from(IoBuf::from(b"ab"));
        triple.append(IoBuf::from(b"cd"));
        triple.append(IoBuf::from(b"ef"));
        let first = triple.copy_to_bytes(5);
        assert_eq!(&first[..], b"abcde");
        assert!(triple.is_single());
        assert_eq!(triple.chunk(), b"f");
    }

    #[test]
    fn test_iobufs_copy_to_bytes_chunked_four_plus() {
        let mut bufs = IoBufs::from(vec![
            IoBuf::from(b"ab"),
            IoBuf::from(b"cd"),
            IoBuf::from(b"ef"),
            IoBuf::from(b"gh"),
        ]);

        // Chunked fast-path: first chunk alone satisfies request.
        let first = bufs.copy_to_bytes(1);
        assert_eq!(&first[..], b"a");

        // Chunked slow-path: request crosses chunk boundaries.
        let second = bufs.copy_to_bytes(4);
        assert_eq!(&second[..], b"bcde");

        let rest = bufs.copy_to_bytes(3);
        assert_eq!(&rest[..], b"fgh");
        assert_eq!(bufs.remaining(), 0);
    }

    #[test]
    fn test_iobufs_copy_to_bytes_edge_cases() {
        // Leading empty chunk should not affect copied payload.
        let mut iobufs = IoBufs::from(IoBuf::from(b""));
        iobufs.append(IoBuf::from(b"hello"));
        assert_eq!(iobufs.copy_to_bytes(5).as_ref(), b"hello");

        // Boundary-aligned reads should return exact chunk payloads in-order.
        let mut boundary = IoBufs::from(IoBuf::from(b"hello"));
        boundary.append(IoBuf::from(b"world"));
        assert_eq!(boundary.copy_to_bytes(5).as_ref(), b"hello");
        assert_eq!(boundary.copy_to_bytes(5).as_ref(), b"world");
        assert_eq!(boundary.remaining(), 0);
    }

    #[test]
    #[should_panic(expected = "cannot advance past end of buffer")]
    fn test_iobufs_advance_past_end() {
        let mut bufs = IoBufs::from(b"hel");
        bufs.append(IoBuf::from(b"lo"));
        bufs.advance(10);
    }

    #[test]
    #[should_panic(expected = "not enough data")]
    fn test_iobufs_copy_to_bytes_past_end() {
        let mut bufs = IoBufs::from(b"hel");
        bufs.append(IoBuf::from(b"lo"));
        bufs.copy_to_bytes(10);
    }

    #[test]
    fn test_iobufs_matches_bytes_chain() {
        let b1 = Bytes::from_static(b"hello");
        let b2 = Bytes::from_static(b" ");
        let b3 = Bytes::from_static(b"world");

        // Buf parity for remaining/chunk/advance should match `Bytes::chain`.
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
    fn test_iobufs_try_into_single() {
        let single = IoBufs::from(IoBuf::from(b"hello"));
        let single = single.try_into_single().expect("single expected");
        assert_eq!(single, b"hello");

        let multi = IoBufs::from(vec![IoBuf::from(b"ab"), IoBuf::from(b"cd")]);
        let multi = multi.try_into_single().expect_err("multi expected");
        assert_eq!(multi.coalesce(), b"abcd");
    }

    #[test]
    fn test_iobufs_chunks_vectored_multiple_slices() {
        // Single non-empty buffers should export exactly one slice.
        let single = IoBufs::from(IoBuf::from(b"xy"));
        let mut single_dst = [IoSlice::new(&[]); 2];
        let count = single.chunks_vectored(&mut single_dst);
        assert_eq!(count, 1);
        assert_eq!(&single_dst[0][..], b"xy");

        // Single empty buffers should export no slices.
        let empty_single = IoBufs::default();
        let mut empty_single_dst = [IoSlice::new(&[]); 1];
        assert_eq!(empty_single.chunks_vectored(&mut empty_single_dst), 0);

        let bufs = IoBufs::from(vec![
            IoBuf::from(b"ab"),
            IoBuf::from(b"cd"),
            IoBuf::from(b"ef"),
            IoBuf::from(b"gh"),
        ]);

        // Destination capacity should cap how many chunks we export.
        let mut small = [IoSlice::new(&[]); 2];
        let count = bufs.chunks_vectored(&mut small);
        assert_eq!(count, 2);
        assert_eq!(&small[0][..], b"ab");
        assert_eq!(&small[1][..], b"cd");

        // Larger destination should include every readable chunk.
        let mut large = [IoSlice::new(&[]); 8];
        let count = bufs.chunks_vectored(&mut large);
        assert_eq!(count, 4);
        assert_eq!(&large[0][..], b"ab");
        assert_eq!(&large[1][..], b"cd");
        assert_eq!(&large[2][..], b"ef");
        assert_eq!(&large[3][..], b"gh");

        // Empty destination cannot accept any slices.
        let mut empty_dst: [IoSlice<'_>; 0] = [];
        assert_eq!(bufs.chunks_vectored(&mut empty_dst), 0);

        // Non-canonical shapes should skip empty leading chunks.
        let sparse = IoBufs {
            inner: IoBufsInner::Pair([IoBuf::default(), IoBuf::from(b"x")]),
        };
        let mut dst = [IoSlice::new(&[]); 2];
        let count = sparse.chunks_vectored(&mut dst);
        assert_eq!(count, 1);
        assert_eq!(&dst[0][..], b"x");

        // Triple should skip empty chunks and preserve readable order.
        let sparse_triple = IoBufs {
            inner: IoBufsInner::Triple([IoBuf::default(), IoBuf::from(b"y"), IoBuf::from(b"z")]),
        };
        let mut dst = [IoSlice::new(&[]); 3];
        let count = sparse_triple.chunks_vectored(&mut dst);
        assert_eq!(count, 2);
        assert_eq!(&dst[0][..], b"y");
        assert_eq!(&dst[1][..], b"z");

        // Chunked shapes with only empty buffers should export no slices.
        let empty_chunked = IoBufs {
            inner: IoBufsInner::Chunked(VecDeque::from([IoBuf::default(), IoBuf::default()])),
        };
        let mut dst = [IoSlice::new(&[]); 2];
        assert_eq!(empty_chunked.chunks_vectored(&mut dst), 0);
    }

    #[test]
    fn test_iobufsmut_freeze_chunked() {
        // Multiple non-empty buffers stay multi-chunk.
        let buf1 = IoBufMut::from(b"hello".as_ref());
        let buf2 = IoBufMut::from(b" world".as_ref());
        let bufs = IoBufsMut::from(vec![buf1, buf2]);
        let mut frozen = bufs.freeze();
        assert!(!frozen.is_single());
        assert_eq!(frozen.chunk(), b"hello");
        frozen.advance(5);
        assert_eq!(frozen.chunk(), b" world");
        frozen.advance(6);
        assert_eq!(frozen.remaining(), 0);

        // Empty buffers are filtered out.
        let buf1 = IoBufMut::from(b"hello".as_ref());
        let empty = IoBufMut::default();
        let buf2 = IoBufMut::from(b" world".as_ref());
        let bufs = IoBufsMut::from(vec![buf1, empty, buf2]);
        let mut frozen = bufs.freeze();
        assert!(!frozen.is_single());
        assert_eq!(frozen.chunk(), b"hello");
        frozen.advance(5);
        assert_eq!(frozen.chunk(), b" world");
        frozen.advance(6);
        assert_eq!(frozen.remaining(), 0);

        // Collapses to Single when one non-empty buffer remains
        let empty1 = IoBufMut::default();
        let buf = IoBufMut::from(b"only one".as_ref());
        let empty2 = IoBufMut::default();
        let bufs = IoBufsMut::from(vec![empty1, buf, empty2]);
        let frozen = bufs.freeze();
        assert!(frozen.is_single());
        assert_eq!(frozen.coalesce(), b"only one");

        // All empty buffers -> Single with empty buffer
        let empty1 = IoBufMut::default();
        let empty2 = IoBufMut::default();
        let bufs = IoBufsMut::from(vec![empty1, empty2]);
        let frozen = bufs.freeze();
        assert!(frozen.is_single());
        assert!(frozen.is_empty());
    }

    #[test]
    fn test_iobufsmut_coalesce() {
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
        let bufs = IoBufsMut::from(vec![buf1, buf2]);
        let coalesced = bufs.coalesce();
        assert_eq!(coalesced, b"hello world");
    }

    #[test]
    fn test_iobufsmut_from_vec() {
        // Empty Vec becomes Single with empty buffer
        let bufs = IoBufsMut::from(Vec::<IoBufMut>::new());
        assert!(bufs.is_single());
        assert!(bufs.is_empty());

        // Vec with one element becomes Single
        let buf = IoBufMut::from(b"test");
        let bufs = IoBufsMut::from(vec![buf]);
        assert!(bufs.is_single());
        assert_eq!(bufs.chunk(), b"test");

        // Vec with multiple elements becomes multi-chunk.
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
        let bufs = IoBufsMut::from(vec![buf1, buf2]);
        assert!(!bufs.is_single());
    }

    #[test]
    fn test_iobufsmut_from_vec_filters_empty_chunks() {
        let mut bufs = IoBufsMut::from(vec![
            IoBufMut::default(),
            IoBufMut::from(b"hello"),
            IoBufMut::default(),
            IoBufMut::from(b" world"),
            IoBufMut::default(),
        ]);
        assert_eq!(bufs.chunk(), b"hello");
        bufs.advance(5);
        assert_eq!(bufs.chunk(), b" world");
        bufs.advance(6);
        assert_eq!(bufs.remaining(), 0);
    }

    #[test]
    fn test_iobufsmut_fast_path_shapes() {
        let pair = IoBufsMut::from(vec![IoBufMut::from(b"a"), IoBufMut::from(b"b")]);
        assert!(matches!(pair.inner, IoBufsMutInner::Pair(_)));

        let triple = IoBufsMut::from(vec![
            IoBufMut::from(b"a"),
            IoBufMut::from(b"b"),
            IoBufMut::from(b"c"),
        ]);
        assert!(matches!(triple.inner, IoBufsMutInner::Triple(_)));

        let chunked = IoBufsMut::from(vec![
            IoBufMut::from(b"a"),
            IoBufMut::from(b"b"),
            IoBufMut::from(b"c"),
            IoBufMut::from(b"d"),
        ]);
        assert!(matches!(chunked.inner, IoBufsMutInner::Chunked(_)));
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
        let mut buf = IoBufMut::from(b"hello world");
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
        let mut buf = IoBufMut::from(b"hello");
        buf.advance(10);
    }

    #[test]
    fn test_iobufsmut_buf_trait_chunked() {
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" ");
        let buf3 = IoBufMut::from(b"world");
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
    #[should_panic(expected = "cannot advance past end of buffer")]
    fn test_iobufsmut_advance_past_end() {
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
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
        let mut bufs = IoBufs::from(IoBuf::from(b"hello"));
        bufs.append(IoBuf::from(b" "));
        bufs.append(IoBuf::from(b"world"));

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
        let mut bufs = IoBufs::from(IoBuf::from(b"abc"));
        bufs.append(IoBuf::from(b"def"));

        // Advance exactly to first buffer boundary
        bufs.advance(3);
        assert_eq!(bufs.remaining(), 3);
        assert_eq!(bufs.chunk(), b"def");

        // Advance exactly to end
        bufs.advance(3);
        assert_eq!(bufs.remaining(), 0);
    }

    #[test]
    fn test_iobufs_advance_canonicalizes_pair_to_single() {
        let mut bufs = IoBufs::from(IoBuf::from(b"ab"));
        bufs.append(IoBuf::from(b"cd"));
        bufs.advance(2);
        assert!(bufs.is_single());
        assert_eq!(bufs.chunk(), b"cd");
    }

    #[test]
    fn test_iobufsmut_with_empty_buffers() {
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::default();
        let buf3 = IoBufMut::from(b" world");
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
    fn test_iobufsmut_advance_skips_leading_writable_empty_chunk() {
        let empty_writable = IoBufMut::with_capacity(4);
        let payload = IoBufMut::from(b"xy");
        let mut bufs = IoBufsMut::from(vec![empty_writable, payload]);

        bufs.advance(1);
        assert_eq!(bufs.chunk(), b"y");
        assert_eq!(bufs.remaining(), 1);
    }

    #[test]
    fn test_iobufsmut_coalesce_after_advance() {
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        bufs.advance(3);
        assert_eq!(bufs.coalesce(), b"lo world");
    }

    #[test]
    fn test_iobufsmut_copy_to_bytes() {
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        // First read spans chunks and leaves unread suffix.
        let first = bufs.copy_to_bytes(7);
        assert_eq!(&first[..], b"hello w");
        assert_eq!(bufs.remaining(), 4);

        // Second read drains the remainder.
        let rest = bufs.copy_to_bytes(4);
        assert_eq!(&rest[..], b"orld");
        assert_eq!(bufs.remaining(), 0);
    }

    #[test]
    fn test_iobufsmut_copy_to_bytes_chunked_four_plus() {
        let mut bufs = IoBufsMut::from(vec![
            IoBufMut::from(b"ab"),
            IoBufMut::from(b"cd"),
            IoBufMut::from(b"ef"),
            IoBufMut::from(b"gh"),
        ]);

        // Exercise chunked advance path before copy_to_bytes.
        bufs.advance(1);
        assert_eq!(bufs.chunk(), b"b");
        bufs.advance(1);
        assert_eq!(bufs.chunk(), b"cd");

        // Chunked fast-path: first chunk alone satisfies request.
        let first = bufs.copy_to_bytes(1);
        assert_eq!(&first[..], b"c");

        // Chunked slow-path: request crosses chunk boundaries.
        let second = bufs.copy_to_bytes(4);
        assert_eq!(&second[..], b"defg");

        let rest = bufs.copy_to_bytes(1);
        assert_eq!(&rest[..], b"h");
        assert_eq!(bufs.remaining(), 0);

        // Enter copy_to_bytes while still in chunked representation.
        let mut bufs = IoBufsMut::from(vec![
            IoBufMut::from(b"a"),
            IoBufMut::from(b"b"),
            IoBufMut::from(b"c"),
            IoBufMut::from(b"d"),
            IoBufMut::from(b"e"),
        ]);
        assert!(matches!(bufs.inner, IoBufsMutInner::Chunked(_)));
        let first = bufs.copy_to_bytes(1);
        assert_eq!(&first[..], b"a");
        assert_eq!(bufs.remaining(), 4);
    }

    #[test]
    fn test_iobufsmut_copy_to_bytes_canonicalizes_pair() {
        let mut bufs = IoBufsMut::from(vec![IoBufMut::from(b"ab"), IoBufMut::from(b"cd")]);
        assert!(matches!(bufs.inner, IoBufsMutInner::Pair(_)));

        let first = bufs.copy_to_bytes(2);
        assert_eq!(&first[..], b"ab");

        assert!(bufs.is_single());
        assert_eq!(bufs.chunk(), b"cd");
        assert_eq!(bufs.remaining(), 2);
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

        // Verify each chunk was filled correctly.
        assert_eq!(bufs.chunk(), b"hello");
        bufs.advance(5);
        assert_eq!(bufs.chunk(), b" world");
        bufs.advance(6);
        assert_eq!(bufs.remaining(), 0);
    }

    #[test]
    #[should_panic(expected = "source slice length must match buffer length")]
    fn test_iobufsmut_copy_from_slice_wrong_length() {
        let mut bufs = IoBufsMut::from(IoBufMut::zeroed(5));
        bufs.copy_from_slice(b"hello world"); // 11 bytes into 5-byte buffer
    }

    #[test]
    fn test_iobufsmut_matches_bytesmut_chain() {
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
            IoBufMut::from(b"hello"),
            IoBufMut::from(b" world"),
            IoBufMut::from(b"!"),
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
            IoBufMut::from(b"hello"),
            IoBufMut::from(b" world"),
            IoBufMut::from(b"!"),
        ]);

        let chain_bytes = b1.chain(b2).chain(b3).copy_to_bytes(8);
        let iobufs_bytes = iobufs.copy_to_bytes(8);
        assert_eq!(chain_bytes, iobufs_bytes);
        assert_eq!(chain_bytes.as_ref(), b"hello wo");
    }

    #[test]
    fn test_iobufsmut_chunks_vectored_multiple_slices() {
        // Single non-empty buffers should export exactly one slice.
        let single = IoBufsMut::from(IoBufMut::from(b"xy"));
        let mut single_dst = [IoSlice::new(&[]); 2];
        let count = single.chunks_vectored(&mut single_dst);
        assert_eq!(count, 1);
        assert_eq!(&single_dst[0][..], b"xy");

        // Single empty buffers should export no slices.
        let empty_single = IoBufsMut::default();
        let mut empty_single_dst = [IoSlice::new(&[]); 1];
        assert_eq!(empty_single.chunks_vectored(&mut empty_single_dst), 0);

        let bufs = IoBufsMut::from(vec![
            IoBufMut::from(b"ab"),
            IoBufMut::from(b"cd"),
            IoBufMut::from(b"ef"),
            IoBufMut::from(b"gh"),
        ]);

        // Destination capacity should cap how many chunks we export.
        let mut small = [IoSlice::new(&[]); 2];
        let count = bufs.chunks_vectored(&mut small);
        assert_eq!(count, 2);
        assert_eq!(&small[0][..], b"ab");
        assert_eq!(&small[1][..], b"cd");

        // Larger destination should include every readable chunk.
        let mut large = [IoSlice::new(&[]); 8];
        let count = bufs.chunks_vectored(&mut large);
        assert_eq!(count, 4);
        assert_eq!(&large[0][..], b"ab");
        assert_eq!(&large[1][..], b"cd");
        assert_eq!(&large[2][..], b"ef");
        assert_eq!(&large[3][..], b"gh");

        // Empty destination cannot accept any slices.
        let mut empty_dst: [IoSlice<'_>; 0] = [];
        assert_eq!(bufs.chunks_vectored(&mut empty_dst), 0);

        // Non-canonical shapes should skip empty leading chunks.
        let sparse = IoBufsMut {
            inner: IoBufsMutInner::Pair([IoBufMut::default(), IoBufMut::from(b"y")]),
        };
        let mut dst = [IoSlice::new(&[]); 2];
        let count = sparse.chunks_vectored(&mut dst);
        assert_eq!(count, 1);
        assert_eq!(&dst[0][..], b"y");

        // Triple should skip empty chunks and preserve readable order.
        let sparse_triple = IoBufsMut {
            inner: IoBufsMutInner::Triple([
                IoBufMut::default(),
                IoBufMut::from(b"z"),
                IoBufMut::from(b"w"),
            ]),
        };
        let mut dst = [IoSlice::new(&[]); 3];
        let count = sparse_triple.chunks_vectored(&mut dst);
        assert_eq!(count, 2);
        assert_eq!(&dst[0][..], b"z");
        assert_eq!(&dst[1][..], b"w");

        // Chunked shapes with only empty buffers should export no slices.
        let empty_chunked = IoBufsMut {
            inner: IoBufsMutInner::Chunked(VecDeque::from([
                IoBufMut::default(),
                IoBufMut::default(),
            ])),
        };
        let mut dst = [IoSlice::new(&[]); 2];
        assert_eq!(empty_chunked.chunks_vectored(&mut dst), 0);
    }

    #[test]
    fn test_iobufsmut_try_into_single() {
        let single = IoBufsMut::from(IoBufMut::from(b"hello"));
        let single = single.try_into_single().expect("single expected");
        assert_eq!(single, b"hello");

        let multi = IoBufsMut::from(vec![IoBufMut::from(b"ab"), IoBufMut::from(b"cd")]);
        let multi = multi.try_into_single().expect_err("multi expected");
        assert_eq!(multi.coalesce(), b"abcd");
    }

    #[test]
    fn test_iobufsmut_freeze_after_advance() {
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        // Advance partway through first buffer
        bufs.advance(3);
        assert_eq!(bufs.len(), 8);

        // Freeze and verify only remaining data is preserved
        let frozen = bufs.freeze();
        assert_eq!(frozen.len(), 8);
        assert_eq!(frozen.coalesce(), b"lo world");
    }

    #[test]
    fn test_iobufsmut_freeze_after_advance_to_boundary() {
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        // Advance exactly to first buffer boundary
        bufs.advance(5);
        assert_eq!(bufs.len(), 6);

        // First buffer should be fully consumed (empty after advance)
        // freeze() filters empty buffers, so result should be Single
        let frozen = bufs.freeze();
        assert!(frozen.is_single());
        assert_eq!(frozen.coalesce(), b" world");
    }

    #[test]
    fn test_iobufsmut_coalesce_after_advance_to_boundary() {
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        // Advance exactly past first buffer
        bufs.advance(5);

        // Coalesce should only include second buffer's data
        assert_eq!(bufs.coalesce(), b" world");
    }

    #[test]
    fn test_iobufsmut_coalesce_with_pool() {
        let pool = test_pool();

        // Single buffer: zero-copy (same pointer)
        let mut buf = IoBufMut::from(b"hello");
        let original_ptr = buf.as_mut_ptr();
        let bufs = IoBufsMut::from(buf);
        let coalesced = bufs.coalesce_with_pool(&pool);
        assert_eq!(coalesced, b"hello");
        assert_eq!(coalesced.as_ref().as_ptr(), original_ptr);

        // Multiple buffers: merged using pool
        let bufs = IoBufsMut::from(vec![IoBufMut::from(b"hello"), IoBufMut::from(b" world")]);
        let coalesced = bufs.coalesce_with_pool(&pool);
        assert_eq!(coalesced, b"hello world");
        assert!(coalesced.is_pooled());

        // With extra capacity: zero-copy if sufficient spare capacity
        let mut buf = IoBufMut::with_capacity(100);
        buf.put_slice(b"hello");
        let original_ptr = buf.as_mut_ptr();
        let bufs = IoBufsMut::from(buf);
        let coalesced = bufs.coalesce_with_pool_extra(&pool, 10);
        assert_eq!(coalesced, b"hello");
        assert_eq!(coalesced.as_ref().as_ptr(), original_ptr);

        // With extra capacity: reallocates if insufficient
        let mut buf = IoBufMut::with_capacity(5);
        buf.put_slice(b"hello");
        let bufs = IoBufsMut::from(buf);
        let coalesced = bufs.coalesce_with_pool_extra(&pool, 100);
        assert_eq!(coalesced, b"hello");
        assert!(coalesced.capacity() >= 105);
    }

    #[test]
    fn test_iobuf_additional_conversion_and_trait_paths() {
        let pool = test_pool();

        let mut pooled_mut = pool.alloc(4);
        pooled_mut.put_slice(b"data");
        let pooled = pooled_mut.freeze();
        assert!(!pooled.as_ptr().is_null());

        let unique = IoBuf::from(Bytes::from(vec![1u8, 2, 3]));
        let unique_mut = unique.try_into_mut().expect("unique bytes should convert");
        assert_eq!(unique_mut.as_ref(), &[1u8, 2, 3]);

        let shared = IoBuf::from(Bytes::from(vec![4u8, 5, 6]));
        let _shared_clone = shared.clone();
        assert!(shared.try_into_mut().is_err());

        let expected: &[u8] = &[9u8, 8];
        let eq_buf = IoBuf::from(vec![9u8, 8]);
        assert!(PartialEq::<[u8]>::eq(&eq_buf, expected));

        let static_slice: &'static [u8] = b"static";
        assert_eq!(IoBuf::from(static_slice), b"static");

        let mut pooled_mut = pool.alloc(3);
        pooled_mut.put_slice(b"xyz");
        let pooled = pooled_mut.freeze();
        let vec_out: Vec<u8> = pooled.clone().into();
        let bytes_out: Bytes = pooled.into();
        assert_eq!(vec_out, b"xyz");
        assert_eq!(bytes_out.as_ref(), b"xyz");
    }

    #[test]
    fn test_iobufmut_additional_conversion_and_trait_paths() {
        // Basic mutable operations should keep readable bytes consistent.
        let mut buf = IoBufMut::from(vec![1u8, 2, 3, 4]);
        assert!(!buf.is_empty());
        buf.truncate(2);
        assert_eq!(buf.as_ref(), &[1u8, 2]);
        buf.clear();
        assert!(buf.is_empty());
        buf.put_slice(b"xyz");

        // Equality should work across slice, array, and byte-string forms.
        let expected: &[u8] = b"xyz";
        assert!(PartialEq::<[u8]>::eq(&buf, expected));
        assert!(buf == b"xyz"[..]);
        assert!(buf == [b'x', b'y', b'z']);
        assert!(buf == b"xyz");

        // Conversions from common owned/shared containers preserve contents.
        let from_vec = IoBufMut::from(vec![7u8, 8]);
        assert_eq!(from_vec.as_ref(), &[7u8, 8]);

        let from_bytesmut = IoBufMut::from(BytesMut::from(&b"hi"[..]));
        assert_eq!(from_bytesmut.as_ref(), b"hi");

        let from_bytes = IoBufMut::from(Bytes::from_static(b"ok"));
        assert_eq!(from_bytes.as_ref(), b"ok");

        // `Bytes::from_static` cannot be converted to mutable without copy.
        let from_iobuf = IoBufMut::from(IoBuf::from(Bytes::from_static(b"io")));
        assert_eq!(from_iobuf.as_ref(), b"io");
    }

    #[test]
    fn test_iobufs_additional_shape_and_conversion_paths() {
        let pool = test_pool();

        // Constructor coverage for mutable/immutable/slice-backed inputs.
        let from_mut = IoBufs::from(IoBufMut::from(b"m"));
        assert_eq!(from_mut.chunk(), b"m");
        let from_bytes = IoBufs::from(Bytes::from_static(b"b"));
        assert_eq!(from_bytes.chunk(), b"b");
        let from_bytesmut = IoBufs::from(BytesMut::from(&b"bm"[..]));
        assert_eq!(from_bytesmut.chunk(), b"bm");
        let from_vec = IoBufs::from(vec![1u8, 2u8]);
        assert_eq!(from_vec.chunk(), &[1u8, 2]);
        let static_slice: &'static [u8] = b"slice";
        let from_static = IoBufs::from(static_slice);
        assert_eq!(from_static.chunk(), b"slice");

        // Canonicalizing an already-empty buffer remains a single empty chunk.
        let mut single_empty = IoBufs::default();
        single_empty.canonicalize();
        assert!(single_empty.is_single());

        // Triple path: prepend/append can promote into chunked while preserving order.
        let mut triple = IoBufs::from(vec![
            IoBuf::from(b"a".to_vec()),
            IoBuf::from(b"b".to_vec()),
            IoBuf::from(b"c".to_vec()),
        ]);
        assert!(triple.as_single().is_none());
        triple.prepend(IoBuf::from(vec![b'0']));
        triple.prepend(IoBuf::from(vec![b'1']));
        triple.append(IoBuf::from(vec![b'2']));
        assert_eq!(triple.copy_to_bytes(triple.remaining()).as_ref(), b"10abc2");

        // Appending to an existing triple keeps byte order stable.
        let mut triple_append = IoBufs::from(vec![
            IoBuf::from(b"x".to_vec()),
            IoBuf::from(b"y".to_vec()),
            IoBuf::from(b"z".to_vec()),
        ]);
        triple_append.append(IoBuf::from(vec![b'w']));
        assert_eq!(triple_append.coalesce(), b"xyzw");

        // coalesce_with_pool on a triple should preserve contents.
        let triple_pool = IoBufs::from(vec![
            IoBuf::from(b"a".to_vec()),
            IoBuf::from(b"b".to_vec()),
            IoBuf::from(b"c".to_vec()),
        ]);
        assert_eq!(triple_pool.coalesce_with_pool(&pool), b"abc");

        // coalesce_with_pool on 4+ chunks should read only remaining bytes.
        let mut chunked_pool = IoBufs::from(vec![
            IoBuf::from(b"a".to_vec()),
            IoBuf::from(b"b".to_vec()),
            IoBuf::from(b"c".to_vec()),
            IoBuf::from(b"d".to_vec()),
        ]);
        assert_eq!(chunked_pool.remaining(), 4);
        chunked_pool.advance(1);
        assert_eq!(chunked_pool.coalesce_with_pool(&pool), b"bcd");

        // Non-canonical Pair/Triple/Chunked shapes should still expose the first readable chunk.
        let pair_second = IoBufs {
            inner: IoBufsInner::Pair([IoBuf::default(), IoBuf::from(vec![1u8])]),
        };
        assert_eq!(pair_second.chunk(), &[1u8]);
        let pair_empty = IoBufs {
            inner: IoBufsInner::Pair([IoBuf::default(), IoBuf::default()]),
        };
        assert_eq!(pair_empty.chunk(), b"");

        let triple_third = IoBufs {
            inner: IoBufsInner::Triple([
                IoBuf::default(),
                IoBuf::default(),
                IoBuf::from(vec![3u8]),
            ]),
        };
        assert_eq!(triple_third.chunk(), &[3u8]);
        let triple_second = IoBufs {
            inner: IoBufsInner::Triple([
                IoBuf::default(),
                IoBuf::from(vec![2u8]),
                IoBuf::default(),
            ]),
        };
        assert_eq!(triple_second.chunk(), &[2u8]);
        let triple_empty = IoBufs {
            inner: IoBufsInner::Triple([IoBuf::default(), IoBuf::default(), IoBuf::default()]),
        };
        assert_eq!(triple_empty.chunk(), b"");

        let chunked_second = IoBufs {
            inner: IoBufsInner::Chunked(VecDeque::from([IoBuf::default(), IoBuf::from(vec![9u8])])),
        };
        assert_eq!(chunked_second.chunk(), &[9u8]);
        let chunked_empty = IoBufs {
            inner: IoBufsInner::Chunked(VecDeque::from([IoBuf::default()])),
        };
        assert_eq!(chunked_empty.chunk(), b"");
    }

    #[test]
    fn test_iobufsmut_additional_shape_and_conversion_paths() {
        // `as_single` accessors should work only for single-shape containers.
        let mut single = IoBufsMut::from(IoBufMut::from(b"x"));
        assert!(single.as_single().is_some());
        assert!(single.as_single_mut().is_some());
        single.canonicalize();
        assert!(single.is_single());

        let mut pair = IoBufsMut::from(vec![IoBufMut::from(b"a"), IoBufMut::from(b"b")]);
        assert!(pair.as_single().is_none());
        assert!(pair.as_single_mut().is_none());

        // Constructor coverage for raw vec and BytesMut sources.
        let from_vec = IoBufsMut::from(vec![1u8, 2u8]);
        assert_eq!(from_vec.chunk(), &[1u8, 2]);
        let from_bytesmut = IoBufsMut::from(BytesMut::from(&b"cd"[..]));
        assert_eq!(from_bytesmut.chunk(), b"cd");

        // Chunked write path: set_len + copy_from_slice + freeze round-trip.
        let mut chunked = IoBufsMut::from(vec![
            IoBufMut::with_capacity(1),
            IoBufMut::with_capacity(1),
            IoBufMut::with_capacity(1),
            IoBufMut::with_capacity(1),
        ]);
        // SAFETY: We only write/read initialized bytes after `copy_from_slice`.
        unsafe { chunked.set_len(4) };
        chunked.copy_from_slice(b"wxyz");
        assert_eq!(chunked.capacity(), 4);
        assert_eq!(chunked.remaining(), 4);
        let frozen = chunked.freeze();
        assert_eq!(frozen.coalesce(), b"wxyz");
    }

    #[test]
    fn test_iobufsmut_coalesce_multi_shape_paths() {
        let pool = test_pool();

        // Pair: plain coalesce and pool-backed coalesce-with-extra.
        let pair = IoBufsMut::from(vec![IoBufMut::from(b"ab"), IoBufMut::from(b"cd")]);
        assert_eq!(pair.coalesce(), b"abcd");
        let pair = IoBufsMut::from(vec![IoBufMut::from(b"ab"), IoBufMut::from(b"cd")]);
        let pair_extra = pair.coalesce_with_pool_extra(&pool, 3);
        assert_eq!(pair_extra, b"abcd");
        assert!(pair_extra.capacity() >= 7);

        // Triple: both coalesce paths should preserve payload and requested spare capacity.
        let triple = IoBufsMut::from(vec![
            IoBufMut::from(b"a"),
            IoBufMut::from(b"b"),
            IoBufMut::from(b"c"),
        ]);
        assert_eq!(triple.coalesce(), b"abc");
        let triple = IoBufsMut::from(vec![
            IoBufMut::from(b"a"),
            IoBufMut::from(b"b"),
            IoBufMut::from(b"c"),
        ]);
        let triple_extra = triple.coalesce_with_pool_extra(&pool, 2);
        assert_eq!(triple_extra, b"abc");
        assert!(triple_extra.capacity() >= 5);

        // Chunked (4+): same expectations as pair/triple for content + capacity.
        let chunked = IoBufsMut::from(vec![
            IoBufMut::from(b"1"),
            IoBufMut::from(b"2"),
            IoBufMut::from(b"3"),
            IoBufMut::from(b"4"),
        ]);
        assert_eq!(chunked.coalesce(), b"1234");
        let chunked = IoBufsMut::from(vec![
            IoBufMut::from(b"1"),
            IoBufMut::from(b"2"),
            IoBufMut::from(b"3"),
            IoBufMut::from(b"4"),
        ]);
        let chunked_extra = chunked.coalesce_with_pool_extra(&pool, 5);
        assert_eq!(chunked_extra, b"1234");
        assert!(chunked_extra.capacity() >= 9);
    }

    #[test]
    fn test_iobufsmut_noncanonical_chunk_and_chunk_mut_paths() {
        fn no_spare_capacity_buf(pool: &BufferPool) -> IoBufMut {
            let mut buf = pool.alloc(1);
            let cap = buf.capacity();
            // SAFETY: We never read from this buffer in this helper.
            unsafe { buf.set_len(cap) };
            buf
        }
        let pool = test_pool();

        // `chunk()` should skip empty front buffers across all shapes.
        let pair_second = IoBufsMut {
            inner: IoBufsMutInner::Pair([IoBufMut::default(), IoBufMut::from(b"b")]),
        };
        assert_eq!(pair_second.chunk(), b"b");
        let pair_empty = IoBufsMut {
            inner: IoBufsMutInner::Pair([IoBufMut::default(), IoBufMut::default()]),
        };
        assert_eq!(pair_empty.chunk(), b"");

        let triple_third = IoBufsMut {
            inner: IoBufsMutInner::Triple([
                IoBufMut::default(),
                IoBufMut::default(),
                IoBufMut::from(b"c"),
            ]),
        };
        assert_eq!(triple_third.chunk(), b"c");
        let triple_second = IoBufsMut {
            inner: IoBufsMutInner::Triple([
                IoBufMut::default(),
                IoBufMut::from(b"b"),
                IoBufMut::default(),
            ]),
        };
        assert_eq!(triple_second.chunk(), b"b");
        let triple_empty = IoBufsMut {
            inner: IoBufsMutInner::Triple([
                IoBufMut::default(),
                IoBufMut::default(),
                IoBufMut::default(),
            ]),
        };
        assert_eq!(triple_empty.chunk(), b"");

        let chunked_second = IoBufsMut {
            inner: IoBufsMutInner::Chunked(VecDeque::from([
                IoBufMut::default(),
                IoBufMut::from(b"d"),
            ])),
        };
        assert_eq!(chunked_second.chunk(), b"d");
        let chunked_empty = IoBufsMut {
            inner: IoBufsMutInner::Chunked(VecDeque::from([IoBufMut::default()])),
        };
        assert_eq!(chunked_empty.chunk(), b"");

        // `chunk_mut()` should skip non-writable fronts and return first writable chunk.
        let mut pair_chunk_mut = IoBufsMut {
            inner: IoBufsMutInner::Pair([no_spare_capacity_buf(&pool), IoBufMut::with_capacity(2)]),
        };
        assert!(pair_chunk_mut.chunk_mut().len() >= 2);

        let mut pair_chunk_mut_empty = IoBufsMut {
            inner: IoBufsMutInner::Pair([
                no_spare_capacity_buf(&pool),
                no_spare_capacity_buf(&pool),
            ]),
        };
        assert_eq!(pair_chunk_mut_empty.chunk_mut().len(), 0);

        let mut triple_chunk_mut = IoBufsMut {
            inner: IoBufsMutInner::Triple([
                no_spare_capacity_buf(&pool),
                no_spare_capacity_buf(&pool),
                IoBufMut::with_capacity(3),
            ]),
        };
        assert!(triple_chunk_mut.chunk_mut().len() >= 3);
        let mut triple_chunk_mut_second = IoBufsMut {
            inner: IoBufsMutInner::Triple([
                no_spare_capacity_buf(&pool),
                IoBufMut::with_capacity(2),
                no_spare_capacity_buf(&pool),
            ]),
        };
        assert!(triple_chunk_mut_second.chunk_mut().len() >= 2);

        let mut triple_chunk_mut_empty = IoBufsMut {
            inner: IoBufsMutInner::Triple([
                no_spare_capacity_buf(&pool),
                no_spare_capacity_buf(&pool),
                no_spare_capacity_buf(&pool),
            ]),
        };
        assert_eq!(triple_chunk_mut_empty.chunk_mut().len(), 0);

        let mut chunked_chunk_mut = IoBufsMut {
            inner: IoBufsMutInner::Chunked(VecDeque::from([
                IoBufMut::default(),
                IoBufMut::with_capacity(4),
            ])),
        };
        assert!(chunked_chunk_mut.chunk_mut().len() >= 4);

        let mut chunked_chunk_mut_empty = IoBufsMut {
            inner: IoBufsMutInner::Chunked(VecDeque::from([no_spare_capacity_buf(&pool)])),
        };
        assert_eq!(chunked_chunk_mut_empty.chunk_mut().len(), 0);
    }

    #[test]
    fn test_iobuf_internal_chunk_helpers() {
        // `copy_to_bytes_chunked` should drop leading empties on zero-length reads.
        let mut empty_with_leading = VecDeque::from([IoBuf::default()]);
        let (bytes, needs_canonicalize) = copy_to_bytes_chunked(&mut empty_with_leading, 0, "x");
        assert!(bytes.is_empty());
        assert!(!needs_canonicalize);
        assert!(empty_with_leading.is_empty());

        // Fast path: front chunk can fully satisfy the request.
        let mut fast = VecDeque::from([
            IoBuf::from(b"ab".to_vec()),
            IoBuf::from(b"cd".to_vec()),
            IoBuf::from(b"ef".to_vec()),
            IoBuf::from(b"gh".to_vec()),
        ]);
        let (bytes, needs_canonicalize) = copy_to_bytes_chunked(&mut fast, 2, "x");
        assert_eq!(bytes.as_ref(), b"ab");
        assert!(needs_canonicalize);
        assert_eq!(fast.front().expect("front exists").as_ref(), b"cd");

        // Slow path: request spans multiple chunks.
        let mut slow = VecDeque::from([
            IoBuf::from(b"a".to_vec()),
            IoBuf::from(b"bc".to_vec()),
            IoBuf::from(b"d".to_vec()),
            IoBuf::from(b"e".to_vec()),
        ]);
        let (bytes, needs_canonicalize) = copy_to_bytes_chunked(&mut slow, 3, "x");
        assert_eq!(bytes.as_ref(), b"abc");
        assert!(needs_canonicalize);

        // `advance_chunked_front` should skip empties and drain in linear order.
        let mut advance_chunked = VecDeque::from([
            IoBuf::default(),
            IoBuf::from(b"abc".to_vec()),
            IoBuf::from(b"d".to_vec()),
        ]);
        advance_chunked_front(&mut advance_chunked, 2);
        assert_eq!(
            advance_chunked.front().expect("front exists").as_ref(),
            b"c"
        );
        advance_chunked_front(&mut advance_chunked, 2);
        assert!(advance_chunked.is_empty());

        // `advance_small_chunks` signals canonicalization when front chunks are exhausted.
        let mut small = [IoBuf::default(), IoBuf::from(b"abc".to_vec())];
        let needs_canonicalize = advance_small_chunks(&mut small, 2);
        assert!(needs_canonicalize);
        assert_eq!(small[1].as_ref(), b"c");

        let mut small_exact = [
            IoBuf::from(b"a".to_vec()),
            IoBuf::from(b"b".to_vec()),
            IoBuf::from(b"c".to_vec()),
        ];
        let needs_canonicalize = advance_small_chunks(&mut small_exact, 3);
        assert!(needs_canonicalize);
        assert_eq!(small_exact[0].remaining(), 0);
        assert_eq!(small_exact[1].remaining(), 0);
        assert_eq!(small_exact[2].remaining(), 0);

        // `advance_mut_in_chunks` returns whether the request fully fit in writable chunks.
        let mut writable = [IoBufMut::with_capacity(2), IoBufMut::with_capacity(1)];
        let mut remaining = 3usize;
        // SAFETY: We do not read from advanced bytes in this test.
        let all_advanced = unsafe { advance_mut_in_chunks(&mut writable, &mut remaining) };
        assert!(all_advanced);
        assert_eq!(remaining, 0);

        // `advance_mut_in_chunks` should skip non-writable chunks.
        let pool = test_pool();
        let mut full = pool.alloc(1);
        // SAFETY: We only mark initialized capacity; bytes are not read.
        unsafe { full.set_len(full.capacity()) };
        let mut writable_after_full = [full, IoBufMut::with_capacity(2)];
        let mut remaining = 2usize;
        // SAFETY: We do not read from advanced bytes in this test.
        let all_advanced =
            unsafe { advance_mut_in_chunks(&mut writable_after_full, &mut remaining) };
        assert!(all_advanced);
        assert_eq!(remaining, 0);

        let mut writable_short = [IoBufMut::with_capacity(1), IoBufMut::with_capacity(1)];
        let mut remaining = 3usize;
        // SAFETY: We do not read from advanced bytes in this test.
        let all_advanced = unsafe { advance_mut_in_chunks(&mut writable_short, &mut remaining) };
        assert!(!all_advanced);
        assert_eq!(remaining, 1);
    }

    #[test]
    fn test_iobufsmut_advance_mut_success_paths() {
        // Pair path.
        let mut pair = IoBufsMut {
            inner: IoBufsMutInner::Pair([IoBufMut::with_capacity(2), IoBufMut::with_capacity(2)]),
        };
        // SAFETY: We only verify cursor movement (`remaining`) and do not read bytes.
        unsafe { pair.advance_mut(3) };
        assert_eq!(pair.remaining(), 3);

        // Triple path.
        let mut triple = IoBufsMut {
            inner: IoBufsMutInner::Triple([
                IoBufMut::with_capacity(1),
                IoBufMut::with_capacity(1),
                IoBufMut::with_capacity(1),
            ]),
        };
        // SAFETY: We only verify cursor movement (`remaining`) and do not read bytes.
        unsafe { triple.advance_mut(2) };
        assert_eq!(triple.remaining(), 2);

        // Chunked wrapped-VecDeque path.
        let mut wrapped = VecDeque::with_capacity(5);
        wrapped.push_back(IoBufMut::with_capacity(1));
        wrapped.push_back(IoBufMut::with_capacity(1));
        wrapped.push_back(IoBufMut::with_capacity(1));
        let _ = wrapped.pop_front();
        wrapped.push_back(IoBufMut::with_capacity(1));
        wrapped.push_back(IoBufMut::with_capacity(1));
        let mut chunked = IoBufsMut {
            inner: IoBufsMutInner::Chunked(wrapped),
        };
        // SAFETY: We only verify cursor movement (`remaining`) and do not read bytes.
        unsafe { chunked.advance_mut(4) };
        assert_eq!(chunked.remaining(), 4);
        assert!(chunked.remaining_mut() > 0);
    }

    #[test]
    fn test_iobufsmut_advance_mut_zero_noop_when_full() {
        fn full_chunk(pool: &BufferPool) -> IoBufMut {
            // Pooled buffers have bounded class capacity (unlike growable Bytes),
            // so force len == capacity to make remaining_mut() == 0.
            let mut buf = pool.alloc(1);
            let cap = buf.capacity();
            // SAFETY: We never read from this buffer in this test.
            unsafe { buf.set_len(cap) };
            buf
        }

        let pool = test_pool();

        // Pair path: fully-written chunks should allow advance_mut(0) as a no-op.
        let mut pair = IoBufsMut::from(vec![full_chunk(&pool), full_chunk(&pool)]);
        assert!(matches!(pair.inner, IoBufsMutInner::Pair(_)));
        assert_eq!(pair.remaining_mut(), 0);
        let before = pair.remaining();
        // SAFETY: Advancing by 0 does not expose uninitialized bytes.
        unsafe { pair.advance_mut(0) };
        assert_eq!(pair.remaining(), before);

        // Triple path: same no-op behavior.
        let mut triple = IoBufsMut::from(vec![
            full_chunk(&pool),
            full_chunk(&pool),
            full_chunk(&pool),
        ]);
        assert!(matches!(triple.inner, IoBufsMutInner::Triple(_)));
        assert_eq!(triple.remaining_mut(), 0);
        let before = triple.remaining();
        // SAFETY: Advancing by 0 does not expose uninitialized bytes.
        unsafe { triple.advance_mut(0) };
        assert_eq!(triple.remaining(), before);

        // Chunked path: 4+ fully-written chunks should also no-op.
        let mut chunked = IoBufsMut::from(vec![
            full_chunk(&pool),
            full_chunk(&pool),
            full_chunk(&pool),
            full_chunk(&pool),
        ]);
        assert!(matches!(chunked.inner, IoBufsMutInner::Chunked(_)));
        assert_eq!(chunked.remaining_mut(), 0);
        let before = chunked.remaining();
        // SAFETY: Advancing by 0 does not expose uninitialized bytes.
        unsafe { chunked.advance_mut(0) };
        assert_eq!(chunked.remaining(), before);
    }

    #[test]
    #[should_panic(expected = "cannot advance past end of buffer")]
    fn test_iobufsmut_advance_mut_past_end_pair() {
        let mut pair = IoBufsMut {
            inner: IoBufsMutInner::Pair([IoBufMut::with_capacity(1), IoBufMut::with_capacity(1)]),
        };
        // SAFETY: Intentional panic path coverage.
        unsafe { pair.advance_mut(3) };
    }

    #[test]
    #[should_panic(expected = "cannot advance past end of buffer")]
    fn test_iobufsmut_advance_mut_past_end_triple() {
        let mut triple = IoBufsMut {
            inner: IoBufsMutInner::Triple([
                IoBufMut::with_capacity(1),
                IoBufMut::with_capacity(1),
                IoBufMut::with_capacity(1),
            ]),
        };
        // SAFETY: Intentional panic path coverage.
        unsafe { triple.advance_mut(4) };
    }

    #[test]
    #[should_panic(expected = "cannot advance past end of buffer")]
    fn test_iobufsmut_advance_mut_past_end_chunked() {
        let mut chunked = IoBufsMut {
            inner: IoBufsMutInner::Chunked(VecDeque::from([
                IoBufMut::with_capacity(1),
                IoBufMut::with_capacity(1),
                IoBufMut::with_capacity(1),
                IoBufMut::with_capacity(1),
            ])),
        };
        // SAFETY: Intentional panic path coverage.
        unsafe { chunked.advance_mut(5) };
    }

    #[test]
    fn test_iobufsmut_set_len() {
        // SAFETY: we don't read the uninitialized bytes.
        unsafe {
            // Single buffer
            let mut bufs = IoBufsMut::from(IoBufMut::with_capacity(16));
            bufs.set_len(10);
            assert_eq!(bufs.len(), 10);

            // Chunked: distributes across chunks [cap 5, cap 10], set 12 -> [5, 7]
            let mut bufs = IoBufsMut::from(vec![
                IoBufMut::with_capacity(5),
                IoBufMut::with_capacity(10),
            ]);
            bufs.set_len(12);
            assert_eq!(bufs.len(), 12);
            assert_eq!(bufs.chunk().len(), 5);
            bufs.advance(5);
            assert_eq!(bufs.chunk().len(), 7);
            bufs.advance(7);
            assert_eq!(bufs.remaining(), 0);

            // Uneven capacities [3, 20, 2], set 18 -> [3, 15, 0].
            let mut bufs = IoBufsMut::from(vec![
                IoBufMut::with_capacity(3),
                IoBufMut::with_capacity(20),
                IoBufMut::with_capacity(2),
            ]);
            bufs.set_len(18);
            assert_eq!(bufs.chunk().len(), 3);
            bufs.advance(3);
            assert_eq!(bufs.chunk().len(), 15);
            bufs.advance(15);
            assert_eq!(bufs.remaining(), 0);

            // Exact total capacity [4, 4], set 8 -> [4, 4]
            let mut bufs =
                IoBufsMut::from(vec![IoBufMut::with_capacity(4), IoBufMut::with_capacity(4)]);
            bufs.set_len(8);
            assert_eq!(bufs.chunk().len(), 4);
            bufs.advance(4);
            assert_eq!(bufs.chunk().len(), 4);
            bufs.advance(4);
            assert_eq!(bufs.remaining(), 0);

            // Zero length preserves caller-provided layout.
            let mut bufs =
                IoBufsMut::from(vec![IoBufMut::with_capacity(4), IoBufMut::with_capacity(4)]);
            bufs.set_len(0);
            assert_eq!(bufs.len(), 0);
            assert_eq!(bufs.chunk(), b"");
        }
    }

    #[test]
    #[should_panic(expected = "set_len(9) exceeds capacity(8)")]
    fn test_iobufsmut_set_len_overflow() {
        let mut bufs =
            IoBufsMut::from(vec![IoBufMut::with_capacity(4), IoBufMut::with_capacity(4)]);
        // SAFETY: this will panic before any read.
        unsafe { bufs.set_len(9) };
    }

    #[test]
    #[should_panic(expected = "set_len(9) exceeds capacity(8)")]
    fn test_iobufmut_set_len_overflow() {
        let mut buf = IoBufMut::with_capacity(8);
        // SAFETY: this will panic before any read.
        unsafe { buf.set_len(9) };
    }

    #[test]
    fn test_encode_with_pool_matches_encode() {
        let pool = test_pool();
        let value = vec![1u8, 2, 3, 4, 5, 6];

        let pooled = value.encode_with_pool(&pool);
        let baseline = value.encode();
        assert_eq!(pooled.as_ref(), baseline.as_ref());
    }

    #[test]
    fn test_encode_with_pool_mut_len_matches_encode_size() {
        let pool = test_pool();
        let value = vec![9u8, 8, 7, 6];

        let buf = value.encode_with_pool_mut(&pool);
        assert_eq!(buf.len(), value.encode_size());
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
