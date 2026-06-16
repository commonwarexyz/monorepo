//! Buffer types for I/O operations.
//!
//! `IoBuf` and `IoBufMut` store readable/writable cursor state directly in the
//! public handle. Allocation ownership lives in a compact tagged owner
//! reference: runtime-owned aligned and pooled buffers keep a header in the
//! tail of their own allocation, caller-supplied `Vec<u8>` values are adopted
//! into that native form when their spare capacity allows, and caller-supplied
//! [`Bytes`] values are held zero-copy by a small external owner. This keeps
//! `bytes::Buf` and `bytes::BufMut` hot paths as simple pointer/length
//! arithmetic; `buffer.rs` documents the owner model.
//!
//! Public types:
//! - [`IoBuf`]: Immutable byte buffer
//! - [`IoBufMut`]: Mutable byte buffer
//! - [`IoBufs`]: Container for one or more immutable buffers
//! - [`IoBufsMut`]: Container for one or more mutable buffers
//! - [`BufferPool`]: Pool of reusable, aligned buffers

mod buffer;
mod freelist;
mod pool;

use buffer::{
    allocate_aligned_mut, owner_from_bytes, owner_from_vec, try_adopt_vec, OwnerRef, PooledBuffer,
};
use bytes::{Buf, BufMut, Bytes, BytesMut, TryGetError};
use commonware_codec::{util::at_least, BufsMut, EncodeSize, Error, RangeCfg, Read, Write};
use crossbeam_utils::CachePadded;
pub use pool::{BufferPool, BufferPoolConfig, BufferPoolThreadCache, PoolError};
use std::{
    collections::VecDeque,
    io::IoSlice,
    mem::{align_of, ManuallyDrop},
    num::NonZeroUsize,
    ops::{Bound, RangeBounds},
    ptr::NonNull,
};

/// Returns the system page size.
///
/// On Unix systems, queries the actual page size via `sysconf`.
/// On other systems (Windows), defaults to 4KB.
#[allow(clippy::missing_const_for_fn)]
pub fn page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: sysconf is safe to call.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size <= 0 {
            4096 // Safe fallback if sysconf fails
        } else {
            size as usize
        }
    }

    #[cfg(not(unix))]
    {
        4096
    }
}

/// Returns the cache line size for the current architecture.
pub const fn cache_line_size() -> usize {
    align_of::<CachePadded<u8>>()
}

#[cfg(feature = "bench")]
pub mod bench {
    pub use super::{buffer::PooledBuffer, freelist::Freelist};
}

/// Immutable byte buffer.
///
/// The handle stores the current readable pointer and length directly:
///
/// ```text
/// [ readable bytes .......... ]
/// ^
/// ptr
/// len = readable bytes
/// ```
///
/// Allocation ownership is represented by `owner`, a compact tagged pointer to
/// an internal owner header. `bytes::Buf` methods use only `ptr` and `len`;
/// clone/drop/slice/split use `owner` on colder lifecycle paths.
///
/// Cloning and slicing are zero-copy. For pooled-backed values, the underlying
/// allocation is returned to the pool when the final immutable reference is
/// dropped.
///
/// All `From<*> for IoBuf` implementations are guaranteed to be non-copy
/// conversions. Use [`IoBuf::copy_from_slice`] when an explicit copy from
/// borrowed data is required.
pub struct IoBuf {
    ptr: NonNull<u8>,
    len: usize,
    owner: OwnerRef,
}

// SAFETY: immutable handles expose read-only bytes and synchronize shared
// ownership through the owner refcount.
unsafe impl Send for IoBuf {}
// SAFETY: shared access is read-only and lifecycle state is atomic.
unsafe impl Sync for IoBuf {}

impl std::fmt::Debug for IoBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoBuf")
            .field("ptr", &self.ptr)
            .field("len", &self.len)
            .field("pooled", &self.is_pooled())
            .finish()
    }
}

impl Clone for IoBuf {
    #[inline]
    fn clone(&self) -> Self {
        // SAFETY: cloning an immutable view retains the shared owner when one
        // exists. Static views have an empty owner and need no lifecycle work.
        unsafe { self.owner.clone_shared() };
        Self {
            ptr: self.ptr,
            len: self.len,
            owner: self.owner,
        }
    }
}

impl Drop for IoBuf {
    fn drop(&mut self) {
        // SAFETY: dropping an immutable view releases exactly one shared owner
        // reference. Static/empty views have no owner.
        unsafe { self.owner.drop_shared() };
    }
}

impl IoBuf {
    /// Create a buffer by copying data from a slice.
    ///
    /// Use this when you have a non-static `&[u8]` that needs owned storage.
    /// For static slices, prefer [`IoBuf::from`] which is zero-copy.
    ///
    /// The copy lands in one native aligned allocation with an inline owner
    /// header, so the result supports zero-copy [`IoBuf::try_into_mut`].
    pub fn copy_from_slice(data: &[u8]) -> Self {
        IoBufMut::from(data).freeze()
    }

    #[inline]
    fn from_static(slice: &'static [u8]) -> Self {
        if slice.is_empty() {
            return Self::default();
        }
        let ptr = NonNull::new(slice.as_ptr().cast_mut()).expect("static slice data is non-null");
        Self {
            ptr,
            len: slice.len(),
            owner: OwnerRef::empty(),
        }
    }

    /// Returns `true` if this buffer is tracked by a pool.
    #[inline]
    pub const fn is_pooled(&self) -> bool {
        self.owner.is_pooled()
    }

    /// Number of bytes remaining in the buffer.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get raw pointer to the first readable byte.
    #[inline]
    pub const fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Returns a slice of self for the provided range (zero-copy).
    ///
    /// Empty ranges return a detached empty buffer so pooled allocations are
    /// not pinned by empty views.
    #[inline]
    pub fn slice(&self, range: impl RangeBounds<usize>) -> Self {
        let (start, end) = resolve_range(self.len, range);
        if start == end {
            return Self::default();
        }

        // SAFETY: range resolution bounds `start <= self.len`.
        let ptr = unsafe { self.ptr.add(start) };
        // SAFETY: the returned view aliases immutable bytes and retains the
        // owner while it is live.
        unsafe { self.owner.clone_shared() };
        Self {
            ptr,
            len: end - start,
            owner: self.owner,
        }
    }

    /// Splits the buffer into two at the given index.
    ///
    /// Afterwards `self` contains bytes `[at, len)`, and the returned [`IoBuf`]
    /// contains bytes `[0, at)`.
    ///
    /// This is an `O(1)` zero-copy operation. Empty halves detach from the
    /// owner so pooled allocations are not pinned by empty views.
    ///
    /// # Panics
    ///
    /// Panics if `at > len`.
    pub fn split_to(&mut self, at: usize) -> Self {
        assert!(
            at <= self.len,
            "split_to out of bounds: {:?} <= {:?}",
            at,
            self.len,
        );
        if at == 0 {
            return Self::default();
        }
        if at == self.len {
            return std::mem::take(self);
        }

        // SAFETY: prefix aliases immutable bytes and retains the owner.
        unsafe { self.owner.clone_shared() };
        let prefix = Self {
            ptr: self.ptr,
            len: at,
            owner: self.owner,
        };
        // SAFETY: `at < self.len`, so advancing within the current readable region is in bounds.
        unsafe {
            self.ptr = self.ptr.add(at);
        }
        self.len -= at;
        prefix
    }

    /// Try to convert this buffer into [`IoBufMut`] without copying.
    ///
    /// Succeeds when this view is the unique owner of a native (aligned,
    /// pooled, or adopted-vec) allocation, including uniquely-owned slices:
    /// capacity is recovered from the allocation base and the current view
    /// offset, so spare capacity beyond the view returns with it. Empty
    /// buffers convert trivially.
    ///
    /// Declines for shared owners, non-empty static views, and
    /// external-backed views (`Bytes` cannot back a mutable handle).
    pub fn try_into_mut(self) -> Result<IoBufMut, Self> {
        if self.owner.is_empty() {
            return if self.len == 0 {
                Ok(IoBufMut::default())
            } else {
                Err(self)
            };
        }

        // External owners always decline: `Bytes` cannot back a mutable
        // handle, so `IoBufMut` is never external-backed.
        if self.owner.is_external() {
            return Err(self);
        }

        // SAFETY: owner is non-empty and live.
        if !unsafe { self.owner.is_unique() } {
            return Err(self);
        }

        let me = ManuallyDrop::new(self);
        // SAFETY: owner is unique and live.
        let base = unsafe { me.owner.data_base() };
        // SAFETY: owner is unique and live.
        let usable_capacity = unsafe { me.owner.usable_capacity() };
        let offset = (me.ptr.as_ptr() as usize)
            .checked_sub(base.as_ptr() as usize)
            .expect("view pointer must be within owner allocation");
        assert!(
            offset <= usable_capacity,
            "view pointer out of owner bounds"
        );
        let cap = usable_capacity - offset;
        assert!(me.len <= cap, "view length out of owner bounds");

        Ok(IoBufMut {
            ptr: me.ptr,
            len: me.len,
            cap,
            owner: me.owner,
        })
    }
}

impl AsRef<[u8]> for IoBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: `ptr..ptr+len` is initialized and kept alive by `owner` or is
        // an immortal static slice.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Default for IoBuf {
    fn default() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            owner: OwnerRef::empty(),
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
    #[inline(always)]
    fn remaining(&self) -> usize {
        self.len
    }

    #[inline(always)]
    fn chunk(&self) -> &[u8] {
        self.as_ref()
    }

    #[inline(always)]
    fn advance(&mut self, cnt: usize) {
        if cnt > self.len {
            panic_advance(cnt, self.len);
        }
        // SAFETY: `cnt <= self.len`, so the new pointer remains in or one byte
        // past the readable region.
        unsafe {
            self.ptr = self.ptr.add(cnt);
        }
        self.len -= cnt;
    }

    #[inline]
    fn copy_to_slice(&mut self, dst: &mut [u8]) {
        if let Err(error) = self.try_copy_to_slice(dst) {
            panic_try_get(error);
        }
    }

    #[inline]
    fn try_copy_to_slice(&mut self, dst: &mut [u8]) -> Result<(), TryGetError> {
        if dst.len() > self.len {
            return Err(TryGetError {
                requested: dst.len(),
                available: self.len,
            });
        }
        // SAFETY: source and destination are valid for `dst.len()` bytes and
        // cannot overlap because `dst` is a unique mutable slice outside this
        // immutable buffer.
        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.as_ptr(), dst.as_mut_ptr(), dst.len());
            self.ptr = self.ptr.add(dst.len());
        }
        self.len -= dst.len();
        Ok(())
    }

    /// Drains `len` readable bytes into [`Bytes`].
    ///
    /// Zero-copy despite the trait method's name: a shared view is carved
    /// off and converted through the `From<IoBuf> for Bytes` fast paths.
    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        assert!(len <= self.len, "copy_to_bytes out of bounds");
        if len == 0 {
            return Bytes::new();
        }
        if len == self.len {
            return Bytes::from(std::mem::take(self));
        }

        // External-backed views slice the inner Bytes directly: one inner
        // refcount clone, instead of cloning and then dropping our owner
        // through the shared-decrement path.
        if self.owner.is_external() {
            // SAFETY: the external owner is live while `self` holds its
            // reference, and the view prefix lies within the inner `Bytes`
            // range by invariant, as `slice_ref` requires.
            let inner = unsafe { self.owner.external_bytes() };
            let bytes = inner.slice_ref(&self.as_ref()[..len]);
            self.advance(len);
            return bytes;
        }

        let drained = Self {
            ptr: self.ptr,
            len,
            owner: self.owner,
        };
        // SAFETY: `drained` is a new immutable view into the same owner.
        unsafe { drained.owner.clone_shared() };
        self.advance(len);
        Bytes::from(drained)
    }
}

/// Convert a [`Vec<u8>`] into an [`IoBuf`] without copying.
///
/// When the vec's spare capacity can host the owner header, its allocation is
/// adopted as a native heap buffer (zero extra allocations, and
/// [`IoBuf::try_into_mut`] recovers it). Otherwise the allocation moves into
/// [`Bytes`] (also zero-copy) behind a small external owner.
impl From<Vec<u8>> for IoBuf {
    fn from(vec: Vec<u8>) -> Self {
        let (ptr, len, owner) = owner_from_vec(vec);
        Self { ptr, len, owner }
    }
}

/// Convert [`Bytes`] into an [`IoBuf`] without copying.
///
/// The `Bytes` value moves into a small external owner and the handle points
/// directly into its payload. The inner refcount is not touched again until
/// the final `IoBuf` reference drops.
impl From<Bytes> for IoBuf {
    fn from(bytes: Bytes) -> Self {
        let (ptr, len, owner) = owner_from_bytes(bytes);
        Self { ptr, len, owner }
    }
}

/// Convert [`BytesMut`] into an [`IoBuf`] without copying (via `freeze`).
impl From<BytesMut> for IoBuf {
    fn from(bytes: BytesMut) -> Self {
        Self::from(bytes.freeze())
    }
}

impl<const N: usize> From<&'static [u8; N]> for IoBuf {
    fn from(array: &'static [u8; N]) -> Self {
        Self::from_static(array)
    }
}

impl From<&'static [u8]> for IoBuf {
    fn from(slice: &'static [u8]) -> Self {
        Self::from_static(slice)
    }
}

/// Convert an [`IoBuf`] into a [`Vec<u8>`].
///
/// This conversion copies the readable bytes.
impl From<IoBuf> for Vec<u8> {
    fn from(buf: IoBuf) -> Self {
        buf.as_ref().to_vec()
    }
}

/// Convert an [`IoBuf`] into [`Bytes`] without copying readable data.
///
/// Static views convert via [`Bytes::from_static`] (free), external-backed
/// views via [`Bytes::slice_ref`] on the inner `Bytes` (a refcount clone, no
/// allocation), and native aligned/pooled views via [`Bytes::from_owner`]
/// (one box).
impl From<IoBuf> for Bytes {
    fn from(buf: IoBuf) -> Self {
        if buf.is_empty() {
            return Self::new();
        }
        if buf.owner.is_empty() {
            // Non-empty views with no owner are 'static by invariant.
            // SAFETY: `ptr..ptr+len` is an initialized immortal slice.
            let slice: &'static [u8] =
                unsafe { std::slice::from_raw_parts(buf.ptr.as_ptr(), buf.len) };
            return Self::from_static(slice);
        }
        if buf.owner.is_external() {
            // SAFETY: the external owner is live while `buf` holds its
            // reference, and the view lies within the inner `Bytes` range by
            // invariant, as `slice_ref` requires.
            let inner = unsafe { buf.owner.external_bytes() };
            return inner.slice_ref(buf.as_ref());
        }
        Self::from_owner(buf)
    }
}

impl Write for IoBuf {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.len().write(buf);
        buf.put_slice(self.as_ref());
    }

    #[inline]
    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.len().write(buf);
        buf.push(self.clone());
    }
}

impl EncodeSize for IoBuf {
    #[inline]
    fn encode_size(&self) -> usize {
        self.len().encode_size() + self.len()
    }

    #[inline]
    fn encode_inline_size(&self) -> usize {
        self.len().encode_size()
    }
}

impl Read for IoBuf {
    type Cfg = RangeCfg<usize>;

    /// Reads a length-prefixed buffer.
    ///
    /// Zero payload copies: `copy_to_bytes` extracts owned [`Bytes`] from the
    /// source (zero-copy for `IoBuf`, `IoBufs`, and `Bytes` sources) and
    /// `Self::from` wraps them zero-copy.
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
/// The handle stores the first readable byte, readable length, and writable
/// view capacity directly:
///
/// ```text
/// before advance:
/// [ readable len ][ writable cap-len ]
/// ^
/// ptr
///
/// after advance(n):
/// [ consumed ][ readable len-n ][ writable cap-len ]
///              ^
///              ptr
/// ```
///
/// `advance` moves `ptr` forward and shrinks both `len` and `cap`. `BufMut`
/// writes always begin at `ptr + len`.
pub struct IoBufMut {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
    owner: OwnerRef,
}

// SAFETY: mutable handles have unique ownership. Moving them across threads is
// safe because final release uses thread-safe pool/allocator paths.
unsafe impl Send for IoBufMut {}
// SAFETY: shared references expose only immutable reads; mutation requires
// `&mut self`.
unsafe impl Sync for IoBufMut {}

impl std::fmt::Debug for IoBufMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoBufMut")
            .field("ptr", &self.ptr)
            .field("len", &self.len)
            .field("cap", &self.cap)
            .field("pooled", &self.is_pooled())
            .finish()
    }
}

impl Drop for IoBufMut {
    fn drop(&mut self) {
        // SAFETY: mutable buffers uniquely own their allocation.
        unsafe { self.owner.release_unique_mut_at(self.ptr, self.cap) };
    }
}

impl Default for IoBufMut {
    fn default() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            cap: 0,
            owner: OwnerRef::empty(),
        }
    }
}

impl IoBufMut {
    /// Create a buffer with the given capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_alignment(capacity, NonZeroUsize::MIN)
    }

    /// Create an untracked aligned buffer with the given capacity and alignment.
    ///
    /// The returned buffer is not tracked by a [`BufferPool`], so dropping it
    /// deallocates the aligned allocation immediately.
    #[inline]
    pub fn with_alignment(capacity: usize, alignment: NonZeroUsize) -> Self {
        if capacity == 0 {
            return Self::default();
        }
        let (ptr, owner) = allocate_aligned_mut(capacity, alignment.get(), false);
        Self {
            ptr,
            len: 0,
            cap: capacity,
            owner,
        }
    }

    /// Create a zero-initialized untracked aligned buffer with the given
    /// length and alignment.
    #[inline]
    pub fn zeroed_with_alignment(len: usize, alignment: NonZeroUsize) -> Self {
        if len == 0 {
            return Self::default();
        }
        let (ptr, owner) = allocate_aligned_mut(len, alignment.get(), true);
        Self {
            ptr,
            len,
            cap: len,
            owner,
        }
    }

    /// Create a buffer of `len` bytes, all initialized to zero.
    ///
    /// Unlike [`Self::with_capacity`], the full buffer is immediately
    /// readable (`len() == capacity() == len`), which suits APIs that fill a
    /// preallocated buffer such as `read_exact`.
    #[inline]
    pub fn zeroed(len: usize) -> Self {
        Self::zeroed_with_alignment(len, NonZeroUsize::MIN)
    }

    /// Create a buffer from a pooled allocation.
    ///
    /// # Safety
    ///
    /// `buffer` must have an initialized live lease in its pooled header.
    #[inline]
    pub(crate) unsafe fn from_pooled_parts(buffer: PooledBuffer) -> Self {
        // SAFETY: pooled buffers returned by the pool have initialized stable
        // header fields.
        let cap = unsafe { buffer.capacity() };
        let ptr = buffer.data_ptr();
        // SAFETY: guaranteed by the caller.
        let owner = unsafe { buffer.owner_ref() };
        Self {
            ptr,
            len: 0,
            cap,
            owner,
        }
    }

    /// Returns `true` if this buffer is tracked by a pool.
    #[inline]
    pub const fn is_pooled(&self) -> bool {
        self.owner.is_pooled()
    }

    /// Sets the length of the buffer.
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
        self.len = len;
    }

    /// Number of readable bytes remaining in the buffer.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer has no readable bytes.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Freeze into immutable [`IoBuf`].
    ///
    /// Free: the owner word moves to the immutable handle without touching
    /// the refcount. Freezing an empty buffer releases the allocation
    /// immediately so empty immutable views never pin pool memory.
    #[inline]
    pub fn freeze(self) -> IoBuf {
        let mut me = ManuallyDrop::new(self);
        if me.len == 0 {
            // SAFETY: mutable buffers uniquely own their allocation. Empty
            // freeze releases it so empty immutable views do not pin pool memory.
            unsafe { me.owner.release_unique_mut_at(me.ptr, me.cap) };
            return IoBuf::default();
        }
        let ptr = me.ptr;
        let cap = me.cap;
        // SAFETY: mutable buffers uniquely own their allocation. A reserved
        // front heap header must be initialized before the owner is shared by
        // the immutable handle.
        unsafe { me.owner.ensure_heap_header_for_mut(ptr, cap) };
        IoBuf {
            ptr: me.ptr,
            len: me.len,
            owner: me.owner,
        }
    }

    /// Returns the number of bytes the buffer can hold without reallocating.
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.cap
    }

    /// Returns an unsafe mutable pointer to the first readable byte.
    #[inline]
    pub const fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Truncates the buffer to `len` readable bytes.
    ///
    /// Has no effect when `len` is greater than the current length.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    /// Clears the buffer, removing all readable data. Existing view capacity is preserved.
    #[inline]
    pub const fn clear(&mut self) {
        self.len = 0;
    }
}

impl AsRef<[u8]> for IoBufMut {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: bytes in `0..len` from `ptr` are initialized.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl AsMut<[u8]> for IoBufMut {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: bytes in `0..len` from `ptr` are initialized and `&mut self`
        // proves unique access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
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
    #[inline(always)]
    fn remaining(&self) -> usize {
        self.len
    }

    #[inline(always)]
    fn chunk(&self) -> &[u8] {
        self.as_ref()
    }

    #[inline(always)]
    fn advance(&mut self, cnt: usize) {
        if cnt > self.len {
            panic_advance(cnt, self.len);
        }
        // SAFETY: `cnt <= len <= cap`, so the pointer stays within the view
        // (zero-length pointer adds are always valid, so `cnt == 0` needs no
        // special case).
        unsafe {
            self.ptr = self.ptr.add(cnt);
        }
        self.len -= cnt;
        self.cap -= cnt;
    }

    #[inline]
    fn copy_to_slice(&mut self, dst: &mut [u8]) {
        if let Err(error) = self.try_copy_to_slice(dst) {
            panic_try_get(error);
        }
    }

    #[inline]
    fn try_copy_to_slice(&mut self, dst: &mut [u8]) -> Result<(), TryGetError> {
        if dst.len() > self.len {
            return Err(TryGetError {
                requested: dst.len(),
                available: self.len,
            });
        }
        // SAFETY: source and destination are valid for `dst.len()` bytes and
        // cannot overlap because `dst` is a unique mutable slice outside this
        // buffer (zero-length copies with valid pointers need no special
        // case).
        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.as_ptr(), dst.as_mut_ptr(), dst.len());
            self.ptr = self.ptr.add(dst.len());
        }
        self.len -= dst.len();
        self.cap -= dst.len();
        Ok(())
    }

    /// Drains `len` readable bytes into [`Bytes`].
    ///
    /// Draining the full readable length consumes the whole handle
    /// (`mem::take` plus `freeze`) to avoid a copy: unlike `BytesMut`, the
    /// caller's handle keeps no spare capacity afterwards. A partial drain
    /// copies the prefix and preserves the handle's remaining capacity.
    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        assert!(len <= self.len, "copy_to_bytes out of bounds");
        if len == 0 {
            return Bytes::new();
        }
        if len == self.len {
            let drained = std::mem::take(self);
            return Bytes::from(drained.freeze());
        }

        let bytes = Bytes::copy_from_slice(&self.as_ref()[..len]);
        self.advance(len);
        bytes
    }
}

// SAFETY: `IoBufMut` exposes only the uninitialized tail `[len..cap)` through
// `chunk_mut`, and `advance_mut` is bounded by that tail.
unsafe impl BufMut for IoBufMut {
    #[inline(always)]
    fn remaining_mut(&self) -> usize {
        self.cap - self.len
    }

    #[inline(always)]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        let writable = self.cap - self.len;
        if cnt > writable {
            panic_advance(cnt, writable);
        }
        self.len += cnt;
    }

    #[inline(always)]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        // SAFETY: `ptr + len` begins the uninitialized writable tail and
        // `cap - len` is in bounds.
        unsafe {
            let ptr = self.ptr.as_ptr().add(self.len);
            bytes::buf::UninitSlice::from_raw_parts_mut(ptr, self.cap - self.len)
        }
    }

    #[inline]
    fn put_slice(&mut self, src: &[u8]) {
        let writable = self.cap - self.len;
        if src.len() > writable {
            panic_advance(src.len(), writable);
        }
        // SAFETY: the unique writable tail has at least `src.len()` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr.as_ptr().add(self.len), src.len());
        }
        self.len += src.len();
    }

    #[inline]
    fn put_bytes(&mut self, val: u8, cnt: usize) {
        let writable = self.cap - self.len;
        if cnt > writable {
            panic_advance(cnt, writable);
        }
        // SAFETY: the unique writable tail has at least `cnt` bytes.
        unsafe {
            std::ptr::write_bytes(self.ptr.as_ptr().add(self.len), val, cnt);
        }
        self.len += cnt;
    }

    #[inline]
    fn put<T: Buf>(&mut self, mut src: T)
    where
        Self: Sized,
    {
        // Early check for a clear panic message; NOT a safety boundary.
        let remaining = src.remaining();
        if remaining > self.cap - self.len {
            panic_advance(remaining, self.cap - self.len);
        }
        while src.has_remaining() {
            let chunk = src.chunk();
            let cnt = chunk.len();
            // Safety boundary: `Buf` is a safe trait, so `src` may report a
            // `remaining()` smaller than the chunks it hands out. Bound every
            // copy by this buffer's own capacity arithmetic, never by `src`.
            let writable = self.cap - self.len;
            if cnt > writable {
                panic_advance(cnt, writable);
            }
            // SAFETY: `cnt` is bounded by the unique writable tail just above.
            unsafe {
                std::ptr::copy_nonoverlapping(chunk.as_ptr(), self.ptr.as_ptr().add(self.len), cnt);
            }
            self.len += cnt;
            src.advance(cnt);
        }
    }
}

impl From<&[u8]> for IoBufMut {
    fn from(slice: &[u8]) -> Self {
        let mut buf = Self::with_capacity(slice.len());
        buf.put_slice(slice);
        buf
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

/// Create a mutable buffer by copying `bytes`.
///
/// A mutable buffer requires runtime-owned storage for its owner header, which
/// a `BytesMut` allocation cannot host, so this conversion copies.
impl From<BytesMut> for IoBufMut {
    fn from(bytes: BytesMut) -> Self {
        Self::from(bytes.as_ref())
    }
}

/// Create a mutable buffer by copying `bytes`.
///
/// A mutable buffer requires unique ownership of its storage, which shared
/// [`Bytes`] cannot provide, so this conversion copies.
impl From<Bytes> for IoBufMut {
    fn from(bytes: Bytes) -> Self {
        Self::from(bytes.as_ref())
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

/// Converts a vec into a mutable handle, preserving the caller's capacity.
///
/// Adopts the vec's allocation zero-copy when its spare capacity can host
/// the owner header (including empty vecs with reserved capacity); otherwise
/// copies the readable bytes into a fresh buffer with at least the vec's
/// capacity. Unlike `From<Vec<u8>> for IoBuf`, an empty vec keeps its
/// reserved capacity instead of detaching.
fn iobuf_mut_from_vec(vec: Vec<u8>) -> IoBufMut {
    match try_adopt_vec(vec) {
        Ok((ptr, len, cap, owner)) => IoBufMut {
            ptr,
            len,
            cap,
            owner,
        },
        Err(vec) => {
            let mut out = IoBufMut::with_capacity(vec.capacity());
            out.put_slice(&vec);
            out
        }
    }
}

/// Panics for cursor or write operations that run past the available region.
///
/// Outlined so the `Buf`/`BufMut` fast paths inline as a compare, a branch,
/// and a memcpy, mirroring the panic helpers in `bytes`.
#[cold]
#[inline(never)]
fn panic_advance(requested: usize, available: usize) -> ! {
    panic!("cannot advance past end of buffer: requested {requested}, available {available}");
}

/// Panics for a failed `copy_to_slice`, preserving the [`TryGetError`]
/// message.
#[cold]
#[inline(never)]
fn panic_try_get(error: TryGetError) -> ! {
    panic!("{error}");
}

fn resolve_range(len: usize, range: impl RangeBounds<usize>) -> (usize, usize) {
    let start = match range.start_bound() {
        Bound::Included(&n) => n,
        Bound::Excluded(&n) => n.checked_add(1).expect("range start overflow"),
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(&n) => n.checked_add(1).expect("range end overflow"),
        Bound::Excluded(&n) => n,
        Bound::Unbounded => len,
    };
    assert!(start <= end, "slice start must be <= end");
    assert!(end <= len, "slice out of bounds");
    (start, end)
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

    /// Visit each readable chunk in order without coalescing.
    #[inline]
    pub fn for_each_chunk(&self, mut f: impl FnMut(&[u8])) {
        match &self.inner {
            IoBufsInner::Single(buf) => {
                let chunk = buf.as_ref();
                if !chunk.is_empty() {
                    f(chunk);
                }
            }
            IoBufsInner::Pair(pair) => {
                for buf in pair {
                    let chunk = buf.as_ref();
                    if !chunk.is_empty() {
                        f(chunk);
                    }
                }
            }
            IoBufsInner::Triple(triple) => {
                for buf in triple {
                    let chunk = buf.as_ref();
                    if !chunk.is_empty() {
                        f(chunk);
                    }
                }
            }
            IoBufsInner::Chunked(bufs) => {
                for buf in bufs {
                    let chunk = buf.as_ref();
                    if !chunk.is_empty() {
                        f(chunk);
                    }
                }
            }
        }
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
    /// Zero-copy if only one buffer. Copies into one native aligned
    /// allocation if multiple buffers, so the result supports zero-copy
    /// [`IoBuf::try_into_mut`].
    #[inline]
    pub fn coalesce(self) -> IoBuf {
        match self.inner {
            IoBufsInner::Single(buf) => buf,
            inner => {
                let bufs = Self { inner };
                let mut out = IoBufMut::with_capacity(bufs.remaining());
                bufs.for_each_chunk(|chunk| out.put_slice(chunk));
                out.freeze()
            }
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
        Self::from(IoBuf::from(bytes))
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
/// Construction and canonicalization keep every chunk that still owns
/// storage (`capacity() > 0`), readable or not, so caller-reserved write
/// capacity survives read operations. Only fully-drained chunks (capacity
/// consumed by `advance`) and empty defaults are removed as the shape
/// collapses.
///
/// Limitation: the deque-backed read paths (four or more chunks) skip past
/// a chunk with no readable bytes by popping it, so a never-filled chunk
/// ordered before readable data loses its capacity when a read crosses it.
/// Fills are front-to-back in practice (`set_len`, `read_at_buf`), which
/// does not produce that ordering.
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
    /// This helper intentionally does not filter; callers route through
    /// [`Self::from_writable_chunks_iter`] so storage-owning chunks are kept.
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
    /// Keeps chunks that still own storage, readable or not (`capacity()`
    /// covers both readable bytes and the writable tail), so a never-filled
    /// chunk's reserved capacity is not discarded. Fully-drained chunks
    /// (capacity consumed by `advance`) and empty defaults are removed.
    fn from_writable_chunks_iter(chunks: impl IntoIterator<Item = IoBufMut>) -> Self {
        Self::from_chunks_iter(chunks.into_iter().filter(|buf| buf.capacity() > 0))
    }

    /// Re-establish canonical mutable representation invariants.
    ///
    /// Uses the same storage-keeping filter as construction: read operations
    /// must not change `remaining_mut()`, so chunks that were drained of
    /// readable bytes but still own writable capacity survive.
    fn canonicalize(&mut self) {
        let inner = std::mem::replace(&mut self.inner, IoBufsMutInner::Single(IoBufMut::default()));
        self.inner = match inner {
            IoBufsMutInner::Single(buf) => IoBufsMutInner::Single(buf),
            IoBufsMutInner::Pair([a, b]) => Self::from_writable_chunks_iter([a, b]).inner,
            IoBufsMutInner::Triple([a, b, c]) => Self::from_writable_chunks_iter([a, b, c]).inner,
            IoBufsMutInner::Chunked(bufs) => Self::from_writable_chunks_iter(bufs).inner,
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
        // Zero-length drains must not disturb chunk state: the deque-backed
        // path skips readable-empty chunks by popping them, which would
        // discard a never-filled chunk's reserved capacity.
        if len == 0 {
            return Bytes::new();
        }
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
        // On failure, every writable byte was consumed before the chunks ran
        // out, so the advanced amount (`cnt - remaining`) is exactly what was
        // available.
        let mut remaining = cnt;
        let advanced = match &mut self.inner {
            IoBufsMutInner::Single(buf) => {
                buf.advance_mut(cnt);
                return;
            }
            IoBufsMutInner::Pair(pair) => advance_mut_in_chunks(pair, &mut remaining),
            IoBufsMutInner::Triple(triple) => advance_mut_in_chunks(triple, &mut remaining),
            IoBufsMutInner::Chunked(bufs) => {
                let (first, second) = bufs.as_mut_slices();
                advance_mut_in_chunks(first, &mut remaining)
                    || advance_mut_in_chunks(second, &mut remaining)
            }
        };
        if !advanced {
            panic_advance(cnt, cnt - remaining);
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

/// Convert a [`Vec<u8>`] into a single-buffer [`IoBufsMut`].
///
/// Zero-copy when the vec's allocation can be adopted as a native buffer
/// (spare capacity hosts the owner header); otherwise copies into a fresh
/// buffer with at least the vec's capacity. The caller's reserved capacity
/// is preserved either way, so reuse patterns like passing
/// `Vec::with_capacity(len)` to [`Blob::read_at_buf`](crate::Blob)
/// work. There is no `From<Vec<u8>> for IoBufMut` because that impl had no
/// production users and exactly-sized vecs have no zero-copy mutable
/// representation (`IoBuf::from(vec).try_into_mut()` covers the zero-copy
/// cases).
impl From<Vec<u8>> for IoBufsMut {
    fn from(vec: Vec<u8>) -> Self {
        Self {
            inner: IoBufsMutInner::Single(iobuf_mut_from_vec(vec)),
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
        // The deque is empty now, so the container must collapse back to the
        // canonical Single representation.
        return (Bytes::new(), true);
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

/// Assembles [`IoBufs`] from a mix of inline writes and zero-copy pieces.
///
/// All inline writes go into a single pool-backed buffer. [`BufsMut::push`]
/// records boundaries without flushing. [`Builder::finish`] freezes the buffer
/// once and uses [`IoBuf::slice`] to carve it into pieces at the recorded
/// boundaries, interleaved with the pushed [`Bytes`].
///
/// The inline buffer has a fixed capacity set at construction and will not
/// grow. Callers must ensure the capacity accounts for all inline
/// (non-pushed) bytes that will be written. Exceeding it will panic.
///
/// ```text
/// builder.put_u16(99);                        // inline
/// builder.push(shard_payload.clone());        // zero-copy (Arc clone)
/// builder.put_u32(checksum);                  // inline
/// let output = builder.finish();
///
/// // output: [ 99 | --- 1 MB shard --- | checksum ]
/// //           pool    Arc clone          pool
/// //            \________________________/
/// //             slices of one allocation
/// ```
pub struct Builder {
    // Single working buffer for all inline writes.
    buf: IoBufMut,
    // Each entry is (offset_in_buf, pushed_bytes) recording where a push
    // interrupts the inline byte stream.
    pushes: Vec<(usize, Bytes)>,
}

impl Builder {
    /// Creates a new builder with a fixed-capacity inline buffer.
    ///
    /// `capacity` is the minimum number of inline bytes the buffer can hold.
    /// The pool may round up to a larger size class. Writing more inline
    /// bytes than the allocated capacity will panic.
    pub fn new(pool: &BufferPool, capacity: NonZeroUsize) -> Self {
        Self {
            buf: pool.alloc(capacity.get()),
            pushes: Vec::new(),
        }
    }

    /// Freezes the inline buffer and assembles [`IoBufs`] by slicing at
    /// the recorded push boundaries.
    pub fn finish(self) -> IoBufs {
        if self.pushes.is_empty() {
            return IoBufs::from(self.buf.freeze());
        }

        let frozen = self.buf.freeze();
        let mut result = IoBufs::default();
        let mut pos = 0;

        for (offset, pushed) in self.pushes {
            if offset > pos {
                result.append(frozen.slice(pos..offset));
            }
            // Zero-copy: pushed Bytes (for example a 1 MB shard payload held
            // by Arc clone) become external-backed chunks, never a memcpy.
            result.append(IoBuf::from(pushed));
            pos = offset;
        }

        if pos < frozen.len() {
            result.append(frozen.slice(pos..));
        }

        result
    }
}

// SAFETY: All methods delegate directly to `self.buf`, a pool-backed
// `IoBufMut` with a sound `BufMut` implementation. The inline buffer has
// fixed capacity; writes that exceed it will panic via the underlying
// `IoBufMut` implementation.
unsafe impl BufMut for Builder {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.buf.remaining_mut()
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.buf.advance_mut(cnt);
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        self.buf.chunk_mut()
    }
}

impl BufsMut for Builder {
    fn push(&mut self, bytes: impl Into<Bytes>) {
        let bytes = bytes.into();
        if !bytes.is_empty() {
            self.pushes.push((self.buf.len(), bytes));
        }
    }
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

    /// Encode into [`IoBufs`] using pool allocation.
    ///
    /// Override [`Write::write_bufs`] to avoid copying large [`Bytes`] fields.
    ///
    /// # Panics
    ///
    /// Panics if [`EncodeSize::encode_inline_size`] underreports the number
    /// of inline bytes written by [`Write::write_bufs`], or if
    /// [`EncodeSize::encode_size`] does not match the total bytes written.
    fn encode_with_pool(&self, pool: &BufferPool) -> IoBufs {
        let len = self.encode_size();
        let capacity = NonZeroUsize::new(self.encode_inline_size()).unwrap_or(NonZeroUsize::MIN);
        let mut builder = Builder::new(pool, capacity);
        self.write_bufs(&mut builder);
        let bufs = builder.finish();
        assert_eq!(
            bufs.remaining(),
            len,
            "write_bufs() did not write expected bytes"
        );
        bufs
    }
}

impl<T: EncodeSize + Write> EncodeExt for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Bytes, BytesMut};
    use commonware_codec::{types::lazy::Lazy, Decode, Encode, RangeCfg};
    use core::ops::{Range, RangeFrom, RangeInclusive, RangeToInclusive};
    use std::{
        collections::{BTreeMap, HashMap},
        mem::size_of,
    };

    fn test_pool() -> BufferPool {
        cfg_if::cfg_if! {
            if #[cfg(miri)] {
                // Reduce max_per_class to avoid slow atomics under miri.
                let pool_config = BufferPoolConfig {
                    pool_min_size: 0,
                    max_per_class: commonware_utils::NZU32!(32),
                    ..BufferPoolConfig::for_network()
                };
            } else {
                let pool_config = BufferPoolConfig::for_network().with_pool_min_size(0);
            }
        }
        let mut registry = crate::telemetry::metrics::Registry::default();
        BufferPool::new(pool_config, &mut registry)
    }

    fn assert_encode_with_pool_matches_encode<T: Encode + EncodeExt>(value: &T) {
        let pool = test_pool();
        let mut pooled = value.encode_with_pool(&pool);
        let baseline = value.encode();
        let mut pooled_bytes = vec![0u8; pooled.remaining()];
        pooled.copy_to_slice(&mut pooled_bytes);
        assert_eq!(pooled_bytes, baseline.as_ref());
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

        let mut truncated = BytesMut::new();
        4usize.write(&mut truncated);
        truncated.extend_from_slice(b"xy");
        let mut truncated = truncated.freeze();
        assert!(IoBuf::read_cfg(&mut truncated, &cfg).is_err());

        // Directly exercise the successful `read_cfg` path, not just decode helpers.
        let mut direct = BytesMut::new();
        4usize.write(&mut direct);
        direct.extend_from_slice(b"wxyz");
        let mut direct = direct.freeze();
        let decoded = IoBuf::read_cfg(&mut direct, &cfg).unwrap();
        assert_eq!(decoded, b"wxyz");
    }

    #[test]
    #[should_panic(expected = "cannot advance")]
    fn test_iobuf_advance_past_end() {
        let mut buf = IoBuf::from(b"hello");
        buf.advance(10);
    }

    #[test]
    fn test_iobuf_split_to_consistent_across_backings() {
        // split_to on pooled and Bytes-backed IoBufs should produce identical results.
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
    fn test_iobufmut_low_alignment_freeze_after_advance_recovers_capacity() {
        let mut buf = IoBufMut::with_capacity(16);
        assert_eq!(buf.capacity(), 16);
        buf.put_slice(b"abcdefghijklmnop");
        buf.advance(3);
        assert_eq!(buf.as_ref(), b"defghijklmnop");
        assert_eq!(buf.capacity(), 13);

        let frozen = buf.freeze();
        assert_eq!(frozen.as_ref(), b"defghijklmnop");

        let recovered = frozen
            .try_into_mut()
            .expect("unique low-alignment buffer should recover mutability");
        assert_eq!(recovered.as_ref(), b"defghijklmnop");
        assert_eq!(recovered.capacity(), 13);
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

        // Prepending into an empty aggregate should stay on the single-buffer fast path.
        let mut prepend_into_empty = IoBufs::default();
        prepend_into_empty.prepend(IoBuf::from(b"z"));
        assert!(prepend_into_empty.is_single());
        assert_eq!(prepend_into_empty.coalesce(), b"z");

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
        // Default IoBufsMut should be a single empty chunk.
        let bufs = IoBufsMut::default();
        assert!(bufs.is_single());
        assert!(bufs.is_empty());
        assert_eq!(bufs.len(), 0);
    }

    #[test]
    fn test_iobufsmut_from_array() {
        // From<[u8; N]> should create a single-chunk container with the array data.
        let bufs = IoBufsMut::from([1u8, 2, 3, 4, 5]);
        assert!(bufs.is_single());
        assert_eq!(bufs.len(), 5);
        assert_eq!(bufs.chunk(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_iobufmut_buf_trait() {
        // Buf trait on IoBufMut: remaining/chunk/advance should work like BytesMut.
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
        assert_eq!(bufs.remaining_mut(), 20);

        bufs.put_slice(b"hello");
        assert_eq!(bufs.chunk(), b"hello");
        assert_eq!(bufs.len(), 5);
        assert_eq!(bufs.remaining_mut(), 15);

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
        // A leading chunk with capacity but no readable bytes (len == 0) should
        // be skipped during advance, reaching the next readable chunk.
        let empty_writable = IoBufMut::with_capacity(4);
        let payload = IoBufMut::from(b"xy");
        let mut bufs = IoBufsMut::from(vec![empty_writable, payload]);

        bufs.advance(1);
        assert_eq!(bufs.chunk(), b"y");
        assert_eq!(bufs.remaining(), 1);
    }

    #[test]
    fn test_iobufsmut_read_ops_preserve_writable_capacity() {
        // Draining the filled first chunk must not discard the never-filled
        // second chunk's reserved capacity: remaining_mut only changes via
        // advance_mut per the BufMut contract.
        let mut a = IoBufMut::with_capacity(8);
        a.put_slice(&[1u8; 8]);
        let b = IoBufMut::with_capacity(8);
        let mut bufs = IoBufsMut::from(vec![a, b]);
        assert_eq!(bufs.remaining(), 8);
        assert_eq!(bufs.remaining_mut(), 8);
        bufs.advance(8);
        assert_eq!(bufs.remaining(), 0);
        assert_eq!(bufs.remaining_mut(), 8);
        bufs.put_slice(&[2u8; 8]);
        assert_eq!(bufs.copy_to_bytes(8).as_ref(), &[2u8; 8]);

        // copy_to_bytes drains must preserve capacity the same way.
        let mut a = IoBufMut::with_capacity(8);
        a.put_slice(&[3u8; 8]);
        let b = IoBufMut::with_capacity(8);
        let mut bufs = IoBufsMut::from(vec![a, b]);
        assert_eq!(bufs.copy_to_bytes(8).as_ref(), &[3u8; 8]);
        assert_eq!(bufs.remaining_mut(), 8);

        // Zero-length drains do not disturb chunk state at all.
        assert!(bufs.copy_to_bytes(0).is_empty());
        assert_eq!(bufs.remaining_mut(), 8);
    }

    #[test]
    fn test_iobufsmut_from_vec_u8_preserves_capacity() {
        // Spare capacity for the header: the vec's allocation is adopted
        // zero-copy and stays writable.
        let mut vec = Vec::with_capacity(128);
        vec.extend_from_slice(b"abc");
        let base = vec.as_ptr() as usize;
        let mut bufs = IoBufsMut::from(vec);
        assert_eq!(bufs.remaining(), 3);
        assert!(bufs.remaining_mut() > 0);
        assert_eq!(bufs.chunk().as_ptr() as usize, base);
        bufs.put_slice(b"d");
        assert_eq!(bufs.copy_to_bytes(4).as_ref(), b"abcd");

        // Empty vec with reserved capacity adopts and stays writable.
        let mut bufs = IoBufsMut::from(Vec::<u8>::with_capacity(64));
        assert!(bufs.is_empty());
        assert!(bufs.remaining_mut() > 0);
        bufs.put_slice(b"z");
        assert_eq!(bufs.remaining(), 1);

        // Too small to host the header: copied, but the reserved capacity is
        // still honored.
        let mut bufs = IoBufsMut::from(Vec::<u8>::with_capacity(20));
        assert!(bufs.is_empty());
        assert!(bufs.remaining_mut() >= 20);
        bufs.put_slice(&[7u8; 20]);
        assert_eq!(bufs.remaining(), 20);

        // Exactly-sized vec: copied with contents intact.
        let bufs = IoBufsMut::from(vec![1u8, 2, 3]);
        assert_eq!(bufs.remaining(), 3);
        assert_eq!(bufs.chunk(), &[1, 2, 3]);
    }

    #[test]
    fn test_iobufsmut_coalesce_after_advance() {
        // Advance mid-chunk: advance 3 of 11 bytes
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        bufs.advance(3);
        assert_eq!(bufs.coalesce(), b"lo world");

        // Advance to exact chunk boundary: advance 5 of 11 bytes
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        bufs.advance(5);
        assert_eq!(bufs.coalesce(), b" world");
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
        // Stay chunked while consuming across multiple tiny chunks.
        let next = bufs.copy_to_bytes(3);
        assert_eq!(&next[..], b"bcd");
        assert_eq!(bufs.chunk(), b"e");
        assert_eq!(bufs.remaining(), 1);
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
        // Create three BytesMut with capacity for final content comparison.
        let mut bm1 = BytesMut::with_capacity(5);
        let mut bm2 = BytesMut::with_capacity(6);
        let mut bm3 = BytesMut::with_capacity(7);

        // Create matching IoBufsMut
        let mut iobufs = IoBufsMut::from(vec![
            IoBufMut::with_capacity(5),
            IoBufMut::with_capacity(6),
            IoBufMut::with_capacity(7),
        ]);

        // Fixed-capacity IoBufsMut exposes the current writable chunk.
        assert_eq!(iobufs.chunk_mut().len(), 5);

        // Write some data
        (&mut bm1)
            .chain_mut(&mut bm2)
            .chain_mut(&mut bm3)
            .put_slice(b"hel");
        iobufs.put_slice(b"hel");

        assert_eq!(iobufs.chunk_mut().len(), 2);

        // Write more data
        (&mut bm1)
            .chain_mut(&mut bm2)
            .chain_mut(&mut bm3)
            .put_slice(b"lo world!");
        iobufs.put_slice(b"lo world!");

        assert_eq!(iobufs.chunk_mut().len(), 6);

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
        // Partial advance: advance 3 of 11 bytes
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        bufs.advance(3);
        assert_eq!(bufs.len(), 8);

        let frozen = bufs.freeze();
        assert_eq!(frozen.len(), 8);
        assert_eq!(frozen.coalesce(), b"lo world");

        // Exact boundary advance: advance 5 of 11 bytes (first buf is 5 bytes)
        let buf1 = IoBufMut::from(b"hello");
        let buf2 = IoBufMut::from(b" world");
        let mut bufs = IoBufsMut::from(vec![buf1, buf2]);

        bufs.advance(5);
        assert_eq!(bufs.len(), 6);

        // First buffer should be fully consumed (empty after advance)
        // freeze() filters empty buffers, so result should be Single
        let frozen = bufs.freeze();
        assert!(frozen.is_single());
        assert_eq!(frozen.coalesce(), b" world");
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

        // Four chunks force the deque-backed coalesce path instead of pair/triple fast paths.
        let bufs = IoBufsMut::from(vec![
            IoBufMut::from(b"a"),
            IoBufMut::from(b"b"),
            IoBufMut::from(b"c"),
            IoBufMut::from(b"d"),
        ]);
        let coalesced = bufs.coalesce_with_pool(&pool);
        assert_eq!(coalesced, b"abcd");
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

        // A vec with spare capacity adopts its allocation, so the unique
        // immutable view recovers mutability zero-copy.
        let mut adopted_vec = Vec::with_capacity(64);
        adopted_vec.extend_from_slice(&[1u8, 2, 3]);
        let unique = IoBuf::from(adopted_vec);
        let unique_mut = unique.try_into_mut().expect("adopted vec should convert");
        assert_eq!(unique_mut.as_ref(), &[1u8, 2, 3]);

        let shared = IoBuf::from(vec![4u8, 5, 6]);
        let _shared_clone = shared.clone();
        assert!(shared.try_into_mut().is_err());

        // External-backed views (exactly-sized vecs, `Bytes`) always decline
        // mutable recovery.
        let external = IoBuf::from(vec![7u8, 8, 9]);
        assert!(external.try_into_mut().is_err());

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
    fn test_iobuf_from_bytes_zero_copy_round_trip() {
        // Bytes -> IoBuf is zero-copy: the handle points into the payload.
        let bytes = Bytes::from(vec![1u8; 64]);
        let payload_ptr = bytes.as_ptr();
        let buf = IoBuf::from(bytes.clone());
        assert_eq!(buf.as_ptr(), payload_ptr);
        assert_eq!(buf, bytes.as_ref());

        // IoBuf -> Bytes on an external backing uses slice_ref: same payload,
        // no copy, no extra owner box.
        let out: Bytes = buf.into();
        assert_eq!(out.as_ptr(), payload_ptr);
        assert_eq!(out, bytes);

        // Sliced external views convert through slice_ref too.
        let sliced = IoBuf::from(bytes).slice(8..32);
        let sliced_ptr = sliced.as_ptr();
        let sliced_out: Bytes = sliced.into();
        assert_eq!(sliced_out.as_ptr(), sliced_ptr);
        assert_eq!(sliced_out.len(), 24);
    }

    #[test]
    fn test_iobuf_from_bytes_mut_zero_copy() {
        let mut bytes = BytesMut::with_capacity(32);
        bytes.extend_from_slice(b"hello");
        let payload_ptr = bytes.as_ref().as_ptr();
        let buf = IoBuf::from(bytes);
        assert_eq!(buf.as_ptr(), payload_ptr);
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn test_iobuf_static_into_bytes_uses_from_static() {
        let buf = IoBuf::from(b"static-payload");
        let payload_ptr = buf.as_ptr();
        let bytes: Bytes = buf.into();
        assert_eq!(bytes.as_ptr(), payload_ptr);
        assert_eq!(bytes.as_ref(), b"static-payload");
    }

    #[test]
    fn test_iobuf_vec_adoption_round_trip_zero_copy() {
        // Vec with spare capacity -> IoBuf adopts the allocation, and
        // try_into_mut recovers a writable handle at the same address.
        let mut vec = Vec::with_capacity(128);
        vec.extend_from_slice(b"adopted payload");
        let base = vec.as_ptr() as usize;
        let buf = IoBuf::from(vec);
        assert_eq!(buf.as_ptr() as usize, base);

        let mut recovered = buf
            .try_into_mut()
            .expect("adopted vec recovers mutability zero-copy");
        assert_eq!(recovered.as_mut_ptr() as usize, base);
        assert_eq!(recovered.as_ref(), b"adopted payload");
        assert!(recovered.capacity() > recovered.len());
        recovered.put_slice(b"!");
        assert_eq!(recovered.as_ref(), b"adopted payload!");
    }

    #[test]
    fn test_iobuf_read_cfg_zero_copy_from_iobuf_source() {
        // Decoding an IoBuf field from an IoBuf source must not copy the
        // payload: copy_to_bytes carves a zero-copy slice and From wraps it.
        let cfg: RangeCfg<usize> = (0..=1024).into();
        let mut source = IoBuf::from(IoBuf::from(vec![7u8; 100]).encode());
        let prefix = source.len() - 100;
        let payload_ptr = source.as_ref()[prefix..].as_ptr();
        let decoded = IoBuf::read_cfg(&mut source, &cfg).unwrap();
        assert_eq!(decoded.len(), 100);
        assert_eq!(decoded.as_ptr(), payload_ptr);
        assert_eq!(decoded, [7u8; 100]);
    }

    #[test]
    #[should_panic(expected = "cannot advance")]
    fn test_iobufmut_put_does_not_trust_lying_buf() {
        // `Buf` is a safe trait: a misbehaving source may hand out chunks
        // larger than its reported remaining(). `put` must bound each copy by
        // its own capacity and panic instead of overflowing the buffer.
        struct LyingBuf;
        impl Buf for LyingBuf {
            fn remaining(&self) -> usize {
                1
            }
            fn chunk(&self) -> &[u8] {
                &[0xAB; 64]
            }
            fn advance(&mut self, _cnt: usize) {}
        }

        let mut buf = IoBufMut::with_capacity(8);
        buf.put(LyingBuf);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_iobuf_handle_sizes() {
        assert_eq!(size_of::<IoBuf>(), 24);
        assert_eq!(size_of::<IoBufMut>(), 32);
    }

    #[test]
    fn test_iobufmut_additional_conversion_and_trait_paths() {
        // Basic mutable operations should keep readable bytes consistent.
        let mut buf = IoBufMut::from([1u8, 2, 3, 4]);
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
        let from_array = IoBufMut::from([7u8, 8]);
        assert_eq!(from_array.as_ref(), &[7u8, 8]);

        let from_bytesmut = IoBufMut::from(BytesMut::from(&b"hi"[..]));
        assert_eq!(from_bytesmut.as_ref(), b"hi");

        let from_bytes = IoBufMut::from(Bytes::from_static(b"ok"));
        assert_eq!(from_bytes.as_ref(), b"ok");

        // `Bytes::from_static` cannot be converted to mutable without copy.
        let from_iobuf = IoBufMut::from(IoBuf::from(Bytes::from_static(b"io")));
        assert_eq!(from_iobuf.as_ref(), b"io");
    }

    #[test]
    fn test_iobuf_aligned_public_paths() {
        // Exercise the public IoBuf/IoBufMut API through the untracked aligned
        // backing: write, advance, copy_to_bytes, freeze, slice, split_to,
        // try_into_mut, and From/Into conversions.
        static ARRAY: &[u8; 4] = b"wxyz";

        let alignment = NonZeroUsize::new(64).expect("non-zero alignment");

        // Start from a non-zero untracked aligned buffer to cover the public mutable API.
        let mut aligned_mut = IoBufMut::with_alignment(8, alignment);
        assert!(!aligned_mut.is_pooled());
        assert!(aligned_mut.is_empty());
        assert_eq!(aligned_mut.capacity(), 8);
        assert!((aligned_mut.as_mut_ptr() as usize).is_multiple_of(64));

        aligned_mut.put_slice(b"abcdefgh");
        assert_eq!(aligned_mut.as_mut(), b"abcdefgh");
        assert_eq!(aligned_mut.chunk(), b"abcdefgh");
        aligned_mut.advance(2);
        assert_eq!(aligned_mut.chunk(), b"cdefgh");

        let partial = aligned_mut.copy_to_bytes(2);
        assert_eq!(partial.as_ref(), b"cd");
        assert_eq!(aligned_mut.as_ref(), b"efgh");
        let empty = aligned_mut.copy_to_bytes(0);
        assert!(empty.is_empty());
        assert_eq!(aligned_mut.as_ref(), b"efgh");

        aligned_mut.clear();
        assert!(aligned_mut.is_empty());
        aligned_mut.put_slice(ARRAY);
        assert!(aligned_mut == ARRAY);

        // Full aligned drains should use the owner-transfer path, including len == 0 first.
        let mut fully_drained = IoBufMut::with_alignment(4, alignment);
        fully_drained.put_slice(b"lmno");
        let empty = fully_drained.copy_to_bytes(0);
        assert!(empty.is_empty());
        assert_eq!(fully_drained.as_ref(), b"lmno");
        let drained = fully_drained.copy_to_bytes(4);
        assert_eq!(drained.as_ref(), b"lmno");
        assert!(fully_drained.is_empty());

        // Freeze to an immutable aligned `IoBuf` and exercise its view/Buf dispatch.
        let aligned = aligned_mut.freeze();
        assert!(!aligned.is_pooled());
        assert_eq!(aligned.as_ref(), &ARRAY[..]);
        assert!(aligned == ARRAY);
        assert!(!aligned.as_ptr().is_null());
        assert_eq!(aligned.slice(..2), b"wx");
        assert_eq!(aligned.slice(1..), b"xyz");
        assert_eq!(aligned.slice(1..=2), b"xy");
        assert_eq!(aligned.chunk(), b"wxyz");

        let mut split = aligned.clone();
        let prefix = split.split_to(2);
        assert_eq!(prefix, b"wx");
        assert_eq!(split, b"yz");

        let mut advanced = aligned.clone();
        advanced.advance(2);
        assert_eq!(advanced.chunk(), b"yz");

        // Partial and full immutable drains should preserve the aligned backing behavior.
        let mut drained = aligned.clone();
        let empty = drained.copy_to_bytes(0);
        assert!(empty.is_empty());
        assert_eq!(drained.as_ref(), &ARRAY[..]);
        let first = drained.copy_to_bytes(1);
        assert_eq!(first.as_ref(), b"w");
        let rest = drained.copy_to_bytes(3);
        assert_eq!(rest.as_ref(), b"xyz");
        assert_eq!(drained.remaining(), 0);

        // Unique aligned immutable buffers can become mutable again.
        let mut unique_source = IoBufMut::zeroed_with_alignment(4, alignment);
        unique_source.as_mut().copy_from_slice(b"pqrs");
        let unique = unique_source.freeze();
        let recovered = unique
            .try_into_mut()
            .expect("unique aligned iobuf should recover mutability");
        assert_eq!(recovered.as_ref(), b"pqrs");

        // Shared aligned immutable buffers must reject the mutable conversion.
        let mut shared_source = IoBufMut::zeroed_with_alignment(4, alignment);
        shared_source.as_mut().copy_from_slice(b"tuvw");
        let shared = shared_source.freeze();
        let _shared_clone = shared.clone();
        assert!(shared.try_into_mut().is_err());

        // Owned/container conversions should preserve bytes for aligned backings.
        let vec_out: Vec<u8> = aligned.clone().into();
        let bytes_out: Bytes = aligned.into();
        assert_eq!(vec_out, ARRAY.to_vec());
        assert_eq!(bytes_out.as_ref(), &ARRAY[..]);

        let from_array = IoBuf::from(ARRAY);
        assert_eq!(from_array, b"wxyz");

        let iobufs = IoBufs::from(ARRAY);
        assert_eq!(iobufs.chunk(), b"wxyz");
    }

    #[test]
    fn test_iobufmut_aligned_zero_length_constructors() {
        let alignment = NonZeroUsize::new(64).expect("non-zero alignment");

        let with_alignment = IoBufMut::with_alignment(0, alignment);
        assert!(with_alignment.is_empty());
        assert_eq!(with_alignment.len(), 0);
        assert_eq!(with_alignment.capacity(), 0);

        let zeroed = IoBufMut::zeroed_with_alignment(0, alignment);
        assert!(zeroed.is_empty());
        assert_eq!(zeroed.len(), 0);
        assert_eq!(zeroed.capacity(), 0);
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
        // `copy_to_bytes_chunked` drops leading empties on zero-length reads
        // and asks for canonicalization so the emptied deque collapses back
        // to the Single representation.
        let mut empty_with_leading = VecDeque::from([IoBuf::default()]);
        let (bytes, needs_canonicalize) = copy_to_bytes_chunked(&mut empty_with_leading, 0, "x");
        assert!(bytes.is_empty());
        assert!(needs_canonicalize);
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

        let mut empty_with_leading_mut = VecDeque::from([IoBufMut::default()]);
        let (bytes, needs_canonicalize) =
            copy_to_bytes_chunked(&mut empty_with_leading_mut, 0, "x");
        assert!(bytes.is_empty());
        assert!(needs_canonicalize);
        assert!(empty_with_leading_mut.is_empty());

        // Mirror the fast/slow chunked helper paths for mutable chunks too.
        let mut fast_mut = VecDeque::from([
            IoBufMut::from(b"ab"),
            IoBufMut::from(b"cd"),
            IoBufMut::from(b"ef"),
            IoBufMut::from(b"gh"),
        ]);
        let (bytes, needs_canonicalize) = copy_to_bytes_chunked(&mut fast_mut, 2, "x");
        assert_eq!(bytes.as_ref(), b"ab");
        assert!(needs_canonicalize);
        assert_eq!(fast_mut.front().expect("front exists").as_ref(), b"cd");

        let mut slow_mut = VecDeque::from([
            IoBufMut::from(b"a"),
            IoBufMut::from(b"bc"),
            IoBufMut::from(b"de"),
            IoBufMut::from(b"f"),
        ]);
        let (bytes, needs_canonicalize) = copy_to_bytes_chunked(&mut slow_mut, 4, "x");
        assert_eq!(bytes.as_ref(), b"abcd");
        assert!(needs_canonicalize);
        assert_eq!(slow_mut.front().expect("front exists").as_ref(), b"e");

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

        // The front-advance helper also has a separate mutable monomorphization.
        let mut advance_chunked_mut = VecDeque::from([
            IoBufMut::default(),
            IoBufMut::from(b"abc"),
            IoBufMut::from(b"d"),
        ]);
        advance_chunked_front(&mut advance_chunked_mut, 2);
        assert_eq!(
            advance_chunked_mut.front().expect("front exists").as_ref(),
            b"c"
        );
        advance_chunked_front(&mut advance_chunked_mut, 2);
        assert!(advance_chunked_mut.is_empty());

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

        // Small-chunk copy canonicalization is also instantiated for mutable chunks.
        let mut small_mut = [
            IoBufMut::from(b"a"),
            IoBufMut::from(b"bc"),
            IoBufMut::from(b"d"),
        ];
        let (bytes, needs_canonicalize) = copy_to_bytes_small_chunks(&mut small_mut, 3, "x");
        assert_eq!(bytes.as_ref(), b"abc");
        assert!(needs_canonicalize);
        assert_eq!(small_mut[2].as_ref(), b"d");

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
        wrapped.push_back(IoBufMut::with_capacity(1));
        wrapped.push_back(IoBufMut::with_capacity(1));
        let _ = wrapped.pop_front();
        wrapped.push_back(IoBufMut::with_capacity(1));
        let (first, second) = wrapped.as_slices();
        assert!(!first.is_empty());
        assert!(!second.is_empty());

        // Force `advance_mut` to consume across the wrapped second slice as well.
        let to_advance = first.len() + 1;
        let mut chunked = IoBufsMut {
            inner: IoBufsMutInner::Chunked(wrapped),
        };
        let before = chunked.remaining_mut();
        // SAFETY: We only verify cursor movement (`remaining`) and do not read bytes.
        unsafe { chunked.advance_mut(to_advance) };
        assert_eq!(chunked.remaining(), to_advance);
        assert_eq!(chunked.remaining_mut(), before - to_advance);
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
        let value = vec![1u8, 2, 3, 4, 5, 6];
        assert_encode_with_pool_matches_encode(&value);
    }

    #[test]
    fn test_encode_with_pool_mut_len_matches_encode_size() {
        let pool = test_pool();
        let value = vec![9u8, 8, 7, 6];

        let buf = value.encode_with_pool_mut(&pool);
        assert_eq!(buf.len(), value.encode_size());
    }

    #[test]
    fn test_iobuf_encode_with_pool_matches_encode() {
        let value = IoBuf::from(vec![0xAB; 512]);
        assert_encode_with_pool_matches_encode(&value);
    }

    #[test]
    fn test_nested_container_encode_with_pool_matches_encode() {
        let value = (
            Some(Bytes::from(vec![0xAA; 256])),
            vec![Bytes::from(vec![0xBB; 128]), Bytes::from(vec![0xCC; 64])],
        );
        assert_encode_with_pool_matches_encode(&value);
    }

    #[test]
    fn test_map_encode_with_pool_matches_encode() {
        let mut btree = BTreeMap::new();
        btree.insert(2u8, Bytes::from(vec![0xDD; 96]));
        btree.insert(1u8, Bytes::from(vec![0xEE; 48]));
        assert_encode_with_pool_matches_encode(&btree);

        let mut hash = HashMap::new();
        hash.insert(2u8, Bytes::from(vec![0x11; 96]));
        hash.insert(1u8, Bytes::from(vec![0x22; 48]));
        assert_encode_with_pool_matches_encode(&hash);
    }

    #[test]
    fn test_lazy_encode_with_pool_matches_encode() {
        let value = Lazy::new(Bytes::from(vec![0x44; 200]));
        assert_encode_with_pool_matches_encode(&value);
    }

    #[test]
    fn test_range_encode_with_pool_matches_encode() {
        let range: Range<Bytes> = Bytes::from(vec![0x10; 32])..Bytes::from(vec![0x20; 48]);
        assert_encode_with_pool_matches_encode(&range);

        let inclusive: RangeInclusive<Bytes> =
            Bytes::from(vec![0x30; 16])..=Bytes::from(vec![0x40; 24]);
        assert_encode_with_pool_matches_encode(&inclusive);

        let from: RangeFrom<IoBuf> = IoBuf::from(vec![0x50; 40])..;
        assert_encode_with_pool_matches_encode(&from);

        let to_inclusive: RangeToInclusive<IoBuf> = ..=IoBuf::from(vec![0x60; 56]);
        assert_encode_with_pool_matches_encode(&to_inclusive);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::IoBuf;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<IoBuf>
        }
    }

    mod builder_tests {
        use super::*;
        use commonware_codec::{BufsMut, Encode, Write};

        fn builder(capacity: usize) -> Builder {
            Builder::new(&test_pool(), NonZeroUsize::new(capacity).unwrap())
        }

        // Only inline writes, no pushes.
        #[test]
        fn test_inline_only() {
            let mut b = builder(64);
            b.put_u32(42);
            b.put_u8(7);
            let mut r = b.finish();
            assert_eq!(r.remaining(), 5);
            assert_eq!(r.get_u32(), 42);
            assert_eq!(r.get_u8(), 7);
        }

        // Only zero-copy pushes, no inline writes.
        #[test]
        fn test_push_only() {
            let mut b = builder(64);
            let data = Bytes::from(vec![0xAA; 1024]);
            b.push(data.clone());
            let mut r = b.finish();
            assert_eq!(r.remaining(), 1024);
            assert_eq!(r.copy_to_bytes(1024), data);
        }

        // Pushed Bytes appear in the output without a payload copy.
        #[test]
        fn test_push_is_zero_copy() {
            let mut b = builder(64);
            b.put_u16(99);
            let payload = Bytes::from(vec![0xDD; 1024]);
            b.push(payload.clone());
            let mut r = b.finish();
            r.advance(2);
            assert_eq!(r.chunk().as_ptr(), payload.as_ptr());
        }

        // Interleaved: inline header, zero-copy push, inline trailer.
        #[test]
        fn test_inline_push_inline() {
            let mut b = builder(64);
            b.put_u16(99);
            let payload = Bytes::from(vec![0xBB; 512]);
            b.push(payload.clone());
            b.put_u8(1);
            let mut r = b.finish();
            assert_eq!(r.remaining(), 2 + 512 + 1);
            assert_eq!(r.get_u16(), 99);
            assert_eq!(r.copy_to_bytes(512), payload);
            assert_eq!(r.get_u8(), 1);
        }

        // Bytes::write_bufs produces identical wire format to Bytes::write.
        #[test]
        fn test_write_bufs_matches_write() {
            let data = Bytes::from(vec![0xCC; 256]);
            let mut b = builder(64);
            data.write_bufs(&mut b);
            let mut bufs = b.finish();

            let mut out = vec![0u8; bufs.remaining()];
            bufs.copy_to_slice(&mut out);
            assert_eq!(out, data.encode().as_ref());
        }

        // Finishing an unused builder produces empty IoBufs.
        #[test]
        fn test_empty() {
            let bufs = builder(64).finish();
            assert_eq!(bufs.remaining(), 0);
        }

        // Inline writes exceeding capacity panic.
        #[test]
        #[should_panic]
        fn test_inline_overflow_panics() {
            let mut b = builder(1);
            let cap = b.remaining_mut();
            b.put_slice(&vec![0xFF; cap]);
            b.put_u8(1); // exceeds capacity
        }

        // Pushing empty Bytes is a no-op.
        #[test]
        fn test_empty_push_ignored() {
            let mut b = builder(64);
            b.push(Bytes::new());
            b.put_u8(1);
            let bufs = b.finish();
            assert_eq!(bufs.remaining(), 1);
        }

        // Consecutive pushes without inline writes between them.
        #[test]
        fn test_multiple_pushes() {
            let mut b = builder(64);
            let a = Bytes::from(vec![0xAA; 100]);
            let c = Bytes::from(vec![0xCC; 200]);
            b.push(a.clone());
            b.push(c.clone());
            let mut r = b.finish();
            assert_eq!(r.remaining(), 300);
            assert_eq!(r.copy_to_bytes(100), a);
            assert_eq!(r.copy_to_bytes(200), c);
        }

        // put() exceeding capacity panics.
        #[test]
        #[should_panic]
        fn test_put_exceeding_capacity_panics() {
            let mut b = builder(1);
            let cap = b.remaining_mut();
            let src = Bytes::from(vec![0xAB; cap + 1]);
            b.put(src);
        }

        // put_slice() exceeding capacity panics.
        #[test]
        #[should_panic]
        fn test_put_slice_exceeding_capacity_panics() {
            let mut b = builder(1);
            let cap = b.remaining_mut();
            b.put_slice(&vec![0xFE; cap + 1]);
        }

        // Simulates a multi-field struct: [u16 | Bytes (via push) | u32].
        // Verifies write_bufs produces identical wire format to write.
        #[test]
        fn test_multi_field_struct_equivalence() {
            let header: u16 = 0xCAFE;
            let payload = Bytes::from(vec![0xDD; 1024]);
            let trailer: u32 = 0xDEADBEEF;

            // Flat encoding via write.
            let size = header.encode_size() + payload.encode_size() + trailer.encode_size();
            let mut flat = BytesMut::with_capacity(size);
            header.write(&mut flat);
            payload.write(&mut flat);
            trailer.write(&mut flat);

            // Multi-buffer encoding via write_bufs.
            let mut b = builder(64);
            header.write(&mut b);
            payload.write_bufs(&mut b);
            trailer.write(&mut b);
            let mut bufs = b.finish();

            let mut out = vec![0u8; bufs.remaining()];
            bufs.copy_to_slice(&mut out);
            assert_eq!(out, flat.as_ref());
        }

        // encode_with_pool (Builder path) matches encode (flat BytesMut path).
        #[test]
        fn test_encode_with_pool_matches_encode() {
            let pool = test_pool();
            let data = Bytes::from(vec![0xEE; 500]);
            let mut pooled = data.encode_with_pool(&pool);
            let baseline = data.encode();
            let mut out = vec![0u8; pooled.remaining()];
            pooled.copy_to_slice(&mut out);
            assert_eq!(out, baseline.as_ref());
        }

        // Exercise remaining_mut, chunk_mut, and advance_mut directly.
        #[test]
        fn test_chunk_mut_and_advance_mut() {
            let mut b = builder(64);
            let initial = b.remaining_mut();
            assert!(initial >= 64);
            let chunk = b.chunk_mut();
            chunk[0..1].copy_from_slice(&[0xAB]);
            // SAFETY: We just wrote 1 byte into chunk_mut above.
            unsafe { b.advance_mut(1) };
            assert_eq!(b.remaining_mut(), initial - 1);
            let mut r = b.finish();
            assert_eq!(r.remaining(), 1);
            assert_eq!(r.get_u8(), 0xAB);
        }

        // Writing past a full buffer panics (fixed capacity).
        #[test]
        #[should_panic]
        fn test_write_past_full_panics() {
            let mut b = builder(1);
            let cap = b.remaining_mut();
            b.put_slice(&vec![0xFF; cap]); // fill the buffer completely
            assert_eq!(b.remaining_mut(), 0);
            b.put_u8(0x42); // panics
        }

        // Push at offset 0 with inline trailer exercises finish branch
        // where offset == pos (no inline prefix before push).
        #[test]
        fn test_push_at_start_with_trailer() {
            let mut b = builder(64);
            let payload = Bytes::from(vec![0xCC; 32]);
            b.push(payload.clone());
            b.put_u8(0x01);
            let mut r = b.finish();
            assert_eq!(r.remaining(), 33);
            assert_eq!(r.copy_to_bytes(32), payload);
            assert_eq!(r.get_u8(), 0x01);
        }
    }
}
