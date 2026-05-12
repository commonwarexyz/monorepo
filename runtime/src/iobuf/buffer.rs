//! Backing storage for [`IoBuf`] and [`super::IoBufMut`].
//!
//! This module contains the low-level allocation handles and the immutable and
//! mutable view types built on top of them:
//! - [`AlignedBuffer`] is self-contained: it carries its own [`Layout`] and
//!   deallocates directly on drop.
//! - [`PooledBuffer`] is the raw pooled allocation handle: it carries only a
//!   pointer and relies on pool-owned metadata to release it.
//! - Pooled views pair that handle with its originating
//!   [`SizeClass`](super::pool::SizeClass) so the buffer is returned to the pool
//!   on drop.
//!
//! The allocator-facing pool logic lives in `pool.rs`. This module only deals
//! with backing ownership and view semantics.

use super::IoBuf;
use crate::iobuf::pool::{BufferPoolThreadCache, SizeClassLease};
use bytes::Bytes;
use std::{
    alloc::{alloc, alloc_zeroed, dealloc, handle_alloc_error, Layout},
    mem::ManuallyDrop,
    ops::{Bound, RangeBounds},
    ptr::NonNull,
    sync::Arc,
};

/// A heap allocation with explicit alignment.
///
/// Owns an aligned region of memory allocated via the global allocator. This
/// handle is self-contained: it stores the [`Layout`] needed to deallocate the
/// region and releases the memory directly on drop.
///
/// This is the raw storage primitive used by untracked aligned buffers.
pub struct AlignedBuffer {
    ptr: NonNull<u8>,
    layout: Layout,
}

// SAFETY: `AlignedBuffer` represents a uniquely-owned heap allocation with no
// aliasing safe references. Sharing only exposes raw pointers or immutable
// slices through higher-level view types.
unsafe impl Send for AlignedBuffer {}
// SAFETY: see above.
unsafe impl Sync for AlignedBuffer {}

impl std::fmt::Debug for AlignedBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBuffer")
            .field("ptr", &self.ptr)
            .field("capacity", &self.capacity())
            .field("alignment", &self.layout.align())
            .finish()
    }
}

impl AlignedBuffer {
    /// Creates a new uninitialized aligned buffer.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `capacity == 0`
    /// - `alignment` is not a power of two
    #[inline]
    pub fn new(capacity: usize, alignment: usize) -> Self {
        assert!(capacity > 0, "capacity must be greater than zero");
        let layout =
            Layout::from_size_align(capacity, alignment).expect("alignment is a power of two");
        // SAFETY: layout is valid and non-zero sized.
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        Self { ptr, layout }
    }

    /// Creates a new zero-initialized aligned buffer.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `capacity == 0`
    /// - `alignment` is not a power of two
    #[inline]
    pub(crate) fn new_zeroed(capacity: usize, alignment: usize) -> Self {
        assert!(capacity > 0, "capacity must be greater than zero");
        let layout =
            Layout::from_size_align(capacity, alignment).expect("alignment is a power of two");
        // SAFETY: layout is valid and non-zero sized.
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        Self { ptr, layout }
    }

    #[inline(always)]
    pub const fn capacity(&self) -> usize {
        self.layout.size()
    }

    #[inline(always)]
    pub const fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for AlignedBuffer {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: ptr/layout came from the global allocator and are unchanged.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

/// A raw pooled allocation handle whose layout is stored by its size class.
///
/// Unlike [`AlignedBuffer`], this handle intentionally carries only the
/// allocation pointer. The size-class freelist stores the allocation layout, so
/// moving pooled buffers through checked-out values and thread-local caches
/// does not need to move a per-buffer [`Layout`].
///
/// `PooledBuffer` does not implement [`Drop`] and has no reference to its
/// originating [`SizeClass`](super::pool::SizeClass). It must be paired with
/// pool metadata that returns it to the size class, or explicitly deallocated
/// with the exact layout used to create it.
pub struct PooledBuffer {
    ptr: NonNull<u8>,
}

// SAFETY: `PooledBuffer` represents a uniquely-owned heap allocation with no
// aliasing safe references. Sharing only exposes raw pointers or immutable
// slices through higher-level view types.
unsafe impl Send for PooledBuffer {}
// SAFETY: see above.
unsafe impl Sync for PooledBuffer {}

impl std::fmt::Debug for PooledBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuffer")
            .field("ptr", &self.ptr)
            .finish()
    }
}

impl PooledBuffer {
    /// Creates a new uninitialized pooled buffer for `layout`.
    ///
    /// # Panics
    ///
    /// Panics if `layout` has zero size.
    #[inline]
    pub fn new(layout: Layout) -> Self {
        assert!(layout.size() > 0, "layout size must be non-zero");
        // SAFETY: layout is valid and non-zero sized.
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        Self { ptr }
    }

    /// Creates a new zero-initialized pooled buffer for `layout`.
    ///
    /// # Panics
    ///
    /// Panics if `layout` has zero size.
    #[inline]
    pub fn new_zeroed(layout: Layout) -> Self {
        assert!(layout.size() > 0, "layout size must be non-zero");
        // SAFETY: layout is valid and non-zero sized.
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        Self { ptr }
    }

    /// Returns the allocation pointer.
    #[inline(always)]
    pub const fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Deallocates this pooled buffer.
    ///
    /// # Safety
    ///
    /// `layout` must exactly match the layout used to allocate this buffer.
    #[inline(always)]
    pub unsafe fn deallocate(self, layout: Layout) {
        // SAFETY: guaranteed by the caller.
        unsafe { dealloc(self.ptr.as_ptr(), layout) };
    }
}

/// Owning allocation handle used by buffer views.
///
/// [`Buf`] and [`BufMut`] are generic over this trait so their view logic can
/// stay shared while each backing decides how the allocation is described and
/// released. Implementations must own exactly one allocation, report its full
/// capacity, expose its base pointer, and consume themselves in
/// [`Self::release`].
///
/// [`AlignedBuffer`] is self-contained and releases directly. [`PooledBacking`]
/// pairs a layoutless [`PooledBuffer`] with its [`SizeClassLease`] and slot id,
/// so release returns the allocation to the pool.
pub(crate) trait BufferBacking: Send + Sync + 'static {
    /// Returns the full allocation capacity, ignoring any view cursor/offset.
    fn capacity(&self) -> usize;

    /// Returns the base allocation pointer.
    fn as_ptr(&self) -> *mut u8;

    /// Consumes the backing and releases the allocation.
    fn release(self);
}

impl BufferBacking for AlignedBuffer {
    #[inline(always)]
    fn capacity(&self) -> usize {
        self.capacity()
    }

    #[inline(always)]
    fn as_ptr(&self) -> *mut u8 {
        self.as_ptr()
    }

    #[inline(always)]
    fn release(self) {
        drop(self);
    }
}

/// Pooled backing storage.
///
/// This pairs a layoutless [`PooledBuffer`] with the lease needed to return it
/// to the pool. The [`SizeClassLease`] points to the originating size class and
/// owns that class reference while the buffer is checked out or shared through
/// immutable views.
pub(crate) struct PooledBacking {
    buffer: PooledBuffer,
    lease: SizeClassLease,
    slot: u32,
}

impl BufferBacking for PooledBacking {
    #[inline(always)]
    fn capacity(&self) -> usize {
        self.lease.size()
    }

    #[inline(always)]
    fn as_ptr(&self) -> *mut u8 {
        self.buffer.as_ptr()
    }

    #[inline(always)]
    fn release(self) {
        BufferPoolThreadCache::push(self.lease, self.slot, self.buffer);
    }
}

/// Shared allocation with backing-specific release behavior.
///
/// This is the single ownership point for the underlying backing allocation.
/// Immutable views hold it behind an [`Arc`], while mutable views own it
/// directly and may later freeze it into an immutable shared view.
struct BufInner<B: BufferBacking> {
    buffer: ManuallyDrop<B>,
}

impl<B: BufferBacking> BufInner<B> {
    #[inline]
    const fn new(buffer: B) -> Self {
        Self {
            buffer: ManuallyDrop::new(buffer),
        }
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.buffer.capacity()
    }
}

impl<B: BufferBacking> Drop for BufInner<B> {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: Drop is called at most once for this value.
        let buffer = unsafe { ManuallyDrop::take(&mut self.buffer) };
        buffer.release();
    }
}

/// Immutable, reference-counted view over fixed-capacity backing storage.
///
/// Cloning is cheap and shares the same underlying aligned allocation.
///
/// The backing type decides what happens when the final reference is dropped:
/// untracked aligned buffers deallocate directly, while pooled buffers return
/// the allocation to their originating size class.
///
/// # View Layout
///
/// ```text
/// [0................offset...........offset+len...........capacity]
///  ^                 ^                   ^                    ^
///  |                 |                   |                    |
///  allocation start  first readable      end of readable      allocation end
///                    byte of this view   region for this view
/// ```
///
/// Regions:
/// - `[0..offset)`: not readable from this view
/// - `[offset..offset+len)`: readable bytes for this view
/// - `[offset+len..capacity)`: not readable from this view
///
/// # Invariants
///
/// - `offset <= capacity`
/// - `offset + len <= capacity`
///
/// This representation allows sliced views to preserve their current readable
/// window while still supporting `try_into_mut` when uniquely owned.
pub(crate) struct Buf<B: BufferBacking> {
    inner: Arc<BufInner<B>>,
    offset: usize,
    len: usize,
}

impl<B: BufferBacking> Buf<B> {
    /// Returns a pointer to the first readable byte.
    #[inline]
    pub(crate) fn as_ptr(&self) -> *const u8 {
        // SAFETY: offset is always within the underlying allocation.
        unsafe { self.inner.buffer.as_ptr().add(self.offset) }
    }

    /// Returns a slice of this view (zero-copy).
    ///
    /// The range is resolved relative to this view's readable window
    /// (`0..self.len`), not relative to the allocation start.
    ///
    /// Returns `None` for empty ranges, allowing callers to detach from the
    /// underlying allocation.
    pub(crate) fn slice(&self, range: impl RangeBounds<usize>) -> Option<Self> {
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

        if start == end {
            return None;
        }

        Some(Self {
            inner: Arc::clone(&self.inner),
            offset: self.offset + start,
            len: end - start,
        })
    }

    /// Splits the buffer into two at the given index.
    ///
    /// Afterwards `self` contains bytes `[at, len)`, and the returned buffer
    /// contains bytes `[0, at)`.
    ///
    /// This is an `O(1)` zero-copy operation.
    ///
    /// # Panics
    ///
    /// Panics if `at > len`.
    #[inline]
    pub(crate) fn split_to(&mut self, at: usize) -> Self {
        assert!(
            at <= self.len,
            "split_to out of bounds: {:?} <= {:?}",
            at,
            self.len,
        );

        let prefix = Self {
            inner: Arc::clone(&self.inner),
            offset: self.offset,
            len: at,
        };

        self.offset += at;
        self.len -= at;
        prefix
    }

    /// Try to recover mutable ownership without copying.
    ///
    /// This succeeds only when this is the sole remaining reference to the
    /// underlying allocation (`Arc` strong count is 1).
    ///
    /// On success, the returned mutable buffer preserves the readable bytes and
    /// mutable capacity from this view's current offset to the end of the
    /// allocation. This means uniquely-owned sliced views can also be recovered
    /// as mutable buffers while keeping the same readable window.
    ///
    /// On failure, returns `self` unchanged.
    pub(crate) fn try_into_mut(self) -> Result<BufMut<B>, Self> {
        let Self { inner, offset, len } = self;
        match Arc::try_unwrap(inner) {
            Ok(inner) => Ok(BufMut {
                inner: ManuallyDrop::new(inner),
                cursor: offset,
                len: offset.checked_add(len).expect("slice end overflow"),
            }),
            Err(inner) => Err(Self { inner, offset, len }),
        }
    }

    /// Converts this view into [`Bytes`] without copying.
    ///
    /// Empty views return detached [`Bytes::new`] so the underlying allocation
    /// is not retained by an empty owner.
    pub(crate) fn into_bytes(self) -> Bytes {
        if self.len == 0 {
            return Bytes::new();
        }
        Bytes::from_owner(self)
    }
}

impl<B: BufferBacking> AsRef<[u8]> for Buf<B> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: offset/len are always bounded within the underlying allocation.
        unsafe { std::slice::from_raw_parts(self.inner.buffer.as_ptr().add(self.offset), self.len) }
    }
}

impl<B: BufferBacking> Clone for Buf<B> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            offset: self.offset,
            len: self.len,
        }
    }
}

impl<B: BufferBacking> bytes::Buf for Buf<B> {
    #[inline]
    fn remaining(&self) -> usize {
        self.len
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.as_ref()
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.len, "cannot advance past end of buffer");
        self.offset += cnt;
        self.len -= cnt;
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        assert!(len <= self.len, "copy_to_bytes out of bounds");
        if len == 0 {
            return Bytes::new();
        }
        let slice = Self {
            inner: Arc::clone(&self.inner),
            offset: self.offset,
            len,
        };
        self.advance(len);
        slice.into_bytes()
    }
}

/// Mutable fixed-capacity buffer view.
///
/// When dropped, the underlying buffer is released according to `B`: untracked
/// aligned buffers deallocate directly, while pooled buffers return to the
/// pool.
///
/// # Buffer Layout
///
/// ```text
/// [0................cursor..............len.............raw_capacity]
///  ^                 ^                   ^                 ^
///  |                 |                   |                 |
///  allocation start  read position       write position    allocation end
///                    (consumed prefix)   (initialized)
///
/// Regions:
/// - [0..cursor]:        consumed (via [`bytes::Buf::advance`]), no longer accessible
/// - [cursor..len]:      readable bytes (as_ref returns this slice)
/// - [len..raw_capacity): uninitialized, writable via [`bytes::BufMut`]
/// ```
///
/// # Invariants
///
/// - `cursor <= len <= raw_capacity`
/// - Bytes in `0..len` have been initialized (safe to read)
/// - Bytes in `len..raw_capacity` are uninitialized (write-only via [`bytes::BufMut`])
///
/// # Computed Values
///
/// - `len()` = readable bytes = `self.len - cursor`
/// - `capacity()` = view capacity = `raw_capacity - cursor` (shrinks after advance)
/// - `remaining_mut()` = writable bytes = `raw_capacity - self.len`
///
/// This matches [`bytes::BytesMut`] semantics.
///
/// # Fixed Capacity
///
/// Unlike [`bytes::BytesMut`], aligned buffers have fixed capacity and do not
/// grow automatically. Calling [`bytes::BufMut::put_slice`] or other
/// [`bytes::BufMut`] methods that would exceed capacity will panic (per the
/// [`bytes::BufMut`] trait contract).
pub(crate) struct BufMut<B: BufferBacking> {
    inner: ManuallyDrop<BufInner<B>>,
    /// Read cursor position (for `Buf` trait).
    cursor: usize,
    /// Number of bytes written (initialized).
    len: usize,
}

impl<B: BufferBacking> BufMut<B> {
    /// Capacity of the underlying allocation (ignoring cursor).
    #[inline]
    fn raw_capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Converts this mutable buffer into a shared immutable view.
    ///
    /// Wraps `self` in [`ManuallyDrop`] to suppress its `Drop` impl, then
    /// moves the inner state into an `Arc`-backed [`Buf`]. The resulting
    /// view covers only the current readable window (`cursor..len`).
    fn into_shared(self) -> Buf<B> {
        let mut me = ManuallyDrop::new(self);
        // SAFETY: `me` is wrapped in `ManuallyDrop`, so its `Drop` impl will not run.
        let inner = unsafe { ManuallyDrop::take(&mut me.inner) };
        Buf {
            inner: Arc::new(inner),
            offset: me.cursor,
            len: me.len - me.cursor,
        }
    }

    /// Returns the number of readable bytes remaining in the buffer.
    ///
    /// This is `len - cursor`, matching [`bytes::BytesMut`] semantics.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len - self.cursor
    }

    /// Returns true if no readable bytes remain.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.cursor == self.len
    }

    /// Returns the number of bytes the buffer can hold without reallocating.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity() - self.cursor
    }

    /// Returns an unsafe mutable pointer to the buffer's data.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        // SAFETY: cursor is always <= raw capacity.
        unsafe { self.inner.buffer.as_ptr().add(self.cursor) }
    }

    /// Sets the length of the buffer (view-relative).
    ///
    /// This will explicitly set the size of the buffer without actually
    /// modifying the data, so it is up to the caller to ensure that the data
    /// has been initialized.
    ///
    /// The `len` parameter is relative to the current view (after any `advance`
    /// calls), matching [`bytes::BytesMut::set_len`] semantics.
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// - All bytes in the range `[cursor, cursor + len)` are initialized
    /// - `len <= capacity()` (where capacity is view-relative)
    #[inline]
    pub const unsafe fn set_len(&mut self, len: usize) {
        self.len = self.cursor + len;
    }

    /// Clears the buffer, removing all data. Existing capacity is preserved.
    #[inline]
    pub const fn clear(&mut self) {
        self.len = self.cursor;
    }

    /// Truncates the buffer to at most `len` readable bytes.
    ///
    /// If `len` is greater than the current readable length, this has no effect.
    /// This operates on readable bytes (after cursor), matching
    /// [`bytes::BytesMut::truncate`] semantics for buffers that have been advanced.
    #[inline]
    pub const fn truncate(&mut self, len: usize) {
        if len < self.len() {
            self.len = self.cursor + len;
        }
    }

    /// Converts the current readable window into [`Bytes`] without copying.
    ///
    /// Empty buffers return detached [`Bytes::new`] so aligned memory is not
    /// retained by an empty owner.
    pub fn into_bytes(self) -> Bytes {
        if self.is_empty() {
            return Bytes::new();
        }
        Bytes::from_owner(self.into_shared())
    }
}

impl<B: BufferBacking> AsRef<[u8]> for BufMut<B> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: bytes from cursor..len have been initialized.
        unsafe {
            std::slice::from_raw_parts(self.inner.buffer.as_ptr().add(self.cursor), self.len())
        }
    }
}

impl<B: BufferBacking> AsMut<[u8]> for BufMut<B> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        let len = self.len();
        // SAFETY: bytes from cursor..len have been initialized.
        unsafe { std::slice::from_raw_parts_mut(self.inner.buffer.as_ptr().add(self.cursor), len) }
    }
}

impl<B: BufferBacking> Drop for BufMut<B> {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: Drop is only called once. freeze() wraps self in ManuallyDrop
        // to prevent this Drop impl from running after ownership is transferred.
        unsafe { ManuallyDrop::drop(&mut self.inner) };
    }
}

impl<B: BufferBacking> bytes::Buf for BufMut<B> {
    #[inline]
    fn remaining(&self) -> usize {
        self.len - self.cursor
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.as_ref()
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        let remaining = self.len - self.cursor;
        assert!(cnt <= remaining, "cannot advance past end of buffer");
        self.cursor += cnt;
    }
}

// SAFETY: `BufMut` exposes the uninitialized tail `[len..raw_capacity)` and
// only advances within the underlying allocation bounds.
unsafe impl<B: BufferBacking> bytes::BufMut for BufMut<B> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.raw_capacity() - self.len
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        assert!(
            cnt <= self.remaining_mut(),
            "cannot advance past end of buffer"
        );
        self.len += cnt;
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        let raw_cap = self.raw_capacity();
        let len = self.len;
        // SAFETY: We have exclusive access and the slice is within raw capacity.
        unsafe {
            let ptr = self.inner.buffer.as_ptr().add(len);
            bytes::buf::UninitSlice::from_raw_parts_mut(ptr, raw_cap - len)
        }
    }
}

/// Immutable, reference-counted view over an untracked aligned allocation.
///
/// The final reference deallocates the underlying aligned buffer directly.
pub(crate) type AlignedBuf = Buf<AlignedBuffer>;

/// Immutable, reference-counted view over a pooled allocation.
///
/// The final reference returns the underlying allocation to its originating
/// [`SizeClass`](super::pool::SizeClass). See [`Buf`] for the shared immutable
/// view layout and invariants.
pub(crate) type PooledBuf = Buf<PooledBacking>;

/// Mutable view over an untracked aligned allocation.
///
/// When dropped, the underlying aligned allocation is deallocated directly.
/// See [`BufMut`] for the shared mutable layout and invariants.
pub(crate) type AlignedBufMut = BufMut<AlignedBuffer>;

/// Mutable view over a pooled allocation.
///
/// When dropped, the underlying allocation is returned to its originating
/// [`SizeClass`](super::pool::SizeClass). See [`BufMut`] for the shared mutable
/// layout and invariants.
pub(crate) type PooledBufMut = BufMut<PooledBacking>;

impl std::fmt::Debug for Buf<AlignedBuffer> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBuf")
            .field("offset", &self.offset)
            .field("len", &self.len)
            .field("capacity", &self.inner.capacity())
            .finish()
    }
}

impl std::fmt::Debug for Buf<PooledBacking> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuf")
            .field("offset", &self.offset)
            .field("len", &self.len)
            .field("capacity", &self.inner.capacity())
            .finish()
    }
}

impl std::fmt::Debug for BufMut<AlignedBuffer> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBufMut")
            .field("cursor", &self.cursor)
            .field("len", &self.len)
            .field("capacity", &self.capacity())
            .finish()
    }
}

impl BufMut<AlignedBuffer> {
    #[inline]
    pub(crate) const fn new(buffer: AlignedBuffer) -> Self {
        Self {
            inner: ManuallyDrop::new(BufInner::new(buffer)),
            cursor: 0,
            len: 0,
        }
    }

    pub(crate) fn into_aligned(self) -> AlignedBuf {
        self.into_shared()
    }

    pub fn freeze(self) -> IoBuf {
        IoBuf::from_aligned(self.into_aligned())
    }
}

impl std::fmt::Debug for BufMut<PooledBacking> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBufMut")
            .field("cursor", &self.cursor)
            .field("len", &self.len)
            .field("capacity", &self.capacity())
            .finish()
    }
}

impl BufMut<PooledBacking> {
    #[inline]
    pub(crate) const fn new(buffer: PooledBuffer, lease: SizeClassLease, slot: u32) -> Self {
        Self {
            inner: ManuallyDrop::new(BufInner::new(PooledBacking {
                buffer,
                lease,
                slot,
            })),
            cursor: 0,
            len: 0,
        }
    }

    /// Convert into an immutable pooled view over the current readable window.
    pub(crate) fn into_pooled(self) -> PooledBuf {
        self.into_shared()
    }

    /// Freezes the buffer into an immutable [`IoBuf`].
    ///
    /// Only the readable portion (`cursor..len`) is included in the result.
    /// The underlying buffer will be returned to the pool when all references
    /// to the [`IoBuf`] (including slices) are dropped.
    pub fn freeze(self) -> IoBuf {
        IoBuf::from_pooled(self.into_pooled())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        iobuf::pool::{BufferPool, BufferPoolConfig, BufferPoolThreadCacheConfig},
        telemetry::metrics::Registry,
    };
    use bytes::{Buf, BufMut, Bytes, BytesMut};
    use commonware_utils::{NZUsize, NZU32};
    use std::ops::Bound;

    fn page_size() -> usize {
        BufferPoolConfig::for_storage().min_size.get()
    }

    fn test_pool(config: BufferPoolConfig) -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(config, &mut registry)
    }

    fn test_config(min_size: usize, max_size: usize, max_per_class: u32) -> BufferPoolConfig {
        BufferPoolConfig {
            pool_min_size: 0,
            min_size: NZUsize!(min_size),
            max_size: NZUsize!(max_size),
            max_per_class: NZU32!(max_per_class),
            parallelism: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::Enabled(None),
            prefill: false,
            alignment: NZUsize!(page_size()),
        }
    }

    #[test]
    fn test_aligned_buffer() {
        // Page-aligned allocation should report correct capacity and alignment.
        let page = page_size();
        let buf = AlignedBuffer::new(4096, page);
        assert_eq!(buf.capacity(), 4096);
        assert!((buf.as_ptr() as usize).is_multiple_of(page));

        // Cache-line-aligned allocation should also satisfy its alignment.
        let cache_line = BufferPoolConfig::for_network().alignment.get();
        let buf2 = AlignedBuffer::new(4096, cache_line);
        assert_eq!(buf2.capacity(), 4096);
        assert!((buf2.as_ptr() as usize).is_multiple_of(cache_line));
    }

    #[test]
    #[should_panic(expected = "capacity must be greater than zero")]
    fn test_aligned_buffer_zero_capacity_panics() {
        let _ = AlignedBuffer::new(0, page_size());
    }

    #[test]
    #[should_panic(expected = "capacity must be greater than zero")]
    fn test_aligned_buffer_zeroed_zero_capacity_panics() {
        let _ = AlignedBuffer::new_zeroed(0, page_size());
    }

    #[test]
    fn test_untracked_aligned_debug_and_view_paths() {
        let page = page_size();

        // Cover debug formatting for the raw aligned owner.
        let buffer = AlignedBuffer::new(16, page);
        let buffer_debug = format!("{buffer:?}");
        assert!(buffer_debug.contains("AlignedBuffer"));
        assert!(buffer_debug.contains("capacity"));

        // Exercise the mutable aligned wrapper through Buf/BufMut-style access.
        let mut aligned_mut = AlignedBufMut::new(buffer);
        let aligned_mut_debug = format!("{aligned_mut:?}");
        assert!(aligned_mut_debug.contains("AlignedBufMut"));
        assert!(aligned_mut.is_empty());

        aligned_mut.put_slice(b"abcdefgh");
        assert_eq!(aligned_mut.as_mut(), b"abcdefgh");
        assert_eq!(Buf::remaining(&aligned_mut), 8);
        assert_eq!(Buf::chunk(&aligned_mut), b"abcdefgh");

        Buf::advance(&mut aligned_mut, 2);
        assert_eq!(aligned_mut.as_mut_ptr() as usize % page, 2);
        assert_eq!(Buf::chunk(&aligned_mut), b"cdefgh");

        let prefix = Buf::copy_to_bytes(&mut aligned_mut, 2);
        assert_eq!(prefix.as_ref(), b"cd");
        assert_eq!(Buf::chunk(&aligned_mut), b"efgh");

        aligned_mut.clear();
        assert!(aligned_mut.is_empty());
        aligned_mut.put_slice(b"wxyz");

        // Empty aligned owners should detach into empty Bytes cleanly.
        let empty_bytes = AlignedBufMut::new(AlignedBuffer::new(8, page)).into_bytes();
        assert!(empty_bytes.is_empty());
        let empty_bytes = AlignedBufMut::new(AlignedBuffer::new(8, page))
            .into_aligned()
            .into_bytes();
        assert!(empty_bytes.is_empty());

        // Non-empty mutable owners should hand their readable window to Bytes
        // without copying.
        let mut bytes_mut_source = AlignedBufMut::new(AlignedBuffer::new(8, page));
        bytes_mut_source.put_slice(b"data");
        let owned_bytes = bytes_mut_source.into_bytes();
        assert_eq!(owned_bytes.as_ref(), b"data");

        // Cover immutable debug/view/slice paths on the aligned wrapper.
        let mut aligned = aligned_mut.into_aligned();
        let aligned_debug = format!("{aligned:?}");
        assert!(aligned_debug.contains("AlignedBuf"));
        assert_eq!(aligned.as_ptr(), aligned.as_ref().as_ptr());
        assert_eq!(aligned.as_ref(), b"wxyz");
        assert_eq!(aligned.slice(..2).unwrap().as_ref(), b"wx");
        assert_eq!(aligned.slice(..=2).unwrap().as_ref(), b"wxy");
        assert_eq!(aligned.slice(1..).unwrap().as_ref(), b"xyz");
        assert_eq!(aligned.slice(1..=2).unwrap().as_ref(), b"xy");
        assert_eq!(
            aligned
                .slice((Bound::Included(1), Bound::Excluded(3)))
                .unwrap()
                .as_ref(),
            b"xy"
        );

        let mut split = aligned.clone();
        let split_prefix = split.split_to(2);
        assert_eq!(split_prefix.as_ref(), b"wx");
        assert_eq!(split.as_ref(), b"yz");

        let head = Buf::copy_to_bytes(&mut aligned, 1);
        assert_eq!(head.as_ref(), b"w");
        let tail = Buf::copy_to_bytes(&mut aligned, 3);
        assert_eq!(tail.as_ref(), b"xyz");
        assert_eq!(Buf::remaining(&aligned), 0);

        // Unique aligned owners can recover mutability without copying.
        let mut unique_source = AlignedBufMut::new(AlignedBuffer::new(8, page));
        unique_source.put_slice(b"qrst");
        let unique = unique_source.into_aligned();
        let recovered = unique
            .try_into_mut()
            .expect("unique aligned buffer should recover mutability");
        assert_eq!(recovered.as_ref(), b"qrst");

        // Shared aligned owners must refuse the mutable conversion.
        let mut shared_source = AlignedBufMut::new(AlignedBuffer::new(8, page));
        shared_source.put_slice(b"uvwx");
        let shared = shared_source.into_aligned();
        let _clone = shared.clone();
        assert!(shared.try_into_mut().is_err());

        // Fully draining a unique aligned owner should hand back owned Bytes.
        let mut bytes_source = AlignedBufMut::new(AlignedBuffer::new(8, page));
        bytes_source.put_slice(b"lmno");
        let owned_bytes = bytes_source.into_aligned().into_bytes();
        assert_eq!(owned_bytes.as_ref(), b"lmno");
    }

    #[test]
    fn test_pooled_buf_mut_freeze() {
        // Freeze a pooled mutable buffer and verify content is preserved in the
        // resulting immutable view, including slices.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        // Write data into a pooled buffer.
        let mut buf = pool.try_alloc(11).unwrap();
        buf.put_slice(&[0u8; 11]);
        assert_eq!(buf.len(), 11);
        buf.as_mut()[..5].copy_from_slice(&[1, 2, 3, 4, 5]);

        // Freeze preserves the content.
        let iobuf = buf.freeze();
        assert_eq!(iobuf.len(), 11);
        assert_eq!(&iobuf.as_ref()[..5], &[1, 2, 3, 4, 5]);

        // Slicing the frozen buffer works.
        let slice = iobuf.slice(0..5);
        assert_eq!(slice.len(), 5);
        let slice = iobuf.slice(1..=4);
        assert_eq!(slice.as_ref(), &[2, 3, 4, 5]);
    }

    #[test]
    #[should_panic(expected = "range start overflow")]
    fn test_pooled_slice_excluded_start_overflow() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 1));

        let pooled = pool.try_alloc(page).unwrap().freeze();
        let _ = pooled.slice((Bound::Excluded(usize::MAX), Bound::<usize>::Unbounded));
    }

    #[test]
    fn test_bytes_parity_iobuf_buf_trait() {
        // Verify pooled IoBuf matches Bytes semantics for Buf trait methods.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 10));

        let data: Vec<u8> = (0..100u8).collect();

        let mut pooled_mut = pool.try_alloc(data.len()).unwrap();
        pooled_mut.put_slice(&data);
        let mut pooled = pooled_mut.freeze();
        let mut bytes = Bytes::from(data);

        // remaining() + chunk()
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // advance()
        Buf::advance(&mut bytes, 13);
        Buf::advance(&mut pooled, 13);
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // copy_to_bytes(0)
        let bytes_zero = Buf::copy_to_bytes(&mut bytes, 0);
        let pooled_zero = Buf::copy_to_bytes(&mut pooled, 0);
        assert_eq!(bytes_zero, pooled_zero);
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // copy_to_bytes(n)
        let bytes_mid = Buf::copy_to_bytes(&mut bytes, 17);
        let pooled_mid = Buf::copy_to_bytes(&mut pooled, 17);
        assert_eq!(bytes_mid, pooled_mid);
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // copy_to_bytes(remaining)
        let remaining = Buf::remaining(&bytes);
        let bytes_rest = Buf::copy_to_bytes(&mut bytes, remaining);
        let pooled_rest = Buf::copy_to_bytes(&mut pooled, remaining);
        assert_eq!(bytes_rest, pooled_rest);
        assert_eq!(Buf::remaining(&bytes), 0);
        assert_eq!(Buf::remaining(&pooled), 0);
        assert!(!Buf::has_remaining(&bytes));
        assert!(!Buf::has_remaining(&pooled));
    }

    #[test]
    fn test_bytes_parity_iobuf_slice() {
        // Verify pooled IoBuf slice behavior matches Bytes for content semantics.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 10));

        let data: Vec<u8> = (0..32u8).collect();
        let mut pooled_mut = pool.try_alloc(data.len()).unwrap();
        pooled_mut.put_slice(&data);
        let pooled = pooled_mut.freeze();
        let bytes = Bytes::from(data);

        assert_eq!(pooled.slice(..5).as_ref(), bytes.slice(..5).as_ref());
        assert_eq!(pooled.slice(6..).as_ref(), bytes.slice(6..).as_ref());
        assert_eq!(pooled.slice(3..8).as_ref(), bytes.slice(3..8).as_ref());
        assert_eq!(pooled.slice(..=7).as_ref(), bytes.slice(..=7).as_ref());
        assert_eq!(pooled.slice(10..10).as_ref(), bytes.slice(10..10).as_ref());
    }

    #[test]
    fn test_bytes_parity_iobuf_split_to() {
        // Verify pooled IoBuf split_to matches Bytes split_to semantics.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 1));

        let mut pooled_mut = pool.try_alloc(8).unwrap();
        pooled_mut.put_slice(b"abcdefgh");
        let mut pooled = pooled_mut.freeze();
        let mut bytes = Bytes::from_static(b"abcdefgh");

        // split_to(0)
        assert_eq!(pooled.split_to(0).as_ref(), bytes.split_to(0).as_ref());
        assert_eq!(pooled.as_ref(), bytes.as_ref());

        // split_to(n)
        assert_eq!(pooled.split_to(3).as_ref(), bytes.split_to(3).as_ref());
        assert_eq!(pooled.as_ref(), bytes.as_ref());

        // split_to(remaining)
        let remaining = bytes.remaining();
        assert_eq!(
            pooled.split_to(remaining).as_ref(),
            bytes.split_to(remaining).as_ref()
        );
        assert_eq!(pooled.as_ref(), bytes.as_ref());
    }

    #[test]
    #[should_panic(expected = "split_to out of bounds")]
    fn test_iobuf_split_to_out_of_bounds() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 1));

        let mut pooled_mut = pool.try_alloc(3).unwrap();
        pooled_mut.put_slice(b"abc");
        let mut pooled = pooled_mut.freeze();
        let _ = pooled.split_to(4);
    }

    #[test]
    fn test_bytesmut_parity_buf_trait() {
        // Verify PooledBufMut matches BytesMut semantics for Buf trait.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 10));

        let mut bytes = BytesMut::with_capacity(100);
        bytes.put_slice(&[0xAAu8; 50]);

        let mut pooled = pool.try_alloc(100).unwrap();
        pooled.put_slice(&[0xAAu8; 50]);

        // remaining()
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));
        // chunk()
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // advance()
        Buf::advance(&mut bytes, 10);
        Buf::advance(&mut pooled, 10);
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // advance to end
        let remaining = Buf::remaining(&bytes);
        Buf::advance(&mut bytes, remaining);
        Buf::advance(&mut pooled, remaining);
        assert_eq!(Buf::remaining(&bytes), 0);
        assert_eq!(Buf::remaining(&pooled), 0);
        assert!(!Buf::has_remaining(&bytes));
        assert!(!Buf::has_remaining(&pooled));
    }

    #[test]
    fn test_bytesmut_parity_bufmut_trait() {
        // Verify PooledBufMut matches BytesMut semantics for BufMut trait.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 10));

        let mut bytes = BytesMut::with_capacity(100);
        let mut pooled = pool.try_alloc(100).unwrap();

        // remaining_mut()
        assert!(bytes::BufMut::remaining_mut(&bytes) >= 100);
        assert!(bytes::BufMut::remaining_mut(&pooled) >= 100);

        // put_slice()
        bytes::BufMut::put_slice(&mut bytes, b"hello");
        bytes::BufMut::put_slice(&mut pooled, b"hello");
        assert_eq!(bytes.as_ref(), pooled.as_ref());

        // put_u8()
        bytes::BufMut::put_u8(&mut bytes, 0x42);
        bytes::BufMut::put_u8(&mut pooled, 0x42);
        assert_eq!(bytes.as_ref(), pooled.as_ref());

        // chunk_mut() - verify we can write to it
        let bytes_chunk = bytes::BufMut::chunk_mut(&mut bytes);
        let pooled_chunk = bytes::BufMut::chunk_mut(&mut pooled);
        assert!(bytes_chunk.len() > 0);
        assert!(pooled_chunk.len() > 0);
    }

    #[test]
    fn test_bytesmut_parity_after_advance_paths() {
        // Verify PooledBufMut matches BytesMut after advance for truncate,
        // clear, set_len, and put operations.
        let page = page_size();
        let pool = test_pool(test_config(page, page * 4, 10));

        // truncate after advance
        {
            let mut bytes = BytesMut::with_capacity(100);
            bytes.put_slice(&[0xAAu8; 50]);
            Buf::advance(&mut bytes, 10);
            let mut pooled = pool.try_alloc(100).unwrap();
            pooled.put_slice(&[0xAAu8; 50]);
            Buf::advance(&mut pooled, 10);
            bytes.truncate(20);
            pooled.truncate(20);
            assert_eq!(bytes.as_ref(), pooled.as_ref());
        }

        // clear after advance
        {
            let mut bytes = BytesMut::with_capacity(100);
            bytes.put_slice(&[0xAAu8; 50]);
            Buf::advance(&mut bytes, 10);
            let mut pooled = pool.try_alloc(100).unwrap();
            pooled.put_slice(&[0xAAu8; 50]);
            Buf::advance(&mut pooled, 10);
            bytes.clear();
            pooled.clear();
            assert_eq!(bytes.len(), 0);
            assert_eq!(pooled.len(), 0);
        }

        // capacity/set_len/clear semantics after advance
        {
            let mut bytes = BytesMut::with_capacity(page);
            bytes.resize(50, 0xBB);
            Buf::advance(&mut bytes, 20);
            let mut pooled = pool.try_alloc(page).unwrap();
            pooled.put_slice(&[0xBB; 50]);
            Buf::advance(&mut pooled, 20);
            assert_eq!(bytes.capacity(), pooled.capacity());
            // SAFETY: shrink readable window to initialized region.
            unsafe {
                bytes.set_len(25);
                pooled.set_len(25);
            }
            assert_eq!(bytes.as_ref(), pooled.as_ref());
            let bytes_cap = bytes.capacity();
            let pooled_cap = pooled.capacity();
            bytes.clear();
            pooled.clear();
            assert_eq!(bytes.capacity(), bytes_cap);
            assert_eq!(pooled.capacity(), pooled_cap);
        }

        // put after advance + truncate-beyond-len no-op
        {
            let mut bytes = BytesMut::with_capacity(100);
            bytes.resize(30, 0xAA);
            Buf::advance(&mut bytes, 10);
            bytes.put_slice(&[0xBB; 10]);
            bytes.truncate(100);

            let mut pooled = pool.try_alloc(100).unwrap();
            pooled.put_slice(&[0xAA; 30]);
            Buf::advance(&mut pooled, 10);
            pooled.put_slice(&[0xBB; 10]);
            pooled.truncate(100);
            assert_eq!(bytes.as_ref(), pooled.as_ref());
        }
    }

    #[test]
    fn test_alloc_and_freeze_view_paths() {
        // Allocation edge cases and freeze behavior after advance/clear.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 10));

        // Zero-capacity request should round up to the minimum size class.
        let buf = pool.try_alloc(0).expect("zero capacity should succeed");
        assert_eq!(buf.capacity(), page);
        assert_eq!(buf.len(), 0);

        let buf = pool.try_alloc(page).expect("exact max size should succeed");
        assert_eq!(buf.capacity(), page);

        // Freeze after full advance -> empty.
        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0x42; 100]);
        Buf::advance(&mut buf, 100);
        assert!(buf.freeze().is_empty());

        // Freeze after partial advance -> suffix view.
        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0xAA; 50]);
        Buf::advance(&mut buf, 20);
        let frozen = buf.freeze();
        assert_eq!(frozen.len(), 30);
        assert_eq!(frozen.as_ref(), &[0xAA; 30]);

        // Clear then freeze -> empty.
        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0xAA; 50]);
        buf.clear();
        let frozen = buf.freeze();
        assert!(frozen.is_empty());
    }

    #[test]
    fn test_interleaved_advance_and_write() {
        // Writing after advancing should append beyond the initialized tail,
        // with the read cursor keeping both old and new data visible.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 10));

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(b"hello");
        Buf::advance(&mut buf, 2);
        buf.put_slice(b"world");
        assert_eq!(buf.as_ref(), b"lloworld");
    }

    #[test]
    fn test_alignment_after_advance() {
        // Advancing breaks base-pointer alignment, which is expected.
        let page = page_size();
        let pool = test_pool(BufferPoolConfig::for_storage());

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0; 100]);

        // Initially aligned
        assert_eq!(buf.as_mut_ptr() as usize % page, 0);

        // After advance, alignment may be broken
        Buf::advance(&mut buf, 7);
        // Pointer is now at offset 7, not page-aligned
        assert_ne!(buf.as_mut_ptr() as usize % page, 0);
    }
}
