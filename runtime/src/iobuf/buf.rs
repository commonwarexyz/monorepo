//! Contiguous immutable and mutable I/O buffer handles.
//!
//! [`IoBuf`] and [`IoBufMut`] keep readable cursor state in the handle, and
//! [`IoBufMut`] also tracks writable capacity there. Allocation ownership and
//! reclamation are delegated to [`super::owner`].
//! This module implements slicing, freezing, mutable recovery, conversions,
//! and codec integration for a single buffer.

use super::{
    owner::{HeapOwner, OwnerRef, PooledBuffer},
    panic_advance,
    pool::BufferPool,
};
use bytes::{Buf, BufMut, Bytes, BytesMut, TryGetError};
use commonware_codec::{BufsMut, EncodeSize, Error, RangeCfg, Read, Write, util::at_least};
use std::{
    mem::ManuallyDrop,
    num::NonZeroUsize,
    ops::{Bound, RangeBounds},
    ptr::NonNull,
};

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
/// an internal owner header. `bytes::Buf` methods use only `ptr` and `len`.
/// Clone/drop/slice/split use `owner` on colder lifecycle paths.
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

// Debug intentionally omits the data pointer: raw addresses differ across
// identically-seeded deterministic runs and would leak heap layout into logs.
impl std::fmt::Debug for IoBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoBuf")
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
    #[inline]
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
    /// The copy lands in one native heap allocation with an inline owner
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
    pub fn is_pooled(&self) -> bool {
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
    ///
    /// # Panics
    ///
    /// Panics if the range is out of bounds of the readable bytes, if its
    /// start is greater than its end, or if an inclusive bound overflows.
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
    /// Succeeds when this view is the unique owner of a native (heap,
    /// pooled, or adopted-vec) allocation, including uniquely-owned slices:
    /// capacity is recovered from the allocation base and the current view
    /// offset, so spare capacity beyond the view returns with it. Views with
    /// no owner (the default and detached empty views) convert trivially.
    ///
    /// Declines for shared owners, non-empty static views, and
    /// external-backed views (`Bytes` cannot back a mutable handle). An empty
    /// view that still holds a shared or external owner declines like any
    /// other view.
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

    /// Convert this buffer into [`IoBufMut`], allocating from `pool` if needed.
    ///
    /// This is zero-copy when `self` has exclusive ownership of the backing
    /// storage. If the buffer is shared, this allocates a new buffer from
    /// `pool` and copies the readable bytes into it.
    pub fn into_mut_with_pool(self, pool: &BufferPool) -> IoBufMut {
        match self.try_into_mut() {
            Ok(buf) => buf,
            Err(buf) => {
                let mut result = pool.alloc(buf.len());
                result.put_slice(buf.as_ref());
                result
            }
        }
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
/// Adopts the vec's allocation when its spare capacity can host the owner
/// header, and otherwise moves it into [`Bytes`] behind an external owner.
impl From<Vec<u8>> for IoBuf {
    fn from(vec: Vec<u8>) -> Self {
        let (ptr, len, owner) = OwnerRef::from_vec(vec);
        Self { ptr, len, owner }
    }
}

/// Convert [`Bytes`] into an [`IoBuf`] without copying.
///
/// The `Bytes` value moves into a small external owner and the handle points
/// directly into its payload. Handle clones and drops never touch the inner
/// refcount. Only the final release and the `slice_ref` conversion fast paths
/// do.
impl From<Bytes> for IoBuf {
    fn from(bytes: Bytes) -> Self {
        let (ptr, len, owner) = OwnerRef::from_bytes(bytes);
        Self { ptr, len, owner }
    }
}

/// Convert [`BytesMut`] into an [`IoBuf`] without copying (via `freeze`).
impl From<BytesMut> for IoBuf {
    fn from(bytes: BytesMut) -> Self {
        Self::from(bytes.freeze())
    }
}

/// Zero-copy: creates a static view with no owner.
impl<const N: usize> From<&'static [u8; N]> for IoBuf {
    fn from(array: &'static [u8; N]) -> Self {
        Self::from_static(array)
    }
}

/// Zero-copy: creates a static view with no owner.
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
/// views via [`Bytes::slice_ref`] on the inner `Bytes` (a refcount clone,
/// though the first conversion of a still-promotable inner `Bytes` pays
/// bytes' one shared-header allocation), and native heap/pooled views via
/// [`Bytes::from_owner`] (one box).
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
///
/// # Capacity
///
/// The capacity is fixed at construction: unlike [`BytesMut`], the buffer
/// never grows, and every write past `capacity()` panics (including through
/// [`BufMut`] methods such as `put_slice`). [`Self::default`] and zero-sized
/// constructions own no storage, so any write to them panics. Allocate the
/// full expected size up front. `remaining_mut()` reports the actual writable
/// tail rather than `usize::MAX`.
pub struct IoBufMut {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
    owner: OwnerRef,
}

// SAFETY: mutable handles have unique ownership. Moving them across threads is
// safe because final release uses thread-safe pool/allocator paths.
unsafe impl Send for IoBufMut {}
// SAFETY: shared references expose only immutable reads. Mutation requires
// `&mut self`.
unsafe impl Sync for IoBufMut {}

// Debug intentionally omits the data pointer: raw addresses differ across
// identically-seeded deterministic runs and would leak heap layout into logs.
impl std::fmt::Debug for IoBufMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoBufMut")
            .field("len", &self.len)
            .field("cap", &self.cap)
            .field("pooled", &self.is_pooled())
            .finish()
    }
}

impl Drop for IoBufMut {
    #[inline]
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
    ///
    /// The capacity is exact and fixed. Writes past it panic (see the
    /// [capacity](Self#capacity) section).
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_alignment(capacity, NonZeroUsize::MIN)
    }

    /// Create an untracked aligned buffer with the given capacity and alignment.
    ///
    /// The returned buffer is not tracked by a [`BufferPool`], so dropping it
    /// deallocates the aligned allocation immediately.
    ///
    /// For alignments above the owner header alignment (8 bytes on 64-bit
    /// targets) the usable region rounds the request up to the header
    /// alignment, so `capacity()` may exceed the request by up to that
    /// alignment minus one.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is nonzero and `alignment` is not a power of two.
    #[inline]
    pub fn with_alignment(capacity: usize, alignment: NonZeroUsize) -> Self {
        if capacity == 0 {
            return Self::default();
        }
        let (ptr, cap, owner) = HeapOwner::allocate_aligned_mut(capacity, alignment.get(), false);
        Self {
            ptr,
            len: 0,
            cap,
            owner,
        }
    }

    /// Create a zero-initialized untracked aligned buffer with the given
    /// length and alignment.
    ///
    /// For alignments above the owner header alignment (8 bytes on 64-bit
    /// targets) the usable region rounds the request up to the header
    /// alignment, so `capacity()` may exceed `len` by up to that alignment
    /// minus one (zero-initialized) bytes.
    ///
    /// # Panics
    ///
    /// Panics if `len` is nonzero and `alignment` is not a power of two.
    #[inline]
    pub fn zeroed_with_alignment(len: usize, alignment: NonZeroUsize) -> Self {
        if len == 0 {
            return Self::default();
        }
        let (ptr, cap, owner) = HeapOwner::allocate_aligned_mut(len, alignment.get(), true);
        Self {
            ptr,
            len,
            cap,
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
    /// `buffer` must have an initialized live lease in its pooled slot.
    #[inline]
    pub(crate) unsafe fn from_pooled_parts(buffer: PooledBuffer) -> Self {
        let cap = buffer.capacity();
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
    pub fn is_pooled(&self) -> bool {
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
    /// Free: the owner word moves to the immutable handle without a refcount
    /// operation (a reserved front heap header is initialized, including its
    /// refcount sentinel, before the owner is shared). Freezing an empty
    /// buffer releases the allocation immediately so empty immutable views
    /// never pin pool memory.
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
        // Early check for a clear panic message, not a safety boundary.
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

/// Create a mutable buffer by copying the slice.
impl From<&[u8]> for IoBufMut {
    fn from(slice: &[u8]) -> Self {
        let mut buf = Self::with_capacity(slice.len());
        buf.put_slice(slice);
        buf
    }
}

/// Create a mutable buffer by copying the array.
impl<const N: usize> From<[u8; N]> for IoBufMut {
    fn from(array: [u8; N]) -> Self {
        Self::from(array.as_ref())
    }
}

/// Create a mutable buffer by copying the array.
impl<const N: usize> From<&[u8; N]> for IoBufMut {
    fn from(array: &[u8; N]) -> Self {
        Self::from(array.as_ref())
    }
}

/// Create a mutable buffer by copying `vec`.
///
/// Zero-copy adoption is not used because it would reserve owner header space
/// inside the vec's allocation, shrinking the writable capacity below
/// `vec.capacity()`. Use `From<Vec<u8>> for IoBuf` for zero-copy immutable
/// conversion (and [`IoBuf::try_into_mut`] to recover mutability).
impl From<Vec<u8>> for IoBufMut {
    fn from(vec: Vec<u8>) -> Self {
        let mut buf = Self::with_capacity(vec.capacity());
        buf.put_slice(&vec);
        buf
    }
}

/// Create a mutable buffer by copying `bytes`.
///
/// A mutable buffer requires runtime-owned storage for its owner header, which
/// a `BytesMut` allocation cannot host, so this conversion copies. The
/// caller's reserved capacity is preserved.
impl From<BytesMut> for IoBufMut {
    fn from(bytes: BytesMut) -> Self {
        let mut out = Self::with_capacity(bytes.capacity());
        out.put_slice(bytes.as_ref());
        out
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

/// Zero-copy when exclusive ownership can be recovered (see
/// [`IoBuf::try_into_mut`]), copies otherwise.
impl From<IoBuf> for IoBufMut {
    fn from(buf: IoBuf) -> Self {
        match buf.try_into_mut() {
            Ok(buf) => buf,
            Err(buf) => Self::from(buf.as_ref()),
        }
    }
}

/// Panics for a failed `copy_to_slice`, preserving the [`TryGetError`]
/// message.
#[cold]
#[inline(never)]
fn panic_try_get(error: TryGetError) -> ! {
    panic!("{error}");
}

/// Resolves `range` against a buffer of length `len` into `(start, end)`.
///
/// Panics if a bound overflows `usize`, the range is inverted, or the end
/// exceeds `len`. Callers forward these as their documented slice panics.
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

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::{
        super::{bufs::IoBufs, pool::BufferPoolConfig},
        *,
    };
    use bytes::{Bytes, BytesMut};
    use commonware_codec::{Decode, Encode, RangeCfg};
    use core::ops::Bound;
    use std::mem::size_of;

    fn test_pool() -> BufferPool {
        cfg_if::cfg_if! {
            if #[cfg(miri)] {
                // Reduce the class limits to avoid slow atomics under miri.
                let pool_config = BufferPoolConfig::for_network()
                    .with_pool_min_size(0)
                    .with_max_per_class(commonware_utils::NZU32!(32));
            } else {
                let pool_config = BufferPoolConfig::for_network().with_pool_min_size(0);
            }
        }
        let mut registry = crate::telemetry::metrics::Registry::default();
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
    fn test_iobuf_from_conversions_are_zero_copy() {
        // The module doc guarantees every From conversion into IoBuf is
        // zero-copy. Pin payload pointer identity for each route.

        // A vec with header room adopts its own allocation.
        let mut vec = Vec::with_capacity(128);
        vec.extend_from_slice(b"adopt");
        let ptr = vec.as_ptr();
        let buf = IoBuf::from(vec);
        assert_eq!(buf.as_ref().as_ptr(), ptr);

        // An exactly-sized vec moves into Bytes without copying.
        let vec = b"exact".to_vec();
        let ptr = vec.as_ptr();
        let buf = IoBuf::from(vec);
        assert_eq!(buf.as_ref().as_ptr(), ptr);

        // Bytes moves behind the external owner.
        let bytes = Bytes::from(b"bytes".to_vec());
        let ptr = bytes.as_ptr();
        let buf = IoBuf::from(bytes);
        assert_eq!(buf.as_ref().as_ptr(), ptr);

        // BytesMut freezes in place.
        let mut bytes = BytesMut::with_capacity(16);
        bytes.put_slice(b"frozen");
        let ptr = bytes.as_ref().as_ptr();
        let buf = IoBuf::from(bytes);
        assert_eq!(buf.as_ref().as_ptr(), ptr);

        // Static views point at the static data itself.
        static DATA: [u8; 4] = *b"data";
        let buf = IoBuf::from(&DATA[..]);
        assert_eq!(buf.as_ref().as_ptr(), DATA.as_ptr());
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
    fn test_iobuf_copy_to_slice_paths() {
        let mut buf = IoBuf::from(b"hello world");
        let mut dst = [0u8; 5];
        buf.copy_to_slice(&mut dst);
        assert_eq!(&dst, b"hello");
        assert_eq!(buf.as_ref(), b" world");

        let mut dst = [0u8; 3];
        buf.try_copy_to_slice(&mut dst).unwrap();
        assert_eq!(&dst, b" wo");

        // Requesting more than remaining fails without consuming anything.
        let mut dst = [0u8; 4];
        let err = buf.try_copy_to_slice(&mut dst).unwrap_err();
        assert_eq!(err.requested, 4);
        assert_eq!(err.available, 3);
        assert_eq!(buf.as_ref(), b"rld");
    }

    #[test]
    #[should_panic(expected = "Not enough bytes remaining in buffer")]
    fn test_iobuf_copy_to_slice_past_end() {
        let mut buf = IoBuf::from(b"ab");
        let mut dst = [0u8; 3];
        buf.copy_to_slice(&mut dst);
    }

    #[test]
    #[should_panic(expected = "copy_to_bytes out of bounds")]
    fn test_iobuf_copy_to_bytes_past_end() {
        let mut buf = IoBuf::from(b"ab");
        let _ = buf.copy_to_bytes(3);
    }

    #[test]
    fn test_iobuf_slice_excluded_start_bound() {
        // Excluded start bounds resolve to start + 1.
        let buf = IoBuf::from(b"hello");
        let sliced = buf.slice((Bound::Excluded(0), Bound::Unbounded));
        assert_eq!(sliced, b"ello");
    }

    #[test]
    #[should_panic(expected = "slice out of bounds")]
    fn test_iobuf_slice_out_of_bounds() {
        let buf = IoBuf::from(b"hello");
        let _ = buf.slice(..6);
    }

    #[test]
    #[should_panic(expected = "slice start must be <= end")]
    fn test_iobuf_slice_inverted_range() {
        let buf = IoBuf::from(b"hello");
        #[allow(clippy::reversed_empty_ranges)]
        let _ = buf.slice(3..1);
    }

    #[test]
    #[should_panic(expected = "range end overflow")]
    fn test_iobuf_slice_inclusive_end_overflow() {
        let buf = IoBuf::from(b"hello");
        let _ = buf.slice(0..=usize::MAX);
    }

    #[test]
    #[should_panic(expected = "range start overflow")]
    fn test_iobuf_slice_excluded_start_overflow() {
        let buf = IoBuf::from(b"hello");
        let _ = buf.slice((Bound::Excluded(usize::MAX), Bound::Unbounded));
    }

    #[test]
    fn test_iobuf_try_into_mut_empty_and_static() {
        // Empty views convert trivially.
        let buf = IoBuf::default().try_into_mut().expect("empty converts");
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), 0);

        // Non-empty static views decline: there is no allocation to recover.
        let err = IoBuf::from(b"static").try_into_mut().unwrap_err();
        assert_eq!(err, b"static");

        // Empty buffers convert to empty Bytes without touching an owner.
        let empty = Bytes::from(IoBuf::default());
        assert!(empty.is_empty());

        // Empty static slices detach to the default representation.
        let empty = IoBuf::from(&b""[..]);
        assert!(empty.is_empty());
        assert!(empty.try_into_mut().is_ok());
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

        // `zeroed` creates readable initialized bytes, so `set_len` can shrink safely.
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
    fn test_iobufmut_copy_to_slice_tracks_len_and_cap() {
        // copy_to_slice must shrink len and cap in lockstep with the pointer
        // advance: the front-heap release path derives the allocation size
        // from ptr + cap, so a cap mismatch would corrupt the dealloc layout.
        let mut buf = IoBufMut::with_capacity(16);
        buf.put_slice(b"abcdefgh");

        let mut dst = [0u8; 3];
        buf.copy_to_slice(&mut dst);
        assert_eq!(&dst, b"abc");
        assert_eq!(buf.as_ref(), b"defgh");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.capacity(), 13);

        // try_copy_to_slice success mirrors copy_to_slice.
        let mut dst = [0u8; 2];
        buf.try_copy_to_slice(&mut dst).unwrap();
        assert_eq!(&dst, b"de");
        assert_eq!(buf.capacity(), 11);

        // Requesting more than remaining fails without consuming anything.
        let mut dst = [0u8; 4];
        let err = buf.try_copy_to_slice(&mut dst).unwrap_err();
        assert_eq!(err.requested, 4);
        assert_eq!(err.available, 3);
        assert_eq!(buf.as_ref(), b"fgh");
        assert_eq!(buf.capacity(), 11);

        // Freeze and recover: the owner must observe a consistent allocation
        // for the advanced handle (view offset 5 leaves 16 - 5 = 11 bytes of
        // capacity), and the final drop (checked under miri) must deallocate
        // with the original layout.
        let frozen = buf.freeze();
        assert_eq!(frozen.as_ref(), b"fgh");
        let recovered = frozen.try_into_mut().expect("unique buffer recovers");
        assert_eq!(recovered.as_ref(), b"fgh");
        assert_eq!(recovered.capacity(), 11);
    }

    #[test]
    fn test_iobufmut_write_after_partial_advance_appends_at_tail() {
        // A partial advance moves the view start while retaining readable
        // bytes. A subsequent write must land at the initialized tail so old
        // and new data stay adjacent, with len and cap tracked in lockstep.
        let mut buf = IoBufMut::with_capacity(16);
        buf.put_slice(b"hello");
        buf.advance(2);
        buf.put_slice(b"world");
        assert_eq!(buf.as_ref(), b"lloworld");
        assert_eq!(buf.len(), 8);
        assert_eq!(buf.capacity(), 14);

        // The same holds for pooled buffers, whose cursor bookkeeping feeds
        // the thread-cache return path instead of a dealloc layout.
        let pool = test_pool();
        let mut buf = pool.alloc(16);
        let capacity = buf.capacity();
        buf.put_slice(b"hello");
        buf.advance(2);
        buf.put_slice(b"world");
        assert_eq!(buf.as_ref(), b"lloworld");
        assert_eq!(buf.len(), 8);
        assert_eq!(buf.capacity(), capacity - 2);
    }

    #[test]
    #[should_panic(expected = "Not enough bytes remaining in buffer")]
    fn test_iobufmut_copy_to_slice_past_end() {
        let mut buf = IoBufMut::from(b"ab");
        let mut dst = [0u8; 3];
        buf.copy_to_slice(&mut dst);
    }

    #[test]
    #[should_panic(expected = "copy_to_bytes out of bounds")]
    fn test_iobufmut_copy_to_bytes_past_end() {
        let mut buf = IoBufMut::from(b"ab");
        let _ = buf.copy_to_bytes(3);
    }

    #[test]
    fn test_iobufmut_put_bytes_success() {
        let mut buf = IoBufMut::with_capacity(8);
        buf.put_bytes(7, 5);
        assert_eq!(buf.as_ref(), &[7u8; 5]);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.remaining_mut(), 3);
    }

    #[test]
    fn test_iobufmut_put_multi_chunk_source() {
        let mut buf = IoBufMut::with_capacity(8);
        buf.put((&b"hel"[..]).chain(&b"lo"[..]));
        assert_eq!(buf.as_ref(), b"hello");
        assert_eq!(buf.remaining_mut(), 3);
    }

    #[test]
    #[should_panic(expected = "cannot advance past end of buffer")]
    fn test_iobufmut_put_slice_past_capacity() {
        let mut buf = IoBufMut::with_capacity(4);
        buf.put_slice(b"hello");
    }

    #[test]
    #[should_panic(expected = "cannot advance past end of buffer")]
    fn test_iobufmut_put_bytes_past_capacity() {
        let mut buf = IoBufMut::with_capacity(4);
        buf.put_bytes(0, 5);
    }

    #[test]
    #[should_panic(expected = "cannot advance past end of buffer")]
    fn test_iobufmut_advance_mut_past_capacity() {
        let mut buf = IoBufMut::with_capacity(4);
        // SAFETY: the call panics on the bounds check before any byte in the
        // advanced region could be observed.
        unsafe { buf.advance_mut(5) };
    }

    #[test]
    #[should_panic(expected = "cannot advance past end of buffer")]
    fn test_iobufmut_put_past_capacity() {
        let mut buf = IoBufMut::with_capacity(4);
        buf.put(&b"hello"[..]);
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
    fn test_iobuf_into_mut_with_pool() {
        let pool = test_pool();

        // Unique buffers recover mutability without copying.
        let mut unique = pool.alloc(4);
        unique.put_slice(b"data");
        let unique_ptr = unique.as_mut_ptr();
        let mut recovered = unique.freeze().into_mut_with_pool(&pool);
        assert_eq!(recovered.as_ref(), b"data");
        assert_eq!(recovered.as_mut_ptr(), unique_ptr);

        // Shared buffers allocate from the pool and copy readable bytes.
        let mut shared = pool.alloc(4);
        shared.put_slice(b"copy");
        let shared = shared.freeze();
        let shared_ptr = shared.as_ptr();
        let _clone = shared.clone();
        let mut copied = shared.into_mut_with_pool(&pool);
        assert_eq!(copied.as_ref(), b"copy");
        assert_ne!(copied.as_mut_ptr() as *const u8, shared_ptr);
        assert!(copied.is_pooled());

        // Recovery after transient slices are dropped is zero-copy and preserves
        // the full readable length and capacity.
        let mut mirror = pool.alloc(8);
        mirror.put_slice(b"abcdefgh");
        let mirror_cap = mirror.capacity();
        let mirror_ptr = mirror.as_mut_ptr();
        let frozen = mirror.freeze();
        let head = frozen.slice(0..3);
        let tail = frozen.slice(5..8);
        drop(head);
        drop(tail);
        let mut recovered = frozen.into_mut_with_pool(&pool);
        assert_eq!(recovered.as_ref(), b"abcdefgh");
        assert_eq!(recovered.as_mut_ptr(), mirror_ptr);
        assert_eq!(recovered.capacity(), mirror_cap);
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
        assert!(buf == *b"xyz");
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
    fn test_iobufmut_from_bytesmut_preserves_capacity() {
        let mut bytes = BytesMut::with_capacity(100);
        bytes.put_slice(b"abc");
        let cap = bytes.capacity();
        let buf = IoBufMut::from(bytes);
        assert_eq!(buf.as_ref(), b"abc");
        assert_eq!(buf.capacity(), cap);

        // An empty reserved BytesMut keeps its reservation writable.
        let bytes = BytesMut::with_capacity(64);
        let cap = bytes.capacity();
        let mut buf = IoBufMut::from(bytes);
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), cap);
        buf.put_bytes(7, cap);
        assert_eq!(buf.len(), cap);
    }

    #[test]
    fn test_iobufmut_from_vec_preserves_capacity() {
        let mut vec = Vec::with_capacity(100);
        vec.extend_from_slice(b"abc");
        let buf = IoBufMut::from(vec);
        assert_eq!(buf.as_ref(), b"abc");
        assert_eq!(buf.capacity(), 100);

        // An empty reservation converts to a writable buffer of the same
        // capacity.
        let mut buf = IoBufMut::from(Vec::with_capacity(64));
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), 64);
        buf.put_bytes(7, 64);
        assert_eq!(buf.len(), 64);
    }

    #[test]
    #[should_panic(expected = "front heap layout size overflow")]
    fn test_iobufmut_with_capacity_rejects_oversized_request() {
        // Constructs the layout (and must panic) before any allocation.
        let _ = IoBufMut::with_capacity(isize::MAX as usize);
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

        // Zero-sized buffers do not allocate, so alignment is not validated.
        let invalid_alignment = NonZeroUsize::new(3).expect("non-zero alignment");
        assert_eq!(IoBufMut::with_alignment(0, invalid_alignment).capacity(), 0);
        assert_eq!(
            IoBufMut::zeroed_with_alignment(0, invalid_alignment).capacity(),
            0
        );
    }

    #[test]
    fn test_iobufmut_aligned_capacity_stable_across_recovery() {
        // High-alignment requests round the usable region up to the header
        // alignment. The handle must report that capacity from construction
        // so a freeze/try_into_mut round trip cannot grow it.
        let alignment = NonZeroUsize::new(4096).expect("non-zero alignment");
        let mut buf = IoBufMut::with_alignment(100, alignment);
        assert_eq!(buf.capacity(), 104);

        buf.put_slice(b"data");
        let recovered = buf
            .freeze()
            .try_into_mut()
            .expect("unique native view recovers");
        assert_eq!(recovered.capacity(), 104);

        // Zeroed variant: the rounded tail is writable and zero-initialized,
        // while len stays at the request.
        let zeroed = IoBufMut::zeroed_with_alignment(100, alignment);
        assert_eq!(zeroed.len(), 100);
        assert_eq!(zeroed.capacity(), 104);

        // Multiple-of-8 requests stay exact.
        let exact = IoBufMut::with_alignment(128, alignment);
        assert_eq!(exact.capacity(), 128);
    }

    #[test]
    #[should_panic(expected = "set_len(9) exceeds capacity(8)")]
    fn test_iobufmut_set_len_overflow() {
        let mut buf = IoBufMut::with_capacity(8);
        // SAFETY: this will panic before any read.
        unsafe { buf.set_len(9) };
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
