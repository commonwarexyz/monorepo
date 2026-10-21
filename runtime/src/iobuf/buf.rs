//! Contiguous immutable and mutable I/O buffer handles.
//!
//! [`IoBuf`] and [`IoBufMut`] keep readable cursor state in the handle, and
//! [`IoBufMut`] also tracks writable capacity there. Allocation ownership and
//! reclamation are delegated to [`super::owner`]. This module implements
//! slicing, freezing, mutable recovery, conversions, and codec integration for
//! a single buffer.

use super::{
    owner::{Descriptor, Owner, OwnerCell, Storage},
    panic_advance,
};
use bytes::{BufMut, Bytes, BytesMut, TryGetError};
use commonware_codec::{
    Buf, BufsMut, EncodeSize, Error, Input, OwnedBytes, RangeCfg, Read, Write, util::at_least,
};
use std::{
    alloc::Layout,
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
/// Allocation ownership lives in `owner`. It describes a native allocation
/// this handle owns alone, points to an internal owner record (for shared
/// allocations, allocations the word cannot describe, and [`Bytes`]), or is
/// empty for static slices and detached empty views. Cursor methods such as
/// `remaining`, `chunk`, `advance`, and `copy_to_slice` use only `ptr` and
/// `len`. Cloning, dropping, slicing, splitting, and `copy_to_bytes` use
/// `owner` on colder lifecycle paths.
///
/// Cloning and slicing are zero-copy, and so is every `From` conversion into
/// `IoBuf`. The first clone, slice, or partial split of an unshared native
/// buffer allocates its owner record. Use [`IoBuf::copy_from_slice`] to copy
/// borrowed data.
pub struct IoBuf {
    ptr: NonNull<u8>,
    len: usize,
    owner: OwnerCell,
}

// Keep the handle at three words outside loom builds, whose atomics are larger.
#[cfg(not(feature = "loom"))]
const _: () = assert!(size_of::<IoBuf>() == 3 * size_of::<usize>());

// SAFETY: immutable handles expose read-only bytes and synchronize shared
// ownership through the owner refcount.
unsafe impl Send for IoBuf {}
// SAFETY: shared access is read-only and lifecycle state is atomic.
unsafe impl Sync for IoBuf {}

// Debug omits the data pointer because raw addresses differ across
// identically-seeded deterministic runs and would leak heap layout into logs.
impl std::fmt::Debug for IoBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoBuf").field("len", &self.len).finish()
    }
}

impl Clone for IoBuf {
    #[inline]
    fn clone(&self) -> Self {
        let owner = self.retain();
        Self {
            ptr: self.ptr,
            len: self.len,
            owner: OwnerCell::new(owner),
        }
    }
}

impl Drop for IoBuf {
    #[inline]
    fn drop(&mut self) {
        let owner = self.owner.get();
        // SAFETY: the handle gives up its ownership.
        if unsafe { owner.drop_view() } {
            // SAFETY: the handle owns its allocation alone, and `ptr` and `len`
            // are its view.
            unsafe { owner.release_unique(self.ptr, self.len) };
        }
    }
}

impl IoBuf {
    /// Takes a reference to this handle's allocation for a new view through a
    /// shared borrow.
    ///
    /// Inlined into clone and slice: a record or an empty word is retained in
    /// place, and a descriptor goes to the outlined [`Self::promote`].
    #[inline(always)]
    fn retain(&self) -> Owner {
        let owner = self.owner.load();
        if let Some(descriptor) = owner.descriptor() {
            // SAFETY: `descriptor` was just loaded from this handle's cell.
            return unsafe { self.promote(descriptor) };
        }
        // SAFETY: this handle holds a reference to the record, if any, for the
        // whole call. Static views have no owner.
        unsafe { owner.clone_shared() };
        owner
    }

    /// Promotes this handle's descriptor to a record and returns a reference
    /// for a new view.
    ///
    /// Only the first share of a buffer takes this path. Keeping it out of
    /// line leaves clone and slice with a tag test and a refcount increment
    /// inline.
    ///
    /// It takes and returns single words, so clone and slice build the new
    /// handle in registers and store it straight into its destination. If
    /// this returned the whole handle instead, the handle would pass through
    /// a stack slot shared by both paths, and a caller that moves it on, such
    /// as the derived clone of an array of handles, can reload that slot with
    /// wider loads than the stores that filled it, which stalls store
    /// forwarding.
    ///
    /// # Safety
    ///
    /// `descriptor` must have been loaded from this handle's cell.
    #[cold]
    #[inline(never)]
    unsafe fn promote(&self, descriptor: Descriptor) -> Owner {
        // SAFETY: guaranteed by the caller, and the promotion uses this
        // handle's whole view, which stays borrowed for the call.
        unsafe { self.owner.promote(descriptor, self.ptr, self.len) }
    }

    /// Create a buffer by copying data from a slice.
    ///
    /// Use this when you have a non-static `&[u8]` that needs owned storage.
    /// For static slices, prefer [`IoBuf::from`] which is zero-copy.
    ///
    /// The copy lands in a native heap allocation, so the result supports
    /// zero-copy [`IoBuf::try_into_mut`].
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
            owner: OwnerCell::empty(),
        }
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
    /// An empty range returns a detached empty buffer that holds no
    /// allocation.
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

        let owner = self.retain();
        Self {
            // SAFETY: range resolution bounds `start <= self.len`.
            ptr: unsafe { self.ptr.add(start) },
            len: end - start,
            owner: OwnerCell::new(owner),
        }
    }

    /// Splits the buffer into two at the given index.
    ///
    /// Afterwards `self` contains bytes `[at, len)`, and the returned [`IoBuf`]
    /// contains bytes `[0, at)`.
    ///
    /// This is an `O(1)` zero-copy operation. A split that leaves both halves
    /// nonempty shares the allocation, which allocates the owner record of an
    /// unshared native buffer. The empty half of a split at either end of a
    /// nonempty buffer is detached and holds no allocation. Splitting an empty
    /// buffer leaves `self` unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `at > len`.
    // Always inlined. An outlined copy has to save the registers that stay
    // live across its cold promotion call, which costs more than the split.
    #[inline(always)]
    pub fn split_to(&mut self, at: usize) -> Self {
        if at > self.len {
            panic_split_to(at, self.len);
        }
        if at == 0 {
            return Self::default();
        }
        if at == self.len {
            return std::mem::take(self);
        }

        let (ptr, len) = (self.ptr, self.len);
        // SAFETY: `ptr` and `len` are this handle's view, and the prefix
        // takes the returned reference.
        let owner = unsafe { self.owner.retain_mut(ptr, len) };
        // SAFETY: `at < len`, so advancing within the current readable region is in bounds.
        self.ptr = unsafe { ptr.add(at) };
        self.len = len - at;
        Self {
            ptr,
            len: at,
            owner: OwnerCell::new(owner),
        }
    }

    /// Try to convert this buffer into [`IoBufMut`] without copying.
    ///
    /// Succeeds when this view, whole or sliced, is the only handle to a
    /// native allocation (one that an [`IoBufMut`] allocated or adopted from a
    /// [`Vec<u8>`]). The recovered capacity runs from the view's start to the
    /// end of the allocation, so spare capacity beyond the view returns with
    /// it. An empty view with no owner converts to an empty [`IoBufMut`].
    ///
    /// Returns `self` when other handles share the allocation or when the
    /// view is a non-empty static slice. Views of [`Bytes`] always decline
    /// because `Bytes` cannot back a mutable handle.
    #[inline]
    pub fn try_into_mut(mut self) -> Result<IoBufMut, Self> {
        let owner = self.owner.get();
        if let Some(descriptor) = owner.descriptor() {
            // A descriptor handle owns its allocation alone, so it needs no
            // refcount check. Its tail returns as spare capacity, and the sum
            // cannot wrap because it is bounded by the allocation size.
            let cap = self.len.wrapping_add(descriptor.tail());
            let me = ManuallyDrop::new(self);
            return Ok(IoBufMut {
                ptr: me.ptr,
                len: me.len,
                cap,
                owner: descriptor.without_tail().into(),
            });
        }
        if owner.is_empty() {
            return if self.len == 0 {
                Ok(IoBufMut::default())
            } else {
                Err(self)
            };
        }

        // `IoBufMut` is never backed by `Bytes`, so external owners decline.
        // SAFETY: owner is non-empty and live.
        let Some(&Storage::Native { base, layout }) = (unsafe { owner.storage() }) else {
            return Err(self);
        };

        // SAFETY: owner is non-empty and live.
        if !unsafe { owner.is_unique() } {
            return Err(self);
        }

        let me = ManuallyDrop::new(self);
        let offset = (me.ptr.as_ptr() as usize)
            .checked_sub(base.as_ptr() as usize)
            .expect("view pointer must be within owner allocation");
        assert!(
            offset <= layout.size(),
            "view pointer must be within owner bounds"
        );
        let cap = layout.size() - offset;
        assert!(me.len <= cap, "view length must be within owner bounds");

        Ok(IoBufMut {
            ptr: me.ptr,
            len: me.len,
            cap,
            owner,
        })
    }

    /// The owner cell, for the owner loom models.
    #[cfg(all(test, feature = "loom"))]
    pub(crate) const fn owner_cell(&self) -> &OwnerCell {
        &self.owner
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
            owner: OwnerCell::empty(),
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
    /// Returns the prefix as a view of this buffer when `T` is [`IoBuf`], and as its bytes
    /// otherwise.
    #[inline]
    fn take_owned<T: OwnedBytes>(&mut self, len: usize) -> T {
        T::claim(self.split_to(len)).unwrap_or_else(|view| T::from_bytes(view.into()))
    }
}

impl OwnedBytes for IoBuf {
    #[inline]
    fn from_bytes(bytes: Bytes) -> Self {
        Self::from(bytes)
    }
}

impl bytes::Buf for IoBuf {
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
    /// This is zero-copy despite the trait method's name. The drained prefix
    /// becomes a shared view, converted through the `From<IoBuf> for Bytes`
    /// fast paths. A partial drain of an unshared native buffer allocates its
    /// owner record.
    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        assert!(len <= self.len, "copy_to_bytes out of bounds");
        if len == 0 {
            return Bytes::new();
        }
        if len == self.len {
            return Bytes::from(std::mem::take(self));
        }

        // Slicing an external-backed view's inner `Bytes` directly skips the
        // owner retain and release that the shared-view path below pays.
        let owner = self.owner.get();
        if owner.descriptor().is_none()
            // SAFETY: the owner is live while `self` holds its reference.
            && let Some(Storage::External(inner)) = unsafe { owner.storage() }
        {
            // The view prefix lies within the inner `Bytes` range by the
            // `Storage::External` invariant, as `slice_ref` requires.
            let bytes = inner.slice_ref(&self.as_ref()[..len]);
            self.advance(len);
            return bytes;
        }

        Bytes::from(self.split_to(len))
    }
}

/// Convert a [`Vec<u8>`] into an [`IoBuf`] without copying.
///
/// Adopts the vec's allocation as native storage, so the result supports
/// zero-copy [`IoBuf::try_into_mut`]. An empty vec becomes an empty buffer.
impl From<Vec<u8>> for IoBuf {
    #[inline]
    fn from(vec: Vec<u8>) -> Self {
        IoBufMut::from(vec).freeze()
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
        if bytes.is_empty() {
            return Self::default();
        }
        let ptr = NonNull::new(bytes.as_ptr().cast_mut())
            .expect("non-empty Bytes must have non-null data");
        Self {
            ptr,
            len: bytes.len(),
            owner: OwnerCell::new(Owner::new(Storage::External(bytes))),
        }
    }
}

/// Convert [`BytesMut`] into an [`IoBuf`] without copying (via `freeze`).
impl From<BytesMut> for IoBuf {
    fn from(bytes: BytesMut) -> Self {
        Self::from(bytes.freeze())
    }
}

/// Convert [`IoBufMut`] into an [`IoBuf`] without copying (via [`IoBufMut::freeze`]).
impl From<IoBufMut> for IoBuf {
    #[inline]
    fn from(buf: IoBufMut) -> Self {
        buf.freeze()
    }
}

/// Create a zero-copy static view with no owner.
impl<const N: usize> From<&'static [u8; N]> for IoBuf {
    #[inline]
    fn from(array: &'static [u8; N]) -> Self {
        Self::from_static(array)
    }
}

/// Create a zero-copy static view with no owner.
impl From<&'static [u8]> for IoBuf {
    #[inline]
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
/// - Static views use [`Bytes::from_static`] and allocate nothing.
/// - Views of a [`Bytes`] use [`Bytes::slice_ref`] on it. That costs at most
///   a refcount increment, except that the first conversion of an inner
///   `Bytes` that still exclusively owns its vector allocates a
///   shared-ownership record.
/// - Native views use [`Bytes::from_owner`] and allocate one box.
impl From<IoBuf> for Bytes {
    fn from(mut buf: IoBuf) -> Self {
        if buf.is_empty() {
            return Self::new();
        }
        let owner = buf.owner.get();
        if owner.descriptor().is_none() {
            if owner.is_empty() {
                // Non-empty views with no owner are 'static by invariant.
                // SAFETY: `ptr..ptr+len` is an initialized immortal slice.
                let slice: &'static [u8] =
                    unsafe { std::slice::from_raw_parts(buf.ptr.as_ptr(), buf.len) };
                return Self::from_static(slice);
            }

            // SAFETY: the owner is live while `buf` holds its reference, and
            // the view lies within the inner `Bytes` range by the
            // `Storage::External` invariant, as `slice_ref` requires.
            if let Some(Storage::External(inner)) = unsafe { owner.storage() } {
                return inner.slice_ref(buf.as_ref());
            }
        }

        // A native view moves into the box with its owner word, so an unshared
        // view stays unshared.
        let buf = ManuallyDrop::new(buf);
        // SAFETY: `owner` is the owner word of `buf`, and `ManuallyDrop` hands
        // its ownership to the returned `Bytes`.
        unsafe { owner.into_bytes(buf.ptr, buf.len) }
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
        Ok(buf.take_owned(len))
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
/// The capacity is fixed at construction, and the buffer never grows the way
/// [`BytesMut`] does. Every write past `capacity()` panics, including writes
/// through [`BufMut`] methods such as `put_slice`, so allocate the full
/// expected size up front. [`Self::default`] and zero-sized constructions own
/// no storage, so any nonempty write to them panics. `remaining_mut()`
/// reports the actual writable tail rather than `usize::MAX`.
pub struct IoBufMut {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
    owner: Owner,
}

// Keep the handle at four words.
const _: () = assert!(size_of::<IoBufMut>() == 4 * size_of::<usize>());

// SAFETY: mutable handles have unique ownership. Moving them across threads is
// safe because final release uses the thread-safe global allocator.
unsafe impl Send for IoBufMut {}
// SAFETY: shared references expose only immutable reads. Mutation requires
// `&mut self`.
unsafe impl Sync for IoBufMut {}

// Debug omits the data pointer because raw addresses differ across
// identically-seeded deterministic runs and would leak heap layout into logs.
impl std::fmt::Debug for IoBufMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoBufMut")
            .field("len", &self.len)
            .field("cap", &self.cap)
            .finish()
    }
}

impl Drop for IoBufMut {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: mutable buffers uniquely own their allocation, and `ptr` and
        // `cap` are their view.
        unsafe { self.owner.release_unique(self.ptr, self.cap) };
    }
}

impl Default for IoBufMut {
    fn default() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            cap: 0,
            owner: Owner::empty(),
        }
    }
}

impl IoBufMut {
    /// Create a buffer whose [capacity](Self#capacity) is exactly `capacity`
    /// bytes.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_alignment(capacity, NonZeroUsize::MIN)
    }

    /// Create a buffer whose allocation is exactly `capacity` bytes at
    /// `alignment`.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is nonzero and `alignment` is not a power of two,
    /// or if `capacity` rounded up to `alignment` exceeds `isize::MAX`.
    #[inline]
    pub fn with_alignment(capacity: usize, alignment: NonZeroUsize) -> Self {
        Self::try_with_alignment(capacity, alignment)
            .expect("alignment must be a power of two and the size must fit a layout")
    }

    /// Create an aligned buffer with the given capacity and alignment, or
    /// `None` if a nonzero `capacity` has no valid layout.
    ///
    /// A layout is invalid when `alignment` is not a power of two or
    /// `capacity` rounded up to `alignment` exceeds `isize::MAX`. A valid
    /// layout the allocator cannot provide is an allocation error, reported
    /// through [`std::alloc::handle_alloc_error`].
    #[inline]
    pub(crate) fn try_with_alignment(capacity: usize, alignment: NonZeroUsize) -> Option<Self> {
        if capacity == 0 {
            return Some(Self::default());
        }
        Layout::from_size_align(capacity, alignment.get()).ok()?;
        let (ptr, owner) = Owner::allocate(capacity, alignment.get(), false);
        Some(Self {
            ptr,
            len: 0,
            cap: capacity,
            owner,
        })
    }

    /// Create a zero-initialized aligned buffer with the given length and
    /// alignment.
    ///
    /// The allocation is exactly `len` bytes at `alignment`, so
    /// `capacity() == len`.
    ///
    /// # Panics
    ///
    /// Panics if `len` is nonzero and `alignment` is not a power of two, or
    /// if `len` rounded up to `alignment` exceeds `isize::MAX`.
    #[inline]
    pub fn zeroed_with_alignment(len: usize, alignment: NonZeroUsize) -> Self {
        if len == 0 {
            return Self::default();
        }
        let (ptr, owner) = Owner::allocate(len, alignment.get(), true);
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
    /// The owner moves to the immutable handle without a refcount operation.
    /// Freezing allocates only when the spare capacity `capacity() - len()`
    /// is too large to record in the handle (at least 128 KiB on 64-bit
    /// targets, 128 bytes on 32-bit targets), and then allocates the owner
    /// record that sharing would otherwise allocate. Freezing an empty buffer
    /// releases its allocation, so the result holds no memory.
    #[inline]
    pub fn freeze(self) -> IoBuf {
        if self.len == 0 {
            // Dropping `self` releases its allocation.
            drop(self);
            return IoBuf::default();
        }
        // SAFETY: these are this handle's fields. A fallback record
        // allocation runs while `self` still owns the allocation, so a
        // failure that unwinds releases it normally.
        let owner = unsafe { self.owner.frozen(self.ptr, self.len, self.cap) };
        // The frozen word now owns the allocation.
        let me = ManuallyDrop::new(self);
        IoBuf {
            ptr: me.ptr,
            len: me.len,
            owner: OwnerCell::new(owner),
        }
    }

    /// Returns how many bytes the buffer can hold, counted from its first
    /// readable byte.
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

impl Input for IoBufMut {
    type Buf = IoBuf;
}

impl bytes::Buf for IoBufMut {
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
    /// Draining a nonempty buffer's full readable length moves the whole
    /// buffer into the result without copying. The handle is then empty with
    /// zero capacity, whereas `BytesMut` would keep its spare capacity. A
    /// partial or zero-length drain copies the prefix and keeps the handle's
    /// remaining capacity.
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
    fn put<T: bytes::Buf>(&mut self, mut src: T)
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

/// Convert a [`Vec<u8>`] into an [`IoBufMut`] without copying.
///
/// The buffer adopts the vec's allocation, with the vec's contents as its
/// readable bytes and `vec.capacity()` as its capacity. A vec without an
/// allocation becomes an empty buffer.
impl From<Vec<u8>> for IoBufMut {
    #[inline]
    fn from(vec: Vec<u8>) -> Self {
        if vec.capacity() == 0 {
            return Self::default();
        }
        let (ptr, len, cap, owner) = Owner::adopt_vec(vec);
        Self {
            ptr,
            len,
            cap,
            owner,
        }
    }
}

/// Convert a [`BytesMut`] into an [`IoBufMut`].
///
/// When no other handle shares the allocation, the buffer reuses it and moves
/// the readable bytes to its front. Otherwise it copies the readable bytes
/// into a new allocation. Either way the capacity is at least
/// `bytes.capacity()`.
impl From<BytesMut> for IoBufMut {
    fn from(bytes: BytesMut) -> Self {
        let capacity = bytes.capacity();
        let mut vec = Vec::from(bytes);
        if vec.capacity() < capacity {
            vec.reserve_exact(capacity - vec.len());
        }
        Self::from(vec)
    }
}

/// Convert [`Bytes`] into an [`IoBufMut`].
///
/// When no other handle shares an allocation the `Bytes` owns (one that came
/// from a `Vec<u8>`, `Box<[u8]>`, or `BytesMut`), the buffer reuses that whole
/// allocation and moves the readable bytes to its front. Otherwise, including
/// for `'static` slices and [`Bytes::from_owner`] storage, it copies the
/// readable bytes into an allocation of exactly their length.
impl From<Bytes> for IoBufMut {
    fn from(bytes: Bytes) -> Self {
        Self::from(Vec::from(bytes))
    }
}

/// Convert an [`IoBuf`] into an [`IoBufMut`], without copying when
/// [`IoBuf::try_into_mut`] succeeds and copying the readable bytes otherwise.
impl From<IoBuf> for IoBufMut {
    fn from(buf: IoBuf) -> Self {
        match buf.try_into_mut() {
            Ok(buf) => buf,
            Err(buf) => Self::from(buf.as_ref()),
        }
    }
}

/// Panics for a `split_to` past the readable bytes.
///
/// Outlined so the inlined `split_to` keeps only a compare and a branch for
/// the bounds check.
#[cold]
#[inline(never)]
fn panic_split_to(at: usize, len: usize) -> ! {
    panic!("split_to out of bounds: {at:?} <= {len:?}");
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
#[commonware_macros::test_group("miri")]
mod unit_tests {
    use super::{super::bufs::IoBufs, *};
    use bytes::{Buf as _, Bytes, BytesMut};
    use commonware_codec::{Decode, Encode, RangeCfg};
    use core::ops::Bound;
    use std::panic::{RefUnwindSafe, UnwindSafe};

    /// Whether `buf` owns a native allocation, through a descriptor or a
    /// native record.
    fn is_native(buf: &IoBuf) -> bool {
        let owner = buf.owner.load();
        owner.descriptor().is_some()
            // SAFETY: `buf` holds a reference to the record for the whole call.
            || matches!(unsafe { owner.storage() }, Some(Storage::Native { .. }))
    }

    /// Whether `buf` owns its native allocation alone, through a descriptor.
    fn is_unshared(buf: &IoBuf) -> bool {
        buf.owner.load().descriptor().is_some()
    }

    /// Address and refcount of `buf`'s owner record, or `None` without one.
    fn record(buf: &IoBuf) -> Option<(usize, usize)> {
        let owner = buf.owner.load();
        if owner.descriptor().is_some() {
            return None;
        }
        // SAFETY: `buf` holds a reference to the record for the whole call,
        // and the storage address identifies the record.
        unsafe {
            let addr = owner.storage()?;
            Some((std::ptr::from_ref(addr).addr(), owner.refcount()?))
        }
    }

    /// Refcount of `buf`'s owner record, or `None` without one.
    fn refcount(buf: &IoBuf) -> Option<usize> {
        record(buf).map(|(_, refs)| refs)
    }

    /// Frozen native buffer holding the bytes `0..len` in an allocation of
    /// `cap` bytes, not yet shared.
    fn unshared(len: usize, cap: usize) -> IoBuf {
        let mut buf = IoBufMut::with_capacity(cap);
        for byte in 0..len {
            buf.put_u8(byte as u8);
        }
        let buf = buf.freeze();
        assert!(is_unshared(&buf));
        buf
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
        // The `IoBuf` docs guarantee every From conversion into IoBuf is
        // zero-copy. Pin payload pointer identity for each route.

        // A vec adopts its own allocation.
        let mut vec = Vec::with_capacity(128);
        vec.extend_from_slice(b"adopt");
        let ptr = vec.as_ptr();
        let buf = IoBuf::from(vec);
        assert_eq!(buf.as_ref().as_ptr(), ptr);

        // So does an exactly-sized vec, and converting it onward to `Bytes`
        // keeps the same payload.
        let vec = b"exact".to_vec();
        let ptr = vec.as_ptr();
        let buf = IoBuf::from(vec);
        assert_eq!(buf.as_ref().as_ptr(), ptr);
        assert_eq!(Bytes::from(buf).as_ptr(), ptr);

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

        // Non-empty static views decline because there is no allocation to
        // recover.
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
        // split_to on native and static IoBufs should produce identical results.
        let mut native = IoBufMut::with_capacity(256);
        native.put_slice(b"hello world");
        let mut native_buf = native.freeze();
        let mut bytes_buf = IoBuf::from(b"hello world");

        let native_empty = native_buf.split_to(0);
        let bytes_empty = bytes_buf.split_to(0);
        assert_eq!(native_empty, bytes_empty);
        assert_eq!(native_buf, bytes_buf);

        let native_prefix = native_buf.split_to(5);
        let bytes_prefix = bytes_buf.split_to(5);
        assert_eq!(native_prefix, bytes_prefix);
        assert_eq!(native_buf, bytes_buf);

        let native_rest = native_buf.split_to(native_buf.len());
        let bytes_rest = bytes_buf.split_to(bytes_buf.len());
        assert_eq!(native_rest, bytes_rest);
        assert_eq!(native_buf, bytes_buf);
        assert!(native_buf.is_empty());
        assert!(bytes_buf.is_empty());
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
    }

    #[test]
    fn test_iobufmut_freeze_after_advance_recovers_capacity() {
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
            .expect("unique buffer must recover mutability");
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
        // advance so the remaining writable capacity stays within the
        // allocation.
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

        // Recovering the advanced handle after a freeze derives its capacity
        // from the view offset (5 bytes into 16 leaves 11), and the final
        // drop, checked under miri, must deallocate with the original layout.
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
        let mut native_mut = IoBufMut::with_capacity(4);
        native_mut.put_slice(b"data");
        let native = native_mut.freeze();
        assert!(!native.as_ptr().is_null());

        // A vec adopts its allocation, so the unique immutable view recovers
        // mutability zero-copy.
        let mut adopted_vec = Vec::with_capacity(64);
        adopted_vec.extend_from_slice(&[1u8, 2, 3]);
        let unique = IoBuf::from(adopted_vec);
        let unique_mut = unique.try_into_mut().expect("adopted vec should convert");
        assert_eq!(unique_mut.as_ref(), &[1u8, 2, 3]);

        let shared = IoBuf::from(vec![4u8, 5, 6]);
        let _shared_clone = shared.clone();
        assert!(shared.try_into_mut().is_err());

        // Exactly-sized vecs adopt as well, and external `Bytes` views always
        // decline mutable recovery.
        let exact = IoBuf::from(vec![7u8, 8, 9]);
        assert_eq!(
            exact
                .try_into_mut()
                .expect("exactly-sized vec must adopt")
                .capacity(),
            3
        );
        let external = IoBuf::from(Bytes::from(vec![7u8, 8, 9]));
        assert!(external.try_into_mut().is_err());

        let expected: &[u8] = &[9u8, 8];
        let eq_buf = IoBuf::from(vec![9u8, 8]);
        assert!(PartialEq::<[u8]>::eq(&eq_buf, expected));

        let static_slice: &'static [u8] = b"static";
        assert_eq!(IoBuf::from(static_slice), b"static");

        let mut native_mut = IoBufMut::with_capacity(3);
        native_mut.put_slice(b"xyz");
        let native = native_mut.freeze();
        let native_ptr = native.as_ptr();
        let vec_out: Vec<u8> = native.clone().into();
        let bytes_out: Bytes = native.into();
        assert_eq!(vec_out, b"xyz");
        assert_eq!(bytes_out.as_ref(), b"xyz");

        // Native owners hand the allocation to `Bytes` without copying.
        assert_eq!(bytes_out.as_ptr(), native_ptr);
    }

    #[test]
    fn test_iobuf_from_bytes_zero_copy_round_trip() {
        // Bytes -> IoBuf is zero-copy. The handle points into the payload.
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
        assert_eq!(buf.as_ref().as_ptr() as usize, base);

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
    fn test_iobufmut_decode_preserves_byte_fields() {
        let values = vec![Bytes::from_static(b"abc"), Bytes::from_static(b"def")];
        let source = IoBufMut::from(values.encode());
        let range = source.as_ref().as_ptr_range();
        let decoded = Vec::<Bytes>::decode_cfg(source, &((..).into(), (..).into())).unwrap();
        assert_eq!(decoded, values);
        assert!(decoded.iter().all(|field| range.contains(&field.as_ptr())));
    }

    #[test]
    fn test_iobuf_read_cfg_zero_copy_from_iobuf_source() {
        // Decoding an IoBuf field from an IoBuf source must not copy the
        // payload. The source hands out a view sharing its owner, and the
        // field claims it as is.
        let cfg: RangeCfg<usize> = (0..=1024).into();
        let mut source = IoBuf::from(IoBuf::from(vec![7u8; 100]).encode());
        let prefix = source.len() - 100;
        let payload_ptr = source.as_ref()[prefix..].as_ptr();
        let decoded = IoBuf::read_cfg(&mut source, &cfg).unwrap();
        assert_eq!(decoded.len(), 100);
        assert_eq!(decoded.as_ptr(), payload_ptr);
        assert_eq!(decoded, [7u8; 100]);

        // A native source hands out a view of its own owner rather than a wrapped `Bytes`.
        let encoded = IoBuf::from(vec![7u8; 100]).encode();
        let mut native = IoBufMut::with_capacity(encoded.len());
        native.put_slice(&encoded);
        let mut source = native.freeze();
        let payload_ptr = source.as_ref()[prefix..].as_ptr();
        let decoded = IoBuf::read_cfg(&mut source, &cfg).unwrap();
        assert_eq!(decoded.as_ptr(), payload_ptr);

        // The field takes the rest of the source, so it keeps the source's
        // unshared native owner.
        assert!(is_unshared(&decoded));
    }

    /// A `Bytes` field decoded from an `IoBuf` source receives the view's bytes, and an
    /// `IoBuf` field decoded from a multi-chunk `IoBufs` source is the prefix coalesced once.
    #[test]
    fn test_take_owned_other_containers() {
        let cfg: RangeCfg<usize> = (0..=1024).into();
        let mut source = IoBuf::from(IoBuf::from(vec![7u8; 100]).encode());
        let decoded = Bytes::read_cfg(&mut source, &cfg).unwrap();
        assert_eq!(decoded, vec![7u8; 100]);

        let encoded = IoBuf::from(vec![7u8; 100]).encode();
        let mut source = IoBufs::from(IoBuf::copy_from_slice(&encoded[..50]));
        source.append(IoBuf::copy_from_slice(&encoded[50..]));
        let decoded = IoBuf::read_cfg(&mut source, &cfg).unwrap();
        assert_eq!(decoded, [7u8; 100]);
        assert!(source.is_empty());
    }

    #[test]
    #[should_panic(expected = "cannot advance")]
    fn test_iobufmut_put_does_not_trust_lying_buf() {
        // `Buf` is a safe trait, so a misbehaving source may hand out chunks
        // larger than its reported remaining(). `put` must bound each copy by
        // its own capacity and panic instead of overflowing the buffer.
        struct LyingBuf;
        impl bytes::Buf for LyingBuf {
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
    fn test_handle_auto_traits() {
        fn check<T: Send + Sync + Unpin + UnwindSafe + RefUnwindSafe>() {}
        check::<IoBuf>();
        check::<IoBufMut>();
    }

    #[test]
    fn test_unshared_lifecycle_keeps_descriptor() {
        let mut buf = IoBufMut::with_capacity(16);
        let base = buf.as_mut_ptr();
        buf.put_slice(b"0123456789");
        let mut frozen = buf.freeze();
        assert!(is_unshared(&frozen));

        // Advancing keeps the descriptor, and recovery returns the spare
        // capacity counted from the new view start.
        frozen.advance(3);
        let mut buf = frozen.try_into_mut().unwrap();
        // SAFETY: the view advanced by 3 bytes within the allocation.
        assert_eq!(buf.as_mut_ptr(), unsafe { base.add(3) });
        assert_eq!(buf.as_ref(), b"3456789");
        assert_eq!(buf.capacity(), 13);
        buf.put_slice(b"abcdef");
        assert_eq!(buf.capacity(), 13);

        let frozen = buf.freeze();
        assert!(is_unshared(&frozen));
        let mut buf = frozen.try_into_mut().unwrap();
        assert_eq!(buf.as_ref(), b"3456789abcdef");
        buf.advance(13);
        assert_eq!(buf.capacity(), 0);

        // A fully advanced view still owns the allocation until it drops.
        let mut frozen = IoBufMut::from(&b"xyz"[..]).freeze();
        frozen.advance(3);
        assert!(frozen.is_empty() && is_unshared(&frozen));
        let recovered = frozen.try_into_mut().unwrap();
        assert_eq!((recovered.len(), recovered.capacity()), (0, 0));
    }

    #[test]
    fn test_first_share_promotes_once() {
        let buf = unshared(8, 12);
        let first = buf.clone();
        let (addr, refs) = record(&buf).unwrap();
        assert_eq!(refs, 2);
        assert_eq!(record(&first), Some((addr, 2)));

        // Later shares reuse the record.
        let second = first.clone();
        let third = buf.slice(2..5);
        assert_eq!(record(&third), Some((addr, 4)));
        assert_eq!(third, [2u8, 3, 4]);
        assert_eq!(second, buf);

        // Recovery declines while views live and keeps the tail afterwards.
        let buf = buf.try_into_mut().unwrap_err();
        drop((first, second, third));
        assert_eq!(refcount(&buf), Some(1));
        let recovered = buf.try_into_mut().unwrap();
        assert_eq!(recovered.as_ref(), [0u8, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(recovered.capacity(), 12);
    }

    #[test]
    fn test_slice_promotes_from_source_view() {
        // A view at offset 5 with a 28-byte tail promotes with the original
        // base and layout, so a slice that outlives it recovers capacity up to
        // the allocation end.
        let mut buf = unshared(100, 128);
        buf.advance(5);
        let slice = buf.slice(10..30);
        assert_eq!(refcount(&slice), Some(2));
        drop(buf);
        let recovered = slice.try_into_mut().unwrap();
        assert_eq!(recovered.as_ref(), (15u8..35).collect::<Vec<_>>());
        assert_eq!(recovered.capacity(), 128 - 15);
    }

    #[test]
    fn test_aligned_descriptor_promotes_from_unaligned_view() {
        let alignment = NonZeroUsize::new(64).unwrap();
        let mut buf = IoBufMut::with_alignment(256, alignment);
        assert!((buf.as_mut_ptr() as usize).is_multiple_of(64));
        buf.put_bytes(9, 100);

        // Promoting a view 3 bytes past the aligned base must recover the base
        // and layout of the original allocation.
        let mut frozen = buf.freeze();
        frozen.advance(3);
        let view = frozen.clone();
        drop(frozen);

        // The recovered capacity reaches the end of the allocation, and all of
        // it is writable.
        let mut recovered = view.try_into_mut().unwrap();
        assert_eq!(recovered.capacity(), 253);
        recovered.put_bytes(1, 156);
        assert_eq!(recovered.len(), 253);
    }

    #[test]
    fn test_clone_of_empty_cursor_keeps_allocation() {
        let mut buf = unshared(4, 8);
        buf.advance(4);
        assert!(buf.is_empty() && is_unshared(&buf));

        // Unlike an empty slice or split, a clone of a fully advanced view
        // shares the allocation, so either handle can recover the tail once
        // the other drops.
        let clone = buf.clone();
        assert_eq!(refcount(&clone), Some(2));
        drop(clone);

        let recovered = buf.try_into_mut().unwrap();
        assert_eq!((recovered.len(), recovered.capacity()), (0, 4));
    }

    #[test]
    fn test_moves_and_empty_views_do_not_promote() {
        let mut buf = unshared(8, 8);
        let mut moved = std::mem::take(&mut buf);
        assert!(is_unshared(&moved));
        assert!(buf.is_empty() && !is_native(&buf));

        // Empty halves and empty slices detach without touching the owner.
        assert!(moved.split_to(0).is_empty());
        assert!(moved.slice(3..3).is_empty());
        assert!(is_unshared(&moved));

        // A whole split, a whole take, and a whole drain move the descriptor.
        let mut whole = moved.split_to(8);
        assert!(moved.is_empty() && is_unshared(&whole));
        let mut taken: IoBuf = whole.take_owned(8);
        assert!(is_unshared(&taken));
        let bytes = taken.copy_to_bytes(8);
        assert_eq!(bytes, [0u8, 1, 2, 3, 4, 5, 6, 7].as_slice());
    }

    #[test]
    fn test_partial_split_promotes_and_shares() {
        // A partial split promotes the descriptor, and both halves share the
        // new record.
        let mut buf = unshared(10, 16);
        let prefix = buf.split_to(4);
        let (addr, refs) = record(&buf).unwrap();
        assert_eq!(refs, 2);
        assert_eq!(record(&prefix), Some((addr, 2)));
        assert_eq!(prefix, [0u8, 1, 2, 3]);

        // Later partial splits and takes reuse that record.
        let middle = buf.split_to(2);
        let taken: IoBuf = buf.take_owned(1);
        assert_eq!(record(&taken), Some((addr, 4)));
        assert_eq!(
            (middle, taken),
            (IoBuf::from(&[4u8, 5]), IoBuf::from(&[6u8]))
        );
        assert_eq!(buf, [7u8, 8, 9]);

        // Once the other views drop, the rest recovers the allocation tail.
        drop(prefix);
        let recovered = buf.try_into_mut().unwrap();
        assert_eq!(recovered.capacity(), 9);
    }

    #[test]
    fn test_bytes_from_unshared_view_keeps_allocation() {
        // A conversion moves the advanced descriptor into the Bytes owner
        // without promoting it. The last Bytes clone frees the allocation
        // with its original layout, on another thread.
        let mut buf = unshared(10, 16);
        buf.advance(2);
        let bytes = Bytes::from(buf);
        let slice = bytes.slice(1..4);
        drop(bytes);
        std::thread::spawn(move || assert_eq!(slice, [3u8, 4, 5].as_slice()))
            .join()
            .unwrap();

        // Direct boxing and a round trip through Bytes keep the view alive.
        let direct = Bytes::from_owner(unshared(3, 5));
        let round_trip = IoBuf::from(direct.clone());
        assert_eq!(round_trip, [0u8, 1, 2]);
        drop(direct);
        assert_eq!(round_trip, [0u8, 1, 2]);

        // A partial drain shares the allocation with the drained Bytes.
        let mut buf = unshared(10, 16);
        let drained = buf.copy_to_bytes(4);
        assert_eq!(refcount(&buf), Some(2));
        drop(drained);
        assert_eq!(refcount(&buf), Some(1));
        assert_eq!(buf.try_into_mut().unwrap().capacity(), 12);
    }

    #[test]
    fn test_freeze_tail_overflow_allocates_record() {
        // Spare capacity beyond every descriptor tail moves into a record at
        // freeze, which keeps the data pointer and the full capacity.
        let capacity = (1 << 17) + 1;
        let mut buf = IoBufMut::with_capacity(capacity);
        let base = buf.as_mut_ptr();
        buf.put_u8(1);
        let frozen = buf.freeze();
        let (addr, refs) = record(&frozen).unwrap();
        assert_eq!(refs, 1);
        let view = frozen.clone();
        assert_eq!(record(&view), Some((addr, 2)));
        drop(view);
        let mut recovered = frozen.try_into_mut().unwrap();
        assert_eq!(recovered.as_mut_ptr(), base);
        assert_eq!(recovered.capacity(), capacity);
    }

    #[test]
    fn test_concurrent_first_clones_share_one_record() {
        // Four threads race the first share. Exactly one record is published,
        // and the threads that lose the race join it.
        let buf = unshared(32, 32);
        let views: Vec<IoBuf> = std::thread::scope(|scope| {
            let buf = &buf;
            let handles: Vec<_> = (0..4)
                .map(|i| {
                    scope.spawn(move || {
                        if i % 2 == 0 {
                            buf.clone()
                        } else {
                            buf.slice(1..31)
                        }
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        // The source and the four views hold the record's five references.
        let (addr, refs) = record(&buf).unwrap();
        assert_eq!(refs, 5);
        assert!(views.iter().all(|view| record(view).unwrap().0 == addr));

        // Dropping the views leaves the source as the record's only holder.
        drop(views);
        assert_eq!(buf.try_into_mut().unwrap().capacity(), 32);
    }

    #[test]
    fn test_iobufmut_from_iobuf() {
        // Unique buffers recover mutability without copying.
        let mut unique = IoBufMut::with_capacity(4);
        unique.put_slice(b"data");
        let unique_ptr = unique.as_mut_ptr();
        let mut recovered = IoBufMut::from(unique.freeze());
        assert_eq!(recovered.as_ref(), b"data");
        assert_eq!(recovered.as_mut_ptr(), unique_ptr);

        // Shared buffers allocate and copy readable bytes.
        let mut shared = IoBufMut::with_capacity(4);
        shared.put_slice(b"copy");
        let shared = shared.freeze();
        let shared_ptr = shared.as_ptr();
        let _clone = shared.clone();
        let mut copied = IoBufMut::from(shared);
        assert_eq!(copied.as_ref(), b"copy");
        assert_ne!(copied.as_mut_ptr() as *const u8, shared_ptr);

        // Recovery after transient slices are dropped is zero-copy and preserves
        // the full readable length and capacity.
        let mut mirror = IoBufMut::with_capacity(8);
        mirror.put_slice(b"abcdefgh");
        let mirror_cap = mirror.capacity();
        let mirror_ptr = mirror.as_mut_ptr();
        let frozen = mirror.freeze();
        let head = frozen.slice(0..3);
        let tail = frozen.slice(5..8);
        drop(head);
        drop(tail);
        let mut recovered = IoBufMut::from(frozen);
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
        // A uniquely owned BytesMut hands over its allocation.
        let mut bytes = BytesMut::with_capacity(100);
        bytes.put_slice(b"abc");
        let cap = bytes.capacity();
        let base = bytes.as_ptr() as usize;
        let buf = IoBufMut::from(bytes);
        assert_eq!(buf.as_ref(), b"abc");
        assert_eq!(buf.capacity(), cap);
        assert_eq!(buf.as_ref().as_ptr() as usize, base);

        // A uniquely owned BytesMut advanced past its allocation's start is
        // reused, with the readable bytes moved to the front.
        let mut advanced = BytesMut::with_capacity(100);
        advanced.put_slice(b"prefix-payload");
        let base = advanced.as_ptr() as usize;
        advanced.advance(7);
        let buf = IoBufMut::from(advanced);
        assert_eq!(buf.as_ref(), b"payload");
        assert_eq!(buf.as_ref().as_ptr() as usize, base);
        assert!(buf.capacity() >= 100);

        // An empty reserved BytesMut keeps its reservation writable.
        let bytes = BytesMut::with_capacity(64);
        let cap = bytes.capacity();
        let mut buf = IoBufMut::from(bytes);
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), cap);
        buf.put_bytes(7, cap);
        assert_eq!(buf.len(), cap);

        // A BytesMut whose allocation is shared with another handle copies,
        // keeping its reserved capacity.
        let mut shared = BytesMut::with_capacity(100);
        shared.put_slice(b"shared");
        let other = shared.split_to(3);
        let cap = shared.capacity();
        let base = shared.as_ptr() as usize;
        let buf = IoBufMut::from(shared);
        assert_eq!(buf.as_ref(), b"red");
        assert_ne!(buf.as_ref().as_ptr() as usize, base);
        assert_eq!(buf.capacity(), cap);
        assert_eq!(other.as_ref(), b"sha");
    }

    /// `From<Bytes>` hands a uniquely owned allocation to the mutable buffer
    /// with the readable bytes moved to its front, and copies when the
    /// allocation is shared or not owned by the `Bytes`.
    #[test]
    fn test_iobufmut_from_bytes_reuses_unique_allocation() {
        // A vec with spare capacity freezes into shared-ownership Bytes whose
        // single handle hands over the vec's allocation and capacity.
        let mut vec = Vec::with_capacity(100);
        vec.extend_from_slice(b"abc");
        let base = vec.as_ptr() as usize;
        let buf = IoBufMut::from(Bytes::from(vec));
        assert_eq!(buf.as_ref(), b"abc");
        assert_eq!(buf.as_ref().as_ptr() as usize, base);
        assert_eq!(buf.capacity(), 100);

        // An exactly-sized vec takes the boxed-slice route in bytes and hands
        // over its allocation the same way.
        let vec = b"exact".to_vec();
        let base = vec.as_ptr() as usize;
        let buf = IoBufMut::from(Bytes::from(vec));
        assert_eq!(buf.as_ref(), b"exact");
        assert_eq!(buf.as_ref().as_ptr() as usize, base);
        assert_eq!(buf.capacity(), 5);

        // A unique view advanced past the allocation's start is reused with
        // the readable bytes moved to the front.
        let vec = b"prefix-payload".to_vec();
        let base = vec.as_ptr() as usize;
        let mut advanced = Bytes::from(vec);
        advanced.advance(7);
        let buf = IoBufMut::from(advanced);
        assert_eq!(buf.as_ref(), b"payload");
        assert_eq!(buf.as_ref().as_ptr() as usize, base);
        assert_eq!(buf.capacity(), 14);

        // A slice becomes unique again once its sibling views are gone.
        let vec = b"head-tail".to_vec();
        let base = vec.as_ptr() as usize;
        let whole = Bytes::from(vec);
        let tail = whole.slice(5..);
        drop(whole);
        let buf = IoBufMut::from(tail);
        assert_eq!(buf.as_ref(), b"tail");
        assert_eq!(buf.as_ref().as_ptr() as usize, base);
        assert_eq!(buf.capacity(), 9);

        // An empty Bytes that still owns spare capacity keeps it writable.
        let vec = Vec::<u8>::with_capacity(64);
        let base = vec.as_ptr() as usize;
        let mut buf = IoBufMut::from(Bytes::from(vec));
        assert!(buf.is_empty());
        assert_eq!(buf.as_ref().as_ptr() as usize, base);
        assert_eq!(buf.capacity(), 64);
        buf.put_slice(b"ready");
        assert_eq!(buf.as_ref(), b"ready");
        assert_eq!(IoBufMut::from(Bytes::new()).capacity(), 0);

        // A Bytes whose allocation another handle shares copies, and the other
        // handle keeps its bytes.
        let shared = Bytes::from(b"shared".to_vec());
        let base = shared.as_ptr() as usize;
        let other = shared.clone();
        let mut buf = IoBufMut::from(shared);
        assert_eq!(buf.as_ref(), b"shared");
        assert_ne!(buf.as_ref().as_ptr() as usize, base);
        assert_eq!(buf.capacity(), 6);
        buf.as_mut()[0] = b'S';
        assert_eq!(other.as_ref(), b"shared");

        // Static and owner-backed Bytes do not own a vec allocation, so they
        // copy.
        let buf = IoBufMut::from(Bytes::from_static(b"static"));
        assert_eq!(buf.as_ref(), b"static");
        assert_ne!(buf.as_ref().as_ptr() as usize, b"static".as_ptr() as usize);
        let owned = Bytes::from_owner(b"owned".to_vec());
        let base = owned.as_ptr() as usize;
        let buf = IoBufMut::from(owned);
        assert_eq!(buf.as_ref(), b"owned");
        assert_ne!(buf.as_ref().as_ptr() as usize, base);
    }

    #[test]
    fn test_iobufmut_from_vec_preserves_capacity() {
        let mut vec = Vec::with_capacity(100);
        vec.extend_from_slice(b"abc");
        let base = vec.as_ptr() as usize;
        let buf = IoBufMut::from(vec);
        assert_eq!(buf.as_ref(), b"abc");
        assert_eq!(buf.capacity(), 100);

        // The vec's allocation is adopted, not copied.
        assert_eq!(buf.as_ref().as_ptr() as usize, base);

        // An empty reservation converts to a writable buffer of the same
        // capacity.
        let mut buf = IoBufMut::from(Vec::with_capacity(64));
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), 64);
        buf.put_bytes(7, 64);
        assert_eq!(buf.len(), 64);

        // A vec without an allocation becomes an empty buffer, and an
        // exactly-sized vec keeps its exact capacity.
        assert!(IoBufMut::from(Vec::new()).is_empty());
        let exact = IoBufMut::from(vec![1u8, 2, 3]);
        assert_eq!(exact.capacity(), 3);
        assert_eq!(
            exact
                .freeze()
                .try_into_mut()
                .expect("unique view must recover mutability")
                .as_ref(),
            &[1u8, 2, 3]
        );
    }

    #[test]
    #[should_panic(expected = "size must fit a layout")]
    fn test_iobufmut_with_capacity_rejects_oversized_request() {
        // The layout check panics before any allocation. Sizes up to
        // isize::MAX are valid layouts and would fail as allocation errors.
        let _ = IoBufMut::with_capacity(isize::MAX as usize + 1);
    }

    #[test]
    fn test_iobufmut_try_with_alignment_declines_impossible_layouts() {
        // Requests without a valid layout return None (the second size rounds
        // up past isize::MAX), and a valid one gets its exact size.
        let page = NonZeroUsize::new(4096).expect("non-zero alignment");
        assert!(IoBufMut::try_with_alignment(isize::MAX as usize + 1, page).is_none());
        assert!(IoBufMut::try_with_alignment(isize::MAX as usize - 4094, page).is_none());
        assert!(
            IoBufMut::try_with_alignment(64, NonZeroUsize::new(3).expect("non-zero")).is_none()
        );
        let mut buf =
            IoBufMut::try_with_alignment(100, page).expect("a page-aligned 100-byte layout");
        assert_eq!(buf.capacity(), 100);
        assert!((buf.as_mut_ptr() as usize).is_multiple_of(4096));
        assert_eq!(
            IoBufMut::try_with_alignment(0, page)
                .expect("empty")
                .capacity(),
            0
        );
    }

    #[test]
    fn test_iobuf_aligned_public_paths() {
        // Exercise the public IoBuf/IoBufMut API on aligned allocations:
        // write, advance, copy_to_bytes, freeze, slice, split_to,
        // try_into_mut, and From/Into conversions.
        static ARRAY: &[u8; 4] = b"wxyz";

        let alignment = NonZeroUsize::new(64).expect("non-zero alignment");

        // Start from a non-zero aligned buffer to cover the public mutable API.
        let mut aligned_mut = IoBufMut::with_alignment(8, alignment);
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

        // Freeze to an immutable aligned `IoBuf` and exercise its view and Buf methods.
        let aligned = aligned_mut.freeze();
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

        // Empty, partial, and full immutable drains return the bytes in order.
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

        // Conversions to `Vec` and `Bytes`, and from a static array, preserve the bytes.
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
        // Aligned requests get their exact capacity, which survives a
        // freeze/try_into_mut round trip.
        let alignment = NonZeroUsize::new(4096).expect("non-zero alignment");
        let mut buf = IoBufMut::with_alignment(100, alignment);
        assert_eq!(buf.capacity(), 100);
        assert!((buf.as_mut_ptr() as usize).is_multiple_of(4096));

        buf.put_slice(b"data");
        let recovered = buf
            .freeze()
            .try_into_mut()
            .expect("unique native view recovers");
        assert_eq!(recovered.capacity(), 100);

        // The zeroed variant is fully readable and exactly sized.
        let zeroed = IoBufMut::zeroed_with_alignment(100, alignment);
        assert_eq!(zeroed.len(), 100);
        assert_eq!(zeroed.capacity(), 100);
    }

    #[test]
    #[should_panic(expected = "set_len(9) exceeds capacity(8)")]
    fn test_iobufmut_set_len_overflow() {
        let mut buf = IoBufMut::with_capacity(8);
        // SAFETY: this will panic before any read.
        unsafe { buf.set_len(9) };
    }
}

// Conformance fixture keys include the test's module path, so this test lives outside the module
// that the `miri` test group renames.
#[cfg(all(test, not(feature = "loom"), feature = "arbitrary"))]
mod tests {
    mod conformance {
        use super::super::IoBuf;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<IoBuf>
        }
    }
}
