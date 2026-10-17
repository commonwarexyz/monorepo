//! Allocation owners for [`super::IoBuf`] and [`super::IoBufMut`].
//!
//! # Handle shapes
//!
//! The public I/O buffer handles are intentionally small and direct:
//!
//! ```text
//! IoBuf    = ptr, len,      owner   (24 bytes on 64-bit)
//! IoBufMut = ptr, len, cap, owner   (32 bytes on 64-bit)
//! ```
//!
//! The `bytes::Buf` and `bytes::BufMut` cursor methods (`remaining`, `chunk`,
//! `advance`, `copy_to_slice`, and the write-side equivalents) read only those
//! handle fields. They do not match on allocation kind and do not dispatch
//! through a vtable. The allocation kind is needed only for lifecycle and
//! ownership-transferring operations such as clone, drop, `freeze`,
//! `copy_to_bytes`, and `try_into_mut`, so that metadata is stored in an owner
//! record outside the hot cursor arithmetic.
//!
//! # Owner model
//!
//! [`OwnerRef`] is a tagged pointer. The value is either zero (no owner) or a
//! pointer to an owner struct with its kind encoded in the low two bits:
//!
//! ```text
//! 0 (entire value)        EMPTY     no owner: empty views and 'static slices
//! record ptr | 0b01       HEAP      HeapOwner: separately allocated record
//!                                   for native heap buffers and adopted
//!                                   vecs
//! owner ptr  | 0b11       EXTERNAL  boxed ExternalOwner holding a Bytes
//! ```
//!
//! Tag `0b10` is unassigned. At most two tag bits are available because
//! every owner type starts with an `AtomicUsize`, which is guaranteed just
//! 4-byte alignment on 32-bit targets such as wasm32 (const-asserted below).
//!
//! Every owner type stores its shared refcount at offset 0 (const-asserted),
//! so refcount operations read directly through the untagged pointer with no
//! kind dispatch. The kind is examined only on final release.
//!
//! # Allocation layouts
//!
//! Native heap allocations keep their owner record in a separate small
//! allocation, so the data allocation has exactly the requested size and
//! alignment:
//!
//! ```text
//! [ usable data bytes ............ ]      [ owner record ]
//! ^                                        ^
//! data base (alignment preserved)          OwnerRef target
//! ```
//!
//! `freeze` shares the record without allocating, and a mutable drop frees
//! both allocations through it. A sliced or advanced handle may point into
//! the usable region, so drop and `try_into_mut` recover the original base
//! from the record.
//!
//! `From<Vec<u8>>` adopts the vec's own allocation as a native heap buffer
//! with the same layout: the record is allocated separately and stores the
//! vec's allocation layout `(cap, align = 1)`, so the data is freed as it
//! was created and every byte of the vec's capacity stays usable. Adoption
//! copies nothing, works for exactly-sized vecs, and keeps mutable recovery
//! through `try_into_mut`.
//!
//! `Bytes` values are owned externally: a small boxed [`ExternalOwner`]
//! holds the `Bytes`, our refcount fronts it, and the handle points directly
//! into the payload:
//!
//! ```text
//! IoBuf.ptr ------------------------------v
//! [ refs | Bytes ]        [ payload bytes ............ ]
//! ^ OwnerRef target        ^ kept alive by the inner Bytes
//! ```
//!
//! Clones, slices, and drops of the `IoBuf` touch only our refcount. The
//! inner `Bytes` refcount is touched at construction, at final release, and
//! by the `slice_ref` fast paths (partial `copy_to_bytes` drains and
//! `Bytes::from(IoBuf)` conversions of external-backed views).
//!
//! # Refcount state machine
//!
//! The refcount uses `1` as the unique-owner sentinel, so the common final
//! release performs no refcount write at all:
//!
//! ```text
//! state                                refs
//! ---------------------------------   -------------------
//! unique mutable (IoBufMut)            1 (never touched)
//! single immutable owner (IoBuf)       1
//! N shared immutable owners            N
//! ```
//!
//! `IoBufMut` never touches the refcount: mutable handles are unique by
//! construction and stay at the sentinel until `freeze` hands the owner word
//! to an immutable `IoBuf`.

use bytes::Bytes;
use std::{
    alloc::{Layout, alloc, alloc_zeroed, dealloc, handle_alloc_error},
    mem::{ManuallyDrop, align_of, offset_of},
    ptr::{self, NonNull},
    sync::atomic::Ordering,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::atomic::{AtomicUsize, fence};
    } else {
        use std::sync::atomic::{AtomicUsize, fence};
    }
}

const OWNER_HEAP: usize = 0b01;
const OWNER_EXTERNAL: usize = 0b11;
const OWNER_TAG_MASK: usize = 0b11;

/// Refcount ceiling shared with `Arc` and `bytes`.
///
/// A refcount above `isize::MAX` can only result from a leak loop (`mem::forget`
/// in a cycle). Allowing it to wrap would turn into use-after-free, so
/// [`OwnerRef::clone_shared`] aborts instead.
const MAX_REFCOUNT: usize = isize::MAX as usize;

// The low two pointer bits are usable as the kind tag only if every owner
// type is at least 4-byte aligned, including on 32-bit targets where
// `AtomicUsize` is 4 bytes.
const _: () = assert!(align_of::<HeapOwner>() >= 4);
const _: () = assert!(align_of::<ExternalOwner>() >= 4);

// `OwnerRef::refs` reads the refcount directly through the untagged pointer,
// which is only sound if every owner type stores it at offset 0.
const _: () = assert!(offset_of!(HeapOwner, refs) == 0);
const _: () = assert!(offset_of!(ExternalOwner, refs) == 0);

/// Tagged reference to an allocation owner.
///
/// The value is either zero (empty) or a pointer to one of the owner structs
/// with the low tag bits set (see the module docs for the encoding).
///
/// Empty owner refs are also used for non-empty `'static` slices. They need no
/// lifecycle work because the payload is immortal. Code that needs to recover
/// mutable ownership therefore checks both `owner.is_empty()` and `len == 0`.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct OwnerRef(*mut ());

// SAFETY: `OwnerRef` is a tagged owner pointer. Shared access to the pointed-to
// owner state is synchronized through the owner's atomic refcount.
unsafe impl Send for OwnerRef {}
// SAFETY: same argument as `Send`.
unsafe impl Sync for OwnerRef {}

impl OwnerRef {
    #[inline(always)]
    pub(crate) const fn empty() -> Self {
        Self(ptr::null_mut())
    }

    #[inline(always)]
    pub(crate) const fn is_empty(self) -> bool {
        self.0.is_null()
    }

    /// Returns the kind tag stored in the low pointer bits.
    #[inline(always)]
    fn tag(self) -> usize {
        self.0.addr() & OWNER_TAG_MASK
    }

    #[inline(always)]
    pub(crate) fn is_external(self) -> bool {
        self.tag() == OWNER_EXTERNAL
    }

    /// Builds an owner ref from an owner pointer and its kind tag.
    #[inline(always)]
    fn from_tagged<T>(ptr: NonNull<T>, tag: usize) -> Self {
        let ptr = ptr.cast::<()>().as_ptr();
        Self(ptr.with_addr(ptr.addr() | tag))
    }

    /// Recovers the untagged owner pointer.
    ///
    /// # Safety
    ///
    /// `self` must be a live non-empty owner whose pointer targets a `T`.
    #[inline(always)]
    unsafe fn untag<T>(self) -> NonNull<T> {
        let ptr = self
            .0
            .with_addr(self.0.addr() & !OWNER_TAG_MASK)
            .cast::<T>();
        // SAFETY: non-empty owner refs are built from non-null pointers, and
        // masking the tag bits cannot zero a record or box address.
        unsafe { NonNull::new_unchecked(ptr) }
    }

    /// Creates a heap owner ref from a [`HeapOwner`] pointer.
    ///
    /// # Safety
    ///
    /// `header` must point to the initialized [`HeapOwner`] record of an
    /// allocation owned by this owner ref, with its low tag bits zero.
    #[inline(always)]
    unsafe fn from_heap(header: NonNull<HeapOwner>) -> Self {
        Self::from_tagged(header, OWNER_HEAP)
    }

    /// Creates an external owner ref.
    ///
    /// # Safety
    ///
    /// `owner` must come from `Box::into_raw(Box<ExternalOwner>)` and be
    /// uniquely represented by this owner ref.
    #[inline(always)]
    unsafe fn from_external(owner: NonNull<ExternalOwner>) -> Self {
        Self::from_tagged(owner, OWNER_EXTERNAL)
    }

    /// Converts `vec` into immutable handle fields by adopting its allocation.
    ///
    /// Empty vecs detach entirely (empty immutable buffers never pin an
    /// allocation).
    pub(crate) fn from_vec(vec: Vec<u8>) -> (NonNull<u8>, usize, Self) {
        if vec.is_empty() {
            return (NonNull::dangling(), 0, Self::empty());
        }
        let (ptr, len, _, owner) = HeapOwner::adopt_vec(vec);
        (ptr, len, owner)
    }

    /// Moves `bytes` into a boxed [`ExternalOwner`] and returns handle fields.
    ///
    /// Zero-copy: the handle points directly into the payload kept alive by the
    /// inner `Bytes`. Costs one box. Handle clones and drops never touch the
    /// inner refcount (only final release and the `slice_ref` conversion fast
    /// paths do).
    pub(crate) fn from_bytes(bytes: Bytes) -> (NonNull<u8>, usize, Self) {
        if bytes.is_empty() {
            return (NonNull::dangling(), 0, Self::empty());
        }
        ExternalOwner::from_bytes(bytes)
    }

    /// Returns the heap record for a heap owner (native or adopted).
    ///
    /// # Safety
    ///
    /// `self` must be a live heap owner.
    #[inline(always)]
    unsafe fn heap(self) -> NonNull<HeapOwner> {
        // SAFETY: a live heap owner's address targets a `HeapOwner`.
        unsafe { self.untag() }
    }

    /// Returns the external owner box pointer.
    ///
    /// # Safety
    ///
    /// `self` must be a live external owner.
    #[inline(always)]
    unsafe fn external(self) -> NonNull<ExternalOwner> {
        // SAFETY: a live external owner's address targets an `ExternalOwner`.
        unsafe { self.untag() }
    }

    /// Returns the shared refcount for a non-empty owner.
    ///
    /// Every owner type stores `refs: AtomicUsize` at offset 0
    /// (const-asserted above), so this reads through the untagged pointer
    /// without dispatching on the owner kind.
    ///
    /// # Safety
    ///
    /// `self` must be a live non-empty owner. The returned reference is only
    /// valid while the owner is live. The `'static` lifetime is a convenience
    /// the caller must bound.
    #[inline(always)]
    unsafe fn refs(self) -> &'static AtomicUsize {
        // SAFETY: every owner kind is repr(C) with `refs` at offset 0, so the
        // untagged address targets the shared refcount regardless of kind.
        unsafe { self.untag::<AtomicUsize>().as_ref() }
    }

    /// Returns the inner [`Bytes`] of an external owner.
    ///
    /// # Safety
    ///
    /// `self` must be a live external owner, and the caller must bound the
    /// returned borrow by the owner's liveness (the handle that supplied
    /// `self` keeps a reference for at least that long).
    #[inline(always)]
    pub(crate) unsafe fn external_bytes<'a>(self) -> &'a Bytes {
        // SAFETY: guaranteed by the caller.
        unsafe { &(*self.external().as_ptr()).bytes }
    }

    /// Retains one immutable shared view.
    ///
    /// Mutable buffers never call this. Their owner is unique until `freeze`
    /// hands it to an immutable `IoBuf`.
    ///
    /// # Safety
    ///
    /// `self` must be empty or have at least one live reference owned by the
    /// caller.
    #[inline(always)]
    pub(crate) unsafe fn clone_shared(self) {
        if self.is_empty() {
            return;
        }
        // Relaxed suffices: the caller's existing handle proves the owner is
        // live, and no payload writes need to be published by a clone.
        // SAFETY: non-empty owners have a valid refcount.
        let old = unsafe { self.refs() }.fetch_add(1, Ordering::Relaxed);
        // Guard against refcount overflow (same insurance as `Arc` and
        // `bytes`): wrapping would alias a freed allocation.
        if old > MAX_REFCOUNT {
            std::process::abort();
        }
    }

    /// Drops one immutable shared view.
    ///
    /// The refcount uses `1` as the unique-owner sentinel (see the module docs),
    /// so the unshared fast path is a single Acquire load followed by release:
    /// no read-modify-write, with the release work outlined in
    /// [`Self::release_unique`]. Shared owners pay one inline Release
    /// decrement. The rare race where another drop reaches the sentinel
    /// between the load and the decrement lands in
    /// [`Self::drop_shared_race_final`].
    ///
    /// # Safety
    ///
    /// `self` must be empty or have one live reference owned by the caller,
    /// which this call consumes.
    #[inline(always)]
    pub(crate) unsafe fn drop_shared(self) {
        if self.is_empty() {
            return;
        }

        // SAFETY: non-empty owners have a valid refcount.
        let refs = unsafe { self.refs() };
        // Acquire pairs with the Release decrements below: observing 1 means
        // every other handle has already dropped, and their payload reads
        // happen-before this release.
        if refs.load(Ordering::Acquire) == 1 {
            // SAFETY: this is the final shared owner.
            unsafe { self.release_unique() };
            return;
        }

        // Release publishes this handle's payload reads to whichever drop ends
        // up releasing the allocation. This is the common shared-clone drop
        // path, so keep it inline instead of paying an outlined call.
        let old = refs.fetch_sub(1, Ordering::Release);
        if old == 1 {
            // SAFETY: this drop won the final-owner race.
            unsafe { self.drop_shared_race_final(refs) };
        }
    }

    /// Releases after a shared-drop race made this handle final.
    ///
    /// Reached when the fast-path load observed a shared count, but every
    /// other handle dropped before this handle's decrement. That branch is
    /// reachable only under true concurrency (covered by loom), so it stays
    /// outlined and cold.
    ///
    /// # Safety
    ///
    /// `self` must be the final owner and `refs` must be this owner's refcount.
    #[cold]
    #[inline(never)]
    unsafe fn drop_shared_race_final(self, refs: &AtomicUsize) {
        // Acquire fence pairs with the Release decrements of all other
        // handles, ordering their payload accesses before the release.
        fence(Ordering::Acquire);
        // Restore the unique-owner sentinel that release expects. No other
        // handle exists, so Relaxed is sufficient.
        refs.store(1, Ordering::Relaxed);
        // SAFETY: guaranteed by the caller.
        unsafe { self.release_unique() };
    }

    /// Releases a uniquely-owned allocation.
    ///
    /// One outlined function serves every drop site, so the dealloc and
    /// box-drop code is not instantiated inline at each `IoBuf`/`IoBufMut`
    /// drop. This keeps `IoBuf`'s drop glue to a null test, one refcount
    /// load, and a branch to this call, small enough to inline into drop
    /// sites; the non-final shared decrement pays no call.
    ///
    /// # Safety
    ///
    /// No other handle may reference this allocation.
    #[inline(never)]
    pub(crate) unsafe fn release_unique(self) {
        let tag = self.tag();
        if tag == OWNER_HEAP {
            // SAFETY: unique initialized heap owner.
            unsafe { HeapOwner::release(self.heap()) };
        } else if tag == OWNER_EXTERNAL {
            // SAFETY: unique external owner.
            unsafe { ExternalOwner::release(self.external()) };
        }
        // Empty owners need no release work.
    }

    /// Returns true when this owner has exactly one live reference.
    ///
    /// Sound for the same reason `Arc::get_mut` is: a count of 1 observed
    /// through Acquire means no other handle exists, and no thread can clone
    /// without a handle. The Acquire load pairs with the Release decrement in
    /// [`Self::drop_shared`] so the last dropper's payload reads
    /// happen-before any mutation that follows a `true` result.
    ///
    /// # Safety
    ///
    /// `self` must be a live non-empty owner.
    #[inline(always)]
    pub(crate) unsafe fn is_unique(self) -> bool {
        // SAFETY: guaranteed by the caller.
        unsafe { self.refs() }.load(Ordering::Acquire) == 1
    }

    /// Returns the base pointer of the usable data region.
    ///
    /// # Safety
    ///
    /// `self` must be a live heap owner. External owners decline
    /// mutable recovery, so lifecycle code never asks for their base.
    #[inline]
    pub(crate) unsafe fn data_base(self) -> NonNull<u8> {
        // SAFETY: guaranteed by the caller.
        unsafe { self.heap().as_ref().data_base }
    }

    /// Returns the usable data capacity for this owner.
    ///
    /// This is the exact size of the data allocation: the requested capacity
    /// for native buffers and the vec's capacity for adopted vecs.
    ///
    /// # Safety
    ///
    /// `self` must be a live heap owner.
    #[inline]
    pub(crate) unsafe fn usable_capacity(self) -> usize {
        // SAFETY: guaranteed by the caller.
        unsafe { self.heap().as_ref().alloc_size }
    }

    /// Returns the current refcount for internal tests.
    ///
    /// # Safety
    ///
    /// `self` must be empty or have a live reference owned by the caller.
    #[cfg(all(test, not(feature = "loom")))]
    pub(crate) unsafe fn refcount(self) -> Option<usize> {
        if self.is_empty() {
            return None;
        }
        // SAFETY: non-empty owners have a valid refcount.
        Some(unsafe { self.refs() }.load(Ordering::Acquire))
    }

    /// Loom-only Relaxed refcount probe.
    ///
    /// Models spin on this (with yields) to observe another handle's
    /// decrement without creating a happens-before edge: the probe must not
    /// synchronize, or it would mask a weakened ordering in the drop path
    /// under test.
    ///
    /// # Safety
    ///
    /// `self` must be non-empty with a live reference owned by the caller.
    #[cfg(all(test, feature = "loom"))]
    pub(crate) unsafe fn refcount_relaxed(self) -> usize {
        // SAFETY: non-empty owners have a valid refcount.
        unsafe { self.refs() }.load(Ordering::Relaxed)
    }
}

/// Owner record for native heap allocations.
///
/// The record lives in its own small allocation so the data allocation keeps
/// exactly the layout it was created with, which the record stores instead of
/// deriving: the caller's size and alignment for native buffers, and
/// `(capacity, align = 1)` for adopted `Vec<u8>`s, so `dealloc` always uses
/// the original layout.
#[repr(C)]
pub(crate) struct HeapOwner {
    /// Shared refcount. Must stay at offset 0 (see [`OwnerRef::refs`]).
    refs: AtomicUsize,
    /// Base address of the usable data region.
    data_base: NonNull<u8>,
    /// Exact size the data allocation was created with.
    alloc_size: usize,
    /// Exact alignment the data allocation was created with.
    alloc_align: usize,
}

impl HeapOwner {
    /// Allocates a buffer of exactly `capacity` bytes at `alignment` with its
    /// owner record in a separate allocation, and returns the data pointer and
    /// the owner.
    ///
    /// # Panics
    ///
    /// Panics if `capacity == 0`, if `alignment` is not a power of two, or if
    /// the layout exceeds `Layout`'s `isize::MAX` bound.
    #[inline]
    pub(crate) fn allocate_aligned(
        capacity: usize,
        alignment: usize,
        zeroed: bool,
    ) -> (NonNull<u8>, OwnerRef) {
        assert!(capacity > 0, "capacity must be greater than zero");
        let layout = Layout::from_size_align(capacity, alignment)
            .expect("alignment must be a power of two and the size must fit a layout");
        let ptr = if zeroed {
            // SAFETY: layout is valid and non-zero sized.
            unsafe { alloc_zeroed(layout) }
        } else {
            // SAFETY: layout is valid and non-zero sized.
            unsafe { alloc(layout) }
        };
        let data = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        // SAFETY: `data` was allocated above with `layout`.
        let owner = unsafe { Self::record(data, layout) };
        (data, owner)
    }

    /// Allocates the owner record for a data allocation.
    ///
    /// If the record cannot be allocated, the data allocation is released
    /// before the allocation error is raised, so a non-aborting error hook
    /// leaks nothing.
    ///
    /// # Safety
    ///
    /// `data` must be a live allocation created with `layout` by the global
    /// allocator, owned by the caller.
    #[inline]
    unsafe fn record(data: NonNull<u8>, layout: Layout) -> OwnerRef {
        // SAFETY: the record layout is valid and non-zero sized.
        let record = unsafe { alloc(Layout::new::<Self>()) }.cast::<Self>();
        let Some(record) = NonNull::new(record) else {
            // SAFETY: guaranteed by the caller.
            unsafe { dealloc(data.as_ptr(), layout) };
            handle_alloc_error(Layout::new::<Self>());
        };
        // SAFETY: `record` is a fresh allocation sized and aligned for `Self`.
        unsafe {
            record.as_ptr().write(Self {
                refs: AtomicUsize::new(1),
                data_base: data,
                alloc_size: layout.size(),
                alloc_align: layout.align(),
            });
            OwnerRef::from_heap(record)
        }
    }

    /// Adopts `vec`'s allocation as a native heap buffer without copying.
    ///
    /// The vec is dismantled and its allocation becomes the data allocation,
    /// recorded with the layout `Vec<u8>` created it with, `(capacity,
    /// align = 1)`. Returns the data pointer, the readable length, the usable
    /// capacity (the vec's capacity), and the owner.
    ///
    /// # Panics
    ///
    /// Panics if the vec has no allocation (`capacity() == 0`).
    pub(crate) fn adopt_vec(vec: Vec<u8>) -> (NonNull<u8>, usize, usize, OwnerRef) {
        let mut vec = ManuallyDrop::new(vec);
        let len = vec.len();
        let cap = vec.capacity();
        assert!(cap > 0, "capacity must be greater than zero");
        let layout = Layout::array::<u8>(cap).expect("vec capacity must fit a layout");
        // SAFETY: a vec with non-zero capacity owns a live allocation.
        let data = unsafe { NonNull::new_unchecked(vec.as_mut_ptr()) };
        // SAFETY: `Vec<u8>` created the allocation with this layout through
        // the global allocator, and the dismantled vec no longer frees it.
        let owner = unsafe { Self::record(data, layout) };
        (data, len, cap, owner)
    }

    /// Releases a unique heap owner.
    ///
    /// The stored fields recover the exact data layout; the record is freed
    /// after the data as its own allocation.
    ///
    /// # Safety
    ///
    /// No other handle may reference this allocation.
    #[inline]
    unsafe fn release(header: NonNull<Self>) {
        // SAFETY: guaranteed by the caller.
        let header_ref = unsafe { header.as_ref() };
        assert_eq!(header_ref.refs.load(Ordering::Relaxed), 1);
        let data = header_ref.data_base;
        // SAFETY: `(alloc_size, alloc_align)` is exactly the layout the
        // allocation was created with (a heap-owner invariant).
        let layout = unsafe {
            Layout::from_size_align_unchecked(header_ref.alloc_size, header_ref.alloc_align)
        };
        // SAFETY: data/layout came from the global allocator, the record is
        // its own allocation with its type's layout, and no handle references
        // either anymore.
        unsafe {
            dealloc(data.as_ptr(), layout);
            dealloc(header.as_ptr().cast(), Layout::new::<Self>());
        }
    }
}

/// External owner for caller-supplied [`Bytes`].
///
/// Release is a plain box drop, which drops the inner `Bytes` exactly once.
#[repr(C)]
struct ExternalOwner {
    /// Shared refcount. Must stay at offset 0 (see [`OwnerRef::refs`]).
    refs: AtomicUsize,
    /// The payload owner. The handle view `ptr..ptr+len` always lies within
    /// this value's range (required by the `slice_ref` conversion fast path).
    bytes: Bytes,
}

impl ExternalOwner {
    fn from_bytes(bytes: Bytes) -> (NonNull<u8>, usize, OwnerRef) {
        // Box the owner first, then derive the handle pointer from the `Bytes`
        // in its final location inside the box. This keeps the provenance
        // chain trivially clean: the pointer the handle uses is derived from
        // the exact value that owns the payload for the buffer's whole life.
        let owner = Box::new(Self {
            refs: AtomicUsize::new(1),
            bytes,
        });
        let ptr = NonNull::new(owner.bytes.as_ptr().cast_mut())
            .expect("non-empty Bytes has non-null data");
        let len = owner.bytes.len();
        let owner = NonNull::from(Box::leak(owner));
        // SAFETY: the pointer came from `Box::leak` and is uniquely owned here.
        let owner = unsafe { OwnerRef::from_external(owner) };
        (ptr, len, owner)
    }

    /// Releases a unique external owner.
    ///
    /// # Safety
    ///
    /// `owner` must come from `Box::leak` and no other handle may reference it.
    #[inline]
    unsafe fn release(owner: NonNull<Self>) {
        // SAFETY: guaranteed by the caller.
        let owner_ref = unsafe { owner.as_ref() };
        assert_eq!(owner_ref.refs.load(Ordering::Relaxed), 1);
        // SAFETY: the owner box was leaked at construction. Dropping it here
        // drops the inner `Bytes` exactly once.
        drop(unsafe { Box::from_raw(owner.as_ptr()) });
    }
}

#[cfg(all(test, not(feature = "loom")))]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::*;

    /// A page-sized alignment for the aligned-allocation tests.
    const PAGE_ALIGNMENT: usize = 4096;

    #[test]
    fn test_heap_allocation_is_exact_and_aligned() {
        let page = PAGE_ALIGNMENT;
        let (data, owner) = HeapOwner::allocate_aligned(4096, page, false);
        assert!((data.as_ptr() as usize).is_multiple_of(page));

        // SAFETY: owner was just allocated and is live.
        let header = unsafe { owner.heap() };
        assert!((header.as_ptr() as usize).is_multiple_of(align_of::<HeapOwner>()));
        // The record is its own allocation, outside the data region.
        let data_addr = data.as_ptr() as usize;
        let header_addr = header.as_ptr() as usize;
        assert!(header_addr < data_addr || header_addr >= data_addr + 4096);
        // SAFETY: owner is unique and live.
        assert_eq!(unsafe { owner.data_base() }, data);
        // SAFETY: owner is unique and live.
        assert_eq!(unsafe { owner.usable_capacity() }, 4096);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
    }

    #[test]
    fn test_heap_zeroed_only_exposes_usable_region() {
        let (data, owner) = HeapOwner::allocate_aligned(64, PAGE_ALIGNMENT, true);
        // SAFETY: data points at a zeroed usable region of length 64.
        let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr(), 64) };
        assert_eq!(bytes, &[0u8; 64]);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
    }

    #[test]
    fn test_heap_capacity_is_not_rounded() {
        let (_, owner) = HeapOwner::allocate_aligned(10, 1, false);
        // SAFETY: owner is unique and live.
        assert_eq!(unsafe { owner.usable_capacity() }, 10);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
    }

    #[test]
    #[should_panic(expected = "alignment must be a power of two and the size must fit a layout")]
    fn test_allocation_rejects_isize_max_overflow() {
        let _ = HeapOwner::allocate_aligned(isize::MAX as usize, 64, false);
    }

    #[test]
    #[should_panic(expected = "alignment must be a power of two and the size must fit a layout")]
    fn test_allocation_rejects_non_power_of_two_alignment() {
        let _ = HeapOwner::allocate_aligned(64, 3, false);
    }

    #[test]
    fn test_external_owner_refcount() {
        let (_, len, owner) = OwnerRef::from_bytes(Bytes::from_static(b"abc"));
        assert_eq!(len, 3);
        assert!(owner.is_external());
        // SAFETY: owner is live.
        assert_eq!(unsafe { owner.refcount() }, Some(1));
        // SAFETY: owner is live.
        unsafe { owner.clone_shared() };
        // SAFETY: owner is live.
        assert_eq!(unsafe { owner.refcount() }, Some(2));
        // SAFETY: owner is live.
        unsafe { owner.drop_shared() };
        // SAFETY: owner is live after one shared drop.
        assert_eq!(unsafe { owner.refcount() }, Some(1));
        // SAFETY: final drop releases the owner.
        unsafe { owner.drop_shared() };
    }

    #[test]
    fn test_external_owner_keeps_inner_bytes_alive() {
        let payload = Bytes::from(vec![7u8; 32]);
        let inner_ptr = payload.as_ptr();
        let (ptr, len, owner) = OwnerRef::from_bytes(payload);
        assert_eq!(ptr.as_ptr().cast_const(), inner_ptr);
        assert_eq!(len, 32);
        // SAFETY: owner is live and external.
        let inner = unsafe { owner.external_bytes() };
        assert_eq!(inner.as_ref(), &[7u8; 32]);
        // SAFETY: final drop releases the owner and the inner Bytes.
        unsafe { owner.drop_shared() };
    }

    #[test]
    fn test_empty_vec_has_no_owner() {
        let (_, len, owner) = OwnerRef::from_vec(Vec::new());
        assert_eq!(len, 0);
        assert!(owner.is_empty());
        // SAFETY: empty owners have no refcount to read.
        assert_eq!(unsafe { owner.refcount() }, None);
    }

    #[test]
    fn test_empty_bytes_has_no_owner() {
        let (_, len, owner) = OwnerRef::from_bytes(Bytes::new());
        assert_eq!(len, 0);
        assert!(owner.is_empty());
    }

    #[test]
    fn test_vec_adoption_keeps_allocation_and_capacity() {
        // The vec's own allocation becomes the data allocation with every byte
        // of its capacity usable; the record lives outside it.
        let mut vec = Vec::with_capacity(256);
        vec.extend_from_slice(&[1u8, 2, 3, 4]);
        let base_addr = vec.as_ptr() as usize;
        let cap = vec.capacity();
        let (ptr, len, owner) = OwnerRef::from_vec(vec);
        assert_eq!(ptr.as_ptr() as usize, base_addr);
        assert_eq!(len, 4);
        assert!(!owner.is_external());
        assert!(!owner.is_empty());
        // SAFETY: owner is unique and live.
        assert_eq!(unsafe { owner.data_base() }.as_ptr() as usize, base_addr);
        // SAFETY: owner is unique and live.
        assert_eq!(unsafe { owner.usable_capacity() }, cap);
        // SAFETY: owner is unique and live.
        let record_addr = unsafe { owner.heap() }.as_ptr() as usize;
        assert!(record_addr < base_addr || record_addr >= base_addr + cap);
        // SAFETY: ptr points at `len` readable bytes kept alive by the owner.
        let payload = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) };
        assert_eq!(payload, &[1, 2, 3, 4]);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
    }

    #[test]
    fn test_vec_adoption_exact_size_is_native() {
        // `len == cap` adopts like any other vec: no spare room is needed.
        let vec = vec![5u8, 6, 7];
        assert_eq!(vec.len(), vec.capacity());
        let base_addr = vec.as_ptr() as usize;
        let (ptr, len, owner) = OwnerRef::from_vec(vec);
        assert_eq!(ptr.as_ptr() as usize, base_addr);
        assert_eq!(len, 3);
        assert!(!owner.is_external());
        // SAFETY: owner is unique and live.
        assert_eq!(unsafe { owner.usable_capacity() }, 3);
        // SAFETY: ptr points at `len` readable bytes kept alive by the owner.
        let payload = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) };
        assert_eq!(payload, &[5, 6, 7]);
        // SAFETY: final drop releases the owner and the adopted allocation.
        unsafe { owner.drop_shared() };
    }

    #[test]
    fn test_adopt_vec_with_capacity_but_no_length() {
        // A mutable adoption keeps an allocation whose readable prefix is
        // empty, exactly as `Vec::with_capacity` created it.
        let vec: Vec<u8> = Vec::with_capacity(64);
        let base_addr = vec.as_ptr() as usize;
        let (ptr, len, cap, owner) = HeapOwner::adopt_vec(vec);
        assert_eq!(ptr.as_ptr() as usize, base_addr);
        assert_eq!(len, 0);
        assert_eq!(cap, 64);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
    }

    #[test]
    #[should_panic(expected = "capacity must be greater than zero")]
    fn test_adopt_vec_rejects_unallocated_vec() {
        let _ = HeapOwner::adopt_vec(Vec::new());
    }

    #[test]
    fn test_heap_owner_shared_clone_and_drop() {
        let (_, owner) = HeapOwner::allocate_aligned(64, 1, false);
        // SAFETY: owner is live.
        unsafe { owner.clone_shared() };
        // SAFETY: owner is live.
        assert_eq!(unsafe { owner.refcount() }, Some(2));
        // SAFETY: owner is live.
        assert!(!unsafe { owner.is_unique() });
        // SAFETY: owner is live.
        unsafe { owner.drop_shared() };
        // SAFETY: owner is live.
        assert!(unsafe { owner.is_unique() });
        // SAFETY: final drop releases the owner.
        unsafe { owner.drop_shared() };
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use loom::{
        cell::UnsafeCell,
        sync::{Arc, atomic::AtomicUsize},
        thread,
    };

    // Models the owner refcount protocol under true concurrency. The
    // restore-sentinel branch in `drop_shared_race_final` (a decrement that hits
    // zero because another thread decremented between this thread's Acquire
    // load and its fetch_sub) is unreachable single-threaded, so loom is the
    // only coverage it has.

    // External payload that counts how many times it is released.
    struct Tracker(Arc<AtomicUsize>);

    impl Drop for Tracker {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl AsRef<[u8]> for Tracker {
        fn as_ref(&self) -> &[u8] {
            &[1, 2, 3]
        }
    }

    #[test]
    fn shared_clone_drop_releases_exactly_once() {
        loom::model(|| {
            let released = Arc::new(AtomicUsize::new(0));
            let bytes = Bytes::from_owner(Tracker(released.clone()));
            let (_, len, owner) = OwnerRef::from_bytes(bytes);
            assert_eq!(len, 3);

            // Three references: this thread plus two spawned droppers.
            // SAFETY: `owner` is live with one reference owned here.
            unsafe { owner.clone_shared() };
            // SAFETY: as above.
            unsafe { owner.clone_shared() };

            let t1 = thread::spawn(move || {
                // SAFETY: this thread owns one reference.
                unsafe { owner.drop_shared() };
            });
            let t2 = thread::spawn(move || {
                // SAFETY: this thread owns one reference.
                unsafe { owner.drop_shared() };
            });
            // SAFETY: the main thread owns the remaining reference.
            unsafe { owner.drop_shared() };
            t1.join().unwrap();
            t2.join().unwrap();

            // Exactly one drop released the payload, whichever interleaving
            // won the final-owner race.
            assert_eq!(released.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn clone_races_concurrent_drop() {
        loom::model(|| {
            let released = Arc::new(AtomicUsize::new(0));
            let bytes = Bytes::from_owner(Tracker(released.clone()));
            let (_, _, owner) = OwnerRef::from_bytes(bytes);

            // Two handles: this thread and the spawned thread. The spawned
            // thread clones from its own live handle while this thread drops,
            // racing clone_shared's Relaxed fetch_add against the drop
            // protocol's Acquire load and Release decrement.
            // SAFETY: `owner` is live with one reference owned here.
            unsafe { owner.clone_shared() };
            let t1 = thread::spawn(move || {
                // SAFETY: this thread owns one live reference to clone from.
                unsafe { owner.clone_shared() };
                // SAFETY: this thread owns two references and drops both.
                unsafe { owner.drop_shared() };
                // SAFETY: as above.
                unsafe { owner.drop_shared() };
            });
            // SAFETY: the main thread owns one reference.
            unsafe { owner.drop_shared() };
            t1.join().unwrap();

            assert_eq!(released.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn is_unique_races_final_drop() {
        loom::model(|| {
            let released = Arc::new(AtomicUsize::new(0));
            let bytes = Bytes::from_owner(Tracker(released.clone()));
            let (_, _, owner) = OwnerRef::from_bytes(bytes);
            // Tracked stand-in for the payload state a caller would mutate
            // after observing uniqueness (the try_into_mut gate).
            let payload = Arc::new(UnsafeCell::new(0usize));

            // Two handles: this thread checks uniqueness while the other
            // drops. Observing unique must mean the other drop fully
            // happened-before (its Release decrement pairs with is_unique's
            // Acquire load), so the dropper's payload write must be visible
            // and race-free here. Weakening the is_unique load to Relaxed
            // makes loom report a data race on the payload cell.
            //
            // The uniqueness check spins with yields (rather than branching
            // on one load) so every explored execution eventually observes
            // the drop: loom advances yielding loads past stale stores, which
            // keeps the post-uniqueness assertions reached in every run.
            // SAFETY: `owner` is live with one reference owned here.
            unsafe { owner.clone_shared() };
            let t1 = thread::spawn({
                let payload = payload.clone();
                move || {
                    // SAFETY: this thread owns one reference, and the write is
                    // sequenced before its drop.
                    payload.with_mut(|cell| unsafe { *cell = 1 });
                    // SAFETY: this thread owns one reference.
                    unsafe { owner.drop_shared() };
                }
            });
            loop {
                // SAFETY: the main thread owns one reference.
                if unsafe { owner.is_unique() } {
                    // The other handle is gone: its payload write must be
                    // visible and the payload must still be live.
                    // SAFETY: uniqueness transfers exclusive payload access.
                    payload.with(|cell| assert_eq!(unsafe { *cell }, 1));
                    assert_eq!(released.load(Ordering::SeqCst), 0);
                    break;
                }
                thread::yield_now();
            }
            // SAFETY: the main thread owns the remaining reference.
            unsafe { owner.drop_shared() };
            t1.join().unwrap();

            assert_eq!(released.load(Ordering::SeqCst), 1);
        });
    }

    /// Tracked stand-in for the payload state the freeing side touches
    /// (deallocation or reuse).
    struct PayloadCell(UnsafeCell<usize>);

    // SAFETY: cross-thread access is what the cell exists to check. Loom
    // tracks every access made through `UnsafeCell::with`/`with_mut`.
    unsafe impl Send for PayloadCell {}
    // SAFETY: as above.
    unsafe impl Sync for PayloadCell {}

    // Payload whose release reads the tracked cell. The reader is whichever
    // thread performs the final release, so the read is race-free only if
    // every other handle's payload writes happen-before that release:
    // exactly the edges the drop-side Acquire load and the race-final Acquire
    // fence provide.
    struct TrackedPayload {
        payload: Arc<PayloadCell>,
        released: Arc<AtomicUsize>,
    }

    impl Drop for TrackedPayload {
        fn drop(&mut self) {
            self.payload.0.with(|cell| {
                // SAFETY: the refcount protocol grants the final release
                // exclusive payload access. Loom reports a data race here if
                // a weakened ordering lets the release run unsynchronized
                // with another handle's write.
                assert_eq!(unsafe { *cell }, 1);
            });
            self.released.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl AsRef<[u8]> for TrackedPayload {
        fn as_ref(&self) -> &[u8] {
            &[1, 2, 3]
        }
    }

    #[test]
    fn payload_writes_happen_before_race_final_release() {
        loom::model(|| {
            let released = Arc::new(AtomicUsize::new(0));
            let payload = Arc::new(PayloadCell(UnsafeCell::new(0)));
            let bytes = Bytes::from_owner(TrackedPayload {
                payload: payload.clone(),
                released: released.clone(),
            });
            let (_, _, owner) = OwnerRef::from_bytes(bytes);

            // Two handles: the spawned thread writes the payload through its
            // handle and drops. The main thread only drops. In the explored
            // executions where the decrements race (both fast-path loads see
            // a shared count and the main thread's decrement lands last), the
            // main thread frees through `drop_shared_race_final`, and the
            // tracked read inside TrackedPayload::drop must be ordered after
            // the writer's access. Weakening the race-final Acquire fence
            // makes loom report a data race on the payload cell. (The
            // cross-thread fast path is not explorable here: loom does not
            // advance a single load past a causally-unseen decrement, so that
            // edge is pinned by the probe-driven model below.)
            // SAFETY: `owner` is live with one reference owned here.
            unsafe { owner.clone_shared() };
            let t1 = thread::spawn({
                move || {
                    // SAFETY: this thread's handle keeps the payload alive.
                    // The write is sequenced before its drop.
                    payload.0.with_mut(|cell| unsafe { *cell = 1 });
                    // SAFETY: this thread owns one reference.
                    unsafe { owner.drop_shared() };
                }
            });
            // SAFETY: the main thread owns the remaining reference.
            unsafe { owner.drop_shared() };
            t1.join().unwrap();

            assert_eq!(released.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn payload_writes_happen_before_fast_path_release() {
        loom::model(|| {
            let released = Arc::new(AtomicUsize::new(0));
            let payload = Arc::new(PayloadCell(UnsafeCell::new(0)));
            let bytes = Bytes::from_owner(TrackedPayload {
                payload: payload.clone(),
                released: released.clone(),
            });
            let (_, _, owner) = OwnerRef::from_bytes(bytes);

            // Two handles: the spawned thread writes the payload through its
            // handle and drops. The main thread waits until the decrement is
            // visible through a Relaxed probe (no happens-before edge, and the
            // yields let loom advance the probe past stale values), so its
            // drop deterministically takes the fast path and frees. The only
            // ordering protecting the tracked read inside TrackedPayload::drop
            // is then the fast-path Acquire load: downgrading it to Relaxed
            // makes loom report a data race on the payload cell.
            // SAFETY: `owner` is live with one reference owned here.
            unsafe { owner.clone_shared() };
            let t1 = thread::spawn({
                move || {
                    // SAFETY: this thread's handle keeps the payload alive.
                    // The write is sequenced before its drop.
                    payload.0.with_mut(|cell| unsafe { *cell = 1 });
                    // SAFETY: this thread owns one reference.
                    unsafe { owner.drop_shared() };
                }
            });
            // SAFETY: the main thread owns the remaining reference.
            while unsafe { owner.refcount_relaxed() } != 1 {
                thread::yield_now();
            }
            // SAFETY: as above. Observing 1 makes this the final owner, and
            // per-location coherence keeps the fast-path load at 1.
            unsafe { owner.drop_shared() };
            t1.join().unwrap();

            assert_eq!(released.load(Ordering::SeqCst), 1);
        });
    }
}
