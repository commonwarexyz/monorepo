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
//! `bytes::Buf` and `bytes::BufMut` methods read only those handle fields. They
//! do not match on allocation kind and do not dispatch through a vtable. The
//! allocation kind is needed only for lifecycle operations such as clone, drop,
//! `freeze`, and `try_into_mut`, so that metadata is stored in an owner header
//! outside the hot cursor arithmetic.
//!
//! # Owner model
//!
//! [`OwnerRef`] is a tagged pointer. The value is either zero (no owner) or a
//! pointer to an owner struct with one of three kinds encoded in the low two
//! bits:
//!
//! ```text
//! 0 (entire value)        EMPTY     no owner; empty views and 'static slices
//! header ptr | 0b01       HEAP      HeapHeader; native aligned allocations,
//!                                   adopted vecs, and front-block mutables
//! slot ptr   | 0b10       POOLED    PooledSlot side-table entry
//! owner ptr  | 0b11       EXTERNAL  boxed ExternalOwner holding a Bytes
//! ```
//!
//! Only two tag bits are used because every owner type starts with an
//! `AtomicUsize`, which is guaranteed just 4-byte alignment on 32-bit targets
//! such as wasm32 (const-asserted below).
//!
//! Every owner type stores its shared refcount at offset 0 (const-asserted),
//! so refcount operations read directly through the untagged pointer with no
//! kind dispatch. The kind is examined only on final release.
//!
//! # Allocation layouts
//!
//! Native heap allocations place the owner header at the tail of the same
//! allocation that stores data when the requested data alignment is larger than
//! the header's own alignment:
//!
//! ```text
//! [ usable data bytes ............ ][ padding ][ owner header ]
//! ^                                            ^
//! data base (alignment preserved)              OwnerRef target
//! ```
//!
//! Pooled allocations keep their owner metadata out of the data allocation.
//! Each size class owns a cache-line-padded side table with one [`PooledSlot`]
//! per possible tracked buffer:
//!
//! ```text
//! SizeClass slots: [ refs | lease | data | capacity | slot | routing ... ]
//!                    ^
//!                    OwnerRef target
//!
//! data allocation:  [ usable data bytes ............ ]
//!                    ^
//!                    data base
//! ```
//!
//! The freelist bitmap records which slots are globally available. The slot
//! entry is the single state record for refcounting, class liveness, data
//! pointer, and return routing.
//!
//! Low-alignment mutable heap allocations use the v2 front-block layout
//! instead:
//!
//! ```text
//! [ reserved HeapHeader ][ usable data bytes ............ ]
//! ^                       ^
//! OwnerRef target         data base
//! ```
//!
//! The front header is reserved but not initialized while the allocation is
//! held by an `IoBufMut`. Mutable drop can deallocate directly from
//! `owner_base`, `ptr`, and `cap` because `ptr + cap` remains the allocation
//! end even after `Buf::advance`. `freeze` initializes the header before the
//! owner is shared by an `IoBuf`. This avoids writing metadata for the common
//! direct alloc/drop path while preserving the same initialized owner shape for
//! immutable buffers.
//!
//! The usable data begins at the allocation base so alignment requested for
//! I/O is preserved on high-alignment allocations. A sliced or advanced handle
//! may point into the usable region, so drop and `try_into_mut` recover the
//! original base from the header, not from the handle's current `ptr`.
//!
//! `From<Vec<u8>>` adopts the vec's own allocation as a native heap buffer
//! when its spare capacity can host the header. The header is placed at the
//! highest header-aligned address that fits:
//!
//! ```text
//! [ len readable ][ writable ......... ][ header ][ waste 0..ALIGN-1 ]
//! ^ base                                ^ header_addr =
//!                                         round_down(base + cap - HDR, ALIGN)
//! ```
//!
//! Adoption succeeds iff `header_addr >= base + len`. The result is a fully
//! native heap buffer: zero copies, zero extra allocations, and mutable
//! recovery through `try_into_mut`. Because a `Vec<u8>` allocation has layout
//! `(cap, align = 1)` rather than the canonical aligned layout, [`HeapHeader`]
//! stores the exact allocation layout instead of deriving it on release.
//!
//! `Bytes` values (and vecs whose spare capacity cannot host the header) are
//! owned externally: a small boxed [`ExternalOwner`] holds the `Bytes`, our
//! refcount fronts it, and the handle points directly into the payload:
//!
//! ```text
//! IoBuf.ptr ------------------------------v
//! [ refs | Bytes ]        [ payload bytes ............ ]
//! ^ OwnerRef target        ^ kept alive by the inner Bytes
//! ```
//!
//! The inner `Bytes` refcount is touched exactly twice in the buffer's life:
//! moved in at construction and dropped at final release. Clones, slices, and
//! drops of the `IoBuf` touch only our refcount.
//!
//! # Refcount state machine
//!
//! The refcount uses `1` as the reusable sentinel, so final release never has
//! to write zero and pooled buffers re-enter the pool checkout-ready:
//!
//! ```text
//! state                                refs
//! ---------------------------------   -------------------
//! parked in pool (pooled only)         1
//! checked out mutable (IoBufMut)       1 (never touched)
//! single immutable owner (IoBuf)       1
//! N shared immutable owners            N
//! ```
//!
//! `IoBufMut` never touches the refcount: mutable handles are unique by
//! construction and stay at the sentinel until `freeze` hands the owner word
//! to an immutable `IoBuf`.

use crate::iobuf::pool::{BufferPoolThreadCache, SizeClassLease};
use bytes::Bytes;
use std::{
    alloc::{alloc, alloc_zeroed, dealloc, handle_alloc_error, Layout},
    mem::{align_of, offset_of, size_of, ManuallyDrop, MaybeUninit},
    ptr::{addr_of_mut, NonNull},
    sync::atomic::Ordering,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::atomic::{fence, AtomicUsize};
    } else {
        use std::sync::atomic::{fence, AtomicUsize};
    }
}

const OWNER_EMPTY: usize = 0b00;
const OWNER_HEAP: usize = 0b01;
const OWNER_POOLED: usize = 0b10;
const OWNER_EXTERNAL: usize = 0b11;
const OWNER_TAG_MASK: usize = 0b11;

/// Refcount ceiling shared with `Arc` and `bytes`.
///
/// A refcount above `isize::MAX` can only result from a leak loop (`mem::forget`
/// in a cycle); allowing it to wrap would turn into use-after-free, so
/// [`OwnerRef::clone_shared`] aborts instead.
const MAX_REFCOUNT: usize = isize::MAX as usize;

// The low two pointer bits are usable as the kind tag only if every owner
// type is at least 4-byte aligned, including on 32-bit targets where
// `AtomicUsize` is 4 bytes.
const _: () = assert!(align_of::<HeapHeader>() >= 4);
const _: () = assert!(align_of::<PooledSlot>() >= 4);
const _: () = assert!(align_of::<ExternalOwner>() >= 4);
const _: () = assert!(size_of::<HeapHeader>().is_multiple_of(align_of::<HeapHeader>()));

// `OwnerRef::refs` reads the refcount directly through the untagged pointer,
// which is only sound if every owner type stores it at offset 0.
const _: () = assert!(offset_of!(HeapHeader, refs) == 0);
const _: () = assert!(offset_of!(PooledSlot, refs) == 0);
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
pub(crate) struct OwnerRef(usize);

impl OwnerRef {
    #[inline(always)]
    pub(crate) const fn empty() -> Self {
        Self(OWNER_EMPTY)
    }

    #[inline(always)]
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == OWNER_EMPTY
    }

    /// Returns the kind tag stored in the low pointer bits.
    #[inline(always)]
    const fn tag(self) -> usize {
        self.0 & OWNER_TAG_MASK
    }

    #[inline(always)]
    pub(crate) const fn is_pooled(self) -> bool {
        self.tag() == OWNER_POOLED
    }

    #[inline(always)]
    pub(crate) const fn is_external(self) -> bool {
        self.tag() == OWNER_EXTERNAL
    }

    /// Builds an owner ref from an owner pointer and its kind tag.
    ///
    /// The pointer's provenance is exposed so [`Self::untag`] can recover a
    /// usable pointer from the stored address. Construction reads no bytes
    /// through `ptr`, so the pointed-to header may be uninitialized.
    #[inline(always)]
    fn from_tagged<T>(ptr: NonNull<T>, tag: usize) -> Self {
        debug_assert_eq!(ptr.as_ptr().addr() & OWNER_TAG_MASK, 0);
        Self(ptr.as_ptr().expose_provenance() | tag)
    }

    /// Recovers the untagged owner pointer.
    ///
    /// Restores the provenance exposed by [`Self::from_tagged`].
    ///
    /// # Safety
    ///
    /// `self` must be a live non-empty owner whose pointer targets a `T`.
    #[inline(always)]
    unsafe fn untag<T>(self) -> NonNull<T> {
        debug_assert!(!self.is_empty());
        let ptr = std::ptr::with_exposed_provenance_mut::<T>(self.0 & !OWNER_TAG_MASK);
        // SAFETY: non-empty owner refs are built from non-null pointers, and
        // masking the tag bits cannot zero a heap/box/slot address.
        unsafe { NonNull::new_unchecked(ptr) }
    }

    /// Creates a heap owner ref from a [`HeapHeader`] pointer.
    ///
    /// # Safety
    ///
    /// `header` must point to the [`HeapHeader`] of an allocation owned by this
    /// owner ref, with its low tag bits zero. The contents may be uninitialized
    /// (for example a reserved front block before `freeze`); they must be
    /// initialized before any clone, drop, or freeze that reads them.
    #[inline(always)]
    unsafe fn from_heap(header: NonNull<HeapHeader>) -> Self {
        Self::from_tagged(header, OWNER_HEAP)
    }

    /// Creates a pooled owner ref from a side-table slot pointer.
    ///
    /// # Safety
    ///
    /// `slot` must point to a live [`PooledSlot`] whose low tag bits are zero
    /// and whose lease is initialized.
    #[inline(always)]
    pub(crate) unsafe fn from_pooled(slot: NonNull<PooledSlot>) -> Self {
        Self::from_tagged(slot, OWNER_POOLED)
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

    /// Returns the heap header for a heap owner (native, adopted, or front).
    ///
    /// # Safety
    ///
    /// `self` must be a live heap owner.
    #[inline(always)]
    unsafe fn heap(self) -> NonNull<HeapHeader> {
        debug_assert_eq!(self.tag(), OWNER_HEAP);
        // SAFETY: a live heap owner's address targets a `HeapHeader`.
        unsafe { self.untag() }
    }

    /// Returns the side-table slot for a pooled owner.
    ///
    /// # Safety
    ///
    /// `self` must be a live pooled owner.
    #[inline(always)]
    unsafe fn pooled(self) -> NonNull<PooledSlot> {
        debug_assert!(self.is_pooled());
        // SAFETY: a live pooled owner's address targets a `PooledSlot`.
        unsafe { self.untag() }
    }

    /// Returns the external owner box pointer.
    ///
    /// # Safety
    ///
    /// `self` must be a live external owner.
    #[inline(always)]
    unsafe fn external(self) -> NonNull<ExternalOwner> {
        debug_assert!(self.is_external());
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
    /// valid while the owner is live; the `'static` lifetime is a convenience
    /// the caller must bound.
    #[inline(always)]
    unsafe fn refs(self) -> &'static AtomicUsize {
        debug_assert!(!self.is_empty());
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
    /// The refcount uses `1` as the reusable sentinel (see the module docs),
    /// so the unshared fast path is a single Acquire load followed by release:
    /// no read-modify-write. Shared owners pay one inline Release decrement.
    /// Only the rare race where another drop reaches the sentinel between the
    /// load and the decrement is outlined in [`Self::drop_shared_race_final`].
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
        debug_assert!(old >= 1);
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
        // Restore the sentinel before releasing. No other handle exists, so
        // Relaxed is sufficient; pooled reuse synchronizes through the
        // freelist's own Release/Acquire bit transitions.
        refs.store(1, Ordering::Relaxed);
        // SAFETY: guaranteed by the caller.
        unsafe { self.release_unique() };
    }

    /// Releases a uniquely-owned allocation.
    ///
    /// Only the pooled arm is inlined: pooled alloc -> fill -> freeze -> drop
    /// is the lifecycle hot loop, and it feeds directly into the thread-cache
    /// push fast path. The aligned and external arms are outlined in
    /// [`release_unique_cold`] so every `IoBuf` drop site does not instantiate
    /// dealloc and box-drop code twice (fast path and race branch).
    ///
    /// # Safety
    ///
    /// No other handle may reference this allocation. Pooled owners must have
    /// an initialized lease.
    #[inline(always)]
    pub(crate) unsafe fn release_unique(self) {
        if self.tag() == OWNER_POOLED {
            // SAFETY: unique pooled owner with initialized lease.
            unsafe { release_pooled(self.pooled()) };
            return;
        }
        // SAFETY: same contract as this method.
        unsafe { release_unique_cold(self) };
    }

    /// Releases a uniquely-owned mutable allocation.
    ///
    /// The pooled arm comes first because thread-local pool alloc/drop is the
    /// hottest mutable lifecycle path. Front-heap mutable owners are also kept
    /// inline: they can deallocate from the tagged owner base plus the
    /// handle's current `ptr` and `cap`, without reading or initializing the
    /// reserved header. Mutable handles are never external-backed (`Bytes`
    /// cannot back mutation), so no external arm exists here.
    ///
    /// # Safety
    ///
    /// This must be called only for a uniquely-owned mutable handle.
    #[inline(always)]
    pub(crate) unsafe fn release_unique_mut_at(self, ptr: NonNull<u8>, cap: usize) {
        let tag = self.tag();
        if tag == OWNER_POOLED {
            // SAFETY: unique pooled owner with initialized lease.
            unsafe { release_pooled(self.pooled()) };
            return;
        }
        if tag == OWNER_EMPTY {
            return;
        }
        debug_assert_eq!(tag, OWNER_HEAP, "IoBufMut owner is never external");
        if self.is_front_heap_for_mut(ptr) {
            // SAFETY: front heap owners are allocated with `front_heap_layout`
            // and `ptr + cap` is the allocation end.
            unsafe { release_front_heap(self.heap(), ptr, cap) };
            return;
        }
        // SAFETY: unique tail-header heap owner.
        unsafe { release_heap(self.heap()) };
    }

    /// Initializes a reserved front heap header before sharing the owner.
    ///
    /// Eager tail headers are already initialized. Front headers can be
    /// initialized more than once while uniquely mutable (for example after
    /// `try_into_mut` and another `freeze`); rewriting the header is harmless
    /// because it contains no drop state and the mutable handle is unique.
    ///
    /// # Safety
    ///
    /// This must be called only for a uniquely-owned mutable handle. `ptr` and
    /// `cap` must be the handle's current pointer and capacity.
    #[inline(always)]
    pub(crate) unsafe fn ensure_heap_header_for_mut(&mut self, ptr: NonNull<u8>, cap: usize) {
        if !self.is_front_heap_for_mut(ptr) {
            return;
        }

        // SAFETY: a front-heap mutable owner carries the reserved header base
        // in its tagged pointer; its contents are written below before sharing.
        let base = unsafe { self.heap() };
        let data_base = front_heap_data_base(base);
        let alloc_size = front_heap_alloc_size(base, ptr, cap);
        // SAFETY: `base` points at the reserved header region of a uniquely
        // owned front-block allocation.
        unsafe {
            base.as_ptr().write(HeapHeader {
                refs: AtomicUsize::new(1),
                data_base,
                alloc_size,
                alloc_align: align_of::<HeapHeader>(),
            });
        }
    }

    /// Returns true when this owner is a front-block heap owner relative to a
    /// mutable handle's current pointer.
    ///
    /// Front blocks place the header before the data, so the owner address is
    /// below the data pointer; tail headers sit above it. This distinguishes
    /// the two heap layouts without spending a tag bit.
    #[inline(always)]
    fn is_front_heap_for_mut(self, ptr: NonNull<u8>) -> bool {
        self.tag() == OWNER_HEAP && (self.0 & !OWNER_TAG_MASK) < ptr.as_ptr().addr()
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
    /// `self` must be a live heap or pooled owner. External owners decline
    /// mutable recovery, so lifecycle code never asks for their base.
    #[inline]
    pub(crate) unsafe fn data_base(self) -> NonNull<u8> {
        if self.is_pooled() {
            // SAFETY: guaranteed by the caller.
            unsafe { self.pooled().as_ref().data_base }
        } else {
            debug_assert_eq!(self.tag(), OWNER_HEAP);
            // SAFETY: guaranteed by the caller.
            unsafe { self.heap().as_ref().data_base }
        }
    }

    /// Returns the usable data capacity for this owner.
    ///
    /// For tail-header heap owners the capacity is the distance from the data
    /// base to the header. For canonical heap allocations this is the requested
    /// capacity rounded up to header alignment; the at most `ALIGN - 1` padding
    /// bytes precede the header and are genuinely writable. For adopted vecs it
    /// is the spare-capacity prefix below the header. For initialized
    /// front-header heap owners, capacity is the allocation size minus the
    /// leading header reservation.
    ///
    /// # Safety
    ///
    /// `self` must be a live heap or pooled owner.
    #[inline]
    pub(crate) unsafe fn usable_capacity(self) -> usize {
        if self.is_pooled() {
            // SAFETY: guaranteed by the caller.
            unsafe { self.pooled().as_ref().capacity }
        } else {
            debug_assert_eq!(self.tag(), OWNER_HEAP);
            // SAFETY: guaranteed by the caller.
            let header = unsafe { self.heap() };
            // SAFETY: guaranteed by the caller.
            let header_ref = unsafe { header.as_ref() };
            heap_usable_capacity(header, header_ref)
        }
    }

    /// Returns the current refcount for internal tests.
    #[cfg(test)]
    pub(crate) unsafe fn refcount(self) -> Option<usize> {
        if self.is_empty() {
            return None;
        }
        // SAFETY: non-empty owners have a valid refcount.
        Some(unsafe { self.refs() }.load(Ordering::Acquire))
    }
}

/// Header for heap allocations.
///
/// The header stores the exact allocation layout instead of deriving it from
/// canonical placement math. Canonical heap allocations could re-derive their
/// layout, but adopted `Vec<u8>` allocations and initialized front-header
/// allocations cannot: adopted vecs use layout `(capacity, align = 1)`, and
/// front-header allocations may be advanced before freeze. `dealloc` therefore
/// uses the stored layout exactly.
#[repr(C)]
struct HeapHeader {
    /// Shared refcount; must stay at offset 0 (see [`OwnerRef::refs`]).
    refs: AtomicUsize,
    /// Base address of the usable data region.
    data_base: NonNull<u8>,
    /// Exact size the allocation was created with.
    alloc_size: usize,
    /// Exact alignment the allocation was created with.
    alloc_align: usize,
}

/// Side-table entry for one pooled slot.
///
/// The owning freelist stores one cache-line-padded slot entry per possible
/// pooled buffer. Stable fields (`refs` sentinel, `data_base`, `capacity`,
/// `slot`) are written when the slot is created and remain associated with
/// that slot until the size class drops. The lease is live only while the slot
/// is outside the global freelist.
#[repr(C)]
pub struct PooledSlot {
    /// Shared refcount; must stay at offset 0 (see [`OwnerRef::refs`]).
    refs: AtomicUsize,
    /// Strong size-class reference; initialized at checkout, consumed at
    /// return.
    lease: MaybeUninit<SizeClassLease>,
    /// Base address of the usable data region.
    data_base: NonNull<u8>,
    /// Usable data capacity for the size class.
    capacity: usize,
    /// Stable slot id within the owning freelist.
    slot: u32,
}

impl PooledSlot {
    /// Creates an empty side-table entry for a stable slot id.
    ///
    /// The data pointer is filled when the freelist first creates the pooled
    /// allocation for this slot. Until the slot is created, no free bit points
    /// at it and no [`PooledBuffer`] may be built from it.
    #[inline]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(slot: u32, capacity: usize) -> Self {
        Self {
            refs: AtomicUsize::new(1),
            lease: MaybeUninit::uninit(),
            data_base: NonNull::dangling(),
            capacity,
            slot,
        }
    }
}

/// External owner for caller-supplied [`Bytes`] (and vecs that cannot adopt).
///
/// A single `Bytes` payload covers both `From<Bytes>` and the non-adopting
/// `From<Vec<u8>>` path, because `Bytes::from(Vec<u8>)` is always zero-copy.
/// Release is a plain box drop, which drops the inner `Bytes` exactly once.
#[repr(C)]
struct ExternalOwner {
    /// Shared refcount; must stay at offset 0 (see [`OwnerRef::refs`]).
    refs: AtomicUsize,
    /// The payload owner. The handle view `ptr..ptr+len` always lies within
    /// this value's range (required by the `slice_ref` conversion fast path).
    bytes: Bytes,
}

/// A raw pooled allocation handle whose layout is stored by its size class.
///
/// This handle is a pointer to the owning side-table slot. The slot stores the
/// data pointer, stable slot id, capacity, refcount sentinel, and optional live
/// lease. Checkout initializes only the lease field in place and returns an
/// [`OwnerRef`] to that slot; return to the global freelist consumes the lease.
///
/// `PooledBuffer` has no `Drop`: callers must return it to the originating
/// freelist or deallocate it with the exact layout used for allocation.
pub struct PooledBuffer {
    slot: NonNull<PooledSlot>,
}

// SAFETY: `PooledBuffer` is a uniquely-owned raw allocation handle while it is
// outside shared freelist state. Sharing happens only through pool structures
// that synchronize ownership transfer.
unsafe impl Send for PooledBuffer {}
// SAFETY: same ownership-transfer discipline as `Send`.
unsafe impl Sync for PooledBuffer {}

impl std::fmt::Debug for PooledBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuffer")
            .field("slot", &self.slot)
            .field("ptr", &self.data_ptr())
            .finish()
    }
}

impl PooledBuffer {
    /// Creates a new pooled data allocation for `slot`.
    ///
    /// `layout` must be the size-class data layout. The slot must be the
    /// side-table entry reserved for this allocation and must not be visible in
    /// the freelist.
    ///
    /// # Safety
    ///
    /// The caller must own `slot` initialization for this size class. No other
    /// thread may read the slot until the returned buffer is published through
    /// the freelist bitmap or handed to a checked-out owner.
    #[inline]
    pub unsafe fn new_in_slot(slot: NonNull<PooledSlot>, layout: Layout, zeroed: bool) -> Self {
        assert!(layout.size() > 0, "pooled data layout must be non-zero");
        let ptr = if zeroed {
            // SAFETY: layout is valid and non-zero sized (asserted above).
            unsafe { alloc_zeroed(layout) }
        } else {
            // SAFETY: layout is valid and non-zero sized (asserted above).
            unsafe { alloc(layout) }
        };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        // SAFETY: guaranteed by the caller. The slot is unique and not
        // concurrently visible while its data pointer is initialized.
        unsafe {
            debug_assert_eq!((*slot.as_ptr()).refs.load(Ordering::Relaxed), 1);
            addr_of_mut!((*slot.as_ptr()).data_base).write(ptr);
        }
        Self { slot }
    }

    /// Recreates a pooled buffer handle from an already-created side-table slot.
    ///
    /// # Safety
    ///
    /// The caller must own the slot and the slot's data allocation must still
    /// be live.
    #[inline(always)]
    pub(crate) const unsafe fn from_slot(slot: NonNull<PooledSlot>) -> Self {
        Self { slot }
    }

    /// Returns the usable data base pointer.
    #[cfg(any(test, feature = "bench"))]
    #[inline(always)]
    pub const fn as_ptr(&self) -> *mut u8 {
        self.data_ptr().as_ptr()
    }

    /// Returns the usable data base pointer without discarding non-nullness.
    #[inline(always)]
    pub(crate) const fn data_ptr(&self) -> NonNull<u8> {
        // SAFETY: pooled buffers are built only for created slots.
        unsafe { self.slot.as_ref().data_base }
    }

    /// Returns the usable data capacity for this size-class buffer.
    #[inline(always)]
    pub(crate) const fn capacity(&self) -> usize {
        // SAFETY: `PooledBuffer` is constructed only for created slots, whose
        // stable side-table fields are initialized.
        unsafe { self.slot.as_ref().capacity }
    }

    /// Returns the stable slot id for this size-class buffer.
    ///
    /// The slot is initialized once when the owning freelist creates this
    /// buffer and is needed only when the buffer returns to the global
    /// freelist.
    ///
    #[inline(always)]
    pub(crate) const fn slot(&self) -> u32 {
        // SAFETY: `PooledBuffer` is constructed only for created slots, whose
        // stable side-table fields are initialized.
        unsafe { self.slot.as_ref().slot }
    }

    /// Initializes the pooled lease for a buffer leaving global state.
    ///
    /// # Safety
    ///
    /// This buffer must be checked out from the size class represented by
    /// `lease`, and the slot must not currently contain a live lease.
    #[inline(always)]
    pub(crate) unsafe fn init_lease(&mut self, lease: SizeClassLease) {
        // SAFETY: slot is a live side-table entry.
        unsafe {
            debug_assert_eq!((*self.slot.as_ptr()).refs.load(Ordering::Relaxed), 1);
            addr_of_mut!((*self.slot.as_ptr()).lease).write(MaybeUninit::new(lease));
        }
    }

    /// Returns a borrowed live lease.
    ///
    /// # Safety
    ///
    /// This pooled buffer must be checked out or parked in a thread-local cache,
    /// so its lease field is initialized.
    #[inline(always)]
    pub(crate) const unsafe fn lease(&self) -> &SizeClassLease {
        // SAFETY: guaranteed by the caller.
        unsafe { &*self.slot.as_ref().lease.as_ptr() }
    }

    /// Consumes the live lease from this slot.
    ///
    /// # Safety
    ///
    /// This pooled buffer must have an initialized lease, and after this call
    /// the buffer must not be treated as checked out or locally cached until a
    /// new lease is initialized.
    #[inline(always)]
    pub(crate) const unsafe fn take_lease(&mut self) -> SizeClassLease {
        // SAFETY: guaranteed by the caller.
        unsafe { self.slot.as_mut().lease.assume_init_read() }
    }

    /// Returns the owner ref for a buffer whose lease is already initialized.
    ///
    /// # Safety
    ///
    /// The lease field must be initialized.
    #[inline(always)]
    pub(crate) unsafe fn owner_ref(&self) -> OwnerRef {
        // SAFETY: guaranteed by the caller.
        unsafe { OwnerRef::from_pooled(self.slot) }
    }

    /// Deallocates this pooled buffer.
    ///
    /// # Safety
    ///
    /// `layout` must exactly match the layout used to allocate this buffer.
    #[inline(always)]
    pub unsafe fn deallocate(self, layout: Layout) {
        // SAFETY: guaranteed by the caller.
        unsafe { dealloc(self.data_ptr().as_ptr(), layout) };
    }
}

/// Allocates an untracked aligned buffer with a tail [`HeapHeader`].
///
/// The header is placed at `capacity` rounded up to `align_of::<HeapHeader>()`
/// past the base, and the layout alignment is raised to at least the header
/// alignment so both the data base and the header are aligned. Returns the
/// data pointer, the usable capacity (the rounded prefix below the header,
/// at most `align_of::<HeapHeader>() - 1` bytes more than requested), and
/// the owner.
///
/// # Panics
///
/// Panics if `capacity == 0` or `alignment` is not a power of two.
#[inline]
pub(crate) fn allocate_aligned(
    capacity: usize,
    alignment: usize,
    zeroed: bool,
) -> (NonNull<u8>, usize, OwnerRef) {
    assert!(capacity > 0, "capacity must be greater than zero");
    let (layout, header_offset) = heap_layout(capacity, alignment);
    let ptr = if zeroed {
        // SAFETY: layout is valid and non-zero sized.
        unsafe { alloc_zeroed(layout) }
    } else {
        // SAFETY: layout is valid and non-zero sized.
        unsafe { alloc(layout) }
    };
    let data = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
    // SAFETY: the computed layout includes the header at `header_offset`, and
    // `header_offset` is a multiple of the header alignment.
    let owner = unsafe {
        let header = data.as_ptr().add(header_offset).cast::<HeapHeader>();
        header.write(HeapHeader {
            refs: AtomicUsize::new(1),
            data_base: data,
            alloc_size: layout.size(),
            alloc_align: layout.align(),
        });
        OwnerRef::from_heap(NonNull::new_unchecked(header))
    };
    (data, header_offset, owner)
}

/// Allocates an untracked mutable buffer.
///
/// Low-alignment allocations reserve a front [`HeapHeader`] and leave it
/// uninitialized until `freeze`; high-alignment allocations use the eager tail
/// header layout from [`allocate_aligned`] so the returned data pointer keeps
/// the requested alignment.
///
/// # Panics
///
/// Panics if `capacity == 0` or `alignment` is not a power of two.
#[inline(always)]
pub(crate) fn allocate_aligned_mut(
    capacity: usize,
    alignment: usize,
    zeroed: bool,
) -> (NonNull<u8>, OwnerRef) {
    assert!(capacity > 0, "capacity must be greater than zero");
    assert!(
        alignment.is_power_of_two(),
        "alignment must be a power of two"
    );
    if alignment > align_of::<HeapHeader>() {
        let (ptr, _, owner) = allocate_aligned(capacity, alignment, zeroed);
        return (ptr, owner);
    }

    let layout = front_heap_layout(capacity);
    let ptr = if zeroed {
        // SAFETY: layout is valid and non-zero sized.
        unsafe { alloc_zeroed(layout) }
    } else {
        // SAFETY: layout is valid and non-zero sized.
        unsafe { alloc(layout) }
    };
    let base = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
    let header = base.cast::<HeapHeader>();
    let data = front_heap_data_base(header);
    // SAFETY: `header` points at the reserved front header region of an
    // allocation owned by this owner ref. The contents are left uninitialized
    // and written before the owner is shared (`from_heap` reads nothing).
    let owner = unsafe { OwnerRef::from_heap(header) };
    (data, owner)
}

/// Tries to adopt `vec`'s allocation as a native heap buffer.
///
/// Adoption places a tail [`HeapHeader`] at the highest header-aligned
/// address inside the vec's own spare capacity and succeeds iff that address
/// is at or above `base + len` (see the module docs for the layout diagram):
/// zero copies and zero extra allocations. The vec's allocation layout
/// `(cap, align = 1)` is recorded exactly so release deallocates with the
/// same layout. On success, returns the data pointer, readable length,
/// usable capacity (the prefix below the header), and the owner.
///
/// Exactly-sized vecs (`len == cap`, the common case for `vec![0; n]` and
/// `collect()`) have no spare room; reallocating could copy, so they are
/// returned unchanged for the caller to convert another way.
pub(crate) fn try_adopt_vec(
    vec: Vec<u8>,
) -> Result<(NonNull<u8>, usize, usize, OwnerRef), Vec<u8>> {
    let len = vec.len();
    let cap = vec.capacity();
    let base_addr = vec.as_ptr() as usize;
    let Some(header_offset) = vec_adoption_header_offset(base_addr, len, cap) else {
        return Err(vec);
    };

    // Adopt: dismantle the vec and place the header in its spare capacity.
    let mut vec = ManuallyDrop::new(vec);
    let base = vec.as_mut_ptr();
    // SAFETY: `base..base+cap` is one live allocation (`cap > 0`) owned by
    // the dismantled vec; `base + header_offset` is header-aligned and
    // `header_offset + size_of::<HeapHeader>() <= cap`, so the header write
    // is in bounds.
    unsafe {
        let header = base.add(header_offset).cast::<HeapHeader>();
        header.write(HeapHeader {
            refs: AtomicUsize::new(1),
            data_base: NonNull::new_unchecked(base),
            alloc_size: cap,
            alloc_align: 1,
        });
        Ok((
            NonNull::new_unchecked(base),
            len,
            header_offset,
            OwnerRef::from_heap(NonNull::new_unchecked(header)),
        ))
    }
}

/// Converts `vec` into immutable handle fields, adopting its allocation if it
/// can host a tail [`HeapHeader`] in spare capacity.
///
/// Empty vecs detach entirely (empty immutable buffers never pin an
/// allocation). Non-adoptable vecs move into `Bytes` (zero-copy for any
/// `Vec<u8>`; for `len == cap` also `bytes`' allocation-free promotable
/// path) behind an external owner.
pub(crate) fn owner_from_vec(vec: Vec<u8>) -> (NonNull<u8>, usize, OwnerRef) {
    if vec.is_empty() {
        return (NonNull::dangling(), 0, OwnerRef::empty());
    }
    match try_adopt_vec(vec) {
        Ok((ptr, len, _, owner)) => (ptr, len, owner),
        Err(vec) => owner_from_bytes(Bytes::from(vec)),
    }
}

/// Moves `bytes` into a boxed [`ExternalOwner`] and returns handle fields.
///
/// Zero-copy: the handle points directly into the payload kept alive by the
/// inner `Bytes`. Costs one box; the inner refcount is not touched again until
/// final release.
pub(crate) fn owner_from_bytes(bytes: Bytes) -> (NonNull<u8>, usize, OwnerRef) {
    if bytes.is_empty() {
        return (NonNull::dangling(), 0, OwnerRef::empty());
    }

    // Box the owner first, then derive the handle pointer from the `Bytes` in
    // its final location inside the box. This keeps the provenance chain
    // trivially clean: the pointer the handle uses is derived from the exact
    // value that owns the payload for the buffer's whole life.
    let owner = Box::new(ExternalOwner {
        refs: AtomicUsize::new(1),
        bytes,
    });
    let ptr =
        NonNull::new(owner.bytes.as_ptr().cast_mut()).expect("non-empty Bytes has non-null data");
    let len = owner.bytes.len();
    let owner = NonNull::from(Box::leak(owner));
    // SAFETY: the pointer came from `Box::leak` and is uniquely owned here.
    let owner = unsafe { OwnerRef::from_external(owner) };
    (ptr, len, owner)
}

/// Returns the data layout for a pooled size class.
///
/// Pooled owner metadata lives in the size class side table, so the allocation
/// itself contains only caller-usable bytes with the requested alignment.
#[inline]
pub(crate) fn pooled_layout(size: usize, alignment: usize) -> Layout {
    Layout::from_size_align(size, alignment).expect("alignment is a power of two")
}

/// Returns the full layout and header offset for a native aligned allocation.
#[inline]
fn heap_layout(capacity: usize, alignment: usize) -> (Layout, usize) {
    let header_offset = capacity
        .checked_next_multiple_of(align_of::<HeapHeader>())
        .expect("layout size overflow");
    let total = header_offset
        .checked_add(size_of::<HeapHeader>())
        .expect("heap layout size overflow");
    let layout_alignment = alignment.max(align_of::<HeapHeader>());
    let layout =
        Layout::from_size_align(total, layout_alignment).expect("alignment is a power of two");
    (layout, header_offset)
}

/// Returns the full layout for a low-alignment front-header allocation.
#[inline(always)]
const fn front_heap_layout(capacity: usize) -> Layout {
    let total = size_of::<HeapHeader>()
        .checked_add(capacity)
        .expect("front heap layout size overflow");
    // SAFETY: `HeapHeader` has a non-zero power-of-two alignment, and
    // `capacity > 0` at allocation sites makes `total` non-zero.
    unsafe { Layout::from_size_align_unchecked(total, align_of::<HeapHeader>()) }
}

#[inline(always)]
const fn front_heap_data_base(base: NonNull<HeapHeader>) -> NonNull<u8> {
    // SAFETY: the front layout reserves the header at the allocation base and
    // the usable data starts immediately after it.
    unsafe { NonNull::new_unchecked(base.as_ptr().cast::<u8>().add(size_of::<HeapHeader>())) }
}

#[inline(always)]
fn front_heap_alloc_size(base: NonNull<HeapHeader>, ptr: NonNull<u8>, cap: usize) -> usize {
    let base_addr = base.as_ptr() as usize;
    let end_addr = ptr.as_ptr() as usize + cap;
    debug_assert!(end_addr >= base_addr);
    end_addr - base_addr
}

#[inline(always)]
fn heap_usable_capacity(header: NonNull<HeapHeader>, header_ref: &HeapHeader) -> usize {
    let header_addr = header.as_ptr() as usize;
    let data_addr = header_ref.data_base.as_ptr() as usize;
    if header_addr < data_addr {
        header_ref
            .alloc_size
            .checked_sub(data_addr - header_addr)
            .expect("front heap data base must lie within allocation")
    } else {
        header_addr - data_addr
    }
}

#[inline(always)]
fn round_down(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}

#[inline(always)]
fn vec_adoption_header_offset(base_addr: usize, len: usize, cap: usize) -> Option<usize> {
    if cap < size_of::<HeapHeader>() {
        return None;
    }
    let header_addr = round_down(
        base_addr.checked_add(cap - size_of::<HeapHeader>())?,
        align_of::<HeapHeader>(),
    );
    if header_addr < base_addr || header_addr < base_addr.checked_add(len)? {
        return None;
    }
    Some(header_addr - base_addr)
}

/// Releases a unique pooled owner into the thread-cache push fast path.
///
/// # Safety
///
/// No other handle may reference this allocation and the pooled lease must be
/// initialized.
#[inline(always)]
unsafe fn release_pooled(slot: NonNull<PooledSlot>) {
    // SAFETY: guaranteed by the caller.
    debug_assert_eq!(unsafe { slot.as_ref() }.refs.load(Ordering::Relaxed), 1);
    // SAFETY: this unique owner proves the slot's data allocation is live.
    let buffer = unsafe { PooledBuffer::from_slot(slot) };
    BufferPoolThreadCache::push(buffer);
}

/// Releases unique non-pooled owners (heap dealloc, external box drop).
///
/// One outlined function serves every drop site so the cold dealloc and
/// box-drop code is not instantiated inline at each `IoBuf`/`IoBufMut` drop.
///
/// # Safety
///
/// No other handle may reference this allocation.
#[cold]
#[inline(never)]
unsafe fn release_unique_cold(owner: OwnerRef) {
    let tag = owner.tag();
    if tag == OWNER_HEAP {
        // SAFETY: unique initialized heap owner.
        unsafe { release_heap(owner.heap()) };
    } else if tag == OWNER_EXTERNAL {
        // SAFETY: unique external owner.
        unsafe { release_external(owner.external()) };
    }
    // Empty owners need no release work.
}

/// Releases a unique initialized heap owner.
///
/// Two loads recover the stored base and layout; no placement math is redone
/// on release. The header fields are copied out before `dealloc` because the
/// header lives inside the allocation being freed.
///
/// # Safety
///
/// No other handle may reference this allocation.
#[inline]
unsafe fn release_heap(header: NonNull<HeapHeader>) {
    // SAFETY: guaranteed by the caller.
    let header_ref = unsafe { header.as_ref() };
    debug_assert_eq!(header_ref.refs.load(Ordering::Relaxed), 1);
    let header_addr = header.as_ptr() as usize;
    let data_addr = header_ref.data_base.as_ptr() as usize;
    let base = if header_addr < data_addr {
        header.cast::<u8>()
    } else {
        header_ref.data_base
    };
    // SAFETY: `(alloc_size, alloc_align)` is exactly the layout the allocation
    // was created with (a heap-owner invariant).
    let layout =
        unsafe { Layout::from_size_align_unchecked(header_ref.alloc_size, header_ref.alloc_align) };
    // SAFETY: base/layout came from the global allocator; the header borrow
    // ended above (its fields were copied to locals).
    unsafe { dealloc(base.as_ptr(), layout) };
}

/// Releases a front-header heap allocation without touching its reserved
/// header.
///
/// # Safety
///
/// `base`, `ptr`, and `cap` must describe a live front-header allocation whose
/// mutable handle is unique.
#[inline(always)]
unsafe fn release_front_heap(base: NonNull<HeapHeader>, ptr: NonNull<u8>, cap: usize) {
    let alloc_size = front_heap_alloc_size(base, ptr, cap);
    // SAFETY: front heap allocations are created with this exact layout.
    let layout = unsafe { Layout::from_size_align_unchecked(alloc_size, align_of::<HeapHeader>()) };
    // SAFETY: base/layout came from the global allocator on the front branch.
    unsafe { dealloc(base.as_ptr().cast::<u8>(), layout) };
}

/// Releases a unique external owner.
///
/// # Safety
///
/// `owner` must come from `Box::leak` and no other handle may reference it.
#[inline]
unsafe fn release_external(owner: NonNull<ExternalOwner>) {
    // SAFETY: guaranteed by the caller.
    let owner_ref = unsafe { owner.as_ref() };
    debug_assert_eq!(owner_ref.refs.load(Ordering::Relaxed), 1);
    // SAFETY: the owner box was leaked at construction; dropping it here drops
    // the inner `Bytes` exactly once.
    drop(unsafe { Box::from_raw(owner.as_ptr()) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iobuf::page_size;
    use commonware_utils::NZUsize;

    #[test]
    fn test_heap_layout_places_tail_header_after_data() {
        let page = page_size();
        let (data, usable, owner) = allocate_aligned(4096, page, false);
        assert!((data.as_ptr() as usize).is_multiple_of(page));
        assert_eq!(usable, 4096);

        // SAFETY: owner was just allocated and is live.
        let header = unsafe { owner.heap() };
        assert!((header.as_ptr() as usize).is_multiple_of(align_of::<HeapHeader>()));
        assert!(header.as_ptr() as usize >= data.as_ptr() as usize + 4096);
        // SAFETY: owner is unique and live.
        assert_eq!(unsafe { owner.data_base() }, data);
        // SAFETY: owner is unique and live.
        assert_eq!(unsafe { owner.usable_capacity() }, 4096);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
    }

    #[test]
    fn test_heap_zeroed_only_exposes_usable_region() {
        let (data, _, owner) = allocate_aligned(64, page_size(), true);
        // SAFETY: data points at a zeroed usable region of length 64.
        let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr(), 64) };
        assert_eq!(bytes, &[0u8; 64]);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
    }

    #[test]
    fn test_heap_unaligned_capacity_rounds_usable_region_up() {
        // A capacity that is not a multiple of the header alignment gains the
        // padding bytes that precede the header; they are genuinely writable.
        let (_, usable, owner) = allocate_aligned(10, 1, false);
        // SAFETY: owner is unique and live.
        let capacity = unsafe { owner.usable_capacity() };
        assert_eq!(capacity, 10usize.next_multiple_of(align_of::<HeapHeader>()));
        assert_eq!(usable, capacity);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
    }

    #[test]
    fn test_front_heap_mut_drop_does_not_read_reserved_header() {
        let (data, owner) = allocate_aligned_mut(64, 1, false);
        assert!((data.as_ptr() as usize).is_multiple_of(align_of::<HeapHeader>()));
        assert!(owner.is_front_heap_for_mut(data));
        // SAFETY: owner is unique and must be released by this test. This path
        // must not read the uninitialized front header.
        unsafe { owner.release_unique_mut_at(data, 64) };

        let (data, owner) = allocate_aligned_mut(64, 1, false);
        // SAFETY: `17 <= 64`, so the advanced pointer stays within the
        // allocation's usable region.
        let advanced = unsafe { data.add(17) };
        assert!(owner.is_front_heap_for_mut(advanced));
        // SAFETY: owner is unique and must be released by this test. The
        // mutable cursor keeps `advanced + 47` equal to the allocation end.
        unsafe { owner.release_unique_mut_at(advanced, 47) };
    }

    #[test]
    fn test_front_heap_materializes_before_shared_owner() {
        let (data, mut owner) = allocate_aligned_mut(64, 1, false);
        // SAFETY: `17 <= 64`, so the advanced pointer stays within the
        // allocation's usable region.
        let advanced = unsafe { data.add(17) };

        // SAFETY: owner is unique and live. This writes the reserved header so
        // immutable lifecycle and try_into_mut paths can use normal heap-owner
        // metadata.
        unsafe { owner.ensure_heap_header_for_mut(advanced, 47) };
        assert!(owner.is_front_heap_for_mut(advanced));
        // SAFETY: owner is live and initialized.
        assert_eq!(unsafe { owner.data_base() }, data);
        // SAFETY: owner is live and initialized.
        assert_eq!(unsafe { owner.usable_capacity() }, 64);
        // SAFETY: owner is live and initialized.
        assert_eq!(unsafe { owner.refcount() }, Some(1));
        // SAFETY: final shared drop releases the initialized front allocation.
        unsafe { owner.drop_shared() };
    }

    #[test]
    fn test_mut_allocator_uses_tail_header_for_high_alignment() {
        let page = page_size();
        let (data, owner) = allocate_aligned_mut(64, page, false);
        assert!((data.as_ptr() as usize).is_multiple_of(page));
        assert!(!owner.is_front_heap_for_mut(data));
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique_mut_at(data, 64) };
    }

    #[test]
    fn test_front_heap_zeroed_exposes_zeroed_data_region() {
        let (data, owner) = allocate_aligned_mut(64, 1, true);
        // SAFETY: data points at a zeroed usable region of length 64.
        let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr(), 64) };
        assert_eq!(bytes, &[0u8; 64]);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique_mut_at(data, 64) };
    }

    #[test]
    fn test_external_owner_refcount() {
        let (_, len, owner) = owner_from_bytes(Bytes::from_static(b"abc"));
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
        let (ptr, len, owner) = owner_from_bytes(payload);
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
        let (_, len, owner) = owner_from_vec(Vec::new());
        assert_eq!(len, 0);
        assert!(owner.is_empty());
    }

    #[test]
    fn test_empty_bytes_has_no_owner() {
        let (_, len, owner) = owner_from_bytes(Bytes::new());
        assert_eq!(len, 0);
        assert!(owner.is_empty());
    }

    #[test]
    fn test_vec_adoption_with_spare_capacity() {
        // Plenty of spare room: the vec's own allocation becomes a native
        // heap buffer with the header in its spare capacity.
        let mut vec = Vec::with_capacity(256);
        vec.extend_from_slice(&[1u8, 2, 3, 4]);
        let base_addr = vec.as_ptr() as usize;
        let cap = vec.capacity();
        let (ptr, len, owner) = owner_from_vec(vec);
        assert_eq!(ptr.as_ptr() as usize, base_addr);
        assert_eq!(len, 4);
        assert!(!owner.is_external());
        assert!(!owner.is_pooled());
        assert!(!owner.is_empty());

        let expected_header = base_addr + vec_adoption_header_offset(base_addr, len, cap).unwrap();
        // SAFETY: owner is unique and live.
        assert_eq!(unsafe { owner.data_base() }.as_ptr() as usize, base_addr);
        // SAFETY: owner is unique and live.
        let usable = unsafe { owner.usable_capacity() };
        assert_eq!(usable, expected_header - base_addr);
        // SAFETY: the adopted region below the header is writable; verify the
        // payload survived adoption.
        let payload = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) };
        assert_eq!(payload, &[1, 2, 3, 4]);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
    }

    #[test]
    fn test_vec_adoption_exact_size_falls_back_to_external() {
        // `len == cap` leaves no spare room, so the vec takes the external
        // owner path (allocation-free promotable `Bytes`).
        let vec = vec![5u8, 6, 7];
        assert_eq!(vec.len(), vec.capacity());
        let (ptr, len, owner) = owner_from_vec(vec);
        assert_eq!(len, 3);
        assert!(owner.is_external());
        // SAFETY: ptr points into the payload kept alive by the owner.
        let payload = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) };
        assert_eq!(payload, &[5, 6, 7]);
        // SAFETY: final drop releases the owner.
        unsafe { owner.drop_shared() };
    }

    #[test]
    fn test_vec_adoption_boundary_matches_placement_rule() {
        // Walk spare capacities around the header size and check the adopt
        // versus external decision matches the placement rule exactly. The
        // exact threshold depends on the runtime base address, so the rule is
        // recomputed per vec rather than hardcoded.
        for spare in 0..(size_of::<HeapHeader>() + 2 * align_of::<HeapHeader>()) {
            let len = 16;
            let mut vec = Vec::with_capacity(len + spare);
            vec.extend_from_slice(&[9u8; 16]);
            let base_addr = vec.as_ptr() as usize;
            let cap = vec.capacity();
            let fits = vec_adoption_header_offset(base_addr, len, cap).is_some();
            let (_, _, owner) = owner_from_vec(vec);
            assert_eq!(
                owner.is_external(),
                !fits,
                "spare={spare} cap={cap} base={base_addr:#x}"
            );
            // SAFETY: final drop releases the owner.
            unsafe { owner.drop_shared() };
        }
    }

    #[test]
    fn test_vec_adoption_rejects_header_before_base() {
        let align = align_of::<HeapHeader>();
        let base_addr = align - 1;
        let cap = size_of::<HeapHeader>();
        let header_addr = round_down(base_addr + cap - size_of::<HeapHeader>(), align);
        assert!(header_addr < base_addr);
        assert_eq!(vec_adoption_header_offset(base_addr, 0, cap), None);
    }

    #[test]
    fn test_heap_owner_shared_clone_and_drop() {
        let (_, _, owner) = allocate_aligned(64, 1, false);
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

    #[test]
    fn test_pooled_layout_is_data_only() {
        let size = 1024;
        let layout = pooled_layout(size, NZUsize!(64).get());
        assert_eq!(layout.size(), size);
        assert!(layout.align() >= 64);
        assert!(align_of::<PooledSlot>() >= 4);
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use loom::{
        sync::{atomic::AtomicUsize, Arc},
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
    fn loom_shared_clone_drop_releases_exactly_once() {
        loom::model(|| {
            let released = Arc::new(AtomicUsize::new(0));
            let bytes = Bytes::from_owner(Tracker(released.clone()));
            let (_, len, owner) = owner_from_bytes(bytes);
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
    fn loom_clone_races_concurrent_drop() {
        loom::model(|| {
            let released = Arc::new(AtomicUsize::new(0));
            let bytes = Bytes::from_owner(Tracker(released.clone()));
            let (_, _, owner) = owner_from_bytes(bytes);

            // Two handles: this thread and the spawned thread. The spawned
            // thread clones from its own live handle while this thread drops,
            // racing clone_shared's Relaxed fetch_add against the drop
            // protocol's Acquire load and Release decrement.
            // SAFETY: `owner` is live with one reference owned here.
            unsafe { owner.clone_shared() };
            let t1 = thread::spawn(move || {
                // SAFETY: this thread owns one live reference to clone from.
                unsafe { owner.clone_shared() };
                // SAFETY: this thread owns two references; drop both.
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
    fn loom_is_unique_races_final_drop() {
        loom::model(|| {
            let released = Arc::new(AtomicUsize::new(0));
            let bytes = Bytes::from_owner(Tracker(released.clone()));
            let (_, _, owner) = owner_from_bytes(bytes);

            // Two handles: this thread checks uniqueness (the try_into_mut
            // gate) while the other drops. Observing unique must mean the
            // other drop fully happened-before (its Release decrement pairs
            // with is_unique's Acquire load) and did not release the payload.
            // SAFETY: `owner` is live with one reference owned here.
            unsafe { owner.clone_shared() };
            let t1 = thread::spawn(move || {
                // SAFETY: this thread owns one reference.
                unsafe { owner.drop_shared() };
            });
            // SAFETY: the main thread owns one reference.
            if unsafe { owner.is_unique() } {
                // The other handle is gone, so this thread holds the only
                // reference and the payload must still be live.
                assert_eq!(released.load(Ordering::SeqCst), 0);
            }
            // SAFETY: the main thread owns the remaining reference.
            unsafe { owner.drop_shared() };
            t1.join().unwrap();

            assert_eq!(released.load(Ordering::SeqCst), 1);
        });
    }
}
