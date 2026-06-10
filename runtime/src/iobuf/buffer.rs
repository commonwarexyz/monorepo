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
//! header ptr | 0b01       ALIGNED   tail HeapHeader; native aligned
//!                                   allocations and adopted vecs
//! header ptr | 0b10       POOLED    tail PooledHeader; pool-tracked buffers
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
//! Native runtime allocations (aligned and pooled) place the owner header at
//! the tail of the same allocation that stores data:
//!
//! ```text
//! [ usable data bytes ............ ][ padding ][ owner header ]
//! ^                                            ^
//! data base (alignment preserved)              OwnerRef target
//! ```
//!
//! The usable data begins at the allocation base so alignment requested for
//! I/O is preserved. A sliced or advanced handle may point into the usable
//! region, so drop and `try_into_mut` recover the original base from the
//! header, not from the handle's current `ptr`.
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
    sync::atomic::{fence, AtomicUsize, Ordering},
};

const OWNER_EMPTY: usize = 0b00;
const OWNER_ALIGNED: usize = 0b01;
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
const _: () = assert!(align_of::<PooledHeader>() >= 4);
const _: () = assert!(align_of::<ExternalOwner>() >= 4);

// `OwnerRef::refs` reads the refcount directly through the untagged pointer,
// which is only sound if every owner type stores it at offset 0.
const _: () = assert!(offset_of!(HeapHeader, refs) == 0);
const _: () = assert!(offset_of!(PooledHeader, refs) == 0);
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

    #[inline(always)]
    pub(crate) const fn is_pooled(self) -> bool {
        (self.0 & OWNER_TAG_MASK) == OWNER_POOLED
    }

    #[inline(always)]
    pub(crate) const fn is_external(self) -> bool {
        (self.0 & OWNER_TAG_MASK) == OWNER_EXTERNAL
    }

    /// Creates a heap owner ref from a tail header pointer.
    ///
    /// # Safety
    ///
    /// `header` must point to a live, initialized [`HeapHeader`] whose low tag
    /// bits are zero and whose backing allocation is owned by this owner ref.
    #[inline(always)]
    unsafe fn from_heap(header: NonNull<HeapHeader>) -> Self {
        debug_assert_eq!(header.as_ptr() as usize & OWNER_TAG_MASK, 0);
        Self(header.as_ptr() as usize | OWNER_ALIGNED)
    }

    /// Creates a pooled owner ref from a tail header pointer.
    ///
    /// # Safety
    ///
    /// `header` must point to a live [`PooledHeader`] whose low tag bits are
    /// zero and whose lease is initialized.
    #[inline(always)]
    pub(crate) unsafe fn from_pooled(header: NonNull<PooledHeader>) -> Self {
        debug_assert_eq!(header.as_ptr() as usize & OWNER_TAG_MASK, 0);
        Self(header.as_ptr() as usize | OWNER_POOLED)
    }

    /// Creates an external owner ref.
    ///
    /// # Safety
    ///
    /// `owner` must come from `Box::into_raw(Box<ExternalOwner>)` and be
    /// uniquely represented by this owner ref.
    #[inline(always)]
    unsafe fn from_external(owner: NonNull<ExternalOwner>) -> Self {
        debug_assert_eq!(owner.as_ptr() as usize & OWNER_TAG_MASK, 0);
        Self(owner.as_ptr() as usize | OWNER_EXTERNAL)
    }

    /// Returns the heap header for an aligned (native or adopted) owner.
    ///
    /// # Safety
    ///
    /// `self` must be a live aligned owner.
    #[inline(always)]
    unsafe fn heap(self) -> NonNull<HeapHeader> {
        debug_assert_eq!(self.0 & OWNER_TAG_MASK, OWNER_ALIGNED);
        // SAFETY: aligned owner refs are created from non-null header pointers.
        unsafe { NonNull::new_unchecked((self.0 & !OWNER_TAG_MASK) as *mut HeapHeader) }
    }

    /// Returns the pooled header for a pooled owner.
    ///
    /// # Safety
    ///
    /// `self` must be a live pooled owner.
    #[inline(always)]
    unsafe fn pooled(self) -> NonNull<PooledHeader> {
        debug_assert!(self.is_pooled());
        // SAFETY: pooled owner refs are created from non-null header pointers.
        unsafe { NonNull::new_unchecked((self.0 & !OWNER_TAG_MASK) as *mut PooledHeader) }
    }

    /// Returns the external owner box pointer.
    ///
    /// # Safety
    ///
    /// `self` must be a live external owner.
    #[inline(always)]
    unsafe fn external(self) -> NonNull<ExternalOwner> {
        debug_assert!(self.is_external());
        // SAFETY: external owner refs are created from non-null box pointers.
        unsafe { NonNull::new_unchecked((self.0 & !OWNER_TAG_MASK) as *mut ExternalOwner) }
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
        // SAFETY: caller guarantees a live non-empty owner; all owner types
        // are repr(C) with `refs` at offset 0.
        unsafe { &*((self.0 & !OWNER_TAG_MASK) as *const AtomicUsize) }
    }

    /// Returns the inner [`Bytes`] of an external owner.
    ///
    /// # Safety
    ///
    /// `self` must be a live external owner, and the caller must bound the
    /// returned borrow by the owner's liveness (the handle that supplied
    /// `self` keeps a reference for at least that long).
    // TODO(iobuf-v2 step 2): the `From<IoBuf> for Bytes` slice_ref fast path
    // consumes this; drop the allow once that lands.
    #[allow(dead_code)]
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
    /// no read-modify-write. The decrement path for shared owners is outlined
    /// in [`Self::drop_shared_slow`]; it is definitionally cold because it
    /// runs at most once per clone.
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

        // Acquire pairs with the Release decrements in `drop_shared_slow`:
        // observing 1 means every other handle has already dropped, and their
        // payload reads happen-before this release.
        // SAFETY: non-empty owners have a valid refcount.
        if unsafe { self.refs() }.load(Ordering::Acquire) == 1 {
            // SAFETY: this is the final shared owner.
            unsafe { self.release_unique() };
            return;
        }

        // SAFETY: same contract as this method; the owner is shared.
        unsafe { self.drop_shared_slow() };
    }

    /// Decrements a shared refcount and releases on the final drop.
    ///
    /// Two shared owners dropping concurrently can both miss the fast path:
    /// one observes `> 1`, the other decrements to `1` in between. The
    /// `old == 1` branch below is that race's loser-turned-winner: its
    /// decrement hit zero, so it restores the sentinel and releases. The
    /// branch is reachable only under true concurrency (covered by loom).
    ///
    /// # Safety
    ///
    /// `self` must be a live non-empty owner with one live reference owned by
    /// the caller, which this call consumes.
    #[cold]
    #[inline(never)]
    unsafe fn drop_shared_slow(self) {
        // SAFETY: guaranteed by the caller.
        let refs = unsafe { self.refs() };
        // Release pairs with the Acquire load in `drop_shared` (and the
        // Acquire fence below): it publishes this handle's payload reads to
        // whichever drop ends up releasing the allocation.
        let old = refs.fetch_sub(1, Ordering::Release);
        debug_assert!(old >= 1);
        if old == 1 {
            // Acquire fence pairs with the Release decrements of all other
            // handles, ordering their payload accesses before the release.
            fence(Ordering::Acquire);
            // Restore the sentinel before releasing. No other handle exists,
            // so Relaxed is sufficient; pooled reuse synchronizes through the
            // freelist's own Release/Acquire bit transitions.
            refs.store(1, Ordering::Relaxed);
            // SAFETY: this drop won the final-owner race.
            unsafe { self.release_unique() };
        }
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
        if self.0 & OWNER_TAG_MASK == OWNER_POOLED {
            // SAFETY: unique pooled owner with initialized lease.
            unsafe { release_pooled(self.pooled()) };
            return;
        }
        // SAFETY: same contract as this method.
        unsafe { release_unique_cold(self) };
    }

    /// Releases a uniquely-owned mutable allocation.
    ///
    /// The empty check comes first because drained mutable handles
    /// (`mem::take`, moved-out defaults) are common at drop sites. The pooled
    /// arm stays inline for the lifecycle hot loop; the aligned arm shares
    /// the outlined [`release_unique_cold`]. Mutable handles are never
    /// external-backed (`Bytes` cannot back mutation), so no external arm
    /// exists here.
    ///
    /// # Safety
    ///
    /// This must be called only for a uniquely-owned mutable handle.
    #[inline(always)]
    pub(crate) unsafe fn release_unique_mut(self) {
        let tag = self.0 & OWNER_TAG_MASK;
        if tag == OWNER_EMPTY {
            return;
        }
        if tag == OWNER_POOLED {
            // SAFETY: unique pooled owner with initialized lease.
            unsafe { release_pooled(self.pooled()) };
            return;
        }
        debug_assert_eq!(tag, OWNER_ALIGNED, "IoBufMut owner is never external");
        // SAFETY: same contract as this method.
        unsafe { release_unique_cold(self) };
    }

    /// Returns true when this owner has exactly one live reference.
    ///
    /// Sound for the same reason `Arc::get_mut` is: a count of 1 observed
    /// through Acquire means no other handle exists, and no thread can clone
    /// without a handle. The Acquire load pairs with the Release decrement in
    /// [`Self::drop_shared_slow`] so the last dropper's payload reads
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
    /// `self` must be a live aligned or pooled owner. External owners decline
    /// mutable recovery, so lifecycle code never asks for their base.
    #[inline]
    pub(crate) unsafe fn data_base(self) -> NonNull<u8> {
        if self.is_pooled() {
            // SAFETY: guaranteed by the caller.
            unsafe { self.pooled().as_ref().data_base }
        } else {
            debug_assert_eq!(self.0 & OWNER_TAG_MASK, OWNER_ALIGNED);
            // SAFETY: guaranteed by the caller.
            unsafe { self.heap().as_ref().data_base }
        }
    }

    /// Returns the usable data capacity for this owner.
    ///
    /// For heap owners the capacity is the distance from the data base to the
    /// header. For canonical aligned allocations this is the requested
    /// capacity rounded up to header alignment; the at most `ALIGN - 1`
    /// padding bytes precede the header and are genuinely writable. For
    /// adopted vecs it is the spare-capacity prefix below the header.
    ///
    /// # Safety
    ///
    /// `self` must be a live aligned or pooled owner.
    #[inline]
    pub(crate) unsafe fn usable_capacity(self) -> usize {
        if self.is_pooled() {
            // SAFETY: guaranteed by the caller.
            unsafe { self.pooled().as_ref().capacity }
        } else {
            debug_assert_eq!(self.0 & OWNER_TAG_MASK, OWNER_ALIGNED);
            // SAFETY: guaranteed by the caller.
            let header = unsafe { self.heap() };
            // SAFETY: guaranteed by the caller.
            let base = unsafe { header.as_ref().data_base };
            header.as_ptr() as usize - base.as_ptr() as usize
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

/// Tail header for heap allocations (native aligned and adopted vecs).
///
/// The header stores the exact allocation layout instead of deriving it from
/// canonical placement math. Native aligned allocations could re-derive their
/// layout, but adopted `Vec<u8>` allocations cannot: a vec's layout is
/// `(capacity, align = 1)` and its header lands wherever spare capacity
/// allows, so `dealloc` must use the stored values exactly.
#[repr(C)]
struct HeapHeader {
    /// Shared refcount; must stay at offset 0 (see [`OwnerRef::refs`]).
    refs: AtomicUsize,
    /// Base address of the allocation (and of the usable data region).
    data_base: NonNull<u8>,
    /// Exact size the allocation was created with.
    alloc_size: usize,
    /// Exact alignment the allocation was created with.
    alloc_align: usize,
}

/// Tail header for pooled allocations.
///
/// Stable fields (`refs` sentinel, `data_base`, `capacity`, `slot`) are
/// written once when the freelist creates the slot and never change as the
/// buffer moves between checked-out, thread-local, and global-free states.
/// The lease is live only while the buffer is outside the global freelist.
#[repr(C)]
pub(crate) struct PooledHeader {
    /// Shared refcount; must stay at offset 0 (see [`OwnerRef::refs`]).
    refs: AtomicUsize,
    /// Strong size-class reference; initialized at checkout, consumed at
    /// return ("lease-in-header").
    lease: MaybeUninit<SizeClassLease>,
    /// Base address of the usable data region.
    data_base: NonNull<u8>,
    /// Usable data capacity for the size class.
    capacity: usize,
    /// Stable slot id within the owning freelist.
    slot: u32,
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
/// This handle carries the allocation base pointer and its tail-header pointer.
/// While a buffer is parked in the global freelist or a thread-local cache, its
/// tail header has a stable refcount sentinel, data base pointer, capacity, and
/// slot id, but its lease is not live. Checkout initializes only the lease
/// field in place and returns an [`OwnerRef`] to that header.
///
/// `PooledBuffer` has no `Drop`: callers must return it to the originating
/// freelist or deallocate it with the exact layout used for allocation.
pub struct PooledBuffer {
    ptr: NonNull<u8>,
    header: NonNull<PooledHeader>,
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
            .field("ptr", &self.ptr)
            .field("header", &self.header)
            .finish()
    }
}

impl PooledBuffer {
    /// Creates a new uninitialized pooled allocation for `layout`.
    ///
    /// `layout` must be the full size-class layout, including usable bytes,
    /// tail padding, and [`PooledHeader`].
    #[inline]
    pub fn new(layout: Layout) -> Self {
        assert!(layout.size() > 0, "layout size must be non-zero");
        // SAFETY: layout is valid and non-zero sized.
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        // SAFETY: layout is the full pooled allocation layout.
        let header = unsafe { pooled_header_for_layout(ptr, layout) };
        Self { ptr, header }
    }

    /// Creates a new zero-initialized pooled allocation for `layout`.
    #[inline]
    pub fn new_zeroed(layout: Layout) -> Self {
        assert!(layout.size() > 0, "layout size must be non-zero");
        // SAFETY: layout is valid and non-zero sized.
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        // SAFETY: layout is the full pooled allocation layout.
        let header = unsafe { pooled_header_for_layout(ptr, layout) };
        Self { ptr, header }
    }

    /// Initializes invariant pooled header fields for a newly-created slot.
    ///
    /// This writes only fields that do not change while the buffer moves
    /// between checked-out, thread-local, and global-free states. The lease is
    /// intentionally left uninitialized until checkout.
    ///
    /// # Safety
    ///
    /// `layout` must be the full size-class layout used to allocate this buffer,
    /// `slot` must be the stable slot id assigned to the allocation, and
    /// `capacity` must be the usable data capacity for the size class.
    #[inline(always)]
    pub(crate) unsafe fn init_owner_header(
        self,
        layout: Layout,
        slot: u32,
        capacity: usize,
    ) -> Self {
        // SAFETY: the layout was used to allocate this buffer.
        debug_assert_eq!(self.header, unsafe {
            pooled_header_for_layout(self.ptr, layout)
        });
        // SAFETY: `header` is within the allocation and points at the stable
        // pooled header location. `MaybeUninit<SizeClassLease>` is valid with
        // uninitialized contents, so leaving `lease` unwritten is intentional.
        unsafe {
            addr_of_mut!((*self.header.as_ptr()).refs).write(AtomicUsize::new(1));
            addr_of_mut!((*self.header.as_ptr()).data_base).write(self.ptr);
            addr_of_mut!((*self.header.as_ptr()).capacity).write(capacity);
            addr_of_mut!((*self.header.as_ptr()).slot).write(slot);
        }
        self
    }

    /// Returns the usable data base pointer.
    #[inline(always)]
    pub const fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Returns the usable data capacity for this size-class buffer.
    ///
    /// # Safety
    ///
    /// The pooled header must have been initialized with
    /// [`Self::init_owner_header`].
    #[inline(always)]
    pub(crate) unsafe fn capacity(&self) -> usize {
        // SAFETY: guaranteed by the caller.
        unsafe { self.header.as_ref().capacity }
    }

    /// Returns the stable slot id for this size-class buffer.
    ///
    /// The slot is initialized once when the owning freelist creates this
    /// buffer and is needed only when the buffer returns to the global
    /// freelist.
    ///
    /// # Safety
    ///
    /// The pooled header must have been initialized with
    /// [`Self::init_owner_header`].
    #[inline(always)]
    pub(crate) unsafe fn slot(&self) -> u32 {
        // SAFETY: guaranteed by the caller.
        unsafe { self.header.as_ref().slot }
    }

    /// Initializes the pooled lease for a buffer leaving global state.
    ///
    /// # Safety
    ///
    /// This buffer must be checked out from the size class represented by
    /// `lease`, and the header must not currently contain a live lease.
    #[inline(always)]
    pub(crate) unsafe fn init_lease(&mut self, lease: SizeClassLease) {
        // SAFETY: header is within the allocation and properly aligned.
        unsafe {
            debug_assert_eq!((*self.header.as_ptr()).refs.load(Ordering::Relaxed), 1);
            addr_of_mut!((*self.header.as_ptr()).lease).write(MaybeUninit::new(lease));
        }
    }

    /// Returns a borrowed live lease.
    ///
    /// # Safety
    ///
    /// This pooled buffer must be checked out or parked in a thread-local cache,
    /// so its lease field is initialized.
    #[inline(always)]
    pub(crate) unsafe fn lease(&self) -> &SizeClassLease {
        // SAFETY: guaranteed by the caller.
        unsafe { &*self.header.as_ref().lease.as_ptr() }
    }

    /// Consumes the live lease from this header.
    ///
    /// # Safety
    ///
    /// This pooled buffer must have an initialized lease, and after this call
    /// the buffer must not be treated as checked out or locally cached until a
    /// new lease is initialized.
    #[inline(always)]
    pub(crate) unsafe fn take_lease(&mut self) -> SizeClassLease {
        // SAFETY: guaranteed by the caller.
        unsafe { self.header.as_mut().lease.assume_init_read() }
    }

    /// Returns the owner ref for a buffer whose lease is already initialized.
    ///
    /// # Safety
    ///
    /// The lease field must be initialized.
    #[inline(always)]
    pub(crate) unsafe fn owner_ref(&self) -> OwnerRef {
        // SAFETY: guaranteed by the caller.
        unsafe { OwnerRef::from_pooled(self.header) }
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

/// Allocates an untracked aligned buffer with a tail [`HeapHeader`].
///
/// The header is placed at `round_up(capacity, align_of::<HeapHeader>())`
/// past the base, and the layout alignment is raised to at least the header
/// alignment so both the data base and the header are aligned.
///
/// # Panics
///
/// Panics if `capacity == 0` or `alignment` is not a power of two.
#[inline]
pub(crate) fn allocate_aligned(
    capacity: usize,
    alignment: usize,
    zeroed: bool,
) -> (NonNull<u8>, OwnerRef) {
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
    (data, owner)
}

/// Converts `vec` into owned handle fields, adopting its allocation if it can
/// host a tail [`HeapHeader`] in spare capacity.
///
/// Adoption produces a fully native heap buffer with zero copies and zero
/// extra allocations: the header is placed at the highest header-aligned
/// address that fits below `base + cap`, and succeeds iff that address is at
/// or above `base + len` (see the module docs for the layout diagram).
///
/// Exactly-sized vecs (`len == cap`, the common case for `vec![0; n]` and
/// `collect()`) have no spare room; reallocating could copy, so they fall back
/// to the external owner path, which for `len == cap` is also `bytes`'
/// allocation-free promotable path.
pub(crate) fn owner_from_vec(vec: Vec<u8>) -> (NonNull<u8>, usize, OwnerRef) {
    if vec.is_empty() {
        return (NonNull::dangling(), 0, OwnerRef::empty());
    }

    let len = vec.len();
    let cap = vec.capacity();
    if cap >= size_of::<HeapHeader>() {
        let base_addr = vec.as_ptr() as usize;
        let header_addr = round_down(
            base_addr + cap - size_of::<HeapHeader>(),
            align_of::<HeapHeader>(),
        );
        if header_addr >= base_addr + len {
            // Adopt: dismantle the vec and place the header in its spare
            // capacity. The vec's allocation layout is `(cap, align = 1)`,
            // recorded exactly so release deallocates with the same layout.
            let mut vec = ManuallyDrop::new(vec);
            let base = vec.as_mut_ptr();
            // SAFETY: `base..base+cap` is one live allocation owned by the
            // dismantled vec; `header_addr` is header-aligned and
            // `header_addr + size_of::<HeapHeader>() <= base + cap`, so the
            // header write is in bounds. `base` is non-null (`len > 0`).
            unsafe {
                let header = base.add(header_addr - base_addr).cast::<HeapHeader>();
                header.write(HeapHeader {
                    refs: AtomicUsize::new(1),
                    data_base: NonNull::new_unchecked(base),
                    alloc_size: cap,
                    alloc_align: 1,
                });
                return (
                    NonNull::new_unchecked(base),
                    len,
                    OwnerRef::from_heap(NonNull::new_unchecked(header)),
                );
            }
        }
    }

    // No room for the header: hand the allocation to `Bytes` (zero-copy for
    // any `Vec<u8>`) behind an external owner.
    owner_from_bytes(Bytes::from(vec))
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

/// Returns the full layout for a pooled size class.
///
/// The layout covers `size` usable bytes, tail padding to header alignment,
/// and the [`PooledHeader`].
#[inline]
pub(crate) fn pooled_layout(size: usize, alignment: usize) -> Layout {
    let header_offset = round_up(size, align_of::<PooledHeader>());
    let total = header_offset
        .checked_add(size_of::<PooledHeader>())
        .expect("pooled layout size overflow");
    let layout_alignment = alignment.max(align_of::<PooledHeader>());
    Layout::from_size_align(total, layout_alignment).expect("alignment is a power of two")
}

/// Returns the full layout and header offset for a native aligned allocation.
#[inline]
fn heap_layout(capacity: usize, alignment: usize) -> (Layout, usize) {
    let header_offset = round_up(capacity, align_of::<HeapHeader>());
    let total = header_offset
        .checked_add(size_of::<HeapHeader>())
        .expect("heap layout size overflow");
    let layout_alignment = alignment.max(align_of::<HeapHeader>());
    let layout =
        Layout::from_size_align(total, layout_alignment).expect("alignment is a power of two");
    (layout, header_offset)
}

/// Locates the pooled tail header within a full size-class allocation.
///
/// # Safety
///
/// `ptr` must be the base of an allocation created with `layout`, and `layout`
/// must be a full pooled layout (see [`pooled_layout`]).
#[inline(always)]
unsafe fn pooled_header_for_layout(ptr: NonNull<u8>, layout: Layout) -> NonNull<PooledHeader> {
    let header_offset = layout
        .size()
        .checked_sub(size_of::<PooledHeader>())
        .expect("pooled layout includes header");
    // SAFETY: the size-class layout places the header at this offset.
    let header = unsafe { ptr.as_ptr().add(header_offset).cast::<PooledHeader>() };
    // SAFETY: pooled headers are placed within non-null allocations.
    unsafe { NonNull::new_unchecked(header) }
}

#[inline(always)]
fn round_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    value.checked_add(align - 1).expect("layout size overflow") & !(align - 1)
}

#[inline(always)]
fn round_down(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}

/// Releases a unique pooled owner into the thread-cache push fast path.
///
/// # Safety
///
/// No other handle may reference this allocation and the pooled lease must be
/// initialized.
#[inline(always)]
unsafe fn release_pooled(header: NonNull<PooledHeader>) {
    // SAFETY: guaranteed by the caller.
    let header_ref = unsafe { header.as_ref() };
    debug_assert_eq!(header_ref.refs.load(Ordering::Relaxed), 1);
    let buffer = PooledBuffer {
        ptr: header_ref.data_base,
        header,
    };
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
    let tag = owner.0 & OWNER_TAG_MASK;
    if tag == OWNER_ALIGNED {
        // SAFETY: unique heap owner (native aligned or adopted vec).
        unsafe { release_heap(owner.heap()) };
    } else if tag == OWNER_EXTERNAL {
        // SAFETY: unique external owner.
        unsafe { release_external(owner.external()) };
    }
    // Empty owners need no release work.
}

/// Releases a unique heap owner (native aligned or adopted vec).
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
    let base = header_ref.data_base;
    // SAFETY: `(alloc_size, alloc_align)` is exactly the layout the allocation
    // was created with (a heap-owner invariant).
    let layout =
        unsafe { Layout::from_size_align_unchecked(header_ref.alloc_size, header_ref.alloc_align) };
    // SAFETY: base/layout came from the global allocator; the header borrow
    // ended above (its fields were copied to locals).
    unsafe { dealloc(base.as_ptr(), layout) };
}

/// Releases a unique external owner.
///
/// # Safety
///
/// `owner` must come from `Box::leak` and no other handle may reference it.
#[inline]
unsafe fn release_external(owner: NonNull<ExternalOwner>) {
    // SAFETY: guaranteed by the caller.
    debug_assert_eq!(
        unsafe { owner.as_ref() }.refs.load(Ordering::Relaxed),
        1
    );
    // SAFETY: the owner box was leaked at construction; dropping it here drops
    // the inner `Bytes` exactly once.
    drop(unsafe { Box::from_raw(owner.as_ptr()) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iobuf::{cache_line_size, page_size};
    use commonware_utils::NZUsize;

    #[test]
    fn test_heap_layout_places_tail_header_after_data() {
        let page = page_size();
        let (data, owner) = allocate_aligned(4096, page, false);
        assert!((data.as_ptr() as usize).is_multiple_of(page));

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
        let (data, owner) = allocate_aligned(64, cache_line_size(), true);
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
        let (_, owner) = allocate_aligned(10, 1, false);
        // SAFETY: owner is unique and live.
        let capacity = unsafe { owner.usable_capacity() };
        assert_eq!(capacity, round_up(10, align_of::<HeapHeader>()));
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
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

        let expected_header =
            round_down(base_addr + cap - size_of::<HeapHeader>(), align_of::<HeapHeader>());
        // SAFETY: owner is unique and live.
        assert_eq!(unsafe { owner.data_base() }.as_ptr() as usize, base_addr);
        // SAFETY: owner is unique and live.
        assert_eq!(unsafe { owner.usable_capacity() }, expected_header - base_addr);
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
            let fits = cap >= size_of::<HeapHeader>()
                && round_down(
                    base_addr + cap - size_of::<HeapHeader>(),
                    align_of::<HeapHeader>(),
                ) >= base_addr + len;
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
    fn test_heap_owner_shared_clone_and_drop() {
        let (_, owner) = allocate_aligned(64, 1, false);
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
    fn test_pooled_layout_includes_header() {
        let size = 1024;
        let layout = pooled_layout(size, NZUsize!(64).get());
        assert!(layout.size() >= size + size_of::<PooledHeader>());
        assert!(layout.align() >= align_of::<PooledHeader>());
        assert!(layout.align() >= 64);
    }
}
