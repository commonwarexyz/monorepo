//! Allocation owners for [`super::IoBuf`] and [`super::IoBufMut`].
//!
//! The public I/O buffer handles are intentionally small and direct:
//!
//! ```text
//! IoBuf       = ptr, len,      owner
//! IoBufMut    = ptr, len, cap, owner
//! ```
//!
//! `bytes::Buf` and `bytes::BufMut` methods read only those handle fields. They
//! do not match on allocation kind and do not dispatch through a vtable. The
//! allocation kind is needed only for lifecycle operations such as clone, drop,
//! `freeze`, and `try_into_mut`, so that metadata is stored in an owner header
//! outside the hot cursor arithmetic.
//!
//! Native runtime allocations place the owner header at the tail of the same
//! allocation that stores data:
//!
//! ```text
//! [ usable data bytes ............ ][ padding ][ owner header ]
//! ^                                           ^
//! |                                           |
//! data/base pointer                           OwnerRef pointer
//! ```
//!
//! The usable data begins at the allocation base so alignment requested for I/O
//! is preserved. The header follows the data, after enough padding to satisfy
//! the header alignment. A sliced or advanced handle may point into the usable
//! region, so drop and `try_into_mut` derive the original base from the header,
//! not from the handle's current `ptr`.
//!
//! `OwnerRef` is a tagged header pointer. The low tag bits are available because
//! all headers are at least 4-byte aligned. Keeping the kind in the handle
//! avoids loading the header just to decide whether final release should
//! deallocate, return to the pool, or drop an external vector owner. That match
//! is cold compared with `remaining`, `chunk`, `advance`, `remaining_mut`,
//! `chunk_mut`, and `advance_mut`.
//!
//! `Vec<u8>` is the one intentionally external owner. A caller-supplied vector
//! allocation cannot be retrofitted with a tail header, so we move it into a
//! small `VecOwner` box and point the public handle at the vector's data. That
//! preserves payload zero-copy conversion from `Vec<u8>` while keeping native
//! aligned and pooled buffers allocation-resident.

use crate::iobuf::pool::{BufferPoolThreadCache, SizeClassLease};
use std::{
    alloc::{alloc, alloc_zeroed, dealloc, handle_alloc_error, Layout},
    mem::{align_of, size_of, ManuallyDrop, MaybeUninit},
    ptr::{addr_of_mut, NonNull},
    sync::atomic::{fence, AtomicUsize, Ordering},
};

const OWNER_EMPTY: usize = 0;
const OWNER_ALIGNED: usize = 0b01;
const OWNER_POOLED: usize = 0b10;
const OWNER_VEC: usize = 0b11;
const OWNER_TAG_MASK: usize = 0b11;

const _: () = assert!(align_of::<AlignedHeader>() >= 4);
const _: () = assert!(align_of::<PooledHeader>() >= 4);
const _: () = assert!(align_of::<VecOwner>() >= 4);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnerKind {
    Empty,
    Aligned,
    Pooled,
    Vec,
}

/// Tagged reference to an allocation owner.
///
/// The value is either zero (`OwnerKind::Empty`) or a pointer to one of the
/// owner headers with the low tag bits set:
///
/// ```text
/// raw header pointer:  0b....0000
/// aligned owner ref:   0b....0001
/// pooled owner ref:    0b....0010
/// vec owner ref:       0b....0011
/// ```
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

    /// Creates an aligned owner ref from a tail header pointer.
    ///
    /// # Safety
    ///
    /// `header` must be a valid aligned header pointer whose low tag bits are
    /// zero and whose backing allocation remains owned by this owner ref.
    #[inline(always)]
    pub(crate) unsafe fn from_aligned(header: NonNull<AlignedHeader>) -> Self {
        debug_assert_eq!(header.as_ptr() as usize & OWNER_TAG_MASK, 0);
        Self(header.as_ptr() as usize | OWNER_ALIGNED)
    }

    /// Creates a pooled owner ref from a tail header pointer.
    ///
    /// # Safety
    ///
    /// `header` must be a valid pooled header pointer whose low tag bits are
    /// zero and whose lease is initialized.
    #[inline(always)]
    pub(crate) unsafe fn from_pooled(header: NonNull<PooledHeader>) -> Self {
        debug_assert_eq!(header.as_ptr() as usize & OWNER_TAG_MASK, 0);
        Self(header.as_ptr() as usize | OWNER_POOLED)
    }

    /// Creates an external vector owner ref.
    ///
    /// # Safety
    ///
    /// `owner` must come from `Box::into_raw(Box<VecOwner>)` and be uniquely
    /// represented by this owner ref.
    #[inline(always)]
    unsafe fn from_vec(owner: NonNull<VecOwner>) -> Self {
        debug_assert_eq!(owner.as_ptr() as usize & OWNER_TAG_MASK, 0);
        Self(owner.as_ptr() as usize | OWNER_VEC)
    }

    #[inline(always)]
    fn kind(self) -> OwnerKind {
        match self.0 & OWNER_TAG_MASK {
            OWNER_EMPTY => OwnerKind::Empty,
            OWNER_ALIGNED => OwnerKind::Aligned,
            OWNER_POOLED => OwnerKind::Pooled,
            OWNER_VEC => OwnerKind::Vec,
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    unsafe fn aligned(self) -> NonNull<AlignedHeader> {
        debug_assert_eq!(self.kind(), OwnerKind::Aligned);
        let ptr = (self.0 & !OWNER_TAG_MASK) as *mut AlignedHeader;
        // SAFETY: guaranteed by the owner kind.
        unsafe { NonNull::new_unchecked(ptr) }
    }

    #[inline(always)]
    unsafe fn pooled(self) -> NonNull<PooledHeader> {
        debug_assert_eq!(self.kind(), OwnerKind::Pooled);
        let ptr = (self.0 & !OWNER_TAG_MASK) as *mut PooledHeader;
        // SAFETY: guaranteed by the owner kind.
        unsafe { NonNull::new_unchecked(ptr) }
    }

    #[inline(always)]
    unsafe fn vec(self) -> NonNull<VecOwner> {
        debug_assert_eq!(self.kind(), OwnerKind::Vec);
        let ptr = (self.0 & !OWNER_TAG_MASK) as *mut VecOwner;
        // SAFETY: guaranteed by the owner kind.
        unsafe { NonNull::new_unchecked(ptr) }
    }

    /// Returns the shared refcount for a non-empty owner.
    ///
    /// # Safety
    ///
    /// `self` must not be empty.
    #[inline(always)]
    unsafe fn refs(self) -> &'static AtomicUsize {
        match self.kind() {
            OwnerKind::Empty => unreachable!("empty owners have no refcount"),
            OwnerKind::Aligned => {
                // SAFETY: owner kind proves the header type.
                unsafe { &self.aligned().as_ref().refs }
            }
            OwnerKind::Pooled => {
                // SAFETY: owner kind proves the header type.
                unsafe { &self.pooled().as_ref().refs }
            }
            OwnerKind::Vec => {
                // SAFETY: owner kind proves the header type.
                unsafe { &self.vec().as_ref().refs }
            }
        }
    }

    /// Retains one immutable shared view.
    ///
    /// Mutable buffers never call this. Their owner is unique until `freeze`
    /// hands it to an immutable `IoBuf`.
    #[inline(always)]
    pub(crate) unsafe fn clone_shared(self) {
        if self.is_empty() {
            return;
        }
        // SAFETY: non-empty owners have a valid refcount.
        let old = unsafe { self.refs() }.fetch_add(1, Ordering::Relaxed);
        debug_assert!(old >= 1);
    }

    /// Drops one immutable shared view.
    ///
    /// The refcount deliberately uses `1` as the reusable sentinel. Pooled
    /// buffers sit in the pool with `refs == 1`, checked-out mutable buffers
    /// keep `refs == 1`, and a single immutable owner has `refs == 1`. Final
    /// drop therefore returns or deallocates without first writing zero.
    ///
    /// If two shared owners drop concurrently, one may observe `> 1` and then
    /// race with another drop that reduces the count to `1`. The `old == 1`
    /// branch handles that race by restoring the sentinel before final release.
    #[inline(always)]
    pub(crate) unsafe fn drop_shared(self) {
        if self.is_empty() {
            return;
        }

        // SAFETY: non-empty owners have a valid refcount.
        let refs = unsafe { self.refs() };
        if refs.load(Ordering::Acquire) == 1 {
            // SAFETY: this is the final shared owner.
            unsafe { self.release_unique() };
            return;
        }

        let old = refs.fetch_sub(1, Ordering::Release);
        debug_assert!(old >= 1);
        if old == 1 {
            fence(Ordering::Acquire);
            refs.store(1, Ordering::Relaxed);
            // SAFETY: this drop won the final-owner race.
            unsafe { self.release_unique() };
        }
    }

    /// Releases a uniquely-owned allocation.
    ///
    /// This is used by `IoBufMut::drop`, empty `freeze`, and final immutable
    /// drop. It must not run while another handle still aliases the allocation.
    #[inline(always)]
    pub(crate) unsafe fn release_unique(self) {
        let tag = self.0 & OWNER_TAG_MASK;
        if tag == OWNER_POOLED {
            // SAFETY: unique pooled owner with initialized lease.
            unsafe { release_pooled(self.pooled()) };
        } else if tag == OWNER_EMPTY {
            // Nothing to release.
        } else if tag == OWNER_ALIGNED {
            // SAFETY: unique aligned owner.
            unsafe { release_aligned(self.aligned()) };
        } else {
            debug_assert_eq!(tag, OWNER_VEC);
            // SAFETY: unique external vector owner.
            unsafe { release_vec(self.vec()) };
        }
    }

    /// Releases a uniquely-owned mutable allocation.
    ///
    /// Mutable handles are expected to end in the pooled or aligned cases. Keep
    /// those paths as direct branches and outline the empty/vector cases so LLVM
    /// does not lower the mutable hot path as a dense owner-tag jump table.
    ///
    /// # Safety
    ///
    /// This must be called only for a uniquely-owned mutable handle.
    #[inline(always)]
    pub(crate) unsafe fn release_unique_mut(self) {
        let tag = self.0 & OWNER_TAG_MASK;
        if tag == OWNER_POOLED {
            // SAFETY: unique pooled owner with initialized lease.
            unsafe { release_pooled(self.pooled()) };
        } else if tag == OWNER_ALIGNED {
            // SAFETY: unique aligned owner.
            unsafe { release_aligned(self.aligned()) };
        } else {
            // SAFETY: same precondition as this method.
            unsafe { release_unique_mut_cold(self, tag) };
        }
    }

    /// Returns true when this owner has exactly one immutable handle.
    ///
    /// Empty non-zero buffers are static and cannot become mutable.
    #[inline(always)]
    pub(crate) unsafe fn is_unique(self) -> bool {
        if self.is_empty() {
            return false;
        }
        // SAFETY: non-empty owners have a valid refcount.
        unsafe { self.refs() }.load(Ordering::Acquire) == 1
    }

    /// Returns the base pointer for the usable data region.
    ///
    /// # Safety
    ///
    /// `self` must be non-empty.
    #[inline(always)]
    pub(crate) unsafe fn data_base(self) -> NonNull<u8> {
        match self.kind() {
            OwnerKind::Empty => unreachable!("static buffers have no owner base"),
            OwnerKind::Aligned => {
                // SAFETY: owner kind proves the header type.
                let header = unsafe { self.aligned() };
                // SAFETY: header belongs to an aligned allocation.
                unsafe { aligned_data_base(header) }
            }
            OwnerKind::Pooled => {
                // SAFETY: owner kind proves the header type.
                let header = unsafe { self.pooled() };
                // SAFETY: header belongs to a pooled allocation.
                unsafe { pooled_data_base(header) }
            }
            OwnerKind::Vec => {
                // SAFETY: owner kind proves the header type.
                let owner = unsafe { self.vec().as_ref() };
                let ptr = owner.vec.as_ptr().cast_mut();
                NonNull::new(ptr).unwrap_or_else(NonNull::dangling)
            }
        }
    }

    /// Returns the usable data capacity for this owner.
    ///
    /// # Safety
    ///
    /// `self` must be non-empty.
    #[inline(always)]
    pub(crate) unsafe fn usable_capacity(self) -> usize {
        match self.kind() {
            OwnerKind::Empty => unreachable!("static buffers have no owner capacity"),
            OwnerKind::Aligned => {
                // SAFETY: owner kind proves the header type.
                unsafe { self.aligned().as_ref().capacity }
            }
            OwnerKind::Pooled => {
                // SAFETY: owner kind proves the header type.
                unsafe { self.pooled().as_ref().capacity }
            }
            OwnerKind::Vec => {
                // SAFETY: owner kind proves the header type.
                unsafe { self.vec().as_ref().vec.capacity() }
            }
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

/// Tail header for untracked aligned allocations.
#[repr(C)]
pub(crate) struct AlignedHeader {
    refs: AtomicUsize,
    capacity: usize,
    layout_alignment: usize,
}

/// Tail header for pooled allocations.
#[repr(C)]
pub(crate) struct PooledHeader {
    refs: AtomicUsize,
    lease: MaybeUninit<SizeClassLease>,
    data_base: NonNull<u8>,
    capacity: usize,
    slot: u32,
}

/// External owner for caller-supplied vectors.
#[repr(C)]
struct VecOwner {
    refs: AtomicUsize,
    vec: ManuallyDrop<Vec<u8>>,
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
    /// The capacity is initialized once when the owning freelist creates this
    /// slot and remains stable while the buffer moves through pool states.
    #[inline(always)]
    pub(crate) unsafe fn capacity(&self) -> usize {
        // SAFETY: caller guarantees the pooled header has been initialized.
        unsafe { self.header.as_ref().capacity }
    }

    /// Returns the stable slot id for this size-class buffer.
    ///
    /// The slot is initialized once when the owning freelist creates this
    /// buffer and is needed only when the buffer returns to the global
    /// freelist.
    #[inline(always)]
    pub(crate) unsafe fn slot(&self) -> u32 {
        // SAFETY: caller guarantees the pooled header has been initialized.
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

/// Allocate an untracked aligned buffer with a tail [`AlignedHeader`].
#[inline]
pub(crate) fn allocate_aligned(
    capacity: usize,
    alignment: usize,
    zeroed: bool,
) -> (NonNull<u8>, OwnerRef) {
    assert!(capacity > 0, "capacity must be greater than zero");
    let (layout, header_offset) = aligned_layout(capacity, alignment);
    let ptr = if zeroed {
        // SAFETY: layout is valid and non-zero sized.
        unsafe { alloc_zeroed(layout) }
    } else {
        // SAFETY: layout is valid and non-zero sized.
        unsafe { alloc(layout) }
    };
    let data = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
    // SAFETY: the computed layout includes the header at `header_offset`.
    let header = unsafe { data.as_ptr().add(header_offset).cast::<AlignedHeader>() };
    // SAFETY: header is within the allocation and properly aligned.
    let owner = unsafe {
        header.write(AlignedHeader {
            refs: AtomicUsize::new(1),
            capacity,
            layout_alignment: layout.align(),
        });
        OwnerRef::from_aligned(NonNull::new_unchecked(header))
    };
    (data, owner)
}

/// Moves `vec` into an external owner and returns direct handle fields.
#[inline]
pub(crate) fn owner_from_vec(mut vec: Vec<u8>) -> (NonNull<u8>, usize, usize, OwnerRef) {
    if vec.is_empty() {
        return (NonNull::dangling(), 0, 0, OwnerRef::empty());
    }

    let ptr = NonNull::new(vec.as_mut_ptr()).expect("non-empty Vec has non-null data");
    let len = vec.len();
    let cap = vec.capacity();
    let owner = Box::new(VecOwner {
        refs: AtomicUsize::new(1),
        vec: ManuallyDrop::new(vec),
    });
    let owner = NonNull::new(Box::into_raw(owner)).expect("Box::into_raw returned null");
    // SAFETY: pointer came from `Box::into_raw`.
    let owner = unsafe { OwnerRef::from_vec(owner) };
    (ptr, len, cap, owner)
}

/// Returns the full layout for a pooled size class.
#[inline]
pub(crate) fn pooled_layout(size: usize, alignment: usize) -> Layout {
    let header_offset = pooled_header_offset(size);
    let total = header_offset
        .checked_add(size_of::<PooledHeader>())
        .expect("pooled layout size overflow");
    let layout_alignment = alignment.max(align_of::<PooledHeader>());
    Layout::from_size_align(total, layout_alignment).expect("alignment is a power of two")
}

/// Returns the full layout and header offset for an aligned allocation.
#[inline]
fn aligned_layout(capacity: usize, alignment: usize) -> (Layout, usize) {
    let header_offset = aligned_header_offset(capacity);
    let total = header_offset
        .checked_add(size_of::<AlignedHeader>())
        .expect("aligned layout size overflow");
    let layout_alignment = alignment.max(align_of::<AlignedHeader>());
    let layout = Layout::from_size_align(total, layout_alignment)
        .expect("alignment is a power of two");
    (layout, header_offset)
}

#[inline(always)]
fn aligned_header_offset(capacity: usize) -> usize {
    round_up(capacity, align_of::<AlignedHeader>())
}

#[inline(always)]
fn pooled_header_offset(size: usize) -> usize {
    round_up(size, align_of::<PooledHeader>())
}

#[inline(always)]
unsafe fn pooled_header_for_layout(
    ptr: NonNull<u8>,
    layout: Layout,
) -> NonNull<PooledHeader> {
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
    value
        .checked_add(align - 1)
        .expect("layout size overflow")
        & !(align - 1)
}

/// Returns the original data base for an aligned header.
///
/// # Safety
///
/// `header` must point to a live [`AlignedHeader`] in a native aligned
/// allocation.
#[inline(always)]
unsafe fn aligned_data_base(header: NonNull<AlignedHeader>) -> NonNull<u8> {
    // SAFETY: guaranteed by the caller.
    let header_ref = unsafe { header.as_ref() };
    let header_offset = aligned_header_offset(header_ref.capacity);
    // SAFETY: the header was placed exactly `header_offset` bytes after base.
    let base = unsafe { header.as_ptr().cast::<u8>().sub(header_offset) };
    // SAFETY: allocation bases are non-null.
    unsafe { NonNull::new_unchecked(base) }
}

/// Returns the original data base for a pooled header.
///
/// # Safety
///
/// `header` must point to a live [`PooledHeader`].
#[inline(always)]
unsafe fn pooled_data_base(header: NonNull<PooledHeader>) -> NonNull<u8> {
    // SAFETY: guaranteed by the caller.
    unsafe { header.as_ref().data_base }
}

/// Releases a unique aligned owner.
///
/// # Safety
///
/// No other handle may reference this allocation.
#[inline(always)]
unsafe fn release_aligned(header: NonNull<AlignedHeader>) {
    // SAFETY: guaranteed by the caller.
    let header_ref = unsafe { header.as_ref() };
    debug_assert_eq!(header_ref.refs.load(Ordering::Relaxed), 1);
    let header_offset = aligned_header_offset(header_ref.capacity);
    let total = header_offset + size_of::<AlignedHeader>();
    let layout = Layout::from_size_align(total, header_ref.layout_alignment)
        .expect("stored layout is valid");
    // SAFETY: this is the original allocation base and layout.
    let base = unsafe { header.as_ptr().cast::<u8>().sub(header_offset) };
    // SAFETY: base/layout came from the global allocator.
    unsafe { dealloc(base, layout) };
}

/// Releases a unique pooled owner.
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
    let data_base = header_ref.data_base;
    let buffer = PooledBuffer {
        ptr: data_base,
        header,
    };
    BufferPoolThreadCache::push(buffer);
}

/// Releases mutable owners that are not expected in the allocation/drop hot path.
///
/// # Safety
///
/// No other handle may reference this allocation. `tag` must be `owner`'s low
/// owner tag bits.
#[cold]
#[inline(never)]
unsafe fn release_unique_mut_cold(owner: OwnerRef, tag: usize) {
    if tag == OWNER_EMPTY {
        return;
    }
    debug_assert_eq!(tag, OWNER_VEC);
    // SAFETY: non-empty non-pooled non-aligned mutable owners are external
    // vector owners.
    unsafe { release_vec(owner.vec()) };
}

/// Releases a unique external vector owner.
///
/// # Safety
///
/// `owner` must come from `Box::into_raw` and no other handle may reference it.
#[inline(always)]
unsafe fn release_vec(owner: NonNull<VecOwner>) {
    // SAFETY: the owner was allocated with `Box::into_raw`.
    let owner = unsafe { Box::from_raw(owner.as_ptr()) };
    let VecOwner { refs: _, vec } = *owner;
    drop(ManuallyDrop::into_inner(vec));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iobuf::{cache_line_size, page_size};
    use commonware_utils::NZUsize;

    #[test]
    fn test_aligned_layout_places_tail_header_after_data() {
        let page = page_size();
        let (data, owner) = allocate_aligned(4096, page, false);
        assert!((data.as_ptr() as usize).is_multiple_of(page));

        // SAFETY: owner was just allocated and is live.
        let header = unsafe { owner.aligned() };
        assert!((header.as_ptr() as usize).is_multiple_of(align_of::<AlignedHeader>()));
        assert!(header.as_ptr() as usize >= data.as_ptr() as usize + 4096);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
    }

    #[test]
    fn test_aligned_zeroed_only_exposes_usable_region() {
        let (data, owner) = allocate_aligned(64, cache_line_size(), true);
        // SAFETY: data points at a zeroed usable region of length 64.
        let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr(), 64) };
        assert_eq!(bytes, &[0u8; 64]);
        // SAFETY: owner is unique and must be released by this test.
        unsafe { owner.release_unique() };
    }

    #[test]
    fn test_vec_owner_refcount() {
        let (_, len, cap, owner) = owner_from_vec(vec![1u8, 2, 3]);
        assert_eq!(len, 3);
        assert!(cap >= 3);
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
    fn test_empty_vec_has_no_owner() {
        let (_, len, cap, owner) = owner_from_vec(Vec::new());
        assert_eq!(len, 0);
        assert_eq!(cap, 0);
        assert!(owner.is_empty());
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
