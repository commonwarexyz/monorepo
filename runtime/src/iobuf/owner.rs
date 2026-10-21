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
//! through a vtable.
//!
//! Only lifecycle and ownership-transferring operations such as clone, drop,
//! `freeze`, `copy_to_bytes`, and `try_into_mut` use the owner, so ownership
//! metadata stays outside the hot cursor arithmetic.
//!
//! # Owner states
//!
//! The owner is one word in one of three states:
//!
//! ```text
//! state        word                               owns
//! ----------   --------------------------------   ---------------------------
//! empty        null                               nothing
//! descriptor   bit 0 set: size, alignment, tail   a native allocation, alone
//! record       pointer to an Owner record         one reference to the record
//! ```
//!
//! Empty owners serve empty views and `'static` slices. A [`Descriptor`] packs
//! the layout of a native allocation that exactly one handle owns, plus its
//! tail: the bytes between the end of the view and the end of the allocation.
//! No record exists for it. The base is not stored, because cursor operations
//! never move the end of a view:
//!
//! ```text
//! IoBuf:    base = ptr + len + tail - size
//! IoBufMut: base = ptr + cap - size          (the tail is always 0)
//! ```
//!
//! The word carries no provenance, and the recovered base keeps the provenance
//! of the handle's data pointer. On 64-bit targets, bits 1..7 hold log2 of the
//! alignment, bits 7..24 the tail, and bits 24..64 the size. On 32-bit
//! targets, bits 1..8 hold the tail and bits 8..32 the size, for alignment 1
//! only. A native allocation whose fields do not fit gets a record instead.
//!
//! A record is one heap-allocated [`Owner`] with the shared refcount and the
//! [`Storage`] it keeps alive. [`OwnerRef`] is a word known to be empty or a
//! record, and refcount operations take it:
//!
//! ```text
//! Owner { refs, Native { base, layout } }   shared heap buffers and adopted vecs
//! Owner { refs, External(bytes) }           caller-supplied Bytes
//! ```
//!
//! Refcount operations follow the pointer to `refs` without examining the
//! storage. The storage is examined only on final release and by the
//! operations that transfer ownership.
//!
//! # Promotion
//!
//! `IoBufMut` stores its word as plain data ([`OwnerWord`]). `IoBuf` stores it
//! in an atomic [`OwnerCell`], because the first clone or slice of a
//! descriptor handle replaces the descriptor with a record through a shared
//! borrow:
//!
//! 1. Allocate a record with the native storage recovered from the source
//!    view and two references, one for the source and one for the new view.
//! 2. Compare-exchange the cell from the observed descriptor to the record,
//!    with Release on success and Acquire on failure.
//! 3. On failure, free only the unpublished record, not the data, and take
//!    one reference on the record another clone published.
//!
//! The borrowed source keeps its reference to the published record, and a
//! record never turns back into a descriptor, so a failed exchange always
//! observes that record. Clone and slice load the cell with Acquire, so a
//! handle that observes a record also observes its initialization. Partial
//! splits and drains hold `&mut` and promote with a plain store.
//!
//! # Allocation layouts
//!
//! A heap buffer's data allocation has exactly the requested size and
//! alignment. While one handle owns it, the descriptor in that handle is all
//! of its metadata:
//!
//! ```text
//! [ usable data bytes ............ ]      handle owner = descriptor
//! ^
//! data base (alignment preserved)
//! ```
//!
//! The first share moves the metadata into a separate small record:
//!
//! ```text
//! [ usable data bytes ............ ]      [ refs | Native { base, layout } ]
//! ^                                        ^
//! data base                                OwnerRef target
//! ```
//!
//! `freeze` keeps a descriptor and stores the spare capacity as its tail. It
//! allocates the record only when that tail does not fit. Dropping a
//! descriptor handle frees the data directly, and `try_into_mut` on one
//! returns the tail as capacity without a refcount check. A record handle
//! recovers the original base from the record instead.
//!
//! `From<Vec<u8>>` adopts any vec with an allocation without copying, with
//! the layout `Vec<u8>` allocated the data with (`capacity` bytes at
//! alignment 1), so release frees it as it was created. The buffer's capacity
//! is the vec's full capacity, and the frozen buffer supports mutable recovery
//! through `try_into_mut`.
//!
//! `Bytes` values are owned externally. Their record exists from the start,
//! holds the `Bytes`, and the handle points directly into its payload:
//!
//! ```text
//! IoBuf.ptr ------------------------------v
//! [ refs | External(bytes) ]  [ payload bytes ............ ]
//! ^ OwnerRef target            ^ kept alive by the inner Bytes
//! ```
//!
//! Clones, slices, and drops of the `IoBuf` touch only the record's refcount.
//! The inner `Bytes` refcount is touched only at final release and by the
//! `slice_ref` fast paths (partial `copy_to_bytes` drains and
//! `Bytes::from(IoBuf)` conversions of external-backed views).
//!
//! # Refcount state machine
//!
//! The refcount uses `1` as the unique-owner sentinel, so the common final
//! release performs no refcount write:
//!
//! ```text
//! state                                refs
//! ---------------------------------   -------------------
//! promoted from a descriptor           2
//! unique mutable (IoBufMut)            1 (never changed)
//! single immutable owner (IoBuf)       1
//! N shared immutable owners            N
//! final release after a drop race      0
//! ```
//!
//! `IoBufMut` never changes the refcount. It holds a record only when the
//! layout does not fit a descriptor or when `try_into_mut` recovers an
//! immutable handle that holds one. The record stays at the sentinel until
//! `freeze` hands the owner word to an immutable `IoBuf`. A mutable final
//! release only reads it, to check that the owner is unshared.

use bytes::Bytes;
use std::{
    alloc::{Layout, alloc, alloc_zeroed, dealloc, handle_alloc_error},
    mem::ManuallyDrop,
    ptr::{self, NonNull},
    sync::atomic::Ordering,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::atomic::{AtomicPtr, AtomicUsize, fence};
    } else {
        use std::sync::atomic::{AtomicPtr, AtomicUsize, fence};
    }
}

/// Refcount ceiling shared with `Arc` and `bytes`.
///
/// A refcount above `isize::MAX` can only result from a leak loop (`mem::forget`
/// in a cycle). Allowing it to wrap would turn into use-after-free, so
/// [`OwnerRef::clone_shared`] aborts instead.
const MAX_REFCOUNT: usize = isize::MAX as usize;

/// Bit 0 of an owner word, set for descriptors and clear for record pointers.
const TAG: usize = 1;

// Record pointers must leave the tag bit clear.
const _: () = assert!(align_of::<Owner>() >= 2);

/// Bit layout of a descriptor word for one pointer width.
///
/// From the low bit up, a word holds the tag (1 bit), log2 of the alignment
/// (`align_bits`), the tail (`tail_bits`), and the allocation size
/// (`size_bits`). The helpers work on `u64` so every format can be checked on
/// any host.
#[derive(Clone, Copy, Debug)]
struct Format {
    align_bits: u32,
    tail_bits: u32,
    size_bits: u32,
}

/// Fields of a packed descriptor word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fields {
    size: usize,
    align: usize,
    tail: usize,
}

impl Format {
    /// Number of bits a word uses, including the tag.
    #[inline(always)]
    const fn bits(self) -> u32 {
        1 + self.align_bits + self.tail_bits + self.size_bits
    }

    #[inline(always)]
    const fn tail_shift(self) -> u32 {
        1 + self.align_bits
    }

    #[inline(always)]
    const fn size_shift(self) -> u32 {
        self.tail_shift() + self.tail_bits
    }

    #[inline(always)]
    const fn tail_mask(self) -> u64 {
        ((1 << self.tail_bits) - 1) << self.tail_shift()
    }

    /// Returns `tail` in its field position, or `None` if it does not fit.
    #[inline(always)]
    const fn tail_field(self, tail: usize) -> Option<u64> {
        let tail = tail as u64;
        if tail >> self.tail_bits != 0 {
            return None;
        }
        Some(tail << self.tail_shift())
    }

    /// Packs `layout` and `tail`, or returns `None` when the size is zero or
    /// a field does not fit.
    #[inline(always)]
    const fn pack(self, layout: Layout, tail: usize) -> Option<u64> {
        let size = layout.size() as u64;
        let log2_align = layout.align().trailing_zeros() as u64;
        if size == 0 || size >> self.size_bits != 0 || log2_align >> self.align_bits != 0 {
            return None;
        }
        match self.tail_field(tail) {
            Some(tail) => Some((size << self.size_shift()) | tail | (log2_align << 1) | TAG as u64),
            None => None,
        }
    }

    /// Replaces the tail of a packed word, or returns `None` if it does not
    /// fit.
    #[inline(always)]
    const fn with_tail(self, word: u64, tail: usize) -> Option<u64> {
        match self.tail_field(tail) {
            Some(tail) => Some((word & !self.tail_mask()) | tail),
            None => None,
        }
    }

    /// Unpacks a word built by [`Self::pack`] or [`Self::with_tail`].
    #[inline(always)]
    const fn unpack(self, word: u64) -> Fields {
        let log2_align = (word >> 1) & ((1 << self.align_bits) - 1);
        Fields {
            size: (word >> self.size_shift()) as usize,
            align: 1 << log2_align,
            tail: ((word & self.tail_mask()) >> self.tail_shift()) as usize,
        }
    }
}

/// 64-bit format: any alignment, tails below 128 KiB, sizes below 1 TiB.
const FORMAT_64: Format = Format {
    align_bits: 6,
    tail_bits: 17,
    size_bits: 40,
};

/// 32-bit format: alignment 1 only, tails below 128 bytes, sizes below 16 MiB.
const FORMAT_32: Format = Format {
    align_bits: 0,
    tail_bits: 7,
    size_bits: 24,
};

const _: () = assert!(FORMAT_64.bits() == 64 && FORMAT_32.bits() == 32);

cfg_if::cfg_if! {
    if #[cfg(target_pointer_width = "64")] {
        /// Descriptor format of this target.
        const FORMAT: Format = FORMAT_64;
    } else if #[cfg(target_pointer_width = "32")] {
        /// Descriptor format of this target.
        const FORMAT: Format = FORMAT_32;
    } else {
        /// Describes no allocation, so every native allocation gets a record.
        const FORMAT: Format = Format {
            align_bits: 0,
            tail_bits: 0,
            size_bits: 0,
        };
    }
}

const _: () = assert!(FORMAT.bits() <= usize::BITS);

/// Owner word of a native allocation that one handle owns without a record.
///
/// The word was packed by [`FORMAT`] from the allocation's layout, so bit 0 is
/// set and the unpacked size and alignment form a valid layout of nonzero
/// size. The tail counts the allocation bytes after the end of the holding
/// handle's view, and is always 0 in an `IoBufMut`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Descriptor(usize);

impl Descriptor {
    /// Describes an allocation with `layout` and `tail`, or returns `None`
    /// when the fields do not fit.
    #[inline(always)]
    const fn new(layout: Layout, tail: usize) -> Option<Self> {
        match FORMAT.pack(layout, tail) {
            Some(word) => Some(Self(word as usize)),
            None => None,
        }
    }

    #[inline(always)]
    const fn fields(self) -> Fields {
        FORMAT.unpack(self.0 as u64)
    }

    /// Layout the allocation was made with.
    #[inline(always)]
    const fn layout(self) -> Layout {
        let Fields { size, align, .. } = self.fields();
        // SAFETY: the word was packed from a valid layout with this size and
        // alignment.
        unsafe { Layout::from_size_align_unchecked(size, align) }
    }

    /// Allocation bytes after the end of the holding handle's view.
    #[inline(always)]
    pub(crate) const fn tail(self) -> usize {
        self.fields().tail
    }

    /// Returns this descriptor with its tail replaced, or `None` when `tail`
    /// does not fit.
    #[inline(always)]
    const fn with_tail(self, tail: usize) -> Option<Self> {
        match FORMAT.with_tail(self.0 as u64, tail) {
            Some(word) => Some(Self(word as usize)),
            None => None,
        }
    }

    /// Returns this descriptor with a zero tail.
    #[inline(always)]
    pub(crate) const fn without_tail(self) -> Self {
        Self(self.0 & !(FORMAT.tail_mask() as usize))
    }

    /// Recovers the allocation base from the holding handle's view.
    ///
    /// # Safety
    ///
    /// `ptr` must be the data pointer of the handle that holds this
    /// descriptor, and `extent` its `len` for an `IoBuf` or its `cap` for an
    /// `IoBufMut`.
    #[inline(always)]
    const unsafe fn base(self, ptr: NonNull<u8>, extent: usize) -> NonNull<u8> {
        let Fields { size, tail, .. } = self.fields();
        // The handle invariant gives offset + extent + tail == size.
        let offset = size.wrapping_sub(tail).wrapping_sub(extent);
        // SAFETY: by the caller's guarantee, `ptr` lies `offset` bytes past
        // the base of the allocation its provenance covers.
        unsafe { ptr.sub(offset) }
    }

    /// Allocates a record with `refs` references that takes over the
    /// allocation.
    ///
    /// # Safety
    ///
    /// As for [`Self::base`].
    #[inline(always)]
    unsafe fn record(self, ptr: NonNull<u8>, extent: usize, refs: usize) -> OwnerRef {
        // SAFETY: guaranteed by the caller.
        let base = unsafe { self.base(ptr, extent) };
        OwnerRef::with_refs(
            Storage::Native {
                base,
                layout: self.layout(),
            },
            refs,
        )
    }

    /// Allocates a record with two references that takes over the allocation:
    /// one for the holding handle and one for a new view.
    ///
    /// Exclusive promotion calls this outlined helper with values and gets
    /// the record back by value.
    ///
    /// # Safety
    ///
    /// As for [`Self::base`].
    #[cold]
    #[inline(never)]
    unsafe fn into_shared_record(self, ptr: NonNull<u8>, len: usize) -> OwnerRef {
        // SAFETY: guaranteed by the caller.
        unsafe { self.record(ptr, len, 2) }
    }

    /// Allocates a record with one reference that takes over the allocation
    /// of a mutable handle being frozen.
    ///
    /// `freeze` calls this outlined helper with values and gets the record
    /// back by value, so its inlined fast path keeps the handle fields in
    /// registers.
    ///
    /// # Safety
    ///
    /// As for [`Self::base`], with the mutable handle's `cap` as `extent`.
    #[cold]
    #[inline(never)]
    unsafe fn into_unique_record(self, ptr: NonNull<u8>, cap: usize) -> OwnerRef {
        // SAFETY: guaranteed by the caller.
        unsafe { self.record(ptr, cap, 1) }
    }

    /// Frees the allocation.
    ///
    /// # Safety
    ///
    /// As for [`Self::base`], and the holding handle gives up its ownership.
    #[inline(always)]
    unsafe fn release(self, ptr: NonNull<u8>, extent: usize) {
        // SAFETY: the holding handle owns the allocation alone, which the
        // global allocator made with this layout at the recovered base.
        unsafe { dealloc(self.base(ptr, extent).as_ptr(), self.layout()) };
    }
}

/// Owner word of a handle: empty, a [`Descriptor`], or a record.
///
/// The word is plain data. Copying it does not copy ownership, which belongs
/// to the handle that stores it.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct OwnerWord(*mut Owner);

// Keep the owner word pointer-sized in both buffer handles.
const _: () = assert!(size_of::<OwnerWord>() == size_of::<*mut Owner>());

/// An owner word split by state.
pub(crate) enum OwnerState {
    /// An empty word or a record.
    Ref(OwnerRef),
    /// A descriptor.
    Descriptor(Descriptor),
}

impl From<OwnerRef> for OwnerWord {
    #[inline(always)]
    fn from(owner: OwnerRef) -> Self {
        Self(owner.as_ptr())
    }
}

impl From<Descriptor> for OwnerWord {
    #[inline(always)]
    fn from(descriptor: Descriptor) -> Self {
        Self(ptr::without_provenance_mut(descriptor.0))
    }
}

impl OwnerWord {
    #[inline(always)]
    pub(crate) const fn empty() -> Self {
        Self(ptr::null_mut())
    }

    #[inline(always)]
    pub(crate) fn state(self) -> OwnerState {
        if self.0.addr() & TAG != 0 {
            OwnerState::Descriptor(Descriptor(self.0.addr()))
        } else {
            OwnerState::Ref(OwnerRef(NonNull::new(self.0)))
        }
    }

    /// Owner word of a native allocation one handle owns: a descriptor when
    /// the layout fits one, and a record otherwise.
    #[inline(always)]
    fn native(base: NonNull<u8>, layout: Layout) -> Self {
        Descriptor::new(layout, 0).map_or_else(|| native_record(base, layout).into(), Self::from)
    }

    /// Allocates a buffer of exactly `capacity` bytes at `alignment` and returns
    /// the data pointer and its owner word.
    ///
    /// # Panics
    ///
    /// Panics if `capacity == 0`, if `alignment` is not a power of two, or if
    /// the layout exceeds `Layout`'s `isize::MAX` bound.
    #[inline]
    pub(crate) fn allocate(capacity: usize, alignment: usize, zeroed: bool) -> (NonNull<u8>, Self) {
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
        let base = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        (base, Self::native(base, layout))
    }

    /// Adopts `vec`'s allocation as the data allocation without copying.
    ///
    /// Returns the data pointer, the readable length, the capacity, and the
    /// owner word. The word describes the layout `Vec<u8>` allocated the data
    /// with (`capacity` bytes at alignment 1), so release frees it exactly as
    /// it was allocated.
    ///
    /// # Panics
    ///
    /// Panics if the vec has no allocation (`capacity() == 0`).
    #[inline]
    pub(crate) fn adopt_vec(vec: Vec<u8>) -> (NonNull<u8>, usize, usize, Self) {
        let mut vec = ManuallyDrop::new(vec);
        let len = vec.len();
        let cap = vec.capacity();
        assert!(cap > 0, "capacity must be greater than zero");
        let layout = Layout::array::<u8>(cap).expect("vec capacity must fit a layout");
        // SAFETY: a vec with non-zero capacity owns a live, non-null
        // allocation that `Vec<u8>` created with `layout` through the global
        // allocator. `ManuallyDrop` keeps the vec from freeing it, so the
        // returned word becomes its only owner.
        let base = unsafe { NonNull::new_unchecked(vec.as_mut_ptr()) };
        (base, len, cap, Self::native(base, layout))
    }

    /// Converts the word of a mutable handle into the word of its frozen view.
    ///
    /// A descriptor takes the spare capacity `cap - len` as its tail. When the
    /// tail does not fit, this allocates a record that takes over the
    /// allocation. A record moves unchanged. A mutable handle keeps
    /// `len <= cap`, so the subtraction cannot wrap.
    ///
    /// # Safety
    ///
    /// `self`, `ptr`, `len`, and `cap` must be the fields of a mutable handle.
    /// The returned word owns what that handle owned, so the caller must not
    /// release it afterwards.
    #[inline(always)]
    pub(crate) unsafe fn frozen(self, ptr: NonNull<u8>, len: usize, cap: usize) -> Self {
        match self.state() {
            OwnerState::Descriptor(descriptor) => {
                descriptor.with_tail(cap.wrapping_sub(len)).map_or_else(
                    // SAFETY: `ptr` and `cap` belong to the handle holding the
                    // descriptor.
                    || unsafe { descriptor.into_unique_record(ptr, cap) }.into(),
                    Self::from,
                )
            }
            OwnerState::Ref(_) => self,
        }
    }

    /// Releases the ownership of an immutable view `ptr..ptr + len` that
    /// holds this word: a descriptor's allocation or one record reference.
    ///
    /// # Safety
    ///
    /// The caller must own what this word owns as an immutable view, and
    /// gives up that ownership. For a descriptor, `ptr` and `len` must be as
    /// described in [`Descriptor::base`].
    #[inline(always)]
    pub(crate) unsafe fn release_view(self, ptr: NonNull<u8>, len: usize) {
        match self.state() {
            // SAFETY: a descriptor view owns its allocation alone.
            OwnerState::Descriptor(_) => unsafe { self.release_unique(ptr, len) },
            // SAFETY: the view owns one reference, if any.
            OwnerState::Ref(owner) => unsafe { owner.drop_shared() },
        }
    }

    /// Releases what a uniquely held word owns. Does nothing for an empty word.
    ///
    /// Every `IoBufMut` drop and every descriptor `IoBuf` drop share this one
    /// outlined copy, so the inlined drop paths stay small.
    ///
    /// # Safety
    ///
    /// The caller must own this word alone, and gives up that ownership. A
    /// record must have no other reference. For a descriptor, `ptr` and
    /// `extent` must be as described in [`Descriptor::base`].
    #[inline(never)]
    pub(crate) unsafe fn release_unique(self, ptr: NonNull<u8>, extent: usize) {
        match self.state() {
            // SAFETY: guaranteed by the caller.
            OwnerState::Descriptor(descriptor) => unsafe { descriptor.release(ptr, extent) },
            // SAFETY: guaranteed by the caller.
            OwnerState::Ref(owner) => unsafe { owner.release_unique() },
        }
    }
}

/// Allocates a unique record for a native allocation whose layout does not
/// fit a descriptor.
#[cold]
#[inline(never)]
fn native_record(base: NonNull<u8>, layout: Layout) -> OwnerRef {
    OwnerRef::new(Storage::Native { base, layout })
}

/// Owner word of an immutable handle, in an atomic cell.
///
/// Shared borrows may replace a descriptor with a record ([`Self::promote`]).
/// No other transition happens while the cell is shared, and exclusive
/// borrows read and write it without atomic operations.
pub(crate) struct OwnerCell(AtomicPtr<Owner>);

impl OwnerCell {
    // Loom's `AtomicPtr::new` is not `const`, so this cannot be `const`
    // without breaking the loom build.
    #[allow(clippy::missing_const_for_fn)]
    #[inline(always)]
    pub(crate) fn new(word: OwnerWord) -> Self {
        Self(AtomicPtr::new(word.0))
    }

    /// Loads the word through a shared borrow.
    ///
    /// Acquire pairs with the Release exchange in [`Self::promote`], so a
    /// record loaded here is fully initialized.
    #[inline(always)]
    pub(crate) fn load(&self) -> OwnerWord {
        OwnerWord(self.0.load(Ordering::Acquire))
    }

    /// Reads the word through an exclusive borrow.
    #[inline(always)]
    pub(crate) fn get(&mut self) -> OwnerWord {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                OwnerWord(self.0.with_mut(|word| *word))
            } else {
                OwnerWord(*self.0.get_mut())
            }
        }
    }

    /// Writes the word through an exclusive borrow.
    #[inline(always)]
    fn set(&mut self, word: OwnerWord) {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                self.0.with_mut(|slot| *slot = word.0);
            } else {
                *self.0.get_mut() = word.0;
            }
        }
    }

    /// Promotes `observed` to a record through a shared borrow and returns a
    /// reference for a new view.
    ///
    /// Callers are cold outlined constructors that return the whole new view,
    /// so their own callers never continue after passing the handle to an
    /// outlined call.
    ///
    /// # Safety
    ///
    /// `observed` must have been loaded from this cell, and `ptr` and `len`
    /// must be the view of the handle that holds the cell, which stays
    /// borrowed for the whole call.
    #[inline(always)]
    pub(crate) unsafe fn promote(
        &self,
        observed: Descriptor,
        ptr: NonNull<u8>,
        len: usize,
    ) -> OwnerRef {
        // One reference for the source handle and one for the new view.
        // SAFETY: guaranteed by the caller.
        let candidate = unsafe { observed.record(ptr, len, 2) };

        // Release publishes the record's initialization to the Acquire loads
        // of other clones. On failure, Acquire does the same for the record
        // that won. The borrowed source keeps that record alive and the word
        // never changes again, so a strong exchange fails only to it.
        match self.0.compare_exchange(
            OwnerWord::from(observed).0,
            candidate.as_ptr(),
            Ordering::Release,
            Ordering::Acquire,
        ) {
            Ok(_) => candidate,
            Err(winner) => {
                // SAFETY: no other thread has seen the candidate, and the
                // source handle still owns the data it describes.
                unsafe { candidate.discard() };
                let OwnerState::Ref(winner) = OwnerWord(winner).state() else {
                    unreachable!("a promoted owner never returns to a descriptor");
                };
                // SAFETY: the borrowed source holds a reference to the winner.
                unsafe { winner.clone_shared() };
                winner
            }
        }
    }

    /// Takes a reference for a new view through an exclusive borrow,
    /// promoting a descriptor with a plain store.
    ///
    /// The outlined promotion takes and returns values only, so a caller
    /// whose handle lives in registers can keep it there.
    ///
    /// # Safety
    ///
    /// `ptr` and `len` must be the view of the handle that holds the cell.
    #[inline(always)]
    pub(crate) unsafe fn retain_mut(&mut self, ptr: NonNull<u8>, len: usize) -> OwnerRef {
        match self.get().state() {
            OwnerState::Descriptor(descriptor) => {
                // SAFETY: guaranteed by the caller.
                let record = unsafe { descriptor.into_shared_record(ptr, len) };
                self.set(record.into());
                record
            }
            OwnerState::Ref(owner) => {
                // SAFETY: the holding handle owns a reference, if any.
                unsafe { owner.clone_shared() };
                owner
            }
        }
    }

    /// Releases the holding handle's ownership.
    ///
    /// # Safety
    ///
    /// `ptr` and `len` must be the view of the handle that holds the cell,
    /// which gives up its ownership.
    #[inline(always)]
    pub(crate) unsafe fn release(&mut self, ptr: NonNull<u8>, len: usize) {
        // SAFETY: guaranteed by the caller.
        unsafe { self.get().release_view(ptr, len) };
    }

    /// Loom-only Relaxed probe for a published record.
    ///
    /// Models spin on this (with yields) to wait for another thread's
    /// promotion without creating a happens-before edge. It only inspects the
    /// word and never dereferences it.
    #[cfg(all(test, feature = "loom"))]
    pub(crate) fn holds_record_relaxed(&self) -> bool {
        let word = OwnerWord(self.0.load(Ordering::Relaxed));
        matches!(word.state(), OwnerState::Ref(owner) if !owner.is_empty())
    }

    /// Loom-only Relaxed refcount probe of a record.
    ///
    /// # Safety
    ///
    /// The cell must hold a record that the calling thread already observed
    /// through a synchronizing operation, with a live reference owned by the
    /// caller.
    #[cfg(all(test, feature = "loom"))]
    pub(crate) unsafe fn refcount_relaxed(&self) -> usize {
        let OwnerState::Ref(owner) = OwnerWord(self.0.load(Ordering::Relaxed)).state() else {
            panic!("owner must be a record");
        };
        // SAFETY: guaranteed by the caller.
        unsafe { owner.refcount_relaxed() }
    }
}

/// Reference to an allocation owner: empty, or a pointer to a live [`Owner`].
///
/// `Option<NonNull<Owner>>` is pointer-sized with the null niche, so
/// [`Self::is_empty`] is a null test.
///
/// Empty owner refs are also used for non-empty `'static` slices. They need no
/// lifecycle work because the payload is immortal. Code that needs to recover
/// mutable ownership therefore checks both `owner.is_empty()` and `len == 0`.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct OwnerRef(Option<NonNull<Owner>>);

// SAFETY: the record behind a non-empty `OwnerRef` is shared between handles
// through its atomic refcount, and its storage is immutable once built.
unsafe impl Send for OwnerRef {}
// SAFETY: same argument as `Send`.
unsafe impl Sync for OwnerRef {}

/// Record shared by every handle of one allocation.
#[repr(C)]
pub(crate) struct Owner {
    /// Shared refcount at offset 0, so atomics need no pointer adjustment.
    /// The module docs list its states under Refcount state machine.
    refs: AtomicUsize,
    /// What the record keeps alive. Written at construction and never
    /// mutated, so any live handle may read it.
    storage: Storage,
    #[cfg(feature = "loom")]
    witness: Witness,
}

/// Loom stand-in for the record's plain fields, which loom does not track.
///
/// Created with the record, read by every dereference, and written by the
/// release, so loom reports a dereference that is not ordered after the
/// record's initialization and a release that is not ordered after every other
/// dereference. The leak tracker reports a record that is never freed.
#[cfg(feature = "loom")]
struct Witness {
    fields: loom::cell::UnsafeCell<()>,
    _leak: loom::alloc::Track<()>,
}

/// Storage kept alive by an [`Owner`].
pub(crate) enum Storage {
    /// A data allocation the global allocator made with exactly `layout`.
    /// Heap buffers record their requested size and alignment, and adopted
    /// vecs record `capacity` bytes at alignment 1. Release frees the data
    /// with the same layout.
    Native { base: NonNull<u8>, layout: Layout },
    /// Caller-supplied [`Bytes`], kept alive while any handle remains. Every
    /// handle's view `ptr..ptr+len` lies within this value's range, as the
    /// `slice_ref` conversion fast paths require.
    External(Bytes),
}

impl OwnerRef {
    #[inline(always)]
    pub(crate) const fn is_empty(self) -> bool {
        self.0.is_none()
    }

    #[inline(always)]
    const fn as_ptr(self) -> *mut Owner {
        match self.0 {
            Some(record) => record.as_ptr(),
            None => ptr::null_mut(),
        }
    }

    /// Allocates a record owning `storage` with one reference.
    #[inline]
    pub(crate) fn new(storage: Storage) -> Self {
        Self::with_refs(storage, 1)
    }

    /// Allocates a record owning `storage` with `refs` references.
    #[inline]
    fn with_refs(storage: Storage, refs: usize) -> Self {
        let record = Box::into_raw(Box::new(Owner {
            refs: AtomicUsize::new(refs),
            storage,
            #[cfg(feature = "loom")]
            witness: Witness {
                fields: loom::cell::UnsafeCell::new(()),
                _leak: loom::alloc::Track::new(()),
            },
        }));
        // SAFETY: `Box::into_raw` never returns null.
        Self(Some(unsafe { NonNull::new_unchecked(record) }))
    }

    /// Returns the record.
    ///
    /// # Safety
    ///
    /// `self` must be a live record. The caller must bound the returned borrow
    /// by the record's liveness (the handle that supplied `self` keeps a
    /// reference for at least that long).
    // The loom build reads the record's witness here, which is not `const`.
    #[allow(clippy::missing_const_for_fn)]
    #[inline(always)]
    unsafe fn record<'a>(self) -> &'a Owner {
        // SAFETY: a non-empty owner ref points at a record built in
        // `with_refs`, and the caller keeps it live.
        let record = unsafe { self.0.unwrap_unchecked().as_ref() };
        #[cfg(feature = "loom")]
        record.witness.fields.with(|_| ());
        record
    }

    /// Returns the shared refcount of a record.
    ///
    /// # Safety
    ///
    /// As for [`Self::record`].
    #[inline(always)]
    unsafe fn refs<'a>(self) -> &'a AtomicUsize {
        // SAFETY: guaranteed by the caller.
        &unsafe { self.record() }.refs
    }

    /// Returns what a record keeps alive, or `None` for an empty owner.
    ///
    /// # Safety
    ///
    /// `self` must be empty or have a live reference owned by the caller, and
    /// the caller must bound the returned borrow by the owner's liveness.
    #[inline(always)]
    pub(crate) unsafe fn storage<'a>(self) -> Option<&'a Storage> {
        if self.is_empty() {
            return None;
        }
        // SAFETY: guaranteed by the caller.
        Some(&unsafe { self.record() }.storage)
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

        // Relaxed suffices because the caller's existing handle proves the
        // owner is live, and a clone publishes no payload writes.
        // SAFETY: non-empty owners have a valid refcount.
        let old = unsafe { self.refs() }.fetch_add(1, Ordering::Relaxed);

        // Abort before the refcount can wrap, as `Arc` and `bytes` do.
        if old > MAX_REFCOUNT {
            std::process::abort();
        }
    }

    /// Drops one immutable shared view.
    ///
    /// Because `1` is the unique-owner sentinel, an unshared drop needs only an
    /// Acquire load before the outlined [`Self::release_unique`]. A shared drop
    /// performs one inline Release decrement. When the other handles drop
    /// between this handle's load and its decrement, the decrement finds the
    /// count at 1 and this drop releases through the cold
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

        // Acquire pairs with the other handles' Release decrements below.
        // Observing 1 means every other handle has already dropped, and their
        // payload reads happen-before this release.
        if refs.load(Ordering::Acquire) == 1 {
            // SAFETY: this is the final shared owner.
            unsafe { self.release_unique() };
            return;
        }

        // Release publishes this handle's payload reads to whichever drop ends
        // up releasing the allocation. This is the common drop path for shared
        // clones, so it stays inline and skips a call.
        let old = refs.fetch_sub(1, Ordering::Release);
        if old == 1 {
            // SAFETY: this drop won the final-owner race.
            unsafe { self.drop_shared_race_final() };
        }
    }

    /// Releases after a shared-drop race made this handle final.
    ///
    /// Reached when the fast-path load observed a shared count, but every
    /// other handle dropped before this handle's decrement. This path is
    /// reachable only under true concurrency (covered by loom), so it stays
    /// outlined and cold.
    ///
    /// # Safety
    ///
    /// `self` must be the final owner.
    #[cold]
    #[inline(never)]
    unsafe fn drop_shared_race_final(self) {
        // The Acquire fence pairs with the Release decrements of every other
        // handle, so their payload accesses happen-before the release.
        fence(Ordering::Acquire);

        // SAFETY: guaranteed by the caller.
        unsafe { self.release_unique() };
    }

    /// Releases a uniquely-owned record. Does nothing for an empty owner.
    ///
    /// Every final `IoBuf` release of a record shares this one outlined copy
    /// of the deallocation code, so the inlined drop paths stay small.
    ///
    /// # Safety
    ///
    /// No other handle may reference this record.
    #[inline(never)]
    pub(crate) unsafe fn release_unique(self) {
        let Some(record) = self.0 else {
            return;
        };
        // SAFETY: the record was boxed in `with_refs`, and the caller
        // guarantees no other handle references it.
        let owner = unsafe { record.as_ref() };
        #[cfg(feature = "loom")]
        owner.witness.fields.with_mut(|_| ());

        // A unique handle leaves the count at 1 and the final shared decrement
        // at 0. Anything higher means a live handle still exists, so this
        // panics before releasing anything that handle still uses.
        assert!(
            owner.refs.load(Ordering::Relaxed) <= 1,
            "an owner must not be released while shared"
        );
        match owner.storage {
            Storage::Native { base, layout } => {
                // SAFETY: `base` was allocated by the global allocator with
                // `layout` (a storage invariant), and no handle references it.
                unsafe { dealloc(base.as_ptr(), layout) };
                // SAFETY: the record is unreferenced, and its witness is
                // dropped only here.
                #[cfg(feature = "loom")]
                unsafe {
                    ptr::drop_in_place(&raw mut (*record.as_ptr()).witness)
                };
            }
            // SAFETY: no handle references the record, and `owner` is not used
            // after this point, so this drop is the only access. The record is
            // dropped only here, so its `Bytes` is released exactly once.
            Storage::External(_) => unsafe { record.drop_in_place() },
        }

        // SAFETY: `with_refs` boxed the record, so the global allocator holds
        // it with `Owner`'s layout. Its storage needs no further drop.
        unsafe { dealloc(record.as_ptr().cast(), Layout::new::<Owner>()) };
    }

    /// Frees a record that was never published, without releasing its
    /// storage.
    ///
    /// # Safety
    ///
    /// `self` must be a record that no other handle or thread has seen. Its
    /// storage stays owned by whoever owned it before the record was built.
    unsafe fn discard(self) {
        // SAFETY: guaranteed by the caller.
        let record = unsafe { self.0.unwrap_unchecked() };
        // SAFETY: the record is unreferenced, and its witness is dropped only
        // here.
        #[cfg(feature = "loom")]
        unsafe {
            ptr::drop_in_place(&raw mut (*record.as_ptr()).witness)
        };
        // SAFETY: `with_refs` boxed the record with `Owner`'s layout.
        unsafe { dealloc(record.as_ptr().cast(), Layout::new::<Owner>()) };
    }

    /// Returns true when this owner has exactly one live reference.
    ///
    /// This is sound for the same reason as `Arc::get_mut`. A count of 1
    /// observed through Acquire means no other handle exists, and no thread can
    /// clone without a handle. The Acquire load pairs with the Release
    /// decrement in [`Self::drop_shared`] so the last dropper's payload reads
    /// happen-before any mutation that follows a `true` result.
    ///
    /// # Safety
    ///
    /// `self` must be a live record.
    #[inline(always)]
    pub(crate) unsafe fn is_unique(self) -> bool {
        // SAFETY: guaranteed by the caller.
        unsafe { self.refs() }.load(Ordering::Acquire) == 1
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
    /// Models spin on this (with yields) to observe another handle's decrement
    /// without creating a happens-before edge. The probe must not synchronize,
    /// or it would mask a weakened ordering in the drop path under test.
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

#[cfg(all(test, not(feature = "loom")))]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::*;
    use std::{
        panic::{self, AssertUnwindSafe},
        sync::Arc,
    };

    /// A page-sized alignment for the aligned-allocation tests.
    const PAGE_ALIGNMENT: usize = 4096;

    /// External payload that counts how many times it is released.
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

    /// Layout of `size` bytes at `align`.
    fn layout(size: usize, align: usize) -> Layout {
        Layout::from_size_align(size, align).unwrap()
    }

    /// Packs and unpacks with `format`, checking the tag and the word width.
    fn round_trip(format: Format, size: usize, align: usize, tail: usize) -> Fields {
        let word = format
            .pack(layout(size, align), tail)
            .expect("fields must fit");
        assert_eq!(word & 1, 1);
        assert!(format.bits() == 64 || word >> format.bits() == 0);
        format.unpack(word)
    }

    /// Descriptor held by a word.
    fn descriptor(word: OwnerWord) -> Descriptor {
        match word.state() {
            OwnerState::Descriptor(descriptor) => descriptor,
            OwnerState::Ref(_) => panic!("owner must be a descriptor"),
        }
    }

    /// Record held by a word.
    fn record(word: OwnerWord) -> OwnerRef {
        match word.state() {
            OwnerState::Ref(owner) if !owner.is_empty() => owner,
            _ => panic!("owner must be a record"),
        }
    }

    /// Address of a non-empty owner's record.
    fn record_addr(owner: OwnerRef) -> usize {
        owner.0.unwrap().as_ptr() as usize
    }

    /// Data base and layout of a native record.
    fn heap(owner: OwnerRef) -> (NonNull<u8>, Layout) {
        // SAFETY: the test holds the owner's reference for the whole call.
        match unsafe { owner.storage() } {
            Some(&Storage::Native { base, layout }) => (base, layout),
            _ => panic!("owner must be native"),
        }
    }

    /// Whether a live owner holds caller-supplied `Bytes`.
    fn is_external(owner: OwnerRef) -> bool {
        // SAFETY: the test holds the owner's reference for the whole call.
        matches!(unsafe { owner.storage() }, Some(Storage::External(_)))
    }

    /// Allocates `capacity` bytes owned by a native record with one reference.
    fn native_record(capacity: usize, alignment: usize) -> (NonNull<u8>, OwnerRef) {
        let (data, word) = OwnerWord::allocate(capacity, alignment, false);
        // SAFETY: `data` and `capacity` are the view of the mutable handle
        // that would hold this descriptor.
        let owner = unsafe { descriptor(word).into_unique_record(data, capacity) };
        (data, owner)
    }

    /// Frozen view of a fresh allocation: `len` readable bytes starting at
    /// `offset`, leaving a tail of `capacity - offset - len` bytes.
    fn frozen_view(
        capacity: usize,
        offset: usize,
        len: usize,
    ) -> (NonNull<u8>, NonNull<u8>, OwnerWord) {
        let (base, word) = OwnerWord::allocate(capacity, 8, false);
        // SAFETY: a mutable handle advanced by `offset` has this view.
        let ptr = unsafe { base.add(offset) };
        // SAFETY: these are the fields of that mutable handle.
        let word = unsafe { word.frozen(ptr, len, capacity - offset) };
        (base, ptr, word)
    }

    #[test]
    fn test_format_64_round_trips() {
        let max_size = (1 << 40) - 1;
        let max_tail = (1 << 17) - 1;
        for (size, align, tail) in [
            (1, 1, 0),
            (10, 1, 9),
            (4096, PAGE_ALIGNMENT, max_tail),
            (max_size, 1, 0),
            (max_size, 1 << 30, max_tail),
            (1, 1 << 62, 0),
        ] {
            let fields = round_trip(FORMAT_64, size, align, tail);
            assert_eq!(fields, Fields { size, align, tail });
        }

        // Each field decodes on its own, so none overlaps another.
        assert_eq!(
            round_trip(FORMAT_64, max_size, 1, 0),
            Fields {
                size: max_size,
                align: 1,
                tail: 0
            }
        );
        assert_eq!(
            round_trip(FORMAT_64, 1, 1, max_tail),
            Fields {
                size: 1,
                align: 1,
                tail: max_tail
            }
        );
        assert_eq!(
            round_trip(FORMAT_64, 1, 1 << 62, 0),
            Fields {
                size: 1,
                align: 1 << 62,
                tail: 0
            }
        );
    }

    #[test]
    fn test_format_64_rejects_fields_that_do_not_fit() {
        assert_eq!(FORMAT_64.pack(layout(1 << 40, 1), 0), None);
        assert_eq!(FORMAT_64.pack(layout(64, 1), 1 << 17), None);
        assert_eq!(FORMAT_64.pack(layout(0, 1), 0), None);
    }

    #[test]
    fn test_format_32_round_trips() {
        let max_size = (1 << 24) - 1;
        for (size, tail) in [(1, 0), (255, 127), (256, 0), (max_size, 0), (max_size, 127)] {
            let fields = round_trip(FORMAT_32, size, 1, tail);
            assert_eq!(
                fields,
                Fields {
                    size,
                    align: 1,
                    tail
                }
            );
        }
        assert_eq!(
            round_trip(FORMAT_32, 1, 1, 127),
            Fields {
                size: 1,
                align: 1,
                tail: 127
            }
        );
    }

    #[test]
    fn test_format_32_rejects_fields_that_do_not_fit() {
        assert_eq!(FORMAT_32.pack(layout(1 << 24, 1), 0), None);
        assert_eq!(FORMAT_32.pack(layout(64, 2), 0), None);
        assert_eq!(FORMAT_32.pack(layout(64, 1), 128), None);
        assert_eq!(FORMAT_32.pack(layout(0, 1), 0), None);
    }

    #[test]
    fn test_format_tail_replacement_keeps_layout() {
        for (format, size, align, max_tail) in [
            (FORMAT_64, 1000, 64, (1 << 17) - 1),
            (FORMAT_32, 1000, 1, 127),
        ] {
            let word = format.pack(layout(size, align), 0).unwrap();
            let replaced = format.with_tail(word, max_tail).unwrap();
            assert_eq!(
                format.unpack(replaced),
                Fields {
                    size,
                    align,
                    tail: max_tail
                }
            );
            let cleared = format.with_tail(replaced, 0).unwrap();
            assert_eq!(cleared, word);
            assert_eq!(format.with_tail(word, max_tail + 1), None);
        }
    }

    #[test]
    fn test_format_without_bits_describes_nothing() {
        let none = Format {
            align_bits: 0,
            tail_bits: 0,
            size_bits: 0,
        };
        assert_eq!(none.pack(layout(1, 1), 0), None);
    }

    #[test]
    fn test_heap_allocation_is_exact_and_aligned() {
        let page = PAGE_ALIGNMENT;
        let (data, word) = OwnerWord::allocate(4096, page, false);
        assert!((data.as_ptr() as usize).is_multiple_of(page));

        // An unshared allocation has no record. Its descriptor holds the
        // exact requested layout, and the base comes back from the view.
        let descriptor = descriptor(word);
        assert_eq!(descriptor.layout(), layout(4096, page));
        assert_eq!(descriptor.tail(), 0);
        // SAFETY: `data` and its capacity are the view holding the descriptor.
        assert_eq!(unsafe { descriptor.base(data, 4096) }, data);
        // SAFETY: the word is unique and must be released by this test.
        unsafe { word.release_unique(data, 4096) };
    }

    #[test]
    fn test_heap_zeroed_only_exposes_usable_region() {
        let (data, word) = OwnerWord::allocate(64, PAGE_ALIGNMENT, true);
        // SAFETY: data points at a zeroed usable region of length 64.
        let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr(), 64) };
        assert_eq!(bytes, &[0u8; 64]);
        // SAFETY: the word is unique and must be released by this test.
        unsafe { word.release_unique(data, 64) };
    }

    #[test]
    fn test_heap_capacity_is_not_rounded() {
        let (data, word) = OwnerWord::allocate(10, 1, false);
        assert_eq!(descriptor(word).layout().size(), 10);
        // SAFETY: the word is unique and must be released by this test.
        unsafe { word.release_unique(data, 10) };
    }

    #[test]
    #[should_panic(expected = "alignment must be a power of two and the size must fit a layout")]
    fn test_allocation_rejects_isize_max_overflow() {
        let _ = OwnerWord::allocate(isize::MAX as usize, 64, false);
    }

    #[test]
    #[should_panic(expected = "alignment must be a power of two and the size must fit a layout")]
    fn test_allocation_rejects_non_power_of_two_alignment() {
        let _ = OwnerWord::allocate(64, 3, false);
    }

    #[test]
    fn test_descriptor_recovers_base_from_any_view() {
        // 64 bytes, a view of 32 bytes at offset 8, and a tail of 24.
        let (base, ptr, word) = frozen_view(64, 8, 32);
        let frozen = descriptor(word);
        assert_eq!(frozen.layout(), layout(64, 8));
        assert_eq!(frozen.tail(), 24);
        // SAFETY: each pointer and extent below is a view of this allocation
        // whose end plus the tail reaches the allocation end.
        unsafe {
            assert_eq!(frozen.base(ptr, 32), base);
            assert_eq!(frozen.base(ptr.add(32), 0), base);
            assert_eq!(frozen.without_tail().base(ptr, 56), base);
            assert_eq!(frozen.without_tail().base(base.add(64), 0), base);
        }
        assert_eq!(frozen.without_tail().layout(), frozen.layout());

        // An immutable view advanced to its end still owns the allocation.
        // SAFETY: the view at the end of the readable bytes holds the word.
        unsafe { word.release_unique(ptr.add(32), 0) };
    }

    #[test]
    fn test_frozen_tail_overflow_allocates_record() {
        // A tail one past the widest field forces a record.
        let capacity = (1 << FORMAT.tail_bits) + 1;
        let (base, ptr, word) = frozen_view(capacity, 0, 1);
        let owner = record(word);
        assert_eq!(ptr, base);
        assert_eq!(heap(owner), (base, layout(capacity, 8)));
        // SAFETY: owner is live.
        assert_eq!(unsafe { owner.refcount() }, Some(1));
        // SAFETY: the word is unique and must be released by this test.
        unsafe { word.release_unique(ptr, 1) };
    }

    #[test]
    fn test_vec_adoption_keeps_allocation_and_capacity() {
        // The vec's own allocation becomes the data allocation with every byte
        // of its capacity usable, described by the handle's word.
        let mut vec = Vec::with_capacity(256);
        vec.extend_from_slice(&[1u8, 2, 3, 4]);
        let base_addr = vec.as_ptr() as usize;
        let vec_cap = vec.capacity();
        let (ptr, len, cap, word) = OwnerWord::adopt_vec(vec);
        assert_eq!(ptr.as_ptr() as usize, base_addr);
        assert_eq!(len, 4);
        assert_eq!(cap, vec_cap);
        assert_eq!(
            descriptor(word).layout(),
            Layout::array::<u8>(vec_cap).unwrap()
        );
        // SAFETY: ptr points at `len` readable bytes kept alive by the word.
        let payload = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) };
        assert_eq!(payload, &[1, 2, 3, 4]);
        // SAFETY: the word is unique and must be released by this test.
        unsafe { word.release_unique(ptr, cap) };
    }

    #[test]
    fn test_vec_adoption_exact_size_is_native() {
        // A vec with `len == cap` is adopted like any other.
        let vec = vec![5u8, 6, 7];
        assert_eq!(vec.len(), vec.capacity());
        let base_addr = vec.as_ptr() as usize;
        let (ptr, len, cap, word) = OwnerWord::adopt_vec(vec);
        assert_eq!(ptr.as_ptr() as usize, base_addr);
        assert_eq!(len, 3);
        assert_eq!(cap, 3);
        assert_eq!(descriptor(word).layout().size(), 3);
        // SAFETY: ptr points at `len` readable bytes kept alive by the word.
        let payload = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) };
        assert_eq!(payload, &[5, 6, 7]);
        // SAFETY: the word is unique and must be released by this test.
        unsafe { word.release_unique(ptr, cap) };
    }

    #[test]
    fn test_adopt_vec_with_capacity_but_no_length() {
        // A mutable adoption keeps an allocation whose readable prefix is
        // empty, exactly as `Vec::with_capacity` created it.
        let vec: Vec<u8> = Vec::with_capacity(64);
        let base_addr = vec.as_ptr() as usize;
        let (ptr, len, cap, word) = OwnerWord::adopt_vec(vec);
        assert_eq!(ptr.as_ptr() as usize, base_addr);
        assert_eq!(len, 0);
        assert_eq!(cap, 64);
        // SAFETY: the word is unique and must be released by this test.
        unsafe { word.release_unique(ptr, cap) };
    }

    #[test]
    #[should_panic(expected = "capacity must be greater than zero")]
    fn test_adopt_vec_rejects_unallocated_vec() {
        let _ = OwnerWord::adopt_vec(Vec::new());
    }

    #[test]
    fn test_external_owner_refcount() {
        let owner = OwnerRef::new(Storage::External(Bytes::from_static(b"abc")));
        assert!(is_external(owner));
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
        let owner = OwnerRef::new(Storage::External(payload));
        // SAFETY: owner is live.
        let Some(Storage::External(inner)) = (unsafe { owner.storage() }) else {
            panic!("owner must be external");
        };
        assert_eq!(inner.as_ptr(), inner_ptr);
        assert_eq!(inner.as_ref(), &[7u8; 32]);
        // SAFETY: final drop releases the owner and the inner Bytes.
        unsafe { owner.drop_shared() };
    }

    #[test]
    fn test_empty_owner_has_no_record() {
        let owner = OwnerRef(None);
        assert!(owner.is_empty());
        // SAFETY: empty owners have no record to read.
        assert!(unsafe { owner.storage() }.is_none());
        // SAFETY: empty owners have no refcount to read.
        assert_eq!(unsafe { owner.refcount() }, None);
        // SAFETY: empty owners need no release work.
        unsafe { owner.release_unique() };
        // SAFETY: as above.
        unsafe { owner.drop_shared() };
        // SAFETY: as above.
        unsafe { OwnerWord::empty().release_unique(NonNull::dangling(), 0) };
    }

    #[test]
    fn test_heap_owner_shared_clone_and_drop() {
        let (_, owner) = native_record(64, 1);
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
    fn test_shared_release_panics_before_releasing_storage() {
        let released = Arc::new(AtomicUsize::new(0));
        let bytes = Bytes::from_owner(Tracker(released.clone()));
        let owner = OwnerRef::new(Storage::External(bytes));
        // A count of 2 is what a second live handle would leave.
        // SAFETY: owner is live.
        unsafe { owner.refs() }.store(2, Ordering::Relaxed);

        // A release that finds a shared count must panic before it drops the
        // payload or frees the record.
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: this is the only handle, so no other handle references
            // the allocation.
            unsafe { owner.release_unique() }
        }));
        assert!(result.is_err());
        assert_eq!(released.load(Ordering::SeqCst), 0);

        // SAFETY: the record survived the panic, so owner is still live.
        unsafe { owner.refs() }.store(1, Ordering::Relaxed);
        // SAFETY: final drop releases the owner.
        unsafe { owner.drop_shared() };
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_shared_promotion_publishes_two_references() {
        // A view of 40 bytes at offset 8 of 64: promotion must recover the
        // original base and layout from the source view.
        let (base, ptr, word) = frozen_view(64, 8, 40);
        let cell = OwnerCell::new(word);
        let observed = descriptor(cell.load());
        // SAFETY: `observed` came from the cell, and `ptr` and `40` are the
        // view holding it.
        let view = unsafe { cell.promote(observed, ptr, 40) };
        let installed = record(cell.load());
        assert_eq!(record_addr(installed), record_addr(view));
        assert_eq!(heap(view), (base, layout(64, 8)));
        // SAFETY: owner is live.
        assert_eq!(unsafe { view.refcount() }, Some(2));

        // SAFETY: the view's reference is live.
        unsafe { view.drop_shared() };
        let mut cell = cell;
        // SAFETY: the cell's handle gives up its reference.
        unsafe { cell.release(ptr, 40) };
    }

    #[test]
    fn test_losing_promotion_retains_winner() {
        let (_, ptr, word) = frozen_view(64, 0, 64);
        let cell = OwnerCell::new(word);
        let observed = descriptor(cell.load());
        // SAFETY: as in the test above.
        let winner = unsafe { cell.promote(observed, ptr, 64) };

        // A contender that loaded the same descriptor before the winner's
        // exchange fails, frees only its own record, and joins the winner.
        // SAFETY: `observed` was loaded from this cell.
        let loser = unsafe { cell.promote(observed, ptr, 64) };
        assert_eq!(record_addr(loser), record_addr(winner));
        // SAFETY: owner is live.
        assert_eq!(unsafe { winner.refcount() }, Some(3));

        // SAFETY: each view owns one reference.
        unsafe { winner.drop_shared() };
        // SAFETY: as above.
        unsafe { loser.drop_shared() };
        let mut cell = cell;
        // SAFETY: the cell's handle gives up the final reference.
        unsafe { cell.release(ptr, 64) };
    }

    #[test]
    fn test_exclusive_promotion_stores_record() {
        let (base, ptr, word) = frozen_view(64, 4, 20);
        let mut cell = OwnerCell::new(word);
        // SAFETY: `ptr` and `20` are the view holding the cell.
        let first = unsafe { cell.retain_mut(ptr, 20) };
        assert_eq!(record_addr(record(cell.get())), record_addr(first));
        assert_eq!(heap(first), (base, layout(64, 8)));
        // SAFETY: owner is live.
        assert_eq!(unsafe { first.refcount() }, Some(2));

        // Later retains use the stored record.
        // SAFETY: as above.
        let second = unsafe { cell.retain_mut(ptr, 20) };
        assert_eq!(record_addr(second), record_addr(first));
        // SAFETY: owner is live.
        assert_eq!(unsafe { first.refcount() }, Some(3));

        // SAFETY: each view owns one reference.
        unsafe { first.drop_shared() };
        // SAFETY: as above.
        unsafe { second.drop_shared() };
        // SAFETY: the cell's handle gives up the final reference.
        unsafe { cell.release(ptr, 20) };
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::{
        super::{IoBuf, IoBufMut},
        *,
    };
    use bytes::BufMut as _;
    use loom::{
        cell::UnsafeCell,
        sync::{Arc, atomic::AtomicUsize},
        thread,
    };

    // These models check the owner refcount and promotion protocols under true
    // concurrency. A drop reaches `drop_shared_race_final` only when its
    // decrement hits zero because other threads decremented between its
    // Acquire load and its `fetch_sub`, and a promotion fails only when another
    // clone published first. Single-threaded tests cannot reach those paths,
    // so loom is their only coverage. Every record carries a loom witness (see
    // `Witness`), so the native models also check that each dereference is
    // ordered after the record's initialization and before its release, and
    // that every record is freed.

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

    /// Tracked stand-in for the payload state that the final release accesses.
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

    /// Frozen native buffer of 8 readable bytes and a 4-byte tail, still
    /// described by its handle.
    fn unshared() -> IoBuf {
        let mut buf = IoBufMut::with_capacity(12);
        buf.put_bytes(7, 8);
        buf.freeze()
    }

    #[test]
    fn shared_clone_drop_releases_exactly_once() {
        loom::model(|| {
            let released = Arc::new(AtomicUsize::new(0));
            let bytes = Bytes::from_owner(Tracker(released.clone()));
            let owner = OwnerRef::new(Storage::External(bytes));

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
            let owner = OwnerRef::new(Storage::External(bytes));

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
            let owner = OwnerRef::new(Storage::External(bytes));
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
            // The uniqueness check spins with yields because loom advances a
            // yielding load past stale stores. Every explored execution then
            // observes the drop and reaches the post-uniqueness assertions.
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

    #[test]
    fn payload_writes_happen_before_race_final_release() {
        loom::model(|| {
            let released = Arc::new(AtomicUsize::new(0));
            let payload = Arc::new(PayloadCell(UnsafeCell::new(0)));
            let bytes = Bytes::from_owner(TrackedPayload {
                payload: payload.clone(),
                released: released.clone(),
            });
            let owner = OwnerRef::new(Storage::External(bytes));

            // Two handles: the spawned thread writes the payload through its
            // handle and drops. The main thread only drops.
            //
            // When the decrements race (both fast-path loads see a shared count
            // and the main thread's decrement lands last), the main thread
            // frees through `drop_shared_race_final`. Its Acquire fence must
            // order the tracked read inside TrackedPayload::drop after the
            // writer's access, and weakening it makes loom report a data race
            // on the payload cell.
            //
            // Loom does not advance a single load past a decrement it has not
            // causally seen, so this model cannot explore the cross-thread fast
            // path. The probe-driven model below covers that edge.
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
            let owner = OwnerRef::new(Storage::External(bytes));

            // Two handles: the spawned thread writes the payload through its
            // handle and drops. The main thread waits until the decrement is
            // visible through a Relaxed probe (no happens-before edge, and the
            // yields let loom advance the probe past stale values), so its
            // drop deterministically takes the fast path and frees.
            //
            // The only ordering protecting the tracked read inside
            // TrackedPayload::drop is then the fast-path Acquire load.
            // Downgrading it to Relaxed makes loom report a data race on the
            // payload cell.
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

    #[test]
    fn promotion_publishes_record_to_observer() {
        loom::model(|| {
            let buf = Arc::new(unshared());

            // The spawned thread promotes the descriptor and drops its view.
            // The main thread waits for the record through a Relaxed probe (no
            // happens-before edge), then clones through it. The clone's
            // Acquire load is then the only edge that orders the record's
            // initialization before the witness read in clone_shared, so a
            // Relaxed load or a Relaxed exchange makes loom report a race.
            let promoter = thread::spawn({
                let buf = buf.clone();
                move || drop(IoBuf::clone(&buf))
            });
            while !buf.owner_cell().holds_record_relaxed() {
                thread::yield_now();
            }
            let view = IoBuf::clone(&buf);
            assert_eq!(view, [7u8; 8]);
            drop(view);
            promoter.join().unwrap();

            // Only the source's reference remains, so it recovers the whole
            // allocation.
            let buf = Arc::try_unwrap(buf).unwrap();
            let recovered = buf.try_into_mut().expect("the views are gone");
            assert_eq!(recovered.capacity(), 12);
        });
    }

    #[test]
    fn losing_promotion_retains_winner() {
        loom::model(|| {
            let buf = Arc::new(unshared());

            // Both threads may find the descriptor and race to publish a
            // record. The loser must free only its own record (the leak
            // tracker reports a lost one) and take a reference on the winner,
            // whose initialization its failed exchange must acquire before the
            // witness read in clone_shared. Loom also explores the winner
            // dropping its view before the loser's increment, which leaves
            // only the source's reference at that point.
            let a = thread::spawn({
                let buf = buf.clone();
                move || drop(IoBuf::clone(&buf))
            });
            let b = thread::spawn({
                let buf = buf.clone();
                move || {
                    let view = buf.slice(1..7);
                    let again = view.clone();
                    assert_eq!(again, [7u8; 6]);
                    drop(view);
                    drop(again);
                }
            });
            a.join().unwrap();
            b.join().unwrap();

            // One record remains, holding only the source's reference.
            let buf = Arc::try_unwrap(buf).unwrap();
            assert!(buf.owner_cell().holds_record_relaxed());
            let recovered = buf.try_into_mut().expect("the views are gone");
            assert_eq!(recovered.capacity(), 12);
        });
    }

    #[test]
    fn promoted_try_into_mut_observes_prior_accesses() {
        loom::model(|| {
            let buf = unshared();
            let view = buf.clone();
            let payload = Arc::new(PayloadCell(UnsafeCell::new(0)));

            // The spawned thread writes the payload and drops its view. The
            // main thread waits for the decrement through a Relaxed probe,
            // then recovers the buffer. Its Acquire uniqueness check must
            // order the write before the read below.
            let t1 = thread::spawn({
                let payload = payload.clone();
                move || {
                    // SAFETY: this thread's view is live, and the write is
                    // sequenced before its drop.
                    payload.0.with_mut(|cell| unsafe { *cell = 1 });
                    drop(view);
                }
            });
            // SAFETY: the main thread observed the record when it promoted.
            while unsafe { buf.owner_cell().refcount_relaxed() } != 1 {
                thread::yield_now();
            }
            let recovered = buf.try_into_mut().expect("the view is gone");
            // SAFETY: recovery transfers exclusive access.
            payload.0.with(|cell| assert_eq!(unsafe { *cell }, 1));
            drop(recovered);
            t1.join().unwrap();
        });
    }

    #[test]
    fn promoted_fast_path_release_observes_prior_accesses() {
        loom::model(|| {
            let buf = unshared();
            let view = buf.slice(2..6);

            // The spawned thread drops its view. The main thread waits for
            // the decrement through a Relaxed probe, so its drop takes the
            // fast path and frees. The fast-path Acquire load must order the
            // other drop's witness read before the release's witness write.
            let t1 = thread::spawn(move || drop(view));
            // SAFETY: the main thread observed the record when it promoted.
            while unsafe { buf.owner_cell().refcount_relaxed() } != 1 {
                thread::yield_now();
            }
            drop(buf);
            t1.join().unwrap();
        });
    }

    #[test]
    fn promoted_concurrent_drops_release_once() {
        loom::model(|| {
            let buf = unshared();
            let view = buf.clone();

            // Either drop may release, including through the race-final path.
            // The leak tracker reports a record that neither frees.
            let t1 = thread::spawn(move || drop(view));
            drop(buf);
            t1.join().unwrap();
        });
    }

    #[test]
    fn exclusive_promotion_shares_record_across_threads() {
        loom::model(|| {
            let mut buf = unshared();
            let prefix = buf.split_to(3);

            let t1 = thread::spawn(move || {
                assert_eq!(prefix, [7u8; 3]);
                drop(prefix);
            });
            let rest = buf.clone();
            assert_eq!(rest, [7u8; 5]);
            drop(buf);
            drop(rest);
            t1.join().unwrap();
        });
    }
}
