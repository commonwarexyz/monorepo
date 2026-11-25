//! Runtime-owned io_uring instance.
//!
//! [`Ring`] creates a ring with SINGLE_ISSUER, DEFER_TASKRUN, NO_SQARRAY, and
//! SQ_REWIND, maps its shared rings and SQE array, and owns the submission
//! queue writer, the completion queue reader, and the `io_uring_enter` and
//! `io_uring_register` calls. It also defines the kernel ABI those need, other
//! than SQEs.
//!
//! # Memory Access
//!
//! Shared ring words are accessed only through atomics. SQE slots are written
//! whole through raw pointers and CQEs are copied out by value, so no reference
//! to a kernel-owned entry is ever formed. Each mapping is unmapped only after
//! the queues that point into it are gone.
//!
//! The SQ writer stages SQEs from the first slot. Pushing writes a whole SQE
//! into the slot after the staged ones. With SQ_REWIND the kernel's submission
//! path ignores the shared SQ head and tail, which stay zero: each enter asks
//! it to submit exactly the staged SQEs, and it fetches them in slot order from
//! the first slot during the call. For this ring (no SQPOLL, no SQ resize, and
//! one submitter), the kernel reads SQEs only inside an enter, after the SQE
//! writes that precede the call on the same thread, and returns the number it
//! fetched when that is positive. A negative result consumes no SQE. After a
//! short submission, the writer moves the unconsumed SQEs to the first slots,
//! in order, so the next enter offers them first, ahead of later pushes. The
//! writer never accesses a shared SQ word other than the flags.
//!
//! The CQ reader takes one acquire load of the kernel's CQ tail per view,
//! copies each readable CQE out, and returns exactly the consumed prefix with
//! one release store of the head when the view drops.
//!
//! # Ownership
//!
//! A ring and its registered slot belong to the thread that creates them, so
//! [`Ring`] is neither `Send` nor `Sync`. The ring descriptor is `O_CLOEXEC`
//! and the mappings are inherited across `fork`, but a forked child must not
//! drive or modify the inherited ring.

use super::sqe::Sqe;
use std::{
    ffi::{c_long, c_void},
    io,
    marker::PhantomData,
    mem,
    ops::{BitOr, BitOrAssign},
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd},
    ptr::{self, NonNull},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

/// Lets the kernel accept submissions only from the thread that created the
/// ring.
const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
/// Defers completion task work until the owner enters with GETEVENTS.
const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
/// Indexes SQEs directly by the SQ head instead of through an index array.
const IORING_SETUP_NO_SQARRAY: u32 = 1 << 16;
/// Starts every submission at the first SQE slot, so submission neither reads
/// the SQ tail nor writes the SQ head. Requires NO_SQARRAY and Linux 7.0.
const IORING_SETUP_SQ_REWIND: u32 = 1 << 20;

/// One mapping at the SQ ring offset covers both rings.
const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;

/// Mapping offset of the shared rings.
const IORING_OFF_SQ_RING: libc::off_t = 0;
/// Mapping offset of the SQE array.
const IORING_OFF_SQES: libc::off_t = 0x1000_0000;

/// SQ flag set while the kernel holds completions that did not fit in the CQ.
const IORING_SQ_CQ_OVERFLOW: u32 = 1 << 1;

/// CQE flag of a completion that more completions of the same request follow.
#[cfg(all(test, not(feature = "loom")))]
const IORING_CQE_F_MORE: u32 = 1 << 1;

/// Register opcode that adds ring descriptors to the calling thread's table.
const IORING_REGISTER_RING_FDS: c_long = 20;
/// Register opcode that removes ring descriptors from the calling thread's
/// table.
const IORING_UNREGISTER_RING_FDS: c_long = 21;
/// Register opcode that cancels requests and waits for them to finish.
const IORING_REGISTER_SYNC_CANCEL: c_long = 24;

/// Flags of `io_uring_enter`.
///
/// [`Ring::enter`] derives EXT_ARG and REGISTERED_RING itself, so only it
/// can name them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnterFlags(u32);

impl EnterFlags {
    /// Run deferred task work and wait for `min_complete` completions.
    pub const GETEVENTS: Self = Self(1 << 0);
    /// The argument is an `io_uring_getevents_arg` instead of a signal mask.
    const EXT_ARG: Self = Self(1 << 3);
    /// The descriptor argument is a slot in the calling thread's ring table.
    const REGISTERED_RING: Self = Self(1 << 4);
    /// A blocking wait does not count as iowait.
    pub const NO_IOWAIT: Self = Self(1 << 7);

    /// No flags.
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Raw flag bits.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every flag in `other` is set.
    #[cfg(test)]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for EnterFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for EnterFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// The kernel's `__kernel_timespec`, two 64-bit fields on every target.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timespec {
    /// Whole seconds.
    tv_sec: i64,
    /// Nanoseconds below one second.
    tv_nsec: i64,
}

const _: () = {
    assert!(mem::size_of::<Timespec>() == 16);
    assert!(mem::offset_of!(Timespec, tv_sec) == 0);
    assert!(mem::offset_of!(Timespec, tv_nsec) == 8);
};

impl From<Duration> for Timespec {
    #[inline]
    fn from(duration: Duration) -> Self {
        Self {
            tv_sec: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(duration.subsec_nanos()),
        }
    }
}

/// The kernel's `io_uring_getevents_arg`, passed with EXT_ARG.
#[repr(C)]
struct GeteventsArg {
    /// Signal mask pointer, zero for none.
    sigmask: u64,
    /// Signal mask size.
    sigmask_sz: u32,
    /// Minimum wait in microseconds before returning fewer completions.
    min_wait_usec: u32,
    /// Pointer to the wait's [`Timespec`].
    ts: u64,
}

const _: () = {
    assert!(mem::size_of::<GeteventsArg>() == 24);
    assert!(mem::offset_of!(GeteventsArg, sigmask) == 0);
    assert!(mem::offset_of!(GeteventsArg, sigmask_sz) == 8);
    assert!(mem::offset_of!(GeteventsArg, min_wait_usec) == 12);
    assert!(mem::offset_of!(GeteventsArg, ts) == 16);
};

/// The kernel's `io_sqring_offsets`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SqringOffsets {
    /// Offset of the SQ head.
    head: u32,
    /// Offset of the SQ tail.
    tail: u32,
    /// Offset of the SQ ring mask.
    ring_mask: u32,
    /// Offset of the SQ entry count.
    ring_entries: u32,
    /// Offset of the SQ flags.
    flags: u32,
    /// Offset of the count of invalid SQEs the kernel dropped.
    dropped: u32,
    /// Offset of the SQ index array, absent with NO_SQARRAY.
    array: u32,
    /// Reserved.
    resv1: u32,
    /// User address of the rings, unused without user-provided memory.
    user_addr: u64,
}

const _: () = {
    assert!(mem::size_of::<SqringOffsets>() == 40);
    assert!(mem::offset_of!(SqringOffsets, head) == 0);
    assert!(mem::offset_of!(SqringOffsets, tail) == 4);
    assert!(mem::offset_of!(SqringOffsets, ring_mask) == 8);
    assert!(mem::offset_of!(SqringOffsets, ring_entries) == 12);
    assert!(mem::offset_of!(SqringOffsets, flags) == 16);
    assert!(mem::offset_of!(SqringOffsets, dropped) == 20);
    assert!(mem::offset_of!(SqringOffsets, array) == 24);
    assert!(mem::offset_of!(SqringOffsets, resv1) == 28);
    assert!(mem::offset_of!(SqringOffsets, user_addr) == 32);
};

/// The kernel's `io_cqring_offsets`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CqringOffsets {
    /// Offset of the CQ head.
    head: u32,
    /// Offset of the CQ tail.
    tail: u32,
    /// Offset of the CQ ring mask.
    ring_mask: u32,
    /// Offset of the CQ entry count.
    ring_entries: u32,
    /// Offset of the count of completions the kernel dropped.
    overflow: u32,
    /// Offset of the CQE array.
    cqes: u32,
    /// Offset of the CQ flags.
    flags: u32,
    /// Reserved.
    resv1: u32,
    /// User address of the rings, unused without user-provided memory.
    user_addr: u64,
}

const _: () = {
    assert!(mem::size_of::<CqringOffsets>() == 40);
    assert!(mem::offset_of!(CqringOffsets, head) == 0);
    assert!(mem::offset_of!(CqringOffsets, tail) == 4);
    assert!(mem::offset_of!(CqringOffsets, ring_mask) == 8);
    assert!(mem::offset_of!(CqringOffsets, ring_entries) == 12);
    assert!(mem::offset_of!(CqringOffsets, overflow) == 16);
    assert!(mem::offset_of!(CqringOffsets, cqes) == 20);
    assert!(mem::offset_of!(CqringOffsets, flags) == 24);
    assert!(mem::offset_of!(CqringOffsets, resv1) == 28);
    assert!(mem::offset_of!(CqringOffsets, user_addr) == 32);
};

/// The kernel's `io_uring_params`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Params {
    /// SQ size, rounded up by the kernel.
    sq_entries: u32,
    /// CQ size, chosen by the kernel without CQSIZE.
    cq_entries: u32,
    /// Setup flags.
    flags: u32,
    /// SQPOLL thread CPU, unused.
    sq_thread_cpu: u32,
    /// SQPOLL idle time, unused.
    sq_thread_idle: u32,
    /// Features the kernel reports.
    features: u32,
    /// Ring whose io-wq to share, unused.
    wq_fd: u32,
    /// Reserved.
    resv: [u32; 3],
    /// SQ word offsets in the rings mapping.
    sq_off: SqringOffsets,
    /// CQ word offsets in the rings mapping.
    cq_off: CqringOffsets,
}

const _: () = {
    assert!(mem::size_of::<Params>() == 120);
    assert!(mem::offset_of!(Params, sq_entries) == 0);
    assert!(mem::offset_of!(Params, cq_entries) == 4);
    assert!(mem::offset_of!(Params, flags) == 8);
    assert!(mem::offset_of!(Params, sq_thread_cpu) == 12);
    assert!(mem::offset_of!(Params, sq_thread_idle) == 16);
    assert!(mem::offset_of!(Params, features) == 20);
    assert!(mem::offset_of!(Params, wq_fd) == 24);
    assert!(mem::offset_of!(Params, resv) == 28);
    assert!(mem::offset_of!(Params, sq_off) == 40);
    assert!(mem::offset_of!(Params, cq_off) == 80);
};

/// The kernel's `io_uring_cqe` without the 32-byte extension.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cqe {
    /// Value of the completed SQE's `user_data`.
    user_data: u64,
    /// Result, a negated errno on failure.
    res: i32,
    /// Completion flags.
    flags: u32,
}

const _: () = {
    assert!(mem::size_of::<Cqe>() == 16);
    assert!(mem::offset_of!(Cqe, user_data) == 0);
    assert!(mem::offset_of!(Cqe, res) == 8);
    assert!(mem::offset_of!(Cqe, flags) == 12);
};

impl Cqe {
    /// Value of the completed SQE's `user_data`.
    #[inline]
    pub const fn user_data(&self) -> u64 {
        self.user_data
    }

    /// Result, a negated errno on failure.
    #[inline]
    pub const fn result(&self) -> i32 {
        self.res
    }

    /// Whether more completions of the same request follow.
    #[cfg(all(test, not(feature = "loom")))]
    pub const fn more(&self) -> bool {
        self.flags & IORING_CQE_F_MORE != 0
    }
}

/// The kernel's `io_uring_rsrc_update`, one ring descriptor table update.
#[repr(C)]
struct RsrcUpdate {
    /// Slot in the thread's table, or all ones to let the kernel choose.
    offset: u32,
    /// Must be zero.
    resv: u32,
    /// Descriptor to register, zero when unregistering.
    data: u64,
}

const _: () = {
    assert!(mem::size_of::<RsrcUpdate>() == 16);
    assert!(mem::offset_of!(RsrcUpdate, offset) == 0);
    assert!(mem::offset_of!(RsrcUpdate, resv) == 4);
    assert!(mem::offset_of!(RsrcUpdate, data) == 8);
};

/// The kernel's `io_uring_sync_cancel_reg`.
#[repr(C)]
struct SyncCancelReg {
    /// `user_data` of the requests to cancel.
    addr: u64,
    /// Descriptor to match, unused without the matching cancel flag.
    fd: i32,
    /// Cancel flags, zero to match by `user_data`.
    flags: u32,
    /// How long to wait for the cancelled requests, all ones for no limit.
    timeout: Timespec,
    /// Opcode to match, unused without the matching cancel flag.
    opcode: u8,
    /// Must be zero.
    pad: [u8; 7],
    /// Must be zero.
    pad2: [u64; 3],
}

const _: () = {
    assert!(mem::size_of::<SyncCancelReg>() == 64);
    assert!(mem::offset_of!(SyncCancelReg, addr) == 0);
    assert!(mem::offset_of!(SyncCancelReg, fd) == 8);
    assert!(mem::offset_of!(SyncCancelReg, flags) == 12);
    assert!(mem::offset_of!(SyncCancelReg, timeout) == 16);
    assert!(mem::offset_of!(SyncCancelReg, opcode) == 32);
    assert!(mem::offset_of!(SyncCancelReg, pad) == 33);
    assert!(mem::offset_of!(SyncCancelReg, pad2) == 40);
};

/// Error for ring memory the kernel described in a way this module cannot use.
fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("io_uring {what}"))
}

/// A shared mapping of the ring descriptor, unmapped on drop.
struct Mapping {
    /// Start of the mapping.
    ptr: NonNull<u8>,
    /// Length of the mapping in bytes.
    len: usize,
}

impl Mapping {
    /// Map `len` bytes of `fd` at the kernel-defined `offset`.
    fn new(fd: &OwnedFd, len: usize, offset: libc::off_t) -> io::Result<Self> {
        #[cfg(test)]
        tests::before_map(offset)?;

        // SAFETY: A new shared mapping placed by the kernel overlaps no
        // existing memory.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd.as_raw_fd(),
                offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let Some(ptr) = NonNull::new(ptr.cast::<u8>()) else {
            // SAFETY: The mapping was just created with this address and
            // length, and nothing refers to it.
            unsafe { libc::munmap(ptr, len) };
            return Err(invalid("mapping at address zero"));
        };

        #[cfg(test)]
        tests::mapped();
        Ok(Self { ptr, len })
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: The mapping was created with this address and length, and
        // nothing accesses it after the queues that point into it are gone.
        let result = unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
        debug_assert_eq!(result, 0, "{}", io::Error::last_os_error());

        #[cfg(test)]
        tests::unmapped();
    }
}

/// A 32-bit word of the shared rings, accessed only atomically.
#[derive(Clone, Copy)]
struct Word(NonNull<AtomicU32>);

impl Word {
    /// Locate the word at `offset` within the `len` bytes at `base`.
    ///
    /// # Safety
    ///
    /// `base` must be valid for atomic reads and writes of `len` bytes for
    /// as long as the returned word is used.
    unsafe fn new(base: NonNull<u8>, len: usize, offset: u32) -> io::Result<Self> {
        let offset = offset as usize;
        if offset
            .checked_add(mem::size_of::<AtomicU32>())
            .is_none_or(|end| end > len)
        {
            return Err(invalid("ring word outside its mapping"));
        }

        // SAFETY: The word ends within the `len` bytes at `base`.
        let word = unsafe { base.add(offset) }.cast::<AtomicU32>();
        if !word.is_aligned() {
            return Err(invalid("ring word misaligned"));
        }
        Ok(Self(word))
    }

    /// Load the word.
    #[inline]
    fn load(self, order: Ordering) -> u32 {
        // SAFETY: `Word::new` checked that the word lies within memory that
        // stays valid while the word is used.
        unsafe { self.0.as_ref() }.load(order)
    }

    /// Store the word.
    #[inline]
    fn store(self, value: u32, order: Ordering) {
        // SAFETY: `Word::new` checked that the word lies within memory that
        // stays valid while the word is used.
        unsafe { self.0.as_ref() }.store(value, order);
    }
}

/// Check that a ring's mask and entry count words match `entries`, which
/// must be a power of two.
fn check_ring_size(mask: Word, ring_entries: Word, entries: u32) -> io::Result<()> {
    if !entries.is_power_of_two()
        || mask.load(Ordering::Relaxed) != entries - 1
        || ring_entries.load(Ordering::Relaxed) != entries
    {
        return Err(invalid("ring size mismatch"));
    }
    Ok(())
}

/// The submission queue writer's state.
struct Sq {
    /// First SQE slot.
    sqes: NonNull<Sqe>,
    /// The SQ flags the kernel sets.
    kflags: Word,
    /// Number of slots.
    entries: u32,
    /// Number of SQEs staged from the first slot, which the next enter asks
    /// the kernel to submit.
    staged: u32,
}

impl Sq {
    /// Drop the first `consumed` staged SQEs, which an enter consumed, and
    /// move the rest to the first slots in order.
    #[inline]
    fn consume(&mut self, consumed: u32) {
        assert!(
            consumed <= self.staged,
            "kernel consumed {consumed} of {} SQEs",
            self.staged
        );
        let rest = self.staged - consumed;
        if consumed != 0 && rest != 0 {
            // SAFETY: Both ranges lie within the staged slots. The kernel
            // reads SQEs only during an enter, so none of them is in use.
            unsafe {
                ptr::copy(
                    self.sqes.add(consumed as usize).as_ptr(),
                    self.sqes.as_ptr(),
                    rest as usize,
                );
            }
        }
        self.staged = rest;
    }
}

/// The submission queue writer, borrowed from its ring.
///
/// The view only borrows the writer, so safe code cannot move a writer away
/// from the ring whose mappings it points into.
pub struct SubmissionQueue<'a> {
    /// Writer state, borrowed for the view's lifetime.
    sq: &'a mut Sq,
}

impl SubmissionQueue<'_> {
    /// Number of SQEs pushed but not yet consumed by the kernel.
    #[inline]
    pub const fn len(&self) -> usize {
        self.sq.staged as usize
    }

    /// Whether the kernel has consumed every pushed SQE.
    #[cfg(test)]
    pub const fn is_empty(&self) -> bool {
        self.sq.staged == 0
    }

    /// Whether no slot is free for another SQE.
    #[inline]
    pub const fn is_full(&self) -> bool {
        self.sq.staged == self.sq.entries
    }

    /// Whether the kernel holds completions that did not fit in the CQ.
    #[inline]
    pub fn cq_overflow(&self) -> bool {
        self.sq.kflags.load(Ordering::Acquire) & IORING_SQ_CQ_OVERFLOW != 0
    }

    /// Write `sqe` into the next free slot. The next enter submits it.
    ///
    /// # Safety
    ///
    /// Every buffer, descriptor, and other resource that `sqe` refers to
    /// must stay valid until its completion is reaped.
    ///
    /// # Panics
    ///
    /// Panics if the queue is full.
    #[inline]
    pub unsafe fn push(&mut self, sqe: &Sqe) {
        assert!(!self.is_full(), "submission queue is full");
        let sq = &mut *self.sq;

        // SAFETY: The slot after the staged SQEs is below the slot count. The
        // kernel reads SQEs only during an enter, so it is not in use.
        unsafe { sq.sqes.add(sq.staged as usize).write(*sqe) };
        sq.staged += 1;
    }
}

/// The completion queue reader's state.
struct Cq {
    /// First CQE slot.
    cqes: NonNull<Cqe>,
    /// The CQ head the kernel reads.
    khead: Word,
    /// The CQ tail the kernel writes.
    ktail: Word,
    /// The count of completions the kernel dropped.
    koverflow: Word,
    /// Number of slots minus one.
    mask: u32,
    /// Count of CQEs consumed.
    head: u32,
}

impl Cq {
    /// A view of the CQEs posted so far.
    #[inline]
    fn completion(&mut self) -> CompletionQueue<'_> {
        // The acquire load orders the kernel's writes of every CQE before the
        // tail ahead of reading them.
        let tail = self.ktail.load(Ordering::Acquire);
        CompletionQueue {
            head: self.head,
            tail,
            cq: self,
        }
    }
}

/// A view of the CQEs posted when it was created.
///
/// Iterating copies each CQE out. Dropping the view returns the slots of the
/// CQEs it yielded to the kernel.
pub struct CompletionQueue<'a> {
    /// Reader state, borrowed for the view's lifetime.
    cq: &'a mut Cq,
    /// Count of the next CQE to yield.
    head: u32,
    /// Count past the last CQE posted when the view was created.
    tail: u32,
}

impl CompletionQueue<'_> {
    /// Number of CQEs left in the view.
    #[inline]
    pub const fn len(&self) -> usize {
        self.tail.wrapping_sub(self.head) as usize
    }

    /// Whether the view has no CQEs left.
    #[cfg(test)]
    pub const fn is_empty(&self) -> bool {
        self.tail == self.head
    }

    /// Number of completions the kernel dropped because it could not hold
    /// them. It never decreases.
    #[inline]
    pub fn overflow(&self) -> u32 {
        self.cq.koverflow.load(Ordering::Acquire)
    }
}

impl Iterator for CompletionQueue<'_> {
    type Item = Cqe;

    #[inline]
    fn next(&mut self) -> Option<Cqe> {
        if self.head == self.tail {
            return None;
        }
        let index = (self.head & self.cq.mask) as usize;

        // SAFETY: `index` is below the slot count. The acquire load of the
        // tail ordered the kernel's write of this CQE before this read, and
        // the kernel does not reuse the slot until the head store that
        // follows.
        let cqe = unsafe { self.cq.cqes.add(index).read() };
        self.head = self.head.wrapping_add(1);
        Some(cqe)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}

impl Drop for CompletionQueue<'_> {
    #[inline]
    fn drop(&mut self) {
        if self.head != self.cq.head {
            // The release store orders every CQE read before it ahead of the
            // kernel's reuse of the slot.
            self.cq.khead.store(self.head, Ordering::Release);
            self.cq.head = self.head;
        }
    }
}

/// Build the SQ writer and CQ reader over ring memory laid out as `params`
/// describes.
///
/// # Safety
///
/// `rings` must be valid for atomic reads and writes of `rings_len` bytes,
/// and `sqes` for writes of `params.sq_entries` SQEs, as long as the queues
/// are used. No other user-side writer may access the queues.
unsafe fn queues(
    params: &Params,
    rings: NonNull<u8>,
    rings_len: usize,
    sqes: NonNull<Sqe>,
) -> io::Result<(Sq, Cq)> {
    let (sq_off, cq_off) = (&params.sq_off, &params.cq_off);

    // SAFETY: The caller guarantees `rings_len` bytes at `rings`, and each
    // word is checked against them.
    let word = |offset| unsafe { Word::new(rings, rings_len, offset) };
    check_ring_size(
        word(sq_off.ring_mask)?,
        word(sq_off.ring_entries)?,
        params.sq_entries,
    )?;
    check_ring_size(
        word(cq_off.ring_mask)?,
        word(cq_off.ring_entries)?,
        params.cq_entries,
    )?;

    let cqes_offset = cq_off.cqes as usize;
    if (params.cq_entries as usize)
        .checked_mul(mem::size_of::<Cqe>())
        .and_then(|size| size.checked_add(cqes_offset))
        .is_none_or(|end| end > rings_len)
    {
        return Err(invalid("CQEs outside their mapping"));
    }

    // SAFETY: The CQE array ends within the `rings_len` bytes at `rings`.
    let cqes = unsafe { rings.add(cqes_offset) }.cast::<Cqe>();
    if !cqes.is_aligned() || !sqes.is_aligned() {
        return Err(invalid("entries misaligned"));
    }

    let sq = Sq {
        sqes,
        kflags: word(sq_off.flags)?,
        entries: params.sq_entries,
        staged: 0,
    };
    let cq = Cq {
        cqes,
        khead: word(cq_off.head)?,
        ktail: word(cq_off.tail)?,
        koverflow: word(cq_off.overflow)?,
        mask: params.cq_entries - 1,
        head: 0,
    };
    Ok((sq, cq))
}

/// An io_uring instance and its shared memory, owned by the creating thread.
pub struct Ring {
    /// SQ writer over the mappings.
    sq: Sq,
    /// CQ reader over the rings mapping.
    cq: Cq,
    /// The ring's slot in the owner thread's ring table, which enters name
    /// the ring by when present.
    slot: Option<u32>,
    /// SQE array mapping, unmapped after the queues are gone.
    _sqes: Mapping,
    /// Shared rings mapping, unmapped after the queues are gone.
    _rings: Mapping,
    /// The ring descriptor, closed after the mappings.
    fd: OwnedFd,
    /// Keeps the ring, and so its registered slot, on the owner thread.
    _owner: PhantomData<*const ()>,
}

impl Ring {
    /// Create a ring of at least `entries` SQ slots and map its memory.
    ///
    /// The kernel rounds the SQ size up to a power of two and sizes the CQ at
    /// twice that.
    pub fn new(entries: u32) -> io::Result<Self> {
        let mut params = Params {
            flags: IORING_SETUP_SINGLE_ISSUER
                | IORING_SETUP_DEFER_TASKRUN
                | IORING_SETUP_NO_SQARRAY
                | IORING_SETUP_SQ_REWIND,
            ..Params::default()
        };

        // SAFETY: `params` is a writable `io_uring_params`, which the kernel
        // reads and fills during the call.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                c_long::from(entries.cast_signed()),
                &raw mut params,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: The kernel returned a new descriptor that nothing else
        // owns. Adopting it at once closes it on every later failure.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        debug_assert!(params.features & IORING_FEAT_SINGLE_MMAP != 0);

        // With NO_SQARRAY and 16-byte CQEs, the CQE array ends the shared
        // rings, so one mapping of this length covers both rings.
        let rings_len = (params.cq_entries as usize)
            .checked_mul(mem::size_of::<Cqe>())
            .and_then(|size| size.checked_add(params.cq_off.cqes as usize))
            .ok_or_else(|| invalid("rings size overflow"))?;
        let sqes_len = (params.sq_entries as usize)
            .checked_mul(mem::size_of::<Sqe>())
            .ok_or_else(|| invalid("SQE array size overflow"))?;

        // Each mapping owns itself at once, so a failure or an unwind unmaps
        // it before the descriptor closes.
        let rings = Mapping::new(&fd, rings_len, IORING_OFF_SQ_RING)?;
        let sqes = Mapping::new(&fd, sqes_len, IORING_OFF_SQES)?;

        // SAFETY: Both mappings span the lengths passed and are unmapped only
        // after the queues, which the ring owns alongside them. The ring is
        // the only user-side writer.
        let (sq, cq) = unsafe { queues(&params, rings.ptr, rings.len, sqes.ptr.cast()) }?;
        Ok(Self {
            sq,
            cq,
            slot: None,
            _sqes: sqes,
            _rings: rings,
            fd,
            _owner: PhantomData,
        })
    }

    /// The ring descriptor.
    #[inline]
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// The ring's slot in the owner thread's ring table, if registered.
    #[inline]
    pub const fn slot(&self) -> Option<u32> {
        self.slot
    }

    /// The submission queue writer.
    #[inline]
    pub const fn submission(&mut self) -> SubmissionQueue<'_> {
        SubmissionQueue { sq: &mut self.sq }
    }

    /// A view of the CQEs posted so far.
    #[inline]
    pub fn completion(&mut self) -> CompletionQueue<'_> {
        self.cq.completion()
    }

    /// Submit every pushed, unconsumed SQE and then do what `flags` ask.
    ///
    /// `timeout`, when present, bounds a wait for `min_complete` completions
    /// through EXT_ARG. A registered ring enters through its slot. Returns the
    /// number of SQEs the kernel consumed, which falls short of the pushed
    /// count when the kernel stopped early, and then GETEVENTS was skipped.
    #[inline]
    pub fn enter(
        &mut self,
        min_complete: u32,
        mut flags: EnterFlags,
        timeout: Option<&Timespec>,
    ) -> io::Result<u32> {
        let to_submit = self.sq.staged;

        // No signal mask. EXT_ARG bounds the wait without a timeout SQE.
        let arg = timeout.map(|timeout| GeteventsArg {
            sigmask: 0,
            sigmask_sz: 0,
            min_wait_usec: 0,
            ts: ptr::from_ref(timeout) as usize as u64,
        });
        let (arg_ptr, arg_size) = arg.as_ref().map_or((ptr::null(), 0), |arg| {
            flags |= EnterFlags::EXT_ARG;
            (
                ptr::from_ref(arg).cast::<c_void>(),
                mem::size_of::<GeteventsArg>(),
            )
        });
        if self.slot.is_some() {
            flags |= EnterFlags::REGISTERED_RING;
        }
        let fd = self.slot.map_or_else(
            || c_long::from(self.raw_fd()),
            |slot| c_long::from(slot.cast_signed()),
        );

        #[cfg(test)]
        {
            tests::record_enter(min_complete, flags);
            if let Some(error) = tests::enter_failure() {
                return Err(error);
            }
        }

        // SAFETY: `fd` names this ring, by its slot in this thread's table
        // when REGISTERED_RING is set. Pushing guaranteed that the staged
        // SQEs' resources outlive their completions. `arg_ptr` is null
        // exactly when EXT_ARG is unset, and otherwise points to an
        // `io_uring_getevents_arg` of `arg_size` bytes whose timespec pointer
        // refers to `timeout`. Both outlive the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                fd,
                c_long::from(to_submit.cast_signed()),
                c_long::from(min_complete.cast_signed()),
                c_long::from(flags.bits().cast_signed()),
                arg_ptr,
                arg_size,
            )
        };
        if result < 0 {
            // A negative result consumed no SQE.
            return Err(io::Error::last_os_error());
        }
        let consumed = u32::try_from(result).unwrap_or(u32::MAX);
        self.sq.consume(consumed);
        Ok(consumed)
    }

    /// Register the ring descriptor with the calling thread and return its
    /// slot, which later enters name the ring by.
    ///
    /// # Panics
    ///
    /// Panics if the ring is already registered.
    pub fn register(&mut self) -> io::Result<u32> {
        assert!(self.slot.is_none(), "ring already registered");
        let mut update = RsrcUpdate {
            offset: u32::MAX,
            resv: 0,
            data: u64::from(self.raw_fd().cast_unsigned()),
        };

        // SAFETY: `update` is one writable `io_uring_rsrc_update`, which the
        // kernel reads and fills with the chosen slot during the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                c_long::from(self.raw_fd()),
                IORING_REGISTER_RING_FDS,
                &raw mut update,
                1 as c_long,
            )
        };
        match result {
            1 => {
                self.slot = Some(update.offset);
                Ok(update.offset)
            }
            result if result < 0 => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other(
                "ring descriptor registration was not applied",
            )),
        }
    }

    /// Release the ring's registered slot, if any, through the raw
    /// descriptor. Later enters use the raw descriptor.
    ///
    /// A failure leaves the slot registered until the owner thread exits.
    pub fn unregister(&mut self) -> io::Result<()> {
        let Some(slot) = self.slot.take() else {
            return Ok(());
        };
        let update = RsrcUpdate {
            offset: slot,
            resv: 0,
            data: 0,
        };

        // SAFETY: `update` is one `io_uring_rsrc_update`, which the kernel
        // reads during the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                c_long::from(self.raw_fd()),
                IORING_UNREGISTER_RING_FDS,
                &raw const update,
                1 as c_long,
            )
        };
        match result {
            1 => Ok(()),
            result if result < 0 => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other(
                "ring descriptor unregistration was not applied",
            )),
        }
    }

    /// Cancel a request with `user_data` and wait for it to finish.
    ///
    /// Without cancel flags, the kernel cancels only the first match. Fails
    /// with `ENOENT` when no such request is live.
    pub fn cancel_sync(&self, user_data: u64) -> io::Result<()> {
        let cancel = SyncCancelReg {
            addr: user_data,
            fd: -1,
            flags: 0,
            timeout: Timespec {
                tv_sec: -1,
                tv_nsec: -1,
            },
            opcode: 0,
            pad: [0; 7],
            pad2: [0; 3],
        };

        // SAFETY: `cancel` is one `io_uring_sync_cancel_reg`, which the kernel
        // reads during the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                c_long::from(self.raw_fd()),
                IORING_REGISTER_SYNC_CANCEL,
                &raw const cancel,
                1 as c_long,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // A ring dropped while registered releases its slot before the
        // mappings and the descriptor go. An owner that reports failures
        // unregisters first.
        let _ = self.unregister();
    }
}

// The registered slot belongs to the creating thread, so a ring can move to
// no other one. Naming it through both impls of a trait is ambiguous, and so
// fails to compile, exactly when the ring is `Send` or `Sync`.
const _: () = {
    trait AmbiguousIfSend<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
    let _ = <Ring as AmbiguousIfSend<_>>::check;

    trait AmbiguousIfSync<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
    let _ = <Ring as AmbiguousIfSync<_>>::check;
};

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::{
        cell::Cell,
        panic::{AssertUnwindSafe, catch_unwind},
    };

    thread_local! {
        /// Minimum completion count and flags of this thread's latest enter.
        static LAST_ENTER: Cell<Option<(u32, EnterFlags)>> = const { Cell::new(None) };

        /// Error the next enter on this thread returns instead of entering.
        static FAIL_ENTER: Cell<Option<i32>> = const { Cell::new(None) };

        /// Mapping offset whose next mapping on this thread fails, and whether
        /// the failure panics instead of returning an error.
        static FAIL_MAP: Cell<Option<(libc::off_t, bool)>> = const { Cell::new(None) };

        /// Mappings this thread created minus those it unmapped. A ring
        /// dropped on another thread unmaps there.
        static LIVE_MAPPINGS: Cell<isize> = const { Cell::new(0) };
    }

    /// Remember an enter's arguments for assertions on the calling thread.
    pub fn record_enter(min_complete: u32, flags: EnterFlags) {
        LAST_ENTER.set(Some((min_complete, flags)));
    }

    /// Minimum completion count and flags of this thread's latest enter.
    pub fn last_enter() -> Option<(u32, EnterFlags)> {
        LAST_ENTER.get()
    }

    /// The flag [`Ring::enter`] sets for an enter bounded by a timeout.
    pub const EXT_ARG: EnterFlags = EnterFlags::EXT_ARG;

    /// The flag [`Ring::enter`] sets for an enter through a registered slot.
    pub const REGISTERED_RING: EnterFlags = EnterFlags::REGISTERED_RING;

    /// Fail this thread's next enter with `errno`, as a kernel that rejects
    /// the enter before submitting does.
    pub fn fail_next_enter(errno: i32) {
        FAIL_ENTER.set(Some(errno));
    }

    /// Take the injected failure of this enter, if any.
    pub(super) fn enter_failure() -> Option<io::Error> {
        FAIL_ENTER.take().map(io::Error::from_raw_os_error)
    }

    /// Number of CQ slots of `ring`.
    pub const fn cq_entries(ring: &Ring) -> u32 {
        ring.cq.mask + 1
    }

    /// Release `ring`'s registered slot behind its back, so its enters name a
    /// slot the calling thread no longer holds.
    pub fn release_slot(ring: &Ring) {
        let update = RsrcUpdate {
            offset: ring.slot.expect("registered ring"),
            resv: 0,
            data: 0,
        };

        // SAFETY: `update` is one `io_uring_rsrc_update`, which the kernel
        // reads during the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                c_long::from(ring.raw_fd()),
                IORING_UNREGISTER_RING_FDS,
                &raw const update,
                1 as c_long,
            )
        };
        assert_eq!(result, 1, "{}", io::Error::last_os_error());
    }

    /// Fail the next mapping at `offset` on this thread, by panicking when
    /// `panic` is set.
    fn fail_map(offset: libc::off_t, panic: bool) {
        FAIL_MAP.set(Some((offset, panic)));
    }

    /// Apply an injected mapping failure.
    pub(super) fn before_map(offset: libc::off_t) -> io::Result<()> {
        match FAIL_MAP.get() {
            Some((target, panic)) if target == offset => {
                FAIL_MAP.set(None);
                assert!(!panic, "injected panic before mapping");
                Err(io::Error::from_raw_os_error(libc::ENOMEM))
            }
            _ => Ok(()),
        }
    }

    /// Count a created mapping.
    pub(super) fn mapped() {
        LIVE_MAPPINGS.set(LIVE_MAPPINGS.get() + 1);
    }

    /// Count a removed mapping.
    pub(super) fn unmapped() {
        LIVE_MAPPINGS.set(LIVE_MAPPINGS.get() - 1);
    }

    /// Slots in the fake ring's SQ.
    const SQ_ENTRIES: u32 = 4;
    /// Slots in the fake ring's CQ.
    const CQ_ENTRIES: u32 = 8;
    /// Offset of the fake ring's CQEs.
    const CQES: u32 = 128;
    /// Length of the fake ring's shared rings.
    const RINGS_LEN: usize = CQES as usize + CQ_ENTRIES as usize * mem::size_of::<Cqe>();

    /// Ring parameters describing the fake ring's layout.
    fn fake_params() -> Params {
        Params {
            sq_entries: SQ_ENTRIES,
            cq_entries: CQ_ENTRIES,
            sq_off: SqringOffsets {
                head: 0,
                tail: 4,
                ring_mask: 8,
                ring_entries: 12,
                flags: 16,
                dropped: 20,
                ..SqringOffsets::default()
            },
            cq_off: CqringOffsets {
                head: 64,
                tail: 68,
                ring_mask: 72,
                ring_entries: 76,
                overflow: 80,
                cqes: CQES,
                ..CqringOffsets::default()
            },
            ..Params::default()
        }
    }

    /// Heap memory standing in for a ring's mappings, with the kernel's side
    /// of its queues.
    ///
    /// Every access goes through the pointers taken once at creation, so
    /// none invalidates the queues' pointers.
    struct FakeRing {
        /// Shared rings.
        rings: NonNull<u8>,
        /// SQE slots.
        sqes: NonNull<Sqe>,
        /// Owner of the shared rings.
        rings_alloc: *mut [u64],
        /// Owner of the SQE slots.
        sqes_alloc: *mut [[u64; 8]],
    }

    impl FakeRing {
        /// Allocate a fake ring and fill in the words a kernel writes at
        /// setup.
        fn new() -> Self {
            let rings_alloc = Box::into_raw(vec![0u64; RINGS_LEN / 8].into_boxed_slice());
            let sqes_alloc = Box::into_raw(vec![[0u64; 8]; SQ_ENTRIES as usize].into_boxed_slice());
            let ring = Self {
                rings: NonNull::new(rings_alloc.cast()).unwrap(),
                sqes: NonNull::new(sqes_alloc.cast()).unwrap(),
                rings_alloc,
                sqes_alloc,
            };
            let params = fake_params();
            ring.word(params.sq_off.ring_mask)
                .store(SQ_ENTRIES - 1, Ordering::Relaxed);
            ring.word(params.sq_off.ring_entries)
                .store(SQ_ENTRIES, Ordering::Relaxed);
            ring.word(params.cq_off.ring_mask)
                .store(CQ_ENTRIES - 1, Ordering::Relaxed);
            ring.word(params.cq_off.ring_entries)
                .store(CQ_ENTRIES, Ordering::Relaxed);
            ring
        }

        /// Build the queues over the fake ring.
        fn queues(&self) -> (Sq, Cq) {
            // SAFETY: The fake ring's memory outlives the queues in every
            // test, which declare it first.
            unsafe { queues(&fake_params(), self.rings, RINGS_LEN, self.sqes) }.unwrap()
        }

        /// The word at `offset` of the shared rings.
        fn word(&self, offset: u32) -> &AtomicU32 {
            // SAFETY: Every offset the tests pass is an aligned word within
            // the shared rings.
            unsafe { self.rings.add(offset as usize).cast::<AtomicU32>().as_ref() }
        }

        /// Move the CQ's counters to `start`, as if that many CQEs had
        /// passed through it.
        fn wind_cq(&self, cq: &mut Cq, start: u32) {
            let params = fake_params();
            self.word(params.cq_off.head)
                .store(start, Ordering::Relaxed);
            self.word(params.cq_off.tail)
                .store(start, Ordering::Relaxed);
            cq.head = start;
        }

        /// Fetch `count` SQEs from the first slot, as the kernel does on a
        /// rewinding ring, and return their `user_data`.
        fn fetch(&self, count: u32) -> Vec<u64> {
            (0..count as usize)
                .map(|slot| {
                    // SAFETY: The slot is within the SQE slots, and the queue
                    // does not write it during a fetch.
                    unsafe { self.sqes.add(slot).read() }.user_data()
                })
                .collect()
        }

        /// The shared SQ head and tail, which the kernel ignores and the
        /// writer never writes.
        fn sq_cursors(&self) -> (u32, u32) {
            let params = fake_params();
            (
                self.word(params.sq_off.head).load(Ordering::Acquire),
                self.word(params.sq_off.tail).load(Ordering::Acquire),
            )
        }

        /// Post a CQE as the kernel does.
        fn post(&self, user_data: u64, res: i32) {
            let tail_word = self.word(fake_params().cq_off.tail);
            let tail = tail_word.load(Ordering::Relaxed);
            let slot = (tail & (CQ_ENTRIES - 1)) as usize;
            let cqe = Cqe {
                user_data,
                res,
                flags: 0,
            };
            // SAFETY: The slot is within the CQEs, and the reader does not
            // read it before the tail store that follows.
            unsafe {
                self.rings
                    .add(CQES as usize)
                    .cast::<Cqe>()
                    .add(slot)
                    .write(cqe)
            };
            tail_word.store(tail.wrapping_add(1), Ordering::Release);
        }

        /// The CQ head the reader returned to the kernel.
        fn cq_head(&self) -> u32 {
            self.word(fake_params().cq_off.head).load(Ordering::Acquire)
        }
    }

    impl Drop for FakeRing {
        fn drop(&mut self) {
            // SAFETY: Both allocations came from `Box::into_raw` and are freed
            // once, after the queues over them are gone.
            unsafe {
                drop(Box::from_raw(self.rings_alloc));
                drop(Box::from_raw(self.sqes_alloc));
            }
        }
    }

    /// A NOP SQE carrying `user_data`.
    fn nop(user_data: u64) -> Sqe {
        Sqe::nop().with_user_data(user_data)
    }

    /// The writer over `sq`, as `Ring::submission` creates it.
    const fn writer(sq: &mut Sq) -> SubmissionQueue<'_> {
        SubmissionQueue { sq }
    }

    /// Push SQEs carrying each `user_data`.
    fn push(sq: &mut Sq, user_data: impl IntoIterator<Item = u64>) {
        let mut writer = writer(sq);
        for user_data in user_data {
            // SAFETY: A NOP refers to no resources.
            unsafe { writer.push(&nop(user_data)) };
        }
    }

    /// Submit like `Ring::enter`, offering the kernel the staged SQEs, and
    /// with the fake kernel fetching `count` of them. Returns the number
    /// offered and the `user_data` fetched.
    fn submit(sq: &mut Sq, ring: &FakeRing, count: u32) -> (u32, Vec<u64>) {
        let to_submit = sq.staged;
        assert!(count <= to_submit, "fetched unstaged SQEs");
        let fetched = ring.fetch(count);
        sq.consume(count);
        (to_submit, fetched)
    }

    /// Every enter offers the staged SQEs from the first slot. A full or empty
    /// consumption moves nothing, an error or a zero count keeps every SQE,
    /// and a partial one moves the rest to the first slots, in order and
    /// ahead of later pushes, overlapping their old slots when the rest
    /// outnumbers the consumed SQEs. The shared SQ head and tail stay zero.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_sq_offers_staged_entries_from_the_first_slot() {
        let ring = FakeRing::new();
        let (mut sq, _cq) = ring.queues();

        // An empty queue offers nothing.
        assert_eq!(submit(&mut sq, &ring, 0), (0, vec![]));

        // A full consumption empties the queue.
        push(&mut sq, [1, 2]);
        assert_eq!(writer(&mut sq).len(), 2);
        assert_eq!(submit(&mut sq, &ring, 2), (2, vec![1, 2]));
        assert!(writer(&mut sq).is_empty());

        // A zero count keeps every SQE in place.
        push(&mut sq, [3, 4, 5, 6]);
        assert!(writer(&mut sq).is_full());
        assert_eq!(submit(&mut sq, &ring, 0), (4, vec![]));
        assert_eq!(ring.fetch(4), [3, 4, 5, 6]);

        // A partial consumption moves the overlapping rest to the front.
        assert_eq!(submit(&mut sq, &ring, 1), (4, vec![3]));
        assert_eq!(writer(&mut sq).len(), 3);
        assert_eq!(ring.fetch(3), [4, 5, 6]);

        // A push follows the moved SQEs, and the next enter offers them first.
        push(&mut sq, [7]);
        assert!(writer(&mut sq).is_full());
        assert_eq!(submit(&mut sq, &ring, 3), (4, vec![4, 5, 6]));
        assert_eq!(ring.fetch(1), [7]);
        push(&mut sq, [8]);
        assert_eq!(submit(&mut sq, &ring, 2), (2, vec![7, 8]));
        assert!(writer(&mut sq).is_empty());
        assert_eq!(ring.sq_cursors(), (0, 0));
    }

    /// Pushing into a full queue panics instead of overwriting an unconsumed
    /// slot.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "submission queue is full")]
    fn test_sq_push_rejects_a_full_queue() {
        let ring = FakeRing::new();
        let (mut sq, _cq) = ring.queues();
        push(&mut sq, 0..=u64::from(SQ_ENTRIES));
    }

    /// A kernel that reports consuming more SQEs than were submitted panics
    /// before the writer can reuse a staged slot.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "kernel consumed 2 of 1 SQEs")]
    fn test_sq_rejects_overconsumption() {
        let ring = FakeRing::new();
        let (mut sq, _cq) = ring.queues();
        push(&mut sq, [1]);
        sq.consume(2);
    }

    /// A view yields the CQEs posted before it was created and returns
    /// exactly the slots it yielded.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_cq_returns_the_consumed_prefix() {
        let ring = FakeRing::new();
        let (_sq, mut cq) = ring.queues();
        ring.wind_cq(&mut cq, u32::MAX - 2);

        // A view that yields nothing returns nothing.
        for user_data in 1..=4 {
            ring.post(user_data, 0);
        }
        drop(cq.completion());
        assert_eq!(ring.cq_head(), u32::MAX - 2);

        // A partly read view returns only the CQEs it yielded, and a CQE
        // posted after the view was created waits for the next one.
        let mut view = cq.completion();
        ring.post(5, -libc::EAGAIN);
        assert_eq!(view.len(), 4);
        let first: Vec<_> = view.by_ref().take(3).map(|cqe| cqe.user_data()).collect();
        assert_eq!(first, [1, 2, 3]);
        assert_eq!(view.len(), 1);
        drop(view);
        assert_eq!(ring.cq_head(), (u32::MAX - 2).wrapping_add(3));

        // The next view continues across the wrap.
        let rest: Vec<_> = cq
            .completion()
            .map(|cqe| (cqe.user_data(), cqe.result()))
            .collect();
        assert_eq!(rest, [(4, 0), (5, -libc::EAGAIN)]);
        assert_eq!(ring.cq_head(), 2);
        assert!(cq.completion().is_empty());
    }

    /// The overflow counter reports dropped completions without affecting
    /// the CQEs in view.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_cq_reports_dropped_completions() {
        let ring = FakeRing::new();
        let (_sq, mut cq) = ring.queues();
        ring.post(1, 0);
        assert_eq!(cq.completion().overflow(), 0);
        ring.word(fake_params().cq_off.overflow)
            .store(1, Ordering::Release);
        let view = cq.completion();
        assert_eq!(view.overflow(), 1);
        assert_eq!(view.len(), 1);
    }

    /// Ring memory whose layout does not fit its mapping is rejected.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_queues_reject_invalid_layouts() {
        let ring = FakeRing::new();
        let check = |params: Params| {
            // SAFETY: The fake ring's memory outlives the call, and no queue
            // is returned.
            let result = unsafe { queues(&params, ring.rings, RINGS_LEN, ring.sqes) };
            assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidData);
        };
        let mut params = fake_params();
        params.sq_off.flags = RINGS_LEN as u32 - 2;
        check(params);
        let mut params = fake_params();
        params.cq_off.head = 66;
        check(params);
        let mut params = fake_params();
        params.cq_off.cqes = CQES + 8;
        check(params);
        let mut params = fake_params();
        params.cq_off.cqes = CQES - 1;
        check(params);
        let mut params = fake_params();
        params.sq_entries = SQ_ENTRIES * 2;
        check(params);
    }

    /// A failed or panicking mapping unmaps the mappings made before it.
    #[test]
    fn test_failed_setup_unmaps_its_mappings() {
        fail_map(IORING_OFF_SQ_RING, false);
        let error = Ring::new(8).err().unwrap();
        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
        assert_eq!(LIVE_MAPPINGS.get(), 0);

        fail_map(IORING_OFF_SQES, false);
        let error = Ring::new(8).err().unwrap();
        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
        assert_eq!(LIVE_MAPPINGS.get(), 0);

        fail_map(IORING_OFF_SQES, true);
        assert!(catch_unwind(AssertUnwindSafe(|| Ring::new(8))).is_err());
        assert_eq!(LIVE_MAPPINGS.get(), 0);

        let ring = Ring::new(8).unwrap();
        assert_eq!(LIVE_MAPPINGS.get(), 2);
        drop(ring);
        assert_eq!(LIVE_MAPPINGS.get(), 0);
    }

    /// A real ring submits through its raw descriptor and its registered
    /// slot, and its CQ yields each completion once.
    #[test]
    fn test_ring_submits_and_completes() {
        let mut ring = Ring::new(4).unwrap();
        for registered in [false, true] {
            if registered {
                ring.register().unwrap();
            }
            for user_data in 0..4 {
                // SAFETY: A NOP refers to no resources.
                unsafe { ring.submission().push(&nop(user_data)) };
            }
            assert!(ring.submission().is_full());
            assert_eq!(ring.enter(4, EnterFlags::GETEVENTS, None).unwrap(), 4);
            let (min_complete, flags) = last_enter().unwrap();
            assert_eq!(min_complete, 4);
            assert_eq!(flags.contains(REGISTERED_RING), registered);
            assert!(ring.submission().is_empty());
            let completed: Vec<_> = ring.completion().map(|cqe| cqe.user_data()).collect();
            assert_eq!(completed, [0, 1, 2, 3]);
            assert!(ring.completion().is_empty());
        }
        ring.unregister().unwrap();
        assert_eq!(ring.slot(), None);
    }

    /// A submission that stops at an SQE the kernel rejects consumes exactly
    /// the SQEs up to and including that one. The next enter offers the rest
    /// first, then a later push, and each completes once.
    #[test]
    fn test_ring_resubmits_the_unconsumed_suffix() {
        let mut ring = Ring::new(4).unwrap();
        let word = AtomicU32::new(0);
        for rejected in [0u32, 1] {
            // Invalid futex2 flags fail the wait's preparation, which ends the
            // submission after it.
            let invalid = Sqe::futex_wait(word.as_ptr(), 0, u64::MAX, u32::MAX);
            let mut sq = ring.submission();
            for user_data in 1..=4 {
                let sqe = if user_data == u64::from(rejected) + 1 {
                    invalid.with_user_data(user_data)
                } else {
                    nop(user_data)
                };
                // SAFETY: NOPs refer to no resources, and the kernel rejects
                // the wait before it reads the word.
                unsafe { sq.push(&sqe) };
            }
            let consumed = rejected + 1;
            assert_eq!(ring.enter(0, EnterFlags::empty(), None).unwrap(), consumed);
            assert_eq!(ring.submission().len(), 4 - consumed as usize);
            let completed: Vec<_> = ring
                .completion()
                .map(|cqe| (cqe.user_data(), cqe.result()))
                .collect();
            let mut expected: Vec<_> = (1..u64::from(consumed)).map(|nop| (nop, 0)).collect();
            expected.push((u64::from(consumed), -libc::EINVAL));
            assert_eq!(completed, expected);

            // The rest goes first, then a push.
            // SAFETY: A NOP refers to no resources.
            unsafe { ring.submission().push(&nop(5)) };
            let submitted = ring.enter(0, EnterFlags::empty(), None);
            assert_eq!(submitted.unwrap(), 5 - consumed);
            assert!(ring.submission().is_empty());
            let completed: Vec<_> = ring.completion().map(|cqe| cqe.user_data()).collect();
            assert_eq!(completed, (u64::from(consumed) + 1..=5).collect::<Vec<_>>());
        }
    }

    /// A wait that times out after a positive submission reports the
    /// submission instead of the timeout, so the submitted SQE leaves the
    /// queue.
    #[test]
    fn test_ring_counts_a_submission_whose_wait_fails() {
        // The wait's futex key outlives any wait a failed test leaves queued.
        static WORD: AtomicU32 = AtomicU32::new(0);
        const FUTEX2_PRIVATE_U32: u32 = 0x02 | libc::FUTEX_PRIVATE_FLAG as u32;

        let mut ring = Ring::new(4).unwrap();
        let wait = Sqe::futex_wait(WORD.as_ptr(), 0, u64::from(u32::MAX), FUTEX2_PRIVATE_U32);
        // SAFETY: The word is static.
        unsafe { ring.submission().push(&wait.with_user_data(7)) };
        let timeout = Timespec::from(Duration::from_millis(1));
        assert_eq!(
            ring.enter(1, EnterFlags::GETEVENTS, Some(&timeout))
                .unwrap(),
            1
        );
        assert!(ring.submission().is_empty());
        assert!(ring.completion().is_empty());

        // Cancel the wait and reap both completions.
        // SAFETY: A cancel refers only to the target's user_data.
        unsafe {
            ring.submission()
                .push(&Sqe::async_cancel(7).with_user_data(8))
        };
        let timeout = Timespec::from(Duration::from_secs(10));
        assert_eq!(
            ring.enter(2, EnterFlags::GETEVENTS, Some(&timeout))
                .unwrap(),
            1
        );
        let mut completed: Vec<_> = ring
            .completion()
            .map(|cqe| (cqe.user_data(), cqe.result()))
            .collect();
        completed.sort_unstable();
        assert_eq!(completed.len(), 2);
        assert_eq!(completed[0], (7, -libc::ECANCELED));
        // A cancel reports success as a nonnegative count.
        assert_eq!(completed[1].0, 8);
        assert!(completed[1].1 >= 0, "{}", completed[1].1);
    }

    /// An enter that fails before submitting keeps every staged SQE, and the
    /// next enter submits each once.
    #[test]
    fn test_ring_keeps_staged_entries_when_enter_fails() {
        let mut ring = Ring::new(4).unwrap();
        ring.register().unwrap();
        // SAFETY: NOPs refer to no resources.
        unsafe {
            let mut sq = ring.submission();
            sq.push(&nop(1));
            sq.push(&nop(2));
        }

        // A slot released behind the ring fails the enter before submission.
        release_slot(&ring);
        let error = ring.enter(0, EnterFlags::empty(), None).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        assert_eq!(ring.submission().len(), 2);
        assert!(ring.completion().is_empty());

        // The raw descriptor submits both.
        ring.unregister().unwrap();
        assert_eq!(ring.enter(0, EnterFlags::empty(), None).unwrap(), 2);
        let completed: Vec<_> = ring.completion().map(|cqe| cqe.user_data()).collect();
        assert_eq!(completed, [1, 2]);
    }

    /// A timed wait on an empty ring times out after its timeout.
    #[test]
    fn test_ring_timed_wait_times_out() {
        let mut ring = Ring::new(4).unwrap();
        let timeout = Duration::from_millis(20);
        let start = std::time::Instant::now();
        let error = ring
            .enter(1, EnterFlags::GETEVENTS, Some(&timeout.into()))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ETIME));
        assert!(start.elapsed() >= timeout);
        let (_, flags) = last_enter().unwrap();
        assert!(flags.contains(EXT_ARG));
    }
}
