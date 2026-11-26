//! The io_uring kernel interface.
//!
//! [`IoUring`] creates a ring with SINGLE_ISSUER, DEFER_TASKRUN, NO_SQARRAY, and
//! SQ_REWIND, maps its shared rings and SQE array, and owns the submission
//! queue writer, the completion queue reader, and the `io_uring_enter` and
//! `io_uring_register` calls. This module also defines the kernel ABI they
//! use, including [`SqueueEntry`] and its encoders.
//!
//! # Entries
//!
//! [`SqueueEntry`] mirrors `struct io_uring_sqe` from
//! `include/uapi/linux/io_uring.h`. Each encoder starts from an all-zero entry
//! and sets only the fields its opcode reads, so every other field stays zero.
//! That includes `ioprio`, `buf_index`, `personality`, the union at offset
//! 44, `addr3` outside [`SqueueEntry::futex_wait`], and the trailing word.
//! The flags stay zero unless [`SqueueEntry::with_flags`] sets them.
//! Pointers are stored as their addresses. Encoding performs no I/O and
//! dereferences nothing, so the caller must keep every referenced buffer alive
//! until the kernel posts the entry's completion.
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
//! [`IoUring`] is neither `Send` nor `Sync`. The ring descriptor is `O_CLOEXEC`
//! and the mappings are inherited across `fork`, but a forked child must not
//! drive or modify the inherited ring.

use std::{
    ffi::{c_long, c_void},
    io,
    marker::PhantomData,
    mem,
    ops::BitOrAssign,
    os::fd::{AsRawFd, FromRawFd as _, OwnedFd, RawFd},
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

/// One mapping at the SQ ring offset covers both rings. Every kernel that
/// accepts SQ_REWIND reports it.
const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;

/// Mapping offset of the shared rings.
const IORING_OFF_SQ_RING: libc::off_t = 0;
/// Mapping offset of the SQE array.
const IORING_OFF_SQES: libc::off_t = 0x1000_0000;

/// SQ flag set while the kernel holds completions that did not fit in the CQ.
const IORING_SQ_CQ_OVERFLOW: u32 = 1 << 1;

/// Fsync flag that syncs data and only the metadata needed to read it back.
const IORING_FSYNC_DATASYNC: u32 = 1;

/// Write flag that makes a write to a socket whose peer has closed fail with
/// `EPIPE` instead of raising `SIGPIPE` (Linux 6.18).
const RWF_NOSIGNAL: i32 = 0x100;

/// The largest length a read, write, send, or receive entry carries.
///
/// Sends and receives store the length as a signed `int` and reject larger
/// values with `EINVAL`, and reads and writes transfer at most `MAX_RW_COUNT`,
/// which is below `i32::MAX`, per call anyway.
const MAX_LEN: usize = i32::MAX as usize;

/// Return `len` capped at [`MAX_LEN`]. The caller sees the rest as a short
/// transfer.
#[inline]
const fn capped_len(len: usize) -> u32 {
    if len > MAX_LEN {
        MAX_LEN as u32
    } else {
        len as u32
    }
}

/// CQE flag of a completion that more completions of the same request follow.
#[cfg(all(test, not(feature = "loom")))]
const IORING_CQE_F_MORE: u32 = 1 << 1;

/// Register opcode that adds ring descriptors to the calling thread's table.
const IORING_REGISTER_RING_FDS: c_long = 20;
/// Register opcode that removes ring descriptors from the calling thread's
/// table.
const IORING_UNREGISTER_RING_FDS: c_long = 21;
/// Register opcode that cancels requests synchronously.
const IORING_REGISTER_SYNC_CANCEL: c_long = 24;

/// Flags of `io_uring_enter`.
///
/// [`IoUring::enter`] derives EXT_ARG and REGISTERED_RING itself, so only it
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

    /// Whether every flag in `other` is set.
    #[cfg(test)]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
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
    /// Convert `duration`, saturating at `i64::MAX` seconds.
    ///
    /// The kernel adds a relative timeout to the current time without an
    /// overflow check, so callers bound timeouts well below its range of
    /// about 292 years. The runtime caps them at 30 years.
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
struct Parameters {
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
    assert!(mem::size_of::<Parameters>() == 120);
    assert!(mem::offset_of!(Parameters, sq_entries) == 0);
    assert!(mem::offset_of!(Parameters, cq_entries) == 4);
    assert!(mem::offset_of!(Parameters, flags) == 8);
    assert!(mem::offset_of!(Parameters, sq_thread_cpu) == 12);
    assert!(mem::offset_of!(Parameters, sq_thread_idle) == 16);
    assert!(mem::offset_of!(Parameters, features) == 20);
    assert!(mem::offset_of!(Parameters, wq_fd) == 24);
    assert!(mem::offset_of!(Parameters, resv) == 28);
    assert!(mem::offset_of!(Parameters, sq_off) == 40);
    assert!(mem::offset_of!(Parameters, cq_off) == 80);
};

/// One submission queue entry, laid out exactly as the kernel's
/// `io_uring_sqe`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SqueueEntry {
    /// Operation code.
    opcode: u8,
    /// `IOSQE_*` flags.
    flags: u8,
    /// Request priority, always zero.
    ioprio: u16,
    /// File descriptor, or the futex2 flags of a futex wait.
    fd: i32,
    /// File offset, length, address length, or expected futex value.
    off: u64,
    /// Buffer, address, futex word, or cancellation target.
    addr: u64,
    /// Buffer length or iovec count.
    len: u32,
    /// Per-opcode flags (`rw_flags`, `fsync_flags`, `poll32_events`,
    /// `msg_flags`, `futex_flags`, or `cancel_flags`).
    op_flags: u32,
    /// Value the kernel echoes in the completion.
    user_data: u64,
    /// Buffer index or group, always zero.
    buf_index: u16,
    /// Credentials personality, always zero.
    personality: u16,
    /// The `splice_fd_in`, `file_index`, or `addr_len` union, always zero.
    file_index: u32,
    /// Third address, the bitset of a futex wait.
    addr3: u64,
    /// Trailing word, always zero.
    pad: u64,
}

const _: () = {
    assert!(mem::size_of::<SqueueEntry>() == 64);
    assert!(mem::offset_of!(SqueueEntry, opcode) == 0);
    assert!(mem::offset_of!(SqueueEntry, flags) == 1);
    assert!(mem::offset_of!(SqueueEntry, ioprio) == 2);
    assert!(mem::offset_of!(SqueueEntry, fd) == 4);
    assert!(mem::offset_of!(SqueueEntry, off) == 8);
    assert!(mem::offset_of!(SqueueEntry, addr) == 16);
    assert!(mem::offset_of!(SqueueEntry, len) == 24);
    assert!(mem::offset_of!(SqueueEntry, op_flags) == 28);
    assert!(mem::offset_of!(SqueueEntry, user_data) == 32);
    assert!(mem::offset_of!(SqueueEntry, buf_index) == 40);
    assert!(mem::offset_of!(SqueueEntry, personality) == 42);
    assert!(mem::offset_of!(SqueueEntry, file_index) == 44);
    assert!(mem::offset_of!(SqueueEntry, addr3) == 48);
    assert!(mem::offset_of!(SqueueEntry, pad) == 56);
};

/// `IOSQE_*` flags of an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqueueFlags(u8);

impl SqueueFlags {
    /// `IOSQE_CQE_SKIP_SUCCESS`, which posts no completion when the request
    /// succeeds.
    pub const SKIP_SUCCESS: Self = Self(1 << 6);
}

/// Return `events` as the kernel reads `poll32_events`, with the two 16-bit
/// halves swapped on big-endian targets as liburing does.
#[inline]
const fn poll32_events(events: u32, big_endian: bool) -> u32 {
    if big_endian {
        events.rotate_left(16)
    } else {
        events
    }
}

impl SqueueEntry {
    /// `IORING_OP_NOP`.
    #[cfg(test)]
    pub const NOP: u8 = 0;
    /// `IORING_OP_WRITEV`.
    pub const WRITEV: u8 = 2;
    /// `IORING_OP_FSYNC`.
    pub const FSYNC: u8 = 3;
    /// `IORING_OP_POLL_ADD`.
    pub const POLL_ADD: u8 = 6;
    /// `IORING_OP_ASYNC_CANCEL`.
    pub const ASYNC_CANCEL: u8 = 14;
    /// `IORING_OP_CONNECT`.
    pub const CONNECT: u8 = 16;
    /// `IORING_OP_READ`.
    pub const READ: u8 = 22;
    /// `IORING_OP_WRITE`.
    pub const WRITE: u8 = 23;
    /// `IORING_OP_SEND`.
    pub const SEND: u8 = 26;
    /// `IORING_OP_RECV`.
    pub const RECV: u8 = 27;
    /// `IORING_OP_FUTEX_WAIT`.
    #[cfg(any(test, not(feature = "loom")))]
    pub const FUTEX_WAIT: u8 = 51;
    /// `IORING_OP_FTRUNCATE`.
    pub const FTRUNCATE: u8 = 55;

    /// An all-zero entry of `opcode` on `fd`.
    #[inline]
    const fn zeroed(opcode: u8, fd: i32) -> Self {
        Self {
            opcode,
            flags: 0,
            ioprio: 0,
            fd,
            off: 0,
            addr: 0,
            len: 0,
            op_flags: 0,
            user_data: 0,
            buf_index: 0,
            personality: 0,
            file_index: 0,
            addr3: 0,
            pad: 0,
        }
    }

    /// Encode a no-op.
    #[cfg(test)]
    pub const fn nop() -> Self {
        Self::zeroed(Self::NOP, -1)
    }

    /// Encode a read of up to `len` bytes at `offset` of `fd` into `buf`, with
    /// `RWF_*` flags. Lengths above [`MAX_LEN`] read [`MAX_LEN`] bytes.
    #[inline]
    pub fn read(fd: RawFd, buf: *mut u8, len: usize, offset: u64, rw_flags: i32) -> Self {
        let mut sqe = Self::zeroed(Self::READ, fd);
        sqe.off = offset;
        sqe.addr = buf as usize as u64;
        sqe.len = capped_len(len);
        sqe.op_flags = rw_flags.cast_unsigned();
        sqe
    }

    /// Encode a write of up to `len` bytes from `buf` at `offset` of `fd`,
    /// with `RWF_*` flags. Lengths above [`MAX_LEN`] write [`MAX_LEN`] bytes.
    #[inline]
    pub fn write(fd: RawFd, buf: *const u8, len: usize, offset: u64, rw_flags: i32) -> Self {
        let mut sqe = Self::zeroed(Self::WRITE, fd);
        sqe.off = offset;
        sqe.addr = buf as usize as u64;
        sqe.len = capped_len(len);
        sqe.op_flags = rw_flags.cast_unsigned();
        sqe
    }

    /// Encode a vectored write of `count` iovecs at `offset` of `fd`, with
    /// `RWF_*` flags.
    #[inline]
    pub fn writev(
        fd: RawFd,
        iovecs: *const libc::iovec,
        count: u32,
        offset: u64,
        rw_flags: i32,
    ) -> Self {
        let mut sqe = Self::zeroed(Self::WRITEV, fd);
        sqe.off = offset;
        sqe.addr = iovecs as usize as u64;
        sqe.len = count;
        sqe.op_flags = rw_flags.cast_unsigned();
        sqe
    }

    /// Encode a vectored send of `count` iovecs on the connected socket `fd`.
    ///
    /// This is a socket write with `RWF_NOSIGNAL`, so a peer that has closed
    /// fails it with `EPIPE` instead of raising `SIGPIPE`, as a send does.
    #[inline]
    pub fn send_vectored(fd: RawFd, iovecs: *const libc::iovec, count: u32) -> Self {
        Self::writev(fd, iovecs, count, 0, RWF_NOSIGNAL)
    }

    /// Encode a send of up to `len` bytes from `buf` on the connected socket
    /// `fd`. Lengths above [`MAX_LEN`] send at most [`MAX_LEN`] bytes.
    #[inline]
    pub fn send(fd: RawFd, buf: *const u8, len: usize) -> Self {
        let mut sqe = Self::zeroed(Self::SEND, fd);
        sqe.addr = buf as usize as u64;
        sqe.len = capped_len(len);
        sqe
    }

    /// Encode a receive of at most `len` bytes into `buf` from the socket
    /// `fd`. Lengths above [`MAX_LEN`] receive at most [`MAX_LEN`] bytes.
    #[inline]
    pub fn recv(fd: RawFd, buf: *mut u8, len: usize) -> Self {
        let mut sqe = Self::zeroed(Self::RECV, fd);
        sqe.addr = buf as usize as u64;
        sqe.len = capped_len(len);
        sqe
    }

    /// Encode a data sync of `fd`.
    #[inline]
    pub const fn fdatasync(fd: RawFd) -> Self {
        let mut sqe = Self::zeroed(Self::FSYNC, fd);
        sqe.op_flags = IORING_FSYNC_DATASYNC;
        sqe
    }

    /// Encode a truncation or extension of `fd` to `len` bytes.
    #[inline]
    pub const fn ftruncate(fd: RawFd, len: u64) -> Self {
        let mut sqe = Self::zeroed(Self::FTRUNCATE, fd);
        sqe.off = len;
        sqe
    }

    /// Encode a connect of the socket `fd` to the `addr_len`-byte address at
    /// `addr`.
    #[inline]
    pub fn connect(fd: RawFd, addr: *const libc::sockaddr, addr_len: libc::socklen_t) -> Self {
        let mut sqe = Self::zeroed(Self::CONNECT, fd);
        sqe.off = u64::from(addr_len);
        sqe.addr = addr as usize as u64;
        sqe
    }

    /// Encode a one-shot poll of `fd` for the `POLL*` `events`.
    #[inline]
    pub const fn poll_add(fd: RawFd, events: u32) -> Self {
        let mut sqe = Self::zeroed(Self::POLL_ADD, fd);
        sqe.op_flags = poll32_events(events, cfg!(target_endian = "big"));
        sqe
    }

    /// Encode a wait on the futex2 word at `futex` while it equals
    /// `expected`. Only wakes whose bitset intersects `mask` end the wait.
    #[cfg(any(test, not(feature = "loom")))]
    #[inline]
    pub fn futex_wait(futex: *const u32, expected: u64, mask: u64, futex2_flags: u32) -> Self {
        let mut sqe = Self::zeroed(Self::FUTEX_WAIT, futex2_flags.cast_signed());
        sqe.off = expected;
        sqe.addr = futex as usize as u64;
        sqe.addr3 = mask;
        sqe
    }

    /// Encode a cancellation of the in-flight request whose `user_data` is
    /// `target`.
    #[inline]
    pub const fn async_cancel(target: u64) -> Self {
        let mut sqe = Self::zeroed(Self::ASYNC_CANCEL, -1);
        sqe.addr = target;
        sqe
    }

    /// Set the entry's `IOSQE_*` flags.
    #[inline]
    #[must_use]
    pub const fn with_flags(mut self, flags: SqueueFlags) -> Self {
        self.flags = flags.0;
        self
    }

    /// Set the `user_data` the kernel echoes in the entry's completion.
    #[inline]
    #[must_use]
    pub const fn with_user_data(mut self, user_data: u64) -> Self {
        self.user_data = user_data;
        self
    }

    /// Operation code.
    #[cfg(test)]
    pub const fn opcode(&self) -> u8 {
        self.opcode
    }

    /// File descriptor field.
    #[cfg(test)]
    pub const fn fd(&self) -> i32 {
        self.fd
    }

    /// The `off` field.
    #[cfg(test)]
    pub const fn off(&self) -> u64 {
        self.off
    }

    /// The `addr` field.
    #[cfg(test)]
    pub const fn addr(&self) -> u64 {
        self.addr
    }

    /// The `len` field.
    #[cfg(test)]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Per-opcode flags field.
    #[cfg(test)]
    pub const fn op_flags(&self) -> u32 {
        self.op_flags
    }

    /// The `user_data` field.
    #[cfg(test)]
    pub const fn user_data(&self) -> u64 {
        self.user_data
    }
}

/// The kernel's standard 16-byte `io_uring_cqe`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CqueueEntry {
    /// Value of the completed SQE's `user_data`.
    user_data: u64,
    /// Result, a negated errno on failure.
    res: i32,
    /// Completion flags.
    flags: u32,
}

const _: () = {
    assert!(mem::size_of::<CqueueEntry>() == 16);
    assert!(mem::offset_of!(CqueueEntry, user_data) == 0);
    assert!(mem::offset_of!(CqueueEntry, res) == 8);
    assert!(mem::offset_of!(CqueueEntry, flags) == 12);
};

impl CqueueEntry {
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
struct Mmap {
    /// Start of the mapping.
    ptr: NonNull<u8>,
    /// Length of the mapping in bytes.
    len: usize,
}

impl Mmap {
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

impl Drop for Mmap {
    fn drop(&mut self) {
        // A failure only leaks the mapping, and a drop that panics while
        // unwinding aborts, so the result is ignored.
        //
        // SAFETY: The mapping was created with this address and length, and
        // nothing accesses it after the queues that point into it are gone.
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };

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
struct SubmissionQueueInner {
    /// First SQE slot.
    sqes: NonNull<SqueueEntry>,
    /// The SQ flags the kernel sets.
    kflags: Word,
    /// Number of slots.
    entries: u32,
    /// Number of SQEs staged from the first slot, which the next enter asks
    /// the kernel to submit.
    staged: u32,
}

impl SubmissionQueueInner {
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
    sq: &'a mut SubmissionQueueInner,
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
        // The flag only decides whether a flush also asks for events, and no
        // data is read through it, so a relaxed load suffices, as in liburing.
        self.sq.kflags.load(Ordering::Relaxed) & IORING_SQ_CQ_OVERFLOW != 0
    }

    /// Write `sqe` into the next free slot. The next enter submits it.
    ///
    /// # Safety
    ///
    /// Every descriptor `sqe` refers to must stay valid until the kernel is
    /// done with it. Every memory region it refers to, including an iovec
    /// array and each buffer the array refers to, must stay at a stable
    /// address and valid for the full extent and access the entry encodes
    /// until then, and nothing may access it in conflict with the kernel's
    /// reads or writes. The operation's final completion, or another
    /// guarantee specific to the operation, shows when the kernel is done,
    /// including when a successful completion is skipped.
    ///
    /// # Panics
    ///
    /// Panics if the queue is full.
    #[inline]
    pub unsafe fn push(&mut self, sqe: &SqueueEntry) {
        assert!(!self.is_full(), "submission queue is full");
        let sq = &mut *self.sq;

        // SAFETY: The slot after the staged SQEs is below the slot count. The
        // kernel reads SQEs only during an enter, so it is not in use.
        unsafe { sq.sqes.add(sq.staged as usize).write(*sqe) };
        sq.staged += 1;
    }
}

/// The completion queue reader's state.
struct CompletionQueueInner {
    /// First CQE slot.
    cqes: NonNull<CqueueEntry>,
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

impl CompletionQueueInner {
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

    /// Number of completions the kernel dropped because it could not hold
    /// them. It never decreases.
    #[inline]
    fn overflow(&self) -> u32 {
        // A count checked after an enter, which no data is read through, so a
        // relaxed load suffices.
        self.koverflow.load(Ordering::Relaxed)
    }
}

/// A view of the CQEs posted when it was created.
///
/// Iterating copies each CQE out. Dropping the view returns the slots of the
/// CQEs it yielded to the kernel.
pub struct CompletionQueue<'a> {
    /// Reader state, borrowed for the view's lifetime.
    cq: &'a mut CompletionQueueInner,
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
}

impl Iterator for CompletionQueue<'_> {
    type Item = CqueueEntry;

    #[inline]
    fn next(&mut self) -> Option<CqueueEntry> {
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
/// and `sqes` for reads and writes of `params.sq_entries` SQEs, as long as
/// the queues are used. No other user-side writer may access the queues.
unsafe fn queues(
    params: &Parameters,
    rings: NonNull<u8>,
    rings_len: usize,
    sqes: NonNull<SqueueEntry>,
) -> io::Result<(SubmissionQueueInner, CompletionQueueInner)> {
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
        .checked_mul(mem::size_of::<CqueueEntry>())
        .and_then(|size| size.checked_add(cqes_offset))
        .is_none_or(|end| end > rings_len)
    {
        return Err(invalid("CQEs outside their mapping"));
    }

    // SAFETY: The CQE array ends within the `rings_len` bytes at `rings`.
    let cqes = unsafe { rings.add(cqes_offset) }.cast::<CqueueEntry>();
    if !cqes.is_aligned() || !sqes.is_aligned() {
        return Err(invalid("entries misaligned"));
    }

    let sq = SubmissionQueueInner {
        sqes,
        kflags: word(sq_off.flags)?,
        entries: params.sq_entries,
        staged: 0,
    };
    let cq = CompletionQueueInner {
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
pub struct IoUring {
    /// SQ writer over the mappings.
    sq: SubmissionQueueInner,
    /// CQ reader over the rings mapping.
    cq: CompletionQueueInner,
    /// The ring's slot in the owner thread's ring table, which enters name
    /// the ring by, until the slot is released.
    slot: Option<u32>,
    /// SQE array mapping, unmapped after the queues are gone.
    _sqes: Mmap,
    /// Shared rings mapping, unmapped after the queues are gone.
    _rings: Mmap,
    /// The ring descriptor, closed after the mappings.
    fd: OwnedFd,
    /// Keeps the ring, and so its registered slot, on the owner thread.
    _owner: PhantomData<*const ()>,
}

impl IoUring {
    /// Create a ring of at least `entries` SQ slots, map its memory, and
    /// register its descriptor with the calling thread.
    ///
    /// The kernel rounds the SQ size up to a power of two and sizes the CQ at
    /// twice that. Every enter names the ring by its registered slot. A
    /// thread's table holds 16 rings, so a seventeenth ring live on one
    /// thread, as only deeply nested runtimes create, fails with
    /// [`io::ErrorKind::ResourceBusy`].
    pub fn new(entries: u32) -> io::Result<Self> {
        let mut params = Parameters {
            flags: IORING_SETUP_SINGLE_ISSUER
                | IORING_SETUP_DEFER_TASKRUN
                | IORING_SETUP_NO_SQARRAY
                | IORING_SETUP_SQ_REWIND,
            ..Parameters::default()
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
        if params.features & IORING_FEAT_SINGLE_MMAP == 0 {
            return Err(invalid("rings need separate mappings"));
        }

        // With NO_SQARRAY and 16-byte CQEs, the CQE array ends the shared
        // rings, so one mapping of this length covers both rings.
        let rings_len = (params.cq_entries as usize)
            .checked_mul(mem::size_of::<CqueueEntry>())
            .and_then(|size| size.checked_add(params.cq_off.cqes as usize))
            .ok_or_else(|| invalid("rings size overflow"))?;
        let sqes_len = (params.sq_entries as usize)
            .checked_mul(mem::size_of::<SqueueEntry>())
            .ok_or_else(|| invalid("SQE array size overflow"))?;

        // Each mapping owns itself at once, so a failure or an unwind unmaps
        // it before the descriptor closes.
        let rings = Mmap::new(&fd, rings_len, IORING_OFF_SQ_RING)?;
        let sqes = Mmap::new(&fd, sqes_len, IORING_OFF_SQES)?;

        // SAFETY: Both mappings span the lengths passed and are unmapped only
        // after the queues, which the ring owns alongside them. The ring is
        // the only user-side writer.
        let (sq, cq) = unsafe { queues(&params, rings.ptr, rings.len, sqes.ptr.cast()) }?;
        let mut ring = Self {
            sq,
            cq,
            slot: None,
            _sqes: sqes,
            _rings: rings,
            fd,
            _owner: PhantomData,
        };

        // Register last. A failure drops the ring with nothing registered,
        // and from here on the ring's drop releases the slot.
        ring.slot = Some(ring.register_ring_fd()?);
        Ok(ring)
    }

    /// The ring's slot in the owner thread's ring table, until released.
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

    /// Number of completions the kernel dropped because it could not hold
    /// them. It never decreases.
    #[inline]
    pub fn overflow(&self) -> u32 {
        self.cq.overflow()
    }

    /// Submit every pushed, unconsumed SQE and then do what `flags` ask.
    ///
    /// `timeout`, when present, bounds a wait for `min_complete` completions
    /// through EXT_ARG. Returns the number of SQEs the kernel consumed, which
    /// falls short of the pushed count when the kernel stopped early, and
    /// then GETEVENTS was skipped. Fails with `EBADF` once the ring's slot is
    /// released.
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
        let Some(slot) = self.slot else {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        };
        flags |= EnterFlags::REGISTERED_RING;

        #[cfg(test)]
        {
            tests::record_enter(min_complete, flags);
            if let Some(error) = tests::enter_failure() {
                return Err(error);
            }
        }

        // SAFETY: `slot` names this ring in this thread's table, as
        // REGISTERED_RING tells the kernel. Pushing guaranteed that the staged
        // SQEs' resources outlive their completions. `arg_ptr` is null
        // exactly when EXT_ARG is unset, and otherwise points to an
        // `io_uring_getevents_arg` of `arg_size` bytes whose timespec pointer
        // refers to `timeout`. Both outlive the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                c_long::from(slot.cast_signed()),
                c_long::from(to_submit.cast_signed()),
                c_long::from(min_complete.cast_signed()),
                c_long::from(flags.0.cast_signed()),
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
    /// slot.
    fn register_ring_fd(&self) -> io::Result<u32> {
        let mut update = RsrcUpdate {
            offset: u32::MAX,
            resv: 0,
            data: u64::from(self.as_raw_fd().cast_unsigned()),
        };

        // SAFETY: `update` is one writable `io_uring_rsrc_update`, which the
        // kernel reads and fills with the chosen slot during the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                c_long::from(self.as_raw_fd()),
                IORING_REGISTER_RING_FDS,
                &raw mut update,
                1 as c_long,
            )
        };
        match result {
            1 => Ok(update.offset),
            result if result < 0 => {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EBUSY) {
                    return Err(io::Error::new(
                        io::ErrorKind::ResourceBusy,
                        "this thread already registers 16 io_uring rings",
                    ));
                }
                Err(error)
            }
            _ => Err(io::Error::other(
                "ring descriptor registration was not applied",
            )),
        }
    }

    /// Release the ring's registered slot, if any, through the raw
    /// descriptor. After a success the ring can no longer be entered.
    ///
    /// A failure keeps the slot, and the ring's drop tries again to release
    /// it.
    pub fn unregister_ring_fd(&mut self) -> io::Result<()> {
        let Some(slot) = self.slot else {
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
                c_long::from(self.as_raw_fd()),
                IORING_UNREGISTER_RING_FDS,
                &raw const update,
                1 as c_long,
            )
        };
        match result {
            1 => {
                self.slot = None;
                Ok(())
            }
            result if result < 0 => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other(
                "ring descriptor unregistration was not applied",
            )),
        }
    }

    /// Synchronously cancel a request with `user_data`.
    ///
    /// Without cancel flags, the kernel cancels only the first match. On
    /// success the request can no longer run, and its `ECANCELED`
    /// completion is posted like any other, by a later enter. Fails with
    /// `ENOENT` when no live request with `user_data` can still be
    /// cancelled, for example because it completed or a wake already claimed
    /// it.
    pub fn register_sync_cancel(&self, user_data: u64) -> io::Result<()> {
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
                c_long::from(self.as_raw_fd()),
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

impl AsRawFd for IoUring {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for IoUring {
    fn drop(&mut self) {
        // A ring dropped while registered releases its slot before the
        // mappings and the descriptor go. An owner that reports failures
        // unregisters first.
        let _ = self.unregister_ring_fd();
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
    let _ = <IoUring as AmbiguousIfSend<_>>::check;

    trait AmbiguousIfSync<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
    let _ = <IoUring as AmbiguousIfSync<_>>::check;
};

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        /// Minimum completion count and flags of this thread's latest enter.
        static LAST_ENTER: Cell<Option<(u32, EnterFlags)>> = const { Cell::new(None) };

        /// Error the next enter on this thread returns instead of entering.
        static FAIL_ENTER: Cell<Option<i32>> = const { Cell::new(None) };

        /// Mapping offset whose next mapping on this thread fails.
        static FAIL_MAP: Cell<Option<libc::off_t>> = const { Cell::new(None) };

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

    /// The flag [`IoUring::enter`] sets for an enter bounded by a timeout.
    pub const EXT_ARG: EnterFlags = EnterFlags::EXT_ARG;

    /// The flag [`IoUring::enter`] sets for an enter through a registered slot.
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
    pub const fn cq_entries(ring: &IoUring) -> u32 {
        ring.cq.mask + 1
    }

    /// Store `count` in `ring`'s mapped dropped-completion counter, as a
    /// kernel that dropped that many completions does.
    pub fn set_overflow(ring: &mut IoUring, count: u32) {
        ring.cq.koverflow.store(count, Ordering::Relaxed);
    }

    /// Release `ring`'s registered slot behind its back, so its enters name a
    /// slot the calling thread no longer holds.
    pub fn release_slot(ring: &IoUring) {
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
                c_long::from(ring.as_raw_fd()),
                IORING_UNREGISTER_RING_FDS,
                &raw const update,
                1 as c_long,
            )
        };
        assert_eq!(result, 1, "{}", io::Error::last_os_error());
    }

    /// Register `ring`'s descriptor again at the slot it names, after
    /// [`release_slot`].
    fn restore_slot(ring: &IoUring) {
        let update = RsrcUpdate {
            offset: ring.slot.expect("registered ring"),
            resv: 0,
            data: u64::from(ring.as_raw_fd().cast_unsigned()),
        };

        // SAFETY: `update` is one `io_uring_rsrc_update`, which the kernel
        // reads during the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                c_long::from(ring.as_raw_fd()),
                IORING_REGISTER_RING_FDS,
                &raw const update,
                1 as c_long,
            )
        };
        assert_eq!(result, 1, "{}", io::Error::last_os_error());
    }

    /// Fail the next mapping at `offset` on this thread.
    fn fail_map(offset: libc::off_t) {
        FAIL_MAP.set(Some(offset));
    }

    /// Apply an injected mapping failure.
    pub(super) fn before_map(offset: libc::off_t) -> io::Result<()> {
        if FAIL_MAP.get() != Some(offset) {
            return Ok(());
        }
        FAIL_MAP.set(None);
        Err(io::Error::from_raw_os_error(libc::ENOMEM))
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
    const RINGS_LEN: usize = CQES as usize + CQ_ENTRIES as usize * mem::size_of::<CqueueEntry>();

    /// Ring parameters describing the fake ring's layout.
    fn fake_params() -> Parameters {
        Parameters {
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
            ..Parameters::default()
        }
    }

    /// The kernel's side of a fake ring's memory.
    ///
    /// Every access goes through the pointers taken once at creation, so
    /// none invalidates the queues' pointers.
    struct FakeKernel {
        /// Shared rings.
        rings: NonNull<u8>,
        /// SQE slots.
        sqes: NonNull<SqueueEntry>,
    }

    impl FakeKernel {
        /// The header word at `offset` of the shared rings.
        ///
        /// # Panics
        ///
        /// Panics if the word is misaligned or outside the header, which ends
        /// where the CQEs start.
        fn word(&self, offset: u32) -> &AtomicU32 {
            // SAFETY: The shared rings span `RINGS_LEN` bytes, more than the
            // header, for as long as the fake kernel is borrowed.
            let word = unsafe { Word::new(self.rings, CQES as usize, offset) }
                .expect("fake ring header word");
            // SAFETY: `Word::new` checked the word, and the memory outlives
            // the returned reference.
            unsafe { word.0.as_ref() }
        }

        /// Move the CQ's counters to `start`, as if that many CQEs had
        /// passed through it.
        fn wind_cq(&self, cq: &mut CompletionQueueInner, start: u32) {
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
            assert!(count <= SQ_ENTRIES, "fetched past the SQE slots");
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
            let cqe = CqueueEntry {
                user_data,
                res,
                flags: 0,
            };
            // SAFETY: The slot is within the CQEs, and the reader does not
            // read it before the tail store that follows.
            unsafe {
                self.rings
                    .add(CQES as usize)
                    .cast::<CqueueEntry>()
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

    /// The queues over heap memory standing in for a ring's mappings, and the
    /// kernel's side of that memory.
    ///
    /// The queues live in the value that frees the memory, whose drop forbids
    /// moving them out, so they cannot outlive the memory.
    struct FakeRing {
        /// SQ writer state.
        sq: SubmissionQueueInner,
        /// CQ reader state.
        cq: CompletionQueueInner,
        /// The kernel's side of the memory.
        kernel: FakeKernel,
        /// Owner of the shared rings.
        rings_alloc: *mut [u64],
        /// Owner of the SQE slots.
        sqes_alloc: *mut [[u64; 8]],
    }

    impl FakeRing {
        /// Allocate a fake ring, fill in the words a kernel writes at setup,
        /// and build the queues over it.
        fn new() -> Self {
            let rings_alloc = Box::into_raw(vec![0u64; RINGS_LEN / 8].into_boxed_slice());
            let sqes_alloc = Box::into_raw(vec![[0u64; 8]; SQ_ENTRIES as usize].into_boxed_slice());
            let kernel = FakeKernel {
                rings: NonNull::new(rings_alloc.cast()).unwrap(),
                sqes: NonNull::new(sqes_alloc.cast()).unwrap(),
            };
            let params = fake_params();
            kernel
                .word(params.sq_off.ring_mask)
                .store(SQ_ENTRIES - 1, Ordering::Relaxed);
            kernel
                .word(params.sq_off.ring_entries)
                .store(SQ_ENTRIES, Ordering::Relaxed);
            kernel
                .word(params.cq_off.ring_mask)
                .store(CQ_ENTRIES - 1, Ordering::Relaxed);
            kernel
                .word(params.cq_off.ring_entries)
                .store(CQ_ENTRIES, Ordering::Relaxed);

            // SAFETY: The allocations span `RINGS_LEN` bytes and
            // `SQ_ENTRIES` SQEs, and the returned value frees them only
            // when it drops along with the queues.
            let (sq, cq) =
                unsafe { queues(&params, kernel.rings, RINGS_LEN, kernel.sqes) }.unwrap();
            Self {
                sq,
                cq,
                kernel,
                rings_alloc,
                sqes_alloc,
            }
        }
    }

    impl Drop for FakeRing {
        fn drop(&mut self) {
            // SAFETY: Both allocations came from `Box::into_raw` and are freed
            // once, and the queues over them go with this value.
            unsafe {
                drop(Box::from_raw(self.rings_alloc));
                drop(Box::from_raw(self.sqes_alloc));
            }
        }
    }

    /// A NOP SQE carrying `user_data`.
    fn nop(user_data: u64) -> SqueueEntry {
        SqueueEntry::nop().with_user_data(user_data)
    }

    /// The writer over `sq`, as `IoUring::submission` creates it.
    const fn writer(sq: &mut SubmissionQueueInner) -> SubmissionQueue<'_> {
        SubmissionQueue { sq }
    }

    /// Push SQEs carrying each `user_data`.
    fn push(sq: &mut SubmissionQueueInner, user_data: impl IntoIterator<Item = u64>) {
        let mut writer = writer(sq);
        for user_data in user_data {
            // SAFETY: A NOP refers to no resources.
            unsafe { writer.push(&nop(user_data)) };
        }
    }

    /// Submit like `IoUring::enter`, offering the kernel the staged SQEs, and
    /// with the fake kernel fetching `count` of them. Returns the number
    /// offered and the `user_data` fetched.
    fn submit(sq: &mut SubmissionQueueInner, ring: &FakeKernel, count: u32) -> (u32, Vec<u64>) {
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
        let mut fake = FakeRing::new();
        let (sq, ring) = (&mut fake.sq, &fake.kernel);

        // An empty queue offers nothing.
        assert_eq!(submit(sq, ring, 0), (0, vec![]));

        // A full consumption empties the queue.
        push(sq, [1, 2]);
        assert_eq!(writer(sq).len(), 2);
        assert_eq!(submit(sq, ring, 2), (2, vec![1, 2]));
        assert!(writer(sq).is_empty());

        // A zero count keeps every SQE in place.
        push(sq, [3, 4, 5, 6]);
        assert!(writer(sq).is_full());
        assert_eq!(submit(sq, ring, 0), (4, vec![]));
        assert_eq!(ring.fetch(4), [3, 4, 5, 6]);

        // A partial consumption moves the overlapping rest to the front.
        assert_eq!(submit(sq, ring, 1), (4, vec![3]));
        assert_eq!(writer(sq).len(), 3);
        assert_eq!(ring.fetch(3), [4, 5, 6]);

        // A push follows the moved SQEs, and the next enter offers them first.
        push(sq, [7]);
        assert!(writer(sq).is_full());
        assert_eq!(submit(sq, ring, 3), (4, vec![4, 5, 6]));
        assert_eq!(ring.fetch(1), [7]);
        push(sq, [8]);
        assert_eq!(submit(sq, ring, 2), (2, vec![7, 8]));
        assert!(writer(sq).is_empty());
        assert_eq!(ring.sq_cursors(), (0, 0));
    }

    /// Pushing into a full queue panics instead of overwriting an unconsumed
    /// slot.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "submission queue is full")]
    fn test_sq_push_rejects_a_full_queue() {
        let mut fake = FakeRing::new();
        push(&mut fake.sq, 0..=u64::from(SQ_ENTRIES));
    }

    /// A kernel that reports consuming more SQEs than were submitted panics
    /// before the writer can reuse a staged slot.
    #[commonware_macros::test_group("miri")]
    #[test]
    #[should_panic(expected = "kernel consumed 2 of 1 SQEs")]
    fn test_sq_rejects_overconsumption() {
        let mut fake = FakeRing::new();
        push(&mut fake.sq, [1]);
        fake.sq.consume(2);
    }

    /// A view yields the CQEs posted before it was created and returns
    /// exactly the slots it yielded.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_cq_returns_the_consumed_prefix() {
        let mut fake = FakeRing::new();
        let (cq, ring) = (&mut fake.cq, &fake.kernel);
        ring.wind_cq(cq, u32::MAX - 2);

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
        let mut fake = FakeRing::new();
        let (cq, ring) = (&mut fake.cq, &fake.kernel);
        ring.post(1, 0);
        assert_eq!(cq.overflow(), 0);
        ring.word(fake_params().cq_off.overflow)
            .store(1, Ordering::Release);
        assert_eq!(cq.overflow(), 1);
        assert_eq!(cq.completion().len(), 1);
    }

    /// Ring memory whose layout does not fit its mapping is rejected.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_queues_reject_invalid_layouts() {
        let fake = FakeRing::new();
        let ring = &fake.kernel;
        let check = |params: Parameters| {
            // SAFETY: The fake ring's memory outlives the call, and no queue
            // is returned.
            let result = unsafe { queues(&params, ring.rings, RINGS_LEN, ring.sqes) };
            assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidData);
        };
        // A word past the end of the mapping, and a misaligned word.
        let mut params = fake_params();
        params.sq_off.flags = RINGS_LEN as u32;
        check(params);
        let mut params = fake_params();
        params.cq_off.head = 66;
        check(params);

        // CQEs past the end of the mapping, and misaligned CQEs.
        let mut params = fake_params();
        params.cq_off.cqes = CQES + 8;
        check(params);
        let mut params = fake_params();
        params.cq_off.cqes = CQES - 1;
        check(params);

        // Misaligned SQEs, in an array one slot longer, so the shifted slots
        // stay inside it.
        let params = fake_params();
        let mut slots = vec![[0u64; 8]; SQ_ENTRIES as usize + 1];
        let sqes = NonNull::new(slots.as_mut_ptr())
            .unwrap()
            .cast::<SqueueEntry>();
        // SAFETY: The rings and `slots` outlive the call, `SQ_ENTRIES`
        // slots from the shifted pointer end within `slots`, and no queue is
        // returned.
        let result = unsafe { queues(&params, ring.rings, RINGS_LEN, sqes.byte_add(4)) };
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidData);

        // Ring sizes that disagree with the kernel's words: the entry count
        // and the mask of each ring, and an entry count that is not a power
        // of two even though both words agree with it.
        let params = fake_params();
        for (offset, value) in [
            (params.sq_off.ring_entries, SQ_ENTRIES / 2),
            (params.sq_off.ring_mask, SQ_ENTRIES / 2 - 1),
            (params.cq_off.ring_entries, CQ_ENTRIES / 2),
            (params.cq_off.ring_mask, CQ_ENTRIES / 2 - 1),
        ] {
            let word = ring.word(offset);
            let correct = word.swap(value, Ordering::Relaxed);
            check(fake_params());
            word.store(correct, Ordering::Relaxed);
        }
        let mut params = fake_params();
        params.sq_entries = 3;
        ring.word(params.sq_off.ring_entries)
            .store(3, Ordering::Relaxed);
        ring.word(params.sq_off.ring_mask)
            .store(2, Ordering::Relaxed);
        check(params);
    }

    /// A setup the kernel rejects returns its error.
    #[test]
    fn test_ring_setup_reports_the_kernels_error() {
        let error = IoUring::new(0).err().expect("a zero-entry ring was set up");
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
    }

    /// A mapping the kernel refuses fails instead of yielding the failure
    /// address, and a dropped mapping is gone.
    #[test]
    fn test_mmap_reports_failure_and_unmaps_on_drop() {
        let null = std::fs::File::open("/dev/null").unwrap().into();
        assert!(Mmap::new(&null, 4096, 0).is_err());

        let name = c"commonware_iouring_mmap_test";
        // SAFETY: The name is a valid C string, and the call creates a new
        // descriptor that nothing else owns.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "{}", io::Error::last_os_error());
        // SAFETY: `fd` is a new descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: `fd` is an open memfd.
        assert_eq!(unsafe { libc::ftruncate(fd.as_raw_fd(), 4096) }, 0);
        // Only this mapping maps the memfd, whatever else the process maps.
        let mapped = || {
            std::fs::read_to_string("/proc/self/maps")
                .unwrap()
                .contains(name.to_str().unwrap())
        };
        let mapping = Mmap::new(&fd, 4096, 0).unwrap();
        assert!(mapped());
        drop(mapping);
        assert!(!mapped());
    }

    /// A failed mapping unmaps the mappings made before it.
    #[test]
    fn test_failed_setup_unmaps_its_mappings() {
        fail_map(IORING_OFF_SQ_RING);
        let error = IoUring::new(8).err().unwrap();
        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
        assert_eq!(LIVE_MAPPINGS.get(), 0);

        fail_map(IORING_OFF_SQES);
        let error = IoUring::new(8).err().unwrap();
        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
        assert_eq!(LIVE_MAPPINGS.get(), 0);

        let ring = IoUring::new(8).unwrap();
        assert_eq!(LIVE_MAPPINGS.get(), 2);
        drop(ring);
        assert_eq!(LIVE_MAPPINGS.get(), 0);
    }

    /// A real ring submits through its registered slot, its CQ yields each
    /// completion once, and it cannot be entered once the slot is released.
    #[test]
    fn test_ring_submits_and_completes() {
        let mut ring = IoUring::new(4).unwrap();
        assert!(ring.slot().is_some());
        for user_data in 0..4 {
            // SAFETY: A NOP refers to no resources.
            unsafe { ring.submission().push(&nop(user_data)) };
        }
        assert!(ring.submission().is_full());
        assert_eq!(ring.enter(4, EnterFlags::GETEVENTS, None).unwrap(), 4);
        let (min_complete, flags) = last_enter().unwrap();
        assert_eq!(min_complete, 4);
        assert!(flags.contains(REGISTERED_RING));
        assert!(ring.submission().is_empty());
        let mut completed: Vec<_> = ring.completion().map(|cqe| cqe.user_data()).collect();
        completed.sort_unstable();
        assert_eq!(completed, [0, 1, 2, 3]);
        assert!(ring.completion().is_empty());

        // A released slot cannot be entered.
        ring.unregister_ring_fd().unwrap();
        assert_eq!(ring.slot(), None);
        let error = ring.enter(0, EnterFlags::GETEVENTS, None).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }

    /// A submission that stops at an SQE the kernel rejects consumes exactly
    /// the SQEs up to and including that one. The next enter offers the rest
    /// first, then a later push, and each completes once.
    #[test]
    fn test_ring_resubmits_the_unconsumed_suffix() {
        let mut ring = IoUring::new(4).unwrap();
        let word = AtomicU32::new(0);
        for rejected in [0u32, 1] {
            // Invalid futex2 flags fail the wait's preparation, which ends the
            // submission after it.
            let invalid = SqueueEntry::futex_wait(word.as_ptr(), 0, u64::MAX, u32::MAX);
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
            let mut completed: Vec<_> = ring
                .completion()
                .map(|cqe| (cqe.user_data(), cqe.result()))
                .collect();
            completed.sort_unstable();
            let mut expected: Vec<_> = (1..u64::from(consumed)).map(|nop| (nop, 0)).collect();
            expected.push((u64::from(consumed), -libc::EINVAL));
            assert_eq!(completed, expected);

            // The rest goes first, then a push.
            // SAFETY: A NOP refers to no resources.
            unsafe { ring.submission().push(&nop(5)) };
            let submitted = ring.enter(0, EnterFlags::empty(), None);
            assert_eq!(submitted.unwrap(), 5 - consumed);
            assert!(ring.submission().is_empty());
            let mut completed: Vec<_> = ring.completion().map(|cqe| cqe.user_data()).collect();
            completed.sort_unstable();
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

        let mut ring = IoUring::new(4).unwrap();
        let wait =
            SqueueEntry::futex_wait(WORD.as_ptr(), 0, u64::from(u32::MAX), FUTEX2_PRIVATE_U32);
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
                .push(&SqueueEntry::async_cancel(7).with_user_data(8))
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
        let mut ring = IoUring::new(4).unwrap();
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

        // Once the slot names the ring again, the next enter submits both.
        restore_slot(&ring);
        assert_eq!(ring.enter(0, EnterFlags::empty(), None).unwrap(), 2);
        let mut completed: Vec<_> = ring.completion().map(|cqe| cqe.user_data()).collect();
        completed.sort_unstable();
        assert_eq!(completed, [1, 2]);
    }

    /// A failed unregistration keeps the slot, and dropping the ring then
    /// releases it, so the next ring on the thread takes the same slot.
    #[test]
    fn test_ring_drop_releases_a_slot_whose_unregistration_failed() {
        let mut ring = IoUring::new(1).unwrap();
        let slot = ring.slot().unwrap();

        // The kernel rejects an unregistration through a descriptor that is
        // not a ring.
        let null = std::fs::File::open("/dev/null").unwrap().into();
        let fd = mem::replace(&mut ring.fd, null);
        let failed = ring.unregister_ring_fd();
        ring.fd = fd;
        assert!(failed.is_err());
        assert_eq!(ring.slot(), Some(slot));

        drop(ring);
        assert_eq!(IoUring::new(1).unwrap().slot(), Some(slot));
    }

    /// A thread registers at most sixteen rings, so a seventeenth fails to
    /// set up. A dropped ring frees only its own slot, which the next ring
    /// takes, and the others keep entering through theirs.
    #[test]
    fn test_seventeenth_ring_on_a_thread_fails() {
        let mut rings: Vec<_> = (0..16).map(|_| IoUring::new(1).unwrap()).collect();
        let error = IoUring::new(1)
            .err()
            .expect("a seventeenth ring registered");
        assert_eq!(error.kind(), io::ErrorKind::ResourceBusy);
        assert!(error.to_string().contains("16 io_uring rings"), "{error}");

        let freed = rings.remove(5);
        let slot = freed.slot();
        drop(freed);
        rings.push(IoUring::new(1).unwrap());
        assert_eq!(rings.last().unwrap().slot(), slot);
        for ring in &mut rings {
            // SAFETY: A NOP refers to no resources.
            unsafe { ring.submission().push(&nop(1)) };
            assert_eq!(ring.enter(1, EnterFlags::GETEVENTS, None).unwrap(), 1);
            assert_eq!(ring.completion().count(), 1);
        }
    }

    /// A timed wait on an empty ring times out after its timeout.
    #[test]
    fn test_ring_timed_wait_times_out() {
        let mut ring = IoUring::new(4).unwrap();
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

#[cfg(test)]
#[commonware_macros::test_group("miri")]
mod squeue_entry_tests {
    use super::*;

    /// Distinctive descriptor.
    const FD: RawFd = 0x0102_0304;
    /// Distinctive `user_data`.
    const USER_DATA: u64 = 0xA1A2_A3A4_A5A6_A7A8;
    /// Distinctive length.
    const LEN: u32 = 0x1112_1314;

    /// [`LEN`] as an encoder argument.
    const LEN_ARG: usize = LEN as usize;
    /// Distinctive offset.
    const OFFSET: u64 = 0x2122_2324_2526_2728;
    /// Distinctive `RWF_*` flags.
    const RW_FLAGS: i32 = 0x31;
    /// Distinctive address, cut to the pointer width, never dereferenced.
    const ADDR: usize = 0x4142_4344_4546_4748_u64 as usize;

    /// A pointer to `ADDR`, which no test dereferences.
    const fn ptr<T>() -> *mut T {
        std::ptr::without_provenance_mut(ADDR)
    }

    /// The 64 bytes of `sqe`.
    fn image(sqe: SqueueEntry) -> [u8; 64] {
        // SAFETY: `SqueueEntry` is `repr(C)` and 64 bytes, made only of integer fields
        // whose offsets leave no padding, so every byte is initialized.
        unsafe { mem::transmute::<SqueueEntry, [u8; 64]>(sqe) }
    }

    /// The uapi image of an entry, built from the kernel's field offsets
    /// independently of [`SqueueEntry`].
    struct Expected([u8; 64]);

    impl Expected {
        /// An image with `opcode` at 0, `fd` at 4, `user_data` at 32, and every
        /// other byte zero.
        fn new(opcode: u8, fd: i32, user_data: u64) -> Self {
            let mut expected = Self([0; 64]);
            expected.0[0] = opcode;
            expected
                .put(4, &fd.to_ne_bytes())
                .put(32, &user_data.to_ne_bytes())
        }

        /// Write `bytes` at `offset`.
        fn put(mut self, offset: usize, bytes: &[u8]) -> Self {
            self.0[offset..offset + bytes.len()].copy_from_slice(bytes);
            self
        }

        /// Write `off` at 8.
        fn off(self, off: u64) -> Self {
            self.put(8, &off.to_ne_bytes())
        }

        /// Write `addr` at 16.
        fn addr(self, addr: u64) -> Self {
            self.put(16, &addr.to_ne_bytes())
        }

        /// Write `len` at 24.
        fn len(self, len: u32) -> Self {
            self.put(24, &len.to_ne_bytes())
        }

        /// Write the per-opcode flags at 28.
        fn op_flags(self, flags: u32) -> Self {
            self.put(28, &flags.to_ne_bytes())
        }

        /// Write `addr3` at 48.
        fn addr3(self, addr3: u64) -> Self {
            self.put(48, &addr3.to_ne_bytes())
        }

        /// Assert that `sqe` has exactly this image.
        #[track_caller]
        fn check(self, sqe: SqueueEntry) {
            assert_eq!(image(sqe), self.0);
        }
    }

    #[test]
    fn test_nop() {
        Expected::new(0, -1, USER_DATA).check(SqueueEntry::nop().with_user_data(USER_DATA));
    }

    #[test]
    fn test_read() {
        Expected::new(22, FD, USER_DATA)
            .off(OFFSET)
            .addr(ADDR as u64)
            .len(LEN)
            .op_flags(0x31)
            .check(
                SqueueEntry::read(FD, ptr(), LEN_ARG, OFFSET, RW_FLAGS).with_user_data(USER_DATA),
            );
    }

    #[test]
    fn test_write() {
        Expected::new(23, FD, USER_DATA)
            .off(OFFSET)
            .addr(ADDR as u64)
            .len(LEN)
            .op_flags(0x31)
            .check(
                SqueueEntry::write(FD, ptr(), LEN_ARG, OFFSET, RW_FLAGS).with_user_data(USER_DATA),
            );
    }

    #[test]
    fn test_writev() {
        Expected::new(2, FD, USER_DATA)
            .off(OFFSET)
            .addr(ADDR as u64)
            .len(7)
            .op_flags(0x31)
            .check(SqueueEntry::writev(FD, ptr(), 7, OFFSET, RW_FLAGS).with_user_data(USER_DATA));
    }

    #[test]
    fn test_send_vectored() {
        // A socket write at offset zero with RWF_NOSIGNAL.
        Expected::new(2, FD, USER_DATA)
            .addr(ADDR as u64)
            .len(7)
            .op_flags(0x100)
            .check(SqueueEntry::send_vectored(FD, ptr(), 7).with_user_data(USER_DATA));
    }

    /// Reads, writes, sends, and receives carry at most `i32::MAX` bytes,
    /// since sends and receives reject larger lengths.
    #[test]
    fn test_lengths_are_capped() {
        let max = i32::MAX as usize;
        for (len, encoded) in [
            (max - 1, i32::MAX as u32 - 1),
            (max, i32::MAX as u32),
            (max + 1, i32::MAX as u32),
            (u32::MAX as usize, i32::MAX as u32),
            (u32::MAX as usize + 1, i32::MAX as u32),
            (usize::MAX, i32::MAX as u32),
        ] {
            for sqe in [
                SqueueEntry::read(FD, ptr(), len, 0, 0),
                SqueueEntry::write(FD, ptr(), len, 0, 0),
                SqueueEntry::send(FD, ptr(), len),
                SqueueEntry::recv(FD, ptr(), len),
            ] {
                assert_eq!(sqe.len(), encoded, "length {len}");
            }
        }
    }

    #[test]
    fn test_send() {
        Expected::new(26, FD, USER_DATA)
            .addr(ADDR as u64)
            .len(LEN)
            .check(SqueueEntry::send(FD, ptr(), LEN_ARG).with_user_data(USER_DATA));
    }

    #[test]
    fn test_recv() {
        Expected::new(27, FD, USER_DATA)
            .addr(ADDR as u64)
            .len(LEN)
            .check(SqueueEntry::recv(FD, ptr(), LEN_ARG).with_user_data(USER_DATA));
    }

    #[test]
    fn test_fdatasync() {
        Expected::new(3, FD, USER_DATA)
            .op_flags(1)
            .check(SqueueEntry::fdatasync(FD).with_user_data(USER_DATA));
    }

    #[test]
    fn test_ftruncate() {
        Expected::new(55, FD, USER_DATA)
            .off(OFFSET)
            .check(SqueueEntry::ftruncate(FD, OFFSET).with_user_data(USER_DATA));
    }

    #[test]
    fn test_connect() {
        Expected::new(16, FD, USER_DATA)
            .off(28)
            .addr(ADDR as u64)
            .check(SqueueEntry::connect(FD, ptr(), 28).with_user_data(USER_DATA));
    }

    #[test]
    fn test_poll_add() {
        let events = if cfg!(target_endian = "big") {
            0x0002_0001
        } else {
            0x0001_0002
        };
        Expected::new(6, FD, USER_DATA)
            .op_flags(events)
            .check(SqueueEntry::poll_add(FD, 0x0001_0002).with_user_data(USER_DATA));
    }

    #[test]
    fn test_poll32_events_swaps_halves_only_on_big_endian() {
        assert_eq!(poll32_events(0x0001_0002, false), 0x0001_0002);
        assert_eq!(poll32_events(0x0001_0002, true), 0x0002_0001);
        assert_eq!(poll32_events(libc::POLLIN as u32, true), 0x0001_0000);
    }

    #[test]
    fn test_futex_wait() {
        // A mask other than all ones reaches addr3 unchanged, and the futex2
        // flags fill the descriptor field.
        for mask in [0b10, u64::from(u32::MAX)] {
            Expected::new(51, 0x82, USER_DATA)
                .off(0x5152_5354)
                .addr(ADDR as u64)
                .addr3(mask)
                .check(
                    SqueueEntry::futex_wait(ptr(), 0x5152_5354, mask, 0x82)
                        .with_user_data(USER_DATA),
                );
        }
    }

    #[test]
    fn test_async_cancel() {
        Expected::new(14, -1, USER_DATA)
            .addr(OFFSET)
            .check(SqueueEntry::async_cancel(OFFSET).with_user_data(USER_DATA));

        // CQE_SKIP_SUCCESS is bit 6 of the flags byte at offset 1.
        Expected::new(14, -1, USER_DATA)
            .put(1, &[1 << 6])
            .addr(OFFSET)
            .check(
                SqueueEntry::async_cancel(OFFSET)
                    .with_flags(SqueueFlags::SKIP_SUCCESS)
                    .with_user_data(USER_DATA),
            );
    }

    #[test]
    fn test_reserved_user_data_round_trips() {
        for user_data in [u64::MAX, u64::from(u32::MAX), 0] {
            Expected::new(14, -1, user_data)
                .addr(user_data)
                .check(SqueueEntry::async_cancel(user_data).with_user_data(user_data));
        }
    }
}
