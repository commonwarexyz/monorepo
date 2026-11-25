//! The kernel's `io_uring_sqe` layout and the encoders of the opcodes this
//! runtime submits.
//!
//! [`Sqe`] mirrors `struct io_uring_sqe` from `include/uapi/linux/io_uring.h`.
//! Each encoder starts from an all-zero entry and sets only the fields its
//! opcode reads, so every other field stays zero. That includes `ioprio`,
//! `buf_index`, `personality`, the union at offset 44, `addr3` outside
//! [`Sqe::futex_wait`], and the trailing word. The flags stay zero unless
//! [`Sqe::with_flags`] sets them. Pointers are stored as their addresses.
//! Encoding performs no I/O and dereferences nothing, so the caller must keep
//! every referenced buffer alive until the kernel posts the entry's
//! completion.

use std::{mem, os::fd::RawFd};

/// One submission queue entry, laid out exactly as the kernel's
/// `io_uring_sqe`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sqe {
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
    assert!(mem::size_of::<Sqe>() == 64);
    assert!(mem::align_of::<Sqe>() == 8);
    assert!(mem::offset_of!(Sqe, opcode) == 0);
    assert!(mem::offset_of!(Sqe, flags) == 1);
    assert!(mem::offset_of!(Sqe, ioprio) == 2);
    assert!(mem::offset_of!(Sqe, fd) == 4);
    assert!(mem::offset_of!(Sqe, off) == 8);
    assert!(mem::offset_of!(Sqe, addr) == 16);
    assert!(mem::offset_of!(Sqe, len) == 24);
    assert!(mem::offset_of!(Sqe, op_flags) == 28);
    assert!(mem::offset_of!(Sqe, user_data) == 32);
    assert!(mem::offset_of!(Sqe, buf_index) == 40);
    assert!(mem::offset_of!(Sqe, personality) == 42);
    assert!(mem::offset_of!(Sqe, file_index) == 44);
    assert!(mem::offset_of!(Sqe, addr3) == 48);
    assert!(mem::offset_of!(Sqe, pad) == 56);
};

/// `IOSQE_*` flags of an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqeFlags(u8);

impl SqeFlags {
    /// `IOSQE_CQE_SKIP_SUCCESS`, which posts no completion when the request
    /// succeeds.
    pub const SKIP_SUCCESS: Self = Self(1 << 6);
}

/// `IORING_FSYNC_DATASYNC`, which syncs data and only the metadata needed to
/// read it back.
const IORING_FSYNC_DATASYNC: u32 = 1;

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

impl Sqe {
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

    /// Encode a read of `len` bytes at `offset` of `fd` into `buf`, with
    /// `RWF_*` flags.
    #[inline]
    pub fn read(fd: RawFd, buf: *mut u8, len: u32, offset: u64, rw_flags: i32) -> Self {
        let mut sqe = Self::zeroed(Self::READ, fd);
        sqe.off = offset;
        sqe.addr = buf as usize as u64;
        sqe.len = len;
        sqe.op_flags = rw_flags.cast_unsigned();
        sqe
    }

    /// Encode a write of `len` bytes from `buf` at `offset` of `fd`, with
    /// `RWF_*` flags.
    #[inline]
    pub fn write(fd: RawFd, buf: *const u8, len: u32, offset: u64, rw_flags: i32) -> Self {
        let mut sqe = Self::zeroed(Self::WRITE, fd);
        sqe.off = offset;
        sqe.addr = buf as usize as u64;
        sqe.len = len;
        sqe.op_flags = rw_flags.cast_unsigned();
        sqe
    }

    /// Encode a vectored write of `count` iovecs at `offset` of `fd`, with
    /// `RWF_*` flags.
    ///
    /// Sockets pass a zero offset and no flags.
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

    /// Encode a send of `len` bytes from `buf` on the connected socket `fd`.
    #[inline]
    pub fn send(fd: RawFd, buf: *const u8, len: u32) -> Self {
        let mut sqe = Self::zeroed(Self::SEND, fd);
        sqe.addr = buf as usize as u64;
        sqe.len = len;
        sqe
    }

    /// Encode a receive of at most `len` bytes into `buf` from the socket
    /// `fd`.
    #[inline]
    pub fn recv(fd: RawFd, buf: *mut u8, len: u32) -> Self {
        let mut sqe = Self::zeroed(Self::RECV, fd);
        sqe.addr = buf as usize as u64;
        sqe.len = len;
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
    pub const fn with_flags(mut self, flags: SqeFlags) -> Self {
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

#[cfg(test)]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::*;

    /// Distinctive descriptor.
    const FD: RawFd = 0x0102_0304;
    /// Distinctive `user_data`.
    const USER_DATA: u64 = 0xA1A2_A3A4_A5A6_A7A8;
    /// Distinctive length.
    const LEN: u32 = 0x1112_1314;
    /// Distinctive offset.
    const OFFSET: u64 = 0x2122_2324_2526_2728;
    /// Distinctive `RWF_*` flags.
    const RW_FLAGS: i32 = 0x31;
    /// Distinctive address, never dereferenced.
    const ADDR: u64 = 0x4142_4344_4546_4748;

    /// A pointer to `ADDR`, which no test dereferences.
    const fn ptr<T>() -> *mut T {
        std::ptr::without_provenance_mut(ADDR as usize)
    }

    /// The 64 bytes of `sqe`.
    fn image(sqe: Sqe) -> [u8; 64] {
        // SAFETY: `Sqe` is `repr(C)` and 64 bytes, made only of integer fields
        // whose offsets leave no padding, so every byte is initialized.
        unsafe { mem::transmute::<Sqe, [u8; 64]>(sqe) }
    }

    /// The uapi image of an entry, built from the kernel's field offsets
    /// independently of [`Sqe`].
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
        fn check(self, sqe: Sqe) {
            assert_eq!(image(sqe), self.0);
        }
    }

    #[test]
    fn test_nop() {
        Expected::new(0, -1, USER_DATA).check(Sqe::nop().with_user_data(USER_DATA));
    }

    #[test]
    fn test_read() {
        Expected::new(22, FD, USER_DATA)
            .off(OFFSET)
            .addr(ADDR)
            .len(LEN)
            .op_flags(0x31)
            .check(Sqe::read(FD, ptr(), LEN, OFFSET, RW_FLAGS).with_user_data(USER_DATA));
    }

    #[test]
    fn test_write() {
        Expected::new(23, FD, USER_DATA)
            .off(OFFSET)
            .addr(ADDR)
            .len(LEN)
            .op_flags(0x31)
            .check(Sqe::write(FD, ptr(), LEN, OFFSET, RW_FLAGS).with_user_data(USER_DATA));
    }

    #[test]
    fn test_writev() {
        Expected::new(2, FD, USER_DATA)
            .off(OFFSET)
            .addr(ADDR)
            .len(7)
            .op_flags(0x31)
            .check(Sqe::writev(FD, ptr(), 7, OFFSET, RW_FLAGS).with_user_data(USER_DATA));
    }

    #[test]
    fn test_send() {
        Expected::new(26, FD, USER_DATA)
            .addr(ADDR)
            .len(LEN)
            .check(Sqe::send(FD, ptr(), LEN).with_user_data(USER_DATA));
    }

    #[test]
    fn test_recv() {
        Expected::new(27, FD, USER_DATA)
            .addr(ADDR)
            .len(LEN)
            .check(Sqe::recv(FD, ptr(), LEN).with_user_data(USER_DATA));
    }

    #[test]
    fn test_fdatasync() {
        Expected::new(3, FD, USER_DATA)
            .op_flags(1)
            .check(Sqe::fdatasync(FD).with_user_data(USER_DATA));
    }

    #[test]
    fn test_ftruncate() {
        Expected::new(55, FD, USER_DATA)
            .off(OFFSET)
            .check(Sqe::ftruncate(FD, OFFSET).with_user_data(USER_DATA));
    }

    #[test]
    fn test_connect() {
        Expected::new(16, FD, USER_DATA)
            .off(28)
            .addr(ADDR)
            .check(Sqe::connect(FD, ptr(), 28).with_user_data(USER_DATA));
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
            .check(Sqe::poll_add(FD, 0x0001_0002).with_user_data(USER_DATA));
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
                .addr(ADDR)
                .addr3(mask)
                .check(Sqe::futex_wait(ptr(), 0x5152_5354, mask, 0x82).with_user_data(USER_DATA));
        }
    }

    #[test]
    fn test_async_cancel() {
        Expected::new(14, -1, USER_DATA)
            .addr(OFFSET)
            .check(Sqe::async_cancel(OFFSET).with_user_data(USER_DATA));

        // CQE_SKIP_SUCCESS is bit 6 of the flags byte at offset 1.
        Expected::new(14, -1, USER_DATA)
            .put(1, &[1 << 6])
            .addr(OFFSET)
            .check(
                Sqe::async_cancel(OFFSET)
                    .with_flags(SqeFlags::SKIP_SUCCESS)
                    .with_user_data(USER_DATA),
            );
    }

    #[test]
    fn test_reserved_user_data_round_trips() {
        for user_data in [u64::MAX, u64::from(u32::MAX), 0] {
            Expected::new(14, -1, user_data)
                .addr(user_data)
                .check(Sqe::async_cancel(user_data).with_user_data(user_data));
        }
    }
}
