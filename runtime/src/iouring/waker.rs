//! Hybrid futex/eventfd wake coordination for the io_uring loop.
//!
//! This module implements the producer-to-loop wake protocol used by [`super::IoUringLoop`]:
//! - Producers call [`Waker::publish`] after enqueueing work.
//! - The loop calls [`Waker::park_idle`] when it is fully idle.
//! - The loop acquires a [`BlockGuard`] from [`Waker::arm`] before
//!   blocking in `submit_and_wait`.
//! - Producers wake only the currently armed wait target.
//! - A dedicated "wake signalled" bit coalesces repeated wake attempts.
//! - Wake CQEs are acknowledged with [`Waker::acknowledge`].
//!
//! The packed atomic state combines:
//! - bit 0: waiting on futex
//! - bit 1: waiting on eventfd
//! - bit 2: wake already signalled
//! - bits 3..: submitted sequence
//!
//! This keeps the arm-and-recheck handshake lock-free, enables futex sleep when
//! the loop is truly idle, and avoids repeated wake writes while a wake is
//! already pending.

use super::UserData;
use io_uring::{opcode::PollAdd, squeue::SubmissionQueue, types::Fd};
use std::{
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};
use tracing::warn;

/// Reserved `user_data` value for internal wake poll completions.
pub(super) const WAKE_USER_DATA: UserData = UserData::MAX;

/// Number of low bits reserved for wake-state flags.
const STATE_BITS: u32 = 3;
/// Bit used when the loop is sleeping on a futex.
const WAITING_ON_FUTEX_BIT: u32 = 1;
/// Bit used when the loop is blocked in `submit_and_wait` and wakeable via eventfd.
const WAITING_ON_EVENTFD_BIT: u32 = 1 << 1;
/// Bit used once a wake has already been signalled for the current wait.
const WAKE_SIGNALLED_BIT: u32 = 1 << 2;
/// Mask covering all non-sequence wake-state flags.
const STATE_MASK: u32 = WAITING_ON_FUTEX_BIT | WAITING_ON_EVENTFD_BIT | WAKE_SIGNALLED_BIT;
/// Mask covering just the current wait target bits.
const WAITING_MASK: u32 = WAITING_ON_FUTEX_BIT | WAITING_ON_EVENTFD_BIT;
/// Packed-state increment for one submitted operation (low bits are reserved).
const SUBMISSION_INCREMENT: u32 = 1 << STATE_BITS;
/// Sequence domain used by the packed submission counter (state >> 3).
pub(super) const SUBMISSION_SEQ_MASK: u32 = u32::MAX >> STATE_BITS;

/// RAII guard covering a `submit_and_wait` blocking section.
///
/// While this guard is live, the loop is armed to receive an eventfd-based
/// wake if producers publish new work or the final handle disconnects.
pub(super) struct BlockGuard<'a> {
    waker: &'a Waker,
    should_block: bool,
}

impl BlockGuard<'_> {
    /// Return whether the loop was still idle after arming the blocking wake
    /// path and therefore may safely enter `submit_and_wait`.
    pub(super) const fn should_block(&self) -> bool {
        self.should_block
    }
}

impl Drop for BlockGuard<'_> {
    fn drop(&mut self) {
        self.waker.disarm();
    }
}

/// Shared wake state used by submitters and the io_uring loop.
///
/// `state` packs two values:
/// - bits 0..2: wait target and wake state
/// - bits 3..: submitted sequence (`submitted_seq`)
///
/// Submitters always increment `submitted_seq` after enqueueing onto the MPSC. The
/// loop tracks how many submissions it has drained from the MPSC (`processed_seq`,
/// stored in loop-local state). The loop may block only when:
/// - a wait target is armed, and
/// - `submitted_seq == processed_seq`.
///
/// Blocking follows an arm-and-recheck protocol:
/// - The loop first verifies `submitted_seq == processed_seq`, then arms a wait target.
/// - `blocking_snapshot()` returns the post-arm snapshot only when blocking still
///   looks safe after that same atomic state transition.
/// - Submitters signal the currently armed wait target exactly once.
/// - Out-of-band notifications latch one wake even while unarmed, so the next
///   arm-and-recheck cycle skips blocking once.
///
/// This makes submissions racing with the sleep transition observable either by
/// sequence mismatch in the loop or by a futex/eventfd wakeup.
struct WakerInner {
    wake_fd: OwnedFd,
    state: AtomicU32,
}

/// Internal hybrid futex/eventfd wake source for the io_uring loop.
///
/// - Publish submissions from producers via [`Waker::publish`]
/// - Wake without publishing via [`Waker::notify`]
/// - Test whether published work is still pending via [`Waker::pending`]
/// - Park in the fully-idle path via [`Waker::park_idle`]
/// - Arm a `submit_and_wait` blocking section via [`Waker::arm`]
/// - Drain `eventfd` readiness on wake CQEs via [`Waker::acknowledge`]
/// - Re-arm the multishot poll request when needed via [`Waker::reinstall`]
///
/// This type intentionally separates:
/// - sequence publication (`state` high bits)
/// - wait gating (`state` low bits)
/// - kernel readiness consumption (`eventfd` read path)
///
/// Keeping these concerns separate makes the wake protocol explicit and avoids
/// coupling correctness to exact eventfd coalescing behavior.
#[derive(Clone)]
pub(super) struct Waker {
    inner: Arc<WakerInner>,
}

impl Waker {
    /// Create a non-blocking eventfd wake source.
    pub(super) fn new() -> Result<Self, std::io::Error> {
        // SAFETY: `eventfd` is called with valid flags and no aliasing pointers.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `eventfd` returned a new owned descriptor.
        let wake_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        Ok(Self {
            inner: Arc::new(WakerInner {
                wake_fd,
                state: AtomicU32::new(0),
            }),
        })
    }

    /// Ring the eventfd doorbell.
    fn ring(&self) {
        let value: u64 = 1;
        loop {
            // SAFETY: `wake_fd` is a valid eventfd descriptor and `value` points
            // to an initialized 8-byte integer for the duration of the call.
            let ret = unsafe {
                libc::write(
                    self.inner.wake_fd.as_raw_fd(),
                    &value as *const u64 as *const libc::c_void,
                    size_of::<u64>(),
                )
            };
            if ret == size_of::<u64>() as isize {
                return;
            }
            assert_eq!(
                ret, -1,
                "eventfd write returned unexpected byte count: {ret}"
            );
            match std::io::Error::last_os_error().raw_os_error() {
                // Retry if interrupted by a signal before completion.
                Some(libc::EINTR) => continue,
                // Non-blocking write would block because the eventfd
                // counter is saturated. A wake is already queued, so no
                // retry is needed.
                Some(libc::EAGAIN) => return,
                _ => {
                    warn!("eventfd write failed");
                    return;
                }
            }
        }
    }

    /// Wake one thread waiting on the idle path.
    fn futex_wake(&self) {
        loop {
            // SAFETY: `state` is a valid aligned futex word for the duration of
            // the syscall.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    self.inner.state.as_ptr(),
                    libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                    1u32,
                )
            };
            if ret >= 0 {
                return;
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                _ => {
                    warn!("futex wake failed");
                    return;
                }
            }
        }
    }

    /// Atomically latch one pending wake and return the previous state.
    ///
    /// The first caller to set `WAKE_SIGNALLED_BIT` in an epoch receives the
    /// full pre-update state. Subsequent callers observe `None` until the loop
    /// disarms and clears the bit.
    fn latch_signal(&self) -> Option<u32> {
        self.inner
            .state
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                ((current & WAKE_SIGNALLED_BIT) == 0).then_some(current | WAKE_SIGNALLED_BIT)
            })
            .ok()
    }

    /// Signal the currently armed wait target described by `waiting`.
    fn signal_waiter(&self, waiting: u32) {
        assert_ne!(
            waiting, WAITING_MASK,
            "iouring wake state cannot wait on futex and eventfd simultaneously"
        );

        match waiting {
            0 => {}
            WAITING_ON_FUTEX_BIT => self.futex_wake(),
            WAITING_ON_EVENTFD_BIT => self.ring(),
            _ => unreachable!("unexpected iouring wake target"),
        }
    }

    /// Publish one submitted operation and optionally ring `eventfd`.
    ///
    /// Callers must invoke this only after successfully enqueueing work into
    /// the MPSC channel. That ordering guarantees that when the loop observes
    /// an updated sequence, there is corresponding work to drain.
    ///
    /// The common unarmed path performs only one `fetch_add`. When a wait is
    /// armed and no wake has yet been claimed for that epoch, this caller
    /// claims `WAKE_SIGNALLED_BIT` with a follow-up atomic update and then
    /// signals the armed wait target.
    pub(super) fn publish(&self) {
        let prev = self
            .inner
            .state
            .fetch_add(SUBMISSION_INCREMENT, Ordering::Relaxed);
        let waiting = prev & WAITING_MASK;

        // Fast path: the loop is not waiting, or another publisher already
        // claimed the wake for the current armed epoch.
        if waiting == 0 || (prev & WAKE_SIGNALLED_BIT) != 0 {
            return;
        }

        if let Some(prev) = self.latch_signal() {
            self.signal_waiter(prev & WAITING_MASK);
        }
    }

    /// Wake the loop without publishing a new submission.
    ///
    /// This is used for out-of-band notifications like producer disconnect.
    ///
    /// Unlike `publish()`, this also latches a pending wake while no wait
    /// target is armed so the next arm-and-recheck cycle skips blocking once.
    pub(super) fn notify(&self) {
        if let Some(prev) = self.latch_signal() {
            self.signal_waiter(prev & WAITING_MASK);
        }
    }

    /// Return the current submitted sequence.
    ///
    /// The sequence domain is masked to 29 bits and compared against the
    /// loop-local `processed_seq` in the same domain.
    fn submitted(&self) -> u32 {
        (self.inner.state.load(Ordering::Relaxed) >> STATE_BITS) & SUBMISSION_SEQ_MASK
    }

    /// Return whether producers have published work the loop has not yet
    /// drained from the channel.
    pub(super) fn pending(&self, processed_seq: u32) -> bool {
        self.submitted() != processed_seq
    }

    /// Park on the idle path until the packed wake state changes.
    ///
    /// This method hides the arm-and-recheck futex sequence used when the ring
    /// is fully idle. It always disarms the wait bits before returning.
    pub(super) fn park_idle(&self, processed_seq: u32) {
        if let Some(snapshot) = self.blocking_snapshot(WAITING_ON_FUTEX_BIT, processed_seq) {
            self.wait_futex(snapshot);
        }
        self.disarm();
    }

    /// Arm the blocking wake path used around `submit_and_wait`.
    ///
    /// The returned guard automatically disarms the wait bits on drop. Call
    /// [`BlockGuard::should_block`] to decide whether the loop was still idle
    /// after arming.
    pub(super) fn arm(&self, processed_seq: u32) -> BlockGuard<'_> {
        let should_block = self
            .blocking_snapshot(WAITING_ON_EVENTFD_BIT, processed_seq)
            .is_some();
        BlockGuard {
            waker: self,
            should_block,
        }
    }

    /// Set one wait target and return the post-update snapshot when it still
    /// permits blocking.
    fn blocking_snapshot(&self, wait_bit: u32, processed_seq: u32) -> Option<u32> {
        // This transition only mutates the packed wake state. Tokio's channel
        // synchronizes message and close visibility independently.
        let prev = self.inner.state.fetch_or(wait_bit, Ordering::Relaxed);
        assert_eq!(
            prev & WAITING_MASK,
            0,
            "iouring wait target should be disarmed before re-arming"
        );
        let snapshot = prev | wait_bit;

        // Only block if the post-arm snapshot still looks idle. When that is
        // true, return the exact packed word so the idle path can futex-wait
        // on the same state it just armed.
        ((snapshot & WAKE_SIGNALLED_BIT) == 0
            && ((snapshot >> STATE_BITS) & SUBMISSION_SEQ_MASK) == processed_seq)
            .then_some(snapshot)
    }

    /// Sleep on the packed state word with futex until it changes.
    ///
    /// Retries on `EINTR`. Treats `EAGAIN` as "state already changed". The
    /// caller must pass the exact armed snapshot.
    fn wait_futex(&self, snapshot: u32) {
        loop {
            // This is only a same-word equality check before entering the
            // syscall.
            if self.inner.state.load(Ordering::Relaxed) != snapshot {
                return;
            }

            // SAFETY: `state` is a valid aligned futex word for the duration of
            // the syscall.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    self.inner.state.as_ptr(),
                    libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                    snapshot,
                    std::ptr::null::<libc::timespec>(),
                )
            };
            if ret == 0 {
                return;
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return,
                _ => {
                    warn!("futex wait failed");
                    return;
                }
            }
        }
    }

    /// Disarm the current wait target after we resume running.
    ///
    /// Keeping wait bits clear while actively running avoids redundant futex
    /// wakes and eventfd writes during bursts. This is done both after a real
    /// wake and after a post-arm recheck decides not to block.
    #[inline]
    fn disarm(&self) {
        self.inner.state.fetch_and(!STATE_MASK, Ordering::Relaxed);
    }

    /// Drain eventfd readiness acknowledged by a wake CQE.
    ///
    /// This acknowledges kernel-visible wake readiness. Wait gating is tracked
    /// separately in the packed `state` atomic and is managed by
    /// [`Waker::park_idle`] and [`Waker::arm`].
    ///
    /// Retries on `EINTR`. Treats `EAGAIN` as "nothing to drain". Without
    /// `EFD_SEMAPHORE`, one successful read drains the full counter to zero.
    pub(super) fn acknowledge(&self) {
        let mut value: u64 = 0;
        loop {
            // SAFETY: `wake_fd` is a valid eventfd descriptor and `value` points
            // to writable 8-byte storage for the duration of the call.
            let ret = unsafe {
                libc::read(
                    self.inner.wake_fd.as_raw_fd(),
                    &mut value as *mut u64 as *mut libc::c_void,
                    size_of::<u64>(),
                )
            };
            if ret == size_of::<u64>() as isize {
                // eventfd (without EFD_SEMAPHORE) returns the full counter and
                // resets it to zero in one read.
                return;
            }
            assert_eq!(
                ret, -1,
                "eventfd read returned unexpected byte count: {ret}"
            );
            match std::io::Error::last_os_error().raw_os_error() {
                // Retry if interrupted by a signal before completion.
                Some(libc::EINTR) => continue,
                // Non-blocking read would block because the counter is zero,
                // there is nothing left to drain right now.
                Some(libc::EAGAIN) => return,
                _ => {
                    tracing::warn!("eventfd read failed");
                    return;
                }
            }
        }
    }

    /// Install the wake poll request into the SQ.
    ///
    /// This uses multishot poll and is called on startup and whenever a wake
    /// CQE indicates the previous multishot request is no longer active.
    pub(super) fn reinstall(&self, submission_queue: &mut SubmissionQueue<'_>) {
        let wake_poll = PollAdd::new(Fd(self.inner.wake_fd.as_raw_fd()), libc::POLLIN as u32)
            .multi(true)
            .build()
            .user_data(WAKE_USER_DATA);

        // SAFETY: The poll SQE owns no user pointers and references a valid FD.
        unsafe {
            submission_queue
                .push(&wake_poll)
                .expect("wake poll SQE should always fit in the ring");
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use io_uring::IoUring;
    use std::{
        mem::size_of,
        os::fd::{AsRawFd, FromRawFd},
    };

    pub(crate) fn wait_until_futex_armed(waker: &Waker) {
        while waker.inner.state.load(Ordering::Relaxed) & WAITING_ON_FUTEX_BIT == 0 {
            std::hint::spin_loop();
        }
    }

    fn read_eventfd_count(waker: &Waker) -> u64 {
        let mut value = 0u64;
        // SAFETY: `wake_fd` is a valid eventfd descriptor and `value` points
        // to writable 8-byte storage for the duration of the call.
        let ret = unsafe {
            libc::read(
                waker.inner.wake_fd.as_raw_fd(),
                &mut value as *mut u64 as *mut libc::c_void,
                size_of::<u64>(),
            )
        };
        assert_eq!(ret, size_of::<u64>() as isize);
        value
    }

    #[test]
    fn test_publish_arm_guard_and_submitted() {
        // Verify the packed wake state tracks submission sequence separately
        // from the blocking wake state across the normal publish and
        // acknowledge flow.
        let waker = Waker::new().expect("eventfd creation should succeed");
        assert_eq!(waker.submitted(), 0);

        // Publish without an armed wait target only advances sequence.
        waker.publish();
        assert_eq!(waker.submitted(), 1);

        // Arm and publish should trigger a ring; acknowledge drains it.
        let arm = waker.arm(1);
        assert!(arm.should_block());
        waker.publish();
        assert_eq!(waker.submitted(), 2);

        // Acknowledge and guard drop are wake-gating operations and must not change
        // the submitted sequence domain.
        waker.acknowledge();
        assert_eq!(waker.submitted(), 2);
        drop(arm);
        assert_eq!(waker.submitted(), 2);
        assert_eq!(
            waker.inner.state.load(std::sync::atomic::Ordering::Acquire) & STATE_MASK,
            0
        );

        // Re-arming should observe the same submitted snapshot while idle.
        let arm = waker.arm(2);
        assert!(arm.should_block());
        drop(arm);
    }

    #[test]
    fn test_park_idle_notify_keeps_sequence_stable() {
        // Verify `park_idle` sleeps on the idle path and out-of-band wakes do
        // not perturb the logical submission sequence.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let before = waker.submitted();
        let notifier = waker.clone();

        let handle = std::thread::spawn(move || {
            while notifier
                .inner
                .state
                .load(std::sync::atomic::Ordering::Acquire)
                & WAITING_ON_FUTEX_BIT
                == 0
            {
                std::hint::spin_loop();
            }
            notifier.notify();
        });

        waker.park_idle(before);
        handle.join().expect("idle notifier thread panicked");
        assert_eq!(waker.submitted(), before);
    }

    #[test]
    fn test_notify_without_idle_wait_keeps_sequence_stable() {
        // Verify out-of-band notifications without an idle wait do not perturb
        // submission sequence.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let before = waker.submitted();
        waker.notify();
        assert_eq!(waker.submitted(), before);
    }

    #[test]
    fn test_notify_before_park_idle_skips_sleep() {
        // Verify an out-of-band wake latched before idle arming makes the next
        // idle park return immediately instead of sleeping.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let before = waker.submitted();

        waker.notify();
        waker.park_idle(before);

        assert_eq!(waker.submitted(), before);
        assert_eq!(waker.inner.state.load(Ordering::Relaxed) & STATE_MASK, 0);
    }

    #[test]
    fn test_publish_deduplicates_eventfd_wakes() {
        // Verify repeated publishes while the same eventfd wait is armed only
        // queue one wake write, while still advancing the sequence each time.
        let waker = Waker::new().expect("eventfd creation should succeed");

        let arm = waker.arm(0);
        assert!(arm.should_block());
        waker.publish();
        waker.publish();

        assert_eq!(waker.submitted(), 2);
        assert_eq!(read_eventfd_count(&waker), 1);
        drop(arm);
    }

    #[test]
    fn test_notify_deduplicates_eventfd_wakes() {
        // Verify repeated out-of-band notifications while the same eventfd
        // wait is armed only queue one wake write and do not perturb sequence.
        let waker = Waker::new().expect("eventfd creation should succeed");

        let arm = waker.arm(0);
        assert!(arm.should_block());
        waker.notify();
        waker.notify();

        assert_eq!(waker.submitted(), 0);
        assert_eq!(read_eventfd_count(&waker), 1);
        drop(arm);
    }

    #[test]
    fn test_ring_and_acknowledge_empty_paths_keep_sequence_stable() {
        // Verify ringing and draining the eventfd does not perturb the
        // logical submission sequence, even when the counter is already empty.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let before = waker.submitted();

        // Drive one normal wake cycle, then immediately drain again to hit the
        // non-blocking empty-read path.
        waker.ring();
        waker.acknowledge();
        // Second acknowledge should take the non-blocking empty path.
        waker.acknowledge();

        assert_eq!(waker.submitted(), before);
    }

    #[test]
    fn test_reinstall_pushes_wake_poll() {
        // Verify reinstall contributes exactly one multishot wake poll SQE.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let mut ring = IoUring::new(8).expect("io_uring creation should succeed");

        // Reinstall should enqueue exactly one wake poll request.
        let mut sq = ring.submission();
        let before = sq.len();
        waker.reinstall(&mut sq);
        assert_eq!(sq.len(), before + 1);
    }

    #[test]
    fn test_ring_and_acknowledge_error_branches() {
        // Verify the explicit EAGAIN and generic error branches leave the
        // logical submission sequence unchanged.
        let mut waker = Waker::new().expect("eventfd creation should succeed");
        let before = waker.submitted();

        // Saturate the eventfd counter near its maximum so `ring` takes the
        // non-blocking EAGAIN path and `acknowledge` drains the queued wake.
        let fd = waker.inner.wake_fd.as_raw_fd();
        let value = u64::MAX - 1;
        // SAFETY: `fd` is a valid eventfd and `value` points to initialized memory.
        let wrote = unsafe {
            libc::write(
                fd,
                &value as *const u64 as *const libc::c_void,
                size_of::<u64>(),
            )
        };
        assert_eq!(wrote, size_of::<u64>() as isize);
        waker.ring();
        waker.acknowledge();

        // Then close the descriptor so both helpers exercise their generic
        // error-logging paths.
        // SAFETY: closing a valid fd is safe.
        let closed = unsafe { libc::close(fd) };
        assert_eq!(closed, 0);
        waker.ring();
        waker.acknowledge();

        // Replace with a known-good fd so drop doesn't accidentally close a reused
        // descriptor number from the manually closed one.
        // SAFETY: `dup` returns a new owned fd on success.
        let replacement = unsafe { libc::dup(libc::STDIN_FILENO) };
        assert!(replacement >= 0);
        let old = {
            let inner = std::sync::Arc::get_mut(&mut waker.inner).expect("unique waker in test");
            // SAFETY: `replacement` came from `dup` above and is uniquely owned here.
            std::mem::replace(&mut inner.wake_fd, unsafe {
                std::os::fd::OwnedFd::from_raw_fd(replacement)
            })
        };
        std::mem::forget(old);

        // Direct eventfd read/write error paths should not perturb sequence tracking.
        assert_eq!(waker.submitted(), before);
    }
}
