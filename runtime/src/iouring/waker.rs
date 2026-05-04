//! Hybrid futex/eventfd wake coordination for the io_uring loop.
//!
//! This module implements the producer-to-loop wake protocol used by [`super::IoUringLoop`]:
//! - Producers call [`Waker::publish`] after enqueueing work.
//! - The loop calls [`Waker::park_idle`] when it is fully idle.
//! - The loop acquires an [`ArmGuard`] from [`Waker::arm`] before
//!   blocking in `submit_and_wait`.
//! - Producers wake only the currently armed wait target.
//! - A dedicated "wake signalled" bit coalesces repeated wake attempts.
//! - Out-of-band wake requests use [`Waker::wake`].
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
use io_uring::squeue::SubmissionQueue;
#[cfg(not(feature = "loom"))]
use io_uring::{opcode::PollAdd, types::Fd};
#[cfg(feature = "loom")]
use loom::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc, Condvar, Mutex,
};
use std::time::{Duration, Instant};
#[cfg(not(feature = "loom"))]
use std::{
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};
#[cfg(not(feature = "loom"))]
use tracing::warn;

/// Reserved `user_data` value for internal wake poll completions.
pub const WAKE_USER_DATA: UserData = UserData::MAX;

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
/// Full sequence domain used by the packed submission counter (state >> 3).
pub const SUBMISSION_SEQ_MASK: u32 = u32::MAX >> STATE_BITS;
/// Maximum live published-minus-processed gap that keeps modular order directional.
pub const HALF_SUBMISSION_SEQUENCE_DOMAIN: u32 = SUBMISSION_SEQ_MASK.div_ceil(2);

/// RAII guard returned by [`Waker::arm`] for a `submit_and_wait` blocking section.
///
/// While this guard is live, the loop is armed to receive an eventfd-based
/// wake if producers publish new work or the final handle disconnects.
pub struct ArmGuard<'a> {
    waker: &'a Waker,
    still_idle: bool,
    wake_latched: bool,
}

impl ArmGuard<'_> {
    /// Return whether the post-arm snapshot still looked idle, meaning no
    /// wake was latched and the published sequence still matched the loop's
    /// `processed_seq`.
    pub const fn still_idle(&self) -> bool {
        self.still_idle
    }

    /// Return whether a wake was already latched before or during arming.
    pub const fn wake_latched(&self) -> bool {
        self.wake_latched
    }
}

impl Drop for ArmGuard<'_> {
    fn drop(&mut self) {
        self.waker.clear_wait();
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
/// stored in loop-local state). After arming a wait target, the loop blocks only
/// if the same post-arm snapshot still shows no latched wake and still carries
/// the exact `submitted_seq == processed_seq` snapshot the loop armed against.
///
/// The loop bounds the rounded channel/ring size strictly below half the packed
/// sequence domain. That makes the modular delta `submitted_seq - processed_seq`
/// directional: any non-zero delta smaller than half the domain means
/// `submitted_seq` is ahead, while larger deltas mean the visible submission
/// sequence is lagging behind requests the loop has already drained.
///
/// Blocking follows an arm-and-recheck protocol:
/// - The loop first checks for a published-ahead delta, then arms a wait target.
/// - The loop blocks only if the post-arm snapshot still looks idle after that
///   same atomic state transition.
/// - Submitters signal the currently armed wait target exactly once.
/// - Out-of-band notifications latch one wake even while unarmed, so the next
///   arm-and-recheck cycle skips blocking once.
///
/// This makes submissions racing with the sleep transition observable either by
/// sequence mismatch in the loop or by a futex/eventfd wakeup.
#[cfg(not(feature = "loom"))]
struct WakerInner {
    /// Non-blocking eventfd monitored by the loop's multishot wake poll.
    wake_fd: OwnedFd,
    /// Packed wait-target, wake-latch, and submitted-sequence state.
    state: AtomicU32,
}

/// Loom-only model of the waker state.
///
/// Loom cannot observe real futexes, eventfds, or io_uring CQEs, so this
/// variant keeps the same packed atomic state as the production waker and
/// replaces the kernel wake surfaces with userspace condvar models. The goal is
/// to model the producer/loop atomic protocol closely enough for loom to
/// explore memory orderings and wake races. It is not a model of kernel CQE
/// ordering, `io_uring_enter`, or wake-poll rearm behavior.
#[cfg(feature = "loom")]
struct WakerInner {
    /// Packed wait-target, wake-latch, and submitted-sequence state.
    state: AtomicU32,
    /// Mutex standing in for the kernel futex bucket lock.
    futex_bucket: Mutex<()>,
    /// Condvar standing in for the fully-idle futex wait queue.
    futex_waiters: Condvar,
    /// Durable eventfd readiness counter observed by the modeled eventfd wait.
    eventfd_counter: AtomicU64,
    /// Mutex pairing eventfd readiness checks with condvar parking.
    eventfd_readiness: Mutex<()>,
    /// Condvar standing in for `submit_and_wait` waking on a wake CQE.
    eventfd_waiters: Condvar,
}

/// Internal hybrid futex/eventfd wake source for the io_uring loop.
///
/// - Publish submissions from producers via [`Waker::publish`]
/// - Wake without publishing via [`Waker::wake`]
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
pub struct Waker {
    inner: Arc<WakerInner>,
}

impl Waker {
    /// Create a hybrid futex/eventfd wake source backed by a non-blocking
    /// `eventfd`.
    #[cfg(not(feature = "loom"))]
    pub fn new() -> Result<Self, std::io::Error> {
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

    /// Create the loom model of the hybrid wake source.
    ///
    /// This keeps the same packed atomic state as production, but replaces the
    /// eventfd and futex kernel objects with loom-visible counters and
    /// condition variables.
    #[cfg(feature = "loom")]
    pub fn new() -> Result<Self, std::io::Error> {
        Ok(Self {
            inner: Arc::new(WakerInner {
                state: AtomicU32::new(0),
                futex_bucket: Mutex::new(()),
                futex_waiters: Condvar::new(),
                eventfd_counter: AtomicU64::new(0),
                eventfd_readiness: Mutex::new(()),
                eventfd_waiters: Condvar::new(),
            }),
        })
    }

    /// Latch one pending wake and, if a target is currently armed, wake it.
    ///
    /// The first caller to set `WAKE_SIGNALLED_BIT` in an epoch performs the
    /// wake. Subsequent callers do nothing until the loop disarms and clears
    /// the bit.
    ///
    /// All claimed wakes flow through this path, whether they come from
    /// `publish()` on an armed epoch or from an out-of-band caller such as the
    /// final sender disconnecting.
    pub fn wake(&self) {
        // `HandleInner::drop` uses this path without bumping the submission
        // sequence. Publish that disconnect here so that after the loop resumes
        // and `clear_wait()` acquires, the next channel check cannot observe
        // the wake without also observing the disconnect that caused it.
        let prev = self
            .inner
            .state
            .fetch_or(WAKE_SIGNALLED_BIT, Ordering::Release);

        if (prev & WAKE_SIGNALLED_BIT) != 0 {
            return;
        }

        let waiting = prev & WAITING_MASK;
        assert_ne!(
            waiting, WAITING_MASK,
            "iouring wake state cannot wait on futex and eventfd simultaneously"
        );

        match waiting {
            0 => {}
            WAITING_ON_FUTEX_BIT => self.futex_wake(),
            WAITING_ON_EVENTFD_BIT => self.eventfd_wake(),
            _ => unreachable!("unexpected iouring wake target"),
        }
    }

    /// Publish one submitted operation and optionally wake the currently armed
    /// wait target.
    ///
    /// Callers must invoke this only after successfully enqueueing work into
    /// the MPSC channel.
    ///
    /// The common unarmed path performs only one `fetch_add`. When a wait is
    /// armed and no wake has yet been claimed for that epoch, this caller
    /// claims `WAKE_SIGNALLED_BIT` with a follow-up atomic update and then
    /// signals the armed wait target.
    #[inline]
    pub fn publish(&self) {
        // Use `Release` so that when `pending()` later observes a published-ahead
        // sequence delta with its `Acquire` load, a following
        // `self.receiver.try_recv()` in `fill_submission_queue()` must observe
        // the corresponding request.
        let prev = self
            .inner
            .state
            .fetch_add(SUBMISSION_INCREMENT, Ordering::Release);

        let waiting = prev & WAITING_MASK;

        // Fast path: the loop is not waiting, or another publisher already
        // claimed the wake for the current armed epoch.
        if waiting == 0 || (prev & WAKE_SIGNALLED_BIT) != 0 {
            return;
        }

        self.wake();
    }

    /// Return whether any published submissions are still pending relative to
    /// `processed_seq`, i.e. whether the published sequence is currently ahead
    /// of that drained sequence.
    #[inline]
    pub fn pending(&self, processed_seq: u32) -> bool {
        // Pair this `Acquire` with `publish()`'s `Release`. The rounded ring
        // size is kept strictly below half the packed sequence domain, so a
        // non-zero modular delta smaller than that half-range unambiguously
        // means `published_seq` is ahead of `processed_seq`.
        let published_seq =
            (self.inner.state.load(Ordering::Acquire) >> STATE_BITS) & SUBMISSION_SEQ_MASK;

        let delta = published_seq.wrapping_sub(processed_seq) & SUBMISSION_SEQ_MASK;
        delta != 0 && delta < HALF_SUBMISSION_SEQUENCE_DOMAIN
    }

    /// Park on the idle path until the packed wake state changes.
    ///
    /// This method hides the arm-and-recheck futex sequence used when the ring
    /// is fully idle. It always clears the current wait state before returning.
    ///
    /// Returns `Some(duration)` only if `futex_wait` actually blocked in the
    /// kernel and later resumed. Returns `None` if the armed snapshot already
    /// showed published work or a latched wake, or if a concurrent state
    /// change rejected the snapshot before the thread could sleep.
    pub fn park_idle(&self, processed_seq: u32) -> Option<Duration> {
        // Arming only updates the packed wake state machine. It does not
        // publish queue memory or consume any out-of-band wake publication, so
        // `Relaxed` is sufficient on this RMW.
        let prev = self
            .inner
            .state
            .fetch_or(WAITING_ON_FUTEX_BIT, Ordering::Relaxed);

        assert_eq!(
            prev & WAITING_MASK,
            0,
            "iouring wait target should be disarmed before re-arming"
        );

        let snapshot = prev | WAITING_ON_FUTEX_BIT;

        // Only block if the post-arm snapshot still looks idle. When that is
        // true, futex-wait on the same packed state word that was just armed.
        if (snapshot & WAKE_SIGNALLED_BIT) == 0
            && ((snapshot >> STATE_BITS) & SUBMISSION_SEQ_MASK) == processed_seq
        {
            let before = Instant::now();
            let slept = self.futex_wait(snapshot);
            self.clear_wait();
            slept.then(|| before.elapsed())
        } else {
            self.clear_wait();
            None
        }
    }

    /// Arm the blocking wake path used around `submit_and_wait`.
    ///
    /// The returned guard automatically clears the current wait state on drop.
    /// Call [`ArmGuard::still_idle`] to decide whether the loop may block on
    /// the normal "still idle" path, or [`ArmGuard::wake_latched`] to detect
    /// an already-latched wake without conflating it with published-ahead
    /// sequence progress.
    pub fn arm(&self, processed_seq: u32) -> ArmGuard<'_> {
        // Arming only updates the packed wake state machine. It does not
        // publish queue memory or consume any out-of-band wake publication, so
        // `Relaxed` is sufficient on this RMW.
        let prev = self
            .inner
            .state
            .fetch_or(WAITING_ON_EVENTFD_BIT, Ordering::Relaxed);

        assert_eq!(
            prev & WAITING_MASK,
            0,
            "iouring wait target should be disarmed before re-arming"
        );

        let snapshot = prev | WAITING_ON_EVENTFD_BIT;
        let wake_latched = (snapshot & WAKE_SIGNALLED_BIT) != 0;
        let still_idle =
            !wake_latched && ((snapshot >> STATE_BITS) & SUBMISSION_SEQ_MASK) == processed_seq;

        ArmGuard {
            waker: self,
            still_idle,
            wake_latched,
        }
    }

    /// Drain readiness from the internal `eventfd` after a wake CQE.
    ///
    /// This acknowledges kernel-visible `eventfd` readiness. Wait gating is
    /// tracked separately in the packed `state` atomic and is managed by
    /// [`Waker::park_idle`] and [`Waker::arm`].
    ///
    /// Retries on `EINTR`. Treats `EAGAIN` as "nothing to drain". Without
    /// `EFD_SEMAPHORE`, one successful read drains the full counter to zero.
    #[cfg(not(feature = "loom"))]
    pub fn acknowledge(&self) {
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

    /// Model an eventfd read that drains all pending readiness.
    ///
    /// Production eventfd reads without `EFD_SEMAPHORE` return the current
    /// counter and reset it to zero atomically. The loom model uses one atomic
    /// swap to preserve that contract for wake-coalescing tests.
    #[cfg(feature = "loom")]
    pub fn acknowledge(&self) {
        self.inner.eventfd_counter.swap(0, Ordering::AcqRel);
    }

    /// Install the internal `eventfd` multishot poll request into the SQ.
    ///
    /// This uses multishot poll and is called on startup and whenever a wake
    /// CQE indicates the previous multishot request is no longer active.
    ///
    /// Returns `false` if the local SQ is already full and the rearm must be
    /// retried in a later staging pass.
    #[cfg(not(feature = "loom"))]
    pub fn reinstall(&self, submission_queue: &mut SubmissionQueue<'_>) -> bool {
        if submission_queue.is_full() {
            return false;
        }

        let wake_poll = PollAdd::new(Fd(self.inner.wake_fd.as_raw_fd()), libc::POLLIN as u32)
            .multi(true)
            .build()
            .user_data(WAKE_USER_DATA);

        // SAFETY: The poll SQE owns no user pointers and references a valid FD.
        unsafe {
            submission_queue
                .push(&wake_poll)
                .expect("checked wake poll SQE capacity");
        }

        true
    }

    /// Model wake-poll reinstall as a successful no-op.
    ///
    /// The loom tests in this module do not model the `io_uring` submission
    /// queue or wake-poll rearm state. Keeping this method present lets the
    /// crate compile with `loom` while keeping that boundary explicit.
    #[cfg(feature = "loom")]
    pub const fn reinstall(&self, _submission_queue: &mut SubmissionQueue<'_>) -> bool {
        true
    }

    /// Clear the current wait epoch after we resume running.
    ///
    /// Keeping wait bits clear while actively running avoids redundant futex
    /// wakes and eventfd writes during bursts. This is done both after
    /// `park_idle()` / `submit_and_wait` return and after a post-arm recheck
    /// decides not to block.
    #[inline]
    fn clear_wait(&self) {
        // Pair with `wake()`'s `Release`. This is the first common point after
        // resuming from a wake and before the next channel check, so acquiring
        // here ensures the loop cannot observe the wake without also observing
        // the sender-side state change that caused it.
        self.inner.state.fetch_and(!STATE_MASK, Ordering::Acquire);
    }

    /// Wake the loop while it is blocked in `submit_and_wait`.
    ///
    /// This writes to the internal `eventfd` monitored by the ring's multishot
    /// poll request. The resulting wake CQE causes the loop to leave its
    /// eventfd-backed blocking section and resume in userspace.
    #[cfg(not(feature = "loom"))]
    fn eventfd_wake(&self) {
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

    /// Model an eventfd write plus wake-CQE delivery.
    ///
    /// Incrementing `eventfd_counter` preserves the durable readiness bit of a
    /// real eventfd, while notifying `eventfd_waiters` stands in for
    /// `submit_and_wait` returning after the wake CQE becomes available.
    #[cfg(feature = "loom")]
    fn eventfd_wake(&self) {
        self.inner.eventfd_counter.fetch_add(1, Ordering::Release);
        let _guard = self.inner.eventfd_readiness.lock().unwrap();
        self.inner.eventfd_waiters.notify_one();
    }

    /// Wake one thread sleeping on the fully-idle futex path.
    ///
    /// This is used only when the loop has no active ring waiters and is
    /// blocked in [`Waker::futex_wait`] on the packed wake-state word.
    #[cfg(not(feature = "loom"))]
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
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                _ => {
                    // The operation-specific `FUTEX_WAKE` error here is `EINVAL` for
                    // a PI waiter mismatch, and the generic futex syscall errors are
                    // invalid or inaccessible user memory, invalid arguments, or an
                    // unsupported op. For this private, aligned in-process futex,
                    // all of those indicate a broken invariant or environment.
                    // Unlike `futex_wait()`, there is no safe "just continue in
                    // userspace" fallback here: because `WAKE_SIGNALLED_BIT` is
                    // already latched for this epoch, logging and continuing would
                    // risk a permanent lost wake.
                    //
                    // [https://www.man7.org/linux/man-pages/man2/FUTEX_WAKE.2const.html#ERRORS]
                    panic!("futex wake failed: {err}");
                }
            }
        }
    }

    /// Model `FUTEX_WAKE` for the fully-idle path.
    ///
    /// Taking `futex_bucket` before notifying mirrors the serialization the
    /// kernel futex bucket provides between compare-and-park and wake.
    #[cfg(feature = "loom")]
    fn futex_wake(&self) {
        let _guard = self.inner.futex_bucket.lock().unwrap();
        self.inner.futex_waiters.notify_one();
    }

    /// Sleep on the packed wake-state word for the fully-idle path.
    ///
    /// The caller must pass the exact post-arm snapshot from the same atomic
    /// transition that set `WAITING_ON_FUTEX_BIT`. `FUTEX_WAIT` only blocks
    /// while the word still equals that value, which closes the race between
    /// arming idle sleep and a concurrent publish or out-of-band wake.
    ///
    /// Retries on `EINTR`. Treats `EAGAIN` as "state already changed before
    /// the kernel slept".
    ///
    /// Returns `true` only if the kernel actually blocked the thread and later
    /// resumed it. Returns `false` for stale-snapshot races, userspace
    /// equality mismatches, and unexpected futex wait failures.
    #[cfg(not(feature = "loom"))]
    fn futex_wait(&self, snapshot: u32) -> bool {
        loop {
            // This is only a same-word equality check before entering the
            // syscall. It relies only on modification order of this atomic, so
            // `Relaxed` is sufficient.
            if self.inner.state.load(Ordering::Relaxed) != snapshot {
                return false;
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
                return true;
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return false,
                _ => {
                    // With a null timeout, documented timeout-specific errors do not
                    // apply here. An unexpected futex wait error means the kernel
                    // refused to block, so the safe fallback is to return to
                    // userspace and re-check the packed state rather than panic.
                    warn!("futex wait failed: {err}");
                    return false;
                }
            }
        }
    }

    /// Model `FUTEX_WAIT` for the fully-idle path.
    ///
    /// The condition variable wait keeps the compare and park under
    /// `futex_bucket`, so loom can explore the same lost-wake boundary that the
    /// kernel's atomic futex wait protects in production.
    #[cfg(feature = "loom")]
    fn futex_wait(&self, snapshot: u32) -> bool {
        let mut guard = self.inner.futex_bucket.lock().unwrap();
        let mut slept = false;
        while self.inner.state.load(Ordering::Acquire) == snapshot {
            slept = true;
            guard = self.inner.futex_waiters.wait(guard).unwrap();
        }
        slept
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use io_uring::IoUring;
    #[cfg(not(feature = "loom"))]
    use std::{
        mem::size_of,
        os::fd::{AsRawFd, FromRawFd},
    };

    pub fn wait_until_futex_armed(waker: &Waker) {
        while waker.inner.state.load(Ordering::Relaxed) & WAITING_ON_FUTEX_BIT == 0 {
            std::hint::spin_loop();
        }
    }

    pub fn wait_until_eventfd_armed(waker: &Waker) {
        while waker.inner.state.load(Ordering::Relaxed) & WAITING_ON_EVENTFD_BIT == 0 {
            std::hint::spin_loop();
        }
    }

    pub fn state_bits(waker: &Waker) -> u32 {
        waker.inner.state.load(Ordering::Relaxed) & STATE_MASK
    }

    pub fn submitted_seq(waker: &Waker) -> u32 {
        (waker.inner.state.load(Ordering::Relaxed) >> STATE_BITS) & SUBMISSION_SEQ_MASK
    }

    pub fn eventfd_count(waker: &Waker) -> u64 {
        #[cfg(not(feature = "loom"))]
        {
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
            if ret == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
                return 0;
            }
            assert_eq!(ret, size_of::<u64>() as isize);
            value
        }

        #[cfg(feature = "loom")]
        {
            waker.inner.eventfd_counter.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn test_publish_arm_guard_and_submitted() {
        // Verify the packed wake state tracks submission sequence separately
        // from the blocking wake state across the normal publish and
        // acknowledge flow.
        let waker = Waker::new().expect("eventfd creation should succeed");
        assert_eq!(submitted_seq(&waker), 0);

        // Publish without an armed wait target only advances sequence.
        waker.publish();
        assert_eq!(submitted_seq(&waker), 1);

        // Arm and publish should trigger an eventfd wake; acknowledge drains it.
        let arm = waker.arm(1);
        assert!(arm.still_idle());
        assert!(!arm.wake_latched());
        waker.publish();
        assert_eq!(submitted_seq(&waker), 2);

        // Acknowledge and guard drop are wake-gating operations and must not change
        // the submitted sequence domain.
        waker.acknowledge();
        assert_eq!(submitted_seq(&waker), 2);
        drop(arm);
        assert_eq!(submitted_seq(&waker), 2);
        assert_eq!(state_bits(&waker), 0);

        // Re-arming should observe the same submitted snapshot while idle.
        let arm = waker.arm(2);
        assert!(arm.still_idle());
        assert!(!arm.wake_latched());
        drop(arm);
    }

    #[test]
    fn test_pending_uses_directional_half_range_compare() {
        // Verify `pending()` only reports work when the published sequence is
        // directionally ahead within the half-range window.
        let waker = Waker::new().expect("eventfd creation should succeed");

        // A one-step published-ahead delta is pending for `processed_seq = 0`,
        // but not once the loop has caught up.
        waker.inner.state.store(1 << STATE_BITS, Ordering::Relaxed);
        assert!(waker.pending(0));
        assert!(!waker.pending(1));

        // A visible published sequence that lags behind `processed_seq` must
        // not be treated as pending work.
        waker.inner.state.store(0, Ordering::Relaxed);
        assert!(!waker.pending(1));

        // Exactly half the domain is ambiguous and therefore not directional.
        waker.inner.state.store(
            HALF_SUBMISSION_SEQUENCE_DOMAIN << STATE_BITS,
            Ordering::Relaxed,
        );
        assert!(!waker.pending(0));

        // Wrapping by one still counts as a published-ahead delta.
        waker.inner.state.store(0, Ordering::Relaxed);
        assert!(waker.pending(SUBMISSION_SEQ_MASK));
    }

    #[test]
    fn test_park_idle_handles_concurrent_publish_and_wake_races() {
        #[derive(Clone, Copy, Debug)]
        enum Notifier {
            Wake,
            Publish,
        }

        // Stress the real concurrent idle-path races rather than only the
        // single-threaded stale-snapshot path. The notifier thread waits until
        // `WAITING_ON_FUTEX_BIT` is visible and then races a `wake()` or
        // `publish()` against the parked thread's equality check, futex
        // syscall, and eventual `clear_wait()`.
        for notifier in [Notifier::Wake, Notifier::Publish] {
            for _ in 0..64 {
                let waker = Waker::new().expect("eventfd creation should succeed");
                let before = submitted_seq(&waker);
                let notifier_waker = waker.clone();

                let handle = std::thread::spawn(move || {
                    while state_bits(&notifier_waker) & WAITING_ON_FUTEX_BIT == 0 {
                        std::hint::spin_loop();
                    }
                    match notifier {
                        Notifier::Wake => notifier_waker.wake(),
                        Notifier::Publish => notifier_waker.publish(),
                    }
                });

                let _ = waker.park_idle(before);
                handle.join().expect("idle notifier thread panicked");

                let expected = match notifier {
                    Notifier::Wake => before,
                    Notifier::Publish => before.wrapping_add(1) & SUBMISSION_SEQ_MASK,
                };

                assert_eq!(submitted_seq(&waker), expected, "{notifier:?}");
                assert_eq!(state_bits(&waker), 0, "{notifier:?}");
            }
        }
    }

    #[test]
    fn test_wake_without_idle_wait_keeps_sequence_stable() {
        // Verify out-of-band notifications without an idle wait do not perturb
        // submission sequence.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let before = submitted_seq(&waker);
        waker.wake();
        assert_eq!(submitted_seq(&waker), before);
    }

    #[test]
    fn test_wake_before_park_idle_skips_sleep() {
        // Verify an out-of-band wake latched before idle arming makes the next
        // idle park return immediately instead of sleeping.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let before = submitted_seq(&waker);

        waker.wake();
        let duration = waker.park_idle(before);

        assert!(duration.is_none(), "should not have slept");
        assert_eq!(submitted_seq(&waker), before);
        assert_eq!(state_bits(&waker), 0);
    }

    #[test]
    fn test_publish_before_park_idle_skips_sleep() {
        // Verify a sequence published before idle arming makes the next idle
        // park return immediately without manufacturing a wake.
        let waker = Waker::new().expect("eventfd creation should succeed");

        waker.publish();
        assert!(waker.park_idle(0).is_none());

        assert_eq!(submitted_seq(&waker), 1);
        assert_eq!(state_bits(&waker), 0);
        assert_eq!(eventfd_count(&waker), 0);
    }

    #[test]
    fn test_publish_after_futex_arm_rejects_stale_snapshot() {
        // Verify the futex idle path tolerates a publish that lands after
        // WAITING_ON_FUTEX_BIT is armed but before the armed thread commits to
        // a stable futex wait on that snapshot.
        //
        // This models the race that `park_idle()` closes:
        // 1. idle path arms WAITING_ON_FUTEX_BIT and computes a snapshot
        // 2. producer publishes, changing the packed state word
        // 3. a futex wait on the stale snapshot must return immediately
        let waker = Waker::new().expect("eventfd creation should succeed");
        let before = submitted_seq(&waker);

        // Manually split `park_idle()` into "arm" and "wait" so the publish
        // can be injected exactly between those two steps.
        let prev = waker
            .inner
            .state
            .fetch_or(WAITING_ON_FUTEX_BIT, Ordering::Relaxed);
        assert_eq!(prev & WAITING_MASK, 0);
        let snapshot = prev | WAITING_ON_FUTEX_BIT;

        // This publish changes the packed word after arming, so a futex wait
        // on the stale snapshot must now return immediately.
        waker.publish();
        assert_eq!(
            submitted_seq(&waker),
            before.wrapping_add(1) & SUBMISSION_SEQ_MASK
        );

        // If the stale snapshot were incorrectly accepted, this call could
        // block indefinitely. Returning here proves the userspace equality
        // check / futex EAGAIN path rejected the outdated snapshot without
        // ever committing to a real futex sleep.
        assert!(!waker.futex_wait(snapshot));
        waker.clear_wait();

        // The publish should remain visible and the wait bits should be fully
        // cleared on exit, matching `park_idle()`'s contract.
        assert_eq!(
            submitted_seq(&waker),
            before.wrapping_add(1) & SUBMISSION_SEQ_MASK
        );
        assert_eq!(state_bits(&waker), 0);
    }

    #[test]
    fn test_publish_deduplicates_eventfd_wakes() {
        // Verify contended publishes while the same eventfd wait is armed only
        // queue one wake write, while still advancing the sequence for every
        // publisher that raced in this epoch.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let barrier = Arc::new(std::sync::Barrier::new(5));
        let mut handles = Vec::new();

        let arm = waker.arm(0);
        assert!(arm.still_idle());
        assert!(!arm.wake_latched());
        for _ in 0..4 {
            let publisher = waker.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                publisher.publish();
            }));
        }
        barrier.wait();
        for handle in handles {
            handle.join().expect("publish thread panicked");
        }

        assert_eq!(submitted_seq(&waker), 4);
        assert_eq!(eventfd_count(&waker), 1);
        drop(arm);
    }

    #[test]
    fn test_arm_after_sticky_wake_skips_blocking() {
        // Verify a wake latched before arming makes the next blocking section
        // skip the normal idle-based blocking decision, and surface that the
        // reason was an out-of-band wake rather than published-ahead work.
        let waker = Waker::new().expect("eventfd creation should succeed");

        waker.wake();
        let arm = waker.arm(0);
        assert!(!arm.still_idle());
        assert!(arm.wake_latched());
        drop(arm);

        assert_eq!(submitted_seq(&waker), 0);
        assert_eq!(state_bits(&waker), 0);
    }

    #[test]
    fn test_unarmed_wakes_rearm_across_epochs() {
        // Verify unarmed wake latches are consumed when the loop next arms,
        // and that later unarmed wakes can be observed in later epochs.
        let waker = Waker::new().expect("eventfd creation should succeed");

        waker.wake();
        let arm = waker.arm(0);
        assert!(!arm.still_idle());
        assert!(arm.wake_latched());
        drop(arm);

        assert_eq!(submitted_seq(&waker), 0);
        assert_eq!(state_bits(&waker), 0);
        assert_eq!(eventfd_count(&waker), 0);

        waker.wake();
        let arm = waker.arm(0);
        assert!(!arm.still_idle());
        assert!(arm.wake_latched());
        drop(arm);

        assert_eq!(submitted_seq(&waker), 0);
        assert_eq!(state_bits(&waker), 0);
        assert_eq!(eventfd_count(&waker), 0);

        waker.publish();
        waker.wake();
        assert_eq!(submitted_seq(&waker), 1);
        assert_eq!(eventfd_count(&waker), 0);
        let arm = waker.arm(1);
        assert!(!arm.still_idle());
        assert!(arm.wake_latched());
        drop(arm);

        assert_eq!(state_bits(&waker), 0);
        assert_eq!(eventfd_count(&waker), 0);
    }

    #[test]
    fn test_arm_after_publish_skips_blocking() {
        // Verify arming with a stale processed sequence notices the newly
        // published submission and skips blocking.
        let waker = Waker::new().expect("eventfd creation should succeed");

        waker.publish();
        let arm = waker.arm(0);
        assert!(!arm.still_idle());
        assert!(!arm.wake_latched());
        drop(arm);

        assert_eq!(submitted_seq(&waker), 1);
        assert_eq!(state_bits(&waker), 0);
    }

    #[test]
    fn test_wake_deduplicates_eventfd_wakes() {
        // Verify contended out-of-band notifications while the same eventfd
        // wait is armed only queue one wake write and do not perturb sequence.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let barrier = Arc::new(std::sync::Barrier::new(5));
        let mut handles = Vec::new();

        let arm = waker.arm(0);
        assert!(arm.still_idle());
        assert!(!arm.wake_latched());
        for _ in 0..4 {
            let notifier = waker.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                notifier.wake();
            }));
        }
        barrier.wait();
        for handle in handles {
            handle.join().expect("wake thread panicked");
        }

        assert_eq!(submitted_seq(&waker), 0);
        assert_eq!(eventfd_count(&waker), 1);
        drop(arm);
    }

    #[test]
    fn test_eventfd_wake_and_acknowledge_empty_paths_keep_sequence_stable() {
        // Verify eventfd wake and drain do not perturb the
        // logical submission sequence, even when the counter is already empty.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let before = submitted_seq(&waker);

        // Drive one normal wake cycle, then immediately drain again to hit the
        // non-blocking empty-read path.
        waker.eventfd_wake();
        waker.acknowledge();
        // Second acknowledge should take the non-blocking empty path.
        waker.acknowledge();

        assert_eq!(submitted_seq(&waker), before);
    }

    #[test]
    fn test_reinstall_pushes_wake_poll() {
        // Verify `reinstall()` queues one multishot wake poll SQE when space
        // is available and reports failure without mutating the SQ when it is
        // full.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let mut ring = IoUring::new(8).expect("io_uring creation should succeed");

        // With SQ space available, `reinstall()` should enqueue exactly one
        // wake poll request.
        let mut sq = ring.submission();
        let before = sq.len();
        assert!(waker.reinstall(&mut sq));
        assert_eq!(sq.len(), before + 1);

        // Once the SQ is full, `reinstall()` must leave it unchanged and ask
        // the caller to retry later.
        while !sq.is_full() {
            let nop = io_uring::opcode::Nop::new().build().user_data(0);
            // SAFETY: Nop SQE owns no user pointers or external resources.
            unsafe {
                sq.push(&nop).expect("unable to fill submission queue");
            }
        }

        let before = sq.len();
        assert!(!waker.reinstall(&mut sq));
        assert_eq!(sq.len(), before);
    }

    #[cfg(not(feature = "loom"))]
    #[test]
    fn test_eventfd_wake_and_acknowledge_error_branches() {
        // Verify the explicit EAGAIN and generic error branches leave the
        // logical submission sequence unchanged.
        let mut waker = Waker::new().expect("eventfd creation should succeed");
        let before = submitted_seq(&waker);

        // Saturate the eventfd counter near its maximum so `eventfd_wake` takes the
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
        waker.eventfd_wake();
        waker.acknowledge();

        // Then close the descriptor so both helpers exercise their generic
        // error-logging paths.
        // SAFETY: closing a valid fd is safe.
        let closed = unsafe { libc::close(fd) };
        assert_eq!(closed, 0);
        waker.eventfd_wake();
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
        assert_eq!(submitted_seq(&waker), before);
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::{
        tests::{eventfd_count, state_bits, submitted_seq},
        *,
    };
    use commonware_utils::test_rng;
    use loom::{
        sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        },
        thread,
    };
    use rand::Rng;

    // This module uses loom to model the waker's producer/loop protocol over
    // the packed atomic state word. The model keeps the production sequence and
    // wait-bit state machine, but replaces kernel wake surfaces with
    // loom-visible userspace models: the futex path uses a mutex and condvar to
    // preserve the atomic compare-and-park property of `FUTEX_WAIT`, and the
    // eventfd path uses a durable readiness counter plus a condvar to model
    // both persistent wake readiness and a blocked `submit_and_wait` returning
    // after a wake CQE.
    //
    // The tests keep schedules small while exercising the important races and
    // invariants: publish versus arm-and-recheck, futex idle parking, eventfd
    // wake coalescing, sticky out-of-band wakes, sequence wraparound, and the
    // Release/Acquire edges that make producer state visible after `pending()`
    // or `clear_wait()`. The model intentionally stops at this userspace
    // protocol boundary. It does not validate kernel CQE ordering,
    // `io_uring_enter`, wake-poll rearming, or syscall error handling.

    // Minimal model of the inbound request queue that feeds the ring.
    //
    // The queue model deliberately uses only relaxed accesses. These tests rely
    // on the waker's Release/Acquire edges to make an enqueued request visible
    // to the loop after it observes progress or resumes from a wake.
    struct QueuedRequest {
        value: AtomicU32,
    }

    impl QueuedRequest {
        fn empty() -> Self {
            Self {
                value: AtomicU32::new(0),
            }
        }

        fn enqueue(&self, value: u32) {
            self.value.store(value, Ordering::Relaxed);
        }

        fn read(&self) -> u32 {
            self.value.load(Ordering::Relaxed)
        }
    }

    // Wait until the modeled eventfd has durable readiness.
    //
    // In production, `submit_and_wait` returns after the wake poll produces a
    // CQE. In the loom model, `eventfd_wake()` increments `eventfd_counter` and
    // notifies this condvar, so this helper represents only that blocking
    // boundary.
    fn wait_for_eventfd_readiness(waker: &Waker) {
        let mut guard = waker.inner.eventfd_readiness.lock().unwrap();
        while waker.inner.eventfd_counter.load(Ordering::Acquire) == 0 {
            guard = waker.inner.eventfd_waiters.wait(guard).unwrap();
        }
    }

    // Wait until a producer/notifier has latched a wake bit.
    //
    // This is deliberately a relaxed spin: the tests using it pair with the
    // producer's Release through the later `clear_wait()` Acquire.
    fn wait_for_wake_signal(waker: &Waker) {
        while state_bits(waker) & WAKE_SIGNALLED_BIT == 0 {
            thread::yield_now();
        }
    }

    // Finish any wake epoch left over after a loop-simulator test has already
    // observed the sequence progress it cares about.
    //
    // A producer can claim `WAKE_SIGNALLED_BIT` and queue modeled eventfd
    // readiness while the simulated loop is also able to make progress by
    // observing `pending()`. At that point the leftover wake is cleanup noise,
    // not the property under test. Tests that care about exact wake coalescing
    // should assert the modeled eventfd counter before calling this helper.
    fn finish_leftover_wake(waker: &Waker) {
        assert_eq!(state_bits(waker) & WAITING_MASK, 0);
        if (state_bits(waker) & WAKE_SIGNALLED_BIT) != 0 {
            let guard = waker.arm(submitted_seq(waker));
            assert!(guard.wake_latched());
            drop(guard);
        }
        // A raced publisher can queue eventfd readiness after the loop has
        // already observed its sequence bump. Finish that modeled wake CQE so
        // cleanup assertions do not confuse it with the unarmed-wake cases.
        waker.acknowledge();
        assert_eq!(state_bits(waker), 0);
        assert_eq!(eventfd_count(waker), 0);
    }

    // Simulate the loop's eventfd-backed wait path until it has observed
    // `target` published submissions. This is not modeling the request queue
    // itself, only the waker-side control flow: check `pending()`, arm the
    // eventfd target, block only if the post-arm snapshot is still idle, then
    // drop the guard and acknowledge modeled eventfd readiness.
    //
    // The final `acknowledge()` is model cleanup for any wake CQE readiness
    // produced during the brief arm window. It may be a no-op when the loop did
    // not actually block, so tests that validate exact wake counts assert the
    // counter directly instead of relying on this helper.
    fn simulate_eventfd_loop_until(waker: &Waker, mut processed: u32, target: u32) -> u32 {
        while processed != target {
            if waker.pending(processed) {
                processed = processed.wrapping_add(1) & SUBMISSION_SEQ_MASK;
                continue;
            }

            let guard = waker.arm(processed);
            if guard.still_idle() {
                wait_for_eventfd_readiness(waker);
                assert!(
                    eventfd_count(waker) > 0,
                    "blocking eventfd wait must observe queued readiness before cleanup",
                );
            }
            drop(guard);
            waker.acknowledge();
        }
        processed
    }

    // Simulate the loop's fully-idle futex path until it has observed `target`
    // published submissions. Like the eventfd loop simulator, this models only
    // waker-side control flow: check `pending()`, otherwise call `park_idle()`
    // to arm the futex wait target and perform the stale-snapshot recheck.
    fn simulate_futex_loop_until(waker: &Waker, mut processed: u32, target: u32) -> u32 {
        while processed != target {
            if waker.pending(processed) {
                processed = processed.wrapping_add(1) & SUBMISSION_SEQ_MASK;
                continue;
            }
            let _ = waker.park_idle(processed);
        }
        processed
    }

    /// Producer operation used by the deterministic generated loom tests.
    ///
    /// Each generated program is built before entering `loom::model`, then run
    /// by a producer thread. `Publish` models a producer making one request
    /// visible to the loop, while `Wake` models an out-of-band notification that
    /// must not affect submission sequence accounting.
    #[derive(Clone, Copy, Debug)]
    enum ProducerOp {
        /// Publish one request to the waker.
        Publish,
        /// Notify the loop without publishing a request.
        Wake,
    }

    impl ProducerOp {
        // Generate a deterministic publish/wake program for loom exploration.
        fn generate_program(rng: &mut impl Rng, len: usize) -> Vec<Self> {
            (0..len)
                .map(|_| {
                    if rng.gen_bool(0.5) {
                        Self::Publish
                    } else {
                        Self::Wake
                    }
                })
                .collect()
        }

        // Execute one generated producer operation.
        fn execute(self, waker: &Waker, publishes: &AtomicU32) {
            match self {
                ProducerOp::Publish => {
                    waker.publish();
                    publishes.fetch_add(1, Ordering::Relaxed);
                }
                ProducerOp::Wake => waker.wake(),
            }
        }
    }

    // Number of deterministic `ProducerOp` programs to generate per test.
    const GENERATED_CASES: usize = 8;
    // Number of operations in each generated `ProducerOp` program.
    const OPS_PER_PROGRAM: usize = 3;

    #[test]
    fn publish_pending_pairing() {
        // `publish` must make the producer's earlier enqueue-side write visible
        // to a loop that observes the published sequence through `pending()`.
        // The loop deliberately spins on `pending()` before joining the producer
        // so the only intended synchronization is publish Release to pending
        // Acquire.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let queued = Arc::new(QueuedRequest::empty());

            let producer = thread::spawn({
                let waker = waker.clone();
                let queued = queued.clone();
                move || {
                    queued.enqueue(42);
                    waker.publish();
                }
            });

            while !waker.pending(0) {
                thread::yield_now();
            }

            assert_eq!(queued.read(), 42);
            producer.join().unwrap();
            assert_eq!(submitted_seq(&waker), 1);
        });
    }

    #[test]
    fn wake_clear_wait_pairing() {
        // `wake` is used by out-of-band callers such as final-handle drop. It
        // must publish the caller's earlier state change to the loop even though
        // it does not advance the submitted sequence.
        //
        // The loop waits for the wake bit before joining the notifier, arms
        // against the current sequence, and drops the guard so `clear_wait()`'s
        // Acquire can pair with `wake()`'s Release.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let queued = Arc::new(QueuedRequest::empty());

            let notifier = thread::spawn({
                let waker = waker.clone();
                let queued = queued.clone();
                move || {
                    queued.enqueue(42);
                    waker.wake();
                }
            });

            wait_for_wake_signal(&waker);

            assert_eq!(eventfd_count(&waker), 0);
            let guard = waker.arm(0);
            assert!(guard.wake_latched());
            drop(guard);

            assert_eq!(queued.read(), 42);
            assert_eq!(eventfd_count(&waker), 0);
            notifier.join().unwrap();
        });
    }

    #[test]
    fn concurrent_unarmed_wakes_coalesce() {
        // Concurrent out-of-band wakes that arrive before the loop arms should
        // coalesce to one sticky wake bit without queuing eventfd readiness.
        loom::model(|| {
            let waker = Waker::new().unwrap();

            let a = thread::spawn({
                let waker = waker.clone();
                move || waker.wake()
            });
            let b = thread::spawn({
                let waker = waker.clone();
                move || waker.wake()
            });

            a.join().unwrap();
            b.join().unwrap();

            assert_eq!(eventfd_count(&waker), 0);
            let guard = waker.arm(0);
            assert!(!guard.still_idle());
            assert!(guard.wake_latched());
            drop(guard);

            assert_eq!(submitted_seq(&waker), 0);
            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn arm_and_recheck_eventfd_race() {
        // A publish racing with the eventfd-backed arm path must be visible
        // either in the post-arm sequence snapshot or through a modeled eventfd
        // wake. After the blocking section exits, guard drop clears wait state
        // and `acknowledge` drains the eventfd counter.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let producer = thread::spawn({
                let waker = waker.clone();
                move || waker.publish()
            });

            let guard = waker.arm(0);
            if guard.still_idle() {
                wait_for_eventfd_readiness(&waker);
            }

            drop(guard);
            waker.acknowledge();
            producer.join().unwrap();

            assert_eq!(submitted_seq(&waker), 1);
            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn publish_clear_wait_pairing_when_armed() {
        // When a producer publishes into an armed eventfd epoch, the loop can
        // resume without first observing `pending()`. `clear_wait()` must still
        // acquire the producer's enqueue-side writes before the loop checks the
        // queue after waking.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let queued = Arc::new(QueuedRequest::empty());
            let guard = waker.arm(0);
            assert!(guard.still_idle());

            let producer = thread::spawn({
                let waker = waker.clone();
                let queued = queued.clone();
                move || {
                    queued.enqueue(42);
                    waker.publish();
                }
            });

            wait_for_wake_signal(&waker);

            drop(guard);
            assert_eq!(queued.read(), 42);
            producer.join().unwrap();

            assert_eq!(submitted_seq(&waker), 1);
            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 1);
            waker.acknowledge();
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn wake_clear_wait_pairing_when_armed() {
        // When an out-of-band wake lands in an armed eventfd epoch, the loop
        // resumes without any sequence progress. `clear_wait()` must still
        // acquire the notifier's earlier state change before the loop checks for
        // disconnect or shutdown state after waking.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let queued = Arc::new(QueuedRequest::empty());
            let guard = waker.arm(0);
            assert!(guard.still_idle());

            let notifier = thread::spawn({
                let waker = waker.clone();
                let queued = queued.clone();
                move || {
                    queued.enqueue(42);
                    waker.wake();
                }
            });

            wait_for_wake_signal(&waker);

            drop(guard);
            assert_eq!(queued.read(), 42);
            notifier.join().unwrap();

            assert_eq!(submitted_seq(&waker), 0);
            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 1);
            waker.acknowledge();
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn arm_and_recheck_futex_race() {
        // The fully-idle path arms a futex wait target on the same state word
        // that producers update. A racing publish must either change the
        // post-arm snapshot before sleep or wake the modeled futex waiter.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let producer = thread::spawn({
                let waker = waker.clone();
                move || waker.publish()
            });

            let _ = waker.park_idle(0);
            producer.join().unwrap();

            assert_eq!(submitted_seq(&waker), 1);
            finish_leftover_wake(&waker);
        });
    }

    #[test]
    fn publishers_dedup_eventfd_wake() {
        // Two publishers in one armed eventfd epoch must both advance the
        // submitted sequence, but only the first wake claimant should increment
        // the modeled eventfd counter.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let guard = waker.arm(0);
            assert!(guard.still_idle());

            let a = thread::spawn({
                let waker = waker.clone();
                move || waker.publish()
            });
            let b = thread::spawn({
                let waker = waker.clone();
                move || waker.publish()
            });

            a.join().unwrap();
            b.join().unwrap();

            assert_eq!(submitted_seq(&waker), 2);
            assert_eq!(eventfd_count(&waker), 1);

            drop(guard);
            waker.acknowledge();
            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn mixed_publish_and_wake_dedup() {
        // A publish and an out-of-band wake racing in the same armed eventfd
        // epoch should coalesce to one eventfd signal while still preserving the
        // publish's sequence increment.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let guard = waker.arm(0);
            assert!(guard.still_idle());

            let publisher = thread::spawn({
                let waker = waker.clone();
                move || waker.publish()
            });
            let notifier = thread::spawn({
                let waker = waker.clone();
                move || waker.wake()
            });

            publisher.join().unwrap();
            notifier.join().unwrap();

            assert_eq!(submitted_seq(&waker), 1);
            assert_eq!(eventfd_count(&waker), 1);

            drop(guard);
            waker.acknowledge();
            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn mixed_publish_and_wake_futex_arm() {
        // A publish and an out-of-band wake racing in the same futex-armed epoch
        // should coalesce through the shared wake latch while preserving the
        // publish's sequence increment. Unlike the eventfd path, there is no
        // durable counter to inspect, so this splits `park_idle()` at the arm
        // point and verifies the stale futex snapshot is rejected after the
        // state changes.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let prev = waker
                .inner
                .state
                .fetch_or(WAITING_ON_FUTEX_BIT, Ordering::Relaxed);
            assert_eq!(prev & WAITING_MASK, 0);
            let snapshot = prev | WAITING_ON_FUTEX_BIT;

            let publisher = thread::spawn({
                let waker = waker.clone();
                move || waker.publish()
            });
            let notifier = thread::spawn({
                let waker = waker.clone();
                move || waker.wake()
            });

            publisher.join().unwrap();
            notifier.join().unwrap();

            assert_eq!(submitted_seq(&waker), 1);
            assert_eq!(eventfd_count(&waker), 0);
            assert_eq!(
                state_bits(&waker),
                WAITING_ON_FUTEX_BIT | WAKE_SIGNALLED_BIT
            );
            assert!(!waker.futex_wait(snapshot));
            waker.clear_wait();
            assert_eq!(state_bits(&waker), 0);
        });
    }

    #[test]
    fn drop_wake() {
        // An out-of-band wake racing with the eventfd arm path must wake the
        // loop without advancing the submitted sequence. If it arrives before
        // arming, `wake_latched` skips the wait, otherwise the modeled eventfd
        // signal releases the loop.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let notifier = thread::spawn({
                let waker = waker.clone();
                move || waker.wake()
            });

            let guard = waker.arm(0);
            if guard.still_idle() {
                wait_for_eventfd_readiness(&waker);
            }

            drop(guard);
            waker.acknowledge();
            notifier.join().unwrap();

            assert_eq!(submitted_seq(&waker), 0);
            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn sequence_wraparound() {
        // Preload the sequence to the last representable value, then publish
        // twice so the visible sequence wraps through zero to one. The
        // half-range modular `pending()` check must remain directional across
        // that boundary.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            waker
                .inner
                .state
                .store(SUBMISSION_SEQ_MASK << STATE_BITS, Ordering::Relaxed);

            let producer = thread::spawn({
                let waker = waker.clone();
                move || {
                    waker.publish();
                    waker.publish();
                }
            });

            assert_eq!(
                simulate_eventfd_loop_until(&waker, SUBMISSION_SEQ_MASK, 1),
                1
            );
            producer.join().unwrap();
            assert_eq!(submitted_seq(&waker), 1);
            finish_leftover_wake(&waker);
        });
    }

    #[test]
    fn two_producers_mixed_ops() {
        // Producer-only mixed publish/wake programs should preserve submitted
        // sequence conservation and must not queue eventfd readiness while the
        // loop is unarmed. A sticky wake bit may remain for the next arm cycle.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let publishes = Arc::new(AtomicU32::new(0));

            let a = thread::spawn({
                let waker = waker.clone();
                let publishes = publishes.clone();
                move || {
                    waker.publish();
                    publishes.fetch_add(1, Ordering::Relaxed);
                    waker.wake();
                    waker.publish();
                    publishes.fetch_add(1, Ordering::Relaxed);
                }
            });

            let b = thread::spawn({
                let waker = waker.clone();
                let publishes = publishes.clone();
                move || {
                    waker.wake();
                    waker.publish();
                    publishes.fetch_add(1, Ordering::Relaxed);
                }
            });

            a.join().unwrap();
            b.join().unwrap();

            assert_eq!(submitted_seq(&waker), publishes.load(Ordering::Relaxed));
            assert_eq!(state_bits(&waker) & WAITING_MASK, 0);
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn producer_with_draining_loop() {
        // A minimal loop simulator must drain both publishes from one producer
        // using the eventfd arm-and-recheck path whenever no sequence progress
        // is currently visible.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let producer = thread::spawn({
                let waker = waker.clone();
                move || {
                    waker.publish();
                    waker.publish();
                }
            });

            let processed = simulate_eventfd_loop_until(&waker, 0, 2);
            producer.join().unwrap();

            assert_eq!(processed, 2);
            assert_eq!(submitted_seq(&waker), 2);
            finish_leftover_wake(&waker);
        });
    }

    #[test]
    fn park_idle_with_concurrent_wake() {
        // The fully-idle futex path must also handle pure out-of-band wakes.
        // The loop either sees the wake bit before sleeping or is resumed by the
        // modeled futex wake. No submission sequence bump is involved.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let notifier = thread::spawn({
                let waker = waker.clone();
                move || waker.wake()
            });

            let _ = waker.park_idle(0);
            notifier.join().unwrap();

            assert_eq!(submitted_seq(&waker), 0);
            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn two_cycle_drain_with_interleaved_wake() {
        // A drain loop must survive an explicit wake between two publishes. The
        // wake may be consumed as a sticky bit or as eventfd readiness, but both
        // publishes must still be processed exactly once.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let producer = thread::spawn({
                let waker = waker.clone();
                move || {
                    waker.publish();
                    waker.wake();
                    waker.publish();
                }
            });

            let processed = simulate_eventfd_loop_until(&waker, 0, 2);
            producer.join().unwrap();

            assert_eq!(processed, 2);
            assert_eq!(submitted_seq(&waker), 2);
            finish_leftover_wake(&waker);
        });
    }

    #[test]
    fn multiple_park_idle_cycles() {
        // Repeated fully-idle futex park cycles must continue to observe
        // publishes. This uses `park_idle()` instead of the eventfd arm path
        // whenever no sequence progress is currently visible.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let producer = thread::spawn({
                let waker = waker.clone();
                move || {
                    waker.publish();
                    waker.publish();
                }
            });

            let processed = simulate_futex_loop_until(&waker, 0, 2);
            producer.join().unwrap();

            assert_eq!(processed, 2);
            assert_eq!(submitted_seq(&waker), 2);
            finish_leftover_wake(&waker);
        });
    }

    #[test]
    fn three_thread_stress() {
        // Two producers publishing concurrently with one loop simulator should
        // still preserve conservation and progress. This adds one more producer
        // thread to the eventfd drain shape.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let a = thread::spawn({
                let waker = waker.clone();
                move || waker.publish()
            });
            let b = thread::spawn({
                let waker = waker.clone();
                move || waker.publish()
            });

            let processed = simulate_eventfd_loop_until(&waker, 0, 2);
            a.join().unwrap();
            b.join().unwrap();

            assert_eq!(processed, 2);
            assert_eq!(submitted_seq(&waker), 2);
            finish_leftover_wake(&waker);
        });
    }

    #[test]
    fn generated_producer_only_programs() {
        // Generate deterministic producer-only programs before entering loom,
        // then model each case with four concurrent producers. Each producer
        // runs a short sequence of `publish()` and out-of-band `wake()` calls
        // without any loop thread consuming them.
        //
        // The invariant is producer-side conservation: every generated `Publish`
        // must be reflected in the submitted sequence exactly once, while
        // generated `Wake`s must not affect the sequence. Since the waker is
        // never armed in this test, producers must also leave no wait target
        // armed and must not queue modeled eventfd readiness. A sticky wake bit
        // may remain because there is intentionally no loop to consume it.
        let mut rng = test_rng();
        let programs = (0..GENERATED_CASES)
            .map(|_| {
                [
                    ProducerOp::generate_program(&mut rng, OPS_PER_PROGRAM),
                    ProducerOp::generate_program(&mut rng, OPS_PER_PROGRAM),
                    ProducerOp::generate_program(&mut rng, OPS_PER_PROGRAM),
                    ProducerOp::generate_program(&mut rng, OPS_PER_PROGRAM),
                ]
            })
            .collect::<Vec<_>>();

        for (iter, programs) in programs.into_iter().enumerate() {
            loom::model(move || {
                let waker = Waker::new().unwrap();
                let publishes = Arc::new(AtomicU32::new(0));

                let handles = programs
                    .iter()
                    .map(|program| {
                        let program = program.clone();
                        let waker = waker.clone();
                        let publishes = publishes.clone();
                        thread::spawn(move || {
                            for &op in program.iter() {
                                op.execute(&waker, &publishes);
                            }
                        })
                    })
                    .collect::<Vec<_>>();

                for handle in handles {
                    handle.join().unwrap();
                }

                let expected = publishes.load(Ordering::Relaxed);
                let got = submitted_seq(&waker);
                assert_eq!(
                    got, expected,
                    "publish conservation failed: iter={iter} programs={programs:?}",
                );
                assert_eq!(
                    state_bits(&waker) & WAITING_MASK,
                    0,
                    "wait target remained armed: iter={iter} programs={programs:?}",
                );
                assert_eq!(
                    eventfd_count(&waker),
                    0,
                    "eventfd readiness queued while unarmed: iter={iter} programs={programs:?}",
                );
            });
        }
    }

    #[test]
    fn generated_eventfd_loop_programs() {
        // Generate deterministic single-producer programs before entering loom,
        // then model each case with one producer and the eventfd loop simulator.
        // The producer may interleave out-of-band `wake()` calls before,
        // between, or after its generated `publish()` calls.
        //
        // The loop simulator must eventually observe exactly the generated
        // publish count, regardless of whether progress arrives through
        // `pending()` or through the arm, eventfd readiness, and `clear_wait()`
        // path. Pure wakes are allowed to resume the loop, but they must not
        // create sequence progress or disturb producer accounting.
        let mut rng = test_rng();
        let programs = (0..GENERATED_CASES)
            .map(|_| ProducerOp::generate_program(&mut rng, OPS_PER_PROGRAM))
            .collect::<Vec<_>>();

        for (iter, program) in programs.into_iter().enumerate() {
            let publish_count = program
                .iter()
                .filter(|op| matches!(op, ProducerOp::Publish))
                .count() as u32;

            loom::model(move || {
                let waker = Waker::new().unwrap();
                let publishes = Arc::new(AtomicU32::new(0));

                let producer = thread::spawn({
                    let program = program.clone();
                    let waker = waker.clone();
                    let publishes = publishes.clone();
                    move || {
                        for &op in program.iter() {
                            op.execute(&waker, &publishes);
                        }
                    }
                });

                let processed = simulate_eventfd_loop_until(&waker, 0, publish_count);
                producer.join().unwrap();

                assert_eq!(
                    processed, publish_count,
                    "loop progress failed: iter={iter} program={program:?}",
                );
                assert_eq!(
                    submitted_seq(&waker),
                    publish_count,
                    "publish conservation failed: iter={iter} program={program:?}",
                );
                assert_eq!(
                    publishes.load(Ordering::Relaxed),
                    publish_count,
                    "producer accounting failed: iter={iter} program={program:?}",
                );
                finish_leftover_wake(&waker);
            });
        }
    }
}
