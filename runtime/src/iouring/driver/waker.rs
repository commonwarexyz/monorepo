//! Hybrid futex/eventfd wake coordination for the io_uring loop.
//!
//! This module implements the wake protocol used by [`super::IoUringLoop`].
//! The active protocol is the out-of-band wake latch:
//! - Producers publish work through their own synchronized containers and
//!   then call [`Waker::wake`], which latches a dedicated "wake signalled"
//!   bit and signals only the currently armed wait target. Task wakes,
//!   sleeper alarms, and stop notifications are cross-thread sources: their
//!   same-thread deliveries skip the ring waker entirely because the
//!   executor rechecks ready tasks and alarms before every park. The orphan
//!   mailbox always wakes directly.
//! - The latch coalesces repeated wake attempts: while a wake is already
//!   pending, further wakes write nothing.
//! - The loop calls [`Waker::park_idle`] when it is fully idle, sleeping in
//!   futex wait on the packed state word.
//! - The loop uses [`Waker::wait_eventfd`] around `submit_and_wait` and is
//!   woken through `eventfd` readiness while armed.
//! - Wake CQEs are acknowledged with [`Waker::acknowledge`].
//!
//! Both wait paths follow a lock-free arm-and-recheck handshake: the loop
//! blocks only when the post-arm snapshot (produced by the same atomic
//! transition that armed the wait target) still shows no latched wake, so a
//! wake racing the sleep transition is never lost.
//!
//! The atomic state combines:
//! - bit 0: waiting on futex
//! - bit 1: waiting on eventfd
//! - bit 2: wake already signalled
//!
//! Packed states use `wake | eventfd | futex` bit order:
//!
//! ```text
//! Running 000
//!   |-- wake ------------------------------> Latched 100
//!   |-- park_idle -------------------------> FutexArmed 001
//!   |                                          |-- wake + futex signal --> FutexSignalled 101
//!   |-- arm -------------------------------> EventfdArmed 010
//!                                              |-- wake + eventfd signal -> EventfdSignalled 110
//!
//! Latched 100
//!   |-- park_idle + skip blocking ---------> FutexSignalled 101
//!   |-- arm + skip blocking ---------------> EventfdSignalled 110
//!
//! {FutexArmed 001, FutexSignalled 101,
//!  EventfdArmed 010, EventfdSignalled 110}
//!   |-- clear_wait ------------------------> Running 000
//!
//! Impossible: 011 and 111
//! ```
//!
//! [`Waker::wake`] sets the sticky wake bit. With no armed target it only
//! latches the wake. With one armed target it also signals that target, and
//! repeated wakes coalesce in the corresponding signalled state. Arming via
//! [`Waker::park_idle`] or [`Waker::arm`] preserves an existing latch and skips
//! blocking. [`Waker::clear_wait`] ends the wait epoch by clearing every packed
//! bit. Both targets cannot be armed because the loop is the sole armer, each
//! arming path asserts that no target is already armed, and `wake` never sets a
//! target bit.

use super::UserData;
use io_uring::squeue::SubmissionQueue;
#[cfg(not(feature = "loom"))]
use io_uring::{opcode::PollAdd, types::Fd};
#[cfg(feature = "loom")]
use loom::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicU32, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
#[cfg(not(feature = "loom"))]
use std::{
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};
#[cfg(not(feature = "loom"))]
use tracing::warn;

/// Reserved `user_data` value for internal wake poll completions.
pub const WAKE_USER_DATA: UserData = UserData::MAX;

/// Bit used when the loop is sleeping on a futex.
const WAITING_ON_FUTEX_BIT: u32 = 1;
/// Bit used when the loop is blocked in `submit_and_wait` and wakeable via eventfd.
const WAITING_ON_EVENTFD_BIT: u32 = 1 << 1;
/// Bit used once a wake has already been signalled for the current wait.
const WAKE_SIGNALLED_BIT: u32 = 1 << 2;
/// Mask covering all wake-state flags.
const STATE_MASK: u32 = WAITING_ON_FUTEX_BIT | WAITING_ON_EVENTFD_BIT | WAKE_SIGNALLED_BIT;
/// Mask covering just the current wait target bits.
const WAITING_MASK: u32 = WAITING_ON_FUTEX_BIT | WAITING_ON_EVENTFD_BIT;

/// RAII guard used by [`Waker::wait_eventfd`] around a `submit_and_wait`
/// blocking section.
///
/// While this guard is live, the loop is armed to receive an eventfd-based
/// wake if producers publish new work or the final handle disconnects.
pub struct ArmGuard<'a> {
    waker: &'a Waker,
    wake_latched: bool,
}

impl ArmGuard<'_> {
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
/// `state` stores the wait target and sticky wake latch. Producers (the
/// executor's `Tasks::queue` and `queue_root`,
/// `register_alarm`, and the driver's orphan mailbox) publish through their
/// own synchronized containers and use only the out-of-band
/// `WAKE_SIGNALLED_BIT` latch via [`Waker::wake`], the task and alarm
/// producers only when called from a foreign thread (same-thread deliveries
/// are observed by the executor's pre-park rechecks) and the orphan mailbox
/// unconditionally. After arming a wait
/// target, the loop blocks only if the same post-arm snapshot still shows no
/// latched wake.
///
/// Blocking follows an arm-and-recheck protocol:
/// - The loop arms a wait target.
/// - The loop blocks only if the same atomic transition's post-arm snapshot
///   still looks idle.
/// - Producers signal the currently armed wait target exactly once.
/// - Out-of-band notifications latch one wake even while unarmed, so the next
///   arm-and-recheck cycle skips blocking once.
///
/// This makes notifications racing with the sleep transition observable by a
/// futex or eventfd wakeup.
#[cfg(not(feature = "loom"))]
struct WakerInner {
    /// Non-blocking eventfd monitored by the loop's multishot wake poll.
    wake_fd: OwnedFd,
    /// Wait-target and wake-latch state.
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
    /// Wait-target and wake-latch state.
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
/// - Wake out of band via [`Waker::wake`] (the production wake path)
/// - Park in the fully-idle path via [`Waker::park_idle`]
/// - Arm a `submit_and_wait` blocking section via [`Waker::wait_eventfd`]
/// - Drain `eventfd` readiness on wake CQEs via [`Waker::acknowledge`]
/// - Re-arm the multishot poll request when needed via [`Waker::reinstall`]
///
/// This type intentionally separates wait gating in `state` from kernel
/// readiness consumption in the `eventfd` read path.
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
    /// All claimed wakes flow through this path, whether they come from a task
    /// enqueue, an alarm registration, or an orphan-mailbox push from a
    /// foreign thread.
    pub fn wake(&self) {
        // The wake payload lives in a separately synchronized container (the
        // ready queue, the alarm heap, or the orphan mailbox). The `Release`
        // here pairs with
        // `clear_wait()`'s `Acquire` so that once the loop resumes, its next
        // pass over those containers cannot observe the wake without also
        // observing the state change that caused it.
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

    /// Return whether an out-of-band wake is currently latched.
    ///
    /// This is a hint for opportunistic checks (e.g. the idle spinner): the
    /// load carries no synchronization and does not consume the latch, so
    /// callers must follow up with an arming wait primitive ([Self::park_idle]
    /// or [Self::arm]) whose post-arm snapshot revalidates the latch and whose
    /// wait-state clear consumes it.
    #[inline]
    pub fn signalled(&self) -> bool {
        self.inner.state.load(Ordering::Relaxed) & WAKE_SIGNALLED_BIT != 0
    }

    /// Park on the idle path until the packed wake state changes.
    ///
    /// This method hides the arm-and-recheck futex sequence used when the ring
    /// is fully idle. It always clears the current wait state before returning.
    ///
    /// Returns `Some(duration)` only if `futex_wait` actually blocked in the
    /// kernel and later resumed. Returns `None` if the armed snapshot already
    /// showed a latched wake, or if a concurrent state change rejected the
    /// snapshot before the thread could sleep.
    pub fn park_idle(&self) -> Option<Duration> {
        // Arming only updates the wake state machine. It does not publish queue
        // memory or consume any wake publication, so `Relaxed` is sufficient
        // on this RMW.
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
        if (snapshot & WAKE_SIGNALLED_BIT) == 0 {
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
    /// Call [`ArmGuard::wake_latched`] to detect an already-latched wake before
    /// blocking.
    pub fn arm(&self) -> ArmGuard<'_> {
        // Arming only updates the wake state machine. It does not publish queue
        // memory or consume any wake publication, so `Relaxed` is sufficient
        // on this RMW.
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
        ArmGuard {
            waker: self,
            wake_latched,
        }
    }

    /// Run a blocking callback while the eventfd wake path is armed.
    ///
    /// If a wake is already latched, the callback is skipped. The arm guard
    /// remains live across the callback so every wait bit is cleared if the
    /// callback returns or unwinds.
    pub fn wait_eventfd(&self, callback: impl FnOnce()) {
        let arm = self.arm();
        if !arm.wake_latched() {
            callback();
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
        // resuming from a wake and before the loop's next pass over the
        // producers' containers (ready queue, alarm heap, orphan mailbox), so
        // acquiring here ensures the loop cannot observe the wake without
        // also observing the producer-side state change that caused it.
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
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                // Retry if interrupted by a signal before completion.
                Some(libc::EINTR) => continue,
                _ => {
                    // The wake latch prevents another signal in this epoch, so
                    // returning could leave the armed loop blocked forever.
                    panic!("eventfd write failed: {err}");
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
    /// blocked in [`Waker::futex_wait`] on the wake-state word.
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

    /// Sleep on the wake-state word for the fully-idle path.
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
    use std::{mem::size_of, os::fd::AsRawFd};

    pub fn state_bits(waker: &Waker) -> u32 {
        waker.inner.state.load(Ordering::Relaxed) & STATE_MASK
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
    fn test_park_idle_handles_concurrent_wake_races() {
        // Stress the real concurrent idle-path race. The notifier thread waits
        // until `WAITING_ON_FUTEX_BIT` is visible and then races `wake()`
        // against the parked thread's equality check, futex syscall, and
        // eventual `clear_wait()`.
        for _ in 0..64 {
            let waker = Waker::new().expect("eventfd creation should succeed");
            let notifier_waker = waker.clone();

            let handle = std::thread::spawn(move || {
                while state_bits(&notifier_waker) & WAITING_ON_FUTEX_BIT == 0 {
                    std::hint::spin_loop();
                }
                notifier_waker.wake();
            });

            let _ = waker.park_idle();
            handle.join().expect("idle notifier thread panicked");
            assert_eq!(state_bits(&waker), 0);
        }
    }

    #[test]
    fn test_wake_before_park_idle_skips_sleep() {
        // Verify an out-of-band wake latched before idle arming makes the next
        // idle park return immediately instead of sleeping.
        let waker = Waker::new().expect("eventfd creation should succeed");

        waker.wake();
        let duration = waker.park_idle();

        assert!(duration.is_none(), "should not have slept");
        assert_eq!(state_bits(&waker), 0);
    }

    #[cfg(not(feature = "loom"))]
    #[test]
    fn test_futex_wait_rejects_changed_state_before_syscall() {
        let waker = Waker::new().expect("eventfd creation should succeed");
        waker
            .inner
            .state
            .store(WAITING_ON_FUTEX_BIT, Ordering::Relaxed);

        waker.wake();
        assert!(!waker.futex_wait(WAITING_ON_FUTEX_BIT));

        waker.clear_wait();
        assert_eq!(state_bits(&waker), 0);
    }

    #[test]
    fn test_wait_eventfd_callback_panic_clears_wait_state() {
        let waker = Waker::new().expect("eventfd creation should succeed");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            waker.wait_eventfd(|| {
                assert_eq!(state_bits(&waker), WAITING_ON_EVENTFD_BIT);
                panic!("callback panic");
            });
        }));
        assert!(result.is_err());
        assert_eq!(state_bits(&waker), 0);

        let mut second_epoch_ran = false;
        waker.wait_eventfd(|| {
            assert_eq!(state_bits(&waker), WAITING_ON_EVENTFD_BIT);
            second_epoch_ran = true;
        });
        assert!(second_epoch_ran);
        assert_eq!(state_bits(&waker), 0);
    }

    #[test]
    fn test_unarmed_wakes_rearm_across_epochs() {
        // Verify unarmed wake latches are consumed when the loop next arms,
        // and that later unarmed wakes can be observed in later epochs.
        let waker = Waker::new().expect("eventfd creation should succeed");

        waker.wake();
        assert_eq!(state_bits(&waker), WAKE_SIGNALLED_BIT);
        let arm = waker.arm();
        assert!(arm.wake_latched());
        drop(arm);

        assert_eq!(state_bits(&waker), 0);
        assert_eq!(eventfd_count(&waker), 0);

        waker.wake();
        assert_eq!(state_bits(&waker), WAKE_SIGNALLED_BIT);
        let arm = waker.arm();
        assert!(arm.wake_latched());
        drop(arm);

        assert_eq!(state_bits(&waker), 0);
        assert_eq!(eventfd_count(&waker), 0);
    }

    #[test]
    fn test_wake_deduplicates_eventfd_wakes() {
        // Verify contended out-of-band notifications while the same eventfd
        // wait is armed only queue one wake write.
        let waker = Waker::new().expect("eventfd creation should succeed");
        let barrier = Arc::new(std::sync::Barrier::new(5));
        let mut handles = Vec::new();

        let arm = waker.arm();
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

        assert_eq!(eventfd_count(&waker), 1);
        drop(arm);
    }

    #[test]
    fn test_eventfd_wake_and_acknowledge_empty_paths() {
        // Verify eventfd wake and drain, including an already empty counter.
        let waker = Waker::new().expect("eventfd creation should succeed");

        // Drive one normal wake cycle, then immediately drain again to hit the
        // non-blocking empty-read path.
        waker.eventfd_wake();
        waker.acknowledge();
        // Second acknowledge should take the non-blocking empty path.
        waker.acknowledge();
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
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::{
        tests::{eventfd_count, state_bits},
        *,
    };
    use loom::{
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
        thread,
    };

    // This module uses loom to model the waker's wait-bit state machine while
    // replacing kernel wake surfaces with loom-visible userspace models. The
    // futex path uses a mutex and condvar to preserve the atomic
    // compare-and-park property of `FUTEX_WAIT`. The eventfd path uses a
    // durable readiness counter plus a condvar to model persistent wake
    // readiness and a blocked `submit_and_wait` returning after a wake CQE.
    //
    // The tests keep schedules small while exercising the important races and
    // invariants: futex idle parking, eventfd wake coalescing, sticky wakes,
    // and the Release/Acquire edge that makes producer state visible after
    // `clear_wait()`. The model intentionally stops at this userspace protocol
    // boundary. It does not validate kernel CQE ordering, `io_uring_enter`,
    // wake-poll rearming, or syscall error handling.

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

    #[test]
    fn test_wake_clear_wait_pairing() {
        // `wake` is used by out-of-band callers such as final-handle drop. It
        // must publish the caller's earlier state change to the loop.
        //
        // The loop waits for the wake bit before joining the notifier and drops
        // the arm guard so `clear_wait()`'s Acquire can pair with `wake()`'s
        // Release.
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
            let guard = waker.arm();
            assert!(guard.wake_latched());
            drop(guard);

            assert_eq!(queued.read(), 42);
            assert_eq!(eventfd_count(&waker), 0);
            notifier.join().unwrap();
        });
    }

    #[test]
    fn test_concurrent_unarmed_wakes_coalesce() {
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
            let guard = waker.arm();
            assert!(guard.wake_latched());
            drop(guard);

            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn test_wake_clear_wait_pairing_when_armed() {
        // When an out-of-band wake lands in an armed eventfd epoch, the loop
        // resumes and `clear_wait()` must acquire the notifier's earlier state
        // change before the loop checks for disconnect or shutdown state.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let queued = Arc::new(QueuedRequest::empty());
            let guard = waker.arm();
            assert!(!guard.wake_latched());

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

            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 1);
            waker.acknowledge();
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn test_drop_wake() {
        // An out-of-band wake racing with the eventfd arm path must wake the
        // loop. If it arrives before arming, `wake_latched` skips the wait.
        // Otherwise the modeled eventfd signal releases the loop.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let notifier = thread::spawn({
                let waker = waker.clone();
                move || waker.wake()
            });

            let guard = waker.arm();
            if !guard.wake_latched() {
                wait_for_eventfd_readiness(&waker);
            }

            drop(guard);
            waker.acknowledge();
            notifier.join().unwrap();

            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 0);
        });
    }

    #[test]
    fn test_park_idle_with_concurrent_wake() {
        // The fully-idle futex path must also handle pure out-of-band wakes.
        // The loop either sees the wake bit before sleeping or is resumed by the
        // modeled futex wake.
        loom::model(|| {
            let waker = Waker::new().unwrap();
            let notifier = thread::spawn({
                let waker = waker.clone();
                move || waker.wake()
            });

            let _ = waker.park_idle();
            notifier.join().unwrap();

            assert_eq!(state_bits(&waker), 0);
            assert_eq!(eventfd_count(&waker), 0);
        });
    }
}
