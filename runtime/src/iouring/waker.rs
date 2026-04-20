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
struct WakerInner {
    wake_fd: OwnedFd,
    state: AtomicU32,
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
    pub fn park_idle(&self, processed_seq: u32) {
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
            self.futex_wait(snapshot);
        }
        self.clear_wait();
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

    /// Install the internal `eventfd` multishot poll request into the SQ.
    ///
    /// This uses multishot poll and is called on startup and whenever a wake
    /// CQE indicates the previous multishot request is no longer active.
    ///
    /// Returns `false` if the local SQ is already full and the rearm must be
    /// retried in a later staging pass.
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

    /// Wake one thread sleeping on the fully-idle futex path.
    ///
    /// This is used only when the loop has no active ring waiters and is
    /// blocked in [`Waker::futex_wait`] on the packed wake-state word.
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

    /// Sleep on the packed wake-state word for the fully-idle path.
    ///
    /// The caller must pass the exact post-arm snapshot from the same atomic
    /// transition that set `WAITING_ON_FUTEX_BIT`. `FUTEX_WAIT` only blocks
    /// while the word still equals that value, which closes the race between
    /// arming idle sleep and a concurrent publish or out-of-band wake.
    ///
    /// Retries on `EINTR`. Treats `EAGAIN` as "state already changed before
    /// the kernel slept".
    fn futex_wait(&self, snapshot: u32) {
        loop {
            // This is only a same-word equality check before entering the
            // syscall. It relies only on modification order of this atomic, so
            // `Relaxed` is sufficient.
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
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return,
                _ => {
                    // With a null timeout, documented timeout-specific errors do not
                    // apply here. An unexpected futex wait error means the kernel
                    // refused to block, so the safe fallback is to return to
                    // userspace and re-check the packed state rather than panic.
                    warn!("futex wait failed: {err}");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use io_uring::IoUring;
    use std::{
        mem::size_of,
        os::fd::{AsRawFd, FromRawFd},
        sync::Arc,
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

    fn state_bits(waker: &Waker) -> u32 {
        waker.inner.state.load(Ordering::Relaxed) & STATE_MASK
    }

    fn submitted_seq(waker: &Waker) -> u32 {
        (waker.inner.state.load(Ordering::Relaxed) >> STATE_BITS) & SUBMISSION_SEQ_MASK
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

                waker.park_idle(before);
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
        waker.park_idle(before);

        assert_eq!(submitted_seq(&waker), before);
        assert_eq!(state_bits(&waker), 0);
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
        // check / futex EAGAIN path rejected the outdated snapshot.
        waker.futex_wait(snapshot);
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
        assert_eq!(read_eventfd_count(&waker), 1);
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
        assert_eq!(read_eventfd_count(&waker), 1);
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
