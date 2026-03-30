//! Eventfd-backed wake coordination for the io_uring loop.
//!
//! This module implements the producer-to-loop wake protocol used by [`super::IoUringLoop`]:
//! - Producers call [`Waker::publish`] after enqueueing work.
//! - The loop arms sleep intent with [`Waker::arm`] before blocking.
//! - Producers ring `eventfd` only when sleep intent is armed.
//! - Wake CQEs are acknowledged with [`Waker::acknowledge`].
//!
//! The packed atomic state combines:
//! - bit 0: sleep intent flag
//! - bits 1..: submitted sequence
//!
//! This keeps the arm-and-recheck handshake lock-free while avoiding redundant `eventfd`
//! writes during normal running.

use super::UserData;
use io_uring::{opcode::PollAdd, squeue::SubmissionQueue, types::Fd};
use std::{
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tracing::warn;

/// Reserved `user_data` value for internal wake poll completions.
pub const WAKE_USER_DATA: UserData = UserData::MAX;

/// Bit used to mark that the loop is armed for sleep.
const SLEEP_INTENT_BIT: u64 = 1;
/// Packed-state increment for one submitted operation (bit 0 is reserved).
const SUBMISSION_INCREMENT: u64 = 2;
/// Sequence domain used by the packed submission counter (state >> 1).
pub const SUBMISSION_SEQ_MASK: u64 = u64::MAX >> 1;

/// Shared wake state used by submitters and the io_uring loop.
///
/// `state` packs two values:
/// - bit 0: sleep intent flag (`1` means the loop may block in `submit_and_wait`)
/// - bits 1..: submitted sequence (`submitted_seq`)
///
/// Submitters always increment `submitted_seq` after enqueueing onto the MPSC. The
/// loop tracks how many submissions it has drained from the MPSC (`processed_seq`,
/// stored in loop-local state). The loop may block only when:
/// - sleep intent is armed, and
/// - `submitted_seq == processed_seq`.
///
/// Blocking follows an arm-and-recheck protocol:
/// - The loop first verifies `submitted_seq == processed_seq`, then arms sleep intent.
/// - `arm()` returns a submission-sequence snapshot from the same atomic state transition.
/// - The loop blocks only if that post-arm snapshot still equals `processed_seq`.
/// - Submitters ring `eventfd` only when they observe sleep intent armed.
///
/// This makes submissions racing with the sleep transition observable either by
/// sequence mismatch in the loop or by an eventfd wakeup.
struct WakerInner {
    wake_fd: OwnedFd,
    state: AtomicU64,
}

/// Internal eventfd-backed wake source for the io_uring loop.
///
/// - Publish submissions from producers via [`Waker::publish`]
/// - Expose submitted sequence snapshots via [`Waker::submitted`]
/// - Coordinate sleep intent transitions via [`Waker::arm`] and [`Waker::disarm`]
/// - Drain `eventfd` readiness on wake CQEs via [`Waker::acknowledge`]
/// - Re-arm the multishot poll request when needed via [`Waker::reinstall`]
///
/// This type intentionally separates:
/// - sequence publication (`state` high bits)
/// - sleep gating (`state` bit 0)
/// - kernel readiness consumption (`eventfd` read path)
///
/// Keeping these concerns separate makes the wake protocol explicit and avoids
/// coupling correctness to exact eventfd coalescing behavior.
#[derive(Clone)]
pub struct Waker {
    inner: Arc<WakerInner>,
}

impl Waker {
    /// Create a non-blocking eventfd wake source.
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
                state: AtomicU64::new(0),
            }),
        })
    }

    /// Ring the eventfd doorbell.
    pub fn ring(&self) {
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

    /// Publish one submitted operation and optionally ring `eventfd`.
    ///
    /// Callers must invoke this only after successfully enqueueing work into
    /// the MPSC channel. That ordering guarantees that when the loop observes
    /// an updated sequence, there is corresponding work to drain.
    ///
    /// We ring `eventfd` only when sleep intent was armed in the previous
    /// state. This ensures submissions that race with the sleep transition
    /// are visible to the loop without requiring submitters to ring on every
    /// enqueue.
    pub fn publish(&self) {
        let prev = self
            .inner
            .state
            .fetch_add(SUBMISSION_INCREMENT, Ordering::Release);

        if (prev & SLEEP_INTENT_BIT) != 0 {
            self.ring();
        }
    }

    /// Return the current submitted sequence.
    ///
    /// The sequence domain is masked to 63 bits and compared against the
    /// loop-local `processed_seq` in the same domain.
    pub fn submitted(&self) -> u64 {
        (self.inner.state.load(Ordering::Acquire) >> 1) & SUBMISSION_SEQ_MASK
    }

    /// Arm sleep intent before attempting to block.
    ///
    /// After this point, any successful submission that races with sleep will
    /// observe sleep intent and ring eventfd.
    ///
    /// Returns the current submitted sequence snapshot from the same atomic
    /// operation that arms sleep intent. If this differs from loop-local
    /// `processed_seq`, the loop skips blocking and disarms immediately.
    pub fn arm(&self) -> u64 {
        let prev = self
            .inner
            .state
            .fetch_or(SLEEP_INTENT_BIT, Ordering::Acquire);
        (prev >> 1) & SUBMISSION_SEQ_MASK
    }

    /// Disarm sleep intent after we resume running.
    ///
    /// Keeping sleep intent clear while actively running avoids redundant
    /// eventfd writes during bursts. This is done both after a real wake and
    /// after a post-arm recheck decides not to block.
    pub fn disarm(&self) {
        self.inner
            .state
            .fetch_and(!SLEEP_INTENT_BIT, Ordering::Release);
    }

    /// Drain eventfd readiness acknowledged by a wake CQE.
    ///
    /// This acknowledges kernel-visible wake readiness. Sleep gating is tracked
    /// separately in the packed `state` atomic and is managed by
    /// [`Waker::arm`] / [`Waker::disarm`].
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

    /// Install the wake poll request into the SQ.
    ///
    /// This uses multishot poll and is called on startup and whenever a wake
    /// CQE indicates the previous multishot request is no longer active.
    pub fn reinstall(&self, submission_queue: &mut SubmissionQueue<'_>) {
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
mod tests {
    use super::*;
    use io_uring::IoUring;
    use std::os::fd::FromRawFd;

    #[test]
    fn test_publish_arm_disarm_and_submitted() {
        // Verify the packed wake state tracks submission sequence separately
        // from sleep intent across the normal publish and acknowledge flow.
        let waker = Waker::new().expect("eventfd creation should succeed");
        assert_eq!(waker.submitted(), 0);

        // Publish without sleep intent only advances sequence.
        waker.publish();
        assert_eq!(waker.submitted(), 1);

        // Arm and publish should trigger a ring; acknowledge drains it.
        let snapshot = waker.arm();
        assert_eq!(snapshot, 1);
        waker.publish();
        assert_eq!(waker.submitted(), 2);

        // Acknowledge/disarm are wake-gating operations and must not change
        // the submitted sequence domain.
        waker.acknowledge();
        assert_eq!(waker.submitted(), 2);
        waker.disarm();
        assert_eq!(waker.submitted(), 2);

        // Re-arming should observe the same submitted snapshot while idle.
        assert_eq!(waker.arm(), 2);
        waker.disarm();
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
        let after = waker.submitted();

        assert_eq!(after, before);
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
