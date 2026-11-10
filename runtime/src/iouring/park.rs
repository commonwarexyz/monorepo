//! Futex parking for io_uring workers.
//!
//! [`Parker::new`] creates the word with its only [`Parker`], which the worker
//! keeps to wait, and [`Parker::unparker`] hands out [`Unparker`]s, with which
//! other threads notify it. An unpark is what this module calls a
//! notification. [`Idle`](super::idle::Idle) selects which pool worker to
//! unpark. See [`super::idle`] for the parking sequence.
//!
//! The word holds a waiter bit and a sequence. A producer first makes its
//! condition visible (a mailbox message, a pool claim, or a driver permit
//! grant), then calls [`Unparker::unpark`], which advances the sequence. A
//! notification that finds the waiter bit set also clears it, and the one
//! whose clear takes the bit wakes the word, so concurrent notifications share
//! one wake. The worker never acknowledges a notification. Each turn it:
//! - loads the sequence with [`Parker::observe`] after its task polls and before
//!   checking any source of work,
//! - runs again if it found work, left a mailbox batch untaken, or the sequence
//!   moved since that load,
//! - arms with [`Parker::arm`], setting the waiter bit, and blocks only while the
//!   armed word still carries the observed sequence,
//! - disarms when the wait returns.
//!
//! A notification leaves no permit behind. One that precedes the observation
//! makes its condition visible to the checks that follow it. One that follows
//! changes the sequence before the arm, which then refuses to block, or comes
//! after the arm. It then finds the waiter bit, which it or another
//! notification clears before waking the word, or finds the bit already taken
//! by an earlier notification whose wake is still to come. A wait queued after
//! the arm first compares the word with the armed snapshot under the kernel's
//! futex lock, so a notification between the arm and that compare fails the
//! wait instead of being missed. A delayed wake syscall can also end a later
//! park, so every return leads back to the source checks.
//!
//! These checks compare sequences, so they could miss a notification only if
//! the 31-bit sequence wrapped all the way around between the observation and
//! the moment the kernel queues the wait. Each source can notify again only
//! after the worker acts. A mailbox notifies once per empty-to-nonempty
//! transition and keeps its batch until the worker takes it, at most once per
//! turn. A pool claim answers one idle publication, and the worker publishes
//! once per last look, which a turn repeats only after a search it started
//! there found the backlog gone. Permit grants coalesce in the driver's set of
//! permit futures, whose waker fires at most once per poll of that set. A
//! notification can also lag behind its condition, but only while its
//! producer thread is inside the call, one per thread. The interval therefore
//! holds a bounded handful of notifications per source and one per thread, far
//! fewer than a wrap needs.
//!
//! The worker waits on the word in two places: in the ring through a one-shot
//! `IORING_OP_FUTEX_WAIT` ([`ArmGuard::install`]) while it has unfinished
//! requests, and with a thread futex wait ([`Parker::park`]) when fully idle.
//! A ring wait remains live until its completion is reaped and can remain
//! queued after the park that installed it ends. Such a wait can absorb a wake
//! meant for the thread's idle wait, so a wake releases up to two waiters.
//!
//! A later ring park reuses a wait that is still queued. That wait's compare
//! belonged to the park that installed it, so the reusing park relies on its
//! arm alone: a notification before the arm fails the sequence check, and one
//! after it finds the waiter bit, or finds it already taken by an earlier
//! notification whose wake is still to come, so the queued wait is woken.
//!
//! The types bound who waits. A word has one [`Parker`], which is neither
//! [`Clone`] nor [`Sync`], so one thread at a time can arm it or wait on it, and a
//! ring wait can be installed only under a live [`ArmGuard`]. [`Unparker`]s can
//! only notify. The remaining half of the bound, at most one live ring wait,
//! rests on each worker owning one driver, which installs again only after
//! reaping its wait's completion.

use super::waiter::UserData;
use crossbeam_utils::CachePadded;
use std::{
    cell::Cell,
    marker::PhantomData,
    time::{Duration, Instant},
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicU32, Ordering},
        };
        use std::{collections::VecDeque, ops::Deref};
    } else {
        use io_uring::{opcode::FutexWait, squeue::SubmissionQueue};
        use std::sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        };
        use tracing::warn;
    }
}

/// Reserved `user_data` value for ring futex wait completions.
pub const RING_WAIT_USER_DATA: UserData = UserData::MAX;

/// Bit the worker's arm sets while it may block on the word. The disarm, or
/// the notification that wakes the word, clears it.
const WAITER: u32 = 1;
/// Word increment of one notification, above the waiter bit.
const INCREMENT: u32 = 2;
/// Waiters one wake releases: a ring wait an earlier park left queued, and the
/// wait of the worker's current park.
const WAKE_COUNT: u32 = 2;
/// futex2 flags of the ring wait: a private 32-bit word.
#[cfg(not(feature = "loom"))]
const FUTEX2_PRIVATE_U32: u32 = 0x02 | libc::FUTEX_PRIVATE_FLAG as u32;

/// RAII guard returned by [`Parker::arm`], which disarms the word on drop.
pub struct ArmGuard<'a> {
    /// Owner of the word to disarm when the guard is dropped.
    parker: &'a Parker,
    /// Whether the armed word still carries the observed sequence.
    still_idle: bool,
    /// Word produced by the arming transition.
    snapshot: u32,
}

impl ArmGuard<'_> {
    /// Return whether the armed word still carried the sequence the worker
    /// observed, so no notification arrived since and the worker may block.
    pub const fn still_idle(&self) -> bool {
        self.still_idle
    }

    /// Exact word after arming, which a new wait compares against.
    const fn snapshot(&self) -> u32 {
        self.snapshot
    }

    /// Queue a one-shot ring futex wait that compares against this guard's
    /// snapshot.
    ///
    /// Call it only when [`Self::still_idle`] permits blocking. The caller
    /// reserves the SQ slot before arming and installs again only after
    /// reaping this wait's completion, so the ring holds at most one live wait.
    /// The caller also keeps an [`Unparker`] of this word until the wait
    /// completes or is cancelled, so no wait stays queued at a freed word's
    /// address. A notification that changes the word before the kernel queues
    /// the wait completes it at once with `EAGAIN`.
    #[cfg(not(feature = "loom"))]
    pub fn install(&self, submission_queue: &mut SubmissionQueue<'_>) {
        assert!(
            self.still_idle,
            "a ring wait must be installed only under an arm that permits blocking"
        );
        let wait = FutexWait::new(
            self.parker.word.as_ptr(),
            self.snapshot.into(),
            u32::MAX.into(),
            FUTEX2_PRIVATE_U32,
        )
        .build()
        .user_data(RING_WAIT_USER_DATA);

        // SAFETY: The SQE carries only the word's address, and the kernel
        // reads the word only while the enter that submits it queues the
        // wait. The caller keeps an unparker of the word until the wait ends,
        // so the word outlives that enter. A queued wait never reads or writes
        // the word again, since wakes and cancellations find it through its
        // futex key and kernel-owned nodes.
        unsafe {
            submission_queue
                .push(&wait)
                .expect("reserved ring futex wait SQ slot");
        }
    }

    /// Model ring wait installation as a no-op.
    ///
    /// The loom tests in this module model a queued ring wait directly instead
    /// of through the `io_uring` submission queue. Keeping this method present
    /// lets the crate compile with `loom`.
    #[cfg(feature = "loom")]
    pub const fn install(&self, _submission_queue: &mut SubmissionQueue<'_>) {}
}

impl Drop for ArmGuard<'_> {
    fn drop(&mut self) {
        // The next observation acquires any notification, so disarming needs
        // no ordering of its own.
        self.parker.word.fetch_and(!WAITER, Ordering::Relaxed);
    }
}

/// The futex word shared by the worker and its producers: a waiter bit and a
/// notification sequence.
///
/// The handles share it padded to its own cache lines. Every notification
/// writes the word, and the worker loads it on every turn and spin iteration,
/// so a neighboring allocation, such as another worker's word or this
/// allocation's reference counts, would turn those writes into misses for
/// unrelated threads.
#[cfg(not(feature = "loom"))]
type Word = AtomicU32;

/// A wait queued on the word in the loom model of the kernel's futex queue.
#[cfg(feature = "loom")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Waiter {
    /// A ring wait, whose wake posts a completion that the driver reaps later.
    /// Only the persistent ring wait models queue one.
    #[cfg_attr(not(test), allow(dead_code))]
    Ring,
    /// A wait that blocks its caller until a wake releases it, identified by
    /// its ticket.
    Thread(u64),
}

/// The loom model of the kernel's futex queue for the word.
#[cfg(feature = "loom")]
struct FutexQueue {
    /// Queued waits, oldest first, the order in which a wake releases them.
    waiters: VecDeque<Waiter>,
    /// Ticket of the next blocking wait.
    next_ticket: u64,
    /// Whether a ring wait was released or refused and its completion waits
    /// for the driver to reap it.
    ring_completed: bool,
    /// Waits one wake releases. A negative control lowers it.
    wake_count: u32,
    /// Wake calls so far.
    #[cfg_attr(not(test), allow(dead_code))]
    wakes: u32,
    /// Whether every thread that could wake the word has finished, so a wait
    /// still queued is never released. A model sets it to fail a stranded wait
    /// directly, since loom cannot unwind a deadlocked model through the loom
    /// objects its threads hold.
    abandoned: bool,
}

/// The loom build's futex word, beside a model of the kernel's futex queue.
///
/// Loom cannot observe real futexes or io_uring CQEs, so this build replaces
/// the futex with a modeled wait queue under a mutex standing in for the
/// kernel's bucket lock, and a condvar on which modeled waits block. It models
/// the producer and worker atomic protocol, and releases waits oldest first,
/// not CQE delivery, `io_uring_enter`, or syscall errors. It dereferences
/// to its atomic, so the handles use it as the production word.
#[cfg(feature = "loom")]
struct Word {
    /// Waiter bit and notification sequence.
    state: AtomicU32,
    /// Modeled futex queue, under a mutex standing in for the bucket lock.
    futex: Mutex<FutexQueue>,
    /// Condvar on which modeled waits block until a wake releases them.
    futex_waiters: Condvar,
}

#[cfg(feature = "loom")]
impl Word {
    /// A word holding `state`, with an empty futex queue.
    fn new(state: u32) -> Self {
        Self {
            state: AtomicU32::new(state),
            futex: Mutex::new(FutexQueue {
                waiters: VecDeque::new(),
                next_ticket: 0,
                ring_completed: false,
                wake_count: WAKE_COUNT,
                wakes: 0,
                abandoned: false,
            }),
            futex_waiters: Condvar::new(),
        }
    }
}

#[cfg(feature = "loom")]
impl Deref for Word {
    type Target = AtomicU32;

    fn deref(&self) -> &AtomicU32 {
        &self.state
    }
}

/// The worker's handle on its word: the only one that can observe, arm, and
/// wait.
///
/// There is one per word, created by [`Parker::new`]. It is neither [`Clone`]
/// nor [`Sync`], so one thread at a time can wait on the word.
pub struct Parker {
    /// The word, shared with its unparkers.
    word: Arc<CachePadded<Word>>,
    /// Keeps the handle [`Send`] but not [`Sync`].
    _not_sync: PhantomData<Cell<()>>,
}

/// A handle that notifies the worker owning a word's [`Parker`].
#[derive(Clone)]
pub struct Unparker {
    /// The word, shared with its parker.
    word: Arc<CachePadded<Word>>,
}

impl std::task::Wake for Unparker {
    fn wake(self: std::sync::Arc<Self>) {
        self.unpark();
    }

    fn wake_by_ref(self: &std::sync::Arc<Self>) {
        self.unpark();
    }
}

impl Parker {
    /// Create a word with no notifications and return its only parker.
    pub fn new() -> Self {
        Self {
            word: Arc::new(CachePadded::new(Word::new(0))),
            _not_sync: PhantomData,
        }
    }

    /// Return a handle that notifies this parker's worker.
    pub fn unparker(&self) -> Unparker {
        Unparker {
            word: self.word.clone(),
        }
    }

    /// Load the sequence before checking the sources of work. The acquire
    /// load makes the conditions of every notification it includes visible.
    #[inline]
    pub fn observe(&self) -> u32 {
        self.word.load(Ordering::Acquire) & !WAITER
    }

    /// Whether a notification arrived since the worker observed `seen`.
    #[inline]
    pub fn moved(&self, seen: u32) -> bool {
        self.observe() != seen
    }

    /// Announce that the worker may block, comparing against `seen`.
    ///
    /// Call [`ArmGuard::still_idle`] to decide whether the worker may block. A
    /// notification since `seen` rejects sleeping and requires the worker to
    /// check its sources again.
    pub fn arm(&self, seen: u32) -> ArmGuard<'_> {
        // The word alone decides whether to block. Producers order their
        // conditions through the sequence, so arming needs no ordering.
        let prev = self.word.fetch_or(WAITER, Ordering::Relaxed);
        assert_eq!(prev & WAITER, 0, "iouring wait armed twice");

        ArmGuard {
            parker: self,
            still_idle: prev == seen,
            snapshot: prev | WAITER,
        }
    }

    /// Park while idle until a notification or the optional absolute deadline,
    /// comparing against the sequence observed as `seen`.
    ///
    /// Returns how long the thread blocked when a notification ended the wait,
    /// which feeds adaptive spinning. Returns `None` without blocking when a
    /// notification arrived since `seen` or the deadline has elapsed, and after
    /// an interruption or a timeout, so timer expiry does not count as a quick
    /// notification wake. The futex timeout is computed immediately before
    /// sleeping. Every return disarms the word, including skipped sleeps.
    pub fn park(&self, seen: u32, deadline: Option<Instant>) -> Option<Duration> {
        let arm = self.arm(seen);
        if !arm.still_idle() {
            return None;
        }

        let before = Instant::now();
        self.futex_wait(arm.snapshot(), deadline)
            .then(|| before.elapsed())
    }

    /// Sleep on the word for the fully idle path, returning whether a wake
    /// ended the sleep.
    ///
    /// `snapshot` must be the exact post-arm word from the atomic transition
    /// that set the waiter bit. `FUTEX_WAIT` blocks only while the word still
    /// equals it, which closes the race between arming and a concurrent
    /// notification. A stale snapshot, an elapsed deadline, `EINTR`, `EAGAIN`,
    /// `ETIMEDOUT`, and an unexpected error all return `false`, and the caller
    /// rechecks its sources with the deadline unchanged.
    #[cfg(not(feature = "loom"))]
    fn futex_wait(&self, snapshot: u32, deadline: Option<Instant>) -> bool {
        // This is only a same-word equality check before entering the
        // syscall. It relies only on modification order of this atomic, so
        // `Relaxed` is sufficient.
        if self.word.load(Ordering::Relaxed) != snapshot {
            return false;
        }

        let timeout = match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return false;
                }
                Some(libc::timespec {
                    tv_sec: remaining.as_secs().try_into().unwrap_or(libc::time_t::MAX),
                    tv_nsec: remaining.subsec_nanos().into(),
                })
            }
            None => None,
        };
        let timeout_ptr = timeout
            .as_ref()
            .map_or(std::ptr::null(), std::ptr::from_ref);

        // SAFETY: `word` retains the aligned atomic futex word throughout
        // this call. `timeout_ptr` is null or references the initialized
        // local timespec, which remains alive and unchanged until return.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_futex,
                self.word.as_ptr(),
                libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                snapshot,
                timeout_ptr,
            )
        };
        if ret == 0 {
            return true;
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR | libc::EAGAIN | libc::ETIMEDOUT) => false,
            _ => {
                // An unexpected futex wait error means the kernel
                // refused to block, so the safe fallback is to return to
                // userspace and re-check the word rather than panic.
                warn!("futex wait failed: {err}");
                false
            }
        }
    }

    /// Model `FUTEX_WAIT` on the futex word.
    ///
    /// The wait compares and queues under the modeled bucket lock, then blocks
    /// until a wake releases it, so loom can explore the same lost-wake
    /// boundary that the kernel's atomic futex wait protects in production.
    #[cfg(feature = "loom")]
    fn futex_wait(&self, snapshot: u32, deadline: Option<Instant>) -> bool {
        // Loom models notification races, not the kernel's timer queue. An
        // already due deadline exercises the no-sleep transition, and a deadline
        // still ahead is ignored, so the wait compares and queues as an untimed
        // wait does.
        if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            return false;
        }

        // The bucket lock orders this compare against every wake, as in the
        // kernel, so the load needs no ordering of its own.
        let mut queue = self.word.futex.lock().unwrap();
        if self.word.load(Ordering::Relaxed) != snapshot {
            return false;
        }

        let waiter = Waiter::Thread(queue.next_ticket);
        queue.next_ticket += 1;
        queue.waiters.push_back(waiter);
        while queue.waiters.contains(&waiter) {
            assert!(
                !queue.abandoned,
                "a futex wait was stranded with no waker left"
            );
            queue = self.word.futex_waiters.wait(queue).unwrap();
        }
        true
    }
}

impl Unparker {
    /// Advance the sequence, and wake the worker if it is armed and no other
    /// notification has woken it yet.
    ///
    /// The caller makes its condition visible first. The release pairs with
    /// [`Parker::observe`], so a worker that loads this notification's sequence
    /// sees the condition.
    ///
    /// Notifications that find the waiter bit share one wake: the one whose
    /// clear takes the bit issues it, and later ones of the same park skip it.
    /// So a notifier stalled between its clear and its wake syscall delays
    /// every later notification of that park until the scheduler runs it
    /// again, or until a completion or deadline ends the park.
    pub fn unpark(&self) {
        let prev = self.word.fetch_add(INCREMENT, Ordering::Release);

        // Every notification that finds the waiter bit tries to clear it, and
        // only the one that clears it wakes, so concurrent notifications share
        // one wake. A wait queued before the clear, including a ring wait an
        // earlier park left queued, is released by the wake that follows it. A
        // wait queued after the clear compares against the armed snapshot,
        // which still has the bit, so it fails at once. The clear needs no
        // ordering of its own: the increment already published the condition,
        // and a read-modify-write continues its release sequence.
        if prev & WAITER != 0 && self.word.fetch_and(!WAITER, Ordering::Relaxed) & WAITER != 0 {
            self.futex_wake();
        }
    }

    /// Whether this handle notifies the word of `parker`.
    pub fn unparks(&self, parker: &Parker) -> bool {
        Arc::ptr_eq(&self.word, &parker.word)
    }

    /// Wake the waiters on the futex word.
    ///
    /// A ring wait that an earlier park left queued can absorb a wake meant
    /// for the worker's current wait, so this releases up to two waiters. The
    /// word has one parker, whose worker owns one driver, which keeps at most
    /// one ring wait live.
    #[cfg(not(feature = "loom"))]
    fn futex_wake(&self) {
        loop {
            // SAFETY: `state` is a valid aligned futex word for the duration of
            // the syscall.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    self.word.as_ptr(),
                    libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                    WAKE_COUNT,
                )
            };
            if ret >= 0 {
                return;
            }

            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                _ => {
                    // FUTEX_WAKE fails only for invalid or inaccessible
                    // memory, invalid arguments, an unsupported op, or a PI
                    // waiter mismatch, none of which a private aligned
                    // in-process word can produce. An armed worker has already
                    // compared against the old word, so continuing without the
                    // wake could lose it for good. Panic instead of continuing.
                    panic!("futex wake failed: {err}");
                }
            }
        }
    }

    /// Model `FUTEX_WAKE` for the futex word.
    ///
    /// The modeled bucket lock serializes compare-and-queue against wake.
    /// Releasing the oldest waits first exercises a stale ring wait absorbing
    /// a wake before the thread wait. A released ring wait posts its completion.
    #[cfg(feature = "loom")]
    fn futex_wake(&self) {
        let mut queue = self.word.futex.lock().unwrap();
        queue.wakes += 1;
        for _ in 0..queue.wake_count {
            match queue.waiters.pop_front() {
                Some(Waiter::Ring) => queue.ring_completed = true,
                Some(Waiter::Thread(_)) => {}
                None => break,
            }
        }
        self.word.futex_waiters.notify_all();
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    /// Bound real-thread rendezvous and notification waits.
    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// Wait until the owner arms, failing by the deadline if it never parks.
    pub fn wait_until_armed(unparker: &Unparker, deadline: Instant) {
        while !waiting(unparker) {
            assert!(Instant::now() < deadline, "wait was not armed");
            std::thread::yield_now();
        }
    }

    /// Wait until the owner arms, failing by the test timeout if it never
    /// parks.
    fn wait_until_armed_by_timeout(unparker: &Unparker) {
        wait_until_armed(unparker, Instant::now() + TEST_TIMEOUT);
    }

    /// Whether the owner is armed to block on the word.
    pub fn waiting(unparker: &Unparker) -> bool {
        word(unparker) & WAITER != 0
    }

    /// Read the word without acquiring producer memory.
    fn word(unparker: &Unparker) -> u32 {
        unparker.word.load(Ordering::Relaxed)
    }

    /// Number of notifications since creation or the last [`reset`], modulo the
    /// sequence width.
    pub fn notifications(unparker: &Unparker) -> u32 {
        word(unparker) / INCREMENT
    }

    /// Forget an unarmed word's notifications, so a test can count new ones.
    pub fn reset(parker: &Parker) {
        assert_eq!(parker.word.load(Ordering::Relaxed) & WAITER, 0);
        parker.word.store(0, Ordering::Relaxed);
    }

    /// Restore the previous signal handler after the notifier has joined.
    struct RestoreSignal(
        /// The signal action to restore when the guard drops.
        libc::sigaction,
    );

    impl Drop for RestoreSignal {
        fn drop(&mut self) {
            // SAFETY: The saved action came from sigaction for this signal.
            // Its storage remains live while the kernel copies it, and the
            // notifier has been joined before the guard is normally dropped.
            unsafe {
                libc::sigaction(libc::SIGUSR2, &self.0, std::ptr::null_mut());
            }
        }
    }

    /// Interrupt a futex wait without changing any shared state.
    extern "C" fn interrupt_wait(_: libc::c_int) {}

    /// Neither an elapsed deadline nor a kernel timeout counts as a
    /// notification.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_timed_park_expiry_is_not_notification() {
        // Park against an elapsed deadline.
        let parker = Parker::new();
        let unparker = parker.unparker();
        let elapsed = Instant::now();
        assert!(parker.park(0, Some(elapsed)).is_none());
        assert_eq!(word(&unparker), 0);

        // A short deadline expires in the kernel, which is not a notification
        // either.
        let deadline = Instant::now() + Duration::from_millis(2);
        assert!(parker.park(0, Some(deadline)).is_none());
        assert!(Instant::now() >= deadline);
        assert_eq!(word(&unparker), 0);
    }

    /// A notification after arming races the kernel's compare-and-wait, and
    /// either way it ends a timed idle park before its deadline.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_timed_park_notification_race() {
        // Notify once the owner arms.
        let parker = Parker::new();
        let unparker = parker.unparker();
        let producer = std::thread::spawn({
            let unparker = unparker.clone();
            move || {
                wait_until_armed_by_timeout(&unparker);
                unparker.unpark();
            }
        });

        // The timed park returns well before its deadline.
        let deadline = Instant::now() + TEST_TIMEOUT;
        let _ = parker.park(0, Some(deadline));
        assert!(
            Instant::now() < deadline,
            "notification did not wake the idle worker"
        );
        producer.join().unwrap();

        // The notification advanced the sequence and the park disarmed.
        assert!(parker.moved(0));
        assert!(!waiting(&unparker));
    }

    /// A signal interrupts a timed idle park without counting as a
    /// notification, and the next park keeps the same absolute deadline.
    #[test]
    fn test_timed_park_interruption_preserves_absolute_deadline() {
        // Install a handler that only interrupts the wait.
        // SAFETY: sigaction consists of integer fields, pointers, and a signal
        // mask. Zero initialization supplies valid storage before its handler
        // and mask are initialized below, and `previous` is filled by the OS.
        let (mut action, mut previous): (libc::sigaction, libc::sigaction) =
            unsafe { std::mem::zeroed() };
        action.sa_sigaction = interrupt_wait as *const () as usize;
        // SAFETY: Both action structures are initialized stack storage retained
        // through the synchronous call. The handler performs no operations and
        // has the signal ABI, and sigemptyset receives its writable mask.
        unsafe {
            assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
            assert_eq!(libc::sigaction(libc::SIGUSR2, &action, &mut previous), 0);
        }
        let _restore = RestoreSignal(previous);

        // Signal this thread repeatedly once it arms, until it returns.
        // SAFETY: pthread_self returns the live identifier of this test thread,
        // which remains running until the notifier is joined.
        let target = unsafe { libc::pthread_self() };
        let parker = Parker::new();
        let unparker = parker.unparker();
        let done = Arc::new(AtomicBool::new(false));
        let notifier = std::thread::spawn({
            let unparker = unparker.clone();
            let done = done.clone();
            move || {
                while !waiting(&unparker) {
                    if done.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::yield_now();
                }
                while !done.load(Ordering::Acquire) {
                    // SAFETY: The parent thread owns this pthread identifier
                    // and joins us before exiting or restoring its handler.
                    unsafe {
                        libc::pthread_kill(target, libc::SIGUSR2);
                    }
                    std::thread::yield_now();
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        let first = parker.park(0, Some(deadline));
        let interrupted = Instant::now() < deadline;
        done.store(true, Ordering::Release);
        notifier.join().unwrap();

        // The signal ended the wait early without counting as a notification.
        assert!(
            interrupted,
            "signal must interrupt the wait before its deadline"
        );
        assert!(first.is_none());
        assert!(!waiting(&unparker));

        // Reuse the same deadline after EINTR. The next wait consumes only its
        // remaining interval and timeout still produces no spinner feedback.
        while Instant::now() < deadline {
            assert!(parker.park(0, Some(deadline)).is_none());
        }
        assert!(Instant::now() >= deadline);
        assert_eq!(word(&unparker), 0);
    }

    /// The word tracks the sequence separately from the waiter bit across
    /// notifications and arming.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_notify_arm_guard_and_sequence() {
        // A fresh word has no notifications.
        let parker = Parker::new();
        let unparker = parker.unparker();
        assert_eq!(notifications(&unparker), 0);

        // A notification without an armed wait only advances the sequence.
        unparker.unpark();
        assert_eq!(notifications(&unparker), 1);
        assert!(!waiting(&unparker));

        // A notification while armed advances the sequence and clears the
        // bit, since it is the one that wakes the word.
        let arm = parker.arm(parker.observe());
        assert!(arm.still_idle());
        unparker.unpark();
        assert_eq!(notifications(&unparker), 2);
        assert!(!waiting(&unparker));

        // A later notification finds the bit clear and leaves the waking to
        // the first.
        unparker.unpark();
        assert_eq!(notifications(&unparker), 3);
        assert!(!waiting(&unparker));

        // Guard drop disarms without changing the sequence.
        drop(arm);
        assert_eq!(notifications(&unparker), 3);
        assert!(!waiting(&unparker));

        // Re-arming against a fresh observation permits blocking.
        let arm = parker.arm(parker.observe());
        assert!(arm.still_idle());
        drop(arm);
    }

    /// `Parker::moved` reports a notification since an observation, including
    /// across the sequence's wrap through zero.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_moved_tracks_notifications_across_wrap() {
        for start in [0, u32::MAX - WAITER] {
            // Start the sequence at zero or at its last value.
            let parker = Parker::new();
            let unparker = parker.unparker();
            parker.word.store(start, Ordering::Relaxed);
            let seen = parker.observe();
            assert!(!parker.moved(seen));

            // A notification moves the word, even across the wrap.
            unparker.unpark();

            // The older observation sees the move and a fresh one does not.
            assert!(parker.moved(seen));
            assert!(!parker.moved(parker.observe()));
        }
    }

    /// A notification racing the idle park's equality check, futex syscall,
    /// and disarm always ends the park. The notifier waits until the waiter
    /// bit is visible, so each round stresses the real concurrent path rather
    /// than only the single-threaded stale snapshot.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_park_handles_concurrent_unpark_races() {
        for _ in 0..64 {
            // Notify once the owner arms.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let before = parker.observe();
            let notifier = std::thread::spawn({
                let unparker = unparker.clone();
                move || {
                    wait_until_armed_by_timeout(&unparker);
                    unparker.unpark();
                }
            });

            // The park returns well before its deadline.
            let deadline = Instant::now() + TEST_TIMEOUT;
            let _ = parker.park(before, Some(deadline));
            assert!(
                Instant::now() < deadline,
                "notification did not wake the idle worker"
            );
            notifier.join().expect("idle notifier thread panicked");

            // One notification arrived and the park disarmed.
            assert_eq!(notifications(&unparker), 1);
            assert!(!waiting(&unparker));
        }
    }

    /// A notification after the observation prevents the next idle park from
    /// sleeping.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_unpark_before_park_skips_sleep() {
        // Observe, then notify before the idle park arms.
        let parker = Parker::new();
        let unparker = parker.unparker();
        let seen = parker.observe();
        unparker.unpark();

        // The park against the older observation returns at once.
        assert!(parker.park(seen, None).is_none());

        // The notification was counted and the park disarmed.
        assert_eq!(notifications(&unparker), 1);
        assert!(!waiting(&unparker));
    }

    /// The idle path tolerates a notification that lands after the waiter bit
    /// is armed but before the armed thread commits to a futex wait on that
    /// snapshot.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_notify_after_arm_rejects_stale_snapshot() {
        // Split `Parker::park` into its arm and its wait, so the notification
        // lands exactly between them.
        let parker = Parker::new();
        let unparker = parker.unparker();
        let arm = parker.arm(parker.observe());
        assert!(arm.still_idle());
        unparker.unpark();

        // A wait on the stale snapshot returns at once instead of blocking,
        // through the userspace equality check or the futex EAGAIN path.
        assert!(!parker.futex_wait(arm.snapshot(), None));
        drop(arm);

        // The notification was counted and the guard disarmed.
        assert_eq!(notifications(&unparker), 1);
        assert!(!waiting(&unparker));
    }

    /// A notification before arming makes the arm refuse to block against the
    /// older sequence.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_arm_after_notify_skips_blocking() {
        // Notify before arming against the initial observation.
        let parker = Parker::new();
        let unparker = parker.unparker();
        unparker.unpark();

        // The arm notices the notification and refuses to block.
        let arm = parker.arm(0);
        assert!(!arm.still_idle());
        drop(arm);

        // The notification was counted and the guard disarmed.
        assert_eq!(notifications(&unparker), 1);
        assert!(!waiting(&unparker));
    }

    #[cfg(not(feature = "loom"))]
    pub mod native {
        use super::*;
        use io_uring::IoUring;
        use std::path::{Path, PathBuf};

        /// How long the idle wait must stay asleep after the single wake.
        const STRANDED: Duration = Duration::from_millis(200);

        /// Number of live handles on the word, which stays allocated while any
        /// remains.
        pub fn handles(parker: &Parker) -> usize {
            Arc::strong_count(&parker.word)
        }

        /// Build a ring with the driver's flags. With deferred task work, a ring
        /// wait's completion waits for the owner's next enter instead of
        /// interrupting the owner's thread futex wait, as in production.
        fn ring() -> IoUring {
            IoUring::builder()
                .setup_single_issuer()
                .setup_defer_taskrun()
                .build(8)
                .unwrap()
        }

        /// Queue a ring wait against the armed snapshot of a fresh observation,
        /// then disarm, leaving the wait queued as a park that ends without its
        /// completion does.
        fn queue_ring_wait(parker: &Parker, ring: &mut IoUring) {
            let arm = parker.arm(parker.observe());
            assert!(arm.still_idle());
            arm.install(&mut ring.submission());
            ring.submit().unwrap();
            drop(arm);

            // A wait whose compare failed would have completed during the submit.
            assert!(ring.completion().is_empty());
        }

        /// Wake up to `count` waiters on the word directly, returning how many woke.
        pub fn wake(unparker: &Unparker, count: u32) -> libc::c_long {
            // SAFETY: `unparker` retains the aligned atomic word for the call.
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    unparker.word.as_ptr(),
                    libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                    count,
                )
            }
        }

        /// The procfs directory of the calling thread.
        fn current_task() -> PathBuf {
            Path::new("/proc").join(std::fs::read_link("/proc/thread-self").unwrap())
        }

        /// Whether the thread at `task` sleeps in a futex call on the word.
        ///
        /// The kernel reports another thread's syscall only once that thread is
        /// descheduled in a sleep, which a futex wait reaches only after it queued
        /// itself.
        fn sleeps_on_word(unparker: &Unparker, task: &Path) -> bool {
            let report = std::fs::read_to_string(task.join("syscall")).expect(
                "reading another thread's syscall file needs this process to be dumpable, since procfs gives a non-dumpable process's files to root",
            );
            let mut fields = report.split_whitespace();
            let number = fields.next().and_then(|field| field.parse().ok());
            let address = fields
                .next()
                .and_then(|field| field.strip_prefix("0x"))
                .and_then(|field| usize::from_str_radix(field, 16).ok());
            number == Some(libc::SYS_futex) && address == Some(unparker.word.as_ptr() as usize)
        }

        /// Wait until the thread at `task` sleeps in a futex call on the word,
        /// failing by the test timeout.
        fn wait_until_sleeping_on_word(unparker: &Unparker, task: &Path) {
            let deadline = Instant::now() + TEST_TIMEOUT;
            while !sleeps_on_word(unparker, task) {
                assert!(
                    Instant::now() < deadline,
                    "the owner never slept on the word"
                );
                std::thread::yield_now();
            }
        }

        /// A notification between the arm and the kernel's compare fails the new
        /// ring wait at once, so the enter that follows does not block.
        #[test]
        fn test_ring_wait_rejects_a_wake_before_enter() {
            // Arm against a fresh observation.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let mut ring = ring();
            let seen = parker.observe();
            let arm = parker.arm(seen);
            assert!(arm.still_idle());

            // Notify before the wait reaches the kernel, then submit it.
            unparker.unpark();
            arm.install(&mut ring.submission());
            ring.submit_and_wait(1).unwrap();

            // The kernel's compare failed, so the wait completed with EAGAIN.
            let cqe = ring.completion().next().unwrap();
            assert_eq!(cqe.user_data(), RING_WAIT_USER_DATA);
            assert_eq!(cqe.result(), -libc::EAGAIN);
            assert!(!io_uring::cqueue::more(cqe.flags()));
            drop(arm);
            assert!(parker.moved(seen));
        }

        /// A notification before the arm refuses the wait without a syscall, and
        /// one after the arm reaches a ring wait that an earlier park left queued,
        /// which the next park reuses without installing another.
        #[test]
        fn test_reused_ring_wait_receives_a_later_wake() {
            // A park installs its wait, and an unrelated completion ends the park
            // with the wait still queued.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let mut ring = ring();
            let seen = parker.observe();
            queue_ring_wait(&parker, &mut ring);

            // A notification while running only advances the sequence, so the
            // next arm against the older observation is refused.
            unparker.unpark();
            assert!(!parker.arm(seen).still_idle());

            // A fresh observation arms, and a producer finds the waiter bit and
            // wakes the queued wait while the owner waits in the ring.
            let seen = parker.observe();
            let arm = parker.arm(seen);
            assert!(arm.still_idle());
            let producer = std::thread::spawn(move || unparker.unpark());
            ring.submit_and_wait(1).unwrap();
            producer.join().unwrap();

            // The queued wait's completion ended this park.
            let cqe = ring.completion().next().unwrap();
            assert_eq!(cqe.user_data(), RING_WAIT_USER_DATA);
            assert_eq!(cqe.result(), 0);
            drop(arm);
            assert!(parker.moved(seen));
        }

        /// A ring wait that an earlier park left queued sits ahead of the owner's
        /// idle wait, and one notification releases both.
        #[test]
        fn test_stale_ring_wait_cannot_absorb_idle_wake() {
            // Leave a ring wait queued, as a park that ended without its
            // completion does.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let mut ring = ring();
            queue_ring_wait(&parker, &mut ring);

            // Park idle, and notify once the owner sleeps behind the ring wait.
            let owner = current_task();
            let producer = std::thread::spawn(move || {
                wait_until_sleeping_on_word(&unparker, &owner);
                unparker.unpark();
            });
            let deadline = Instant::now() + TEST_TIMEOUT;
            let woken = parker.park(0, Some(deadline));
            producer.join().unwrap();

            // The notification released the idle wait and the ring wait alike.
            assert!(woken.is_some(), "stale ring wait absorbed the idle wake");
            ring.submit_and_wait(1).unwrap();
            let cqe = ring.completion().next().unwrap();
            assert_eq!(cqe.user_data(), RING_WAIT_USER_DATA);
            assert_eq!(cqe.result(), 0);
        }

        /// Waking one waiter releases only the ring wait queued ahead of the
        /// owner's idle wait, which stays asleep. This is why a notification wakes
        /// two, and it shows the test above would catch a notification that woke
        /// one.
        #[test]
        fn test_waking_one_strands_idle_wait_behind_stale_ring_wait() {
            // Leave a ring wait queued, as a park that ended without its
            // completion does.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let mut ring = ring();
            queue_ring_wait(&parker, &mut ring);

            // Park idle. Once the owner sleeps behind the ring wait, wake one
            // waiter, check that the owner still sleeps, then release it with a
            // notification.
            let owner = current_task();
            let returned = Arc::new(AtomicBool::new(false));
            let producer = std::thread::spawn({
                let returned = returned.clone();
                move || {
                    wait_until_sleeping_on_word(&unparker, &owner);
                    let woken = wake(&unparker, 1);
                    std::thread::sleep(STRANDED);
                    let stranded =
                        !returned.load(Ordering::Acquire) && sleeps_on_word(&unparker, &owner);
                    unparker.unpark();
                    (woken, stranded)
                }
            });
            let deadline = Instant::now() + TEST_TIMEOUT;
            let released = parker.park(0, Some(deadline));
            returned.store(true, Ordering::Release);
            let (woken, stranded) = producer.join().unwrap();

            // The single wake took the ring wait and left the idle wait asleep
            // until the notification.
            assert_eq!(woken, 1);
            assert!(stranded, "a single wake reached the idle wait");
            assert!(released.is_some());
            ring.submit_and_wait(1).unwrap();
            let cqe = ring.completion().next().unwrap();
            assert_eq!(cqe.user_data(), RING_WAIT_USER_DATA);
            assert_eq!(cqe.result(), 0);
        }
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::{
        tests::{notifications, waiting},
        *,
    };
    use crate::iouring::{
        mailbox::{Cancel, Mailbox, Message},
        slab::Id,
        waiter::WaiterId,
    };
    use loom::{
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
        thread,
    };
    use rstest::rstest;
    use std::mem;

    /// Operations in each enumerated producer program.
    const PROGRAM_OPS: u32 = 3;

    /// Preemptions explored by the models in which several notifications race
    /// the worker. Each notification that finds the waiter bit takes two
    /// read-modify-writes of the word, and exploring every interleaving of
    /// those does not finish in minutes.
    const PREEMPTIONS: usize = 8;

    /// Explore `model` with preemptions bounded at [`PREEMPTIONS`].
    fn check_bounded(model: impl Fn() + Sync + Send + 'static) {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(PREEMPTIONS);
        builder.check(model);
    }

    /// Block in a modeled ring futex wait installed against `guard`'s snapshot.
    ///
    /// The kernel compares the word with the snapshot and queues the wait under
    /// the futex bucket lock, as for a thread wait, and the park blocks until a
    /// wake of that wait posts its completion. A fresh ring wait therefore
    /// behaves as a blocking wait.
    fn ring_wait(parker: &Parker, guard: &ArmGuard<'_>) {
        let _ = parker.futex_wait(guard.snapshot(), None);
    }

    /// Arm against `seen` and block in a new ring wait if that is still idle.
    fn ring_park(parker: &Parker, seen: u32) {
        let guard = parker.arm(seen);
        if guard.still_idle() {
            ring_wait(parker, &guard);
        }
    }

    /// Park on the idle path against `seen`.
    fn idle_park(parker: &Parker, seen: u32) {
        let _ = parker.park(seen, None);
    }

    /// The driver's record of its ring wait in the persistent ring models.
    #[derive(Default)]
    struct Ring {
        /// Whether a ring wait was installed and its completion is not yet
        /// reaped, the inverse of the driver's `ring_wait_needed` flag.
        live: bool,
    }

    /// Queue a modeled ring wait that compares against `snapshot`, as the
    /// kernel does when the enter after [`ArmGuard::install`] submits it.
    fn install_ring_wait(parker: &Parker, snapshot: u32) {
        let mut queue = parker.word.futex.lock().unwrap();
        assert!(
            !queue.ring_completed && !queue.waiters.contains(&Waiter::Ring),
            "a second ring wait installed while one is live"
        );

        // A changed word fails the compare, which completes the wait at once.
        if parker.word.load(Ordering::Relaxed) == snapshot {
            queue.waiters.push_back(Waiter::Ring);
        } else {
            queue.ring_completed = true;
        }
    }

    /// Park in the ring against `seen` as the driver does, with a ring wait
    /// that stays queued across parks until a wake completes it.
    ///
    /// The park arms and installs a wait unless one is live. With `block`, its
    /// enter returns once a ring wait completion is posted. Without it, the
    /// enter returns at once, as a deadline or an unrelated completion ends a
    /// park. The park then reaps a posted completion, so the next park
    /// installs a new wait, and otherwise leaves the live wait for the next
    /// park to reuse.
    fn persistent_ring_park(parker: &Parker, ring: &mut Ring, seen: u32, block: bool) {
        let guard = parker.arm(seen);
        if guard.still_idle() {
            if !ring.live {
                install_ring_wait(parker, guard.snapshot());
                ring.live = true;
            }
            if block {
                let mut queue = parker.word.futex.lock().unwrap();
                while !queue.ring_completed {
                    queue = parker.word.futex_waiters.wait(queue).unwrap();
                }
            }
        }
        drop(guard);

        // Service reaps the completion after the park, which ends the wait.
        if mem::take(&mut parker.word.futex.lock().unwrap().ring_completed) {
            ring.live = false;
        }
    }

    /// Leave a ring wait queued, as a park that ended without its completion
    /// does, before any producer runs.
    fn queued_ring_wait(parker: &Parker) -> Ring {
        let mut ring = Ring::default();
        persistent_ring_park(parker, &mut ring, parker.observe(), false);
        assert!(ring.live);
        ring
    }

    /// Simulate the worker until `source` reaches `target`: observe, check the
    /// source with a relaxed load, and park through `park` against the
    /// observation when the source is still below the target.
    ///
    /// The load is relaxed, as is the store in [`publish`], so only the
    /// eventcount's release and acquire edges can make a condition visible.
    fn simulate_until(
        parker: &Parker,
        source: &AtomicU32,
        target: u32,
        mut park: impl FnMut(&Parker, u32),
    ) {
        loop {
            let seen = parker.observe();
            if source.load(Ordering::Relaxed) >= target {
                assert_eq!(parker.word.load(Ordering::Relaxed) & WAITER, 0);
                return;
            }
            park(parker, seen);
        }
    }

    /// Make one condition visible with a relaxed store, then notify, so only
    /// the notification's release can publish the condition.
    fn publish(unparker: &Unparker, source: &AtomicU32) {
        source.fetch_add(1, Ordering::Relaxed);
        unparker.unpark();
    }

    /// A message identified by `index`, with no payload to release.
    const fn message(index: u32) -> Message {
        Message::Cancel(Cancel::Waiter(WaiterId(Id {
            index,
            generation: 0,
        })))
    }

    /// The index of a message built by [`message`].
    fn index(message: Message) -> u32 {
        match message {
            Message::Cancel(Cancel::Waiter(WaiterId(id))) => id.index,
            _ => panic!("not a modeled message"),
        }
    }

    /// Record that the calling producer, the last thread able to wake the
    /// word, has finished, so a wait still queued fails the model.
    fn abandon(unparker: &Unparker) {
        let mut queue = unparker.word.futex.lock().unwrap();
        queue.abandoned = true;
        unparker.word.futex_waiters.notify_all();
    }

    /// Run a worker that parks idle behind a stale ring wait while a producer
    /// publishes one condition, with wakes that release `wake_count` waits. An
    /// idle wait that the producer's wake missed fails the model once the
    /// producer finishes.
    fn idle_wait_behind_stale_ring_wait(wake_count: u32) {
        loom::model(move || {
            // Leave a ring wait queued ahead of every idle wait.
            let parker = Parker::new();
            let unparker = parker.unparker();
            parker.word.futex.lock().unwrap().wake_count = wake_count;
            let _ring = queued_ring_wait(&parker);
            let source = Arc::new(AtomicU32::new(0));

            // The worker parks idle until it sees the producer's condition.
            let producer = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || {
                    publish(&unparker, &source);
                    abandon(&unparker);
                }
            });
            simulate_until(&parker, &source, 1, idle_park);
            producer.join().unwrap();

            // The worker saw the condition and disarmed.
            assert_eq!(notifications(&unparker), 1);
            assert!(!waiting(&unparker));
        });
    }

    /// Producer operation of the enumerated programs.
    ///
    /// Each program is built before entering `loom::model`, then run by a
    /// producer thread. `Publish` makes a condition visible before notifying,
    /// as a mailbox message does, while `Notify` carries no condition the
    /// modeled worker counts, as a pool claim does.
    #[derive(Clone, Copy, Debug)]
    enum ProducerOp {
        /// Make one condition visible, then notify.
        Publish,
        /// Notify without a counted condition.
        Notify,
    }

    impl ProducerOp {
        /// The program of [`PROGRAM_OPS`] operations whose operation `i`
        /// publishes when bit `i` of `bits` is set and only notifies
        /// otherwise.
        fn program(bits: u8) -> Vec<Self> {
            (0..PROGRAM_OPS)
                .map(|i| {
                    if (bits >> i) & 1 == 1 {
                        Self::Publish
                    } else {
                        Self::Notify
                    }
                })
                .collect()
        }

        /// Execute one producer operation.
        fn execute(self, unparker: &Unparker, source: &AtomicU32) {
            match self {
                Self::Publish => publish(unparker, source),
                Self::Notify => unparker.unpark(),
            }
        }
    }

    /// How the modeled worker of a program parks.
    #[derive(Clone, Copy, Debug)]
    enum ParkPath {
        /// A thread futex wait per park, which a ring park that installs a
        /// fresh wait matches step for step in this model.
        Idle,
        /// A ring wait queued before the producer starts and reused across
        /// parks until a wake completes it, as the driver keeps it.
        ReusedRing,
    }

    /// Explore the producer program `bits` (see [`ProducerOp::program`])
    /// alongside one modeled worker that parks through `path` until it has
    /// observed every notification of the program, so a notification without
    /// a condition must end a park too. Each observation must make the
    /// conditions of the notifications it includes visible to a relaxed load,
    /// so only the eventcount's release and acquire edges can publish them.
    fn worker_program(bits: u8, path: ParkPath) {
        let program = ProducerOp::program(bits);

        check_bounded(move || {
            // Run the program on a producer thread, with a ring wait already
            // queued on the reused ring path.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let mut ring = match path {
                ParkPath::Idle => None,
                ParkPath::ReusedRing => Some(queued_ring_wait(&parker)),
            };
            let source = Arc::new(AtomicU32::new(0));
            let producer = thread::spawn({
                let program = program.clone();
                let unparker = unparker.clone();
                let source = source.clone();
                move || {
                    for &op in program.iter() {
                        op.execute(&unparker, &source);
                    }
                }
            });

            // The worker parks until it has observed every notification. The
            // producer notifies in program order, so the number of
            // notifications an observation includes says which conditions it
            // must make visible.
            loop {
                let seen = parker.observe();
                let observed = (seen / INCREMENT) as usize;
                let published = program[..observed]
                    .iter()
                    .filter(|op| matches!(op, ProducerOp::Publish))
                    .count() as u32;
                assert!(
                    source.load(Ordering::Relaxed) >= published,
                    "an observed condition was not visible: program={program:?} path={path:?}",
                );
                if observed == program.len() {
                    break;
                }
                match &mut ring {
                    None => idle_park(&parker, seen),
                    Some(ring) => persistent_ring_park(&parker, ring, seen, true),
                }
            }
            producer.join().unwrap();

            // Every operation notified once and the worker disarmed.
            assert_eq!(
                notifications(&unparker),
                PROGRAM_OPS,
                "notification conservation failed: program={program:?} path={path:?}",
            );
            assert!(
                !waiting(&unparker),
                "wait remained armed: program={program:?} path={path:?}",
            );
        });
    }

    /// Run a worker shaped like the drive loop while a producer sends one
    /// message behind a batch of two. Each turn observes, takes only into an
    /// empty scratch while its parker reports mail, applies one message, its
    /// bounded share, and decides in that same turn whether to park. With
    /// `check_mail` the decision reads the mail flag, as the drive loop does.
    /// Without it, the turn that empties the scratch parks on the word alone.
    fn batch_started_during_partial_drain(check_mail: bool) {
        loom::model(move || {
            // The inbox holds a batch of two before the producer starts.
            let parker = Parker::new();
            let mailbox = Arc::new(Mailbox::new(parker.unparker()));
            assert!(mailbox.send(message(0)).is_ok());
            assert!(mailbox.send(message(1)).is_ok());

            // The producer's message starts a second batch if the worker took
            // the first one before it. The producer is the last thread able
            // to wake the word, so a wait still queued once it finishes fails
            // the model.
            let producer = thread::spawn({
                let mailbox = mailbox.clone();
                move || {
                    assert!(mailbox.send(message(2)).is_ok());
                    abandon(&mailbox.unparker);
                }
            });

            // The worker runs turns until it has applied all three, and stops
            // before the park decision of the turn that applies the last one.
            let mut received = Vec::new();
            let mut scratch = Vec::new();
            loop {
                let seen = parker.observe();
                if scratch.is_empty() && mailbox.has_mail() {
                    assert!(mailbox.take(&mut scratch));
                }
                if !scratch.is_empty() {
                    received.push(index(scratch.remove(0)));
                }
                if received.len() == 3 {
                    break;
                }

                // The park decision of the same turn. The take above was
                // skipped if the turn began with a message left in the scratch.
                if !scratch.is_empty() || (check_mail && mailbox.has_mail()) || parker.moved(seen) {
                    continue;
                }
                idle_park(&parker, seen);
            }
            producer.join().unwrap();

            // Every message arrived in order and the flag is clear.
            assert_eq!(received, [0, 1, 2]);
            assert!(!mailbox.has_mail());
            assert!(!waiting(&mailbox.unparker));
        });
    }

    /// The mailbox notifies once per batch, after unlocking, and a pool claim
    /// moves the word without mail. A producer can be delayed between
    /// unlocking and notifying while the worker takes, applies its scratch one
    /// message per turn, and parks once the scratch is empty. The worker
    /// observes, then takes only while its parker reports mail, as the run
    /// loop does, so the claim costs no take and no batch is missed. This
    /// models userspace ownership and waking, not kernel CQE delivery.
    #[test]
    fn test_batch_notification_and_take_gate() {
        check_bounded(|| {
            // A producer sends two messages around a claim notification.
            let parker = Parker::new();
            let mailbox = Arc::new(Mailbox::new(parker.unparker()));
            let producer = thread::spawn({
                let mailbox = mailbox.clone();
                move || {
                    assert!(mailbox.send(message(1)).is_ok());
                    mailbox.unparker.unpark();
                    assert!(mailbox.send(message(2)).is_ok());
                }
            });

            // The worker takes through the mail flag and parks in the ring
            // until it has applied both. A set flag always finds a batch.
            let mut received = Vec::new();
            let mut scratch = Vec::new();
            while received.len() < 2 {
                let seen = parker.observe();
                if scratch.is_empty() && mailbox.has_mail() {
                    assert!(mailbox.take(&mut scratch));
                }
                if scratch.is_empty() {
                    ring_park(&parker, seen);
                } else {
                    received.push(index(scratch.remove(0)));
                }
            }
            producer.join().unwrap();

            // Both messages arrived in order, the claim and one or two batches
            // notified, and the flag is clear.
            assert_eq!(received, [1, 2]);
            assert!((2..=3).contains(&notifications(&mailbox.unparker)));
            assert!(!mailbox.has_mail());
            assert!(!waiting(&mailbox.unparker));
        });
    }

    /// A batch that starts while the worker still applies an earlier one
    /// notifies before the observation of the turn that empties the scratch.
    /// That turn skipped its take, so it reads the mail flag before it parks
    /// and no batch stays in the mailbox of a parked worker.
    #[test]
    fn test_batch_started_during_partial_drain_is_taken_before_park() {
        batch_started_during_partial_drain(true);
    }

    /// Negative control: a park decision on the word alone strands that batch,
    /// since no later send to its mailbox notifies.
    #[test]
    #[should_panic(expected = "a futex wait was stranded with no waker left")]
    fn test_parking_on_the_word_alone_strands_a_batch_started_during_partial_drain() {
        batch_started_during_partial_drain(false);
    }

    /// Closure transfers shared ownership while one already taken batch still
    /// has local messages. A send and its delayed notification may race that
    /// transfer, but no accepted or rejected message is lost, and closing
    /// leaves the mail flag clear.
    #[test]
    fn test_batch_close_with_retained_scratch_and_delayed_notification() {
        loom::model(|| {
            // The worker took a batch of two and applied one, then armed.
            let parker = Parker::new();
            let mailbox = Arc::new(Mailbox::new(parker.unparker()));
            assert!(mailbox.send(message(0)).is_ok());
            assert!(mailbox.send(message(1)).is_ok());
            let mut scratch = Vec::new();
            assert!(mailbox.has_mail());
            assert!(mailbox.take(&mut scratch));
            let first = scratch.remove(0);
            let arm = parker.arm(parker.observe());

            // A producer sends while the worker closes the mailbox twice, as
            // the worker's close and its cleanup do.
            let producer = thread::spawn({
                let mailbox = mailbox.clone();
                move || mailbox.send(message(2)).err().map(index)
            });
            let mut detached = mailbox.close();
            assert!(mailbox.close().is_empty());
            drop(arm);
            let rejected = producer.join().unwrap();

            // Every message is accounted for exactly once, and a send that
            // closing rejected left no mail behind.
            assert_eq!(
                notifications(&mailbox.unparker),
                1 + u32::from(rejected.is_none())
            );
            assert!(!mailbox.has_mail());
            detached.push(first);
            detached.append(&mut scratch);
            let mut indices = detached.into_iter().map(index).collect::<Vec<_>>();
            indices.extend(rejected);
            indices.sort_unstable();
            assert_eq!(indices, [0, 1, 2]);
            assert!(!waiting(&mailbox.unparker));
        });
    }

    /// An already due absolute deadline stands in for the kernel's elapsed
    /// timeout, and a racing notification across the same arm and disarm
    /// transition still moves the word. Real tests cover syscall timeout
    /// delivery, which this userspace model does not simulate.
    #[test]
    fn test_timed_futex_expiry_races_notification() {
        loom::model(|| {
            // A producer notifies once.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let deadline = Instant::now();
            let producer = thread::spawn({
                let unparker = unparker.clone();
                move || unparker.unpark()
            });

            // The expired park returns without counting as a notification.
            assert!(parker.park(0, Some(deadline)).is_none());
            producer.join().unwrap();

            // The notification still moved the word.
            assert!(parker.moved(0));
            assert_eq!(notifications(&unparker), 1);
            assert!(!waiting(&unparker));
        });
    }

    /// `Unparker::unpark` must make the producer's earlier condition visible to
    /// a worker that observes the advanced sequence. The worker spins on
    /// `moved()` before joining the producer, so the only intended
    /// synchronization is the notification's release and the observation's
    /// acquire.
    #[test]
    fn test_notify_observe_pairing() {
        loom::model(|| {
            // A producer stores a condition and notifies.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let source = Arc::new(AtomicU32::new(0));
            let producer = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || {
                    source.store(42, Ordering::Relaxed);
                    unparker.unpark();
                }
            });

            // The worker waits for the word to move.
            while !parker.moved(0) {
                thread::yield_now();
            }

            // The condition is visible once the word moved.
            assert_eq!(source.load(Ordering::Relaxed), 42);
            producer.join().unwrap();
            assert_eq!(notifications(&unparker), 1);
        });
    }

    /// When a producer notifies an armed word, the worker resumes from its ring
    /// wait. Its next observation must acquire the producer's condition before
    /// it checks the source.
    #[test]
    fn test_notify_wakes_armed_ring_wait() {
        loom::model(|| {
            // The worker arms against a fresh observation.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let source = Arc::new(AtomicU32::new(0));
            let seen = parker.observe();
            let guard = parker.arm(seen);
            assert!(guard.still_idle());

            // A producer publishes while the worker waits in the ring.
            let producer = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || {
                    source.store(42, Ordering::Relaxed);
                    unparker.unpark();
                }
            });
            ring_wait(&parker, &guard);
            drop(guard);

            // The resumed worker sees the moved word and the condition.
            assert!(parker.moved(seen));
            assert_eq!(source.load(Ordering::Relaxed), 42);
            producer.join().unwrap();
            assert!(!waiting(&unparker));
        });
    }

    /// The fully idle path arms a futex wait on the same word that producers
    /// update. A racing notification must either change the post-arm snapshot
    /// before sleep or wake the modeled futex waiter.
    #[test]
    fn test_arm_and_recheck_futex_race() {
        loom::model(|| {
            // A producer publishes one condition.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let source = Arc::new(AtomicU32::new(0));
            let producer = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || publish(&unparker, &source)
            });

            // The worker parks idle until it sees the condition.
            simulate_until(&parker, &source, 1, idle_park);
            producer.join().unwrap();

            // One notification arrived.
            assert_eq!(notifications(&unparker), 1);
        });
    }

    /// Two notifications racing against the same armed word both advance the
    /// sequence, and only the one that clears the waiter bit wakes the word, so
    /// they share one wake and a futex wait on the armed snapshot returns at
    /// once.
    #[test]
    fn test_concurrent_notifications_reject_armed_snapshot() {
        loom::model(|| {
            // The worker arms against a fresh observation.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let guard = parker.arm(parker.observe());
            assert!(guard.still_idle());

            // Two producers notify concurrently.
            let a = thread::spawn({
                let unparker = unparker.clone();
                move || unparker.unpark()
            });
            let b = thread::spawn({
                let unparker = unparker.clone();
                move || unparker.unpark()
            });
            a.join().unwrap();
            b.join().unwrap();

            // Both counted, one of them cleared the bit and woke the word, and
            // the stale snapshot does not block.
            assert_eq!(notifications(&unparker), 2);
            assert!(!waiting(&unparker));
            assert_eq!(parker.word.futex.lock().unwrap().wakes, 1);
            assert!(!parker.futex_wait(guard.snapshot(), None));
            drop(guard);
            assert!(!waiting(&unparker));
        });
    }

    /// Notifications must remain observable across the sequence's wrap through
    /// zero.
    #[test]
    fn test_sequence_wraparound() {
        loom::model(|| {
            // Start the sequence at its last value.
            let parker = Parker::new();
            let unparker = parker.unparker();
            parker.word.store(u32::MAX - WAITER, Ordering::Relaxed);
            let source = Arc::new(AtomicU32::new(0));

            // A producer publishes twice, wrapping the sequence.
            let producer = thread::spawn({
                let source = source.clone();
                move || {
                    publish(&unparker, &source);
                    publish(&unparker, &source);
                }
            });
            simulate_until(&parker, &source, 2, ring_park);
            producer.join().unwrap();

            // The worker saw both and the sequence wrapped.
            assert_eq!(parker.observe(), INCREMENT);
        });
    }

    /// The fully idle futex path must also handle a notification without a
    /// counted condition. The worker either sees the changed sequence before
    /// sleeping or is resumed by the modeled futex wake.
    #[test]
    fn test_park_with_concurrent_unpark() {
        loom::model(|| {
            // A producer notifies without a condition.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let notifier = thread::spawn({
                let unparker = unparker.clone();
                move || unparker.unpark()
            });

            // The worker parks idle against the initial observation.
            idle_park(&parker, 0);
            notifier.join().unwrap();

            // The park ended and disarmed.
            assert_eq!(notifications(&unparker), 1);
            assert!(!waiting(&unparker));
        });
    }

    /// Repeated fully idle futex park cycles must continue to see conditions.
    #[test]
    fn test_multiple_park_cycles() {
        loom::model(|| {
            // A producer publishes twice.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let source = Arc::new(AtomicU32::new(0));
            let producer = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || {
                    publish(&unparker, &source);
                    publish(&unparker, &source);
                }
            });

            // The worker parks idle until it sees both.
            simulate_until(&parker, &source, 2, idle_park);
            producer.join().unwrap();

            // Both notifications arrived.
            assert_eq!(notifications(&unparker), 2);
        });
    }

    /// Two producers notifying concurrently with one worker should still
    /// preserve conservation and progress.
    #[test]
    fn test_three_thread_stress() {
        // Exploring every interleaving of three threads does not finish in
        // minutes, so preemptions are bounded at five, which finishes in
        // seconds.
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(5);
        builder.check(|| {
            // Two producers publish once each.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let source = Arc::new(AtomicU32::new(0));
            let a = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || publish(&unparker, &source)
            });
            let b = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || publish(&unparker, &source)
            });

            // The worker parks in the ring until it sees both.
            simulate_until(&parker, &source, 2, ring_park);
            a.join().unwrap();
            b.join().unwrap();

            // Both notifications arrived.
            assert_eq!(notifications(&unparker), 2);
        });
    }

    /// A ring wait that an earlier park left queued stays live across parks. A
    /// later park reuses it instead of installing another, so only the arm's
    /// recheck guards notifications since the worker observed, and a
    /// notification while armed must still reach the reused wait.
    #[test]
    fn test_reused_ring_wait_receives_a_later_notification() {
        loom::model(|| {
            // Leave a ring wait queued before the producer starts.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let mut ring = queued_ring_wait(&parker);
            let source = Arc::new(AtomicU32::new(0));

            // A producer publishes twice while the worker parks in the ring.
            let producer = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || {
                    publish(&unparker, &source);
                    publish(&unparker, &source);
                }
            });
            simulate_until(&parker, &source, 2, |parker, seen| {
                persistent_ring_park(parker, &mut ring, seen, true);
            });
            producer.join().unwrap();

            // The worker saw both conditions and disarmed.
            assert_eq!(notifications(&unparker), 2);
            assert!(!waiting(&unparker));
        });
    }

    /// A stale ring wait sits ahead of the worker's idle wait. The notification
    /// releases two waits, so it reaches the idle wait.
    #[test]
    fn test_idle_wait_behind_stale_ring_wait_is_woken() {
        idle_wait_behind_stale_ring_wait(WAKE_COUNT);
    }

    /// Negative control: a wake that releases one wait spends it on the stale
    /// ring wait, so loom finds the idle wait stranded.
    #[test]
    #[should_panic(expected = "a futex wait was stranded with no waker left")]
    fn test_waking_one_strands_idle_wait_behind_stale_ring_wait() {
        idle_wait_behind_stale_ring_wait(1);
    }

    /// A ring wait left queued sits ahead of idle waits, and a wake that
    /// releases an idle wait completes the ring wait as well. A ring park that
    /// follows finds that completion still unreaped, returns at once, and the
    /// park after it installs a new wait.
    #[test]
    fn test_stale_ring_wait_across_idle_and_ring_parks() {
        check_bounded(|| {
            // Leave a ring wait queued before the producer starts.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let mut ring = queued_ring_wait(&parker);
            let source = Arc::new(AtomicU32::new(0));

            // A producer publishes twice. The worker parks idle until the
            // first condition, then in the ring until the second.
            let producer = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || {
                    publish(&unparker, &source);
                    publish(&unparker, &source);
                }
            });
            simulate_until(&parker, &source, 1, idle_park);
            simulate_until(&parker, &source, 2, |parker, seen| {
                persistent_ring_park(parker, &mut ring, seen, true);
            });
            producer.join().unwrap();

            // The worker saw both conditions and disarmed.
            assert_eq!(notifications(&unparker), 2);
            assert!(!waiting(&unparker));
        });
    }

    /// Every program of three producer operations, each a published condition
    /// or a notification without one, alongside a worker that parks idle until
    /// it has observed every notification. A ring park that installs a fresh
    /// wait takes the same steps in this model, so these programs cover it too.
    /// Each case models one program, so nextest can run them in parallel.
    #[rstest]
    fn test_worker_programs_on_idle_park(#[values(0, 1, 2, 3, 4, 5, 6, 7)] program: u8) {
        worker_program(program, ParkPath::Idle);
    }

    /// Every program of three producer operations alongside a worker that
    /// parks in the ring on a wait queued before the producer starts, reusing
    /// it across parks until a wake completes it. Only the arm's recheck guards
    /// a reused wait, and a wake that completes it posts a completion that the
    /// next park reaps before it installs another.
    #[rstest]
    fn test_worker_programs_on_reused_ring_wait(#[values(0, 1, 2, 3, 4, 5, 6, 7)] program: u8) {
        worker_program(program, ParkPath::ReusedRing);
    }

    /// Two producers notify concurrently while the worker parks in the ring on
    /// a wait queued before they start. Whichever producer clears the waiter
    /// bit wakes the reused wait, which compares nothing, so the other skipping
    /// its wake must not strand the worker.
    #[test]
    fn test_concurrent_publishers_wake_a_reused_ring_wait() {
        // As in `test_three_thread_stress`, preemptions are bounded at five.
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(5);
        builder.check(|| {
            // Leave a ring wait queued, then two producers publish once each.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let mut ring = queued_ring_wait(&parker);
            let source = Arc::new(AtomicU32::new(0));
            let a = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || publish(&unparker, &source)
            });
            let b = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || publish(&unparker, &source)
            });

            // The worker parks in the ring until it sees both.
            simulate_until(&parker, &source, 2, |parker, seen| {
                persistent_ring_park(parker, &mut ring, seen, true);
            });
            a.join().unwrap();
            b.join().unwrap();

            // Both notifications arrived and the worker disarmed.
            assert_eq!(notifications(&unparker), 2);
            assert!(!waiting(&unparker));
        });
    }

    /// The worker's first park reuses a ring wait queued before two producers
    /// start and ends without a wake, as an unrelated completion ends a park.
    /// A producer that found the first park's waiter bit can then clear the
    /// bit of the next park late, and the other producer, finding it already
    /// taken, skips its wake. The late clear's wake must still release the
    /// reused wait.
    #[test]
    fn test_late_clear_on_a_reused_ring_wait_covers_a_skipped_wake() {
        // As in `test_three_thread_stress`, preemptions are bounded at five.
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(5);
        builder.check(|| {
            // Leave a ring wait queued, then two producers publish once each.
            let parker = Parker::new();
            let unparker = parker.unparker();
            let mut ring = queued_ring_wait(&parker);
            let source = Arc::new(AtomicU32::new(0));
            let a = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || publish(&unparker, &source)
            });
            let b = thread::spawn({
                let unparker = unparker.clone();
                let source = source.clone();
                move || publish(&unparker, &source)
            });

            // The first park returns without blocking, and the later ones
            // block until a wake completes the ring wait.
            let mut first = true;
            simulate_until(&parker, &source, 2, |parker, seen| {
                let block = !mem::take(&mut first);
                persistent_ring_park(parker, &mut ring, seen, block);
            });
            a.join().unwrap();
            b.join().unwrap();

            // Both notifications arrived and the worker disarmed.
            assert_eq!(notifications(&unparker), 2);
            assert!(!waiting(&unparker));
        });
    }
}
