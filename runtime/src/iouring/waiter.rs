//! Request ownership, completion results, and identity for one worker's ring.
//!
//! A registration keeps one ID while queued, in flight, and awaiting result
//! consumption. A pending entry owns the request and its observer. Terminal
//! completion replaces it with a retained result for an ordinary future, or
//! recycles the slot for detached and orphaned requests.
//!
//! Unfinished requests and outstanding operation SQEs are counted separately.
//! Retained results contribute to neither count, so a slow observer cannot hold
//! staging capacity. Driver queues and deadlines must also reject these results
//! even though their IDs still resolve in the slab.
//!
//! Wakers, detached publications, and owners ready for destruction are handed
//! to [`Deferred`]. The worker invokes callbacks after releasing its local borrow.

use super::{
    UserData,
    request::{Request, RequestOutput},
    runtime::Deferred,
    slab::{Id, Slab},
    timeout::Tick,
};
use crate::Error;
use commonware_utils::channel::oneshot;
use io_uring::squeue::Entry as SqueueEntry;
use std::{mem, task::Waker, time::Instant};
use tracing::warn;

/// Full-width identity for a tracked request.
///
/// Userspace queues retain the slab's full generation. Kernel `user_data` packs
/// a 32-bit index, the low 31 generation bits, and a cancellation tag in bit 63.
/// A staged operation's CQE must arrive before its waiter can be recycled.
/// Cancellation CQEs may arrive after reuse, so completion lookup also checks
/// the packed generation. The kernel generation wraps after 2^31 slot reuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaiterId(
    /// Slab index and full generation retained by userspace handles and queues.
    pub Id,
);

impl WaiterId {
    /// Low bits encode the slot index.
    const INDEX_MASK: UserData = u32::MAX as UserData;
    /// Generation bits available below the cancellation tag.
    const GENERATION_MASK: UserData = (1 << 31) - 1;
    /// Distinguishes cancellation CQEs from operation CQEs.
    const CANCEL_TAG: UserData = 1 << 63;

    /// Encode the kernel identity, retaining the full generation in userspace.
    pub const fn user_data(self) -> UserData {
        ((self.0.generation & Self::GENERATION_MASK) << 32) | self.0.index as UserData
    }

    /// Encode a cancellation targeting this operation's kernel identity.
    pub const fn cancel_user_data(self) -> UserData {
        self.user_data() | Self::CANCEL_TAG
    }

    /// Decode the slot index, truncated generation, and cancellation tag.
    const fn from_user_data(user_data: UserData) -> (usize, u64, bool) {
        (
            (user_data & Self::INDEX_MASK) as usize,
            (user_data >> 32) & Self::GENERATION_MASK,
            user_data & Self::CANCEL_TAG != 0,
        )
    }
}

/// Deadline and cancellation state of an unfinished request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaiterState {
    /// Queued or in-flight request for which cancellation has not been requested.
    Active {
        /// Absolute wheel tick by which the request must complete.
        ///
        /// If completion has not been observed by this tick, cancellation is
        /// requested. `None` means no wheel deadline has been installed yet,
        /// including requests that have no timeout.
        target_tick: Option<Tick>,
    },
    /// Cancellation was requested.
    ///
    /// The driver completes queued requests locally and schedules async cancel
    /// for in-flight requests. In-flight resources stay owned until the operation CQE.
    CancelRequested,
}

/// Destination of a logical request's terminal output.
pub(super) enum Observer {
    /// Ordinary future whose result stays in the slot until consumed or dropped.
    ///
    /// The waker is absent until the future first installs one.
    /// Completion retains the result even if it races that installation.
    Ordinary(Option<Waker>),
    /// Independent sync completion sender, used outside the worker borrow.
    DetachedSync(oneshot::Sender<Result<(), Error>>),
    /// No caller remains, so terminal output is deferred for destruction.
    Orphaned,
}

/// State retained until a logical request reaches terminal completion.
struct Waiter {
    /// Deadline and cancellation state.
    state: WaiterState,
    /// Whether an operation SQE was staged without its CQE being consumed.
    in_flight: bool,
    /// Result destination and any waker awaiting terminal completion.
    observer: Observer,
    /// Buffer owners, descriptors, and operation progress.
    request: Request,
}

/// One identity retained from registration through result consumption.
#[allow(clippy::large_enum_variant)]
enum Entry {
    /// Queued or in-flight request that still owns its kernel resources.
    Pending(Waiter),
    /// Ordinary result retained under the same ID until consumption or drop.
    Ready(RequestOutput),
    /// Temporary replacement while [`Waiters::finish`] splits owned state.
    ///
    /// Before returning, finish replaces this with Ready or removes the slot.
    Retiring,
}

/// Action required after applying one CQE.
pub enum CompletionOutcome {
    /// Cancellation acknowledgement, including one for an already retired request.
    Cancel,
    /// Partial progress or retry requires another SQE for the same request.
    Requeue(WaiterId),
    /// Terminal status the driver must pass to [`Waiters::finish`] for this ID.
    Complete(WaiterId, Result<(), Error>),
}

/// Result of inspecting an ordinary future without cloning its waker.
pub(super) enum Observation {
    /// Output removed from the slab, with its slot already recycled.
    Ready(RequestOutput),
    /// Request is unfinished and its installed waker already matches the caller.
    Pending,
    /// The caller must clone its waker outside the worker borrow, then recheck.
    Refresh,
}

/// Request ownership and retained results for one worker.
pub struct Waiters {
    /// Pending requests and retained ordinary results sharing one identity space.
    entries: Slab<Entry>,
    /// Unfinished logical requests, excluding retained results.
    pending: usize,
    /// Staged operation SQEs whose CQEs have not been consumed.
    in_flight: usize,
}

impl Waiters {
    /// Preallocate storage without imposing a request limit.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Slab::with_capacity(capacity),
            pending: 0,
            in_flight: 0,
        }
    }

    /// Number of unfinished logical requests, excluding retained results.
    pub const fn len(&self) -> usize {
        self.pending
    }

    /// Whether all logical requests have finished, regardless of result consumption.
    pub const fn is_empty(&self) -> bool {
        self.pending == 0
    }

    /// Number of staged operation SQEs whose CQEs have not been consumed.
    ///
    /// Cancellation SQEs and completed results do not contribute to this count.
    pub const fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Register an owned request before kernel submission.
    ///
    /// `target_tick` identifies a deadline already tracked by the driver, or is
    /// absent until the driver installs one. The slot remains occupied through
    /// ordinary result consumption, even after the request finishes.
    pub fn insert(
        &mut self,
        request: Request,
        target_tick: Option<Tick>,
        observer: Observer,
    ) -> WaiterId {
        let id = self.entries.insert_with(|id| {
            // Reserve the maximum index so cancellation IDs cannot alias the
            // all-ones mailbox wake token, even when kernel generations wrap.
            assert!(id.index < u32::MAX as usize, "waiter slot index overflow");
            Entry::Pending(Waiter {
                state: WaiterState::Active { target_tick },
                in_flight: false,
                observer,
                request,
            })
        });
        self.pending += 1;
        WaiterId(id)
    }

    /// Borrow an unfinished request, rejecting stale IDs and retained results.
    fn get(&self, id: WaiterId) -> Option<&Waiter> {
        match self.entries.get(id.0)? {
            Entry::Pending(waiter) => Some(waiter),
            _ => None,
        }
    }

    /// Mutably borrow an unfinished request, rejecting stale IDs and retained results.
    fn get_mut(&mut self, id: WaiterId) -> Option<&mut Waiter> {
        match self.entries.get_mut(id.0)? {
            Entry::Pending(waiter) => Some(waiter),
            _ => None,
        }
    }

    /// Reject both stale identities and entries retaining a completed result.
    pub fn is_pending(&self, id: WaiterId) -> bool {
        self.get(id).is_some()
    }

    /// Original absolute deadline of an unfinished request, if it has one.
    ///
    /// Stale IDs and retained results return `None`. Cancellation does not
    /// erase this deadline. Use [`Self::target_tick`] for active wheel tracking.
    pub fn deadline(&self, id: WaiterId) -> Option<Instant> {
        self.get(id).and_then(|waiter| waiter.request.deadline())
    }

    /// Deadline that still contributes to the wheel's active counts.
    ///
    /// Returns `None` before scheduling, after cancellation or completion, and
    /// for stale IDs. The driver removes the previous tick when cancelling.
    pub fn target_tick(&self, id: WaiterId) -> Option<Tick> {
        match self.get(id)?.state {
            WaiterState::Active { target_tick } => target_tick,
            WaiterState::CancelRequested => None,
        }
    }

    /// Record the tick after the driver schedules this request on its wheel.
    ///
    /// Panics unless the request is pending, active, and has no installed tick.
    pub fn set_deadline(&mut self, id: WaiterId, tick: Tick) {
        let waiter = self.get_mut(id).expect("deadline waiter missing");
        let WaiterState::Active { target_tick } = &mut waiter.state else {
            panic!("deadline installed on cancelled waiter");
        };
        assert!(
            target_tick.replace(tick).is_none(),
            "deadline installed twice"
        );
    }

    /// Inspect or consume a result without running observer callbacks.
    ///
    /// A ready result is removed and its slot recycled. An unfinished request
    /// remains in place, returning whether its waker needs refreshing. Panics
    /// if the ID no longer belongs to an ordinary observer.
    pub(super) fn observe(&mut self, id: WaiterId, waker: &Waker) -> Observation {
        match self.entries.get(id.0).expect("live observer missing") {
            Entry::Ready(_) => {
                let Some(Entry::Ready(output)) = self.entries.remove(id.0) else {
                    unreachable!()
                };
                Observation::Ready(output)
            }
            Entry::Pending(waiter) => {
                let Observer::Ordinary(current) = &waiter.observer else {
                    panic!("request has no ordinary observer");
                };
                if current
                    .as_ref()
                    .is_some_and(|current| current.will_wake(waker))
                {
                    Observation::Pending
                } else {
                    Observation::Refresh
                }
            }
            Entry::Retiring => unreachable!(),
        }
    }

    /// Install a waker already cloned outside the worker borrow.
    ///
    /// Returns the previous waker for deferred destruction. The caller must
    /// recheck [`Self::observe`] after cloning, since cloning can reenter and
    /// finish the request. Panics unless a pending ordinary observer remains.
    pub(super) fn set_waker(&mut self, id: WaiterId, waker: Waker) -> Option<Waker> {
        let waiter = self.get_mut(id).expect("observer waiter missing");
        let Observer::Ordinary(current) = &mut waiter.observer else {
            panic!("request has no ordinary observer");
        };
        current.replace(waker)
    }

    /// Detach ordinary observation, returning whether cancellation is needed.
    ///
    /// Pending writes and syncs keep running without their observer. Other
    /// newly orphaned requests return `true` so the driver can cancel them.
    /// A retained result is removed and deferred for destruction. Stale IDs,
    /// detached syncs, and already orphaned requests are left alone.
    pub(super) fn orphan(&mut self, id: WaiterId, deferred: &mut Deferred) -> bool {
        match self.entries.get_mut(id.0) {
            Some(Entry::Pending(waiter)) => {
                if !matches!(waiter.observer, Observer::Ordinary(_)) {
                    return false;
                }
                let Observer::Ordinary(waker) =
                    mem::replace(&mut waiter.observer, Observer::Orphaned)
                else {
                    unreachable!()
                };
                deferred.drops.extend(waker);
                !waiter.request.retains_on_orphan()
            }
            Some(Entry::Ready(_)) => {
                let Some(Entry::Ready(output)) = self.entries.remove(id.0) else {
                    unreachable!()
                };
                deferred.outputs.push(output);
                false
            }
            None => false,
            Some(Entry::Retiring) => unreachable!(),
        }
    }

    /// Remove ordinary observers and results, returning pending cancellation IDs.
    ///
    /// Writes and syncs remain owned until they finish. Detached sync senders
    /// stay installed. Removed wakers and results go to deferred destruction.
    pub(super) fn close(&mut self, deferred: &mut Deferred) -> Vec<WaiterId> {
        let mut cancel = Vec::new();
        for index in 0..self.entries.slots() {
            if let Some(id) = self.entries.id_at(index) {
                let id = WaiterId(id);
                if self.orphan(id, deferred) {
                    cancel.push(id);
                }
            }
        }
        cancel
    }

    /// Request cancellation without ending an outstanding kernel access interval.
    ///
    /// Returns `true` only when it first records a cancellation request.
    /// The driver must remove the old wheel tick and arrange local completion
    /// or a cancellation SQE. Stale IDs and completed results return `false`.
    pub fn cancel(&mut self, id: WaiterId) -> bool {
        let Some(waiter) = self.get_mut(id) else {
            return false;
        };
        match waiter.state {
            WaiterState::Active { .. } => {
                waiter.state = WaiterState::CancelRequested;
                true
            }
            WaiterState::CancelRequested => false,
        }
    }

    /// Split terminal ownership and retain an ordinary result in the same slot.
    ///
    /// `result` is the terminal CQE status or an explicit local failure.
    /// Ordinary output replaces the pending request. Detached and orphaned
    /// output leaves the slab, freeing its slot immediately.
    ///
    /// Returns any active tick the driver must remove from the wheel. Waking,
    /// detached publication, and resource destruction are deferred. Panics if
    /// the request is missing, already completed, or still has an SQE in flight.
    pub(super) fn finish(
        &mut self,
        id: WaiterId,
        result: Result<(), Error>,
        deferred: &mut Deferred,
    ) -> Option<Tick> {
        assert!(
            !self.get(id).expect("finished waiter missing").in_flight,
            "cannot finish kernel-visible request"
        );
        let entry = self.entries.get_mut(id.0).unwrap();
        let Entry::Pending(waiter) = mem::replace(entry, Entry::Retiring) else {
            unreachable!()
        };
        self.pending -= 1;
        let tick = match waiter.state {
            WaiterState::Active { target_tick } => target_tick,
            WaiterState::CancelRequested => None,
        };
        let (output, resources) = waiter.request.complete(result);
        deferred.resources.push(resources);
        match waiter.observer {
            Observer::Ordinary(waker) => {
                *entry = Entry::Ready(output);
                deferred.wakes.extend(waker);
            }
            Observer::DetachedSync(sender) => {
                let RequestOutput::Sync(output) = output else {
                    panic!("sync observer received other request");
                };
                self.entries.remove(id.0);
                deferred.sync_results.push((sender, output));
            }
            Observer::Orphaned => {
                self.entries.remove(id.0);
                deferred.outputs.push(output);
            }
        }
        tick
    }

    /// Build the next SQE without moving the request out of its slot.
    ///
    /// Marks the request in flight before returning the SQE. The driver retires
    /// cancelled requests before staging or at their operation CQE.
    /// Panics if the ID is not pending, is cancelled, or already has an SQE in flight.
    pub fn stage(&mut self, id: WaiterId) -> SqueueEntry {
        let waiter = self.get_mut(id).expect("stage called for untracked waiter");
        assert!(
            !waiter.in_flight,
            "stage called for waiter with op already in flight"
        );
        assert!(
            matches!(waiter.state, WaiterState::Active { .. }),
            "stage called for cancelled waiter"
        );
        // Construction can reject an invalid buffer range. Until it
        // succeeds, cleanup must remain able to finish the request locally.
        let sqe = waiter.request.build_sqe(id);
        waiter.in_flight = true;
        self.in_flight += 1;
        sqe
    }

    /// Apply an operation CQE or acknowledge a cancellation CQE.
    ///
    /// An operation CQE releases its in-flight count and updates progress in
    /// place. The driver then requeues or finishes the request. Cancellation
    /// acknowledgements leave request ownership and retained results untouched.
    /// Missing or stale operation identities are invariant failures, while late
    /// cancellation acknowledgements are accepted after completion or reuse.
    pub fn on_completion(&mut self, user_data: UserData, result: i32) -> CompletionOutcome {
        let (index, generation, is_cancel) = WaiterId::from_user_data(user_data);
        let Some(id) = self
            .entries
            .id_at(index)
            .filter(|id| id.generation & WaiterId::GENERATION_MASK == generation)
        else {
            assert!(is_cancel, "operation CQE for missing or stale waiter");
            return CompletionOutcome::Cancel;
        };
        let id = WaiterId(id);
        // A cancel acknowledgement may outlive the operation or its observer.
        // It never changes a retained result or releases operation capacity.
        if is_cancel {
            if !self.is_pending(id) {
                return CompletionOutcome::Cancel;
            }
            match result {
                0 => {}
                result if result == -libc::EALREADY || result == -libc::ENOENT => {}
                result if result == -libc::EINVAL => {
                    panic!("async cancel SQE rejected by kernel: EINVAL")
                }
                _ => warn!(result, "unexpected async cancel CQE result"),
            }
            return CompletionOutcome::Cancel;
        }
        let waiter = self
            .get_mut(id)
            .expect("operation CQE for completed waiter");
        assert!(waiter.in_flight);
        waiter.in_flight = false;
        let outcome = match waiter.request.on_cqe(waiter.state, result) {
            Some(result) => CompletionOutcome::Complete(id, result),
            None if matches!(waiter.observer, Observer::Orphaned)
                && !waiter.request.retains_on_orphan() =>
            {
                // An abandoned read or network request needs no follow-up SQE.
                // Its output is discarded, but its owners still retire normally.
                CompletionOutcome::Complete(id, Err(Error::Closed))
            }
            None => CompletionOutcome::Requeue(id),
        };
        self.in_flight -= 1;
        outcome
    }

    /// Whether this request has a staged operation whose CQE is still owed.
    ///
    /// Returns `false` for stale IDs and retained results.
    pub fn is_in_flight(&self, id: WaiterId) -> bool {
        self.get(id).is_some_and(|waiter| waiter.in_flight)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        IoBuf, IoBufMut, IoBufs,
        iouring::{
            request::{Cache, Held, ReadAtRequest, RecvRequest, SendRequest, SyncRequest},
            slab::tests::set_generation,
        },
        storage::hold::Hold,
    };
    use std::{
        fs::File,
        os::{fd::OwnedFd, unix::net::UnixStream},
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc, OnceLock,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
    };

    /// Build a full waiter identity without registering a request.
    pub fn waiter_id(index: u32, generation: u64) -> WaiterId {
        WaiterId(Id {
            index: index as usize,
            generation,
        })
    }

    /// Share one directory hold across the simulated file requests in this process.
    fn held(file: File) -> Arc<Held> {
        static HOLD: OnceLock<Arc<Hold>> = OnceLock::new();
        let hold = HOLD.get_or_init(|| {
            Hold::acquire(
                &std::env::temp_dir()
                    .join(format!("commonware_waiter_test_{}", std::process::id())),
            )
            .unwrap()
        });
        Held::new(file, hold.clone())
    }

    /// Build a descriptor-owning request for simulated sync completions.
    fn make_sync_request() -> Request {
        let (socket, _peer) = UnixStream::pair().unwrap();
        Request::Sync(SyncRequest {
            file: held(File::from(OwnedFd::from(socket))),
        })
    }

    /// Build a cancellable send, recv, or file-read request for lifecycle tests.
    fn read_request(kind: usize) -> Request {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let fd = OwnedFd::from(socket);
        match kind {
            0 => Request::Send(SendRequest {
                fd: Arc::new(fd),
                write: IoBufs::from(IoBuf::from(b"hello")).into(),
                deadline: None,
            }),
            1 => Request::Recv(RecvRequest {
                fd: Arc::new(fd),
                buf: IoBufMut::with_capacity(5),
                offset: 0,
                len: 5,
                exact: true,
                deadline: None,
            }),
            2 => Request::ReadAt(ReadAtRequest {
                file: held(File::from(fd)),
                offset: 0,
                len: 5,
                read: 0,
                buf: IoBufMut::with_capacity(5),
                cache: Cache::Enabled,
            }),
            _ => unreachable!(),
        }
    }

    /// Ordinary observation before the future installs its first waker.
    fn observer() -> Observer {
        Observer::Ordinary(None)
    }

    /// Apply a terminal simulated CQE and finish its request.
    fn complete(
        waiters: &mut Waiters,
        id: WaiterId,
        result: i32,
        deferred: &mut Deferred,
    ) -> Option<Tick> {
        let CompletionOutcome::Complete(current, result) =
            waiters.on_completion(id.user_data(), result)
        else {
            panic!("expected terminal completion");
        };
        assert_eq!(current, id);
        waiters.finish(id, result, deferred)
    }

    /// Consume an ordinary result, failing if the request is still pending.
    fn output(waiters: &mut Waiters, id: WaiterId) -> RequestOutput {
        let Observation::Ready(output) = waiters.observe(id, Waker::noop()) else {
            panic!("expected retained output");
        };
        output
    }

    /// Counts deferred wake invocations without touching worker state.
    #[derive(Default)]
    struct Counter(AtomicUsize);

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_waiter_id_encoding_preserves_full_generation() {
        let id = waiter_id(7, (1 << 31) + 3);
        assert_eq!(id.0.generation, (1 << 31) + 3);
        assert_eq!(WaiterId::from_user_data(id.user_data()), (7, 3, false));
        assert_eq!(
            WaiterId::from_user_data(id.cancel_user_data()),
            (7, 3, true)
        );
    }

    #[test]
    fn test_cqe_resolves_full_generation_after_kernel_wrap() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let id = waiters.insert(make_sync_request(), None, observer());
        let last = WaiterId(set_generation(
            &mut waiters.entries,
            id.0,
            WaiterId::GENERATION_MASK,
        ));
        waiters.finish(last, Err(Error::Closed), &mut deferred);
        drop(output(&mut waiters, last));
        let current = waiters.insert(make_sync_request(), None, observer());
        assert_eq!(current.0.generation, 1 << 31);

        // Packed generations wrap while all userspace queues keep the full ID.
        assert_eq!(current.user_data(), id.user_data());
        assert!(!waiters.is_pending(id));
        assert!(!waiters.cancel(id));
        waiters.stage(current);
        assert!(matches!(
            waiters.on_completion(last.cancel_user_data(), 0),
            CompletionOutcome::Cancel
        ));
        assert_eq!(waiters.in_flight(), 1);
        assert!(
            matches!(waiters.on_completion(current.user_data(), -libc::EINTR), CompletionOutcome::Requeue(id) if id == current)
        );
        assert_eq!(waiters.in_flight(), 0);

        waiters.stage(current);
        complete(&mut waiters, current, 0, &mut deferred);
        assert!(waiters.is_empty());
        assert!(matches!(
            output(&mut waiters, current),
            RequestOutput::Sync(Ok(()))
        ));
    }

    #[test]
    fn test_retained_result_does_not_count_as_pending_or_recycle_early() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        assert!(waiters.is_empty());
        let first = waiters.insert(make_sync_request(), Some(5), observer());
        assert_eq!(waiters.len(), 1);
        waiters.stage(first);
        assert_eq!(complete(&mut waiters, first, 0, &mut deferred), Some(5));

        // The live result keeps its ID but must disappear from all I/O queries.
        assert!(waiters.is_empty());
        assert!(!waiters.is_pending(first));
        assert!(!waiters.is_in_flight(first));
        assert_eq!(waiters.target_tick(first), None);
        assert_eq!(waiters.deadline(first), None);
        assert!(!waiters.cancel(first));
        assert!(catch_unwind(AssertUnwindSafe(|| waiters.stage(first))).is_err());
        assert!(
            catch_unwind(AssertUnwindSafe(
                || waiters.on_completion(first.user_data(), 0)
            ))
            .is_err()
        );

        let second = waiters.insert(make_sync_request(), None, observer());
        assert_ne!(first.0.index, second.0.index);
        assert!(matches!(
            output(&mut waiters, first),
            RequestOutput::Sync(Ok(()))
        ));
        let reused = waiters.insert(make_sync_request(), None, observer());
        assert_eq!(reused.0.index, first.0.index);
        assert_ne!(reused, first);
        assert!(!waiters.orphan(first, &mut deferred));
        assert!(waiters.is_pending(reused));
    }

    #[test]
    fn test_exhausted_generation_retires_slot_after_result_consumption() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let id = waiters.insert(make_sync_request(), None, observer());
        let exhausted = WaiterId(set_generation(&mut waiters.entries, id.0, u64::MAX));
        waiters.stage(exhausted);
        complete(&mut waiters, exhausted, 0, &mut deferred);
        drop(output(&mut waiters, exhausted));
        let next = waiters.insert(make_sync_request(), None, observer());
        assert_ne!(next.0.index, exhausted.0.index);
        assert_eq!(waiters.in_flight(), 0);
    }

    #[test]
    fn test_observer_refresh_and_completion_defer_waking() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let id = waiters.insert(make_sync_request(), None, observer());
        let counter = Arc::new(Counter::default());
        let waker = Waker::from(counter.clone());
        assert!(matches!(waiters.observe(id, &waker), Observation::Refresh));
        assert!(waiters.set_waker(id, waker.clone()).is_none());
        assert!(matches!(waiters.observe(id, &waker), Observation::Pending));

        let other = Waker::from(Arc::new(Counter::default()));
        assert!(matches!(waiters.observe(id, &other), Observation::Refresh));
        assert!(
            waiters
                .set_waker(id, other.clone())
                .unwrap()
                .will_wake(&waker)
        );
        assert!(waiters.set_waker(id, waker).unwrap().will_wake(&other));
        waiters.finish(id, Err(Error::Closed), &mut deferred);
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        assert_eq!(deferred.wakes.len(), 1);
        deferred.wakes.pop().unwrap().wake();
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
        assert!(matches!(
            output(&mut waiters, id),
            RequestOutput::Sync(Err(Error::Closed))
        ));
    }

    #[test]
    fn test_cancellation_acknowledgements_do_not_retire_requests_or_results() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let id = waiters.insert(make_sync_request(), Some(2), observer());
        waiters.stage(id);
        assert!(waiters.cancel(id));
        assert!(!waiters.cancel(id));
        for result in [0, -libc::EALREADY, -libc::ENOENT, -libc::EPERM] {
            assert!(matches!(
                waiters.on_completion(id.cancel_user_data(), result),
                CompletionOutcome::Cancel
            ));
            assert_eq!(waiters.in_flight(), 1);
        }
        assert!(catch_unwind(AssertUnwindSafe(|| waiters.stage(id))).is_err());
        assert!(
            catch_unwind(AssertUnwindSafe(|| waiters.finish(
                id,
                Err(Error::Closed),
                &mut deferred
            )))
            .is_err()
        );
        assert_eq!(complete(&mut waiters, id, 0, &mut deferred), None);

        // The result is still addressable when a late cancellation CQE arrives.
        for result in [0, -libc::ENOENT, -libc::EINVAL] {
            assert!(matches!(
                waiters.on_completion(id.cancel_user_data(), result),
                CompletionOutcome::Cancel
            ));
        }
        assert_eq!(waiters.in_flight(), 0);
        assert!(matches!(
            output(&mut waiters, id),
            RequestOutput::Sync(Ok(()))
        ));
        assert!(matches!(
            waiters.on_completion(id.cancel_user_data(), -libc::ENOENT),
            CompletionOutcome::Cancel
        ));
    }

    #[test]
    fn test_invalid_ids_and_cancel_opcode_rejection() {
        let mut waiters = Waiters::new(1);
        for id in [waiter_id(0, 0), waiter_id(7, 0)] {
            assert!(!waiters.is_pending(id));
            assert!(!waiters.cancel(id));
            assert!(!waiters.is_in_flight(id));
            assert!(catch_unwind(AssertUnwindSafe(|| waiters.stage(id))).is_err());
            assert!(
                catch_unwind(AssertUnwindSafe(|| waiters.on_completion(id.user_data(), 0)))
                    .is_err()
            );
        }
        let id = waiters.insert(make_sync_request(), None, observer());
        waiters.stage(id);
        assert!(
            catch_unwind(AssertUnwindSafe(
                || waiters.on_completion(id.cancel_user_data(), -libc::EINVAL)
            ))
            .is_err()
        );
        assert_eq!(waiters.in_flight(), 1);
    }

    #[test]
    fn test_failed_sqe_construction_keeps_request_unsubmitted() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let mut request = read_request(1);
        let Request::Recv(recv) = &mut request else {
            unreachable!()
        };
        recv.len = 6;
        let id = waiters.insert(request, None, observer());
        assert!(catch_unwind(AssertUnwindSafe(|| waiters.stage(id))).is_err());
        assert!(!waiters.is_in_flight(id));
        assert_eq!(waiters.in_flight(), 0);
        waiters.finish(id, Err(Error::RecvFailed), &mut deferred);
        assert!(matches!(
            output(&mut waiters, id),
            RequestOutput::Recv(Err((_, Error::RecvFailed)))
        ));
    }

    #[test]
    fn test_orphaned_reads_and_sends_stop_before_staging_or_after_partial_completion() {
        for kind in 0..3 {
            let mut waiters = Waiters::new(1);
            let mut deferred = Deferred::default();
            let id = waiters.insert(read_request(kind), Some(7), observer());
            assert!(waiters.orphan(id, &mut deferred));
            assert!(waiters.cancel(id));

            // The driver retires queued cancellations without staging an SQE.
            assert_eq!(waiters.finish(id, Err(Error::Timeout), &mut deferred), None);
            assert!(waiters.is_empty());

            for result in [-libc::EAGAIN, 2] {
                let id = waiters.insert(read_request(kind), Some(9), observer());
                waiters.stage(id);
                assert!(waiters.orphan(id, &mut deferred));
                assert!(!waiters.orphan(id, &mut deferred));
                assert!(waiters.cancel(id));

                // ReadAt can request another SQE despite cancellation. Its
                // orphaned observer lets completion retire it here instead.
                assert_eq!(complete(&mut waiters, id, result, &mut deferred), None);
                assert!(waiters.is_empty());
            }
        }
    }

    #[test]
    fn test_queued_timeout_retains_result_until_drop() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let id = waiters.insert(read_request(1), None, observer());
        assert!(waiters.cancel(id));
        assert!(catch_unwind(AssertUnwindSafe(|| waiters.stage(id))).is_err());
        assert!(!waiters.is_in_flight(id));
        waiters.finish(id, Err(Error::Timeout), &mut deferred);
        assert!(waiters.is_empty());
        assert!(!waiters.is_pending(id));

        assert!(!waiters.orphan(id, &mut deferred));
        assert!(matches!(
            deferred.outputs.pop(),
            Some(RequestOutput::Recv(Err((_, Error::Timeout))))
        ));
        let next = waiters.insert(read_request(1), None, observer());
        assert_eq!(id.0.index, next.0.index);
        assert_ne!(id, next);
    }

    #[test]
    fn test_close_clears_results_and_keeps_unobserved_syncs() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let pending = waiters.insert(read_request(1), None, observer());
        let sync = waiters.insert(make_sync_request(), None, observer());
        let ready = waiters.insert(read_request(1), None, observer());
        waiters.finish(ready, Err(Error::Timeout), &mut deferred);
        let (sender, receiver) = oneshot::channel();
        let detached = waiters.insert(make_sync_request(), None, Observer::DetachedSync(sender));

        assert_eq!(waiters.close(&mut deferred), vec![pending]);
        assert!(!waiters.is_pending(ready));
        assert!(!waiters.orphan(sync, &mut deferred));
        assert_eq!(waiters.len(), 3);
        waiters.stage(sync);
        assert!(
            matches!(waiters.on_completion(sync.user_data(), -libc::EINTR), CompletionOutcome::Requeue(id) if id == sync)
        );
        waiters.stage(sync);
        complete(&mut waiters, sync, 0, &mut deferred);
        waiters.stage(detached);
        complete(&mut waiters, detached, 0, &mut deferred);
        waiters.finish(pending, Err(Error::Timeout), &mut deferred);
        assert!(waiters.is_empty());
        assert_eq!(waiters.entries.len(), 0);

        let (sender, result) = deferred.sync_results.pop().unwrap();
        sender.send(result).unwrap();
        assert!(futures::executor::block_on(receiver).unwrap().is_ok());
    }

    #[test]
    fn test_growth_preserves_in_flight_identity_and_counts() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let first = waiters.insert(make_sync_request(), None, observer());
        waiters.stage(first);
        for _ in 0..64 {
            waiters.insert(make_sync_request(), None, observer());
        }
        assert_eq!(waiters.len(), 65);
        assert_eq!(waiters.in_flight(), 1);
        assert!(waiters.is_in_flight(first));
        complete(&mut waiters, first, 0, &mut deferred);
        assert_eq!(waiters.len(), 64);
        assert_eq!(waiters.in_flight(), 0);
    }
}
