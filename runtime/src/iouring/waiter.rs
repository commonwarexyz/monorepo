//! Waiter identity and lifecycle state for tracked io_uring requests.
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
    request::{Request, RequestOutput},
    runtime::Deferred,
    slab::{Id, Slab},
    timeout::Tick,
};
use crate::Error;
use commonware_utils::channel::oneshot;
use io_uring::squeue::Entry as SqueueEntry;
use std::{mem, task::Waker, time::Instant};

/// Kernel completion identity packed into an SQE's `user_data` field.
pub type UserData = u64;

/// Slab identity used for operation SQE/CQE `user_data`.
///
/// Userspace retains the full generation. Kernel `user_data` packs the index in
/// the low 32 bits and the low 32 generation bits in the high 32 bits.
/// An operation CQE cannot be stale because its slot cannot recycle before it
/// arrives, so completion lookup recovers the full identity from the live slot.
/// Cancellation acknowledgements use a separate token handled by the driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaiterId(pub Id);

impl WaiterId {
    /// Encode this waiter id as `user_data` for the operation SQE/CQE.
    ///
    /// The packed generation wraps at 2^32. Userspace handles and queues must
    /// retain the full ID rather than using this truncated kernel identity.
    pub const fn user_data(self) -> UserData {
        ((self.0.generation & u32::MAX as UserData) << 32) | self.0.index as UserData
    }

    /// Decode the slot index and truncated generation from kernel `user_data`.
    const fn from_user_data(user_data: UserData) -> (u32, u32) {
        (user_data as u32, (user_data >> 32) as u32)
    }
}

/// Lifecycle state of a tracked request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaiterState {
    /// Request is still tracked and has not transitioned to cancellation.
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
pub enum Observer {
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

/// State for one tracked logical request.
struct Waiter {
    /// Lifecycle state for the logical request stored in this slot.
    state: WaiterState,
    /// Whether the logical request currently has an operation SQE in flight.
    in_flight: bool,
    /// Result destination and any waker awaiting terminal completion.
    observer: Observer,
    /// The active request state machine.
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

/// Outcome produced when handling an operation CQE for a waiter.
pub enum CompletionOutcome {
    /// The logical request needs another SQE and should be placed back in the
    /// ready queue.
    Requeue(WaiterId),
    /// Terminal status the driver must pass to [`Waiters::finish`] for this ID.
    Complete(WaiterId, Result<(), Error>),
}

/// Result of inspecting an ordinary future without cloning its waker.
pub enum Observation {
    /// Output removed from the slab, with its slot already recycled.
    Ready(RequestOutput),
    /// Request is unfinished and its installed waker already matches the caller.
    Pending,
    /// The caller must clone its waker outside the worker borrow, then recheck.
    Refresh,
}

/// Tracks logical requests and the state needed to complete them.
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

    /// Insert a request and return its assigned id.
    ///
    /// The driver installs any deadline before staging the request. The slot
    /// remains occupied until an ordinary result is consumed or dropped.
    pub fn insert(&mut self, request: Request, observer: Observer) -> WaiterId {
        let id = self.entries.insert_with(|id| {
            // Reserve the maximum index for cancellation and mailbox wake tokens.
            assert!(id.index < u32::MAX, "waiter slot index overflow");
            Entry::Pending(Waiter {
                state: WaiterState::Active { target_tick: None },
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

    /// Return whether the ID refers to an unfinished request.
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
        assert!(target_tick.is_none(), "deadline installed twice");
        *target_tick = Some(tick);
    }

    /// Inspect or consume a result without running observer callbacks.
    ///
    /// A ready result is removed and its slot recycled. An unfinished request
    /// remains in place, returning whether its waker needs refreshing. Panics
    /// if the ID no longer belongs to an ordinary observer.
    pub fn observe(&mut self, id: WaiterId, waker: &Waker) -> Observation {
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
    pub fn set_waker(&mut self, id: WaiterId, waker: Waker) -> Option<Waker> {
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
    pub fn orphan(&mut self, id: WaiterId, deferred: &mut Deferred) -> bool {
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

                // The driver cancels eligible requests before processing more CQEs.
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
    pub fn close(&mut self, deferred: &mut Deferred) -> Vec<WaiterId> {
        let mut cancel = Vec::new();
        for index in 0..self.entries.slots() {
            if let Some(id) = self.entries.id_at(index).map(WaiterId)
                && self.orphan(id, deferred)
            {
                cancel.push(id);
            }
        }
        cancel
    }

    /// Request cancellation for an active waiter.
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
    pub fn finish(
        &mut self,
        id: WaiterId,
        result: Result<(), Error>,
        deferred: &mut Deferred,
    ) -> Option<Tick> {
        // The kernel must be done with the request before we move or release
        // the resources referenced by its SQE.
        assert!(
            !self.get(id).expect("finished waiter missing").in_flight,
            "cannot finish kernel-visible request"
        );

        // Keep the identity occupied while separating the output from the
        // resources whose destruction must wait for the worker borrow to end.
        let entry = self.entries.get_mut(id.0).unwrap();
        let Entry::Pending(waiter) = mem::replace(entry, Entry::Retiring) else {
            unreachable!()
        };

        // A retained result must not keep the request counted as pending.
        self.pending -= 1;

        // The driver removes the wheel tick when cancelling. Other completions
        // still need to report it for removal.
        let tick = match waiter.state {
            WaiterState::Active { target_tick } => target_tick,
            WaiterState::CancelRequested => None,
        };

        let (output, resources) = waiter.request.complete(result);
        deferred.resources.push(resources);

        match waiter.observer {
            Observer::Ordinary(waker) => {
                // The future still holds this ID and will consume the result
                // on a later poll.
                *entry = Entry::Ready(output);
                deferred.wakes.extend(waker);
            }
            Observer::DetachedSync(sender) => {
                // The receiver no longer needs the slot. Sending may wake user
                // code, so defer publication until the worker borrow ends.
                let RequestOutput::Sync(output) = output else {
                    panic!("sync observer received other request");
                };
                self.entries.remove(id.0);
                deferred.sync_results.push((sender, output));
            }
            Observer::Orphaned => {
                // Nobody will consume the result. Its buffers may run user code
                // when dropped, so defer their destruction after freeing the slot.
                self.entries.remove(id.0);
                deferred.outputs.push(output);
            }
        }
        tick
    }

    /// Stage the next SQE for a waiter.
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

    /// Process one operation CQE for a waiter.
    ///
    /// An operation CQE releases its in-flight count and updates progress in
    /// place. The driver then requeues or finishes the request. A cancelled
    /// request never requeues, returning its terminal result or `Error::Timeout`
    /// if another SQE would be needed.
    ///
    /// A missing entry or mismatched packed generation is an invariant failure.
    pub fn on_completion(&mut self, user_data: UserData, result: i32) -> CompletionOutcome {
        let (index, generation) = WaiterId::from_user_data(user_data);

        // The outstanding SQE keeps this slot occupied, even if the packed
        // generation has wrapped. Recover the full ID before returning it.
        let id = self
            .entries
            .id_at(index as usize)
            .map(WaiterId)
            .expect("operation CQE for missing waiter");
        assert_eq!(
            id.0.generation as u32, generation,
            "operation CQE for mismatched waiter generation"
        );
        let waiter = self
            .get_mut(id)
            .expect("operation CQE for completed waiter");

        // The operation CQE retires the currently in-flight SQE, regardless of
        // whether the request completes or is requeued for another one.
        assert!(waiter.in_flight);
        waiter.in_flight = false;

        let outcome = match waiter.request.on_cqe(waiter.state, result) {
            Some(result) => CompletionOutcome::Complete(id, result),
            None if matches!(waiter.state, WaiterState::CancelRequested) => {
                // Preserve terminal results above, but never issue a follow-up
                // SQE after cancellation, including for an orphaned file read.
                CompletionOutcome::Complete(id, Err(Error::Timeout))
            }
            None => CompletionOutcome::Requeue(id),
        };
        self.in_flight -= 1;
        outcome
    }

    /// Return whether a waiter currently has an operation SQE in flight.
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
            request::{
                Cache, ConnectRequest, Held, PollRequest, ReadAtRequest, RecvRequest, SendRequest,
                SyncRequest,
            },
            slab::tests::set_generation,
        },
        storage::hold::Hold,
    };
    use std::{
        fs::File,
        net::{SocketAddr, TcpListener},
        os::{fd::OwnedFd, unix::net::UnixStream},
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc, OnceLock,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
    };

    /// Counts deferred wake invocations without touching worker state.
    #[derive(Default)]
    struct Counter(
        /// Number of times the waker was invoked.
        AtomicUsize,
    );

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Build a full waiter identity without registering a request.
    pub fn waiter_id(index: u32, generation: u64) -> WaiterId {
        WaiterId(Id { index, generation })
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

    /// Build a socket descriptor for SQE construction without kernel submission.
    fn make_socket_fd() -> OwnedFd {
        let (socket, _peer) = UnixStream::pair().unwrap();
        socket.into()
    }

    /// Build a `Sync` request backed by a socket fd so waiter tests can
    /// exercise slot lifecycle without submitting kernel work.
    fn make_sync_request() -> Request {
        Request::Sync(SyncRequest {
            file: held(File::from(make_socket_fd())),
        })
    }

    /// Build a send that needs five bytes of progress before completing.
    fn make_send_request() -> Request {
        Request::Send(SendRequest {
            fd: Arc::new(make_socket_fd()),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        })
    }

    /// Build an exact recv that needs five bytes of progress before completing.
    fn make_recv_request() -> Request {
        Request::Recv(RecvRequest {
            fd: Arc::new(make_socket_fd()),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        })
    }

    /// Build a file read that needs five bytes of progress before completing.
    fn make_read_request() -> Request {
        Request::ReadAt(ReadAtRequest {
            file: held(File::from(make_socket_fd())),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
        })
    }

    /// Build a connect with an address that remains valid across retries.
    fn make_connect_request() -> Request {
        Request::Connect(ConnectRequest {
            fd: Arc::new(make_socket_fd()),
            address: Box::new("127.0.0.1:1234".parse::<SocketAddr>().unwrap().into()),
            deadline: None,
        })
    }

    /// Build a single readiness observation on a listener.
    fn make_poll_request() -> Request {
        Request::Poll(PollRequest {
            fd: Arc::new(TcpListener::bind("127.0.0.1:0").unwrap()),
            flags: libc::POLLIN as u32,
            deadline: None,
        })
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

    #[test]
    fn test_user_data_encoding() {
        // All index bits survive, while only the low 32 generation bits reach the kernel.
        for (index, generation, encoded) in [
            (0, 0, 0),
            (0x89ab_cdef, 0x0123_4567, 0x0123_4567_89ab_cdef),
            (7, 1 << 31, 0x8000_0000_0000_0007),
            (7, 1 << 32, 7),
            (u32::MAX - 1, u64::MAX, u64::MAX - 1),
        ] {
            let id = waiter_id(index, generation);
            assert_eq!(id.user_data(), encoded);
            assert_eq!(
                WaiterId::from_user_data(encoded),
                (index, generation as u32)
            );
        }
    }

    #[test]
    fn test_cqe_resolves_full_generation_after_kernel_wrap() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let id = waiters.insert(make_sync_request(), observer());
        let last = WaiterId(set_generation(&mut waiters.entries, id.0, u32::MAX as u64));
        waiters.finish(last, Err(Error::Closed), &mut deferred);
        drop(output(&mut waiters, last));

        let current = waiters.insert(make_sync_request(), observer());
        assert_eq!(current.0.generation, 1 << 32);

        // Kernel generations wrap while userspace IDs retain the full generation.
        assert_eq!(current.user_data(), id.user_data());
        assert!(!waiters.is_pending(id));
        assert!(!waiters.cancel(id));
        waiters.stage(current);

        // Neither a different generation nor a duplicate CQE can retire this SQE.
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                waiters.on_completion(last.user_data(), 0)
            }))
            .is_err()
        );
        assert_eq!(waiters.in_flight(), 1);
        assert!(matches!(
            waiters.on_completion(current.user_data(), -libc::EINTR),
            CompletionOutcome::Requeue(id) if id == current
        ));
        assert_eq!(waiters.in_flight(), 0);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                waiters.on_completion(current.user_data(), 0)
            }))
            .is_err()
        );

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

        let first = waiters.insert(make_sync_request(), observer());
        waiters.set_deadline(first, 5);
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

        let second = waiters.insert(make_sync_request(), observer());
        assert_ne!(first.0.index, second.0.index);
        assert!(matches!(
            output(&mut waiters, first),
            RequestOutput::Sync(Ok(()))
        ));

        // Consuming the result makes the slot reusable, with a different identity.
        let reused = waiters.insert(make_sync_request(), observer());
        assert_eq!(reused.0.index, first.0.index);
        assert_ne!(reused, first);
        assert!(!waiters.orphan(first, &mut deferred));
        assert!(waiters.is_pending(reused));
    }

    #[test]
    fn test_exhausted_generation_retires_slot_after_result_consumption() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let id = waiters.insert(make_sync_request(), observer());
        let exhausted = WaiterId(set_generation(&mut waiters.entries, id.0, u64::MAX));

        waiters.stage(exhausted);
        complete(&mut waiters, exhausted, 0, &mut deferred);
        drop(output(&mut waiters, exhausted));

        // Consumption cannot put an exhausted slot back on the free list.
        let next = waiters.insert(make_sync_request(), observer());
        assert_ne!(next.0.index, exhausted.0.index);
        assert_eq!(waiters.in_flight(), 0);
    }

    #[test]
    fn test_observer_refresh_and_completion_defer_waking() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let id = waiters.insert(make_sync_request(), observer());
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

        // Completion stores the result immediately, but waking is deferred.
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
    fn test_cancellation_waits_for_operation_completion() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let id = waiters.insert(make_sync_request(), observer());
        waiters.set_deadline(id, 2);
        waiters.stage(id);
        assert!(waiters.cancel(id));
        assert!(!waiters.cancel(id));

        // Cancellation cannot release resources before the operation's CQE.
        assert!(catch_unwind(AssertUnwindSafe(|| waiters.stage(id))).is_err());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                waiters.finish(id, Err(Error::Closed), &mut deferred)
            }))
            .is_err()
        );
        assert_eq!(waiters.in_flight(), 1);

        assert_eq!(complete(&mut waiters, id, 0, &mut deferred), None);
        assert_eq!(waiters.in_flight(), 0);
        assert!(matches!(
            output(&mut waiters, id),
            RequestOutput::Sync(Ok(()))
        ));
    }

    #[test]
    fn test_invalid_ids() {
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
    }

    #[test]
    fn test_failed_sqe_construction_keeps_request_unsubmitted() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let mut request = make_recv_request();
        let Request::Recv(recv) = &mut request else {
            unreachable!()
        };
        recv.len = 6;
        let id = waiters.insert(request, observer());

        // SQE construction rejects a target larger than the owned buffer.
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
    fn test_cancelled_network_requests_do_not_requeue() {
        for (request, progress, result) in [
            (make_send_request(), Some(2), -libc::EAGAIN),
            (make_send_request(), Some(2), 1),
            (make_recv_request(), Some(3), -libc::EINTR),
            (make_recv_request(), Some(3), 1),
            (make_connect_request(), None, -libc::EALREADY),
            (make_connect_request(), None, -libc::EAGAIN),
            (make_connect_request(), None, -libc::EINTR),
            (make_poll_request(), None, -libc::EINTR),
        ] {
            let mut waiters = Waiters::new(1);
            let mut deferred = Deferred::default();
            let id = waiters.insert(request, observer());
            waiters.stage(id);

            // Exercise cancellation after earlier SQEs have made progress too.
            if let Some(progress) = progress {
                assert!(matches!(
                    waiters.on_completion(id.user_data(), progress),
                    CompletionOutcome::Requeue(current) if current == id
                ));
                waiters.stage(id);
            }

            assert!(waiters.cancel(id));
            assert!(matches!(
                waiters.on_completion(id.user_data(), result),
                CompletionOutcome::Complete(current, Err(Error::Timeout)) if current == id
            ));
            assert_eq!(waiters.in_flight(), 0);

            // Cancellation still leaves an ordinary result for the waiting future.
            waiters.finish(id, Err(Error::Timeout), &mut deferred);
            assert!(waiters.is_empty());
            assert!(matches!(
                output(&mut waiters, id),
                RequestOutput::Send(Err(Error::Timeout))
                    | RequestOutput::Recv(Err((_, Error::Timeout)))
                    | RequestOutput::Connect(Err(Error::Timeout))
                    | RequestOutput::Poll(Err(Error::Timeout))
            ));
        }
    }

    #[test]
    fn test_cancellation_preserves_terminal_results() {
        for (request, result) in [
            (make_send_request(), 5),
            (make_recv_request(), 5),
            (make_connect_request(), 0),
            (make_connect_request(), -libc::EISCONN),
            (make_poll_request(), libc::POLLIN as i32),
        ] {
            let mut waiters = Waiters::new(1);
            let id = waiters.insert(request, observer());
            waiters.stage(id);
            assert!(waiters.cancel(id));

            // Cancellation can lose the race with a successful operation.
            assert!(matches!(
                waiters.on_completion(id.user_data(), result),
                CompletionOutcome::Complete(current, Ok(())) if current == id
            ));
            assert_eq!(waiters.in_flight(), 0);
        }

        let mut waiters = Waiters::new(1);
        let id = waiters.insert(make_send_request(), observer());
        waiters.stage(id);
        assert!(waiters.cancel(id));

        // An operation's terminal error also takes precedence over Timeout.
        assert!(matches!(
            waiters.on_completion(id.user_data(), -libc::EPIPE),
            CompletionOutcome::Complete(current, Err(Error::SendFailed)) if current == id
        ));
        assert_eq!(waiters.in_flight(), 0);
    }

    #[test]
    fn test_orphaned_reads_and_sends_stop_before_staging_or_after_partial_completion() {
        let requests: [fn() -> Request; 3] =
            [make_send_request, make_recv_request, make_read_request];

        for request in requests {
            let mut waiters = Waiters::new(1);
            let mut deferred = Deferred::default();
            let id = waiters.insert(request(), observer());

            assert!(waiters.orphan(id, &mut deferred));
            assert!(waiters.cancel(id));

            // The driver retires queued cancellations without staging an SQE.
            assert_eq!(waiters.finish(id, Err(Error::Timeout), &mut deferred), None);
            assert!(waiters.is_empty());

            for result in [-libc::EAGAIN, 2] {
                let id = waiters.insert(request(), observer());
                waiters.stage(id);
                assert!(waiters.orphan(id, &mut deferred));
                assert!(!waiters.orphan(id, &mut deferred));
                assert!(waiters.cancel(id));

                // Partial progress and retryable errors cannot revive a
                // request whose observer already requested cancellation.
                assert_eq!(complete(&mut waiters, id, result, &mut deferred), None);
                assert!(waiters.is_empty());
            }
        }
    }

    #[test]
    fn test_queued_timeout_retains_result_until_drop() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let deadline = Instant::now();
        let mut request = make_recv_request();
        let Request::Recv(recv) = &mut request else {
            unreachable!()
        };
        recv.deadline = Some(deadline);
        let id = waiters.insert(request, observer());
        assert_eq!(waiters.deadline(id), Some(deadline));
        assert_eq!(waiters.target_tick(id), None);

        // The driver installs a wheel tick separately from the request deadline.
        waiters.set_deadline(id, 7);
        assert_eq!(waiters.target_tick(id), Some(7));
        assert!(waiters.cancel(id));
        assert_eq!(waiters.target_tick(id), None);
        assert_eq!(waiters.deadline(id), Some(deadline));
        assert!(catch_unwind(AssertUnwindSafe(|| waiters.stage(id))).is_err());
        assert!(!waiters.is_in_flight(id));
        assert_eq!(waiters.finish(id, Err(Error::Timeout), &mut deferred), None);
        assert!(waiters.is_empty());
        assert!(!waiters.is_pending(id));

        // Dropping the future after completion releases its retained output.
        assert!(!waiters.orphan(id, &mut deferred));
        assert!(matches!(
            deferred.outputs.pop(),
            Some(RequestOutput::Recv(Err((_, Error::Timeout))))
        ));

        let next = waiters.insert(make_recv_request(), observer());
        assert_eq!(id.0.index, next.0.index);
        assert_ne!(id, next);
    }

    #[test]
    fn test_close_clears_results_and_keeps_unobserved_syncs() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let pending = waiters.insert(make_recv_request(), observer());
        let sync = waiters.insert(make_sync_request(), observer());
        let ready = waiters.insert(make_recv_request(), observer());
        waiters.finish(ready, Err(Error::Timeout), &mut deferred);

        let (sender, receiver) = oneshot::channel();
        let detached = waiters.insert(make_sync_request(), Observer::DetachedSync(sender));

        assert_eq!(waiters.close(&mut deferred), vec![pending]);
        assert!(!waiters.is_pending(ready));
        assert!(!waiters.orphan(sync, &mut deferred));
        assert_eq!(waiters.len(), 3);

        // Closing removes observers without cancelling committed sync work.
        waiters.stage(sync);
        assert!(
            matches!(waiters.on_completion(sync.user_data(), -libc::EINTR), CompletionOutcome::Requeue(id) if id == sync)
        );
        waiters.stage(sync);
        complete(&mut waiters, sync, 0, &mut deferred);

        waiters.stage(detached);
        complete(&mut waiters, detached, 0, &mut deferred);

        assert!(waiters.cancel(pending));
        waiters.finish(pending, Err(Error::Timeout), &mut deferred);
        assert!(waiters.is_empty());
        assert_eq!(waiters.entries.len(), 0);

        // Detached results are published after leaving the worker borrow.
        let (sender, result) = deferred.sync_results.pop().unwrap();
        sender.send(result).unwrap();
        assert!(futures::executor::block_on(receiver).unwrap().is_ok());
    }

    #[test]
    fn test_growth_preserves_in_flight_identity_and_counts() {
        let mut waiters = Waiters::new(1);
        let mut deferred = Deferred::default();
        let first = waiters.insert(make_sync_request(), observer());
        waiters.stage(first);

        // Growing the slab cannot change the identity already handed to the kernel.
        for _ in 0..64 {
            waiters.insert(make_sync_request(), observer());
        }
        assert_eq!(waiters.len(), 65);
        assert_eq!(waiters.in_flight(), 1);
        assert!(waiters.is_in_flight(first));

        complete(&mut waiters, first, 0, &mut deferred);
        assert_eq!(waiters.len(), 64);
        assert_eq!(waiters.in_flight(), 0);
    }
}
