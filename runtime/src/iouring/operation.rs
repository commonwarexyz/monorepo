//! Worker-affine I/O futures and retained ordinary completion results.
//!
//! An [`Operation`] owns its request until admission. Admission allocates an
//! ordinary result entry together with a bounded driver waiter. Completion
//! releases the waiter before notifying the observer, while the growable local
//! result slab retains the output until its future takes or drops it.
//!
//! ```text
//! Unbound -> Admitting -> Waiting -> Done
//!              |            |
//!              |            +-> operation entry: Pending -> Ready -> recycle
//!              +-> FIFO grant          |
//!                                  bounded waiter -> kernel retirement
//! ```
//!
//! Futures retain only full-width IDs and weak mailbox identities across polls.
//! Resources may move between workers between operations, but registered work
//! cannot move between live workers. Foreign destruction publishes cancellation
//! instead of accessing the original worker's local state.

use super::{
    admission::AdmissionId,
    callbacks::Panics,
    mailbox::{Mailbox, Message},
    request::{Request, RequestOutput},
    runtime::{self, Local},
    waiter::{Observer, WaiterId},
};
use crate::Error;
use commonware_utils::channel::oneshot;
use std::{
    cell::RefCell,
    future::Future,
    mem,
    panic::resume_unwind,
    pin::Pin,
    rc::Rc,
    sync::{Arc, Weak},
    task::{Context, Poll, Waker},
};

/// Full-width observer identity, independent of the kernel's packed waiter ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OperationId {
    /// Index in the owning worker's ordinary result slab.
    pub(super) index: usize,
    /// Slot incarnation validated before any waiter or result access.
    pub(super) generation: u64,
}

/// Contents retained for a live ordinary observer.
pub(super) enum EntryState {
    /// The driver still owns the request and its kernel resources.
    Pending {
        /// Bounded waiter paired with this observer at admission.
        waiter_id: WaiterId,
        /// Most recent observer waker, replaced without destruction under Local.
        waker: Option<Waker>,
    },
    /// Terminal output retained independently of active waiter capacity.
    Ready(RequestOutput),
}

/// One reusable result slot.
struct Entry {
    /// Current generation, retired rather than wrapped on exhaustion.
    generation: u64,
    /// Present while the observer owns this slot.
    state: Option<EntryState>,
    /// Next reusable slot while vacant.
    next_free: Option<usize>,
}

/// Ordinary observer state owned exclusively by one worker.
#[derive(Default)]
pub(super) struct Operations {
    /// Growable result storage that is not bounded by ring capacity.
    entries: Vec<Entry>,
    /// Head of vacant slots eligible for another generation.
    free: Option<usize>,
}

impl Operations {
    /// Reserve insertion space before the driver consumes waiter capacity.
    fn reserve(&mut self) -> OperationId {
        match self.free {
            Some(index) => OperationId {
                index,
                generation: self.entries[index].generation,
            },
            None => {
                self.entries.reserve(1);
                OperationId {
                    index: self.entries.len(),
                    generation: 0,
                }
            }
        }
    }

    /// Install the waiter and observer together after both allocations succeed.
    fn insert(&mut self, id: OperationId, waiter_id: WaiterId, waker: Waker) {
        let state = Some(EntryState::Pending {
            waiter_id,
            waker: Some(waker),
        });
        if id.index == self.entries.len() {
            self.entries.push(Entry {
                generation: id.generation,
                state,
                next_free: None,
            });
        } else {
            assert_eq!(self.free, Some(id.index));
            let entry = &mut self.entries[id.index];
            assert_eq!(entry.generation, id.generation);
            assert!(entry.state.is_none());
            self.free = entry.next_free.take();
            entry.state = state;
        }
    }

    /// Inspect a live full-width identity without following stale waiter IDs.
    fn get_mut(&mut self, id: OperationId) -> Option<&mut EntryState> {
        let entry = self.entries.get_mut(id.index)?;
        if entry.generation != id.generation {
            return None;
        }
        entry.state.as_mut()
    }

    /// Recycle only the observer slot, returning all owned values untouched.
    fn take(&mut self, id: OperationId) -> Option<EntryState> {
        let entry = self.entries.get_mut(id.index)?;
        if entry.generation != id.generation {
            return None;
        }
        let state = entry.state.take()?;
        if let Some(generation) = entry.generation.checked_add(1) {
            entry.generation = generation;
            entry.next_free = self.free;
            self.free = Some(id.index);
        }
        Some(state)
    }
}

/// Ownership held by an ordinary future across polls.
enum State {
    /// No worker has been selected and the request is still caller-owned.
    Unbound(Request),
    /// Waiting for one FIFO reservation on the selected worker.
    Admitting {
        /// Weak identity of the selected worker.
        mailbox: Weak<Mailbox>,
        /// Request data not yet transferred to the driver.
        request: Request,
        /// Existing FIFO registration, reused on subsequent polls.
        registration: AdmissionId,
    },
    /// The request is admitted and this future observes its local result slot.
    Waiting {
        /// Weak identity checked before every subsequent poll.
        mailbox: Weak<Mailbox>,
        /// Ordinary result slot retained until take or destruction.
        operation_id: OperationId,
    },
    /// Terminal state installed before arbitrary callbacks can run.
    Done,
}

/// Ordinary I/O bound to the worker that first polls it.
pub(crate) struct Operation {
    /// Request or observer ownership retained between polls.
    state: State,
}

impl Operation {
    /// Construct an unbound request without requiring a current worker.
    pub(crate) const fn new(request: Request) -> Self {
        Self {
            state: State::Unbound(request),
        }
    }
}

/// Resolve a registered worker, rejecting migration while allowing closed polls.
pub(super) fn bound(mailbox: &Weak<Mailbox>) -> Result<Rc<RefCell<Local>>, Error> {
    if let Some(local) = runtime::current() {
        let matches = std::ptr::eq(Arc::as_ptr(&local.borrow().mailbox), mailbox.as_ptr());
        if matches {
            return Ok(local);
        }
    }
    if mailbox.upgrade().is_none_or(|mailbox| !mailbox.is_open()) {
        return Err(Error::Closed);
    }
    panic!("registered io_uring operation polled outside its owning worker");
}

impl Future for Operation {
    type Output = Result<RequestOutput, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Validate affinity before moving registration ownership out of the
        // future. A rejected foreign poll can then unwind through normal Drop,
        // which still has the identity needed to cancel on the owning worker.
        let owner = match &this.state {
            State::Unbound(_) => {
                runtime::current().expect("io_uring I/O requires a current worker")
            }
            State::Admitting { mailbox, .. } | State::Waiting { mailbox, .. } => {
                match bound(mailbox) {
                    Ok(owner) => owner,
                    Err(error) => {
                        drop(Self {
                            state: mem::replace(&mut this.state, State::Done),
                        });
                        return Poll::Ready(Err(error));
                    }
                }
            }
            State::Done => panic!("io_uring operation polled after completion"),
        };
        // Clone before touching Local because arbitrary RawWaker clone callbacks
        // may reenter the runtime. Done is installed before displaced ownership
        // can be destroyed or any terminal result is returned.
        let incoming = cx.waker().clone();
        let state = mem::replace(&mut this.state, State::Done);
        let (request, mailbox, registration) = match state {
            State::Unbound(request) => {
                let mailbox = Arc::downgrade(&owner.borrow().mailbox);
                (request, mailbox, None)
            }
            State::Admitting {
                request,
                mailbox,
                registration,
            } => (request, mailbox, Some(registration)),
            State::Waiting {
                mailbox,
                operation_id,
            } => {
                let mut local = owner.borrow_mut();
                local.drops.reserve(1);
                if local.closing {
                    local.drops.push(incoming);
                    return Poll::Ready(Err(Error::Closed));
                }
                match local
                    .operations
                    .get_mut(operation_id)
                    .expect("live operation entry missing")
                {
                    EntryState::Pending { waker, .. } => {
                        let old = waker.replace(incoming);
                        if let Some(old) = old {
                            local.drops.push(old);
                        }
                        this.state = State::Waiting {
                            mailbox,
                            operation_id,
                        };
                        return Poll::Pending;
                    }
                    EntryState::Ready(_) => {
                        local.drops.push(incoming);
                        let Some(EntryState::Ready(output)) = local.operations.take(operation_id)
                        else {
                            unreachable!()
                        };
                        return Poll::Ready(Ok(output));
                    }
                }
            }
            State::Done => panic!("io_uring operation polled after completion"),
        };
        let mut local = owner.borrow_mut();
        local.drops.reserve(2);
        if local.closing {
            local.drops.push(incoming);
            drop(local);
            retire_request(request);
            return Poll::Ready(Err(Error::Closed));
        }
        if request
            .deadline()
            .is_some_and(|deadline| deadline <= local.now)
        {
            if let Some(id) = registration {
                local.cancel_admission(id);
            }
            local.retired_resources.reserve(1);
            let (output, retired) = request.timeout();
            local.retired_resources.push(retired);
            local.drops.push(incoming);
            return Poll::Ready(Ok(output));
        }
        local.reconcile_admissions();
        // A grant already owns capacity. Fresh callers may only use capacity
        // left after older registrations have received their FIFO reservations.
        let granted = match registration {
            Some(id) => match local.admissions.take_grant(id) {
                Ok(old) => {
                    if let Some(old) = old {
                        local.drops.push(old);
                    }
                    true
                }
                Err(()) => false,
            },
            None => local
                .admissions
                .can_admit(local.driver.as_ref().unwrap().free_slots()),
        };
        if granted {
            // Reserve the unbounded observer entry before consuming a bounded
            // waiter. Both identities become visible in the same local borrow.
            let id = local.operations.reserve();
            let waiter = local
                .driver
                .as_mut()
                .unwrap()
                .admit(request, Observer::Ordinary(id));
            local.operations.insert(id, waiter, incoming);
            this.state = State::Waiting {
                mailbox,
                operation_id: id,
            };
        } else {
            // Repeated polls replace only the observer waker. The original FIFO
            // position and deadline remain attached to the same registration.
            let id = match registration {
                Some(id) => {
                    let old = local
                        .admissions
                        .refresh(id, incoming)
                        .expect("live admission missing");
                    if let Some(old) = old {
                        local.drops.push(old);
                    }
                    id
                }
                None => local.admissions.register(request.deadline(), incoming),
            };
            this.state = State::Admitting {
                mailbox,
                request,
                registration: id,
            };
        }
        Poll::Pending
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        match mem::replace(&mut self.state, State::Done) {
            State::Admitting {
                mailbox,
                registration,
                request,
            } => {
                cancel(&mailbox, Message::CancelAdmission(registration));
                retire_request(request);
            }
            State::Waiting {
                mailbox,
                operation_id,
            } => cancel(&mailbox, Message::OrphanOperation(operation_id)),
            State::Unbound(request) => retire_request(request),
            State::Done => {}
        }
    }
}

/// Retire unsubmitted buffers independently, including during a foreign drop.
fn retire_request(request: Request) {
    let (output, resources) = request.fail(Error::Closed);
    let mut panics = Panics::default();
    panics.run(|| drop(output));
    resources.retire(&mut panics);
    if let Some(panic) = panics.take() {
        // A task destructor may already be unwinding. Starting another unwind
        // here would interrupt the worker's mandatory kernel retirement.
        if std::thread::panicking() {
            mem::forget(panic);
        } else {
            resume_unwind(panic);
        }
    }
}

/// Admission state for a sync whose result may outlive the owning worker.
struct SyncAdmission {
    /// Unsubmitted request, transferred only after a grant is consumed.
    request: Option<Request>,
    /// Selected worker, fixed on the first poll.
    mailbox: Option<Weak<Mailbox>>,
    /// FIFO registration while waiting for capacity.
    registration: Option<AdmissionId>,
    /// Sender transferred directly to the detached waiter at admission.
    sender: Option<oneshot::Sender<Result<(), Error>>>,
    /// Receiver returned only once the request is admitted or rejected.
    receiver: Option<oneshot::Receiver<Result<(), Error>>>,
}

/// Admit a sync before returning its independent completion receiver.
pub(crate) async fn start_sync(request: Request) -> oneshot::Receiver<Result<(), Error>> {
    assert!(
        matches!(&request, Request::Sync(_)),
        "detached admission requires sync"
    );
    let (sender, receiver) = oneshot::channel();
    SyncAdmission {
        request: Some(request),
        mailbox: None,
        registration: None,
        sender: Some(sender),
        receiver: Some(receiver),
    }
    .await
}

impl Future for SyncAdmission {
    type Output = oneshot::Receiver<Result<(), Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let incoming = cx.waker().clone();
        if this.mailbox.is_none() {
            let owner = runtime::current().expect("io_uring sync requires a current worker");
            this.mailbox = Some(Arc::downgrade(&owner.borrow().mailbox));
        }
        let owner = bound(this.mailbox.as_ref().unwrap());
        if let Ok(owner) = owner {
            let mut local = owner.borrow_mut();
            local.drops.reserve(2);
            if !local.closing {
                local.reconcile_admissions();
                let granted = match this.registration {
                    Some(id) => match local.admissions.take_grant(id) {
                        Ok(old) => {
                            if let Some(old) = old {
                                local.drops.push(old);
                            }
                            true
                        }
                        Err(()) => false,
                    },
                    None => local
                        .admissions
                        .can_admit(local.driver.as_ref().unwrap().free_slots()),
                };
                if granted {
                    local.drops.push(incoming);
                    let request = this.request.take().expect("sync polled after admission");
                    let sender = this.sender.take().unwrap();
                    local
                        .driver
                        .as_mut()
                        .unwrap()
                        .admit(request, Observer::DetachedSync(sender));
                    this.registration = None;
                    return Poll::Ready(this.receiver.take().unwrap());
                }
                this.registration = Some(match this.registration {
                    Some(id) => {
                        let old = local
                            .admissions
                            .refresh(id, incoming)
                            .expect("sync admission missing");
                        if let Some(old) = old {
                            local.drops.push(old);
                        }
                        id
                    }
                    None => local.admissions.register(None, incoming),
                });
                return Poll::Pending;
            }
            local.drops.push(incoming);
            if let Some(id) = this.registration.take() {
                local.cancel_admission(id);
            }
        }
        // Closure rejects unstarted work and publishes only after releasing
        // Local. The request was never exposed to the kernel.
        let request = this.request.take();
        let receiver = this.receiver.take().expect("sync polled after completion");
        let sender = this.sender.take().unwrap();
        this.registration = None;
        drop(request);
        let _ = sender.send(Err(Error::Closed));
        Poll::Ready(receiver)
    }
}

impl Drop for SyncAdmission {
    fn drop(&mut self) {
        if let Some(id) = self.registration.take() {
            cancel(
                self.mailbox.as_ref().expect("registered sync has a worker"),
                Message::CancelAdmission(id),
            );
        }
    }
}

/// Route destruction locally without weak upgrade, or publish to a foreign owner.
pub(super) fn cancel(mailbox: &Weak<Mailbox>, message: Message) {
    if let Some(local) = runtime::current() {
        let mut local = local.borrow_mut();
        if std::ptr::eq(Arc::as_ptr(&local.mailbox), mailbox.as_ptr()) {
            match message {
                Message::CancelAdmission(id) => local.cancel_admission(id),
                Message::OrphanOperation(id) => local.orphan_operation(id),
                Message::CancelTimer(id) => {
                    local.drops.reserve(1);
                    if let Some(waker) = local.timers.cancel(id) {
                        local.drops.push(waker);
                    }
                }
                _ => unreachable!("invalid cancellation message"),
            }
            return;
        }
    }
    if let Some(mailbox) = mailbox.upgrade() {
        let _ = mailbox.send(message);
    }
}

impl Local {
    /// Redistribute released capacity before invoking any observer notification.
    pub(super) fn reconcile_admissions(&mut self) {
        let free = self
            .driver
            .as_ref()
            .expect("driver present during local access")
            .free_slots();
        self.admissions.reconcile(self.now, free, &mut self.wakes);
    }

    /// Release an admission reservation and immediately grant its successor.
    pub(super) fn cancel_admission(&mut self, id: AdmissionId) {
        self.drops.reserve(1);
        if let Some(waker) = self.admissions.cancel(id) {
            self.drops.push(waker);
        }
        if !self.closing {
            self.reconcile_admissions();
        }
    }

    /// Detach an observer before changing its waiter's cancellation state.
    pub(super) fn orphan_operation(&mut self, id: OperationId) {
        self.drops.reserve(1);
        self.retired_outputs.reserve(1);
        match self.operations.take(id) {
            Some(EntryState::Pending { waiter_id, waker }) => {
                if let Some(waker) = waker {
                    self.drops.push(waker);
                }
                self.driver
                    .as_mut()
                    .expect("driver present during orphaning")
                    .orphan(waiter_id, id, &mut self.completed);
                self.apply_completions();
            }
            Some(EntryState::Ready(output)) => self.retired_outputs.push(output),
            None => {}
        }
    }

    /// Transfer terminal results out of bounded waiter capacity before waking.
    pub(super) fn apply_completions(&mut self) {
        self.wakes.reserve(self.completed.len());
        self.retired_outputs.reserve(self.completed.len());
        self.retired_resources.reserve(self.completed.len());
        self.sync_results.reserve(self.completed.len());
        for completed in self.completed.drain(..) {
            self.retired_resources.push(completed.retired);
            match completed.observer {
                Observer::Ordinary(id) => {
                    // Driver retirement has already returned waiter capacity.
                    // Keep the result in its original observer slot until take,
                    // so an unpolled completion cannot block another request.
                    let entry = self
                        .operations
                        .get_mut(id)
                        .expect("completed observer missing");
                    let old = mem::replace(entry, EntryState::Ready(completed.output));
                    let EntryState::Pending { waker, .. } = old else {
                        panic!("operation completed twice")
                    };
                    if let Some(waker) = waker {
                        self.wakes.push(waker);
                    }
                }
                Observer::DetachedSync(sender) => {
                    let RequestOutput::Sync(output) = completed.output else {
                        panic!("sync observer received other request")
                    };
                    self.sync_results.push((sender, output));
                }
                Observer::Orphaned => self.retired_outputs.push(completed.output),
            }
        }
        if !self.closing {
            self.reconcile_admissions();
        }
    }

    /// Remove all ordinary observers, including futures retained outside workers.
    pub(super) fn close_operations(&mut self) {
        for index in 0..self.operations.entries.len() {
            let id = OperationId {
                index,
                generation: self.operations.entries[index].generation,
            };
            self.orphan_operation(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::request::{RecvRequest, SendRequest},
        *,
    };
    use crate::{
        Clock as _, IoBufMut, IoBufs, Runner as _,
        iouring::{Config, RingConfig, Runner},
        utils::reschedule,
    };
    use futures::{FutureExt as _, poll};
    use std::{
        os::{fd::OwnedFd, unix::net::UnixStream},
        sync::atomic::{AtomicUsize, Ordering},
        task::{RawWaker, RawWakerVTable},
        time::Duration,
    };

    /// Arbitrary waker callbacks that reenter the current worker's local state.
    struct Reentrant {
        clones: AtomicUsize,
        wakes: AtomicUsize,
        drops: AtomicUsize,
    }

    impl Reentrant {
        fn check_local() {
            if let Some(local) = runtime::current() {
                // A callback under an outstanding Local borrow fails here.
                let _borrow = local.borrow_mut();
            }
        }

        unsafe fn clone(data: *const ()) -> RawWaker {
            // SAFETY: Each raw waker owns one Arc reference to Reentrant.
            // ManuallyDrop borrows that reference without consuming it.
            let owner = mem::ManuallyDrop::new(unsafe { Arc::from_raw(data.cast::<Self>()) });
            Self::check_local();
            owner.clones.fetch_add(1, Ordering::Relaxed);
            RawWaker::new(Arc::into_raw(Arc::clone(&owner)).cast(), &Self::VTABLE)
        }

        unsafe fn wake(data: *const ()) {
            // SAFETY: Consuming wake takes exactly the Arc reference owned by
            // this raw waker. No reference is reconstructed a second time.
            let owner = unsafe { Arc::from_raw(data.cast::<Self>()) };
            Self::check_local();
            owner.wakes.fetch_add(1, Ordering::Relaxed);
        }

        unsafe fn wake_by_ref(data: *const ()) {
            // SAFETY: The waker retains its Arc reference after this callback,
            // so the temporary reconstructed Arc must not decrement it.
            let owner = mem::ManuallyDrop::new(unsafe { Arc::from_raw(data.cast::<Self>()) });
            Self::check_local();
            owner.wakes.fetch_add(1, Ordering::Relaxed);
        }

        unsafe fn drop(data: *const ()) {
            // SAFETY: Raw-waker destruction consumes its one owned Arc reference.
            let owner = unsafe { Arc::from_raw(data.cast::<Self>()) };
            Self::check_local();
            owner.drops.fetch_add(1, Ordering::Relaxed);
        }

        const VTABLE: RawWakerVTable =
            RawWakerVTable::new(Self::clone, Self::wake, Self::wake_by_ref, Self::drop);

        fn waker(self: &Arc<Self>) -> Waker {
            let raw = RawWaker::new(Arc::into_raw(self.clone()).cast(), &Self::VTABLE);
            // SAFETY: The vtable consistently owns or borrows one Arc reference
            // and Reentrant contains only thread-safe atomic state.
            unsafe { Waker::from_raw(raw) }
        }
    }

    #[test]
    fn observer_clone_wake_and_drop_run_outside_local_borrows() {
        let callbacks = Arc::new(Reentrant {
            clones: AtomicUsize::new(0),
            wakes: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
        });
        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut operation = send(fd);
            let waker = callbacks.waker();
            let mut cx = Context::from_waker(&waker);
            assert!(operation.poll_unpin(&mut cx).is_pending());
            // Refreshing displaces the first observer. The deferred destructor
            // must run without keeping the operation slab borrowed.
            assert!(operation.poll_unpin(&mut cx).is_pending());
            while callbacks.wakes.load(Ordering::Relaxed) == 0 {
                reschedule().await;
            }
            assert!(operation.poll_unpin(&mut cx).is_ready());
            drop(waker);
        });
        assert_eq!(callbacks.clones.load(Ordering::Relaxed), 3);
        assert_eq!(callbacks.wakes.load(Ordering::Relaxed), 1);
        assert_eq!(callbacks.drops.load(Ordering::Relaxed), 3);
        assert_eq!(Arc::strong_count(&callbacks), 1);
    }

    fn runner() -> Runner {
        Runner::new(Config::default().with_ring_config(RingConfig {
            size: 1,
            ..Default::default()
        }))
    }

    fn socket() -> (Arc<OwnedFd>, UnixStream) {
        let (local, peer) = UnixStream::pair().unwrap();
        local.set_nonblocking(true).unwrap();
        (Arc::new(local.into()), peer)
    }

    fn send(fd: Arc<OwnedFd>) -> Operation {
        Operation::new(Request::Send(SendRequest {
            fd,
            write: IoBufs::from(vec![1]).into(),
            deadline: None,
            result: None,
        }))
    }

    fn recv(fd: Arc<OwnedFd>, deadline: Option<std::time::Instant>) -> Operation {
        Operation::new(Request::Recv(RecvRequest {
            fd,
            buf: IoBufMut::with_capacity(1),
            offset: 0,
            len: 1,
            exact: true,
            deadline,
            result: None,
        }))
    }

    #[test]
    fn completed_unpolled_operation_releases_capacity_one() {
        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut first = send(fd.clone());
            assert!(poll!(&mut first).is_pending());
            while runtime::current()
                .unwrap()
                .borrow()
                .driver
                .as_ref()
                .unwrap()
                .free_slots()
                == 0
            {
                reschedule().await;
            }
            // The first output remains retained while another request acquires
            // the sole waiter, completes, and releases that waiter again.
            assert!(matches!(send(fd).await, Ok(RequestOutput::Send(Ok(())))));
            assert!(matches!(first.await, Ok(RequestOutput::Send(Ok(())))));
        });
    }

    #[test]
    fn admission_deadline_and_timer_progress_with_full_ring() {
        runner().start(|context| async move {
            let (fd, _peer) = socket();
            let mut first = recv(fd.clone(), None);
            assert!(poll!(&mut first).is_pending());
            let deadline = std::time::Instant::now() + Duration::from_millis(10);
            let waiting = recv(fd, Some(deadline));
            assert!(matches!(
                waiting.await,
                Ok(RequestOutput::Recv(Err((_, Error::Timeout))))
            ));
            // An untimed admitted receive still owns the only waiter. Sleep
            // registration and expiry must not depend on obtaining that slot.
            context.sleep(Duration::from_millis(1)).await;
            drop(first);
        });
    }

    #[test]
    fn foreign_drop_orphans_registered_request() {
        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut operation = recv(fd, None);
            assert!(poll!(&mut operation).is_pending());
            std::thread::spawn(move || drop(operation)).join().unwrap();
            while runtime::current()
                .unwrap()
                .borrow()
                .driver
                .as_ref()
                .unwrap()
                .free_slots()
                == 0
            {
                reschedule().await;
            }
        });
    }

    #[test]
    fn escaped_operation_observes_worker_closure() {
        let (operation,) = runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut operation = recv(fd, None);
            assert!(poll!(&mut operation).is_pending());
            (operation,)
        });
        assert!(matches!(
            futures::executor::block_on(operation),
            Err(Error::Closed)
        ));
    }

    #[test]
    fn foreign_poll_rejection_keeps_cancellation_identity() {
        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut operation = recv(fd, None);
            assert!(poll!(&mut operation).is_pending());
            let rejected = std::thread::spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    operation.poll_unpin(&mut Context::from_waker(Waker::noop()))
                }));
                assert!(result.is_err());
                // Drop must still publish the original registration identity
                // after a caller catches the unsupported migration attempt.
                drop(operation);
            });
            rejected.join().unwrap();
            while runtime::current()
                .unwrap()
                .borrow()
                .driver
                .as_ref()
                .unwrap()
                .free_slots()
                == 0
            {
                reschedule().await;
            }
        });
    }

    #[test]
    fn retained_result_survives_waiter_reuse() {
        let mut operations = Operations::default();
        let first = operations.reserve();
        let waiter = WaiterId::new(0, 0);
        operations.insert(first, waiter, Waker::noop().clone());
        let old = mem::replace(
            operations.get_mut(first).unwrap(),
            EntryState::Ready(RequestOutput::Send(Ok(()))),
        );
        drop(old);

        // The next operation can use the same bounded waiter while the earlier
        // output remains in its independent observer slot.
        let second = operations.reserve();
        operations.insert(second, WaiterId::new(0, 1), Waker::noop().clone());
        assert_ne!(first, second);
        assert!(matches!(
            operations.take(first),
            Some(EntryState::Ready(RequestOutput::Send(Ok(()))))
        ));
        assert!(matches!(
            operations.get_mut(second),
            Some(EntryState::Pending { .. })
        ));
    }

    #[test]
    fn delayed_drop_cannot_alias_recycled_result_slot() {
        let mut operations = Operations::default();
        let first = operations.reserve();
        operations.insert(first, WaiterId::new(0, 0), Waker::noop().clone());
        drop(operations.take(first));
        let second = operations.reserve();
        operations.insert(second, WaiterId::new(0, 1), Waker::noop().clone());
        assert_eq!(first.index, second.index);
        assert_ne!(first.generation, second.generation);
        assert!(operations.take(first).is_none());
        assert!(operations.get_mut(second).is_some());
    }

    #[test]
    fn exhausted_result_generation_retires_slot() {
        let mut operations = Operations::default();
        let id = operations.reserve();
        operations.insert(id, WaiterId::new(0, 0), Waker::noop().clone());
        operations.entries[id.index].generation = u64::MAX;
        drop(operations.take(OperationId {
            generation: u64::MAX,
            ..id
        }));
        assert_ne!(operations.reserve().index, id.index);
    }
}
