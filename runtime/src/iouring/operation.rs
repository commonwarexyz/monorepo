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
    mailbox::{Mailbox, Message},
    request::{Request, RequestOutput},
    runtime::{self, Local},
    slab::{Id, Slab},
    waiter::{Observer, WaiterId},
};
use crate::Error;
use commonware_utils::channel::oneshot;
use std::{
    cell::RefCell,
    future::Future,
    mem,
    pin::Pin,
    rc::Rc,
    sync::{Arc, Weak},
    task::{Context, Poll, Waker},
};

/// Full-width observer identity, independent of the kernel's packed waiter ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OperationId(pub(super) Id);

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

/// Ordinary observer state owned exclusively by one worker.
#[derive(Default)]
pub(super) struct Operations {
    /// Growable result storage that is not bounded by ring capacity.
    entries: Slab<EntryState>,
}

impl Operations {
    /// Select the observer identity before pairing it with a driver waiter.
    fn next_id(&self) -> OperationId {
        OperationId(self.entries.next_id())
    }

    /// Install the waiter association before releasing the local borrow.
    fn insert(&mut self, id: OperationId, waiter_id: WaiterId, waker: Waker) {
        self.entries.insert_at(
            id.0,
            EntryState::Pending {
                waiter_id,
                waker: Some(waker),
            },
        );
    }

    /// Inspect a live full-width identity without following stale waiter IDs.
    fn get_mut(&mut self, id: OperationId) -> Option<&mut EntryState> {
        self.entries.get_mut(id.0)
    }

    /// Recycle only the observer slot, returning all owned values untouched.
    fn take(&mut self, id: OperationId) -> Option<EntryState> {
        self.entries.remove(id.0)
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
        let mut incoming = None;
        loop {
            let mut local = owner.borrow_mut();
            if local.closing {
                if let Some(incoming) = incoming {
                    local.deferred.drops.push(incoming);
                }
                drop(local);
                drop(Self {
                    state: mem::replace(&mut this.state, State::Done),
                });
                return Poll::Ready(Err(Error::Closed));
            }
            match &this.state {
                State::Waiting { operation_id, .. } => {
                    match local
                        .operations
                        .get_mut(*operation_id)
                        .expect("live operation entry missing")
                    {
                        EntryState::Ready(_) => {
                            let Some(EntryState::Ready(output)) =
                                local.operations.take(*operation_id)
                            else {
                                unreachable!()
                            };
                            this.state = State::Done;
                            if let Some(incoming) = incoming {
                                local.deferred.drops.push(incoming);
                            }
                            return Poll::Ready(Ok(output));
                        }
                        EntryState::Pending { waker, .. } => {
                            if incoming.is_none()
                                && waker
                                    .as_ref()
                                    .is_some_and(|waker| waker.will_wake(cx.waker()))
                            {
                                return Poll::Pending;
                            }
                        }
                    }
                }
                State::Unbound(request) | State::Admitting { request, .. } => {
                    if request
                        .deadline()
                        .is_some_and(|deadline| deadline <= local.now)
                    {
                        let request = match mem::replace(&mut this.state, State::Done) {
                            State::Unbound(request) => request,
                            State::Admitting {
                                request,
                                registration,
                                ..
                            } => {
                                local.cancel_admission(registration);
                                request
                            }
                            _ => unreachable!(),
                        };
                        let (output, retired) = request.timeout();
                        local.deferred.resources.push(retired);
                        if let Some(incoming) = incoming {
                            local.deferred.drops.push(incoming);
                        }
                        return Poll::Ready(Ok(output));
                    }
                    local.reconcile_admissions();
                    if let State::Admitting { registration, .. } = &this.state
                        && !local.admissions.is_granted(*registration)
                        && incoming.is_none()
                        && local.admissions.will_wake(*registration, cx.waker())
                    {
                        return Poll::Pending;
                    }
                }
                State::Done => unreachable!(),
            }
            let Some(incoming) = incoming.take() else {
                // Keep cancellation identity through a clone panic. Reentry can
                // complete or expire this registration, so inspect it again.
                drop(local);
                incoming = Some(cx.waker().clone());
                continue;
            };
            let (request, mailbox, registration) = match mem::replace(&mut this.state, State::Done)
            {
                State::Unbound(request) => (request, Arc::downgrade(&local.mailbox), None),
                State::Admitting {
                    request,
                    mailbox,
                    registration,
                } => (request, mailbox, Some(registration)),
                State::Waiting {
                    mailbox,
                    operation_id,
                } => {
                    let Some(EntryState::Pending { waker, .. }) =
                        local.operations.get_mut(operation_id)
                    else {
                        unreachable!()
                    };
                    if let Some(old) = waker.replace(incoming) {
                        local.deferred.drops.push(old);
                    }
                    this.state = State::Waiting {
                        mailbox,
                        operation_id,
                    };
                    return Poll::Pending;
                }
                State::Done => unreachable!(),
            };
            // A grant already owns capacity. Fresh callers may only use capacity
            // left after older registrations received their FIFO reservations.
            let granted = match registration {
                Some(id) => match local.admissions.take_grant(id) {
                    Ok(old) => {
                        if let Some(old) = old {
                            local.deferred.drops.push(old);
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
                let id = local.operations.next_id();
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
                let id = match registration {
                    Some(id) => {
                        let old = local
                            .admissions
                            .refresh(id, incoming)
                            .expect("live admission missing");
                        if let Some(old) = old {
                            local.deferred.drops.push(old);
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
            return Poll::Pending;
        }
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
                drop(request);
            }
            State::Waiting {
                mailbox,
                operation_id,
            } => cancel(&mailbox, Message::OrphanOperation(operation_id)),
            State::Unbound(request) => drop(request),
            State::Done => {}
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
        if this.mailbox.is_none() {
            let owner = runtime::current().expect("io_uring sync requires a current worker");
            this.mailbox = Some(Arc::downgrade(&owner.borrow().mailbox));
        }
        let owner = bound(this.mailbox.as_ref().unwrap());
        if let Ok(owner) = owner {
            let mut incoming = None;
            loop {
                let mut local = owner.borrow_mut();
                if local.closing {
                    if let Some(incoming) = incoming {
                        local.deferred.drops.push(incoming);
                    }
                    if let Some(id) = this.registration.take() {
                        local.cancel_admission(id);
                    }
                    break;
                }
                local.reconcile_admissions();
                let granted = match this.registration {
                    Some(id) => match local.admissions.take_grant(id) {
                        Ok(old) => {
                            if let Some(old) = old {
                                local.deferred.drops.push(old);
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
                    if let Some(incoming) = incoming {
                        local.deferred.drops.push(incoming);
                    }
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
                if incoming.is_none()
                    && this
                        .registration
                        .is_some_and(|id| local.admissions.will_wake(id, cx.waker()))
                {
                    return Poll::Pending;
                }
                let Some(incoming) = incoming.take() else {
                    drop(local);
                    incoming = Some(cx.waker().clone());
                    continue;
                };
                this.registration = Some(match this.registration {
                    Some(id) => {
                        let old = local
                            .admissions
                            .refresh(id, incoming)
                            .expect("sync admission missing");
                        if let Some(old) = old {
                            local.deferred.drops.push(old);
                        }
                        id
                    }
                    None => local.admissions.register(None, incoming),
                });
                return Poll::Pending;
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
                    if let Some(waker) = local.timers.cancel(id) {
                        local.deferred.drops.push(waker);
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
        self.admissions
            .reconcile(self.now, free, &mut self.deferred.wakes);
    }

    /// Release an admission reservation and immediately grant its successor.
    pub(super) fn cancel_admission(&mut self, id: AdmissionId) {
        if let Some(waker) = self.admissions.cancel(id) {
            self.deferred.drops.push(waker);
        }
        if !self.closing {
            self.reconcile_admissions();
        }
    }

    /// Detach an observer before changing its waiter's cancellation state.
    pub(super) fn orphan_operation(&mut self, id: OperationId) {
        match self.operations.take(id) {
            Some(EntryState::Pending { waiter_id, waker }) => {
                if let Some(waker) = waker {
                    self.deferred.drops.push(waker);
                }
                self.driver
                    .as_mut()
                    .expect("driver present during orphaning")
                    .orphan(waiter_id, id, &mut self.completed);
                self.apply_completions();
            }
            Some(EntryState::Ready(output)) => self.deferred.outputs.push(output),
            None => {}
        }
    }

    /// Transfer terminal results out of bounded waiter capacity before waking.
    pub(super) fn apply_completions(&mut self) {
        for completed in self.completed.drain(..) {
            self.deferred.resources.push(completed.retired);
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
                        self.deferred.wakes.push(waker);
                    }
                }
                Observer::DetachedSync(sender) => {
                    let RequestOutput::Sync(output) = completed.output else {
                        panic!("sync observer received other request")
                    };
                    self.deferred.sync_results.push((sender, output));
                }
                Observer::Orphaned => self.deferred.outputs.push(completed.output),
            }
        }
        if !self.closing {
            self.reconcile_admissions();
        }
    }

    /// Remove all ordinary observers, including futures retained outside workers.
    pub(super) fn close_operations(&mut self) {
        for index in 0..self.operations.entries.slots_len() {
            if let Some(id) = self.operations.entries.id_at(index) {
                self.orphan_operation(OperationId(id));
            }
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
        Blob as _, Clock as _, IoBufMut, IoBufs, Runner as _, Storage as _,
        iouring::{Config, RingConfig, Runner},
        utils::{extract_panic_message, reschedule},
    };
    use futures::{FutureExt as _, poll};
    use std::{
        os::{fd::OwnedFd, unix::net::UnixStream},
        panic::{AssertUnwindSafe, catch_unwind},
        sync::atomic::{AtomicUsize, Ordering},
        task::{RawWaker, RawWakerVTable},
        time::Duration,
    };

    /// Arbitrary waker callbacks that reenter the current worker's local state.
    #[derive(Default)]
    struct Reentrant {
        clones: AtomicUsize,
        wakes: AtomicUsize,
        drops: AtomicUsize,
        panic_callback: AtomicUsize,
        on_clone: Option<fn()>,
    }

    impl Reentrant {
        const CLONE: usize = 1;
        const WAKE: usize = 2;
        const DROP: usize = 3;

        fn panic_once(&self, callback: usize) {
            if self
                .panic_callback
                .compare_exchange(callback, 0, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                panic!("waker callback panic {callback}");
            }
        }

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
            owner.panic_once(Self::CLONE);
            if let Some(on_clone) = owner.on_clone {
                on_clone();
            }
            RawWaker::new(Arc::into_raw(Arc::clone(&owner)).cast(), &Self::VTABLE)
        }

        unsafe fn wake(data: *const ()) {
            // SAFETY: Consuming wake takes exactly the Arc reference owned by
            // this raw waker. No reference is reconstructed a second time.
            let owner = unsafe { Arc::from_raw(data.cast::<Self>()) };
            Self::check_local();
            owner.wakes.fetch_add(1, Ordering::Relaxed);
            owner.panic_once(Self::WAKE);
        }

        unsafe fn wake_by_ref(data: *const ()) {
            // SAFETY: The waker retains its Arc reference after this callback,
            // so the temporary reconstructed Arc must not decrement it.
            let owner = mem::ManuallyDrop::new(unsafe { Arc::from_raw(data.cast::<Self>()) });
            Self::check_local();
            owner.wakes.fetch_add(1, Ordering::Relaxed);
            owner.panic_once(Self::WAKE);
        }

        unsafe fn drop(data: *const ()) {
            // SAFETY: Raw-waker destruction consumes its one owned Arc reference.
            let owner = unsafe { Arc::from_raw(data.cast::<Self>()) };
            Self::check_local();
            owner.drops.fetch_add(1, Ordering::Relaxed);
            owner.panic_once(Self::DROP);
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
    fn sync_admission_clones_only_changed_pending_observers() {
        for queued in [false, true] {
            let callbacks = Arc::new(Reentrant::default());
            runner().start(|context| async move {
                let (blob, _) = context.open("observer_sync", b"file").await.unwrap();
                let (fd, _peer) = socket();
                let mut blocker = queued.then(|| recv(fd, None));
                if let Some(blocker) = &mut blocker {
                    assert!(poll!(blocker).is_pending());
                }
                let mut admission = Box::pin(blob.start_sync());
                let waker = callbacks.waker();
                let mut cx = Context::from_waker(&waker);
                if queued {
                    assert!(admission.poll_unpin(&mut cx).is_pending());
                    assert!(admission.poll_unpin(&mut cx).is_pending());
                    assert_eq!(callbacks.clones.load(Ordering::Relaxed), 1);
                    drop(blocker);
                    while callbacks.wakes.load(Ordering::Relaxed) == 0 {
                        reschedule().await;
                    }
                }
                let Poll::Ready(handle) = admission.poll_unpin(&mut cx) else {
                    panic!("available sync admission must complete");
                };
                assert_eq!(
                    callbacks.clones.load(Ordering::Relaxed),
                    usize::from(queued)
                );
                handle.await.unwrap();
            });
        }
    }

    #[test]
    fn observer_clone_reentry_rechecks_expired_registrations() {
        for sleep_first in [false, true] {
            let callbacks = Arc::new(Reentrant {
                on_clone: Some(|| {
                    let owner = runtime::current().unwrap();
                    let mut local = owner.borrow_mut();
                    local.now += Duration::from_secs(120);
                    local.reconcile_admissions();
                    let Local {
                        now,
                        timers,
                        deferred,
                        ..
                    } = &mut *local;
                    timers.expire(*now, &mut deferred.wakes);
                }),
                ..Default::default()
            });
            runner().start(|_| async {
                let (fd, _peer) = socket();
                let mut blocker = recv(fd.clone(), None);
                assert!(poll!(&mut blocker).is_pending());
                let mut queued = recv(
                    fd,
                    Some(std::time::Instant::now() + Duration::from_secs(60)),
                );
                let mut sleep = super::super::sleep::Sleep::new(Duration::from_secs(60));
                assert!(poll!(&mut queued).is_pending());
                assert!(poll!(&mut sleep).is_pending());
                let waker = callbacks.waker();
                let mut cx = Context::from_waker(&waker);
                if sleep_first {
                    assert!(sleep.poll_unpin(&mut cx).is_ready());
                }
                assert!(matches!(
                    queued.poll_unpin(&mut cx),
                    Poll::Ready(Ok(RequestOutput::Recv(Err((_, Error::Timeout)))))
                ));
                assert!(sleep.poll_unpin(&mut cx).is_ready());
                assert_eq!(callbacks.clones.load(Ordering::Relaxed), 1);
            });
        }
    }

    #[test]
    fn sleep_clone_panic_preserves_registration_cancellation() {
        runner().start(|_| async {
            let mut sleep = super::super::sleep::Sleep::new(Duration::from_secs(60));
            let registered = Arc::new(Reentrant::default());
            let registered_waker = registered.waker();
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&registered_waker))
                    .is_pending()
            );
            let callbacks = Arc::new(Reentrant::default());
            callbacks
                .panic_callback
                .store(Reentrant::CLONE, Ordering::Relaxed);
            let waker = callbacks.waker();
            let panic = catch_unwind(AssertUnwindSafe(|| {
                let _ = sleep.poll_unpin(&mut Context::from_waker(&waker));
            }))
            .expect_err("changed sleep observer must clone");
            assert_eq!(extract_panic_message(&*panic), "waker callback panic 1");
            drop(sleep);
            reschedule().await;
            assert_eq!(registered.drops.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn pending_observers_retain_equivalent_wakers() {
        let callbacks = Arc::new(Reentrant::default());
        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut admitted = recv(fd.clone(), None);
            let mut queued = recv(fd, None);
            let mut sleep = super::super::sleep::Sleep::new(Duration::from_secs(60));
            let waker = callbacks.waker();
            let mut cx = Context::from_waker(&waker);
            assert!(admitted.poll_unpin(&mut cx).is_pending());
            assert!(queued.poll_unpin(&mut cx).is_pending());
            assert!(sleep.poll_unpin(&mut cx).is_pending());
            let clones = callbacks.clones.load(Ordering::Relaxed);
            assert!(admitted.poll_unpin(&mut cx).is_pending());
            assert!(queued.poll_unpin(&mut cx).is_pending());
            assert!(sleep.poll_unpin(&mut cx).is_pending());
            assert_eq!(callbacks.clones.load(Ordering::Relaxed), clones);
        });
    }

    #[test]
    fn ready_observer_does_not_clone_unused_waker() {
        let callbacks = Arc::new(Reentrant::default());
        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut operation = send(fd);
            let waker = callbacks.waker();
            let mut cx = Context::from_waker(&waker);
            assert!(operation.poll_unpin(&mut cx).is_pending());
            while callbacks.wakes.load(Ordering::Relaxed) == 0 {
                reschedule().await;
            }
            let clones = callbacks.clones.load(Ordering::Relaxed);
            assert!(operation.poll_unpin(&mut cx).is_ready());
            assert_eq!(callbacks.clones.load(Ordering::Relaxed), clones);
        });
    }

    #[test]
    fn observer_clone_wake_and_drop_run_outside_local_borrows() {
        let callbacks = Arc::new(Reentrant::default());
        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut operation = send(fd);
            let waker = callbacks.waker();
            let mut cx = Context::from_waker(&waker);
            assert!(operation.poll_unpin(&mut cx).is_pending());
            // Refreshing displaces the first observer. The deferred destructor
            // must run without keeping the operation slab borrowed.
            assert!(
                operation
                    .poll_unpin(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            assert!(operation.poll_unpin(&mut cx).is_pending());
            while callbacks.wakes.load(Ordering::Relaxed) == 0 {
                reschedule().await;
            }
            assert!(operation.poll_unpin(&mut cx).is_ready());
            drop(waker);
        });
        assert_eq!(callbacks.clones.load(Ordering::Relaxed), 2);
        assert_eq!(callbacks.wakes.load(Ordering::Relaxed), 1);
        assert_eq!(callbacks.drops.load(Ordering::Relaxed), 2);
        assert_eq!(Arc::strong_count(&callbacks), 1);
    }

    #[test]
    fn observer_clone_panic_preserves_queued_and_admitted_cancellation() {
        for queued in [false, true] {
            let callbacks = Arc::new(Reentrant::default());
            let (fd, _peer) = socket();
            runner().start(|_| async {
                let mut blocker = queued.then(|| recv(fd.clone(), None));
                if let Some(blocker) = &mut blocker {
                    assert!(poll!(blocker).is_pending());
                }
                let mut operation = recv(fd.clone(), None);
                let waker = callbacks.waker();
                let mut cx = Context::from_waker(&waker);
                assert!(poll!(&mut operation).is_pending());
                let registration = match &operation.state {
                    State::Admitting { registration, .. } => (Some(*registration), None),
                    State::Waiting { operation_id, .. } => (None, Some(*operation_id)),
                    _ => panic!("operation did not register"),
                };
                callbacks
                    .panic_callback
                    .store(Reentrant::CLONE, Ordering::Relaxed);
                let panic = catch_unwind(AssertUnwindSafe(|| {
                    let _ = operation.poll_unpin(&mut cx);
                }))
                .expect_err("observer clone must panic");
                assert_eq!(extract_panic_message(&*panic), "waker callback panic 1");
                let retained = match &operation.state {
                    State::Admitting { registration, .. } if queued => (Some(*registration), None),
                    State::Waiting { operation_id, .. } if !queued => (None, Some(*operation_id)),
                    _ => panic!("clone panic lost cancellation identity"),
                };
                assert_eq!(retained, registration);
                // Dropping after the caught poll failure must return both the
                // queued grant and any admitted waiter to the size-one driver.
                drop(operation);
                drop(blocker);
                assert!(matches!(
                    send(fd.clone()).await,
                    Ok(RequestOutput::Send(Ok(())))
                ));
            });
            assert_eq!(Arc::strong_count(&fd), 1);
            assert_eq!(Arc::strong_count(&callbacks), 1);
        }
    }

    #[test]
    fn observer_wake_and_drop_panics_finish_worker_retirement() {
        for callback in [Reentrant::WAKE, Reentrant::DROP] {
            let callbacks = Arc::new(Reentrant::default());
            let (fd, _peer) = socket();
            let mut retained_local = None;
            let panic = catch_unwind(AssertUnwindSafe(|| {
                runner().start(|_| async {
                    retained_local = runtime::current();
                    let mut operation = if callback == Reentrant::WAKE {
                        send(fd.clone())
                    } else {
                        recv(fd.clone(), None)
                    };
                    let waker = callbacks.waker();
                    let mut cx = Context::from_waker(&waker);
                    assert!(operation.poll_unpin(&mut cx).is_pending());
                    callbacks.panic_callback.store(callback, Ordering::Relaxed);
                    if callback == Reentrant::DROP {
                        // Replacing an observer queues its destructor. The
                        // receive stays pending until failure cleanup cancels it.
                        assert!(
                            operation
                                .poll_unpin(&mut Context::from_waker(Waker::noop()))
                                .is_pending()
                        );
                    }
                    futures::future::pending::<()>().await;
                });
            }))
            .expect_err("deferred observer callback must fail the runner");
            assert_eq!(
                extract_panic_message(&*panic),
                format!("waker callback panic {callback}")
            );
            let local = retained_local.unwrap();
            let local = local.borrow();
            assert_eq!(local.operations.entries.len(), 0);
            assert!(local.driver.is_none());
            assert!(runtime::current().is_none());
            assert_eq!(Arc::strong_count(&fd), 1);
            assert_eq!(Arc::strong_count(&callbacks), 1);
        }
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
        let first = operations.next_id();
        let waiter = WaiterId::new(0, 0);
        operations.insert(first, waiter, Waker::noop().clone());
        let old = mem::replace(
            operations.get_mut(first).unwrap(),
            EntryState::Ready(RequestOutput::Send(Ok(()))),
        );
        drop(old);

        // The next operation can use the same bounded waiter while the earlier
        // output remains in its independent observer slot.
        let second = operations.next_id();
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
        let first = operations.next_id();
        operations.insert(first, WaiterId::new(0, 0), Waker::noop().clone());
        drop(operations.take(first));
        let second = operations.next_id();
        operations.insert(second, WaiterId::new(0, 1), Waker::noop().clone());
        assert_eq!(first.0.index, second.0.index);
        assert_ne!(first.0.generation, second.0.generation);
        assert!(operations.take(first).is_none());
        assert!(operations.get_mut(second).is_some());
    }

    #[test]
    fn exhausted_result_generation_retires_slot() {
        let mut operations = Operations::default();
        let id = operations.next_id();
        operations.insert(id, WaiterId::new(0, 0), Waker::noop().clone());
        let exhausted = OperationId(operations.entries.set_generation(id.0, u64::MAX));
        drop(operations.take(exhausted));
        assert_ne!(operations.next_id().0.index, id.0.index);
    }
}
