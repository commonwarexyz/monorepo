//! Small worker-affine handles for registered I/O.
//!
//! Adapters register requests inside their async bodies, then await an
//! [`Operation`] containing only its waiter ID and weak worker identity.
//! The driver retains both pending requests and completed results in one slab.
//! Foreign destruction publishes cancellation to the owning worker.

use super::{
    mailbox::{Mailbox, Message},
    request::{Request, RequestOutput, SyncRequest},
    runtime::{self, Local},
    waiter::{Observation, Observer, WaiterId},
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
    task::{Context, Poll},
};

/// Registration identity retained until observation ends.
enum State {
    /// Registered on a worker and awaiting its retained result.
    Waiting {
        /// Weak identity of the owning worker, checked before every poll.
        mailbox: Weak<Mailbox>,
        /// Slot holding the pending request or its retained result.
        waiter_id: WaiterId,
    },
    /// Registration was rejected because the worker was closing.
    Closed,
    /// The result was taken or the registration was released.
    Done,
}

/// Ordinary completion handle with no inline request storage.
pub(crate) struct Operation {
    /// Registration identity, or the terminal state once observation ends.
    state: State,
}

impl Operation {
    /// Register on the current worker and return a handle to its result.
    ///
    /// Call this inside the adapter's async body so creating an I/O future
    /// remains lazy. The request is transferred before this handle is awaited.
    pub(crate) fn register(request: Request) -> Self {
        let owner = runtime::current().expect("io_uring I/O requires a current worker");
        let mut local = owner.borrow_mut();
        if local.closing {
            drop(local);
            drop(request);
            return Self {
                state: State::Closed,
            };
        }
        let expired = request
            .deadline()
            .is_some_and(|deadline| deadline <= local.now);
        let mailbox = Arc::downgrade(&local.mailbox);
        let Local {
            driver, deferred, ..
        } = &mut *local;
        let driver = driver.as_mut().unwrap();
        let waiter_id = driver.admit(request, Observer::Ordinary(None));
        if expired {
            driver.expire(waiter_id, deferred);
        }
        Self {
            state: State::Waiting { mailbox, waiter_id },
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
        // Validate affinity before changing ownership, so a rejected foreign
        // poll retains the identity needed by Drop.
        let (owner, waiter_id) = match &this.state {
            State::Waiting { mailbox, waiter_id } => match bound(mailbox) {
                Ok(owner) => (owner, *waiter_id),
                Err(error) => {
                    drop(Self {
                        state: mem::replace(&mut this.state, State::Done),
                    });
                    return Poll::Ready(Err(error));
                }
            },
            State::Closed => {
                this.state = State::Done;
                return Poll::Ready(Err(Error::Closed));
            }
            State::Done => panic!("io_uring operation polled after completion"),
        };
        let mut incoming = None;
        loop {
            let mut local = owner.borrow_mut();
            if local.closing {
                local.deferred.drops.extend(incoming);
                drop(local);
                drop(Self {
                    state: mem::replace(&mut this.state, State::Done),
                });
                return Poll::Ready(Err(Error::Closed));
            }
            let Local {
                driver, deferred, ..
            } = &mut *local;
            let driver = driver.as_mut().unwrap();
            match driver.observe(waiter_id, cx.waker()) {
                Observation::Ready(output) => {
                    this.state = State::Done;
                    deferred.drops.extend(incoming);
                    return Poll::Ready(Ok(output));
                }
                Observation::Pending => {
                    deferred.drops.extend(incoming);
                    return Poll::Pending;
                }
                Observation::Refresh => {
                    if let Some(waker) = incoming.take() {
                        deferred.drops.extend(driver.set_waker(waiter_id, waker));
                        return Poll::Pending;
                    }
                }
            }
            // A clone can reenter and finish this request, or panic. Keep its
            // identity intact and inspect the slot again after the callback.
            drop(local);
            incoming = Some(cx.waker().clone());
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if let State::Waiting { mailbox, waiter_id } = mem::replace(&mut self.state, State::Done) {
            cancel(&mailbox, Message::Orphan(waiter_id));
        }
    }
}

/// Transfer a sync to its worker and return its independent completion receiver.
pub(crate) fn start_sync(request: SyncRequest) -> oneshot::Receiver<Result<(), Error>> {
    let owner = runtime::current().expect("io_uring sync requires a current worker");
    let (sender, receiver) = oneshot::channel();
    let mut local = owner.borrow_mut();
    if local.closing {
        // Release the request and publish closure outside the local borrow.
        drop(local);
        drop(request);
        let _ = sender.send(Err(Error::Closed));
    } else {
        local
            .driver
            .as_mut()
            .unwrap()
            .admit(Request::Sync(request), Observer::DetachedSync(sender));
    }
    receiver
}

/// Route destruction locally without weak upgrade, or publish to a foreign owner.
pub(super) fn cancel(mailbox: &Weak<Mailbox>, message: Message) {
    if let Some(local) = runtime::current() {
        let mut local = local.borrow_mut();
        if std::ptr::eq(Arc::as_ptr(&local.mailbox), mailbox.as_ptr()) {
            match message {
                Message::Orphan(id) => local.orphan(id),
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
        task::{RawWaker, RawWakerVTable, Waker},
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
    fn test_start_sync_returns_without_cloning_an_admission_waker() {
        let callbacks = Arc::new(Reentrant::default());
        runner().start(|context| async move {
            let (blob, _) = context.open("observer_sync", b"file").await.unwrap();
            let (fd, _peer) = socket();
            let mut blocker = recv(fd, None);
            assert!(poll!(&mut blocker).is_pending());
            reschedule().await;

            // The only in-flight slot is occupied, but sync accepts ownership now.
            let mut sync = Box::pin(blob.start_sync());
            let waker = callbacks.waker();
            let Poll::Ready(handle) = sync.poll_unpin(&mut Context::from_waker(&waker)) else {
                panic!("sync must return its completion handle on the first poll");
            };
            assert_eq!(callbacks.clones.load(Ordering::Relaxed), 0);
            assert_eq!(callbacks.wakes.load(Ordering::Relaxed), 0);
            drop(blocker);
            handle.await.unwrap();
        });
    }

    #[test]
    fn test_observer_clone_reentry_rechecks_expired_registrations() {
        for sleep_first in [false, true] {
            let callbacks = Arc::new(Reentrant {
                on_clone: Some(|| {
                    let owner = runtime::current().unwrap();
                    let mut local = owner.borrow_mut();
                    local.now += Duration::from_secs(120);
                    let Local {
                        driver,
                        deferred,
                        now,
                        ..
                    } = &mut *local;
                    driver
                        .as_mut()
                        .unwrap()
                        .service(*now, false, deferred)
                        .unwrap();
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
    fn test_sleep_clone_panic_preserves_registration_cancellation() {
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
    fn test_pending_observers_retain_equivalent_wakers() {
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
    fn test_ready_observer_does_not_clone_unused_waker() {
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
    fn test_observer_clone_wake_and_drop_run_outside_local_borrows() {
        let callbacks = Arc::new(Reentrant::default());
        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut operation = send(fd);
            let waker = callbacks.waker();
            let mut cx = Context::from_waker(&waker);
            assert!(operation.poll_unpin(&mut cx).is_pending());
            // Refreshing displaces the first observer. The deferred destructor
            // must run without keeping the waiter slab borrowed.
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
    fn test_observer_clone_panic_preserves_queued_and_in_flight_cancellation() {
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
                reschedule().await;
                let registration = match &operation.state {
                    State::Waiting { waiter_id, .. } => *waiter_id,
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
                    State::Waiting { waiter_id, .. } => *waiter_id,
                    _ => panic!("clone panic lost cancellation identity"),
                };
                assert_eq!(retained, registration);
                // A clone panic must retain the identity needed to cancel
                // both queued and in-flight requests.
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
    fn test_observer_wake_and_drop_panics_finish_worker_retirement() {
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
        Operation::register(Request::Send(SendRequest {
            fd,
            write: IoBufs::from(vec![1]).into(),
            deadline: None,
        }))
    }

    fn recv(fd: Arc<OwnedFd>, deadline: Option<std::time::Instant>) -> Operation {
        Operation::register(Request::Recv(RecvRequest {
            fd,
            buf: IoBufMut::with_capacity(1),
            offset: 0,
            len: 1,
            exact: true,
            deadline,
        }))
    }

    #[test]
    fn test_queued_operation_completes_without_an_admission_poll() {
        let callbacks = Arc::new(Reentrant::default());
        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut blocker = recv(fd.clone(), None);
            assert!(poll!(&mut blocker).is_pending());
            reschedule().await;

            let mut queued = send(fd.clone());
            let waker = callbacks.waker();
            assert!(
                queued
                    .poll_unpin(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            drop(blocker);

            // Await another request while the queued future receives no polls.
            assert!(matches!(send(fd).await, Ok(RequestOutput::Send(Ok(())))));
            assert_eq!(callbacks.clones.load(Ordering::Relaxed), 1);
            assert_eq!(callbacks.wakes.load(Ordering::Relaxed), 1);
            assert!(
                queued
                    .poll_unpin(&mut Context::from_waker(&waker))
                    .is_ready()
            );
            assert_eq!(callbacks.clones.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn test_completed_unpolled_operation_releases_capacity_one() {
        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut first = send(fd.clone());
            assert!(poll!(&mut first).is_pending());
            while !runtime::current()
                .unwrap()
                .borrow()
                .driver
                .as_ref()
                .unwrap()
                .is_empty()
            {
                reschedule().await;
            }
            // The first output remains retained while another request uses the
            // sole in-flight slot and completes independently.
            assert!(matches!(send(fd).await, Ok(RequestOutput::Send(Ok(())))));
            assert!(matches!(first.await, Ok(RequestOutput::Send(Ok(())))));
        });
    }

    #[test]
    fn test_queued_deadline_and_timer_progress_with_full_ring() {
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
            // The untimed receive still occupies the only in-flight slot.
            // Sleeper expiry must also progress independently of that slot.
            context.sleep(Duration::from_millis(1)).await;
            drop(first);
        });
    }

    #[test]
    fn test_foreign_drop_orphans_registered_request() {
        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut operation = recv(fd, None);
            assert!(poll!(&mut operation).is_pending());
            std::thread::spawn(move || drop(operation)).join().unwrap();
            while !runtime::current()
                .unwrap()
                .borrow()
                .driver
                .as_ref()
                .unwrap()
                .is_empty()
            {
                reschedule().await;
            }
        });
    }

    #[test]
    fn test_escaped_operation_observes_worker_closure() {
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
    fn test_foreign_poll_rejection_keeps_cancellation_identity() {
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
            while !runtime::current()
                .unwrap()
                .borrow()
                .driver
                .as_ref()
                .unwrap()
                .is_empty()
            {
                reschedule().await;
            }
        });
    }
}
