//! Completion handles for I/O registered on one worker.
//!
//! Adapters register requests inside their async bodies, then await an
//! [`Operation`] containing only its waiter ID and weak worker identity.
//! The driver retains both pending requests and completed results in one slab.
//!
//! A registered operation must be polled on its owning worker, but may be
//! dropped on any thread. Dropping it releases its observer. The driver decides
//! whether to cancel the request or finish retained work such as writes and syncs.

use super::{
    mailbox::{Mailbox, Message},
    request::{Request, RequestOutput, SyncRequest},
    runtime::Local,
    waiter::{Observation, Observer, WaiterId},
};
use crate::Error;
use commonware_utils::channel::oneshot;
use std::{
    future::Future,
    mem,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

/// Registration identity retained until observation ends.
enum State {
    /// Registered request whose result has not been consumed.
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

/// Handle to an ordinary request and its result in the worker's waiter slab.
pub(crate) struct Operation {
    /// Registration identity, or the terminal state once observation ends.
    state: State,
}

impl Operation {
    /// Register on the current worker and return a handle to its result.
    ///
    /// Call this inside the adapter's async body so creating an I/O future
    /// remains lazy. The request is transferred before this handle is awaited.
    /// A closing worker returns a handle that resolves to [`Error::Closed`].
    pub fn register(request: Request) -> Self {
        let owner = Local::current().expect("io_uring I/O requires a current worker");
        let mut local = owner.borrow_mut();

        if local.closing {
            // Request owners may run destructors that reenter the worker.
            drop(local);
            drop(request);

            return Self {
                state: State::Closed,
            };
        }

        let mailbox = Arc::downgrade(&local.mailbox);

        // The driver takes ownership even when the SQ is full. Polling installs
        // a waker only while the request is still pending.
        let Local {
            driver,
            deferred,
            now,
            ..
        } = &mut *local;
        let waiter_id =
            driver
                .as_mut()
                .unwrap()
                .admit(request, Observer::Ordinary(None), *now, deferred);

        Self {
            state: State::Waiting { mailbox, waiter_id },
        }
    }

    /// Release this observer once, routing cleanup to the owning worker.
    ///
    /// The caller must release any worker borrow before calling this method.
    fn release(&mut self) {
        if let State::Waiting { mailbox, waiter_id } = mem::replace(&mut self.state, State::Done) {
            // Orphaning also releases an already completed result. The driver
            // decides whether unfinished work must continue.
            Local::cancel(&mailbox, Message::Orphan(waiter_id));
        }
    }
}

impl Future for Operation {
    type Output = Result<RequestOutput, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // Validate affinity before changing ownership, so a rejected foreign
        // poll retains the identity needed by Drop.
        let (mailbox, waiter_id) = match &this.state {
            State::Waiting { mailbox, waiter_id } => (mailbox, *waiter_id),
            State::Closed => {
                this.state = State::Done;
                return Poll::Ready(Err(Error::Closed));
            }
            State::Done => panic!("io_uring operation polled after completion"),
        };
        let owner = match Local::bound(mailbox) {
            Ok(owner) => owner,
            Err(error) => {
                this.release();
                return Poll::Ready(Err(error));
            }
        };

        let mut local = owner.borrow_mut();
        if local.closing {
            drop(local);
            this.release();
            return Poll::Ready(Err(Error::Closed));
        }

        // Inspect before cloning: ready results and matching wakers require
        // no callback.
        match local
            .driver
            .as_mut()
            .unwrap()
            .observe(waiter_id, cx.waker())
        {
            Observation::Ready(output) => {
                this.state = State::Done;
                return Poll::Ready(Ok(output));
            }
            Observation::Pending => return Poll::Pending,
            Observation::Refresh => {}
        }

        // Worker service cannot run during this poll. Clone outside its borrow,
        // retaining the cancellation identity if the callback panics.
        drop(local);
        let waker = cx.waker().clone();
        let mut local = owner.borrow_mut();
        let Local {
            driver, deferred, ..
        } = &mut *local;
        deferred
            .drops
            .extend(driver.as_mut().unwrap().set_waker(waiter_id, waker));
        Poll::Pending
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        self.release();
    }
}

/// Transfer a sync to its worker and return its independent completion receiver.
///
/// Dropping the receiver leaves the sync running. A closing worker rejects the
/// request and publishes [`Error::Closed`] through the receiver.
pub fn start_sync(request: SyncRequest) -> oneshot::Receiver<Result<(), Error>> {
    let owner = Local::current().expect("io_uring sync requires a current worker");
    let (sender, receiver) = oneshot::channel();
    let mut local = owner.borrow_mut();
    if local.closing {
        // Release the request and publish closure outside the local borrow.
        drop(local);
        drop(request);
        let _ = sender.send(Err(Error::Closed));
    } else {
        // Registration needs no task waker. The worker publishes to this
        // channel when the sync finishes.
        let Local {
            driver,
            deferred,
            now,
            ..
        } = &mut *local;
        driver.as_mut().unwrap().admit(
            Request::Sync(request),
            Observer::DetachedSync(sender),
            *now,
            deferred,
        );
    }
    receiver
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        Blob as _, Clock as _, IoBufMut, IoBufs, Runner as _, Storage as _, WriteOptions,
        iouring::{
            Config, RingConfig, Runner,
            request::{RecvRequest, SendRequest},
            sleep::Sleep,
        },
        utils::{extract_panic_message, reschedule},
    };
    use futures::{FutureExt as _, future::pending, poll};
    use std::{
        io::Write as _,
        os::{fd::OwnedFd, unix::net::UnixStream},
        panic::{AssertUnwindSafe, catch_unwind},
        pin::pin,
        sync::atomic::{AtomicUsize, Ordering},
        task::{RawWaker, RawWakerVTable, Waker},
        thread,
        time::{Duration, Instant},
    };

    /// Arbitrary waker callbacks that reenter the current worker's local state.
    ///
    /// RawWaker exposes clone and drop as well as wake, so every callback can
    /// check for an outstanding worker borrow or inject a panic.
    #[derive(Default)]
    pub struct Reentrant {
        /// Number of cloned wakers, including clones that panic.
        clones: AtomicUsize,
        /// Number of consuming and borrowed wakes.
        wakes: AtomicUsize,
        /// Number of waker destructors invoked.
        pub drops: AtomicUsize,
        /// Callback that should panic once, or zero when no panic is armed.
        pub panic_callback: AtomicUsize,
        /// Optional action run while cloning, outside any worker borrow.
        on_clone: Option<fn()>,
    }

    impl Reentrant {
        pub const CLONE: usize = 1;
        const WAKE: usize = 2;
        const DROP: usize = 3;

        fn panic_once(&self, callback: usize) {
            // Disarm before unwinding so cleanup can use the remaining wakers.
            if self
                .panic_callback
                .compare_exchange(callback, 0, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                panic!("waker callback panic {callback}");
            }
        }

        fn check_local() {
            if let Some(local) = Local::current() {
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

        pub fn waker(self: &Arc<Self>) -> Waker {
            let raw = RawWaker::new(Arc::into_raw(self.clone()).cast(), &Self::VTABLE);
            // SAFETY: The vtable consistently owns or borrows one Arc reference
            // and Reentrant contains only thread-safe atomic state.
            unsafe { Waker::from_raw(raw) }
        }
    }

    /// Limit the driver to one in-flight request.
    fn runner() -> Runner {
        Runner::new(Config::default().with_ring_config(RingConfig {
            size: 1,
            ..Default::default()
        }))
    }

    /// Connected sockets whose local endpoint can be shared by requests.
    ///
    /// Keeping the peer open and silent blocks receives while allowing sends.
    fn socket() -> (Arc<OwnedFd>, UnixStream) {
        let (local, peer) = UnixStream::pair().unwrap();
        local.set_nonblocking(true).unwrap();
        (Arc::new(local.into()), peer)
    }

    /// Register a one-byte send on the current worker.
    fn send(fd: Arc<OwnedFd>) -> Operation {
        Operation::register(Request::Send(SendRequest {
            fd,
            write: IoBufs::from(vec![1]).into(),
            deadline: None,
        }))
    }

    /// Register a one-byte receive, optionally bounded by a deadline.
    fn recv(fd: Arc<OwnedFd>, deadline: Option<Instant>) -> Operation {
        Operation::register(Request::Recv(RecvRequest {
            fd,
            buf: IoBufMut::from([0]),
            offset: 0,
            len: 1,
            exact: true,
            deadline,
        }))
    }

    /// Service the worker until every logical request retires.
    async fn drained() {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !Local::current()
            .unwrap()
            .borrow()
            .driver
            .as_ref()
            .unwrap()
            .is_empty()
        {
            assert!(Instant::now() < deadline, "I/O did not retire");
            reschedule().await;
        }
    }

    #[test]
    fn test_start_sync_returns_while_ring_is_full() {
        let callbacks = Arc::new(Reentrant::default());

        runner().start(|context| async move {
            let (blob, _) = context.open("observer_sync", b"file").await.unwrap();
            let (fd, _peer) = socket();
            let mut blocker = recv(fd, None);
            assert!(poll!(&mut blocker).is_pending());
            reschedule().await;

            // The only in-flight slot is occupied, but sync accepts ownership now.
            let mut sync = pin!(blob.start_sync());
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
    fn test_expired_registration_does_not_consume_ready_data() {
        let callbacks = Arc::new(Reentrant::default());
        runner().start(|context| async move {
            let deadline = Instant::now();
            context.sleep(Duration::from_millis(1)).await;
            assert!(Local::current().unwrap().borrow().now >= deadline);

            let (fd, mut peer) = socket();
            peer.write_all(b"x").unwrap();
            let mut operation = recv(fd.clone(), Some(deadline));
            let waker = callbacks.waker();
            assert!(matches!(
                operation.poll_unpin(&mut Context::from_waker(&waker)),
                Poll::Ready(Ok(RequestOutput::Recv(Err((_, Error::Timeout)))))
            ));
            assert_eq!(callbacks.clones.load(Ordering::Relaxed), 0);
            assert!(
                Local::current()
                    .unwrap()
                    .borrow()
                    .driver
                    .as_ref()
                    .unwrap()
                    .is_empty()
            );

            let RequestOutput::Recv(Ok((buffer, len))) =
                recv(fd, Some(Instant::now() + Duration::from_secs(1)))
                    .await
                    .unwrap()
            else {
                panic!("expired receive consumed ready data");
            };
            assert_eq!(len, 1);
            assert_eq!(buffer.as_ref(), b"x");
        });
    }

    #[test]
    fn test_worker_closure_rejects_registration_and_polling() {
        let callbacks = Arc::new(Reentrant::default());
        runner().start(|context| async move {
            let (blob, _) = context.open("observer_closed", b"file").await.unwrap();

            // A clean open skips the sync, so record an uncovered mutation first.
            blob.write_at(0, b"x", WriteOptions::default())
                .await
                .unwrap();
            let (fd, _peer) = socket();
            let mut operation = recv(fd.clone(), None);
            let waker = callbacks.waker();
            let mut cx = Context::from_waker(&waker);

            Local::current().unwrap().borrow_mut().closing = true;
            assert!(matches!(
                operation.poll_unpin(&mut cx),
                Poll::Ready(Err(Error::Closed))
            ));
            assert_eq!(callbacks.clones.load(Ordering::Relaxed), 0);

            // New ordinary and detached requests must also reject closure.
            let mut rejected = recv(fd, None);
            assert!(matches!(
                rejected.poll_unpin(&mut cx),
                Poll::Ready(Err(Error::Closed))
            ));
            let handle = blob.start_sync().await;
            assert!(matches!(handle.await, Err(Error::Closed)));
            assert!(
                Local::current()
                    .unwrap()
                    .borrow()
                    .driver
                    .as_ref()
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    fn test_observer_clone_can_register_and_cancel_other_work() {
        for in_flight in [false, true] {
            let callbacks = Arc::new(Reentrant {
                on_clone: Some(|| {
                    let mut sleep = Sleep::new(Duration::from_secs(60));
                    let (fd, _peer) = socket();
                    let mut operation = recv(fd, None);
                    let mut cx = Context::from_waker(Waker::noop());
                    assert!(sleep.poll_unpin(&mut cx).is_pending());
                    assert!(operation.poll_unpin(&mut cx).is_pending());
                    drop(operation);
                    drop(sleep);
                }),
                ..Default::default()
            });

            runner().start(|_| async {
                let (fd, mut peer) = socket();
                let mut operation = recv(fd, Some(Instant::now() + Duration::from_secs(60)));
                let mut sleep = Sleep::new(Duration::from_secs(60));
                assert!(poll!(&mut operation).is_pending());
                assert!(poll!(&mut sleep).is_pending());
                if in_flight {
                    reschedule().await;
                }

                // Each replacement may register and cancel other identities.
                // The current registrations still need their own completion.
                let waker = callbacks.waker();
                let mut cx = Context::from_waker(&waker);
                assert!(operation.poll_unpin(&mut cx).is_pending());
                assert!(sleep.poll_unpin(&mut cx).is_pending());
                assert_eq!(callbacks.clones.load(Ordering::Relaxed), 2);

                drop(sleep);
                peer.write_all(b"x").unwrap();
                let RequestOutput::Recv(Ok((buffer, len))) = operation.await.unwrap() else {
                    panic!("receive failed after observer replacement");
                };
                assert_eq!(len, 1);
                assert_eq!(buffer.as_ref(), b"x");
            });
        }
    }

    #[test]
    fn test_pending_observers_retain_equivalent_wakers() {
        let callbacks = Arc::new(Reentrant::default());

        runner().start(|_| async {
            let (fd, _peer) = socket();
            let mut first = recv(fd.clone(), None);
            let mut queued = recv(fd, None);
            let mut sleep = Sleep::new(Duration::from_secs(60));
            let waker = callbacks.waker();
            let mut cx = Context::from_waker(&waker);
            assert!(first.poll_unpin(&mut cx).is_pending());
            reschedule().await;
            assert!(queued.poll_unpin(&mut cx).is_pending());
            assert!(sleep.poll_unpin(&mut cx).is_pending());

            // Equivalent wakers need no replacement for an in-flight request,
            // a queued request, or a registered sleep.
            let clones = callbacks.clones.load(Ordering::Relaxed);
            assert!(first.poll_unpin(&mut cx).is_pending());
            assert!(queued.poll_unpin(&mut cx).is_pending());
            assert!(sleep.poll_unpin(&mut cx).is_pending());
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

            // Replace the observer with a noop waker, then restore it. The
            // old observer must be dropped after the worker borrow ends.
            assert!(
                operation
                    .poll_unpin(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            assert!(operation.poll_unpin(&mut cx).is_pending());

            while callbacks.wakes.load(Ordering::Relaxed) == 0 {
                reschedule().await;
            }

            // A different waker would need cloning if the request were pending.
            // Consuming the completed result must skip that callback entirely.
            let ready = Arc::new(Reentrant::default());
            let ready_waker = ready.waker();
            assert!(matches!(
                operation.poll_unpin(&mut Context::from_waker(&ready_waker)),
                Poll::Ready(Ok(RequestOutput::Send(Ok(()))))
            ));
            assert_eq!(ready.clones.load(Ordering::Relaxed), 0);
            drop(waker);
        });

        // Two installations, one completion wake, and destruction of the
        // displaced clone and the original waker.
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
                assert!(
                    matches!(operation.state, State::Waiting { waiter_id, .. } if waiter_id == registration),
                    "clone panic lost cancellation identity"
                );

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
        // These callbacks run in worker service. Their panics must leave
        // through Runner::start only after all worker cleanup has finished.
        for callback in [Reentrant::WAKE, Reentrant::DROP] {
            let callbacks = Arc::new(Reentrant::default());
            let (fd, _peer) = socket();

            // Keep Local alive to inspect cleanup after its scope is gone.
            let mut retained_local = None;
            let panic = catch_unwind(AssertUnwindSafe(|| {
                runner().start(|_| async {
                    retained_local = Local::current();
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
                    pending::<()>().await;
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
            assert!(Local::current().is_none());
            assert_eq!(Arc::strong_count(&fd), 1);
            assert_eq!(Arc::strong_count(&callbacks), 1);
        }
    }

    #[test]
    fn test_queued_operation_completes_without_further_polls() {
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

            // Let a later request drive the worker. The queued future receives
            // no polls, and its unconsumed result must not occupy the sole
            // in-flight slot needed by this later request.
            assert!(matches!(send(fd).await, Ok(RequestOutput::Send(Ok(())))));
            assert_eq!(callbacks.clones.load(Ordering::Relaxed), 1);
            assert_eq!(callbacks.wakes.load(Ordering::Relaxed), 1);
            assert!(matches!(
                queued.poll_unpin(&mut Context::from_waker(&waker)),
                Poll::Ready(Ok(RequestOutput::Send(Ok(()))))
            ));
            assert_eq!(callbacks.clones.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn test_queued_deadline_and_timer_progress_with_full_ring() {
        runner().start(|context| async move {
            let (fd, _peer) = socket();
            let mut first = recv(fd.clone(), None);
            assert!(poll!(&mut first).is_pending());
            let deadline = Instant::now() + Duration::from_millis(10);
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
    fn test_escaped_operation_observes_worker_closure() {
        // Return the handle without awaiting it, then poll it after cleanup.
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
    fn test_foreign_drop_releases_registration() {
        for (in_flight, poll_first) in [(false, false), (false, true), (true, false), (true, true)]
        {
            runner().start(|_| async {
                let (fd, _peer) = socket();
                let mut operation = recv(fd, None);
                assert!(poll!(&mut operation).is_pending());

                // A queued receive retires locally. A staged receive must wait
                // for its operation CQE after cancellation.
                if in_flight {
                    reschedule().await;
                }

                thread::spawn(move || {
                    if poll_first {
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            operation.poll_unpin(&mut Context::from_waker(Waker::noop()))
                        }));
                        assert!(result.is_err());
                    }
                    // Both ordinary destruction and destruction after a rejected
                    // poll must publish the original registration identity.
                    drop(operation);
                })
                .join()
                .unwrap();

                // The owner must process the foreign message and finish any
                // kernel cancellation before the registration can retire.
                drained().await;
            });
        }
    }
}
