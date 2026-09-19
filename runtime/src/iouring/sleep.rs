//! Worker-local deadlines for sleeping tasks.
//!
//! Sleepers use a deadline heap independent of ring capacity. The worker expires
//! due timers on each turn and uses the earliest deadline to bound its waits.
//!
//! [`Timers`] stores observers in a slab. Generations reject stale heap records and
//! delayed cancellation messages after a slot is reused. Cancellation removes
//! the observer immediately, leaving its heap record for lazy pruning or compaction.
//!
//! Registered sleeps may be polled or dropped on any thread. Their deadlines
//! stay on the original worker. Observer callbacks run outside worker borrows.

use super::{
    mailbox::Message,
    registration::{Key, Observation, Registration},
    runtime::{Deferred, Local},
    slab::{Id, Slab},
    timeout::TimeoutWheel,
};
use crate::Error;
use commonware_utils::channel::oneshot;
use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    future::Future,
    mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant, SystemTime},
};

/// Ownership held by a sleep between polls.
enum State {
    /// Sleep that has not needed a timer registration yet.
    Unregistered {
        /// Absolute monotonic deadline established at creation.
        deadline: Instant,
    },
    /// Observer of the worker selected by the first pending poll.
    Registered(Registration<TimerId>),
    /// Immediate or completed sleep, requiring no worker access.
    Done,
}

/// Sleep future.
pub struct Sleep {
    /// Deadline or registration retained without any local reference.
    state: State,
}

impl Sleep {
    /// Establish a relative deadline, clamping the duration to [`TimeoutWheel::MAX_TIMEOUT`].
    ///
    /// Zero sleeps take the ready path without reading a clock or accessing TLS.
    pub fn new(duration: Duration) -> Self {
        if duration.is_zero() {
            return Self { state: State::Done };
        }

        let deadline = Instant::now()
            .checked_add(duration.min(TimeoutWheel::MAX_TIMEOUT))
            .expect("sleep deadline clamped to TimeoutWheel::MAX_TIMEOUT is not representable");

        Self {
            state: State::Unregistered { deadline },
        }
    }

    /// Convert a wall-clock deadline once, completing immediately if it has passed.
    pub fn until(deadline: SystemTime) -> Self {
        let duration = deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default();

        Self::new(duration)
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();

        match &mut this.state {
            State::Done => Poll::Ready(()),
            State::Registered(registration) => {
                std::task::ready!(Pin::new(registration).poll(cx))
                    .expect("io_uring sleep polled after its worker closed");
                this.state = State::Done;
                Poll::Ready(())
            }
            State::Unregistered { deadline } => {
                // Synchronous work may have made the worker's cached time stale.
                // An elapsed first poll needs neither a worker nor a registration.
                if *deadline <= Instant::now() {
                    this.state = State::Done;
                    return Poll::Ready(());
                }
                let owner = Local::current().expect("io_uring sleep requires a current worker");
                assert!(
                    !owner.borrow().closing,
                    "io_uring sleep polled after its worker closed"
                );

                // Register after cloning succeeds, so a clone panic cannot leave
                // a timer without a cancellation identity in this future.
                let waker = cx.waker().clone();
                let mut local = owner.borrow_mut();
                let id = local.timers.insert(*deadline, waker);
                this.state =
                    State::Registered(Registration::new(Arc::downgrade(&local.mailbox), id));
                Poll::Pending
            }
        }
    }
}

/// Generational identity for one sleeper registration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimerId(Id);

impl Key for TimerId {
    type Output = ();

    fn observe(self, local: &mut Local, waker: &Waker) -> Observation<()> {
        local.timers.observe(self, waker)
    }

    fn refresh(self, local: &mut Local, waker: Waker) -> Option<Waker> {
        Some(
            local
                .timers
                .refresh(self, waker)
                .expect("live io_uring sleeper registration missing"),
        )
    }

    fn forward(self, sender: oneshot::Sender<Result<(), Error>>) -> Message {
        Message::ForwardTimer(self, sender)
    }

    fn cancel(self) -> Message {
        Message::CancelTimer(self)
    }
}

/// Destination of a timer's expiry or worker-closure notification.
enum Observer {
    /// Waker installed while the sleeper is observed on its worker.
    Local(Waker),
    /// Completion sender installed after observation moves off the worker.
    Forwarded(oneshot::Sender<Result<(), Error>>),
}

impl Observer {
    fn complete(self, result: Result<(), Error>, deferred: &mut Deferred) {
        match self {
            Self::Local(waker) => deferred.wakes.push(waker),
            Self::Forwarded(sender) => deferred.completions.push((sender, result)),
        }
    }

    fn release(self, deferred: &mut Deferred) {
        match self {
            Self::Local(waker) => deferred.drops.push(waker),
            Self::Forwarded(sender) => deferred.completions.push((sender, Err(Error::Closed))),
        }
    }
}

/// Growable timer registrations and their earliest-first deadline heap.
#[derive(Default)]
pub struct Timers {
    /// Local or forwarded observer for each live registration.
    entries: Slab<Observer>,
    /// Deadline records, including lazily removed stale registrations.
    deadlines: BinaryHeap<Reverse<(Instant, TimerId)>>,
}

impl Timers {
    /// Register a fixed deadline and a waker cloned outside the worker borrow.
    fn insert(&mut self, deadline: Instant, waker: Waker) -> TimerId {
        let id = TimerId(self.entries.insert(Observer::Local(waker)));
        self.deadlines.push(Reverse((deadline, id)));
        id
    }

    /// Inspect a local observer. Expiry removes its registration before waking it.
    fn observe(&self, id: TimerId, waker: &Waker) -> Observation<()> {
        match self.entries.get(id.0) {
            None => Observation::Ready(()),
            Some(Observer::Local(current)) if current.will_wake(waker) => Observation::Pending,
            Some(Observer::Local(_)) => Observation::Refresh,
            Some(Observer::Forwarded(_)) => panic!("timer has no local observer"),
        }
    }

    /// Refresh a registered sleeper's waker and return the displaced waker.
    ///
    /// A missing registration returns the incoming waker untouched.
    fn refresh(&mut self, id: TimerId, waker: Waker) -> Result<Waker, Waker> {
        match self.entries.get_mut(id.0) {
            Some(Observer::Local(current)) => Ok(mem::replace(current, waker)),
            None => Err(waker),
            Some(Observer::Forwarded(_)) => panic!("timer has no local observer"),
        }
    }

    /// Move timer observation to a channel while retaining its original deadline.
    pub fn forward(
        &mut self,
        id: TimerId,
        sender: oneshot::Sender<Result<(), Error>>,
        deferred: &mut Deferred,
    ) {
        let Some(observer) = self.entries.get_mut(id.0) else {
            // Expiry removes the slot before a delayed forwarding message arrives.
            // Cancellation may also overtake forwarding, but then its receiver is gone.
            deferred.completions.push((sender, Ok(())));
            return;
        };
        let Observer::Local(waker) = mem::replace(observer, Observer::Forwarded(sender)) else {
            panic!("timer forwarded twice");
        };
        deferred.drops.push(waker);
    }

    /// Remove a live registration without invoking its observer.
    fn remove(&mut self, id: TimerId) -> Option<Observer> {
        let observer = self.entries.remove(id.0)?;
        self.compact();
        Some(observer)
    }

    /// Cancel observation, rejecting delayed messages for expired or recycled slots.
    pub fn cancel(&mut self, id: TimerId, deferred: &mut Deferred) {
        if let Some(observer) = self.remove(id) {
            observer.release(deferred);
        }
    }

    /// Remove every due timer and defer its completion notification.
    pub fn expire(&mut self, now: Instant, deferred: &mut Deferred) {
        while let Some(deadline) = self.next_deadline() {
            if deadline > now {
                break;
            }

            // next_deadline pruned stale records, so this ID still owns an observer.
            let Reverse((_, id)) = self.deadlines.pop().unwrap();
            self.entries
                .remove(id.0)
                .unwrap()
                .complete(Ok(()), deferred);
        }
        self.compact();
    }

    /// Return the earliest live deadline, pruning stale heap heads.
    pub fn next_deadline(&mut self) -> Option<Instant> {
        while let Some(&Reverse((deadline, id))) = self.deadlines.peek() {
            if self.entries.get(id.0).is_some() {
                return Some(deadline);
            }
            self.deadlines.pop();
        }
        None
    }

    /// Remove every registration and notify surviving observers of worker closure.
    pub fn clear(&mut self, deferred: &mut Deferred) {
        for index in 0..self.entries.slots() {
            if let Some(id) = self.entries.id_at(index) {
                self.entries
                    .remove(id)
                    .unwrap()
                    .complete(Err(Error::Closed), deferred);
            }
        }
        self.deadlines.clear();
    }

    /// Rebuild once stale entries exceed both 64 and the live timer count.
    fn compact(&mut self) {
        // Each live registration has exactly one heap record. Cancellation
        // leaves that record behind, so the difference counts stale records.
        let stale = self.deadlines.len() - self.entries.len();
        if stale <= 64 || stale <= self.entries.len() {
            return;
        }

        // A registration's deadline never changes. Generations alone reject
        // records left by earlier registrations in reused slots.
        let entries = &self.entries;
        self.deadlines
            .retain(|&Reverse((_, id))| entries.get(id.0).is_some());
        self.deadlines.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Clock as _, Runner as _,
        iouring::{
            Runner,
            operation::tests::{Reentrant, poll_on_foreign_thread},
        },
        utils::{extract_panic_message, reschedule},
    };
    use futures::{FutureExt as _, poll};
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::atomic::{AtomicUsize, Ordering},
        task::Wake,
        thread,
    };

    /// Count invocations without scheduling a task.
    #[derive(Default)]
    struct Counter(AtomicUsize);

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_elapsed_sleeps_are_ready_without_a_worker() {
        let mut cx = Context::from_waker(Waker::noop());

        // The last case has a deadline that passed between creation and polling.
        for mut sleep in [
            Sleep::new(Duration::ZERO),
            Sleep::until(SystemTime::UNIX_EPOCH),
            Sleep {
                state: State::Unregistered {
                    deadline: Instant::now(),
                },
            },
        ] {
            assert!(sleep.poll_unpin(&mut cx).is_ready());
            assert!(matches!(sleep.state, State::Done));
        }
    }

    #[test]
    fn test_far_future_sleep_clamps_the_deadline() {
        let before = Instant::now();
        let sleep = Sleep::new(Duration::MAX);
        let after = Instant::now();
        let State::Unregistered { deadline } = sleep.state else {
            panic!("positive sleep must retain a deadline");
        };

        assert!(deadline >= before + TimeoutWheel::MAX_TIMEOUT);
        assert!(deadline <= after + TimeoutWheel::MAX_TIMEOUT);
    }

    #[test]
    fn test_expiry_removes_due_timers_before_waking() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let counter = Arc::new(Counter::default());
        let mut timers = Timers::default();
        assert_eq!(timers.next_deadline(), None);

        // Insert out of order, including two timers due at exactly the same time.
        let future = timers.insert(later, Waker::from(counter.clone()));
        let due = timers.insert(now, Waker::from(counter.clone()));
        let also_due = timers.insert(now, Waker::from(counter.clone()));
        let mut deferred = Deferred::default();
        timers.expire(now, &mut deferred);

        assert_eq!(deferred.wakes.len(), 2);
        assert!(timers.remove(due).is_none());
        assert!(timers.remove(also_due).is_none());
        assert!(timers.entries.get(future.0).is_some());
        assert_eq!(timers.next_deadline(), Some(later));
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);

        // Repeating expiry cannot enqueue the same wake twice.
        timers.expire(now, &mut deferred);
        assert_eq!(deferred.wakes.len(), 2);

        for waker in deferred.wakes.drain(..) {
            waker.wake();
        }
        assert_eq!(counter.0.load(Ordering::Relaxed), 2);

        timers.expire(later, &mut deferred);
        assert_eq!(timers.next_deadline(), None);
        assert_eq!(timers.entries.len(), 0);
        assert_eq!(deferred.wakes.len(), 1);
        deferred.wakes.pop().unwrap().wake();
        assert_eq!(counter.0.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_refresh_replaces_only_the_waker() {
        let now = Instant::now();
        let first = Arc::new(Counter::default());
        let second = Arc::new(Counter::default());
        let mut timers = Timers::default();
        let id = timers.insert(now, Waker::from(first.clone()));
        let replacement = Waker::from(second.clone());
        assert!(matches!(
            timers.observe(id, &replacement),
            Observation::Refresh
        ));

        let displaced = timers.refresh(id, replacement.clone()).unwrap();

        // Refresh returns the old observer without dropping it, and leaves
        // exactly one record for the original deadline.
        assert_eq!(Arc::strong_count(&first), 2);
        assert!(matches!(
            timers.observe(id, &replacement),
            Observation::Pending
        ));
        assert_eq!(timers.entries.len(), 1);
        assert_eq!(timers.deadlines.len(), 1);
        assert_eq!(timers.next_deadline(), Some(now));
        drop(displaced);
        assert_eq!(Arc::strong_count(&first), 1);

        let mut deferred = Deferred::default();
        timers.expire(now, &mut deferred);
        deferred.wakes.pop().unwrap().wake();
        assert_eq!(first.0.load(Ordering::Relaxed), 0);
        assert_eq!(second.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stale_ids_and_deadlines_preserve_reused_slots() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut timers = Timers::default();
        let old = timers.insert(now, Waker::noop().clone());
        assert!(timers.remove(old).is_some());
        let current_waker = Waker::from(Arc::new(Counter::default()));
        let current = timers.insert(later, current_waker.clone());

        assert_eq!(old.0.index, current.0.index);
        assert_ne!(old.0.generation, current.0.generation);
        assert!(timers.remove(old).is_none());
        assert!(matches!(
            timers.observe(old, &current_waker),
            Observation::Ready(())
        ));

        // A stale refresh returns the incoming waker instead of replacing
        // or dropping either observer.
        let waker = Waker::from(Arc::new(Counter::default()));
        let rejected = timers.refresh(old, waker.clone()).unwrap_err();
        assert!(rejected.will_wake(&waker));
        assert!(matches!(
            timers.observe(current, &current_waker),
            Observation::Pending
        ));

        // Pruning the old heap head must not expire the new registration.
        assert_eq!(timers.next_deadline(), Some(later));
        let mut deferred = Deferred::default();
        timers.expire(now, &mut deferred);
        assert!(deferred.wakes.is_empty());
        assert!(timers.entries.get(current.0).is_some());
    }

    #[test]
    fn test_compaction_bounds_stale_deadlines() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut timers = Timers::default();
        let oldest = timers.insert(now, Waker::noop().clone());

        // A live heap head prevents lazy pruning from cleaning up cancellations
        // behind it. Repeated slot reuse must still keep the heap bounded.
        for _ in 0..1000 {
            let id = timers.insert(later, Waker::noop().clone());
            assert!(timers.remove(id).is_some());
            assert!(timers.deadlines.len() <= timers.entries.len() + 64);
        }

        assert_eq!(timers.entries.slots(), 2);
        assert_eq!(timers.next_deadline(), Some(now));
        assert!(timers.remove(oldest).is_some());
        assert_eq!(timers.next_deadline(), None);

        // More than 64 stale records can remain when live timers outnumber
        // them. Expiring those live timers must also trigger compaction.
        for _ in 0..128 {
            timers.insert(now, Waker::noop().clone());
        }
        let future = timers.insert(later, Waker::noop().clone());
        for _ in 0..65 {
            let id = timers.insert(later + Duration::from_secs(1), Waker::noop().clone());
            assert!(timers.remove(id).is_some());
        }
        assert_eq!(timers.deadlines.len(), 128 + 1 + 65);

        // The future timer keeps the stale records behind a live heap head.
        let mut deferred = Deferred::default();
        timers.expire(now, &mut deferred);
        assert_eq!(deferred.wakes.len(), 128);
        assert_eq!(timers.deadlines.len(), 1);
        assert!(timers.entries.get(future.0).is_some());
    }

    #[test]
    fn test_clear_defers_wakes_and_preserves_reuse() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let counter = Arc::new(Counter::default());
        let mut timers = Timers::default();

        // Leave a vacant slot before the live timer and a stale heap record.
        let cancelled = timers.insert(now, Waker::noop().clone());
        let id = timers.insert(later, Waker::from(counter.clone()));
        assert!(timers.remove(cancelled).is_some());

        // Clear must append to existing deferred work without invoking callbacks.
        let mut deferred = Deferred::default();
        deferred.wakes.push(Waker::noop().clone());
        timers.clear(&mut deferred);
        timers.clear(&mut deferred);
        assert_eq!(deferred.wakes.len(), 2);
        assert!(deferred.drops.is_empty());
        assert!(timers.deadlines.is_empty());
        assert_eq!(timers.next_deadline(), None);
        assert_eq!(timers.entries.len(), 0);
        assert_eq!(Arc::strong_count(&counter), 2);
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);

        // Invoke notifications after clear has released the timer registrations.
        for waker in deferred.wakes.drain(..) {
            waker.wake();
        }
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
        assert_eq!(Arc::strong_count(&counter), 1);

        // Reusing a cleared slot must reject the previous registration's identity.
        let reused = timers.insert(now, Waker::noop().clone());
        assert_eq!(reused.0.index, id.0.index);
        assert!(timers.remove(id).is_none());
        assert_eq!(timers.next_deadline(), Some(now));
    }

    #[test]
    fn test_waker_refresh_and_clone_panic_preserve_cancellation() {
        Runner::default().start(|_| async {
            let mut sleep = Sleep::new(Duration::from_secs(60));
            let first = Arc::new(Reentrant::default());
            let first_waker = first.waker();
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&first_waker))
                    .is_pending()
            );
            let State::Registered(registration) = &sleep.state else {
                panic!("sleep did not register");
            };
            let timer_id = registration.key();
            let owner = Local::current().unwrap();

            // A successful replacement keeps the timer's identity and defers
            // destruction of its previous waker until after the worker borrow.
            let second = Arc::new(Reentrant::default());
            let second_waker = second.waker();
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&second_waker))
                    .is_pending()
            );
            assert!(matches!(
                owner.borrow().timers.observe(timer_id, &second_waker),
                Observation::Pending
            ));
            assert_eq!(first.drops.load(Ordering::Relaxed), 0);
            reschedule().await;
            assert_eq!(first.drops.load(Ordering::Relaxed), 1);

            // Trying to restore the first observer now panics during cloning.
            // The second observer and the cancellation identity must survive.
            first
                .panic_callback
                .store(Reentrant::CLONE, Ordering::Relaxed);
            let panic = catch_unwind(AssertUnwindSafe(|| {
                let _ = sleep.poll_unpin(&mut Context::from_waker(&first_waker));
            }))
            .expect_err("changed sleep observer must clone");
            assert_eq!(extract_panic_message(&*panic), "waker callback panic 1");
            assert!(matches!(
                owner.borrow().timers.observe(timer_id, &second_waker),
                Observation::Pending
            ));

            drop(sleep);
            assert!(owner.borrow().timers.entries.get(timer_id.0).is_none());

            // Cancellation also defers destruction of the installed waker.
            assert_eq!(second.drops.load(Ordering::Relaxed), 0);
            reschedule().await;
            assert_eq!(second.drops.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn test_foreign_drop_cancels_registration() {
        for poll_first in [false, true] {
            Runner::default().start(|_| async {
                let mut sleep = Sleep::new(Duration::from_secs(60));
                assert!(poll!(&mut sleep).is_pending());
                let State::Registered(registration) = &sleep.state else {
                    panic!("sleep did not register");
                };
                let timer_id = registration.key();
                let owner = Local::current().unwrap();

                thread::spawn(move || {
                    if poll_first {
                        assert!(
                            sleep
                                .poll_unpin(&mut Context::from_waker(Waker::noop()))
                                .is_pending()
                        );
                    }

                    drop(sleep);
                })
                .join()
                .unwrap();

                // Foreign destruction sends a message. Only worker service
                // removes the registration and its deferred waker.
                assert!(owner.borrow().timers.entries.get(timer_id.0).is_some());
                reschedule().await;
                assert!(owner.borrow().timers.entries.get(timer_id.0).is_none());
            });
        }
    }

    #[test]
    fn test_sleep_moves_between_threads() {
        for expired in [false, true] {
            for return_to_owner in [false, true] {
                Runner::default().start(|context| async move {
                    let mut sleep = Sleep::new(Duration::from_millis(20));
                    let State::Unregistered { deadline } = sleep.state else {
                        unreachable!()
                    };
                    assert!(poll!(&mut sleep).is_pending());
                    if expired {
                        context.sleep(Duration::from_millis(30)).await;
                    }
                    let sleep = poll_on_foreign_thread(sleep, Waker::noop().clone());
                    let sleep = poll_on_foreign_thread(sleep, Waker::noop().clone());
                    if return_to_owner {
                        sleep.await;
                    } else {
                        let (sender, receiver) = oneshot::channel();
                        let thread = thread::spawn(move || {
                            futures::executor::block_on(sleep);
                            sender.send(()).unwrap();
                        });
                        receiver.await.unwrap();
                        thread.join().unwrap();
                    }
                    assert!(Instant::now() >= deadline);
                });
            }
        }
    }

    #[test]
    fn test_forwarding_and_cancellation_preserve_reused_timer() {
        for promoted in [false, true] {
            Runner::default().start(|_| async {
                let mut sleep = Sleep::new(Duration::from_secs(60));
                assert!(poll!(&mut sleep).is_pending());
                let State::Registered(registration) = &sleep.state else {
                    unreachable!()
                };
                let old = registration.key();
                let sleep = poll_on_foreign_thread(sleep, Waker::noop().clone());
                if promoted {
                    reschedule().await;
                }
                drop(sleep);

                let mut replacement = Sleep::new(Duration::from_secs(60));
                assert!(poll!(&mut replacement).is_pending());
                let State::Registered(registration) = &replacement.state else {
                    unreachable!()
                };
                let current = registration.key();
                assert_eq!(old.0.index, current.0.index);
                assert_ne!(old.0.generation, current.0.generation);
                reschedule().await;
                assert!(poll!(&mut replacement).is_pending());
                let owner = Local::current().unwrap();
                assert!(owner.borrow().timers.entries.get(old.0).is_none());
                assert!(owner.borrow().timers.entries.get(current.0).is_some());
                drop(replacement);
                assert!(owner.borrow().timers.entries.get(current.0).is_none());
            });
        }
    }

    #[test]
    fn test_forwarded_timer_closure_and_callbacks() {
        for promoted in [false, true] {
            let callbacks = Arc::new(Reentrant::default());
            let (mut sleep,) = Runner::default().start(|_| async {
                let mut sleep = Sleep::new(Duration::from_secs(60));
                assert!(
                    sleep
                        .poll_unpin(&mut Context::from_waker(&callbacks.waker()))
                        .is_pending()
                );
                let sleep = poll_on_foreign_thread(sleep, callbacks.waker());
                if promoted {
                    reschedule().await;
                }
                (sleep,)
            });

            // An installed forwarding channel must notify its receiver when the worker closes.
            if promoted {
                assert!(callbacks.wakes.load(Ordering::Relaxed) > 0);
            }
            let result = catch_unwind(AssertUnwindSafe(|| {
                sleep.poll_unpin(&mut Context::from_waker(Waker::noop()))
            }));
            assert!(
                extract_panic_message(&*result.unwrap_err())
                    .starts_with("io_uring sleep polled after its worker closed")
            );
            drop(sleep);
            assert_eq!(Arc::strong_count(&callbacks), 1);
        }
    }

    #[test]
    fn test_worker_closure_releases_escaped_sleep() {
        let counter = Arc::new(Counter::default());
        let (mut sleep,) = Runner::default().start(|_| async {
            let mut sleep = Sleep::new(Duration::from_secs(60));
            let waker = Waker::from(counter.clone());
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            (sleep,)
        });

        // Shutdown owns cleanup even though the registered future escaped.
        assert_eq!(Arc::strong_count(&counter), 1);
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);

        // Sleep has no error output. Polling after closure must panic rather
        // than report that an unelapsed deadline completed.
        let panic = catch_unwind(AssertUnwindSafe(|| {
            sleep.poll_unpin(&mut Context::from_waker(Waker::noop()))
        }))
        .expect_err("registered sleep must reject polling after closure");
        assert!(
            extract_panic_message(&*panic)
                .starts_with("io_uring sleep polled after its worker closed")
        );
        drop(sleep);
    }
}
