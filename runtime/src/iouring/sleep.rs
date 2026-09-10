//! Worker-local deadlines for sleeping tasks.
//!
//! Sleepers use a deadline heap independent of ring capacity. The worker expires
//! due timers on each turn and uses the earliest deadline to bound its waits.
//!
//! [`Timers`] stores wakers in a slab. Generations reject stale heap records and
//! delayed cancellation messages after a slot is reused. Cancellation removes
//! the waker immediately, leaving its heap record for lazy pruning or compaction.
//!
//! Registered sleeps must be polled on their owning worker, but may be dropped
//! on any thread. Wakers are cloned, invoked, and dropped outside worker borrows.
//! Timer methods return displaced wakers or append them to deferred storage.

use super::{
    mailbox::{Mailbox, Message},
    runtime,
    slab::{Id, Slab},
    timeout::TimeoutWheel,
};
use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    future::Future,
    mem,
    pin::Pin,
    sync::{Arc, Weak},
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
    /// Registration bound to the worker selected by the first pending poll.
    Registered {
        /// Weak identity used for affinity checks and foreign cancellation.
        mailbox: Weak<Mailbox>,
        /// Slot identity used to refresh or cancel the timer.
        timer_id: TimerId,
        /// Retained deadline so polling can detect expiry after the timer is removed.
        deadline: Instant,
    },
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

        // The first pending poll selects the worker. Later polls must preserve
        // that affinity, even if the deadline has already passed.
        let (owner, deadline, registered) = match &this.state {
            State::Done => return Poll::Ready(()),
            State::Unregistered { deadline } => {
                // Synchronous work may have made the worker's cached time stale.
                // An elapsed first poll needs neither a worker nor a registration.
                if *deadline <= Instant::now() {
                    this.state = State::Done;
                    return Poll::Ready(());
                }

                (
                    runtime::current().expect("io_uring sleep requires a current worker"),
                    *deadline,
                    None,
                )
            }
            State::Registered {
                mailbox,
                timer_id,
                deadline,
            } => (
                // Check affinity before changing the identity needed by Drop.
                runtime::bound(mailbox).expect("io_uring sleep polled after its worker closed"),
                *deadline,
                Some(*timer_id),
            ),
        };

        let mut cloned_waker = None;
        loop {
            let mut local = owner.borrow_mut();

            // A waker clone can reenter and close the worker between passes.
            assert!(
                !local.closing,
                "io_uring sleep polled after its worker closed"
            );

            // Expiry removes the registration before waking the task. Use the
            // retained deadline to recognize completion even if the slot is gone.
            if deadline <= local.now {
                this.state = State::Done;

                // If expiry has not removed the registration, detach its waker
                // here. A clone that raced expiry also needs deferred destruction.
                if let Some(timer_id) = registered
                    && let Some(waker) = local.timers.cancel(timer_id)
                {
                    local.deferred.drops.push(waker);
                }
                local.deferred.drops.extend(cloned_waker);

                return Poll::Ready(());
            }

            // An equivalent waker needs no clone or replacement.
            if cloned_waker.is_none()
                && registered.is_some_and(|id| local.timers.will_wake(id, cx.waker()))
            {
                return Poll::Pending;
            }

            let Some(waker) = cloned_waker.take() else {
                // Cloning can reenter deadline service or panic. Retain the
                // registration identity and recheck expiry before refreshing.
                drop(local);
                cloned_waker = Some(cx.waker().clone());
                continue;
            };

            if let Some(timer_id) = registered {
                // Refresh only the observer, leaving the deadline and heap record
                // in place. The displaced waker is dropped after this borrow.
                let old = local
                    .timers
                    .refresh(timer_id, waker)
                    .expect("live io_uring sleeper registration missing");
                local.deferred.drops.push(old);
            } else {
                // Register after cloning succeeds, so a clone panic cannot leave
                // a timer behind without a cancellation identity in this future.
                let timer_id = local.timers.insert(deadline, waker);
                this.state = State::Registered {
                    mailbox: Arc::downgrade(&local.mailbox),
                    timer_id,
                    deadline,
                };
            }

            return Poll::Pending;
        }
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let State::Registered {
            mailbox, timer_id, ..
        } = mem::replace(&mut self.state, State::Done)
        {
            // Cancel directly on the owning worker, or send it a mailbox message
            // from another thread. If expiry already removed the timer, its old
            // ID cannot cancel a new registration that reused the slot.
            runtime::cancel(&mailbox, Message::CancelTimer(timer_id));
        }
    }
}

/// Generational identity for one sleeper registration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimerId(Id);

/// Growable timer registrations and their earliest-first deadline heap.
#[derive(Default)]
pub struct Timers {
    /// Latest waker for each live registration.
    entries: Slab<Waker>,
    /// Deadline records, including lazily removed stale registrations.
    deadlines: BinaryHeap<Reverse<(Instant, TimerId)>>,
}

impl Timers {
    /// Register a fixed deadline and a waker cloned outside the worker borrow.
    fn insert(&mut self, deadline: Instant, waker: Waker) -> TimerId {
        let id = TimerId(self.entries.insert(waker));
        self.deadlines.push(Reverse((deadline, id)));
        id
    }

    /// Whether a live registration already holds an equivalent observer.
    fn will_wake(&self, id: TimerId, waker: &Waker) -> bool {
        self.entries
            .get(id.0)
            .is_some_and(|current| current.will_wake(waker))
    }

    /// Refresh a registered sleeper's waker and return the displaced waker.
    ///
    /// A missing registration returns the incoming waker untouched.
    fn refresh(&mut self, id: TimerId, waker: Waker) -> Result<Waker, Waker> {
        let Some(current) = self.entries.get_mut(id.0) else {
            return Err(waker);
        };
        Ok(mem::replace(current, waker))
    }

    /// Remove a live registration and return its waker for deferred destruction.
    ///
    /// A delayed cancellation for an expired or recycled timer is harmless.
    pub fn cancel(&mut self, id: TimerId) -> Option<Waker> {
        let waker = self.entries.remove(id.0)?;
        self.compact();
        Some(waker)
    }

    /// Remove every due timer and append its waker for deferred invocation.
    pub fn expire(&mut self, now: Instant, wakes: &mut Vec<Waker>) {
        while let Some(deadline) = self.next_deadline() {
            if deadline > now {
                break;
            }

            // next_deadline pruned stale records, so this ID still owns a waker.
            let Reverse((_, id)) = self.deadlines.pop().unwrap();
            wakes.push(self.entries.remove(id.0).unwrap());
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

    /// Remove every registration at worker closure and detach its waker.
    pub fn clear(&mut self, drops: &mut Vec<Waker>) {
        drops.reserve(self.entries.len());
        for index in 0..self.entries.slots() {
            if let Some(id) = self.entries.id_at(index) {
                drops.push(self.entries.remove(id).unwrap());
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
        Runner as _,
        iouring::{Runner, operation::tests::Reentrant},
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
        let mut wakes = Vec::new();
        timers.expire(now, &mut wakes);

        assert_eq!(wakes.len(), 2);
        assert!(timers.cancel(due).is_none());
        assert!(timers.cancel(also_due).is_none());
        assert!(timers.entries.get(future.0).is_some());
        assert_eq!(timers.next_deadline(), Some(later));
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);

        // Repeating expiry cannot enqueue the same wake twice.
        timers.expire(now, &mut wakes);
        assert_eq!(wakes.len(), 2);

        for waker in wakes.drain(..) {
            waker.wake();
        }
        assert_eq!(counter.0.load(Ordering::Relaxed), 2);

        timers.expire(later, &mut wakes);
        assert_eq!(timers.next_deadline(), None);
        assert_eq!(timers.entries.len(), 0);
        assert_eq!(wakes.len(), 1);
        wakes.pop().unwrap().wake();
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
        assert!(!timers.will_wake(id, &replacement));

        let displaced = timers.refresh(id, replacement.clone()).unwrap();

        // Refresh returns the old observer without dropping it, and leaves
        // exactly one record for the original deadline.
        assert_eq!(Arc::strong_count(&first), 2);
        assert!(timers.will_wake(id, &replacement));
        assert_eq!(timers.entries.len(), 1);
        assert_eq!(timers.deadlines.len(), 1);
        assert_eq!(timers.next_deadline(), Some(now));
        drop(displaced);
        assert_eq!(Arc::strong_count(&first), 1);

        let mut wakes = Vec::new();
        timers.expire(now, &mut wakes);
        wakes.pop().unwrap().wake();
        assert_eq!(first.0.load(Ordering::Relaxed), 0);
        assert_eq!(second.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stale_ids_and_deadlines_preserve_reused_slots() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut timers = Timers::default();
        let old = timers.insert(now, Waker::noop().clone());
        assert!(timers.cancel(old).is_some());
        let current_waker = Waker::from(Arc::new(Counter::default()));
        let current = timers.insert(later, current_waker.clone());

        assert_eq!(old.0.index, current.0.index);
        assert_ne!(old.0.generation, current.0.generation);
        assert!(timers.cancel(old).is_none());
        assert!(!timers.will_wake(old, &current_waker));

        // A stale refresh returns the incoming waker instead of replacing
        // or dropping either observer.
        let waker = Waker::from(Arc::new(Counter::default()));
        let rejected = timers.refresh(old, waker.clone()).unwrap_err();
        assert!(rejected.will_wake(&waker));
        assert!(timers.will_wake(current, &current_waker));

        // Pruning the old heap head must not expire the new registration.
        assert_eq!(timers.next_deadline(), Some(later));
        let mut wakes = Vec::new();
        timers.expire(now, &mut wakes);
        assert!(wakes.is_empty());
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
            assert!(timers.cancel(id).is_some());
            assert!(timers.deadlines.len() <= timers.entries.len() + 64);
        }

        assert_eq!(timers.entries.slots(), 2);
        assert_eq!(timers.next_deadline(), Some(now));
        assert!(timers.cancel(oldest).is_some());
        assert_eq!(timers.next_deadline(), None);

        // More than 64 stale records can remain when live timers outnumber
        // them. Expiring those live timers must also trigger compaction.
        for _ in 0..128 {
            timers.insert(now, Waker::noop().clone());
        }
        let future = timers.insert(later, Waker::noop().clone());
        for _ in 0..65 {
            let id = timers.insert(later + Duration::from_secs(1), Waker::noop().clone());
            assert!(timers.cancel(id).is_some());
        }
        assert_eq!(timers.deadlines.len(), 128 + 1 + 65);

        // The future timer keeps the stale records behind a live heap head.
        let mut wakes = Vec::new();
        timers.expire(now, &mut wakes);
        assert_eq!(wakes.len(), 128);
        assert_eq!(timers.deadlines.len(), 1);
        assert!(timers.entries.get(future.0).is_some());
    }

    #[test]
    fn test_clear_detaches_wakers_and_preserves_reuse() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let counter = Arc::new(Counter::default());
        let mut timers = Timers::default();

        // Leave a vacant slot before the live timer and a stale heap record.
        let cancelled = timers.insert(now, Waker::noop().clone());
        let id = timers.insert(later, Waker::from(counter.clone()));
        assert!(timers.cancel(cancelled).is_some());

        // Clear must append to existing deferred work without invoking callbacks.
        let mut drops = vec![Waker::noop().clone()];
        timers.clear(&mut drops);
        timers.clear(&mut drops);
        assert_eq!(drops.len(), 2);
        assert!(timers.deadlines.is_empty());
        assert_eq!(timers.next_deadline(), None);
        assert_eq!(timers.entries.len(), 0);
        assert_eq!(Arc::strong_count(&counter), 2);
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        drop(drops);
        assert_eq!(Arc::strong_count(&counter), 1);

        let reused = timers.insert(now, Waker::noop().clone());
        assert_eq!(reused.0.index, id.0.index);
        assert!(timers.cancel(id).is_none());
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
            let State::Registered { timer_id, .. } = sleep.state else {
                panic!("sleep did not register");
            };
            let owner = runtime::current().unwrap();

            // A successful replacement keeps the timer's identity and defers
            // destruction of its previous waker until after the worker borrow.
            let second = Arc::new(Reentrant::default());
            let second_waker = second.waker();
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&second_waker))
                    .is_pending()
            );
            assert!(owner.borrow().timers.will_wake(timer_id, &second_waker));
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
            assert!(owner.borrow().timers.will_wake(timer_id, &second_waker));

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
                let State::Registered { timer_id, .. } = sleep.state else {
                    panic!("sleep did not register");
                };
                let owner = runtime::current().unwrap();

                thread::spawn(move || {
                    if poll_first {
                        let panic = catch_unwind(AssertUnwindSafe(|| {
                            sleep.poll_unpin(&mut Context::from_waker(Waker::noop()))
                        }))
                        .expect_err("registered sleep must reject a foreign poll");
                        assert_eq!(
                            extract_panic_message(&*panic),
                            "registered io_uring handle polled outside its owning worker"
                        );
                    }

                    // A rejected foreign poll must retain the cancellation ID.
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
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);

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
