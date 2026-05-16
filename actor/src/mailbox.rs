//! Bounded message queue with caller-managed overflow.
//!
//! # Architecture
//!
//! The mailbox is split into two queues: a bounded `ready` queue
//! that producers push to and the receiver pops from, and an unbounded
//! `overflow` queue that holds messages displaced when ready is full. A
//! [`Policy`] decides how overflow is updated when overflow is contended.
//!
//! ```text
//!                          senders
//!                             |
//!         +-------------------+--------------------+
//!         | overflow inactive                      | overflow active
//!         | and ready has room                     | or ready full
//!         v                                        v
//!     +----------+    refill front-to-back     +----------+
//!     |  ready   |<----------------------------| overflow |
//!     +----------+    after each ready pop     +----------+
//!         |
//!         | pop first
//!         v
//!      receiver
//! ```
//!
//! The receiver always pops from the ready queue first. After each ready pop, it
//! eagerly refills ready from published overflow so senders can return to the
//! ready fast path without waiting for ready to drain completely. Overflow is
//! refilled from front to back, but policies decide which overflow messages are
//! retained and in what order.
//!
//! Overflow should be rare. When overflow is populated, the receiver refills
//! ready immediately instead of waiting to batch refill work. This can take the
//! overflow lock once per popped message, but it keeps ready capacity available
//! for later sends as soon as possible.
//!
//! # Ordering
//!
//! Enqueue calls from the same sender will be delivered in order. Concurrent enqueue calls,
//! however, are not globally ordered and may be observed in any interleaving.

use crate::Feedback;
use commonware_runtime::{
    telemetry::metrics::{Counter, MetricsExt as _},
    Metrics,
};
use std::{
    collections::VecDeque,
    fmt,
    future::poll_fn,
    num::NonZeroUsize,
    sync::mpsc::TryRecvError,
    task::{Context, Poll},
};

/// Retained overflow messages for a mailbox policy.
pub trait Overflow<T>: Default {
    /// Return whether the retained message set is empty.
    fn is_empty(&self) -> bool;

    /// Drain retained messages into `push` in delivery order until `push`
    /// rejects a message.
    ///
    /// If `push` returns `Some`, the undelivered message and any later messages
    /// must remain retained for a future drain.
    fn drain<F>(&mut self, push: F)
    where
        F: FnMut(T) -> Option<T>;
}

impl<T> Overflow<T> for VecDeque<T> {
    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(T) -> Option<T>,
    {
        while let Some(message) = self.pop_front() {
            if let Some(message) = push(message) {
                self.push_front(message);
                break;
            }
        }
    }
}

/// Overflow behavior for actor messages when an inbox is full.
pub trait Policy: Sized {
    /// Overflow storage used by this policy.
    type Overflow: Overflow<Self>;

    /// Handle `message` when it cannot enter the bounded ready queue immediately.
    ///
    /// Messages already in the ready queue are not provided here. Policy changes only apply to
    /// overflow retained beyond ready capacity. Policies may append, remove, replace, reorder, or
    /// clear overflow, and are responsible for bounding it when a hard memory limit is required.
    ///
    /// # Warning
    ///
    /// Do not enqueue into the same mailbox from this method or from destructors triggered by
    /// editing `overflow`. This method runs while the mailbox holds its overflow lock, so same
    /// mailbox re-entry can deadlock.
    ///
    /// This method should not unwind after mutating `overflow`. A panic, including one from a
    /// destructor triggered while editing `overflow`, can leave retained overflow data stranded in
    /// the mailbox.
    fn handle(overflow: &mut Self::Overflow, message: Self);
}

// `activity` packs the published overflow state and in-flight overflow
// mutations into one atomic word. The overflow lock serializes actual
// overflow changes (this word lets the ready fast path avoid that lock when
// overflow is inactive).
//
// The low bit records whether the most recently published overflow state was
// non-empty. The higher bits count active overflow mutations. Each mutation
// adds `OVERFLOW_MUTATION` while it may mutate or publish overflow state, so
// the count and the state bit coexist in the same word.
//
// Useful states:
// - `activity == 0`: no published overflow and no active overflow mutation, so
//   senders may try the direct ready fast path.
// - `activity & OVERFLOW_HAS_MESSAGES != 0`: overflow has published messages,
//   so the receiver may try to refill ready. The overflow lock serializes
//   refill with any active mutation.
// - `activity >= OVERFLOW_MUTATION`: at least one overflow mutation is active.
//   The overflow lock still serializes queue access; this state only keeps
//   lock-free fast-path/refill decisions from acting on a changing overflow
//   snapshot.
//
// Activity accesses are relaxed because this word does not publish queue
// contents. The overflow mutex serializes overflow access, and the ready queue
// owns its own synchronization. Stale activity observations only decide whether
// a caller tries a fast path, locks overflow, or waits for a later wake.
const OVERFLOW_HAS_MESSAGES: usize = 1;
const OVERFLOW_MUTATION: usize = 2;

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::future::AtomicWaker;
        use loom::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex, MutexGuard,
        };

        fn register_waker(waker: &AtomicWaker, task: &std::task::Waker) {
            waker.register_by_ref(task);
        }

        fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
            mutex.lock().unwrap()
        }

        struct ReadyState<T> {
            published: VecDeque<T>,
            reserved: usize,
        }

        struct Ready<T> {
            state: Mutex<ReadyState<T>>,
            capacity: usize,
        }

        impl<T> Ready<T> {
            fn new(capacity: usize) -> Self {
                Self {
                    state: Mutex::new(ReadyState {
                        published: VecDeque::new(),
                        reserved: 0,
                    }),
                    capacity,
                }
            }

            const fn capacity(&self) -> usize {
                self.capacity
            }

            fn push(&self, message: T) -> Result<(), T> {
                {
                    let mut state = lock(&self.state);
                    if state.published.len() + state.reserved >= self.capacity {
                        return Err(message);
                    }
                    state.reserved += 1;
                }

                loom::thread::yield_now();

                let mut state = lock(&self.state);
                state.reserved -= 1;
                state.published.push_back(message);
                Ok(())
            }

            fn pop(&self) -> Option<T> {
                loop {
                    let mut state = lock(&self.state);
                    if let Some(message) = state.published.pop_front() {
                        return Some(message);
                    }
                    if state.reserved == 0 {
                        return None;
                    }
                    drop(state);
                    loom::thread::yield_now();
                }
            }
        }
    } else {
        use crossbeam_queue::ArrayQueue;
        use futures_util::task::AtomicWaker;
        use parking_lot::{Mutex, MutexGuard};
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };

        fn register_waker(waker: &AtomicWaker, task: &std::task::Waker) {
            waker.register(task);
        }

        fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
            mutex.lock()
        }

        struct Ready<T> {
            queue: ArrayQueue<T>,
        }

        impl<T> Ready<T> {
            fn new(capacity: usize) -> Self {
                Self {
                    queue: ArrayQueue::new(capacity),
                }
            }

            fn capacity(&self) -> usize {
                self.queue.capacity()
            }

            fn push(&self, message: T) -> Result<(), T> {
                self.queue.push(message)
            }

            fn pop(&self) -> Option<T> {
                self.queue.pop()
            }
        }
    }
}

struct OverflowState<T: Policy> {
    queue: Mutex<T::Overflow>,
    activity: AtomicUsize,
}

impl<T: Policy> OverflowState<T> {
    #[allow(clippy::missing_const_for_fn)]
    fn new() -> Self {
        Self {
            queue: Mutex::new(T::Overflow::default()),
            activity: AtomicUsize::new(0),
        }
    }

    fn try_ready(&self, ready: &Ready<T>, message: T) -> Result<(), T> {
        // Avoid ready while overflow is retained or changing.
        if self.activity.load(Ordering::Relaxed) != 0 {
            return Err(message);
        }
        ready.push(message)
    }

    fn enqueue(&self, ready: &Ready<T>, message: T, is_closed: impl Fn() -> bool) -> Feedback {
        // Mark overflow active so racing senders stay off the ready fast path.
        let mutation = Mutation::begin(&self.activity);
        let mut queue = lock(&self.queue);
        if is_closed() {
            mutation.publish(queue.is_empty());
            return Feedback::Closed;
        }

        // The fast-path push may have observed stale ready fullness. Retry
        // ready under the overflow lock before applying policy, but only when
        // there is no retained overflow that must stay ahead of this message.
        let message = if queue.is_empty() {
            match ready.push(message) {
                Ok(()) => {
                    mutation.publish(queue.is_empty());
                    return Feedback::Ok;
                }
                Err(message) => message,
            }
        } else {
            message
        };

        // Preserve overflow order, or handle a still-full ready queue.
        T::handle(&mut queue, message);
        mutation.publish(queue.is_empty());
        Feedback::Backoff
    }

    fn refill(&self, ready: &Ready<T>) {
        // Skip the overflow lock unless non-empty overflow was published.
        if self.activity.load(Ordering::Relaxed) & OVERFLOW_HAS_MESSAGES == 0 {
            return;
        }

        let mutation = Mutation::begin(&self.activity);
        let mut queue = lock(&self.queue);
        queue.drain(|message| ready.push(message).err());
        mutation.publish(queue.is_empty());
    }

    fn drain(&self, ready: &Ready<T>) {
        // Attempt to drain all messages from ready
        let mutation = Mutation::begin(&self.activity);
        while ready.pop().is_some() {}

        // Attempt to drain all messages from overflow (storing messages to drop after
        // releasing the lock)
        let mut drained = Vec::new();
        let mut queue = lock(&self.queue);
        queue.drain(|message| {
            drained.push(message);
            None
        });
        mutation.publish(queue.is_empty());
        drop(queue);
        drop(drained);

        // A sender may have passed the fast-path activity check before this
        // mutation began, so we drain again
        while ready.pop().is_some() {}
    }
}

struct Mutation<'a> {
    activity: &'a AtomicUsize,
}

impl<'a> Mutation<'a> {
    fn begin(activity: &'a AtomicUsize) -> Self {
        activity.fetch_add(OVERFLOW_MUTATION, Ordering::Relaxed);
        Self { activity }
    }

    fn publish(&self, is_empty: bool) {
        if is_empty {
            self.activity
                .fetch_and(!OVERFLOW_HAS_MESSAGES, Ordering::Relaxed);
        } else {
            self.activity
                .fetch_or(OVERFLOW_HAS_MESSAGES, Ordering::Relaxed);
        }
    }
}

impl Drop for Mutation<'_> {
    fn drop(&mut self) {
        let previous = self
            .activity
            .fetch_sub(OVERFLOW_MUTATION, Ordering::Relaxed);
        assert!(previous >= OVERFLOW_MUTATION);
    }
}

struct State<T: Policy> {
    ready: Ready<T>,
    overflow: OverflowState<T>,
    backoff: Counter,
    closed: AtomicBool,
    senders: AtomicUsize,
    waker: AtomicWaker,
}

/// Sender half of a mailbox.
pub struct Sender<T: Policy> {
    state: Arc<State<T>>,
}

impl<T: Policy> Clone for Sender<T> {
    fn clone(&self) -> Self {
        // Live sender count drives receiver disconnect detection.
        self.state.senders.fetch_add(1, Ordering::Relaxed);
        Self {
            state: self.state.clone(),
        }
    }
}

impl<T: Policy> Drop for Sender<T> {
    fn drop(&mut self) {
        let previous = self.state.senders.fetch_sub(1, Ordering::AcqRel);
        assert!(previous > 0);
        // Wake a receiver that is parked waiting for data or disconnect.
        if previous == 1 {
            self.state.waker.wake();
        }
    }
}

impl<T: Policy> fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sender")
            .field("capacity", &self.state.ready.capacity())
            .field("closed", &self.state.closed.load(Ordering::Acquire))
            .finish()
    }
}

impl<T: Policy> Sender<T> {
    /// Submit a message without waiting for inbox capacity.
    #[must_use = "caller must handle enqueue feedback"]
    pub fn enqueue(&self, message: T) -> Feedback {
        // Receiver closure makes new sends fail immediately.
        if self.state.closed.load(Ordering::Acquire) {
            return Feedback::Closed;
        }

        // Common case: publish directly to ready without taking overflow lock.
        let message = match self.state.overflow.try_ready(&self.state.ready, message) {
            Ok(()) => {
                if self.state.closed.load(Ordering::Acquire) {
                    self.state.overflow.drain(&self.state.ready);
                    return Feedback::Closed;
                }
                self.state.waker.wake();
                return Feedback::Ok;
            }
            Err(message) => message,
        };

        // Slow path: serialize through overflow and apply the policy.
        let feedback = self.state.overflow.enqueue(&self.state.ready, message, || {
            self.state.closed.load(Ordering::Acquire)
        });

        // Record any backoff.
        if feedback == Feedback::Backoff {
            self.state.backoff.inc();
        }

        // Wake on any handled enqueue because a receiver may have skipped
        // refill while this overflow mutation was active. By the time we wake,
        // the mutation has published its overflow state. Spurious wakes are
        // acceptable.
        if feedback != Feedback::Closed {
            self.state.waker.wake();
        }
        feedback
    }
}

/// Receiver half of a mailbox.
///
/// Dropping the receiver closes the mailbox and drains buffered messages.
///
/// Dropping the last sender disconnects the mailbox, but the receiver continues
/// returning buffered messages until ready and overflow are empty.
pub struct Receiver<T: Policy> {
    state: Arc<State<T>>,
}

impl<T: Policy> Receiver<T> {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        // Fast path avoids waker churn when a message is already ready.
        if let Some(message) = self.pop() {
            return Poll::Ready(Some(message));
        }

        if self.is_disconnected() {
            return Poll::Ready(self.pop());
        }

        register_waker(&self.state.waker, cx.waker());

        // A sender can enqueue and wake after the first pop but before this
        // waker is installed. Re-check before sleeping so the wake is not lost.
        if let Some(message) = self.pop() {
            return Poll::Ready(Some(message));
        }

        if self.is_disconnected() {
            Poll::Ready(self.pop())
        } else {
            Poll::Pending
        }
    }

    fn pop(&mut self) -> Option<T> {
        if let Some(message) = self.state.ready.pop() {
            // A freed ready slot may let the oldest overflow message advance.
            self.state.overflow.refill(&self.state.ready);
            return Some(message);
        }

        // Empty ready may race with stale activity, so let `refill`
        // decide whether overflow is worth locking.
        self.state.overflow.refill(&self.state.ready);
        self.state.ready.pop()
    }

    fn is_disconnected(&self) -> bool {
        self.state.closed.load(Ordering::Acquire) || self.state.senders.load(Ordering::Acquire) == 0
    }

    /// Receive the next message.
    ///
    /// Returns `None` after all senders are dropped and all buffered messages
    /// have been drained.
    pub async fn recv(&mut self) -> Option<T> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Try to receive the next message without waiting.
    ///
    /// Returns [`TryRecvError::Disconnected`] after all senders are dropped and
    /// all buffered messages have been drained.
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        if let Some(message) = self.pop() {
            return Ok(message);
        }
        if self.is_disconnected() {
            return self.pop().ok_or(TryRecvError::Disconnected);
        }
        Err(TryRecvError::Empty)
    }
}

impl<T: Policy> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.state.closed.store(true, Ordering::Release);
        self.state.overflow.drain(&self.state.ready);
    }
}

/// Create a new bounded mailbox.
pub fn new<T: Policy>(metrics: impl Metrics, capacity: NonZeroUsize) -> (Sender<T>, Receiver<T>) {
    let state = Arc::new(State {
        ready: Ready::new(capacity.get()),
        overflow: OverflowState::new(),
        backoff: metrics.counter("backoff", "number of enqueue calls that requested backoff"),
        closed: AtomicBool::new(false),
        senders: AtomicUsize::new(1),
        waker: AtomicWaker::new(),
    });
    (
        Sender {
            state: state.clone(),
        },
        Receiver { state },
    )
}

#[cfg(test)]
mod mocks {
    use commonware_runtime::{
        telemetry::metrics::{Metric, Registered, Registration},
        Metrics as RuntimeMetrics, Name, Supervisor,
    };
    use std::fmt;

    #[derive(Clone, Copy, Debug, Default)]
    pub(super) struct Metrics;

    impl Supervisor for Metrics {
        fn name(&self) -> Name {
            Name::default()
        }

        fn child(&self, _label: &'static str) -> Self {
            Self
        }

        fn with_attribute(self, _key: &'static str, _value: impl fmt::Display) -> Self {
            self
        }
    }

    impl RuntimeMetrics for Metrics {
        fn register<N: Into<String>, H: Into<String>, M: Metric>(
            &self,
            _name: N,
            _help: H,
            metric: M,
        ) -> Registered<M> {
            Registered::with_registration(metric, Registration::from(()))
        }

        fn encode(&self) -> String {
            String::new()
        }
    }
}

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::{mocks, *};
    use commonware_macros::test_async;
    use commonware_runtime::{deterministic, Runner as _, Supervisor};
    use commonware_utils::{channel::oneshot, NZUsize};
    use futures::{
        pin_mut,
        task::{waker_ref, ArcWake},
        FutureExt,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::TryRecvError,
        Arc,
    };

    fn new<T: Policy>(capacity: NonZeroUsize) -> (Sender<T>, Receiver<T>) {
        super::new(mocks::Metrics, capacity)
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Message {
        Update(u64),
        Vote(u64),
        Required(u64),
        Buffered(u64),
        Hint(u64),
    }

    impl Policy for Message {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) {
            match message {
                Self::Update(value) => {
                    if let Some(index) = overflow
                        .iter()
                        .rposition(|pending| matches!(pending, Self::Update(_)))
                    {
                        overflow.remove(index);
                    }
                    overflow.push_back(Self::Update(value));
                }
                Self::Required(_) | Self::Buffered(_) => {
                    overflow.push_back(message);
                }
                Self::Hint(value) => {
                    let Some(index) = overflow
                        .iter()
                        .rposition(|pending| matches!(pending, Self::Update(_)))
                    else {
                        return;
                    };
                    overflow.remove(index);
                    overflow.push_back(Self::Hint(value));
                }
                Self::Vote(_) => {}
            }
        }
    }

    struct Ack {
        _sender: oneshot::Sender<()>,
    }

    impl Policy for Ack {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) {
            overflow.push_back(message);
        }
    }

    #[derive(Default)]
    struct WakeCounter {
        wakes: AtomicUsize,
    }

    impl WakeCounter {
        fn count(&self) -> usize {
            self.wakes.load(Ordering::Acquire)
        }
    }

    impl ArcWake for WakeCounter {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.wakes.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn vecdeque_overflow_drain_stops_after_rejected_message() {
        let mut overflow = VecDeque::from([Message::Vote(1), Message::Vote(2), Message::Vote(3)]);
        let mut drained = VecDeque::new();

        Overflow::drain(&mut overflow, |message| {
            drained.push_back(message);
            if drained.len() == 2 {
                drained.pop_back()
            } else {
                None
            }
        });

        assert_eq!(drained, VecDeque::from([Message::Vote(1)]));
        assert_eq!(
            overflow,
            VecDeque::from([Message::Vote(2), Message::Vote(3)])
        );
    }

    #[test_async]
    async fn full_inbox_replaces_stale_overflow_message() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Update(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Update(2)), Feedback::Backoff);
        assert_eq!(sender.enqueue(Message::Update(3)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Update(1)));
        assert_eq!(receiver.recv().await, Some(Message::Update(3)));
    }

    #[test_async]
    async fn policy_can_replace_stale_overflow_at_back() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Update(2)), Feedback::Backoff);
        assert_eq!(sender.enqueue(Message::Required(3)), Feedback::Backoff);
        assert_eq!(sender.enqueue(Message::Update(4)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Required(3)));
        assert_eq!(receiver.recv().await, Some(Message::Update(4)));
    }

    #[test_async]
    async fn full_inbox_rejects_non_replaceable_message() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Vote(2)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
    }

    #[test_async]
    async fn full_inbox_retains_required_message() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Buffered(2)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Buffered(2)));
    }

    #[test]
    fn try_recv_refills_from_overflow() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Buffered(2)), Feedback::Backoff);

        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Buffered(2)));
    }

    #[test]
    fn backoff_metric_counts_backoff_feedback() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (sender, _receiver) = super::new(context.child("mailbox"), NZUsize!(1));
            assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
            assert_eq!(sender.enqueue(Message::Buffered(2)), Feedback::Backoff);
            assert_eq!(sender.enqueue(Message::Buffered(3)), Feedback::Backoff);

            let buffer = context.encode();
            assert!(
                buffer.contains("mailbox_backoff_total 2"),
                "missing backoff count in metrics: {buffer}"
            );
        });
    }

    #[test]
    fn try_recv_drains_buffered_messages_after_senders_drop() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Buffered(2)), Feedback::Backoff);
        drop(sender);

        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Buffered(2)));
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));
    }

    #[test]
    fn poll_recv_drains_buffered_messages_after_senders_drop() {
        let (sender, mut receiver) = new(NZUsize!(1));
        let wakes = Arc::new(WakeCounter::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);

        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Buffered(2)), Feedback::Backoff);
        drop(sender);

        assert_eq!(
            receiver.poll_recv(&mut cx),
            Poll::Ready(Some(Message::Vote(1)))
        );
        assert_eq!(
            receiver.poll_recv(&mut cx),
            Poll::Ready(Some(Message::Buffered(2)))
        );
        assert_eq!(receiver.poll_recv(&mut cx), Poll::Ready(None));
    }

    #[test]
    fn enqueue_uses_ready_capacity_after_partial_drain() {
        let (sender, mut receiver) = new(NZUsize!(2));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Vote(2)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Required(3)), Feedback::Backoff);

        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(2)));

        assert_eq!(sender.enqueue(Message::Vote(4)), Feedback::Ok);
        assert_eq!(receiver.try_recv(), Ok(Message::Required(3)));
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(4)));
    }

    #[test]
    fn receiver_refills_overflow_after_partial_drain() {
        let (sender, mut receiver) = new(NZUsize!(3));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Vote(2)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Vote(3)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Required(4)), Feedback::Backoff);

        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(2)));

        assert_eq!(sender.enqueue(Message::Vote(5)), Feedback::Ok);
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(3)));
        assert_eq!(receiver.try_recv(), Ok(Message::Required(4)));
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(5)));
    }

    #[test_async]
    async fn full_inbox_retains_unmatched_replaceable_message() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Required(2)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Required(2)));
    }

    #[test_async]
    async fn full_inbox_replaces_stale_overflow_after_ready_fills() {
        let (sender, mut receiver) = new(NZUsize!(2));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Update(2)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Update(3)), Feedback::Backoff);
        assert_eq!(sender.enqueue(Message::Update(4)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Update(2)));
        assert_eq!(receiver.recv().await, Some(Message::Update(4)));
    }

    #[test_async]
    async fn mailbox_capacity_is_soft_limit_for_required_messages() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Required(2)), Feedback::Backoff);
        assert_eq!(sender.enqueue(Message::Required(3)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Required(2)));
        assert_eq!(receiver.recv().await, Some(Message::Required(3)));
    }

    #[test_async]
    async fn full_inbox_rejects_hint() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Hint(2)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
    }

    #[test_async]
    async fn full_inbox_can_replace_or_drop_by_message() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Update(2)), Feedback::Backoff);
        assert_eq!(sender.enqueue(Message::Hint(3)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Hint(3)));
    }

    #[test_async]
    async fn empty_inbox_wakes_on_enqueue() {
        let (sender, mut receiver) = new(NZUsize!(1));

        let next = receiver.recv();
        pin_mut!(next);
        assert!(next.as_mut().now_or_never().is_none());

        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(next.await, Some(Message::Vote(1)));
    }

    #[test]
    fn pending_recv_wakes_when_senders_drop() {
        let (sender, mut receiver) = new::<Message>(NZUsize!(1));
        let wakes = Arc::new(WakeCounter::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);

        assert_eq!(receiver.poll_recv(&mut cx), Poll::Pending);
        assert_eq!(wakes.count(), 0);

        drop(sender);

        assert_eq!(wakes.count(), 1);
        assert_eq!(receiver.poll_recv(&mut cx), Poll::Ready(None));
    }

    #[test]
    fn pending_recv_wakes_on_handled_overflow_enqueue() {
        let (sender, mut receiver) = new(NZUsize!(1));
        let wakes = Arc::new(WakeCounter::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);

        assert_eq!(receiver.poll_recv(&mut cx), Poll::Pending);
        assert_eq!(wakes.count(), 0);

        // Prime ready directly to isolate the overflow wake after registration.
        assert_eq!(sender.state.ready.push(Message::Vote(1)), Ok(()));
        assert_eq!(sender.enqueue(Message::Buffered(2)), Feedback::Backoff);

        assert_eq!(wakes.count(), 1);
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Buffered(2)));
    }

    #[test]
    fn receiver_drop_blocks_ready_fast_path_feedback() {
        let (sender, mut receiver) = new(NZUsize!(1));
        let wakes = Arc::new(WakeCounter::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);

        assert_eq!(receiver.poll_recv(&mut cx), Poll::Pending);
        drop(receiver);

        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Closed);
        assert_eq!(wakes.count(), 0);
    }

    #[test_async]
    async fn empty_inbox_closes_when_senders_drop() {
        let (sender, mut receiver) = new::<Message>(NZUsize!(1));
        drop(sender);

        assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));
        assert_eq!(receiver.recv().await, None);
    }

    #[test]
    fn enqueue_after_receiver_drop_returns_closed() {
        let (sender, receiver) = new(NZUsize!(1));
        drop(receiver);

        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Closed);
    }

    #[test_async]
    async fn receiver_drop_cancels_buffered_responders() {
        let (sender, receiver) = new(NZUsize!(1));
        let (ready_tx, ready_rx) = oneshot::channel();
        let (overflow_tx, overflow_rx) = oneshot::channel();

        assert_eq!(sender.enqueue(Ack { _sender: ready_tx }), Feedback::Ok);
        assert_eq!(
            sender.enqueue(Ack {
                _sender: overflow_tx
            }),
            Feedback::Backoff
        );
        drop(receiver);

        assert!(ready_rx.await.is_err());
        assert!(overflow_rx.await.is_err());
    }

    #[derive(Debug, PartialEq, Eq)]
    enum ClearingMessage {
        FillReady,
        ClearOverflow,
    }

    impl Policy for ClearingMessage {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) {
            overflow.push_back(message);
            overflow.clear();
        }
    }

    #[test]
    fn policy_can_clear_overflow_and_request_backoff() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(ClearingMessage::FillReady), Feedback::Ok);
        assert_eq!(
            sender.enqueue(ClearingMessage::ClearOverflow),
            Feedback::Backoff
        );

        assert!(matches!(
            receiver.try_recv(),
            Ok(ClearingMessage::FillReady)
        ));
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
    }

    #[derive(Debug, PartialEq, Eq)]
    enum SpillMessage {
        FillReady,
        Spill,
    }

    impl Policy for SpillMessage {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) {
            overflow.push_back(message);
        }
    }

    #[test]
    fn pending_recv_wakes_when_policy_spills() {
        let (sender, mut receiver) = new(NZUsize!(1));
        let wakes = Arc::new(WakeCounter::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);

        assert_eq!(receiver.poll_recv(&mut cx), Poll::Pending);
        assert_eq!(wakes.count(), 0);

        assert_eq!(sender.state.ready.push(SpillMessage::FillReady), Ok(()));
        assert_eq!(sender.enqueue(SpillMessage::Spill), Feedback::Backoff);

        assert_eq!(wakes.count(), 1);
        assert_eq!(receiver.try_recv(), Ok(SpillMessage::FillReady));
        assert_eq!(receiver.try_recv(), Ok(SpillMessage::Spill));
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::{mocks, *};
    use commonware_utils::NZUsize;
    use futures::pin_mut;
    use loom::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread,
    };
    use std::{
        future::Future,
        task::{RawWaker, RawWakerVTable, Waker},
    };

    fn new<T: Policy>(capacity: NonZeroUsize) -> (Sender<T>, Receiver<T>) {
        super::new(mocks::Metrics, capacity)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Message {
        Drop(u8),
        Spill(u8),
    }

    #[derive(Clone, Debug)]
    enum OrderedMessage {
        Item(u8),
        Coordinated(u8, Arc<AtomicUsize>),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ReplacingMessage {
        FillReady,
        Replace(u8),
    }

    struct TrackedMessage {
        drops: Arc<AtomicUsize>,
    }

    struct CyclicMessage {
        _sender: Sender<Self>,
        drops: Arc<AtomicUsize>,
    }

    impl TrackedMessage {
        const fn new(drops: Arc<AtomicUsize>) -> Self {
            Self { drops }
        }
    }

    impl Drop for TrackedMessage {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    impl Drop for CyclicMessage {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    impl Policy for Message {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) {
            match message {
                Self::Drop(_) => {}
                Self::Spill(_) => {
                    overflow.push_back(message);
                }
            }
        }
    }

    impl Policy for OrderedMessage {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) {
            let gate = match &message {
                Self::Item(_) => None,
                Self::Coordinated(_, gate) => Some(gate.clone()),
            };
            overflow.push_back(message);
            if let Some(gate) = gate {
                gate.store(1, Ordering::Release);
                while gate.load(Ordering::Acquire) == 1 {
                    thread::yield_now();
                }
            }
        }
    }

    impl Policy for ReplacingMessage {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) {
            match message {
                Self::FillReady => {}
                Self::Replace(_) => {
                    if let Some(pending) = overflow
                        .iter_mut()
                        .rev()
                        .find(|pending| matches!(pending, Self::Replace(_)))
                    {
                        *pending = message;
                    } else {
                        overflow.push_back(message);
                    }
                }
            }
        }
    }

    impl Policy for TrackedMessage {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) {
            overflow.push_back(message);
        }
    }

    impl Policy for CyclicMessage {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) {
            overflow.push_back(message);
        }
    }

    fn record(seen: &AtomicUsize, message: Message) {
        let value = match message {
            Message::Drop(value) | Message::Spill(value) => value,
        };
        seen.fetch_or(1usize << usize::from(value), Ordering::AcqRel);
    }

    fn value(message: OrderedMessage) -> u8 {
        match message {
            OrderedMessage::Item(value) | OrderedMessage::Coordinated(value, _) => value,
        }
    }

    const fn replacement_value(message: ReplacingMessage) -> Option<u8> {
        match message {
            ReplacingMessage::FillReady => None,
            ReplacingMessage::Replace(value) => Some(value),
        }
    }

    unsafe fn clone_counter(data: *const ()) -> RawWaker {
        // SAFETY: `data` was created by `Arc::into_raw` for an `AtomicUsize`
        // in `counting_waker` or this function's clone path.
        let wakes = unsafe { Arc::<AtomicUsize>::from_raw(data.cast()) };
        let cloned = wakes.clone();
        let _ = Arc::into_raw(wakes);
        RawWaker::new(Arc::into_raw(cloned).cast(), &COUNTER_WAKER_VTABLE)
    }

    unsafe fn wake_counter(data: *const ()) {
        // SAFETY: `data` owns one raw `Arc<AtomicUsize>` reference for this
        // consuming wake path.
        let wakes = unsafe { Arc::<AtomicUsize>::from_raw(data.cast()) };
        wakes.fetch_add(1, Ordering::AcqRel);
    }

    unsafe fn wake_counter_by_ref(data: *const ()) {
        // SAFETY: `data` is a borrowed raw `Arc<AtomicUsize>` reference. The
        // reference is converted back into raw form before returning.
        let wakes = unsafe { Arc::<AtomicUsize>::from_raw(data.cast()) };
        wakes.fetch_add(1, Ordering::AcqRel);
        let _ = Arc::into_raw(wakes);
    }

    unsafe fn drop_counter(data: *const ()) {
        // SAFETY: `data` owns one raw `Arc<AtomicUsize>` reference that should
        // be dropped by the waker.
        unsafe {
            drop(Arc::<AtomicUsize>::from_raw(data.cast()));
        }
    }

    static COUNTER_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        clone_counter,
        wake_counter,
        wake_counter_by_ref,
        drop_counter,
    );

    fn counting_waker(wakes: Arc<AtomicUsize>) -> Waker {
        let raw = RawWaker::new(Arc::into_raw(wakes).cast(), &COUNTER_WAKER_VTABLE);
        // SAFETY: The vtable above reconstructs the same `Arc<AtomicUsize>`
        // type and preserves the raw waker reference-counting contract.
        unsafe { Waker::from_raw(raw) }
    }

    #[test]
    fn sender_drop_racing_waker_registration_wakes_or_disconnects() {
        loom::model(|| {
            let (sender, mut receiver) = new::<Message>(NZUsize!(1));
            let wakes = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);

            let close = thread::spawn(move || {
                drop(sender);
            });

            let poll = receiver.poll_recv(&mut cx);
            close.join().unwrap();

            match poll {
                Poll::Ready(None) => {}
                Poll::Pending => {
                    assert!(wakes.load(Ordering::Acquire) > 0);
                    assert_eq!(receiver.poll_recv(&mut cx), Poll::Ready(None));
                }
                Poll::Ready(Some(_)) => panic!("unexpected message"),
            }
        });
    }

    #[test]
    fn sender_enqueue_then_drop_racing_poll_recv_drains_message() {
        loom::model(|| {
            let (sender, mut receiver) = new::<Message>(NZUsize!(1));
            let wakes = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);

            let enqueue = thread::spawn(move || {
                assert_eq!(sender.enqueue(Message::Spill(0)), Feedback::Ok);
            });

            let poll = receiver.poll_recv(&mut cx);
            enqueue.join().unwrap();

            match poll {
                Poll::Ready(Some(Message::Spill(0))) => {}
                Poll::Pending => {
                    assert!(wakes.load(Ordering::Acquire) > 0);
                    assert_eq!(
                        receiver.poll_recv(&mut cx),
                        Poll::Ready(Some(Message::Spill(0)))
                    );
                }
                Poll::Ready(None) => panic!("disconnected before draining message"),
                Poll::Ready(Some(message)) => panic!("unexpected message: {message:?}"),
            }

            assert_eq!(receiver.poll_recv(&mut cx), Poll::Ready(None));
        });
    }

    #[test]
    fn sender_enqueue_then_drop_racing_try_recv_drains_message() {
        loom::model(|| {
            let (sender, mut receiver) = new::<Message>(NZUsize!(1));

            let enqueue = thread::spawn(move || {
                assert_eq!(sender.enqueue(Message::Spill(0)), Feedback::Ok);
            });

            let result = receiver.try_recv();
            enqueue.join().unwrap();

            match result {
                Ok(Message::Spill(0)) => {}
                Err(TryRecvError::Empty) => {
                    assert_eq!(receiver.try_recv(), Ok(Message::Spill(0)));
                }
                Err(TryRecvError::Disconnected) => {
                    panic!("disconnected before draining message");
                }
                Ok(message) => panic!("unexpected message: {message:?}"),
            }

            assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));
        });
    }

    #[test]
    fn handled_enqueue_wakes_registered_receiver() {
        loom::model(|| {
            let (sender, mut receiver) = new::<Message>(NZUsize!(1));
            let wakes = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);

            let next = receiver.recv();
            pin_mut!(next);
            assert!(matches!(next.as_mut().poll(&mut cx), Poll::Pending));
            assert_eq!(sender.enqueue(Message::Spill(0)), Feedback::Ok);

            assert_eq!(wakes.load(Ordering::Acquire), 1);
            assert_eq!(
                next.as_mut().poll(&mut cx),
                Poll::Ready(Some(Message::Spill(0)))
            );
        });
    }

    #[test]
    fn receiver_drop_racing_ready_fast_path_feedback_wakes_if_ready() {
        loom::model(|| {
            let (sender, mut receiver) = new::<Message>(NZUsize!(1));
            let wakes = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);

            assert_eq!(receiver.poll_recv(&mut cx), Poll::Pending);

            let close = thread::spawn(move || {
                drop(receiver);
            });
            let feedback = sender.enqueue(Message::Spill(0));
            close.join().unwrap();

            if feedback.accepted() {
                assert!(wakes.load(Ordering::Acquire) > 0);
            } else {
                assert_eq!(feedback, Feedback::Closed);
            }
            assert_eq!(sender.enqueue(Message::Spill(1)), Feedback::Closed);
        });
    }

    #[test]
    fn receiver_drop_racing_ready_enqueue_drops_message() {
        loom::model(|| {
            let (sender, receiver) = new::<TrackedMessage>(NZUsize!(1));
            let drops = Arc::new(AtomicUsize::new(0));

            let close = thread::spawn(move || {
                drop(receiver);
            });
            let _ = sender.enqueue(TrackedMessage::new(drops.clone()));
            close.join().unwrap();

            assert_eq!(drops.load(Ordering::Acquire), 1);
        });
    }

    #[test]
    fn receiver_drop_racing_overflow_enqueue_drops_messages() {
        loom::model(|| {
            let (sender, receiver) = new::<TrackedMessage>(NZUsize!(1));
            let ready_drops = Arc::new(AtomicUsize::new(0));
            let overflow_drops = Arc::new(AtomicUsize::new(0));

            assert_eq!(
                sender.enqueue(TrackedMessage::new(ready_drops.clone())),
                Feedback::Ok
            );
            let close = thread::spawn(move || {
                drop(receiver);
            });
            let _ = sender.enqueue(TrackedMessage::new(overflow_drops.clone()));
            close.join().unwrap();

            assert_eq!(ready_drops.load(Ordering::Acquire), 1);
            assert_eq!(overflow_drops.load(Ordering::Acquire), 1);
        });
    }

    #[test]
    fn receiver_drop_drains_ready_message_published_under_overflow_lock() {
        loom::model(|| {
            let (sender, receiver) = new::<TrackedMessage>(NZUsize!(1));
            let drops = Arc::new(AtomicUsize::new(0));
            let mutation = Mutation::begin(&sender.state.overflow.activity);
            let queue = lock(&sender.state.overflow.queue);

            let close = thread::spawn(move || {
                drop(receiver);
            });

            assert!(sender
                .state
                .ready
                .push(TrackedMessage::new(drops.clone()))
                .is_ok());
            mutation.publish(queue.is_empty());
            drop(queue);
            drop(mutation);
            close.join().unwrap();

            assert_eq!(drops.load(Ordering::Acquire), 1);
        });
    }

    #[test]
    fn receiver_drop_drains_overflow_message_published_under_overflow_lock() {
        loom::model(|| {
            let (sender, receiver) = new::<TrackedMessage>(NZUsize!(1));
            let ready_drops = Arc::new(AtomicUsize::new(0));
            let overflow_drops = Arc::new(AtomicUsize::new(0));

            assert_eq!(
                sender.enqueue(TrackedMessage::new(ready_drops.clone())),
                Feedback::Ok
            );

            let mutation = Mutation::begin(&sender.state.overflow.activity);
            let mut queue = lock(&sender.state.overflow.queue);
            let close = thread::spawn(move || {
                drop(receiver);
            });

            queue.push_back(TrackedMessage::new(overflow_drops.clone()));
            mutation.publish(queue.is_empty());
            drop(queue);
            drop(mutation);
            close.join().unwrap();

            assert_eq!(ready_drops.load(Ordering::Acquire), 1);
            assert_eq!(overflow_drops.load(Ordering::Acquire), 1);
        });
    }

    #[test]
    fn receiver_drop_breaks_message_sender_cycle() {
        loom::model(|| {
            let (sender, receiver) = new::<CyclicMessage>(NZUsize!(1));
            let drops = Arc::new(AtomicUsize::new(0));

            assert_eq!(
                sender.enqueue(CyclicMessage {
                    _sender: sender.clone(),
                    drops: drops.clone(),
                }),
                Feedback::Ok
            );
            assert_eq!(
                sender.enqueue(CyclicMessage {
                    _sender: sender.clone(),
                    drops: drops.clone(),
                }),
                Feedback::Backoff
            );

            drop(receiver);

            assert_eq!(drops.load(Ordering::Acquire), 2);
            assert_eq!(
                sender.enqueue(CyclicMessage {
                    _sender: sender.clone(),
                    drops,
                }),
                Feedback::Closed
            );
        });
    }

    #[test]
    fn concurrent_close_and_ready_enqueue_remains_closed() {
        loom::model(|| {
            let (sender, receiver) = new::<Message>(NZUsize!(1));

            let enqueue_sender = sender.clone();
            let enqueue = thread::spawn(move || {
                let _ = enqueue_sender.enqueue(Message::Spill(1));
            });

            let close = thread::spawn(move || {
                drop(receiver);
            });

            enqueue.join().unwrap();
            close.join().unwrap();
            assert_eq!(sender.enqueue(Message::Spill(2)), Feedback::Closed);
        });
    }

    #[test]
    fn concurrent_close_and_overflow_enqueue_remains_closed() {
        loom::model(|| {
            let (sender, receiver) = new::<Message>(NZUsize!(1));
            assert_eq!(sender.enqueue(Message::Drop(0)), Feedback::Ok);

            let enqueue_sender = sender.clone();
            let enqueue = thread::spawn(move || {
                let _ = enqueue_sender.enqueue(Message::Spill(1));
            });

            let close = thread::spawn(move || {
                drop(receiver);
            });

            enqueue.join().unwrap();
            close.join().unwrap();
            assert_eq!(sender.enqueue(Message::Spill(2)), Feedback::Closed);
        });
    }

    #[test]
    fn concurrent_spill_and_refill_preserves_messages() {
        loom::model(|| {
            let (sender, mut receiver) = new::<Message>(NZUsize!(1));
            let idle_sender = sender.clone();
            assert_eq!(sender.enqueue(Message::Spill(0)), Feedback::Ok);

            let seen = Arc::new(AtomicUsize::new(0));
            let enqueue = thread::spawn(move || {
                let feedback = sender.enqueue(Message::Spill(1));
                assert!(feedback.accepted());
            });

            let seen_by_receiver = seen.clone();
            let recv = thread::spawn(move || {
                if let Ok(message) = receiver.try_recv() {
                    record(&seen_by_receiver, message);
                }
                receiver
            });

            enqueue.join().unwrap();
            let mut receiver = recv.join().unwrap();

            while let Ok(message) = receiver.try_recv() {
                record(&seen, message);
            }
            assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
            drop(idle_sender);
            assert_eq!(seen.load(Ordering::Acquire), 0b11);
        });
    }

    #[test]
    fn concurrent_spill_senders_preserve_messages() {
        loom::model(|| {
            let (sender, mut receiver) = new::<Message>(NZUsize!(1));
            let idle_sender = sender.clone();
            assert_eq!(sender.enqueue(Message::Spill(0)), Feedback::Ok);

            let sender_1 = sender.clone();
            let enqueue_1 = thread::spawn(move || sender_1.enqueue(Message::Spill(1)));
            let enqueue_2 = thread::spawn(move || sender.enqueue(Message::Spill(2)));

            let seen = Arc::new(AtomicUsize::new(0));

            assert!(enqueue_1.join().unwrap().accepted());
            assert!(enqueue_2.join().unwrap().accepted());

            while let Ok(message) = receiver.try_recv() {
                record(&seen, message);
            }
            assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
            drop(idle_sender);
            assert_eq!(seen.load(Ordering::Acquire), 0b111);
        });
    }

    #[test]
    fn concurrent_replace_keeps_one_overflow_message() {
        loom::model(|| {
            let (sender, mut receiver) = new::<ReplacingMessage>(NZUsize!(1));
            let idle_sender = sender.clone();
            assert_eq!(sender.enqueue(ReplacingMessage::FillReady), Feedback::Ok);
            assert_eq!(
                sender.enqueue(ReplacingMessage::Replace(1)),
                Feedback::Backoff
            );

            let sender_1 = sender.clone();
            let replace_1 = thread::spawn(move || sender_1.enqueue(ReplacingMessage::Replace(2)));
            let replace_2 = thread::spawn(move || sender.enqueue(ReplacingMessage::Replace(3)));

            assert_eq!(replace_1.join().unwrap(), Feedback::Backoff);
            assert_eq!(replace_2.join().unwrap(), Feedback::Backoff);
            assert_eq!(receiver.try_recv(), Ok(ReplacingMessage::FillReady));

            let retained = replacement_value(receiver.try_recv().unwrap()).unwrap();
            assert!(retained == 2 || retained == 3);
            assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
            drop(idle_sender);
        });
    }

    #[test]
    fn stale_overflow_hint_retries_ready_before_policy() {
        loom::model(|| {
            let (sender, mut receiver) = new::<Message>(NZUsize!(2));
            assert_eq!(sender.enqueue(Message::Drop(0)), Feedback::Ok);
            assert_eq!(sender.enqueue(Message::Drop(1)), Feedback::Ok);
            assert_eq!(sender.enqueue(Message::Spill(2)), Feedback::Backoff);

            assert_eq!(receiver.try_recv(), Ok(Message::Drop(0)));
            assert_eq!(receiver.try_recv(), Ok(Message::Drop(1)));

            assert_eq!(sender.enqueue(Message::Drop(3)), Feedback::Ok);
            assert_eq!(receiver.try_recv(), Ok(Message::Spill(2)));
            assert_eq!(receiver.try_recv(), Ok(Message::Drop(3)));
        });
    }

    #[test]
    fn concurrent_overflow_cannot_be_bypassed_by_ready_fast_path() {
        loom::model(|| {
            let (sender, mut receiver) = new::<OrderedMessage>(NZUsize!(2));
            assert_eq!(sender.enqueue(OrderedMessage::Item(0)), Feedback::Ok);
            assert_eq!(sender.enqueue(OrderedMessage::Item(1)), Feedback::Ok);

            let gate = Arc::new(AtomicUsize::new(0));
            let overflow_sender = sender.clone();
            let overflow_gate = gate.clone();
            let overflow = thread::spawn(move || {
                assert_eq!(
                    overflow_sender.enqueue(OrderedMessage::Coordinated(2, overflow_gate)),
                    Feedback::Backoff
                );
            });

            while gate.load(Ordering::Acquire) == 0 {
                thread::yield_now();
            }

            // Message 2 has already been spilled. Even without cross-sender
            // FIFO, later enqueue calls must not bypass retained overflow.
            let mut observed = vec![value(receiver.try_recv().unwrap())];
            gate.store(2, Ordering::Release);
            let feedback = sender.enqueue(OrderedMessage::Item(3));
            assert!(feedback.accepted());

            overflow.join().unwrap();
            while let Ok(message) = receiver.try_recv() {
                observed.push(value(message));
            }

            assert_eq!(observed, vec![0, 1, 2, 3]);
        });
    }

    #[test]
    fn concurrent_overflow_mutation_does_not_hide_published_overflow() {
        loom::model(|| {
            let (sender, mut receiver) = new::<OrderedMessage>(NZUsize!(1));
            assert_eq!(sender.enqueue(OrderedMessage::Item(0)), Feedback::Ok);
            assert_eq!(sender.enqueue(OrderedMessage::Item(1)), Feedback::Backoff);

            let gate = Arc::new(AtomicUsize::new(0));
            let overflow_gate = gate.clone();
            let overflow = thread::spawn(move || {
                sender.enqueue(OrderedMessage::Coordinated(2, overflow_gate))
            });

            while gate.load(Ordering::Acquire) == 0 {
                thread::yield_now();
            }

            let release_gate = gate;
            let release = thread::spawn(move || {
                release_gate.store(2, Ordering::Release);
            });

            let receive = thread::spawn(move || {
                assert_eq!(receiver.try_recv().map(value), Ok(0));
                assert_eq!(receiver.try_recv().map(value), Ok(1));
                receiver
            });

            release.join().unwrap();
            let mut receiver = receive.join().unwrap();
            assert_eq!(overflow.join().unwrap(), Feedback::Backoff);
            assert_eq!(receiver.try_recv().map(value), Ok(2));
        });
    }

    #[test]
    fn published_overflow_wakes_pending_receiver() {
        loom::model(|| {
            let (sender, mut receiver) = new::<OrderedMessage>(NZUsize!(1));
            let wakes = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);

            let gate = Arc::new(AtomicUsize::new(0));
            let overflow = {
                let next = receiver.recv();
                pin_mut!(next);
                assert!(matches!(next.as_mut().poll(&mut cx), Poll::Pending));

                assert_eq!(sender.enqueue(OrderedMessage::Item(0)), Feedback::Ok);
                while wakes.load(Ordering::Acquire) == 0 {
                    thread::yield_now();
                }

                let overflow_gate = gate.clone();
                let overflow = thread::spawn(move || {
                    sender.enqueue(OrderedMessage::Coordinated(1, overflow_gate))
                });

                while gate.load(Ordering::Acquire) == 0 {
                    thread::yield_now();
                }

                assert_eq!(
                    next.as_mut()
                        .poll(&mut cx)
                        .map(|message| message.map(value)),
                    Poll::Ready(Some(0))
                );
                overflow
            };

            {
                let next = receiver.recv();
                pin_mut!(next);
                assert!(matches!(next.as_mut().poll(&mut cx), Poll::Pending));
                assert_eq!(wakes.load(Ordering::Acquire), 1);

                gate.store(2, Ordering::Release);
                while wakes.load(Ordering::Acquire) < 2 {
                    thread::yield_now();
                }

                assert_eq!(
                    next.as_mut()
                        .poll(&mut cx)
                        .map(|message| message.map(value)),
                    Poll::Ready(Some(1))
                );
            }
            assert_eq!(overflow.join().unwrap(), Feedback::Backoff);
        });
    }

    #[test]
    fn concurrent_refill_and_enqueue_preserves_overflow_order() {
        loom::model(|| {
            let (sender, mut receiver) = new::<OrderedMessage>(NZUsize!(1));
            assert_eq!(sender.enqueue(OrderedMessage::Item(0)), Feedback::Ok);
            assert_eq!(sender.enqueue(OrderedMessage::Item(1)), Feedback::Backoff);

            let enqueue = thread::spawn(move || sender.enqueue(OrderedMessage::Item(2)));
            let receive = thread::spawn(move || {
                assert_eq!(receiver.try_recv().map(value), Ok(0));
                receiver
            });

            let mut receiver = receive.join().unwrap();
            assert_eq!(enqueue.join().unwrap(), Feedback::Backoff);
            assert_eq!(receiver.try_recv().map(value), Ok(1));
            assert_eq!(receiver.try_recv().map(value), Ok(2));
        });
    }
}
