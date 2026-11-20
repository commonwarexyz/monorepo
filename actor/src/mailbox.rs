//! Bounded message queue with caller-managed overflow.
//!
//! # Architecture
//!
//! The mailbox is split into two queues: a bounded `ready` queue
//! that producers push to and the receiver pops from, and an unbounded
//! `overflow` queue that holds messages displaced when ready is full. A
//! [`Policy`] or [`UnreliablePolicy`] decides how overflow is updated when
//! overflow is contended.
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
//!
//! # Cooperative budget
//!
//! Each ready result of a receiver's `recv`, a message or the end of the
//! mailbox, spends one unit of the cooperative budget that bounds the current
//! task poll (see [`commonware_utils::coop`]): the commonware budget on the
//! io_uring and deterministic runtimes, tokio's own budget on tokio. Once the
//! budget is spent, `recv` returns pending without removing a message and the
//! task is woken again, so a fed receive loop yields to the executor once per
//! budget. Polls that find the mailbox empty cost nothing, and `try_recv` is
//! never budgeted, so it is the way to probe a mailbox without waiting.

use crate::{Feedback, Unreliable};
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_utils::coop;
use std::{
    collections::VecDeque,
    fmt,
    future::poll_fn,
    marker::PhantomData,
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

    /// Reliably handle `message` when it cannot enter the bounded ready queue immediately.
    ///
    /// This may retain the message, coalesce it with retained work, replace older retained work,
    /// or deliberately do no work because the message is already satisfied, superseded, or no
    /// longer needed (for example, a request whose response channel is already closed).
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

/// Overflow behavior for actor messages that can be rejected when an inbox is full.
pub trait UnreliablePolicy: Sized {
    /// Overflow storage used by this policy.
    type Overflow: Overflow<Self>;

    /// Unreliably handle `message` when it cannot enter the bounded ready queue immediately.
    ///
    /// Returns `true` when the policy considered the message's effects. This includes retaining
    /// the message, coalescing it with retained work, replacing older retained work, or deliberately
    /// doing no work because the message is already satisfied, superseded, or no longer needed.
    ///
    /// Returns `false` only when the policy rejects the message under backpressure without
    /// retaining, coalescing, replacing, or otherwise handling it. This is the unreliable case: the
    /// submitted work was not semantically handled, and callers that care should retry or treat the
    /// submission as failed.
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
    fn handle(overflow: &mut Self::Overflow, message: Self) -> bool;
}

// Marker types that select the mailbox overflow policy.
mod mode {
    /// Uses a policy that always handles overflow messages.
    pub(super) struct Reliable;

    /// Uses a policy that may reject overflow messages.
    pub(super) struct Unreliable;
}

trait Mode<T>: Sized {
    /// Overflow storage used by this mode.
    type Overflow: Overflow<T>;
    /// Feedback returned from enqueue attempts.
    type Feedback;

    /// Updates overflow for a full inbox and reports whether the message was handled.
    fn handle(overflow: &mut Self::Overflow, message: T) -> bool;
    /// Maps ready-path feedback into this mode's feedback type.
    fn ready_feedback(feedback: Feedback) -> Self::Feedback;
    /// Maps overflow handling into this mode's feedback type.
    fn overflow_feedback(handled: bool) -> Self::Feedback;
    /// Returns `true` when this feedback should count as backoff.
    fn is_backoff(feedback: &Self::Feedback) -> bool;
    /// Returns `true` when this feedback means the receiver is closed.
    fn is_closed(feedback: &Self::Feedback) -> bool;
}

impl<T: Policy> Mode<T> for mode::Reliable {
    type Overflow = T::Overflow;
    type Feedback = Feedback;

    fn handle(overflow: &mut Self::Overflow, message: T) -> bool {
        T::handle(overflow, message);
        true
    }

    fn ready_feedback(feedback: Feedback) -> Self::Feedback {
        feedback
    }

    fn overflow_feedback(_handled: bool) -> Self::Feedback {
        Feedback::Backoff
    }

    fn is_backoff(feedback: &Self::Feedback) -> bool {
        *feedback == Feedback::Backoff
    }

    fn is_closed(feedback: &Self::Feedback) -> bool {
        *feedback == Feedback::Closed
    }
}

impl<T: UnreliablePolicy> Mode<T> for mode::Unreliable {
    type Overflow = T::Overflow;
    type Feedback = Unreliable<Feedback>;

    fn handle(overflow: &mut Self::Overflow, message: T) -> bool {
        T::handle(overflow, message)
    }

    fn ready_feedback(feedback: Feedback) -> Self::Feedback {
        Unreliable::new(feedback)
    }

    fn overflow_feedback(handled: bool) -> Self::Feedback {
        if handled {
            Unreliable::new(Feedback::Backoff)
        } else {
            Unreliable::Rejected
        }
    }

    fn is_backoff(feedback: &Self::Feedback) -> bool {
        *feedback == Unreliable::new(Feedback::Backoff)
    }

    fn is_closed(feedback: &Self::Feedback) -> bool {
        *feedback == Unreliable::new(Feedback::Closed)
    }
}

/// Sender half of a mailbox.
pub struct Sender<T: Policy> {
    state: Arc<State<T, mode::Reliable>>,
}

/// Sender half of an unreliable mailbox.
pub struct UnreliableSender<T: UnreliablePolicy> {
    state: Arc<State<T, mode::Unreliable>>,
}

impl<T: Policy> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            state: clone_sender_state(&self.state),
        }
    }
}

impl<T: UnreliablePolicy> Clone for UnreliableSender<T> {
    fn clone(&self) -> Self {
        Self {
            state: clone_sender_state(&self.state),
        }
    }
}

impl<T: Policy> Drop for Sender<T> {
    fn drop(&mut self) {
        drop_sender_state(&self.state);
    }
}

impl<T: UnreliablePolicy> Drop for UnreliableSender<T> {
    fn drop(&mut self) {
        drop_sender_state(&self.state);
    }
}

impl<T: Policy> fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_sender_state("Sender", &self.state, f)
    }
}

impl<T: UnreliablePolicy> fmt::Debug for UnreliableSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_sender_state("UnreliableSender", &self.state, f)
    }
}

impl<T: Policy> Sender<T> {
    /// Submit a message without waiting for inbox capacity.
    #[must_use = "caller must handle enqueue feedback"]
    pub fn enqueue(&self, message: T) -> Feedback {
        self.state.enqueue(message)
    }
}

impl<T: UnreliablePolicy> UnreliableSender<T> {
    /// Submit a message without waiting for inbox capacity, allowing policy rejection.
    #[must_use = "caller must handle enqueue feedback"]
    pub fn enqueue(&self, message: T) -> Unreliable<Feedback> {
        self.state.enqueue(message)
    }
}

/// Receiver half of a mailbox.
///
/// Dropping the receiver closes the mailbox and drains buffered messages.
///
/// Dropping the last sender disconnects the mailbox, but the receiver continues
/// returning buffered messages until ready and overflow are empty.
pub struct Receiver<T: Policy> {
    state: Arc<State<T, mode::Reliable>>,
}

/// Receiver half of an unreliable mailbox.
///
/// Dropping the receiver closes the mailbox and drains buffered messages.
///
/// Dropping the last sender disconnects the mailbox, but the receiver continues
/// returning buffered messages until ready and overflow are empty.
pub struct UnreliableReceiver<T: UnreliablePolicy> {
    state: Arc<State<T, mode::Unreliable>>,
}

impl<T: Policy> Receiver<T> {
    /// Receive the next message.
    ///
    /// Returns `None` after all senders are dropped and all buffered messages
    /// have been drained.
    #[inline]
    pub async fn recv(&mut self) -> Option<T> {
        recv_from(&self.state).await
    }

    /// Try to receive the next message without waiting.
    ///
    /// Returns [`TryRecvError::Disconnected`] after all senders are dropped and
    /// all buffered messages have been drained.
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        try_recv_from(&self.state)
    }
}

impl<T: UnreliablePolicy> UnreliableReceiver<T> {
    /// Receive the next message.
    ///
    /// Returns `None` after all senders are dropped and all buffered messages
    /// have been drained.
    #[inline]
    pub async fn recv(&mut self) -> Option<T> {
        recv_from(&self.state).await
    }

    /// Try to receive the next message without waiting.
    ///
    /// Returns [`TryRecvError::Disconnected`] after all senders are dropped and
    /// all buffered messages have been drained.
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        try_recv_from(&self.state)
    }
}

impl<T: Policy> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.state.close();
    }
}

impl<T: UnreliablePolicy> Drop for UnreliableReceiver<T> {
    fn drop(&mut self) {
        self.state.close();
    }
}

/// Create a new bounded mailbox.
pub fn new<T: Policy>(metrics: impl Metrics, capacity: NonZeroUsize) -> (Sender<T>, Receiver<T>) {
    let state = new_state(metrics, capacity);
    (
        Sender {
            state: state.clone(),
        },
        Receiver { state },
    )
}

/// Create a new bounded unreliable mailbox.
pub fn new_unreliable<T: UnreliablePolicy>(
    metrics: impl Metrics,
    capacity: NonZeroUsize,
) -> (UnreliableSender<T>, UnreliableReceiver<T>) {
    let state = new_state(metrics, capacity);
    (
        UnreliableSender {
            state: state.clone(),
        },
        UnreliableReceiver { state },
    )
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
        use loom::{
            future::AtomicWaker,
            sync::{
                Arc, Mutex, MutexGuard,
                atomic::{AtomicBool, AtomicUsize, Ordering},
            },
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
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
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

struct OverflowState<T, M: Mode<T>> {
    queue: Mutex<M::Overflow>,
    activity: AtomicUsize,
    _phantom: PhantomData<fn() -> T>,
}

impl<T, M: Mode<T>> OverflowState<T, M> {
    fn new() -> Self {
        Self {
            queue: Mutex::new(M::Overflow::default()),
            activity: AtomicUsize::new(0),
            _phantom: PhantomData,
        }
    }

    fn try_ready(&self, ready: &Ready<T>, message: T) -> Result<(), T> {
        // Avoid ready while overflow is retained or changing.
        if self.activity.load(Ordering::Relaxed) != 0 {
            return Err(message);
        }
        ready.push(message)
    }

    fn enqueue_overflow(
        &self,
        ready: &Ready<T>,
        message: T,
        is_closed: impl Fn() -> bool,
    ) -> M::Feedback {
        // Mark overflow active so racing senders stay off the ready fast path.
        let mutation = Mutation::begin(&self.activity);
        let mut queue = lock(&self.queue);
        if is_closed() {
            mutation.publish(queue.is_empty());
            return M::ready_feedback(Feedback::Closed);
        }

        // The fast-path push may have observed stale ready fullness. Retry
        // ready under the overflow lock before applying policy, but only when
        // there is no retained overflow that must stay ahead of this message.
        let message = if queue.is_empty() {
            match ready.push(message) {
                Ok(()) => {
                    mutation.publish(queue.is_empty());
                    return M::ready_feedback(Feedback::Ok);
                }
                Err(message) => message,
            }
        } else {
            message
        };

        // Preserve overflow order, or handle a still-full ready queue.
        let handled = M::handle(&mut queue, message);
        mutation.publish(queue.is_empty());
        M::overflow_feedback(handled)
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

struct State<T, M: Mode<T>> {
    ready: Ready<T>,
    overflow: OverflowState<T, M>,
    backoff: Counter,
    closed: AtomicBool,
    senders: AtomicUsize,
    waker: AtomicWaker,
}

impl<T, M: Mode<T>> State<T, M> {
    fn enqueue(&self, message: T) -> M::Feedback {
        // Receiver closure makes new sends fail immediately.
        if self.closed.load(Ordering::Acquire) {
            return M::ready_feedback(Feedback::Closed);
        }

        // Common case: publish directly to ready without taking overflow lock.
        let message = match self.overflow.try_ready(&self.ready, message) {
            Ok(()) => {
                if self.closed.load(Ordering::Acquire) {
                    self.overflow.drain(&self.ready);
                    return M::ready_feedback(Feedback::Closed);
                }
                self.waker.wake();
                return M::ready_feedback(Feedback::Ok);
            }
            Err(message) => message,
        };

        // Slow path: serialize through overflow and apply the policy.
        let feedback = self
            .overflow
            .enqueue_overflow(&self.ready, message, || self.closed.load(Ordering::Acquire));

        // Record any backoff.
        if M::is_backoff(&feedback) {
            self.backoff.inc();
        }

        // Wake after any non-closed slow-path enqueue because a receiver may
        // have skipped refill while this overflow mutation was active. By the
        // time we wake, the mutation has published its overflow state. Spurious
        // wakes are acceptable.
        if !M::is_closed(&feedback) {
            self.waker.wake();
        }
        feedback
    }

    /// Polls for the next message, spending one unit of the cooperative
    /// budget that bounds the current task poll for each ready result, a
    /// message or the end of the mailbox.
    ///
    /// The budget is checked before any message is removed, so a spent budget
    /// leaves ready and overflow untouched. The receiver then returns pending
    /// without registering the waker, and the budget wakes the task. This is
    /// safe because the task is already scheduled to poll again, and a sender
    /// wake that finds an older registration only causes a spurious poll.
    /// Empty polls cost nothing.
    #[inline(always)]
    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        coop::poll_budgeted(cx, |cx| self.poll_recv_inner(cx))
    }

    /// Polls for the next message without consulting the cooperative budget.
    ///
    /// Returns `None` once the mailbox is disconnected and drained. Otherwise
    /// registers the waker of `cx` when no message is available.
    #[inline(always)]
    fn poll_recv_inner(&self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        // Fast path avoids waker churn when a message is already ready.
        if let Some(message) = self.pop() {
            return Poll::Ready(Some(message));
        }

        if self.is_disconnected() {
            return Poll::Ready(self.pop());
        }

        register_waker(&self.waker, cx.waker());

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

    /// Removes the next message, moving the oldest overflow messages into
    /// ready as slots free up.
    #[inline(always)]
    fn pop(&self) -> Option<T> {
        if let Some(message) = self.ready.pop() {
            // A freed ready slot may let the oldest overflow message advance.
            self.overflow.refill(&self.ready);
            return Some(message);
        }

        // Empty ready may race with stale activity, so let `refill`
        // decide whether overflow is worth locking.
        self.overflow.refill(&self.ready);
        self.ready.pop()
    }

    fn is_disconnected(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.senders.load(Ordering::Acquire) == 0
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.overflow.drain(&self.ready);
    }
}

fn new_state<T, M: Mode<T>>(metrics: impl Metrics, capacity: NonZeroUsize) -> Arc<State<T, M>> {
    Arc::new(State {
        ready: Ready::new(capacity.get()),
        overflow: OverflowState::new(),
        backoff: metrics.counter("backoff", "number of enqueue calls that requested backoff"),
        closed: AtomicBool::new(false),
        senders: AtomicUsize::new(1),
        waker: AtomicWaker::new(),
    })
}

fn clone_sender_state<T, M: Mode<T>>(state: &Arc<State<T, M>>) -> Arc<State<T, M>> {
    // Live sender count drives receiver disconnect detection.
    state.senders.fetch_add(1, Ordering::Relaxed);
    state.clone()
}

fn drop_sender_state<T, M: Mode<T>>(state: &State<T, M>) {
    let previous = state.senders.fetch_sub(1, Ordering::AcqRel);
    assert!(previous > 0);
    // Wake a receiver that is parked waiting for data or disconnect.
    if previous == 1 {
        state.waker.wake();
    }
}

fn fmt_sender_state<T, M: Mode<T>>(
    name: &str,
    state: &State<T, M>,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    f.debug_struct(name)
        .field("capacity", &state.ready.capacity())
        .field("closed", &state.closed.load(Ordering::Acquire))
        .finish()
}

/// Waits for the next message of `state`, or `None` once it is disconnected
/// and drained.
#[inline]
async fn recv_from<T, M: Mode<T>>(state: &State<T, M>) -> Option<T> {
    poll_fn(|cx| state.poll_recv(cx)).await
}

fn try_recv_from<T, M: Mode<T>>(state: &State<T, M>) -> Result<T, TryRecvError> {
    if let Some(message) = state.pop() {
        return Ok(message);
    }
    if state.is_disconnected() {
        return state.pop().ok_or(TryRecvError::Disconnected);
    }
    Err(TryRecvError::Empty)
}

#[cfg(test)]
mod mocks {
    use commonware_runtime::{
        Metrics as RuntimeMetrics, Name, Supervisor,
        telemetry::metrics::{Metric, Registered},
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
            Registered::detached(metric)
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
    use commonware_runtime::{Runner as _, Supervisor, deterministic};
    use commonware_utils::{NZUsize, channel::oneshot};
    use futures::{
        FutureExt, pin_mut,
        task::{ArcWake, waker_ref},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::TryRecvError,
    };

    fn new<T: Policy>(capacity: NonZeroUsize) -> (Sender<T>, Receiver<T>) {
        super::new(mocks::Metrics, capacity)
    }

    fn new_unreliable<T: UnreliablePolicy>(
        capacity: NonZeroUsize,
    ) -> (UnreliableSender<T>, UnreliableReceiver<T>) {
        super::new_unreliable(mocks::Metrics, capacity)
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Message {
        Update(u64),
        Vote(u64),
        Required(u64),
        Buffered(u64),
        Hint(u64),
    }

    impl UnreliablePolicy for Message {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
            match message {
                Self::Update(value) => {
                    if let Some(index) = overflow
                        .iter()
                        .rposition(|pending| matches!(pending, Self::Update(_)))
                    {
                        overflow.remove(index);
                    }
                    overflow.push_back(Self::Update(value));
                    true
                }
                Self::Required(_) | Self::Buffered(_) => {
                    overflow.push_back(message);
                    true
                }
                Self::Hint(value) => {
                    let Some(index) = overflow
                        .iter()
                        .rposition(|pending| matches!(pending, Self::Update(_)))
                    else {
                        return true;
                    };
                    overflow.remove(index);
                    overflow.push_back(Self::Hint(value));
                    true
                }
                Self::Vote(_) => false,
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
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));
        assert_eq!(
            sender.enqueue(Message::Update(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Update(2)),
            Unreliable::new(Feedback::Backoff)
        );
        assert_eq!(
            sender.enqueue(Message::Update(3)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(receiver.recv().await, Some(Message::Update(1)));
        assert_eq!(receiver.recv().await, Some(Message::Update(3)));
    }

    #[test_async]
    async fn policy_can_replace_stale_overflow_at_back() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Update(2)),
            Unreliable::new(Feedback::Backoff)
        );
        assert_eq!(
            sender.enqueue(Message::Required(3)),
            Unreliable::new(Feedback::Backoff)
        );
        assert_eq!(
            sender.enqueue(Message::Update(4)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Required(3)));
        assert_eq!(receiver.recv().await, Some(Message::Update(4)));
    }

    #[test_async]
    async fn full_inbox_rejects_non_replaceable_message() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(sender.enqueue(Message::Vote(2)), Unreliable::Rejected);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
    }

    #[test_async]
    async fn full_inbox_retains_required_message() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Buffered(2)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Buffered(2)));
    }

    #[test]
    fn try_recv_refills_from_overflow() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Buffered(2)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Buffered(2)));
    }

    #[test]
    fn backoff_metric_counts_backoff_feedback() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (sender, _receiver) = super::new_unreliable(context.child("mailbox"), NZUsize!(1));
            assert_eq!(
                sender.enqueue(Message::Vote(1)),
                Unreliable::new(Feedback::Ok)
            );
            assert_eq!(
                sender.enqueue(Message::Buffered(2)),
                Unreliable::new(Feedback::Backoff)
            );
            assert_eq!(
                sender.enqueue(Message::Buffered(3)),
                Unreliable::new(Feedback::Backoff)
            );

            let buffer = context.encode();
            assert!(
                buffer.contains("mailbox_backoff_total 2"),
                "missing backoff count in metrics: {buffer}"
            );
        });
    }

    #[test]
    fn unreliable_rejected_feedback_is_not_accepted_or_counted_as_backoff() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (sender, _receiver) = super::new_unreliable(context.child("mailbox"), NZUsize!(1));
            assert_eq!(
                sender.enqueue(Message::Vote(1)),
                Unreliable::new(Feedback::Ok)
            );
            let feedback = sender.enqueue(Message::Vote(2));

            assert_eq!(feedback, Unreliable::Rejected);
            assert!(!feedback.accepted());

            let buffer = context.encode();
            assert!(
                buffer.contains("mailbox_backoff_total 0"),
                "unexpected backoff count in metrics: {buffer}"
            );
        });
    }

    #[test]
    fn try_recv_drains_buffered_messages_after_senders_drop() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Buffered(2)),
            Unreliable::new(Feedback::Backoff)
        );
        drop(sender);

        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Buffered(2)));
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));
    }

    #[test]
    fn poll_recv_drains_buffered_messages_after_senders_drop() {
        let (sender, receiver) = new_unreliable(NZUsize!(1));
        let wakes = Arc::new(WakeCounter::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Buffered(2)),
            Unreliable::new(Feedback::Backoff)
        );
        drop(sender);

        assert_eq!(
            receiver.state.poll_recv(&mut cx),
            Poll::Ready(Some(Message::Vote(1)))
        );
        assert_eq!(
            receiver.state.poll_recv(&mut cx),
            Poll::Ready(Some(Message::Buffered(2)))
        );
        assert_eq!(receiver.state.poll_recv(&mut cx), Poll::Ready(None));
    }

    #[test]
    fn enqueue_uses_ready_capacity_after_partial_drain() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(2));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Vote(2)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Required(3)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(2)));

        assert_eq!(
            sender.enqueue(Message::Vote(4)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(receiver.try_recv(), Ok(Message::Required(3)));
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(4)));
    }

    #[test]
    fn receiver_refills_overflow_after_partial_drain() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(3));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Vote(2)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Vote(3)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Required(4)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(2)));

        assert_eq!(
            sender.enqueue(Message::Vote(5)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(3)));
        assert_eq!(receiver.try_recv(), Ok(Message::Required(4)));
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(5)));
    }

    #[test_async]
    async fn full_inbox_retains_unmatched_replaceable_message() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Required(2)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Required(2)));
    }

    #[test_async]
    async fn full_inbox_replaces_stale_overflow_after_ready_fills() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(2));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Update(2)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Update(3)),
            Unreliable::new(Feedback::Backoff)
        );
        assert_eq!(
            sender.enqueue(Message::Update(4)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Update(2)));
        assert_eq!(receiver.recv().await, Some(Message::Update(4)));
    }

    #[test_async]
    async fn mailbox_capacity_is_soft_limit_for_required_messages() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Required(2)),
            Unreliable::new(Feedback::Backoff)
        );
        assert_eq!(
            sender.enqueue(Message::Required(3)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Required(2)));
        assert_eq!(receiver.recv().await, Some(Message::Required(3)));
    }

    #[test_async]
    async fn full_inbox_rejects_hint() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Hint(2)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
    }

    #[test_async]
    async fn full_inbox_can_replace_or_drop_by_message() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));
        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Update(2)),
            Unreliable::new(Feedback::Backoff)
        );
        assert_eq!(
            sender.enqueue(Message::Hint(3)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Hint(3)));
    }

    #[test_async]
    async fn empty_inbox_wakes_on_enqueue() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));

        let next = receiver.recv();
        pin_mut!(next);
        assert!(next.as_mut().now_or_never().is_none());

        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(next.await, Some(Message::Vote(1)));
    }

    #[test]
    fn pending_recv_wakes_when_senders_drop() {
        let (sender, receiver) = new_unreliable::<Message>(NZUsize!(1));
        let wakes = Arc::new(WakeCounter::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);

        assert_eq!(receiver.state.poll_recv(&mut cx), Poll::Pending);
        assert_eq!(wakes.count(), 0);

        drop(sender);

        assert_eq!(wakes.count(), 1);
        assert_eq!(receiver.state.poll_recv(&mut cx), Poll::Ready(None));
    }

    #[test]
    fn pending_recv_wakes_on_handled_overflow_enqueue() {
        let (sender, mut receiver) = new_unreliable(NZUsize!(1));
        let wakes = Arc::new(WakeCounter::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);

        assert_eq!(receiver.state.poll_recv(&mut cx), Poll::Pending);
        assert_eq!(wakes.count(), 0);

        // Prime ready directly to isolate the overflow wake after registration.
        assert_eq!(sender.state.ready.push(Message::Vote(1)), Ok(()));
        assert_eq!(
            sender.enqueue(Message::Buffered(2)),
            Unreliable::new(Feedback::Backoff)
        );

        assert_eq!(wakes.count(), 1);
        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Buffered(2)));
    }

    #[test]
    fn receiver_drop_blocks_ready_fast_path_feedback() {
        let (sender, receiver) = new_unreliable(NZUsize!(1));
        let wakes = Arc::new(WakeCounter::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);

        assert_eq!(receiver.state.poll_recv(&mut cx), Poll::Pending);
        drop(receiver);

        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Closed)
        );
        assert_eq!(wakes.count(), 0);
    }

    #[test_async]
    async fn empty_inbox_closes_when_senders_drop() {
        let (sender, mut receiver) = new_unreliable::<Message>(NZUsize!(1));
        drop(sender);

        assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));
        assert_eq!(receiver.recv().await, None);
    }

    #[test]
    fn enqueue_after_receiver_drop_returns_closed() {
        let (sender, receiver) = new_unreliable(NZUsize!(1));
        drop(receiver);

        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Unreliable::new(Feedback::Closed)
        );
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

        assert_eq!(receiver.state.poll_recv(&mut cx), Poll::Pending);
        assert_eq!(wakes.count(), 0);

        assert_eq!(sender.state.ready.push(SpillMessage::FillReady), Ok(()));
        assert_eq!(sender.enqueue(SpillMessage::Spill), Feedback::Backoff);

        assert_eq!(wakes.count(), 1);
        assert_eq!(receiver.try_recv(), Ok(SpillMessage::FillReady));
        assert_eq!(receiver.try_recv(), Ok(SpillMessage::Spill));
    }
}

#[cfg(all(test, not(feature = "loom")))]
mod coop_tests {
    use super::{mocks, *};
    use commonware_utils::{
        NZUsize,
        channel::{mpsc, oneshot, ring},
    };
    use futures::task::{ArcWake, waker_ref};
    use std::{
        future::Future,
        pin::pin,
        sync::{Arc, atomic::AtomicUsize},
    };

    /// Messages for the unreliable mailbox tests.
    #[derive(Debug, PartialEq, Eq)]
    enum Message {
        /// A message the test expects to fit in a free ready slot.
        Fill(u64),
        /// A message the test expects to be kept, possibly in overflow.
        Keep(u64),
    }

    impl UnreliablePolicy for Message {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
            overflow.push_back(message);
            true
        }
    }

    /// A reliable message whose drop is visible to a oneshot receiver.
    struct Ack {
        /// Dropped with the message, which closes the paired receiver.
        _sender: oneshot::Sender<()>,
    }

    impl Policy for Ack {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) {
            overflow.push_back(message);
        }
    }

    /// A waker that counts how often it is woken.
    #[derive(Default)]
    struct Wakes(
        /// Number of wakes so far.
        AtomicUsize,
    );

    impl Wakes {
        /// Returns the number of wakes so far.
        fn count(&self) -> usize {
            self.0.load(Ordering::Acquire)
        }
    }

    impl ArcWake for Wakes {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Creates an unreliable mailbox with `capacity` ready slots.
    fn new(capacity: usize) -> (UnreliableSender<Message>, UnreliableReceiver<Message>) {
        super::new_unreliable(mocks::Metrics, NonZeroUsize::new(capacity).unwrap())
    }

    /// Polls `receiver` once with a waker that counts into `wakes`.
    fn poll(receiver: &UnreliableReceiver<Message>, wakes: &Arc<Wakes>) -> Poll<Option<Message>> {
        let waker = waker_ref(wakes);
        let mut cx = Context::from_waker(&waker);
        receiver.state.poll_recv(&mut cx)
    }

    /// Spend the whole budget of the current scope.
    fn exhaust() {
        for _ in 0..coop::BUDGET {
            coop::charge();
        }
        assert!(coop::exhausted());
    }

    /// Returns the number of messages held in overflow.
    fn overflow_len(receiver: &UnreliableReceiver<Message>) -> usize {
        lock(&receiver.state.overflow.queue).len()
    }

    #[test]
    fn test_exhaustion_preserves_ready_and_overflow() {
        // Fill the single ready slot and push two messages into overflow.
        let (sender, mut receiver) = new(1);
        assert_eq!(
            sender.enqueue(Message::Fill(1)),
            Unreliable::new(Feedback::Ok)
        );
        for value in 2..=3 {
            assert_eq!(
                sender.enqueue(Message::Keep(value)),
                Unreliable::new(Feedback::Backoff)
            );
        }
        assert_eq!(overflow_len(&receiver), 2);
        let wakes = Arc::new(Wakes::default());

        {
            let _scope = coop::Scope::enter();
            exhaust();

            // A spent budget pops nothing and refills nothing.
            for _ in 0..3 {
                assert_eq!(poll(&receiver, &wakes), Poll::Pending);
            }
            assert_eq!(overflow_len(&receiver), 2);

            // The non-polling path is not bounded by the budget.
            assert_eq!(receiver.try_recv(), Ok(Message::Fill(1)));
        }

        // A fresh budget delivers the overflow, in order.
        let _scope = coop::Scope::enter();
        assert_eq!(poll(&receiver, &wakes), Poll::Ready(Some(Message::Keep(2))));
        assert_eq!(poll(&receiver, &wakes), Poll::Ready(Some(Message::Keep(3))));
    }

    #[test]
    fn test_exhaustion_wakes_the_polling_task_without_registering_it() {
        // Queue a message and spend the budget.
        let (sender, receiver) = new(2);
        assert_eq!(
            sender.enqueue(Message::Fill(1)),
            Unreliable::new(Feedback::Ok)
        );
        let wakes = Arc::new(Wakes::default());
        let _scope = coop::Scope::enter();
        exhaust();

        // Every exhausted poll wakes the task once.
        assert_eq!(poll(&receiver, &wakes), Poll::Pending);
        assert_eq!(wakes.count(), 1);
        assert_eq!(poll(&receiver, &wakes), Poll::Pending);
        assert_eq!(wakes.count(), 2);

        // Nothing was parked: an enqueue finds no waker to call.
        assert_eq!(
            sender.enqueue(Message::Fill(2)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(wakes.count(), 2);
    }

    #[test]
    fn test_exhausted_poll_keeps_a_parked_waker_working() {
        let (sender, receiver) = new(2);
        let wakes = Arc::new(Wakes::default());

        // Park on an empty mailbox, then run out of budget in a later poll.
        {
            let _scope = coop::Scope::enter();
            assert_eq!(poll(&receiver, &wakes), Poll::Pending);
            assert_eq!(wakes.count(), 0);
        }

        {
            let _scope = coop::Scope::enter();
            exhaust();
            assert_eq!(poll(&receiver, &wakes), Poll::Pending);
            assert_eq!(wakes.count(), 1);
        }

        // The earlier registration still delivers the sender's wake.
        assert_eq!(
            sender.enqueue(Message::Fill(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(wakes.count(), 2);

        // The next poll receives the message.
        let _scope = coop::Scope::enter();
        assert_eq!(poll(&receiver, &wakes), Poll::Ready(Some(Message::Fill(1))));
    }

    #[test]
    fn test_refill_makes_progress_through_overflow_without_loss() {
        // Queue more than three budgets, most of them in overflow, and close the mailbox.
        let budget = u64::from(coop::BUDGET);
        let total = 3 * budget + 5;
        let (sender, receiver) = new(4);
        for value in 0..total {
            assert!(sender.enqueue(Message::Keep(value)).accepted());
        }
        assert!(overflow_len(&receiver) > 0);
        drop(sender);
        let wakes = Arc::new(Wakes::default());

        // Poll until the stream ends, one scope per task poll.
        let mut next = 0;
        let mut polls = 0;
        loop {
            let _scope = coop::Scope::enter();
            polls += 1;
            let mut delivered = 0;
            let done = loop {
                match poll(&receiver, &wakes) {
                    Poll::Ready(Some(message)) => {
                        assert_eq!(message, Message::Keep(next));
                        next += 1;
                        delivered += 1;
                    }
                    Poll::Ready(None) => break true,
                    Poll::Pending => break false,
                }
            };
            assert!(delivered <= budget);
            if done {
                break;
            }
        }

        // Every message arrived in order, with one self-wake per full budget.
        assert_eq!(next, total);
        assert_eq!(polls, 4);
        assert_eq!(wakes.count(), 3);
    }

    #[test]
    fn test_empty_mailbox_does_not_charge() {
        let budget = u64::from(coop::BUDGET);
        let (sender, receiver) = new(budget as usize);
        let wakes = Arc::new(Wakes::default());
        let _scope = coop::Scope::enter();

        // Poll the empty mailbox well past one budget.
        for _ in 0..10 * budget {
            assert_eq!(poll(&receiver, &wakes), Poll::Pending);
        }

        // Parking spent no budget and caused no self-wake.
        assert!(!coop::exhausted());
        assert_eq!(wakes.count(), 0);

        // The whole budget is still there for the mailbox that has work.
        for value in 0..budget {
            assert_eq!(
                sender.enqueue(Message::Fill(value)),
                Unreliable::new(Feedback::Ok)
            );
        }
        assert_eq!(wakes.count(), 1);

        // Exactly one budget of messages is delivered.
        for value in 0..budget {
            assert_eq!(
                poll(&receiver, &wakes),
                Poll::Ready(Some(Message::Fill(value)))
            );
        }
        assert!(coop::exhausted());
    }

    #[test]
    fn test_exhaustion_keeps_buffered_messages_after_senders_drop() {
        // Queue one ready and one overflow message, then drop the sender.
        let (sender, receiver) = new(1);
        assert_eq!(
            sender.enqueue(Message::Fill(1)),
            Unreliable::new(Feedback::Ok)
        );
        assert_eq!(
            sender.enqueue(Message::Keep(2)),
            Unreliable::new(Feedback::Backoff)
        );
        drop(sender);
        let wakes = Arc::new(Wakes::default());

        {
            let _scope = coop::Scope::enter();
            exhaust();

            // Neither a message nor the end of the stream is delivered.
            assert_eq!(poll(&receiver, &wakes), Poll::Pending);
            assert_eq!(wakes.count(), 1);
        }

        // A fresh budget delivers both messages, then the end of the stream.
        let _scope = coop::Scope::enter();
        assert_eq!(poll(&receiver, &wakes), Poll::Ready(Some(Message::Fill(1))));
        assert_eq!(poll(&receiver, &wakes), Poll::Ready(Some(Message::Keep(2))));
        assert_eq!(poll(&receiver, &wakes), Poll::Ready(None));
    }

    #[test]
    fn test_receiver_drop_drains_while_the_budget_is_spent() {
        // Queue one ready and one overflow message, each holding a oneshot sender.
        let (sender, receiver) = super::new(mocks::Metrics, NZUsize!(1));
        let (ready_tx, mut ready_rx) = oneshot::channel();
        let (overflow_tx, mut overflow_rx) = oneshot::channel();
        assert_eq!(sender.enqueue(Ack { _sender: ready_tx }), Feedback::Ok);
        assert_eq!(
            sender.enqueue(Ack {
                _sender: overflow_tx
            }),
            Feedback::Backoff
        );

        // Drop the receiver with the budget spent.
        let _scope = coop::Scope::enter();
        exhaust();
        drop(receiver);

        // Both messages were dropped and the mailbox is closed. The responders
        // are checked with try_recv, which the spent budget does not defer.
        assert!(sender.state.ready.pop().is_none());
        assert!(matches!(
            ready_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(matches!(
            overflow_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        let (late_tx, _late_rx) = oneshot::channel();
        assert_eq!(sender.enqueue(Ack { _sender: late_tx }), Feedback::Closed);
    }

    #[test]
    fn test_recv_loop_yields_once_per_budget() {
        // Queue three budgets of messages and close the mailbox.
        let budget = u64::from(coop::BUDGET);
        let total = 3 * budget;
        let (sender, mut receiver) = new(4);
        for value in 0..total {
            assert!(sender.enqueue(Message::Keep(value)).accepted());
        }
        drop(sender);

        // Drive an ordinary receive loop to completion.
        let mut future = pin!(async move {
            let mut received = 0;
            while let Some(message) = receiver.recv().await {
                assert_eq!(message, Message::Keep(received));
                received += 1;
            }
            received
        });
        let wakes = Arc::new(Wakes::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);
        let mut suspensions = 0;
        let received = loop {
            // An executor enters one scope per task poll.
            let _scope = coop::Scope::enter();
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(received) => break received,
                Poll::Pending => suspensions += 1,
            }
        };

        // The loop yielded once per budget, each time with a self-wake.
        assert_eq!(received, total);
        assert_eq!(suspensions, 3);
        assert_eq!(wakes.count(), 3);
    }

    /// On the tokio runtime, which installs no commonware budget, mailbox
    /// receives spend tokio's own budget, so a fed receive loop still yields.
    #[test]
    fn test_tokio_budget_bounds_receives_on_the_tokio_runtime() {
        use commonware_runtime::{Runner as _, Spawner as _};

        let cfg = commonware_runtime::tokio::Config::new().with_worker_threads(1);
        let storage = cfg.storage_directory().clone();
        let per_poll = commonware_runtime::tokio::Runner::new(cfg).start(|context| async move {
            // Queue more messages than tokio lets one poll take, and close the
            // mailbox.
            let total = 1024u64;
            let (sender, receiver) = new(4);
            for value in 0..total {
                assert!(sender.enqueue(Message::Keep(value)).accepted());
            }
            drop(sender);

            // Drain them from a task, counting the messages each poll receives.
            context
                .spawn(move |_| async move {
                    let mut per_poll = Vec::new();
                    futures::future::poll_fn(|cx| {
                        per_poll.push(0u64);
                        loop {
                            match receiver.state.poll_recv(cx) {
                                Poll::Ready(Some(_)) => *per_poll.last_mut().unwrap() += 1,
                                Poll::Ready(None) => return Poll::Ready(()),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                    })
                    .await;
                    per_poll
                })
                .await
                .unwrap()
        });
        let _ = std::fs::remove_dir_all(storage);

        // Every message arrived, over several polls that each stayed within
        // tokio's budget of 128.
        assert_eq!(per_poll.iter().sum::<u64>(), 1024);
        assert!(per_poll.len() > 1, "{per_poll:?}");
        assert!(per_poll.iter().all(|&count| count <= 128), "{per_poll:?}");
    }

    /// Messages a mixed test keeps in mailbox overflow.
    #[derive(Debug, PartialEq, Eq)]
    struct Mixed(u32);

    impl Policy for Mixed {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) {
            overflow.push_back(message);
        }
    }

    /// A resource other than a receive that takes part in the budget: it asks
    /// before a send and charges the send it completes.
    fn poll_charged_send(
        sender: &mpsc::Sender<u32>,
        value: u32,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), mpsc::error::TrySendError<u32>>> {
        if coop::exhausted() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let sent = sender.try_send(value);
        if sent.is_ok() {
            coop::charge();
        }
        Poll::Ready(sent)
    }

    /// The wrapped mpsc, ring and mailbox receivers and a charged send spend
    /// one shared budget per poll, including messages retained in mailbox
    /// overflow. Exhaustion preserves every next value.
    #[test]
    fn test_mixed_resources_share_one_budget() {
        // Queue rounds plus two values on every resource. The mailbox keeps
        // all but the first in overflow.
        let rounds = coop::BUDGET / 4;
        let capacity = usize::try_from(rounds + 2).unwrap();
        let (sender, mut receiver) = mpsc::channel::<u32>(capacity);
        let (ring_sender, mut ring_receiver) = ring::channel::<u32>(NZUsize!(capacity));
        let (mailbox_sender, mut mailbox_receiver) = super::new(mocks::Metrics, NZUsize!(1));
        let (charged_sender, mut charged_receiver) = mpsc::channel::<u32>(capacity);
        let (full_sender, _full_receiver) = mpsc::channel::<u32>(1);
        full_sender.try_send(7).unwrap();
        for value in 0..rounds + 2 {
            sender.try_send(value).unwrap();
            assert!(ring_sender.send_lossy(value));
            assert_eq!(
                mailbox_sender.enqueue(Mixed(value)),
                if value == 0 {
                    Feedback::Ok
                } else {
                    Feedback::Backoff
                }
            );
        }

        // Run everything inside one task poll.
        let wakes = Arc::new(Wakes::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);
        let _scope = coop::Scope::enter();
        // A send that fails charges nothing.
        assert!(matches!(
            poll_charged_send(&full_sender, 9, &mut cx),
            Poll::Ready(Err(mpsc::error::TrySendError::Full(9)))
        ));

        // Four units per round spend the whole budget without a wake.
        for value in 0..rounds {
            assert_eq!(
                pin!(receiver.recv()).poll(&mut cx),
                Poll::Ready(Some(value))
            );
            assert_eq!(
                pin!(ring_receiver.recv()).poll(&mut cx),
                Poll::Ready(Some(value))
            );
            assert_eq!(
                pin!(mailbox_receiver.recv()).poll(&mut cx),
                Poll::Ready(Some(Mixed(value)))
            );
            assert!(matches!(
                poll_charged_send(&charged_sender, value, &mut cx),
                Poll::Ready(Ok(()))
            ));
        }
        assert!(coop::exhausted());
        assert_eq!(wakes.count(), 0);
        assert_eq!(receiver.len(), 2);

        // Every resource now wakes the task and takes nothing.
        let capacity_left = charged_sender.capacity();
        for _ in 0..2 {
            assert!(pin!(receiver.recv()).poll(&mut cx).is_pending());
            assert!(pin!(ring_receiver.recv()).poll(&mut cx).is_pending());
            assert!(pin!(mailbox_receiver.recv()).poll(&mut cx).is_pending());
            assert!(poll_charged_send(&charged_sender, rounds, &mut cx).is_pending());
        }
        assert_eq!(wakes.count(), 8);
        assert_eq!(receiver.len(), 2);
        assert_eq!(charged_sender.capacity(), capacity_left);

        // A refill lets every resource deliver its remaining values.
        coop::refill();
        for value in rounds..rounds + 2 {
            assert_eq!(
                pin!(receiver.recv()).poll(&mut cx),
                Poll::Ready(Some(value))
            );
            assert_eq!(
                pin!(ring_receiver.recv()).poll(&mut cx),
                Poll::Ready(Some(value))
            );
            assert_eq!(
                pin!(mailbox_receiver.recv()).poll(&mut cx),
                Poll::Ready(Some(Mixed(value)))
            );
        }
        assert!(matches!(
            poll_charged_send(&charged_sender, rounds, &mut cx),
            Poll::Ready(Ok(()))
        ));

        // The charged sends arrived in order.
        for value in 0..=rounds {
            assert_eq!(charged_receiver.try_recv(), Ok(value));
        }
        assert!(charged_receiver.try_recv().is_err());

        // Six receives and one send spent seven fresh units.
        for _ in 7..coop::BUDGET {
            assert!(!coop::exhausted());
            coop::charge();
        }
        assert!(coop::exhausted());
        assert_eq!(wakes.count(), 8);
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::{mocks, *};
    use commonware_utils::NZUsize;
    use futures::pin_mut;
    use loom::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
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

    fn new_unreliable<T: UnreliablePolicy>(
        capacity: NonZeroUsize,
    ) -> (UnreliableSender<T>, UnreliableReceiver<T>) {
        super::new_unreliable(mocks::Metrics, capacity)
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

    impl UnreliablePolicy for Message {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
            match message {
                Self::Drop(_) => false,
                Self::Spill(_) => {
                    overflow.push_back(message);
                    true
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

    impl UnreliablePolicy for ReplacingMessage {
        type Overflow = VecDeque<Self>;

        fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
            match message {
                Self::FillReady => false,
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
                    true
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
            let (sender, receiver) = new_unreliable::<Message>(NZUsize!(1));
            let wakes = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);

            let close = thread::spawn(move || {
                drop(sender);
            });

            let poll = receiver.state.poll_recv(&mut cx);
            close.join().unwrap();

            match poll {
                Poll::Ready(None) => {}
                Poll::Pending => {
                    assert!(wakes.load(Ordering::Acquire) > 0);
                    assert_eq!(receiver.state.poll_recv(&mut cx), Poll::Ready(None));
                }
                Poll::Ready(Some(_)) => panic!("unexpected message"),
            }
        });
    }

    #[test]
    fn sender_enqueue_then_drop_racing_poll_recv_drains_message() {
        loom::model(|| {
            let (sender, receiver) = new_unreliable::<Message>(NZUsize!(1));
            let wakes = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);

            let enqueue = thread::spawn(move || {
                assert_eq!(
                    sender.enqueue(Message::Spill(0)),
                    Unreliable::new(Feedback::Ok)
                );
            });

            let poll = receiver.state.poll_recv(&mut cx);
            enqueue.join().unwrap();

            match poll {
                Poll::Ready(Some(Message::Spill(0))) => {}
                Poll::Pending => {
                    assert!(wakes.load(Ordering::Acquire) > 0);
                    assert_eq!(
                        receiver.state.poll_recv(&mut cx),
                        Poll::Ready(Some(Message::Spill(0)))
                    );
                }
                Poll::Ready(None) => panic!("disconnected before draining message"),
                Poll::Ready(Some(message)) => panic!("unexpected message: {message:?}"),
            }

            assert_eq!(receiver.state.poll_recv(&mut cx), Poll::Ready(None));
        });
    }

    #[test]
    fn sender_enqueue_then_drop_racing_try_recv_drains_message() {
        loom::model(|| {
            let (sender, mut receiver) = new_unreliable::<Message>(NZUsize!(1));

            let enqueue = thread::spawn(move || {
                assert_eq!(
                    sender.enqueue(Message::Spill(0)),
                    Unreliable::new(Feedback::Ok)
                );
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
            let (sender, mut receiver) = new_unreliable::<Message>(NZUsize!(1));
            let wakes = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);

            let next = receiver.recv();
            pin_mut!(next);
            assert!(matches!(next.as_mut().poll(&mut cx), Poll::Pending));
            assert_eq!(
                sender.enqueue(Message::Spill(0)),
                Unreliable::new(Feedback::Ok)
            );

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
            let (sender, receiver) = new_unreliable::<Message>(NZUsize!(1));
            let wakes = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);

            assert_eq!(receiver.state.poll_recv(&mut cx), Poll::Pending);

            let close = thread::spawn(move || {
                drop(receiver);
            });
            let feedback = sender.enqueue(Message::Spill(0));
            close.join().unwrap();

            if feedback.accepted() {
                assert!(wakes.load(Ordering::Acquire) > 0);
            } else {
                assert_eq!(feedback, Unreliable::new(Feedback::Closed));
            }
            assert_eq!(
                sender.enqueue(Message::Spill(1)),
                Unreliable::new(Feedback::Closed)
            );
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

            assert!(
                sender
                    .state
                    .ready
                    .push(TrackedMessage::new(drops.clone()))
                    .is_ok()
            );
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
            let (sender, receiver) = new_unreliable::<Message>(NZUsize!(1));

            let enqueue_sender = sender.clone();
            let enqueue = thread::spawn(move || {
                let _ = enqueue_sender.enqueue(Message::Spill(1));
            });

            let close = thread::spawn(move || {
                drop(receiver);
            });

            enqueue.join().unwrap();
            close.join().unwrap();
            assert_eq!(
                sender.enqueue(Message::Spill(2)),
                Unreliable::new(Feedback::Closed)
            );
        });
    }

    #[test]
    fn concurrent_close_and_overflow_enqueue_remains_closed() {
        loom::model(|| {
            let (sender, receiver) = new_unreliable::<Message>(NZUsize!(1));
            assert_eq!(
                sender.enqueue(Message::Drop(0)),
                Unreliable::new(Feedback::Ok)
            );

            let enqueue_sender = sender.clone();
            let enqueue = thread::spawn(move || {
                let _ = enqueue_sender.enqueue(Message::Spill(1));
            });

            let close = thread::spawn(move || {
                drop(receiver);
            });

            enqueue.join().unwrap();
            close.join().unwrap();
            assert_eq!(
                sender.enqueue(Message::Spill(2)),
                Unreliable::new(Feedback::Closed)
            );
        });
    }

    #[test]
    fn concurrent_spill_and_refill_preserves_messages() {
        loom::model(|| {
            let (sender, mut receiver) = new_unreliable::<Message>(NZUsize!(1));
            let idle_sender = sender.clone();
            assert_eq!(
                sender.enqueue(Message::Spill(0)),
                Unreliable::new(Feedback::Ok)
            );

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
            let (sender, mut receiver) = new_unreliable::<Message>(NZUsize!(1));
            let idle_sender = sender.clone();
            assert_eq!(
                sender.enqueue(Message::Spill(0)),
                Unreliable::new(Feedback::Ok)
            );

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
            let (sender, mut receiver) = new_unreliable::<ReplacingMessage>(NZUsize!(1));
            let idle_sender = sender.clone();
            assert_eq!(
                sender.enqueue(ReplacingMessage::FillReady),
                Unreliable::new(Feedback::Ok)
            );
            assert_eq!(
                sender.enqueue(ReplacingMessage::Replace(1)),
                Unreliable::new(Feedback::Backoff)
            );

            let sender_1 = sender.clone();
            let replace_1 = thread::spawn(move || sender_1.enqueue(ReplacingMessage::Replace(2)));
            let replace_2 = thread::spawn(move || sender.enqueue(ReplacingMessage::Replace(3)));

            assert_eq!(
                replace_1.join().unwrap(),
                Unreliable::new(Feedback::Backoff)
            );
            assert_eq!(
                replace_2.join().unwrap(),
                Unreliable::new(Feedback::Backoff)
            );
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
            let (sender, mut receiver) = new_unreliable::<Message>(NZUsize!(2));
            assert_eq!(
                sender.enqueue(Message::Drop(0)),
                Unreliable::new(Feedback::Ok)
            );
            assert_eq!(
                sender.enqueue(Message::Drop(1)),
                Unreliable::new(Feedback::Ok)
            );
            assert_eq!(
                sender.enqueue(Message::Spill(2)),
                Unreliable::new(Feedback::Backoff)
            );

            assert_eq!(receiver.try_recv(), Ok(Message::Drop(0)));
            assert_eq!(receiver.try_recv(), Ok(Message::Drop(1)));

            assert_eq!(
                sender.enqueue(Message::Drop(3)),
                Unreliable::new(Feedback::Ok)
            );
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
