//! Bounded ready queues with policy-managed overflow.

use crate::Feedback;
#[cfg(not(feature = "loom"))]
use futures::task::AtomicWaker;
use std::{
    collections::VecDeque,
    fmt,
    future::poll_fn,
    num::NonZeroUsize,
    sync::mpsc::TryRecvError,
    task::{Context, Poll},
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex, MutexGuard,
        };
    } else {
        use crossbeam_queue::ArrayQueue;
        use parking_lot::{Mutex, MutexGuard};
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };
    }
}

/// Policy-managed overflow behind the bounded ready queue.
///
/// The mailbox capacity only bounds the ready queue. Overflow is controlled by
/// policy code and can grow without bound if the policy keeps spilling messages.
pub struct Overflow<'a, T> {
    queue: &'a mut VecDeque<T>,
}

impl<T> Overflow<'_, T> {
    /// Spill `message` into overflow after ready capacity is exceeded.
    pub fn spill(&mut self, message: T) -> bool {
        self.queue.push_back(message);
        true
    }

    /// Spill the message into overflow if it could not replace existing overflow work.
    pub fn replace_or_spill(&mut self, result: Result<(), T>) -> bool {
        match result {
            Ok(()) => true,
            Err(message) => self.spill(message),
        }
    }

    /// Drop the message if it could not replace existing overflow work.
    pub fn replace_or_drop(&mut self, result: Result<(), T>) -> bool {
        match result {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    /// Replace the newest matching overflow message.
    pub fn replace_last(&mut self, message: T, is_match: impl FnMut(&T) -> bool) -> Result<(), T> {
        if let Some(pending) = self.find_last_mut(is_match) {
            *pending = message;
            Ok(())
        } else {
            Err(message)
        }
    }

    /// Coalesce `message` into the newest matching overflow message, or spill it.
    pub fn coalesce_or_spill(
        &mut self,
        message: T,
        is_match: impl FnMut(&T) -> bool,
        merge: impl FnOnce(&mut T, T),
    ) -> bool {
        if let Some(pending) = self.find_last_mut(is_match) {
            merge(pending, message);
            true
        } else {
            self.spill(message)
        }
    }

    /// Coalesce `message` into preferred overflow, replace fallback overflow, or spill it.
    pub fn coalesce_or_replace_or_spill(
        &mut self,
        message: T,
        coalesce_match: impl FnMut(&T) -> bool,
        coalesce: impl FnOnce(&mut T, T),
        replace_match: impl FnMut(&T) -> bool,
    ) -> bool {
        if let Some(pending) = self.find_last_mut(coalesce_match) {
            coalesce(pending, message);
            true
        } else {
            let result = self.replace_last(message, replace_match);
            self.replace_or_spill(result)
        }
    }

    /// Find the newest matching overflow message.
    pub fn find_last_mut(&mut self, mut is_match: impl FnMut(&T) -> bool) -> Option<&mut T> {
        self.queue
            .iter_mut()
            .rev()
            .find(|message| is_match(message))
    }

    /// Remove all overflow messages.
    ///
    /// A policy may clear overflow and still return `true` from [`Policy::handle`]
    /// to request producer backoff after changing mailbox state.
    pub fn clear(&mut self) {
        self.queue.clear();
    }

    /// Replace overflow with a single spilled `message`.
    pub fn replace_all(&mut self, message: T) -> bool {
        self.clear();
        self.spill(message)
    }
}

/// Overflow behavior for actor messages when an inbox is full.
pub trait Policy: Sized {
    /// Handle `message` when it cannot enter the bounded ready queue immediately.
    ///
    /// Messages already in the ready queue are not provided here; replacement only applies to
    /// overflow spilled beyond ready capacity. Return `true` to report [`Feedback::Backoff`] or
    /// `false` to report [`Feedback::Dropped`].
    fn handle(overflow: &mut Overflow<'_, Self>, message: Self) -> bool;
}

#[cfg(feature = "loom")]
struct AtomicWaker {
    waker: Mutex<Option<std::task::Waker>>,
}

#[cfg(feature = "loom")]
impl AtomicWaker {
    fn new() -> Self {
        Self {
            waker: Mutex::new(None),
        }
    }

    fn register(&self, waker: &std::task::Waker) {
        *lock(&self.waker) = Some(waker.clone());
    }

    fn wake(&self) {
        let waker = lock(&self.waker).take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[cfg(feature = "loom")]
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap()
}

#[cfg(not(feature = "loom"))]
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock()
}

#[cfg(feature = "loom")]
struct ReadyQueue<T> {
    queue: Mutex<VecDeque<T>>,
    capacity: usize,
}

#[cfg(feature = "loom")]
impl<T> ReadyQueue<T> {
    fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            capacity,
        }
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn len(&self) -> usize {
        lock(&self.queue).len()
    }

    fn push(&self, message: T) -> Result<(), T> {
        let mut queue = lock(&self.queue);
        if queue.len() >= self.capacity {
            return Err(message);
        }
        queue.push_back(message);
        Ok(())
    }

    fn pop(&self) -> Option<T> {
        lock(&self.queue).pop_front()
    }
}

#[cfg(not(feature = "loom"))]
struct ReadyQueue<T> {
    queue: ArrayQueue<T>,
}

#[cfg(not(feature = "loom"))]
impl<T> ReadyQueue<T> {
    fn new(capacity: usize) -> Self {
        Self {
            queue: ArrayQueue::new(capacity),
        }
    }

    fn capacity(&self) -> usize {
        self.queue.capacity()
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn push(&self, message: T) -> Result<(), T> {
        self.queue.push(message)
    }

    fn pop(&self) -> Option<T> {
        self.queue.pop()
    }
}

struct OverflowState<T> {
    queue: Mutex<VecDeque<T>>,
    len: AtomicUsize,
}

impl<T> OverflowState<T> {
    #[cfg(not(feature = "loom"))]
    const fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            len: AtomicUsize::new(0),
        }
    }

    #[cfg(feature = "loom")]
    fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            len: AtomicUsize::new(0),
        }
    }

    fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    fn is_active(&self) -> bool {
        self.len() > 0
    }

    fn apply_policy(&self, message: T, is_closed: impl Fn() -> bool) -> Feedback
    where
        T: Policy,
    {
        let mut queue = lock(&self.queue);
        if is_closed() {
            return Feedback::Closed;
        }

        let backoff = {
            let mut overflow = Overflow { queue: &mut queue };
            T::handle(&mut overflow, message)
        };
        self.len.store(queue.len(), Ordering::Release);
        if backoff {
            Feedback::Backoff
        } else {
            Feedback::Dropped
        }
    }

    fn refill_ready(&self, ready: &ReadyQueue<T>) {
        let mut queue = lock(&self.queue);
        while let Some(message) = queue.pop_front() {
            match ready.push(message) {
                Ok(()) => {}
                Err(message) => {
                    queue.push_front(message);
                    break;
                }
            }
        }
        self.len.store(queue.len(), Ordering::Release);
    }
}

struct State<T> {
    ready: ReadyQueue<T>,
    overflow: OverflowState<T>,
    closed: AtomicBool,
    senders: AtomicUsize,
    receiver_waker: AtomicWaker,
}

/// Sender half of a mailbox.
pub struct Sender<T: Policy> {
    state: Arc<State<T>>,
}

impl<T: Policy> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self::from_state(&self.state)
    }
}

impl<T: Policy> Drop for Sender<T> {
    fn drop(&mut self) {
        let previous = self.state.senders.fetch_sub(1, Ordering::AcqRel);
        assert!(previous > 0);
        if previous == 1 {
            self.state.receiver_waker.wake();
        }
    }
}

impl<T: Policy> fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sender")
            .field("len", &self.len())
            .field("capacity", &self.state.ready.capacity())
            .field("closed", &self.state.closed.load(Ordering::Acquire))
            .finish()
    }
}

impl<T: Policy> Sender<T> {
    fn from_state(state: &Arc<State<T>>) -> Self {
        state.senders.fetch_add(1, Ordering::Relaxed);
        Self {
            state: state.clone(),
        }
    }

    /// Submit a message without waiting for inbox capacity.
    #[must_use = "handle dropped/closed submissions; required actor messages must not be silently dropped"]
    pub fn enqueue(&self, message: T) -> Feedback {
        if self.state.closed.load(Ordering::Acquire) {
            return Feedback::Closed;
        }

        let message = if self.state.overflow.is_active() {
            message
        } else {
            match self.state.ready.push(message) {
                Ok(()) => {
                    self.state.receiver_waker.wake();
                    return Feedback::Ok;
                }
                Err(message) => message,
            }
        };

        self.backpressure_overflow(message)
    }

    fn len(&self) -> usize {
        self.state.ready.len() + self.state.overflow.len()
    }

    fn backpressure_overflow(&self, message: T) -> Feedback {
        let feedback = self
            .state
            .overflow
            .apply_policy(message, || self.state.closed.load(Ordering::Acquire));
        if feedback == Feedback::Backoff {
            self.state.receiver_waker.wake();
        }
        feedback
    }
}

/// Receiver half of a mailbox.
pub struct Receiver<T> {
    state: Arc<State<T>>,
}

impl<T> Receiver<T> {
    /// Receive the next message.
    pub async fn recv(&mut self) -> Option<T> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        if let Some(message) = self.pop() {
            return Poll::Ready(Some(message));
        }

        if self.is_disconnected() {
            return Poll::Ready(None);
        }

        self.state.receiver_waker.register(cx.waker());

        if let Some(message) = self.pop() {
            return Poll::Ready(Some(message));
        }

        if self.is_disconnected() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    /// Try to receive the next message without waiting.
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        if let Some(message) = self.pop() {
            return Ok(message);
        }
        if self.is_disconnected() {
            return Err(TryRecvError::Disconnected);
        }
        Err(TryRecvError::Empty)
    }

    fn pop(&mut self) -> Option<T> {
        if let Some(message) = self.state.ready.pop() {
            return Some(message);
        }

        // Refill on receive so senders keep the lock-free ready path when no overflow exists.
        self.state.overflow.refill_ready(&self.state.ready);
        self.state.ready.pop()
    }

    fn is_disconnected(&self) -> bool {
        self.state.closed.load(Ordering::Acquire) || self.state.senders.load(Ordering::Acquire) == 0
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.state.closed.store(true, Ordering::Release);
    }
}

/// Create a mailbox with a bounded ready queue and policy-managed overflow.
pub fn new<T: Policy>(capacity: NonZeroUsize) -> (Sender<T>, Receiver<T>) {
    let state = Arc::new(State {
        ready: ReadyQueue::new(capacity.get()),
        overflow: OverflowState::new(),
        closed: AtomicBool::new(false),
        senders: AtomicUsize::new(0),
        receiver_waker: AtomicWaker::new(),
    });
    (Sender::from_state(&state), Receiver { state })
}

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::*;
    use commonware_macros::test_async;
    use commonware_utils::NZUsize;
    use futures::{pin_mut, FutureExt};
    use std::sync::mpsc::TryRecvError;

    #[derive(Debug, PartialEq, Eq)]
    enum Message {
        Update(u64),
        Vote(u64),
        Required(u64),
        Buffered(u64),
        Hint(u64),
    }

    impl Policy for Message {
        fn handle(overflow: &mut Overflow<'_, Self>, message: Self) -> bool {
            match message {
                Self::Update(value) => {
                    let result = overflow.replace_last(Self::Update(value), |pending| {
                        matches!(pending, Self::Update(_))
                    });
                    overflow.replace_or_spill(result)
                }
                Self::Required(_) => overflow.spill(message),
                Self::Buffered(_) => overflow.spill(message),
                Self::Hint(value) => {
                    let result = overflow.replace_last(Self::Hint(value), |pending| {
                        matches!(pending, Self::Update(_))
                    });
                    overflow.replace_or_drop(result)
                }
                Self::Vote(_) => false,
            }
        }
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
    async fn full_inbox_rejects_non_replaceable_message() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Vote(2)), Feedback::Dropped);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
    }

    #[test_async]
    async fn full_inbox_retains_required_message() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Buffered(2)), Feedback::Backoff);
        assert_eq!(sender.len(), 2);

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

    #[test_async]
    async fn full_inbox_retains_unmatched_replaceable_message() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Required(2)), Feedback::Backoff);
        assert_eq!(sender.len(), 2);

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
        assert_eq!(sender.len(), 3);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Required(2)));
        assert_eq!(receiver.recv().await, Some(Message::Required(3)));
    }

    #[test_async]
    async fn full_inbox_rejects_hint() {
        let (sender, mut receiver) = new(NZUsize!(1));
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Hint(2)), Feedback::Dropped);

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

    #[derive(Debug, PartialEq, Eq)]
    enum ClearingMessage {
        FillReady,
        ClearOverflow,
    }

    impl Policy for ClearingMessage {
        fn handle(overflow: &mut Overflow<'_, Self>, message: Self) -> bool {
            let backoff = overflow.spill(message);
            overflow.clear();
            backoff
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
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use commonware_utils::NZUsize;
    use loom::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread,
    };

    // These tests run the real actor mailbox with loom-backed atomics, mutexes,
    // and ready queue. The only modeled boundary is the production `ArrayQueue`,
    // which is replaced under the loom feature with a small capacity-preserving
    // queue because crossbeam's queue internals are not loom-instrumented.

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Message {
        Drop(u8),
        Spill(u8),
    }

    impl Policy for Message {
        fn handle(overflow: &mut Overflow<'_, Self>, message: Self) -> bool {
            match message {
                Self::Drop(_) => false,
                Self::Spill(_) => overflow.spill(message),
            }
        }
    }

    fn assert_closed(sender: &Sender<Message>) {
        assert!(sender.state.closed.load(Ordering::Acquire));
    }

    fn record(seen: &AtomicUsize, message: Message) {
        let value = match message {
            Message::Drop(value) | Message::Spill(value) => value,
        };
        seen.fetch_or(1usize << usize::from(value), Ordering::AcqRel);
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
            assert_closed(&sender);
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
            assert_closed(&sender);
            assert_eq!(sender.enqueue(Message::Spill(2)), Feedback::Closed);
        });
    }

    #[test]
    fn concurrent_spill_and_refill_preserves_messages() {
        loom::model(|| {
            let (sender, mut receiver) = new::<Message>(NZUsize!(1));
            assert_eq!(sender.enqueue(Message::Spill(0)), Feedback::Ok);

            let seen = Arc::new(AtomicUsize::new(0));
            let enqueue = thread::spawn(move || {
                let feedback = sender.enqueue(Message::Spill(1));
                assert!(matches!(feedback, Feedback::Backoff | Feedback::Ok));
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
            assert_eq!(receiver.state.ready.len(), 0);
            assert_eq!(receiver.state.overflow.len(), 0);
            assert_eq!(seen.load(Ordering::Acquire), 0b11);
        });
    }
}
