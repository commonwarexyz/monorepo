//! Actor mailboxes with explicit full-inbox behavior.

use super::{mpsc, Feedback};
use std::{
    collections::VecDeque,
    future::poll_fn,
    fmt,
    task::{Context, Poll},
};

#[cfg(not(feature = "loom"))]
use futures::task::AtomicWaker;

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex, MutexGuard,
        };
    } else {
        use crate::sync::{Mutex, MutexGuard};
        use crossbeam_queue::ArrayQueue;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
    }
}

/// Policy-managed overflow behind the bounded ready queue.
pub struct Overflow<'a, T> {
    queue: &'a mut VecDeque<T>,
}

impl<T> Overflow<'_, T> {
    /// Spill `message` into overflow after capacity is exceeded.
    pub fn spill(&mut self, message: T) -> Feedback {
        self.queue.push_back(message);
        Feedback::Backoff
    }

    /// Spill the message into overflow if it could not replace existing overflow work.
    pub fn replace_or_spill(&mut self, result: Result<(), T>) -> Feedback {
        match result {
            Ok(()) => Feedback::Backoff,
            Err(message) => self.spill(message),
        }
    }

    /// Drop the message if it could not replace existing overflow work.
    pub fn replace_or_drop(&mut self, result: Result<(), T>) -> Feedback {
        match result {
            Ok(()) => Feedback::Backoff,
            Err(_) => Feedback::Dropped,
        }
    }

    /// Replace the newest matching overflow message.
    pub fn replace_last(
        &mut self,
        message: T,
        is_stale: impl FnMut(&T) -> bool,
    ) -> Result<(), T> {
        if let Some(pending) = self.find_last_mut(is_stale) {
            *pending = message;
            Ok(())
        } else {
            Err(message)
        }
    }

    /// Find the newest matching overflow message.
    pub fn find_last_mut(&mut self, mut is_match: impl FnMut(&T) -> bool) -> Option<&mut T> {
        self.queue.iter_mut().rev().find(|message| is_match(message))
    }

    /// Remove all overflow messages.
    pub fn clear(&mut self) {
        self.queue.clear();
    }

    /// Replace overflow with a single spilled `message`.
    pub fn replace_all(&mut self, message: T) -> Feedback {
        self.clear();
        self.spill(message)
    }
}

/// Backpressure behavior for actor messages when an inbox is full.
pub trait Backpressure: Sized {
    /// Handle `message` when the bounded ready queue is full.
    ///
    /// Messages already in the ready queue are not provided here; replacement only applies to
    /// overflow spilled beyond ready capacity.
    fn handle(overflow: &mut Overflow<'_, Self>, message: Self) -> Feedback;
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

#[cfg(feature = "loom")]
fn spin_loop() {
    loom::thread::yield_now();
}

#[cfg(not(feature = "loom"))]
fn spin_loop() {
    std::hint::spin_loop();
}

struct OverflowState<T> {
    queue: Mutex<VecDeque<T>>,
    len: AtomicUsize,
}

impl<T> OverflowState<T> {
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
        T: Backpressure,
    {
        let mut queue = lock(&self.queue);
        if is_closed() {
            return Feedback::Closed;
        }

        let feedback = {
            let mut overflow = Overflow { queue: &mut queue };
            T::handle(&mut overflow, message)
        };
        self.len.store(queue.len(), Ordering::Release);
        feedback
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

    fn clear(&self) {
        let mut queue = lock(&self.queue);
        queue.clear();
        self.len.store(0, Ordering::Release);
    }
}

struct Shared<T> {
    ready: ReadyQueue<T>,
    overflow: OverflowState<T>,
    lifecycle: AtomicUsize,
    senders: AtomicUsize,
    receiver_waker: AtomicWaker,
}

const LIFECYCLE_CLOSED: usize = 1;
const LIFECYCLE_INFLIGHT: usize = 2;

impl<T> Shared<T> {
    fn is_closed(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) & LIFECYCLE_CLOSED != 0
    }

    fn close(&self) {
        self.lifecycle
            .fetch_or(LIFECYCLE_CLOSED, Ordering::AcqRel);
    }

    fn inflight(&self) -> usize {
        self.lifecycle.load(Ordering::Acquire) & !LIFECYCLE_CLOSED
    }
}

struct SendPermit<'a, T> {
    shared: &'a Shared<T>,
}

impl<T> Drop for SendPermit<'_, T> {
    fn drop(&mut self) {
        self.shared
            .lifecycle
            .fetch_sub(LIFECYCLE_INFLIGHT, Ordering::AcqRel);
    }
}

/// Sender half of an actor mailbox.
pub struct ActorMailbox<T: Backpressure> {
    shared: Arc<Shared<T>>,
}

impl<T: Backpressure> Clone for ActorMailbox<T> {
    fn clone(&self) -> Self {
        self.shared.senders.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T: Backpressure> Drop for ActorMailbox<T> {
    fn drop(&mut self) {
        let previous = self.shared.senders.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
        if previous == 1 {
            self.shared.receiver_waker.wake();
        }
    }
}

impl<T: Backpressure> fmt::Debug for ActorMailbox<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActorMailbox")
            .field("len", &self.len())
            .field("capacity", &self.shared.ready.capacity())
            .field("closed", &self.shared.is_closed())
            .finish()
    }
}

impl<T: Backpressure> ActorMailbox<T> {
    /// Submit a message without waiting for inbox capacity.
    #[must_use = "handle dropped/closed submissions; required actor messages must not be silently dropped"]
    pub fn enqueue(&self, message: T) -> Feedback {
        let (_permit, message) = match self.acquire_send(message) {
            Ok(send) => send,
            Err(_) => return Feedback::Closed,
        };

        let message = if self.shared.overflow.is_active() {
            message
        } else {
            match self.shared.ready.push(message) {
                Ok(()) => {
                    self.shared.receiver_waker.wake();
                    return Feedback::Ok;
                }
                Err(message) => message,
            }
        };

        self.backpressure_overflow(message)
    }

    fn acquire_send(&self, message: T) -> Result<(SendPermit<'_, T>, T), T> {
        let mut lifecycle = self.shared.lifecycle.load(Ordering::Acquire);
        loop {
            if lifecycle & LIFECYCLE_CLOSED != 0 {
                return Err(message);
            }
            match self.shared.lifecycle.compare_exchange_weak(
                lifecycle,
                lifecycle + LIFECYCLE_INFLIGHT,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok((
                        SendPermit {
                            shared: &self.shared,
                        },
                        message,
                    ));
                }
                Err(next) => lifecycle = next,
            }
        }
    }

    fn len(&self) -> usize {
        self.shared.ready.len() + self.shared.overflow.len()
    }

    fn backpressure_overflow(&self, message: T) -> Feedback {
        if self.shared.is_closed() {
            return Feedback::Closed;
        }

        let feedback = self
            .shared
            .overflow
            .apply_policy(message, || self.shared.is_closed());
        match feedback {
            Feedback::Backoff => {
                if self.shared.overflow.is_active() {
                    self.shared.receiver_waker.wake();
                }
                Feedback::Backoff
            }
            Feedback::Dropped if self.shared.is_closed() => Feedback::Closed,
            feedback => feedback,
        }
    }
}

/// Receiver half of an actor mailbox.
pub struct ActorInbox<T> {
    shared: Arc<Shared<T>>,
}

impl<T> ActorInbox<T> {
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

        self.shared.receiver_waker.register(cx.waker());

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
    pub fn try_recv(&mut self) -> Result<T, mpsc::error::TryRecvError> {
        if let Some(message) = self.pop() {
            return Ok(message);
        }
        if self.is_disconnected() {
            return Err(mpsc::error::TryRecvError::Disconnected);
        }
        Err(mpsc::error::TryRecvError::Empty)
    }

    fn pop(&mut self) -> Option<T> {
        if let Some(message) = self.shared.ready.pop() {
            return Some(message);
        }

        self.shared.overflow.refill_ready(&self.shared.ready);
        self.shared.ready.pop()
    }

    fn is_disconnected(&self) -> bool {
        self.shared.is_closed() || self.shared.senders.load(Ordering::Acquire) == 0
    }
}

impl<T> Drop for ActorInbox<T> {
    fn drop(&mut self) {
        self.shared.close();
        while self.shared.inflight() != 0 {
            spin_loop();
        }
        while self.shared.ready.pop().is_some() {}
        self.shared.overflow.clear();
    }
}

/// Create an actor mailbox with a bounded ready queue and policy-managed overflow.
pub fn channel<T: Backpressure>(capacity: usize) -> (ActorMailbox<T>, ActorInbox<T>) {
    assert!(capacity > 0, "actor mailbox capacity must be greater than zero");

    let shared = Arc::new(Shared {
        ready: ReadyQueue::new(capacity),
        overflow: OverflowState::new(),
        lifecycle: AtomicUsize::new(0),
        senders: AtomicUsize::new(1),
        receiver_waker: AtomicWaker::new(),
    });
    (
        ActorMailbox {
            shared: shared.clone(),
        },
        ActorInbox { shared },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{pin_mut, FutureExt};

    #[derive(Debug, PartialEq, Eq)]
    enum Message {
        Update(u64),
        Vote(u64),
        Required(u64),
        Buffered(u64),
        Hint(u64),
    }

    impl Backpressure for Message {
        fn handle(overflow: &mut Overflow<'_, Self>, message: Self) -> Feedback {
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
                Self::Vote(_) => Feedback::Dropped,
            }
        }
    }

    #[commonware_macros::test_async]
    async fn full_inbox_replaces_stale_overflow_message() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Update(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Update(2)), Feedback::Backoff);
        assert_eq!(sender.enqueue(Message::Update(3)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Update(1)));
        assert_eq!(receiver.recv().await, Some(Message::Update(3)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_rejects_non_replaceable_message() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(
            sender.enqueue(Message::Vote(2)),
            Feedback::Dropped
        );

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_retains_required_message() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Buffered(2)), Feedback::Backoff);
        assert_eq!(sender.len(), 2);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Buffered(2)));
    }

    #[test]
    fn try_recv_refills_from_overflow() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Buffered(2)), Feedback::Backoff);

        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Buffered(2)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_retains_unmatched_replaceable_message() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Required(2)), Feedback::Backoff);
        assert_eq!(sender.len(), 2);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Required(2)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_replaces_stale_overflow_after_ready_fills() {
        let (sender, mut receiver) = channel(2);
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Update(2)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Update(3)), Feedback::Backoff);
        assert_eq!(sender.enqueue(Message::Update(4)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Update(2)));
        assert_eq!(receiver.recv().await, Some(Message::Update(4)));
    }

    #[commonware_macros::test_async]
    async fn mailbox_capacity_is_soft_limit_for_required_messages() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Required(2)), Feedback::Backoff);
        assert_eq!(sender.enqueue(Message::Required(3)), Feedback::Backoff);
        assert_eq!(sender.len(), 3);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Required(2)));
        assert_eq!(receiver.recv().await, Some(Message::Required(3)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_rejects_hint() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(
            sender.enqueue(Message::Hint(2)),
            Feedback::Dropped
        );

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_can_replace_or_drop_by_message() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(sender.enqueue(Message::Update(2)), Feedback::Backoff);
        assert_eq!(sender.enqueue(Message::Hint(3)), Feedback::Backoff);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Hint(3)));
    }

    #[commonware_macros::test_async]
    async fn empty_inbox_wakes_on_enqueue() {
        let (sender, mut receiver) = channel(1);

        let next = receiver.recv();
        pin_mut!(next);
        assert!(next.as_mut().now_or_never().is_none());

        assert_eq!(sender.enqueue(Message::Vote(1)), Feedback::Ok);
        assert_eq!(next.await, Some(Message::Vote(1)));
    }

    #[commonware_macros::test_async]
    async fn empty_inbox_closes_when_senders_drop() {
        let (sender, mut receiver) = channel::<Message>(1);
        drop(sender);

        assert_eq!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        );
        assert_eq!(receiver.recv().await, None);
    }

    #[test]
    fn enqueue_after_receiver_drop_returns_closed() {
        let (sender, receiver) = channel(1);
        drop(receiver);

        assert_eq!(
            sender.enqueue(Message::Vote(1)),
            Feedback::Closed
        );
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
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

    impl Backpressure for Message {
        fn handle(overflow: &mut Overflow<'_, Self>, message: Self) -> Feedback {
            match message {
                Self::Drop(_) => Feedback::Dropped,
                Self::Spill(_) => overflow.spill(message),
            }
        }
    }

    fn assert_closed_and_empty(sender: &ActorMailbox<Message>) {
        assert!(sender.shared.is_closed());
        assert_eq!(sender.shared.inflight(), 0);
        assert_eq!(sender.shared.ready.len(), 0);
        assert_eq!(sender.shared.overflow.len(), 0);
    }

    fn record(seen: &AtomicUsize, message: Message) {
        let value = match message {
            Message::Drop(value) | Message::Spill(value) => value,
        };
        seen.fetch_or(1usize << usize::from(value), Ordering::AcqRel);
    }

    #[test]
    fn close_waits_for_inflight_ready_enqueue() {
        loom::model(|| {
            let (sender, receiver) = channel::<Message>(1);

            let enqueue_sender = sender.clone();
            let enqueue = thread::spawn(move || {
                let _ = enqueue_sender.enqueue(Message::Spill(1));
            });

            let close = thread::spawn(move || {
                drop(receiver);
            });

            enqueue.join().unwrap();
            close.join().unwrap();
            assert_closed_and_empty(&sender);
            assert_eq!(sender.enqueue(Message::Spill(2)), Feedback::Closed);
        });
    }

    #[test]
    fn close_waits_for_inflight_overflow_enqueue() {
        loom::model(|| {
            let (sender, receiver) = channel::<Message>(1);
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
            assert_closed_and_empty(&sender);
            assert_eq!(sender.enqueue(Message::Spill(2)), Feedback::Closed);
        });
    }

    #[test]
    fn concurrent_spill_and_refill_preserves_messages() {
        loom::model(|| {
            let (sender, mut receiver) = channel::<Message>(1);
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
            assert_eq!(receiver.shared.ready.len(), 0);
            assert_eq!(receiver.shared.overflow.len(), 0);
            assert_eq!(seen.load(Ordering::Acquire), 0b11);
        });
    }
}
