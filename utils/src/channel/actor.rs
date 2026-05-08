//! Actor mailboxes with explicit full-inbox behavior.

use super::{mpsc, Feedback};
use crate::sync::Mutex;
use crossbeam_queue::ArrayQueue;
use futures::task::AtomicWaker;
use std::{
    collections::VecDeque,
    future::poll_fn,
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

/// Backpressure behavior for actor messages when an inbox is full.
pub trait Backpressure: Sized {
    /// Handle `message` when the bounded ready queue is full.
    ///
    /// Messages already in the ready queue are not provided here; replacement only applies to
    /// overflow retained behind the ready queue.
    fn handle(queue: &mut VecDeque<Self>, message: Self) -> Feedback;
}

struct Overflow<T> {
    queue: Mutex<VecDeque<T>>,
    len: AtomicUsize,
}

impl<T> Overflow<T> {
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

    fn apply_policy(&self, message: T, closed: &AtomicBool) -> Feedback
    where
        T: Backpressure,
    {
        let mut queue = self.queue.lock();
        if closed.load(Ordering::Acquire) {
            return Feedback::Closed;
        }

        let feedback = T::handle(&mut queue, message);
        self.len.store(queue.len(), Ordering::Release);
        feedback
    }

    fn refill_ready(&self, ready: &ArrayQueue<T>) {
        let mut queue = self.queue.lock();
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
        let mut queue = self.queue.lock();
        queue.clear();
        self.len.store(0, Ordering::Release);
    }
}

struct Shared<T> {
    ready: ArrayQueue<T>,
    overflow: Overflow<T>,
    closed: AtomicBool,
    inflight: AtomicUsize,
    senders: AtomicUsize,
    receiver_waker: AtomicWaker,
}

struct SendPermit<'a, T> {
    shared: &'a Shared<T>,
}

impl<T> Drop for SendPermit<'_, T> {
    fn drop(&mut self) {
        self.shared.inflight.fetch_sub(1, Ordering::AcqRel);
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
            .field("closed", &self.shared.closed.load(Ordering::Acquire))
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
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(message);
        }

        self.shared.inflight.fetch_add(1, Ordering::AcqRel);
        if self.shared.closed.load(Ordering::Acquire) {
            self.shared.inflight.fetch_sub(1, Ordering::AcqRel);
            Err(message)
        } else {
            Ok((
                SendPermit {
                    shared: &self.shared,
                },
                message,
            ))
        }
    }

    fn len(&self) -> usize {
        self.shared.ready.len() + self.shared.overflow.len()
    }

    fn backpressure_overflow(&self, message: T) -> Feedback {
        if self.shared.closed.load(Ordering::Acquire) {
            return Feedback::Closed;
        }

        let feedback = self
            .shared
            .overflow
            .apply_policy(message, &self.shared.closed);
        match feedback {
            Feedback::Backoff => {
                if self.shared.overflow.is_active() {
                    self.shared.receiver_waker.wake();
                }
                Feedback::Backoff
            }
            Feedback::Dropped if self.shared.closed.load(Ordering::Acquire) => Feedback::Closed,
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
        self.shared.closed.load(Ordering::Acquire)
            || self.shared.senders.load(Ordering::Acquire) == 0
    }
}

impl<T> Drop for ActorInbox<T> {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        while self.shared.inflight.load(Ordering::Acquire) != 0 {
            std::hint::spin_loop();
        }
        while self.shared.ready.pop().is_some() {}
        self.shared.overflow.clear();
    }
}

/// Create an actor mailbox with a bounded ready queue and policy-managed overflow.
pub fn channel<T: Backpressure>(capacity: usize) -> (ActorMailbox<T>, ActorInbox<T>) {
    assert!(capacity > 0, "actor mailbox capacity must be greater than zero");

    let shared = Arc::new(Shared {
        ready: ArrayQueue::new(capacity),
        overflow: Overflow::new(),
        closed: AtomicBool::new(false),
        inflight: AtomicUsize::new(0),
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

/// Retain `message` in overflow.
pub fn retain<T>(queue: &mut VecDeque<T>, message: T) -> Feedback {
    queue.push_back(message);
    Feedback::Backoff
}

/// Retain the message in overflow if it could not replace existing overflow work.
pub fn replace_or_retain<T>(result: Result<(), T>, queue: &mut VecDeque<T>) -> Feedback {
    match result {
        Ok(()) => Feedback::Backoff,
        Err(message) => retain(queue, message),
    }
}

/// Drop the message if it could not replace existing overflow work.
pub fn replace_or_drop<T>(result: Result<(), T>) -> Feedback {
    match result {
        Ok(()) => Feedback::Backoff,
        Err(_) => Feedback::Dropped,
    }
}

/// Replace the newest matching overflow message.
pub fn replace_last<T>(
    queue: &mut VecDeque<T>,
    message: T,
    is_stale: impl FnMut(&T) -> bool,
) -> Result<(), T> {
    if let Some(pending) = find_last_mut(queue, is_stale) {
        *pending = message;
        Ok(())
    } else {
        Err(message)
    }
}

/// Find the newest matching overflow message.
pub fn find_last_mut<T>(
    queue: &mut VecDeque<T>,
    mut is_match: impl FnMut(&T) -> bool,
) -> Option<&mut T> {
    queue.iter_mut().rev().find(|message| is_match(message))
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
        fn handle(queue: &mut VecDeque<Self>, message: Self) -> Feedback {
            match message {
                Self::Update(value) => replace_or_retain(
                    replace_last(queue, Self::Update(value), |pending| {
                        matches!(pending, Self::Update(_))
                    }),
                    queue,
                ),
                Self::Required(_) => retain(queue, message),
                Self::Buffered(_) => retain(queue, message),
                Self::Hint(value) => replace_or_drop(replace_last(
                    queue,
                    Self::Hint(value),
                    |pending| matches!(pending, Self::Update(_)),
                )),
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
