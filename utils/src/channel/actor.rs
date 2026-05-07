//! Actor mailboxes with explicit full-inbox behavior.

use super::mpsc;
use crate::sync::Mutex;
use crossbeam_queue::ArrayQueue;
use futures::task::AtomicWaker;
use std::{
    collections::VecDeque,
    fmt,
    future::poll_fn,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

/// Result of trying to enqueue a message.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Enqueue<T> {
    /// The message was accepted by the mailbox.
    ///
    /// This may exceed the configured capacity for messages that must be retained.
    Queued,
    /// The message replaced a stale queued message.
    Replaced,
    /// The message could not be accepted.
    Rejected(T),
    /// The receiver has been dropped.
    Closed(T),
}

impl<T> Enqueue<T> {
    /// Returns true if the message was accepted by the mailbox.
    pub const fn accepted(&self) -> bool {
        matches!(self, Self::Queued | Self::Replaced)
    }

    /// Map the payload returned with rejected or closed messages.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Enqueue<U> {
        match self {
            Self::Queued => Enqueue::Queued,
            Self::Replaced => Enqueue::Replaced,
            Self::Rejected(message) => Enqueue::Rejected(f(message)),
            Self::Closed(message) => Enqueue::Closed(f(message)),
        }
    }

    /// Drop the payload returned with rejected or closed messages.
    pub fn discard(self) -> Enqueue<()> {
        self.map(|_| ())
    }
}

impl<T> fmt::Debug for Enqueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued => f.write_str("Queued"),
            Self::Replaced => f.write_str("Replaced"),
            Self::Rejected(_) => f.write_str("Rejected"),
            Self::Closed(_) => f.write_str("Closed"),
        }
    }
}

/// Result of applying backpressure to a full actor inbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backpressure<T> {
    /// The incoming message was queued behind the bounded ready queue.
    Queued,
    /// The incoming message replaced stale overflow work.
    Replaced,
    /// Skip the incoming message.
    Skip(T),
}

impl<T> Backpressure<T> {
    /// Queue `message` behind the bounded ready queue.
    pub fn queue(queue: &mut VecDeque<T>, message: T) -> Self {
        queue.push_back(message);
        Self::Queued
    }

    /// Queue the message if it could not replace existing work.
    pub fn replace_or_queue(result: Result<(), T>, queue: &mut VecDeque<T>) -> Self {
        match result {
            Ok(()) => Self::Replaced,
            Err(message) => Self::queue(queue, message),
        }
    }

    /// Skip the message if it could not replace existing work.
    pub fn replace_or_skip(result: Result<(), T>) -> Self {
        match result {
            Ok(()) => Self::Replaced,
            Err(message) => Self::Skip(message),
        }
    }
}

/// Policy for actor messages when an inbox is full.
pub trait MessagePolicy: Sized {
    /// Apply backpressure to `message` when the bounded ready queue is full.
    ///
    /// Messages already in the ready queue are not provided here; replacement only applies to
    /// overflow retained behind the ready queue.
    fn backpressure(_queue: &mut VecDeque<Self>, message: Self) -> Backpressure<Self> {
        Backpressure::queue(_queue, message)
    }
}

struct Overflow<T> {
    queue: VecDeque<T>,
}

struct Shared<T> {
    ready: ArrayQueue<T>,
    overflow: Mutex<Overflow<T>>,
    overflow_len: AtomicUsize,
    overflowing: AtomicBool,
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
pub struct ActorMailbox<T: MessagePolicy> {
    shared: Arc<Shared<T>>,
}

impl<T: MessagePolicy> Clone for ActorMailbox<T> {
    fn clone(&self) -> Self {
        self.shared.senders.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T: MessagePolicy> Drop for ActorMailbox<T> {
    fn drop(&mut self) {
        let previous = self.shared.senders.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
        if previous == 1 {
            self.shared.receiver_waker.wake();
        }
    }
}

impl<T: MessagePolicy> fmt::Debug for ActorMailbox<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActorMailbox")
            .field("len", &self.len())
            .field("capacity", &self.shared.ready.capacity())
            .field("closed", &self.shared.closed.load(Ordering::Acquire))
            .finish()
    }
}

impl<T: MessagePolicy> ActorMailbox<T> {
    /// Enqueue a message without waiting for inbox capacity.
    #[must_use = "handle queue rejection/closure; required actor messages must not be silently dropped"]
    pub fn enqueue(&self, message: T) -> Enqueue<T> {
        let (_permit, message) = match self.acquire_send(message) {
            Ok(send) => send,
            Err(message) => return Enqueue::Closed(message),
        };

        let message = if self.shared.overflowing.load(Ordering::Acquire) {
            message
        } else {
            match self.shared.ready.push(message) {
                Ok(()) => {
                    self.shared.receiver_waker.wake();
                    return Enqueue::Queued;
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
        self.shared.ready.len() + self.shared.overflow_len.load(Ordering::Acquire)
    }

    fn backpressure_overflow(&self, message: T) -> Enqueue<T> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Enqueue::Closed(message);
        }

        let mut overflow = self.shared.overflow.lock();
        if self.shared.closed.load(Ordering::Acquire) {
            return Enqueue::Closed(message);
        }

        let old_len = overflow.queue.len();
        match T::backpressure(&mut overflow.queue, message) {
            Backpressure::Queued => {
                self.sync_overflow_state(overflow.queue.len());
                drop(overflow);

                self.shared.receiver_waker.wake();
                Enqueue::Queued
            }
            Backpressure::Replaced => {
                let new_len = overflow.queue.len();
                self.sync_overflow_state(new_len);
                if old_len == 0 && new_len > 0 {
                    self.shared.receiver_waker.wake();
                }
                Enqueue::Replaced
            }
            Backpressure::Skip(message) => {
                self.sync_overflow_state(overflow.queue.len());
                if self.shared.closed.load(Ordering::Acquire) {
                    Enqueue::Closed(message)
                } else {
                    Enqueue::Rejected(message)
                }
            }
        }
    }

    fn sync_overflow_state(&self, len: usize) {
        self.shared.overflow_len.store(len, Ordering::Release);
        self.shared.overflowing.store(len > 0, Ordering::Release);
    }
}

/// Receiver half of an actor mailbox.
pub struct ActorInbox<T> {
    shared: Arc<Shared<T>>,
}

impl<T> ActorInbox<T> {
    /// Receive the next queued message.
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

    /// Try to receive the next queued message without waiting.
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
            self.refill_ready_if_pending();
            return Some(message);
        }

        self.refill_ready();
        self.shared.ready.pop()
    }

    fn refill_ready_if_pending(&self) {
        if self.shared.overflow_len.load(Ordering::Acquire) > 0 {
            self.refill_ready();
        }
    }

    fn refill_ready(&self) {
        let mut overflow = self.shared.overflow.lock();
        while let Some(message) = overflow.queue.pop_front() {
            match self.shared.ready.push(message) {
                Ok(()) => {}
                Err(message) => {
                    overflow.queue.push_front(message);
                    break;
                }
            }
        }
        let len = overflow.queue.len();
        self.shared.overflow_len.store(len, Ordering::Release);
        self.shared.overflowing.store(len > 0, Ordering::Release);
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
        let mut overflow = self.shared.overflow.lock();
        overflow.queue.clear();
        self.shared.overflow_len.store(0, Ordering::Release);
        self.shared.overflowing.store(false, Ordering::Release);
    }
}

/// Create an actor mailbox with a bounded ready queue and policy-managed overflow.
pub fn channel<T: MessagePolicy>(capacity: usize) -> (ActorMailbox<T>, ActorInbox<T>) {
    assert!(capacity > 0, "actor mailbox capacity must be greater than zero");

    let shared = Arc::new(Shared {
        ready: ArrayQueue::new(capacity),
        overflow: Mutex::new(Overflow {
            queue: VecDeque::new(),
        }),
        overflow_len: AtomicUsize::new(0),
        overflowing: AtomicBool::new(false),
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

/// Replace the newest matching queued message.
pub fn replace_last<T>(
    queue: &mut VecDeque<T>,
    message: T,
    is_stale: impl FnMut(&T) -> bool,
) -> Result<(), T> {
    if let Some(queued) = find_last_mut(queue, is_stale) {
        *queued = message;
        Ok(())
    } else {
        Err(message)
    }
}

/// Find the newest matching queued message.
pub fn find_last_mut<T>(
    queue: &mut VecDeque<T>,
    mut is_match: impl FnMut(&T) -> bool,
) -> Option<&mut T> {
    let index = (0..queue.len())
        .rev()
        .find(|&index| is_match(queue.get(index).expect("index is in bounds")))?;
    queue.get_mut(index)
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

    impl MessagePolicy for Message {
        fn backpressure(queue: &mut VecDeque<Self>, message: Self) -> Backpressure<Self> {
            match message {
                Self::Update(value) => Backpressure::replace_or_queue(
                    replace_last(queue, Self::Update(value), |pending| {
                        matches!(pending, Self::Update(_))
                    }),
                    queue,
                ),
                Self::Required(_) => Backpressure::queue(queue, message),
                Self::Buffered(_) => Backpressure::queue(queue, message),
                Self::Hint(value) => Backpressure::replace_or_skip(replace_last(
                    queue,
                    Self::Hint(value),
                    |pending| matches!(pending, Self::Update(_)),
                )),
                Self::Vote(_) => Backpressure::Skip(message),
            }
        }
    }

    #[commonware_macros::test_async]
    async fn full_inbox_replaces_stale_overflow_message() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Update(1)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Update(2)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Update(3)), Enqueue::Replaced);

        assert_eq!(receiver.recv().await, Some(Message::Update(1)));
        assert_eq!(receiver.recv().await, Some(Message::Update(3)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_rejects_non_replaceable_message() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Enqueue::Queued);
        assert_eq!(
            sender.enqueue(Message::Vote(2)),
            Enqueue::Rejected(Message::Vote(2))
        );

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_retains_required_message() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Buffered(2)), Enqueue::Queued);
        assert_eq!(sender.len(), 2);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Buffered(2)));
    }

    #[test]
    fn try_recv_refills_from_overflow() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Buffered(2)), Enqueue::Queued);

        assert_eq!(receiver.try_recv(), Ok(Message::Vote(1)));
        assert_eq!(receiver.try_recv(), Ok(Message::Buffered(2)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_retains_unmatched_replaceable_message() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Required(2)), Enqueue::Queued);
        assert_eq!(sender.len(), 2);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Required(2)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_replaces_stale_queued_message() {
        let (sender, mut receiver) = channel(2);
        assert_eq!(sender.enqueue(Message::Vote(1)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Update(2)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Update(3)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Update(4)), Enqueue::Replaced);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Update(2)));
        assert_eq!(receiver.recv().await, Some(Message::Update(4)));
    }

    #[commonware_macros::test_async]
    async fn mailbox_capacity_is_soft_limit_for_required_messages() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Required(2)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Required(3)), Enqueue::Queued);
        assert_eq!(sender.len(), 3);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Required(2)));
        assert_eq!(receiver.recv().await, Some(Message::Required(3)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_rejects_hint() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Enqueue::Queued);
        assert_eq!(
            sender.enqueue(Message::Hint(2)),
            Enqueue::Rejected(Message::Hint(2))
        );

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
    }

    #[commonware_macros::test_async]
    async fn full_inbox_can_replace_or_skip_by_message() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Vote(1)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Update(2)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Hint(3)), Enqueue::Replaced);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Hint(3)));
    }

    #[commonware_macros::test_async]
    async fn empty_inbox_wakes_on_enqueue() {
        let (sender, mut receiver) = channel(1);

        let next = receiver.recv();
        pin_mut!(next);
        assert!(next.as_mut().now_or_never().is_none());

        assert_eq!(sender.enqueue(Message::Vote(1)), Enqueue::Queued);
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
            Enqueue::Closed(Message::Vote(1))
        );
    }
}
