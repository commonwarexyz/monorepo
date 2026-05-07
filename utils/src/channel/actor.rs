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

/// Behavior to apply when an actor inbox is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FullPolicy {
    /// Reject the incoming message.
    Reject,
    /// Queue the incoming message, even if this exceeds the configured capacity.
    Retain,
    /// Try to replace a stale overflow message, queueing the message if nothing was replaced.
    Replace,
}

/// Policy for actor messages when an inbox is full.
pub trait MessagePolicy: Sized {
    /// Stable message kind for logging and metrics.
    fn kind(&self) -> &'static str;

    /// Full-inbox behavior for this message.
    fn full_policy(&self) -> FullPolicy;

    /// Try to replace a stale overflow message with `message`.
    ///
    /// This is only called when [`Self::full_policy`] returns [`FullPolicy::Replace`] and the
    /// bounded ready queue is full. Messages already in the ready queue are not provided here;
    /// replacement only applies to overflow retained behind the ready queue.
    fn replace(_queue: &mut VecDeque<Self>, _protected: usize, message: Self) -> Result<(), Self> {
        Err(message)
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
        let policy = message.full_policy();

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

        if matches!(policy, FullPolicy::Retain | FullPolicy::Replace) {
            self.shared.overflowing.store(true, Ordering::Release);
        }

        match policy {
            FullPolicy::Reject => {
                if self.shared.closed.load(Ordering::Acquire) {
                    Enqueue::Closed(message)
                } else {
                    Enqueue::Rejected(message)
                }
            }
            FullPolicy::Retain => self.retain_overflow(message),
            FullPolicy::Replace => self.replace_overflow(message),
        }
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

    fn retain_overflow(&self, message: T) -> Enqueue<T> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Enqueue::Closed(message);
        }
        self.shared.overflowing.store(true, Ordering::Release);

        let mut overflow = self.shared.overflow.lock();
        if self.shared.closed.load(Ordering::Acquire) {
            return Enqueue::Closed(message);
        }

        overflow.queue.push_back(message);
        self.shared.overflow_len.fetch_add(1, Ordering::Release);
        drop(overflow);

        self.shared.receiver_waker.wake();
        Enqueue::Queued
    }

    fn replace_overflow(&self, message: T) -> Enqueue<T> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Enqueue::Closed(message);
        }
        self.shared.overflowing.store(true, Ordering::Release);

        let mut overflow = self.shared.overflow.lock();
        if self.shared.closed.load(Ordering::Acquire) {
            return Enqueue::Closed(message);
        }

        match T::replace(&mut overflow.queue, 0, message) {
            Ok(()) => {
                if overflow.queue.is_empty() {
                    self.shared.overflowing.store(false, Ordering::Release);
                }
                Enqueue::Replaced
            }
            Err(message) => {
                overflow.queue.push_back(message);
                self.shared.overflow_len.fetch_add(1, Ordering::Release);
                drop(overflow);

                self.shared.receiver_waker.wake();
                Enqueue::Queued
            }
        }
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
                Ok(()) => {
                    self.shared.overflow_len.fetch_sub(1, Ordering::AcqRel);
                }
                Err(message) => {
                    overflow.queue.push_front(message);
                    break;
                }
            }
        }
        if overflow.queue.is_empty() {
            self.shared.overflowing.store(false, Ordering::Release);
        }
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

/// Replace the newest matching queued message after the protected prefix.
pub fn replace_last<T>(
    queue: &mut VecDeque<T>,
    protected: usize,
    message: T,
    is_stale: impl FnMut(&T) -> bool,
) -> Result<(), T> {
    if let Some(queued) = find_last_mut(queue, protected, is_stale) {
        *queued = message;
        Ok(())
    } else {
        Err(message)
    }
}

/// Find the newest matching queued message after the protected prefix.
pub fn find_last_mut<T>(
    queue: &mut VecDeque<T>,
    protected: usize,
    mut is_match: impl FnMut(&T) -> bool,
) -> Option<&mut T> {
    let index = (protected..queue.len())
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
        fn kind(&self) -> &'static str {
            match self {
                Self::Update(_) => "update",
                Self::Vote(_) => "vote",
                Self::Required(_) => "required",
                Self::Buffered(_) => "buffered",
                Self::Hint(_) => "hint",
            }
        }

        fn full_policy(&self) -> FullPolicy {
            match self {
                Self::Update(_) => FullPolicy::Replace,
                Self::Vote(_) => FullPolicy::Reject,
                Self::Required(_) => FullPolicy::Replace,
                Self::Buffered(_) => FullPolicy::Retain,
                Self::Hint(_) => FullPolicy::Reject,
            }
        }

        fn replace(queue: &mut VecDeque<Self>, protected: usize, message: Self) -> Result<(), Self> {
            match message {
                Self::Update(value) => replace_last(queue, protected, Self::Update(value), |pending| {
                    matches!(pending, Self::Update(_))
                }),
                message => Err(message),
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
