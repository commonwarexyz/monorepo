//! Actor mailboxes with explicit full-inbox behavior.

use super::mpsc;
use crate::sync::Mutex;
use std::{
    collections::VecDeque,
    fmt,
    future::poll_fn,
    sync::Arc,
    task::{Context, Poll, Waker},
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
    /// Try to replace a stale queued message, queueing the message if nothing was replaced.
    Replace,
}

/// Policy for actor messages when an inbox is full.
pub trait MessagePolicy: Sized {
    /// Stable message kind for logging and metrics.
    fn kind(&self) -> &'static str;

    /// Full-inbox behavior for this message.
    fn full_policy(&self) -> FullPolicy;

    /// Try to replace a stale queued message with `message`.
    ///
    /// This is only called when [`Self::full_policy`] returns [`FullPolicy::Replace`].
    fn replace(_queue: &mut VecDeque<Self>, message: Self) -> Result<(), Self> {
        Err(message)
    }
}

struct State<T> {
    queue: VecDeque<T>,
    capacity: usize,
    closed: bool,
    senders: usize,
    receiver_waker: Option<Waker>,
}

struct QueueMailbox<T> {
    state: Arc<Mutex<State<T>>>,
}

impl<T> Clone for QueueMailbox<T> {
    fn clone(&self) -> Self {
        self.state.lock().senders += 1;
        Self {
            state: self.state.clone(),
        }
    }
}

impl<T> Drop for QueueMailbox<T> {
    fn drop(&mut self) {
        let waker = {
            let mut state = self.state.lock();
            debug_assert!(state.senders > 0);
            state.senders -= 1;
            if state.senders == 0 {
                state.receiver_waker.take()
            } else {
                None
            }
        };

        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<T: MessagePolicy> QueueMailbox<T> {
    fn enqueue(&self, message: T) -> Enqueue<T> {
        let mut state = self.state.lock();
        if state.closed {
            return Enqueue::Closed(message);
        }

        let (result, wake) = if state.queue.len() < state.capacity {
            let wake = state.queue.is_empty();
            state.queue.push_back(message);
            (Enqueue::Queued, wake)
        } else {
            match message.full_policy() {
                FullPolicy::Reject => (Enqueue::Rejected(message), false),
                FullPolicy::Retain => {
                    state.queue.push_back(message);
                    (Enqueue::Queued, false)
                }
                FullPolicy::Replace => match T::replace(&mut state.queue, message) {
                    Ok(()) => (Enqueue::Replaced, false),
                    Err(message) => {
                        state.queue.push_back(message);
                        (Enqueue::Queued, false)
                    }
                },
            }
        };
        let waker = if wake {
            state.receiver_waker.take()
        } else {
            None
        };
        drop(state);

        if let Some(waker) = waker {
            waker.wake();
        }
        result
    }

    fn len(&self) -> usize {
        self.state.lock().queue.len()
    }

    fn capacity(&self) -> usize {
        self.state.lock().capacity
    }

    fn is_closed(&self) -> bool {
        self.state.lock().closed
    }
}

/// Sender half of an actor mailbox.
pub struct ActorMailbox<T: MessagePolicy> {
    inner: ActorMailboxInner<T>,
}

enum ActorMailboxInner<T: MessagePolicy> {
    Queue(QueueMailbox<T>),
}

impl<T: MessagePolicy> Clone for ActorMailbox<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: MessagePolicy> fmt::Debug for ActorMailbox<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActorMailbox")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("closed", &self.is_closed())
            .finish()
    }
}

impl<T: MessagePolicy> Clone for ActorMailboxInner<T> {
    fn clone(&self) -> Self {
        match self {
            Self::Queue(mailbox) => Self::Queue(mailbox.clone()),
        }
    }
}

impl<T: MessagePolicy> ActorMailbox<T> {
    /// Enqueue a message without waiting for inbox capacity.
    #[must_use = "handle queue rejection/closure; required actor messages must not be silently dropped"]
    pub fn enqueue(&self, message: T) -> Enqueue<T> {
        match &self.inner {
            ActorMailboxInner::Queue(mailbox) => mailbox.enqueue(message),
        }
    }

    /// Returns whether the receiver has been dropped.
    pub fn is_closed(&self) -> bool {
        match &self.inner {
            ActorMailboxInner::Queue(mailbox) => mailbox.is_closed(),
        }
    }

    /// Returns the number of queued messages when known.
    pub fn len(&self) -> usize {
        match &self.inner {
            ActorMailboxInner::Queue(mailbox) => mailbox.len(),
        }
    }

    /// Returns true if the inbox is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the configured capacity threshold.
    pub fn capacity(&self) -> usize {
        match &self.inner {
            ActorMailboxInner::Queue(mailbox) => mailbox.capacity(),
        }
    }
}

/// Receiver half of an actor mailbox.
pub struct ActorInbox<T> {
    state: Arc<Mutex<State<T>>>,
}

impl<T> ActorInbox<T> {
    /// Receive the next queued message.
    pub async fn recv(&mut self) -> Option<T> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut state = self.state.lock();
        if let Some(message) = state.queue.pop_front() {
            return Poll::Ready(Some(message));
        }

        if state.closed || state.senders == 0 {
            return Poll::Ready(None);
        }

        match &state.receiver_waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            _ => state.receiver_waker = Some(cx.waker().clone()),
        }

        Poll::Pending
    }

    /// Try to receive the next queued message without waiting.
    pub fn try_recv(&mut self) -> Result<T, mpsc::error::TryRecvError> {
        let mut state = self.state.lock();
        if let Some(message) = state.queue.pop_front() {
            return Ok(message);
        }
        if state.closed || state.senders == 0 {
            return Err(mpsc::error::TryRecvError::Disconnected);
        }
        Err(mpsc::error::TryRecvError::Empty)
    }
}

impl<T> Drop for ActorInbox<T> {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        state.closed = true;
        state.queue.clear();
        state.receiver_waker.take();
    }
}

/// Create an actor mailbox with a capacity threshold.
pub fn channel<T: MessagePolicy>(capacity: usize) -> (ActorMailbox<T>, ActorInbox<T>) {
    assert!(capacity > 0, "actor mailbox capacity must be greater than zero");

    let state = Arc::new(Mutex::new(State {
        queue: VecDeque::with_capacity(capacity),
        capacity,
        closed: false,
        senders: 1,
        receiver_waker: None,
    }));
    (
        ActorMailbox {
            inner: ActorMailboxInner::Queue(QueueMailbox {
                state: state.clone(),
            }),
        },
        ActorInbox { state },
    )
}

/// Replace the newest matching queued message.
pub fn replace_last<T>(
    queue: &mut VecDeque<T>,
    message: T,
    mut is_stale: impl FnMut(&T) -> bool,
) -> Result<(), T> {
    for queued in queue.iter_mut().rev() {
        if is_stale(queued) {
            *queued = message;
            return Ok(());
        }
    }
    Err(message)
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

        fn replace(queue: &mut VecDeque<Self>, message: Self) -> Result<(), Self> {
            match message {
                Self::Update(value) => replace_last(queue, Self::Update(value), |pending| {
                    matches!(pending, Self::Update(_))
                }),
                message => Err(message),
            }
        }
    }

    #[commonware_macros::test_async]
    async fn full_inbox_replaces_stale_message() {
        let (sender, mut receiver) = channel(1);
        assert_eq!(sender.enqueue(Message::Update(1)), Enqueue::Queued);
        assert_eq!(sender.enqueue(Message::Update(2)), Enqueue::Replaced);

        assert_eq!(receiver.recv().await, Some(Message::Update(2)));
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
        assert_eq!(sender.enqueue(Message::Update(3)), Enqueue::Replaced);

        assert_eq!(receiver.recv().await, Some(Message::Vote(1)));
        assert_eq!(receiver.recv().await, Some(Message::Update(3)));
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
}
