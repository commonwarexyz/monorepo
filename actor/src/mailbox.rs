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

const OVERFLOW_HAS_MESSAGES: usize = 1;
const OVERFLOW_MUTATION: usize = 2;

/// Policy-managed overflow behind the bounded ready queue.
///
/// Mailbox capacity only bounds the ready queue. Overflow is controlled by
/// policy code and can grow without bound if the policy keeps spilling messages.
/// [`Feedback::Backoff`] is advisory and does not imply that the mailbox enforced
/// a hard bound on retained overflow work.
pub struct Overflow<'a, T> {
    queue: &'a mut VecDeque<T>,
}

impl<T> Overflow<'_, T> {
    /// Spill `message` into overflow after ready capacity is exceeded.
    pub fn spill(&mut self, message: T) -> &mut Self {
        self.queue.push_back(message);
        self
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
    pub fn clear(&mut self) -> &mut Self {
        self.queue.clear();
        self
    }
}

/// Overflow behavior for actor messages when an inbox is full.
pub trait Policy: Sized {
    /// Handle `message` when it cannot enter the bounded ready queue immediately.
    ///
    /// Messages already in the ready queue are not provided here; replacement only applies to
    /// overflow spilled beyond ready capacity. Policies that retain overflow are responsible for
    /// bounding it when a hard memory limit is required. The returned value is feedback for this
    /// enqueue attempt after the policy has made any overflow changes; it does not guarantee that
    /// `message` or any existing overflow item was retained. Return `true` to report
    /// [`Feedback::Backoff`] or `false` to report [`Feedback::Dropped`].
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
struct ReadyState<T> {
    published: VecDeque<T>,
    reserved: usize,
}

#[cfg(feature = "loom")]
struct ReadyQueue<T> {
    state: Mutex<ReadyState<T>>,
    capacity: usize,
}

#[cfg(feature = "loom")]
impl<T> ReadyQueue<T> {
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

    fn len(&self) -> usize {
        let state = lock(&self.state);
        state.published.len() + state.reserved
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
    activity: AtomicUsize,
}

impl<T> OverflowState<T> {
    #[allow(clippy::missing_const_for_fn)]
    fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            activity: AtomicUsize::new(0),
        }
    }

    fn is_active(&self) -> bool {
        self.activity.load(Ordering::SeqCst) != 0
    }

    fn try_push_ready(&self, ready: &ReadyQueue<T>, message: T) -> Result<(), T> {
        if self.is_active() {
            return Err(message);
        }
        ready.push(message)
    }

    fn enqueue(&self, ready: &ReadyQueue<T>, message: T, is_closed: impl Fn() -> bool) -> Feedback
    where
        T: Policy,
    {
        let _mutation = self.begin_mutation();
        let mut queue = lock(&self.queue);
        if is_closed() {
            self.publish_activity(&queue);
            return Feedback::Closed;
        }

        let message = match Self::try_ready_if_overflow_empty_locked(&queue, ready, message) {
            Ok(()) => {
                self.publish_activity(&queue);
                return Feedback::Ok;
            }
            Err(message) => message,
        };

        let feedback = Self::apply_policy_locked(&mut queue, message);
        self.publish_activity(&queue);
        feedback
    }

    fn refill_ready(&self, ready: &ReadyQueue<T>) {
        if !self.is_active() {
            return;
        }

        let _mutation = self.begin_mutation();
        let mut queue = lock(&self.queue);
        Self::refill_ready_locked(&mut queue, ready);
        self.publish_activity(&queue);
    }

    fn begin_mutation(&self) -> Mutation<'_> {
        self.activity.fetch_add(OVERFLOW_MUTATION, Ordering::SeqCst);
        Mutation {
            activity: &self.activity,
        }
    }

    fn try_ready_if_overflow_empty_locked(
        queue: &VecDeque<T>,
        ready: &ReadyQueue<T>,
        message: T,
    ) -> Result<(), T> {
        // The overflow lock is the ordering point for senders. A message may
        // enter ready directly only when no older overflow exists.
        if queue.is_empty() {
            ready.push(message)
        } else {
            Err(message)
        }
    }

    fn apply_policy_locked(queue: &mut VecDeque<T>, message: T) -> Feedback
    where
        T: Policy,
    {
        let mut overflow = Overflow { queue };
        if T::handle(&mut overflow, message) {
            Feedback::Backoff
        } else {
            Feedback::Dropped
        }
    }

    fn refill_ready_locked(queue: &mut VecDeque<T>, ready: &ReadyQueue<T>) {
        while let Some(message) = queue.pop_front() {
            match ready.push(message) {
                Ok(()) => {}
                Err(message) => {
                    queue.push_front(message);
                    break;
                }
            }
        }
    }

    fn publish_activity(&self, queue: &VecDeque<T>) {
        if queue.is_empty() {
            self.activity
                .fetch_and(!OVERFLOW_HAS_MESSAGES, Ordering::SeqCst);
        } else {
            self.activity
                .fetch_or(OVERFLOW_HAS_MESSAGES, Ordering::SeqCst);
        }
    }
}

struct Mutation<'a> {
    activity: &'a AtomicUsize,
}

impl Drop for Mutation<'_> {
    fn drop(&mut self) {
        let previous = self.activity.fetch_sub(OVERFLOW_MUTATION, Ordering::SeqCst);
        assert!(previous >= OVERFLOW_MUTATION);
    }
}

struct State<T> {
    ready: ReadyQueue<T>,
    overflow: OverflowState<T>,
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
    #[must_use = "handle dropped/closed submissions; required actor messages must not be silently dropped"]
    pub fn enqueue(&self, message: T) -> Feedback {
        if self.state.closed.load(Ordering::Acquire) {
            return Feedback::Closed;
        }

        let message = match self
            .state
            .overflow
            .try_push_ready(&self.state.ready, message)
        {
            Ok(()) => {
                self.state.waker.wake();
                return Feedback::Ok;
            }
            Err(message) => message,
        };

        let feedback = self.state.overflow.enqueue(&self.state.ready, message, || {
            self.state.closed.load(Ordering::Acquire)
        });
        if feedback.accepted() {
            self.state.waker.wake();
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

        self.state.waker.register(cx.waker());

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
            if self.state.overflow.is_active() && self.state.ready.len() == 0 {
                self.state.overflow.refill_ready(&self.state.ready);
            }
            return Some(message);
        }

        // Empty ready may race with stale activity, so let `refill_ready`
        // decide whether overflow is worth locking.
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

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::*;
    use commonware_macros::test_async;
    use commonware_utils::NZUsize;
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
                    overflow
                        .replace_last(Self::Update(value), |pending| {
                            matches!(pending, Self::Update(_))
                        })
                        .unwrap_or_else(|message| {
                            overflow.spill(message);
                        });
                    true
                }
                Self::Required(_) | Self::Buffered(_) => {
                    overflow.spill(message);
                    true
                }
                Self::Hint(value) => {
                    let result = overflow.replace_last(Self::Hint(value), |pending| {
                        matches!(pending, Self::Update(_))
                    });
                    result.is_ok()
                }
                Self::Vote(_) => false,
            }
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
    fn pending_recv_wakes_on_accepted_overflow_enqueue() {
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

    #[derive(Debug, PartialEq, Eq)]
    enum ClearingMessage {
        FillReady,
        ClearOverflow,
    }

    impl Policy for ClearingMessage {
        fn handle(overflow: &mut Overflow<'_, Self>, message: Self) -> bool {
            overflow.spill(message);
            overflow.clear();
            true
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
    use std::task::{RawWaker, RawWakerVTable, Waker};

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

    impl Policy for Message {
        fn handle(overflow: &mut Overflow<'_, Self>, message: Self) -> bool {
            match message {
                Self::Drop(_) => false,
                Self::Spill(_) => {
                    overflow.spill(message);
                    true
                }
            }
        }
    }

    impl Policy for OrderedMessage {
        fn handle(overflow: &mut Overflow<'_, Self>, message: Self) -> bool {
            let gate = match &message {
                Self::Item(_) => None,
                Self::Coordinated(_, gate) => Some(gate.clone()),
            };
            overflow.spill(message);
            if let Some(gate) = gate {
                gate.store(1, Ordering::Release);
                while gate.load(Ordering::Acquire) == 1 {
                    thread::yield_now();
                }
            }
            true
        }
    }

    impl Policy for ReplacingMessage {
        fn handle(overflow: &mut Overflow<'_, Self>, message: Self) -> bool {
            match message {
                Self::FillReady => false,
                Self::Replace(_) => {
                    overflow
                        .replace_last(message, |pending| matches!(pending, Self::Replace(_)))
                        .unwrap_or_else(|message| {
                            overflow.spill(message);
                        });
                    true
                }
            }
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
    fn accepted_overflow_enqueue_wakes_registered_receiver() {
        loom::model(|| {
            let (sender, mut receiver) = new::<Message>(NZUsize!(1));
            let wakes = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);

            assert_eq!(receiver.poll_recv(&mut cx), Poll::Pending);
            assert_eq!(sender.state.ready.push(Message::Drop(0)), Ok(()));
            assert_eq!(sender.enqueue(Message::Spill(1)), Feedback::Backoff);

            assert_eq!(wakes.load(Ordering::Acquire), 1);
            assert_eq!(receiver.try_recv(), Ok(Message::Drop(0)));
            assert_eq!(receiver.try_recv(), Ok(Message::Spill(1)));
        });
    }

    #[test]
    fn receiver_drop_racing_ready_fast_path_feedback_wakes_if_accepted() {
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

            match feedback {
                Feedback::Ok => assert!(wakes.load(Ordering::Acquire) > 0),
                Feedback::Closed => {}
                feedback => panic!("unexpected feedback: {feedback:?}"),
            }
            assert_eq!(sender.enqueue(Message::Spill(1)), Feedback::Closed);
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

            let mut observed = vec![value(receiver.try_recv().unwrap())];
            gate.store(2, Ordering::Release);
            let feedback = sender.enqueue(OrderedMessage::Item(3));
            assert!(matches!(feedback, Feedback::Backoff | Feedback::Ok));

            overflow.join().unwrap();
            while let Ok(message) = receiver.try_recv() {
                observed.push(value(message));
            }

            assert_eq!(observed, vec![0, 1, 2, 3]);
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
