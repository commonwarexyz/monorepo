use super::Ingress;
use crate::mailbox::{Policy, Receiver, UnreliablePolicy, UnreliableReceiver};
use std::{
    collections::BTreeMap,
    fmt,
    future::poll_fn,
    task::{Context, Poll},
};
use thiserror::Error;

/// Receives messages for one service lane.
pub trait LaneReceiver<I>: Send {
    #[doc(hidden)]
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<I>>;
    #[doc(hidden)]
    fn try_recv(&mut self) -> Result<I, std::sync::mpsc::TryRecvError>;
}

impl<I> LaneReceiver<I> for Receiver<I>
where
    I: Policy + Send + 'static,
    I::Overflow: Send,
{
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<I>> {
        self.poll_recv(cx)
    }

    fn try_recv(&mut self) -> Result<I, std::sync::mpsc::TryRecvError> {
        self.try_recv()
    }
}

impl<I> LaneReceiver<I> for UnreliableReceiver<I>
where
    I: UnreliablePolicy + Send + 'static,
    I::Overflow: Send,
{
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<I>> {
        self.poll_recv(cx)
    }

    fn try_recv(&mut self) -> Result<I, std::sync::mpsc::TryRecvError> {
        self.try_recv()
    }
}

/// Returned when the same lane key is configured more than once.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("duplicate lane configured")]
pub struct DuplicateLaneError;

/// Per-lane mailboxes returned by [`crate::service::MultiLaneBuilder::build`].
pub struct Lanes<L, M>
where
    L: Ord,
{
    pub(super) mailboxes: BTreeMap<L, M>,
}

impl<L, M> Clone for Lanes<L, M>
where
    L: Ord + Clone,
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            mailboxes: self.mailboxes.clone(),
        }
    }
}

impl<L, M> fmt::Debug for Lanes<L, M>
where
    L: Ord + fmt::Debug,
    M: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lanes")
            .field("mailboxes", &self.mailboxes)
            .finish()
    }
}

impl<L, M> Lanes<L, M>
where
    L: Ord,
{
    /// Returns the number of lanes.
    pub fn len(&self) -> usize {
        self.mailboxes.len()
    }

    /// Returns `true` if there are no lanes.
    pub fn is_empty(&self) -> bool {
        self.mailboxes.is_empty()
    }

    /// Returns a reference to the mailbox for `lane`.
    pub fn lane(&self, lane: &L) -> Option<&M> {
        self.mailboxes.get(lane)
    }

    /// Consume and return all lane mailboxes.
    pub fn into_inner(self) -> BTreeMap<L, M> {
        self.mailboxes
    }
}

impl<L, M> IntoIterator for Lanes<L, M>
where
    L: Ord,
{
    type Item = (L, M);
    type IntoIter = std::collections::btree_map::IntoIter<L, M>;

    fn into_iter(self) -> Self::IntoIter {
        self.mailboxes.into_iter()
    }
}

/// Opaque declaration index for a service lane.
///
/// Values are produced by [`LaneSet`] and should be passed back unchanged when
/// returning [`Event::Ingress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lane {
    index: usize,
}

impl Lane {
    const fn new(index: usize) -> Self {
        Self { index }
    }

    /// Returns the lane's declaration index.
    pub const fn index(self) -> usize {
        self.index
    }
}

/// Event selected by an actor for one service-loop iteration.
pub enum Event<I, W> {
    /// Dispatch an ingress message received from `lane`.
    Ingress {
        /// Lane that produced `message`.
        ///
        /// Use the lane returned with the same [`LaneEvent::Message`]. The
        /// driver uses this token to batch additional ready messages from that
        /// lane.
        lane: Lane,
        /// Ingress message to dispatch.
        message: I,
    },
    /// Dispatch an actor-owned event as read-write ingress.
    External(W),
    /// No message was selected; start the next service-loop iteration.
    ///
    /// Sources that are immediately ready must be muted before returning this,
    /// otherwise the actor will select the same source again immediately.
    Continue,
    /// Stop the actor, run shutdown, and exit.
    Stop,
}

/// Result of polling actor mailbox lanes.
pub enum LaneEvent<I> {
    /// A lane produced a message.
    Message {
        /// Lane that produced the message.
        lane: Lane,
        /// Message received from the lane.
        message: I,
    },
    /// A lane closed and will not be polled again.
    Closed {
        /// Lane that closed.
        lane: Lane,
    },
}

/// Borrowed view over service mailbox lanes.
pub struct LaneSet<'a, I: Ingress, R> {
    pub(super) lanes: &'a mut [Option<R>],
    _ingress: std::marker::PhantomData<I>,
}

impl<'a, I, R> LaneSet<'a, I, R>
where
    I: Ingress,
    R: LaneReceiver<I>,
{
    pub(super) const fn new(lanes: &'a mut [Option<R>]) -> Self {
        Self {
            lanes,
            _ingress: std::marker::PhantomData,
        }
    }

    /// Returns `true` when every lane has closed.
    pub fn is_exhausted(&self) -> bool {
        self.lanes.iter().all(Option::is_none)
    }

    /// Await the next lane message or lane closure.
    ///
    /// Polling is declaration-order biased. Closed lanes are reported once
    /// and then disabled. Once every lane has closed, this future never
    /// resolves again; use [`LaneSet::is_exhausted`] to choose another event
    /// or stop the actor.
    pub async fn recv(&mut self) -> LaneEvent<I> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<LaneEvent<I>> {
        for (lane, slot) in self.lanes.iter_mut().enumerate() {
            let Some(receiver) = slot.as_mut() else {
                continue;
            };
            match receiver.poll_recv(cx) {
                Poll::Ready(Some(message)) => {
                    let lane = Lane::new(lane);
                    return Poll::Ready(LaneEvent::Message { lane, message });
                }
                Poll::Ready(None) => {
                    *slot = None;
                    let lane = Lane::new(lane);
                    return Poll::Ready(LaneEvent::Closed { lane });
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
