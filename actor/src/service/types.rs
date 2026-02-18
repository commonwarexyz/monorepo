use commonware_utils::channel::mpsc;
use std::{
    collections::BTreeMap,
    fmt,
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;

/// Returned when the same lane key is configured more than once.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("duplicate lane configured")]
pub struct DuplicateLaneError;

/// Per-lane mailboxes returned by [`crate::service::MultiLaneServiceBuilder::build`].
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
}

impl<L, M> Lanes<L, M>
where
    L: Ord,
    M: Clone,
{
    /// Returns the mailbox for `lane`.
    pub fn lane(&self, lane: &L) -> Option<M> {
        self.mailboxes.get(lane).cloned()
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

/// Receive half of a single lane.
///
/// Lane order in the containing `Vec` preserves declaration order.
pub(super) struct LaneReceiver<I> {
    pub(super) receiver: LaneReceiverKind<I>,
}

/// Receive half of a lane channel, either bounded or unbounded.
pub(super) enum LaneReceiverKind<I> {
    Bounded(mpsc::Receiver<I>),
    Unbounded(mpsc::UnboundedReceiver<I>),
}

/// Non-blocking lane receive result.
pub(super) enum LaneTryRecv<I> {
    /// A message was received.
    Message(I),
    /// No message is currently available.
    Empty,
    /// The lane closed.
    Closed,
}

impl<I> LaneReceiver<I> {
    pub(super) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<I>> {
        match &mut self.receiver {
            LaneReceiverKind::Bounded(rx) => Pin::new(rx).poll_recv(cx),
            LaneReceiverKind::Unbounded(rx) => Pin::new(rx).poll_recv(cx),
        }
    }

    pub(super) fn try_recv(&mut self) -> LaneTryRecv<I> {
        match &mut self.receiver {
            LaneReceiverKind::Bounded(rx) => match rx.try_recv() {
                Ok(message) => LaneTryRecv::Message(message),
                Err(mpsc::error::TryRecvError::Empty) => LaneTryRecv::Empty,
                Err(mpsc::error::TryRecvError::Disconnected) => LaneTryRecv::Closed,
            },
            LaneReceiverKind::Unbounded(rx) => match rx.try_recv() {
                Ok(message) => LaneTryRecv::Message(message),
                Err(mpsc::error::TryRecvError::Empty) => LaneTryRecv::Empty,
                Err(mpsc::error::TryRecvError::Disconnected) => LaneTryRecv::Closed,
            },
        }
    }
}

/// Events that drive the actor control loop.
pub(super) enum LoopEvent<I, W>
where
    I: Send + 'static,
    W: Send + 'static,
{
    /// Runtime shutdown signal observed.
    Shutdown,
    /// A message received from lane `usize`. `None` indicates that lane closed.
    Mailbox(usize, Option<I>),
    /// A message received from the actor-defined external future.
    External(Option<W>),
}
