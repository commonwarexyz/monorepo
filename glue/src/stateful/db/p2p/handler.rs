//! Internal handler types for resolver actor coordination.

use super::mailbox::Reply;
use bytes::Bytes;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_resolver::{self as resolver, Delivery, p2p::Producer};
use commonware_storage::{merkle::Family, qmdb::sync::Request};
use commonware_utils::channel::oneshot;
use std::{cmp::Ordering, collections::VecDeque};

/// A caller's reply route, identified independently of the peer-visible request.
pub(super) struct Subscriber<R> {
    pub id: u64,
    pub reply: Reply<R>,
}

impl<R> Clone for Subscriber<R> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            reply: self.reply.clone(),
        }
    }
}

impl<R> PartialEq for Subscriber<R> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<R> Eq for Subscriber<R> {}

impl<R> PartialOrd for Subscriber<R> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<R> Ord for Subscriber<R> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

/// Messages sent from [`Handler`] to the resolver [`Actor`](super::Actor).
///
/// Each variant corresponds to one of the `resolver::Consumer` or `p2p::Producer`
/// callbacks, re-routed so the actor processes them on its own task.
pub(super) enum EngineMessage<F: Family, R> {
    /// A peer response for the subscribers in `delivery`. Send its validity through `response`,
    /// or drop `response` to leave the delivery unjudged.
    Deliver {
        delivery: Delivery<Request<F>, Subscriber<R>>,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    /// A peer request for `key`. Send an encoded
    /// [`Response`](commonware_storage::qmdb::sync::Response) through `response`,
    /// or drop `response` if the request cannot be served.
    Produce {
        key: Request<F>,
        response: oneshot::Sender<Bytes>,
    },
}

impl<F: Family, R> EngineMessage<F, R> {
    fn response_closed(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

/// Deliveries retained while the ready queue is full.
pub(super) struct EnginePending<F: Family, R>(VecDeque<EngineMessage<F, R>>);

impl<F: Family, R> Default for EnginePending<F, R> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<F: Family, R> Overflow<EngineMessage<F, R>> for EnginePending<F, R> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(EngineMessage<F, R>) -> Option<EngineMessage<F, R>>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.response_closed() {
                continue;
            }

            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

impl<F: Family, R> Policy for EngineMessage<F, R> {
    type Overflow = EnginePending<F, R>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Drop produce requests when the ready queue is full. We prefer handling our own
        // responses over serving peers, who can ask a less loaded peer instead.
        if matches!(message, Self::Produce { .. }) {
            return;
        }

        // Retain deliveries that still have a waiting requester.
        if message.response_closed() {
            return;
        }
        overflow.0.push_back(message);
    }
}

/// Bridges `resolver::Consumer` and `p2p::Producer` into the actor's
/// message channel.
///
/// Every callback from the resolver engine is converted into an
/// [`EngineMessage`] and sent to the actor. This keeps all mutable
/// state (database handle and outstanding work) on the actor task,
/// while the engine runs independently.
pub(super) struct Handler<F: Family, R> {
    sender: Sender<EngineMessage<F, R>>,
}

impl<F: Family, R> Clone for Handler<F, R> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<F: Family, R> Handler<F, R> {
    pub(super) const fn new(sender: Sender<EngineMessage<F, R>>) -> Self {
        Self { sender }
    }
}

impl<F: Family, R: Send + 'static> resolver::Consumer for Handler<F, R> {
    type Key = Request<F>;
    type Value = Bytes;
    type Subscriber = Subscriber<R>;
    type Outcome = bool;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(EngineMessage::Deliver {
            delivery,
            value,
            response,
        });
        receiver
    }
}

impl<F: Family, R: Send + 'static> Producer for Handler<F, R> {
    type Key = Request<F>;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(EngineMessage::Produce { key, response });
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_storage::mmr::{self, Location};
    use commonware_utils::{NZU64, channel::mpsc, non_empty_vec};

    #[test]
    fn handle_retains_open_deliveries_only() {
        let mut overflow = EnginePending::<mmr::Family, ()>::default();
        let key = Request::Operations {
            size: Location::new(10),
            start: Location::new(0),
            max_ops: NZU64!(1),
        };

        // An overflowed produce request is dropped and its requester sees the
        // closed response.
        let (response, mut produce) = oneshot::channel();
        EngineMessage::handle(&mut overflow, EngineMessage::Produce { key, response });
        assert!(matches!(
            produce.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));

        let (reply, _receiver) = mpsc::channel(1);

        // Deliveries are retained, and drain skips one whose requester left.
        let (response, closed) = oneshot::channel();
        EngineMessage::handle(
            &mut overflow,
            EngineMessage::Deliver {
                delivery: Delivery {
                    key,
                    subscribers: non_empty_vec![(
                        Subscriber {
                            id: 0,
                            reply: reply.clone()
                        },
                        tracing::Span::none()
                    )],
                },
                value: Bytes::new(),
                response,
            },
        );
        let (response, _open) = oneshot::channel();
        EngineMessage::handle(
            &mut overflow,
            EngineMessage::Deliver {
                delivery: Delivery {
                    key,
                    subscribers: non_empty_vec![(
                        Subscriber { id: 0, reply },
                        tracing::Span::none()
                    )],
                },
                value: Bytes::from_static(b"open"),
                response,
            },
        );
        drop(closed);

        let mut messages = Vec::new();
        Overflow::drain(&mut overflow, |message| {
            messages.push(message);
            None
        });
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            messages.pop(),
            Some(EngineMessage::Deliver { value, .. }) if value == Bytes::from_static(b"open")
        ));
    }
}
