//! Internal handler types for resolver actor coordination.

use bytes::Bytes;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_resolver::{self as resolver, Delivery, p2p::Producer};
use commonware_storage::{merkle::Family, qmdb::sync::Request};
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

/// Messages sent from [`Handler`] to the resolver [`Actor`](super::Actor).
///
/// Each variant corresponds to one of the `resolver::Consumer` or `p2p::Producer`
/// callbacks, re-routed so the actor processes them on its own task.
pub(super) enum EngineMessage<F: Family> {
    /// A peer delivered a response for a previously fetched key.
    /// The actor decodes the value, fans it out to waiting subscribers,
    /// and reports acceptance back through `response`.
    Deliver {
        key: Request<F>,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    /// A peer requested data for `key`.
    /// The actor queries the local database and sends the encoded
    /// [`Response`](commonware_storage::qmdb::sync::Response) back through `response`.
    Produce {
        key: Request<F>,
        response: oneshot::Sender<Bytes>,
    },
}

impl<F: Family> EngineMessage<F> {
    fn response_closed(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

/// Deliveries retained while the ready queue is full.
pub(super) struct EnginePending<F: Family>(VecDeque<EngineMessage<F>>);

impl<F: Family> Default for EnginePending<F> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<F: Family> Overflow<EngineMessage<F>> for EnginePending<F> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(EngineMessage<F>) -> Option<EngineMessage<F>>,
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

impl<F: Family> Policy for EngineMessage<F> {
    type Overflow = EnginePending<F>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Drop produce requests so the serve backlog stays bounded by the ready
        // queue. We prefer handling our own responses over serving peers, who can
        // ask a less loaded peer instead.
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
/// state (pending subscribers, database handle) on the actor task,
/// while the engine runs independently.
#[derive(Clone)]
pub(super) struct Handler<F: Family> {
    sender: Sender<EngineMessage<F>>,
}

impl<F: Family> Handler<F> {
    pub(super) const fn new(sender: Sender<EngineMessage<F>>) -> Self {
        Self { sender }
    }
}

impl<F: Family> resolver::Consumer for Handler<F> {
    type Key = Request<F>;
    type Value = Bytes;
    type Subscriber = ();
    type Outcome = bool;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(EngineMessage::Deliver {
            key: delivery.key,
            value,
            response,
        });
        receiver
    }
}

impl<F: Family> Producer for Handler<F> {
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
    use commonware_utils::NZU64;

    #[test]
    fn handle_retains_open_deliveries_only() {
        let mut overflow = EnginePending::<mmr::Family>::default();
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

        // Deliveries are retained, and drain skips one whose requester left.
        let (response, closed) = oneshot::channel();
        EngineMessage::handle(
            &mut overflow,
            EngineMessage::Deliver {
                key,
                value: Bytes::new(),
                response,
            },
        );
        let (response, _open) = oneshot::channel();
        EngineMessage::handle(
            &mut overflow,
            EngineMessage::Deliver {
                key,
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
