//! A mailbox-backed [Consumer] and [Producer] that forwards resolver callbacks to an actor.

use crate::{Consumer, Delivery, p2p::Producer};
use bytes::Bytes;
use commonware_actor::mailbox::{Live, Policy, Sender, Stale};
use commonware_utils::{Span, channel::oneshot};

/// A resolver callback forwarded to the actor that owns the application state.
pub enum Message<K, S, O = bool> {
    /// A peer response for the subscribers in `delivery`. Send its outcome through `response`,
    /// or drop `response` to leave the delivery unjudged.
    Deliver {
        delivery: Delivery<K, S>,
        value: Bytes,
        response: oneshot::Sender<O>,
    },
    /// A peer request for `key`. Send the encoded value through `response`, or drop `response`
    /// if the request cannot be served.
    Produce {
        key: K,
        response: oneshot::Sender<Bytes>,
    },
}

impl<K, S, O> Stale for Message<K, S, O> {
    fn is_stale(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

impl<K, S, O> Policy for Message<K, S, O> {
    type Overflow = Live<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // When the queue is full, peer requests are dropped so the serve backlog stays bounded
        // and deliveries to local callers keep priority. The requesting peer can ask a less
        // loaded peer instead.
        if matches!(message, Self::Produce { .. }) {
            return;
        }

        // Retain deliveries that still have a waiting requester.
        overflow.push(message);
    }
}

/// Forwards [Consumer] and [Producer] callbacks to an actor as [Message]s.
pub struct Handler<K, S, O = bool> {
    sender: Sender<Message<K, S, O>>,
}

impl<K, S, O> Handler<K, S, O> {
    /// Creates a handler that enqueues callbacks on `sender`.
    pub const fn new(sender: Sender<Message<K, S, O>>) -> Self {
        Self { sender }
    }
}

impl<K, S, O> Clone for Handler<K, S, O> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<K, S, O> Consumer for Handler<K, S, O>
where
    K: Span,
    S: Clone + Eq + Send + 'static,
    O: Into<crate::Outcome> + Send + 'static,
{
    type Key = K;
    type Value = Bytes;
    type Subscriber = S;
    type Outcome = O;

    fn deliver(&mut self, delivery: Delivery<K, S>, value: Bytes) -> oneshot::Receiver<O> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Deliver {
            delivery,
            value,
            response,
        });
        receiver
    }
}

impl<K, S, O> Producer for Handler<K, S, O>
where
    K: Span,
    S: Send + 'static,
    O: Send + 'static,
{
    type Key = K;

    fn produce(&mut self, key: K) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Produce { key, response });
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_actor::mailbox::Overflow;
    use commonware_utils::non_empty_vec;

    #[test]
    fn handle_retains_open_deliveries_only() {
        let mut overflow = Live::<Message<u64, (), bool>>::default();
        let deliver = |key: u64, response| Message::Deliver {
            delivery: Delivery {
                key,
                subscribers: non_empty_vec![((), tracing::Span::none())],
            },
            value: Bytes::new(),
            response,
        };

        // An overflowed produce request is dropped and its requester sees the
        // closed response.
        let (response, mut produce) = oneshot::channel();
        Message::handle(&mut overflow, Message::Produce { key: 1, response });
        assert!(matches!(
            produce.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));

        // Deliveries are retained, and drain skips one whose requester left.
        let (response, closed) = oneshot::channel();
        Message::handle(&mut overflow, deliver(2, response));
        let (response, _open) = oneshot::channel();
        Message::handle(&mut overflow, deliver(3, response));
        drop(closed);

        let mut messages = Vec::new();
        Overflow::drain(&mut overflow, |message| {
            messages.push(message);
            None
        });
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            messages.pop(),
            Some(Message::Deliver { delivery, .. }) if delivery.key == 3
        ));
    }
}
