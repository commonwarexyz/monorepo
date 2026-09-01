//! A mailbox-backed `commonware-resolver` consumer and producer.

use bytes::Bytes;
use commonware_actor::mailbox::{self, Overflow, Policy};
use commonware_resolver::{Consumer, Delivery, Outcome, p2p};
use commonware_utils::{Span, channel::oneshot};
use std::collections::VecDeque;

/// A request from `commonware-resolver` to the actor that owns a [`Handler`].
pub(crate) enum HandlerMessage<K, S, O> {
    /// A fetched value to validate; `response` receives the outcome.
    Deliver {
        delivery: Delivery<K, S>,
        value: Bytes,
        response: oneshot::Sender<O>,
    },
    /// A request to serve the value stored for `key`.
    Produce {
        key: K,
        response: oneshot::Sender<Bytes>,
    },
}

impl<K, S, O> HandlerMessage<K, S, O> {
    fn response_closed(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

/// Overflow that retains deliveries in arrival order and discards any whose caller has gone.
pub(crate) struct HandlerPending<K, S, O>(VecDeque<HandlerMessage<K, S, O>>);

impl<K, S, O> Default for HandlerPending<K, S, O> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<K, S, O> Overflow<HandlerMessage<K, S, O>> for HandlerPending<K, S, O> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(HandlerMessage<K, S, O>) -> Option<HandlerMessage<K, S, O>>,
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

/// Serve requests are dropped under overflow: a peer retries, and serving is best effort.
impl<K, S, O> Policy for HandlerMessage<K, S, O> {
    type Overflow = HandlerPending<K, S, O>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if matches!(&message, Self::Deliver { .. }) && !message.response_closed() {
            overflow.0.push_back(message);
        }
    }
}

/// Forwards `commonware-resolver` deliveries and serve requests to an actor mailbox.
pub(crate) struct Handler<K, S, O> {
    sender: mailbox::Sender<HandlerMessage<K, S, O>>,
}

impl<K, S, O> Handler<K, S, O> {
    /// Returns a handler that forwards to `sender`.
    pub(crate) const fn new(sender: mailbox::Sender<HandlerMessage<K, S, O>>) -> Self {
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
    O: Into<Outcome> + Send + 'static,
{
    type Key = K;
    type Value = Bytes;
    type Subscriber = S;
    type Outcome = O;

    fn deliver(&mut self, delivery: Delivery<K, S>, value: Bytes) -> oneshot::Receiver<O> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(HandlerMessage::Deliver {
            delivery,
            value,
            response,
        });
        receiver
    }
}

impl<K, S, O> p2p::Producer for Handler<K, S, O>
where
    K: Span,
    S: Send + 'static,
    O: Send + 'static,
{
    type Key = K;

    fn produce(&mut self, key: K) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(HandlerMessage::Produce { key, response });
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::vec::NonEmptyVec;

    type Message = HandlerMessage<u64, (), bool>;

    fn deliver(key: u64) -> (Message, oneshot::Receiver<bool>) {
        let (response, receiver) = oneshot::channel();
        let message = HandlerMessage::Deliver {
            delivery: Delivery {
                key,
                subscribers: NonEmptyVec::new(((), tracing::Span::none())),
            },
            value: Bytes::new(),
            response,
        };
        (message, receiver)
    }

    #[test]
    fn overflow_drops_peer_produce_requests() {
        let mut overflow = HandlerPending::default();
        let mut receivers = Vec::new();
        for key in 1..=64 {
            let (response, receiver) = oneshot::channel();
            <Message as Policy>::handle(&mut overflow, HandlerMessage::Produce { key, response });
            receivers.push(receiver);
        }
        assert!(overflow.is_empty());
    }

    #[test]
    fn overflow_retains_open_deliveries_and_skips_closed_ones() {
        let mut overflow = HandlerPending::default();
        let (closed, closed_receiver) = deliver(1);
        drop(closed_receiver);
        <Message as Policy>::handle(&mut overflow, closed);
        assert!(overflow.is_empty());

        let (first, first_receiver) = deliver(2);
        let (second, second_receiver) = deliver(3);
        <Message as Policy>::handle(&mut overflow, first);
        <Message as Policy>::handle(&mut overflow, second);
        drop(first_receiver);

        let mut drained = Vec::new();
        overflow.drain(|message| {
            drained.push(message);
            None
        });
        assert!(overflow.is_empty());
        assert!(matches!(
            drained.as_slice(),
            [HandlerMessage::Deliver { delivery, .. }] if delivery.key == 3
        ));
        drop(second_receiver);
    }
}
