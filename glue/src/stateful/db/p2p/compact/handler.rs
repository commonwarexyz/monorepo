//! Handler types for compact resolver actor coordination.

use bytes::Bytes;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::Digest;
use commonware_resolver::{self as resolver, Delivery, p2p::Producer};
use commonware_storage::{merkle::Family, qmdb::sync::compact};
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

pub(super) enum EngineMessage<F: Family, D: Digest> {
    Deliver {
        key: compact::Target<F, D>,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        key: compact::Target<F, D>,
        response: oneshot::Sender<Bytes>,
    },
}

impl<F: Family, D: Digest> EngineMessage<F, D> {
    fn response_closed(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

pub(super) struct EnginePending<F: Family, D: Digest>(VecDeque<EngineMessage<F, D>>);

impl<F: Family, D: Digest> Default for EnginePending<F, D> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<F: Family, D: Digest> Overflow<EngineMessage<F, D>> for EnginePending<F, D> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(EngineMessage<F, D>) -> Option<EngineMessage<F, D>>,
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

impl<F: Family, D: Digest> Policy for EngineMessage<F, D> {
    type Overflow = EnginePending<F, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }
        overflow.0.push_back(message);
    }
}

#[derive(Clone)]
pub(super) struct Handler<F: Family, D: Digest> {
    sender: Sender<EngineMessage<F, D>>,
}

impl<F: Family, D: Digest> Handler<F, D> {
    pub(super) const fn new(sender: Sender<EngineMessage<F, D>>) -> Self {
        Self { sender }
    }
}

impl<F: Family, D: Digest> resolver::Consumer for Handler<F, D> {
    type Key = compact::Target<F, D>;
    type Value = Bytes;
    type Subscriber = ();

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

impl<F: Family, D: Digest> Producer for Handler<F, D> {
    type Key = compact::Target<F, D>;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(EngineMessage::Produce { key, response });
        receiver
    }
}
