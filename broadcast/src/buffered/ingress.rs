use crate::Broadcaster;
use commonware_actor::{
    mailbox::{Overflow, Policy, Sender},
    Feedback,
};
use commonware_codec::Codec;
use commonware_cryptography::{Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, sync::Arc};

/// Message types that can be sent to the `Mailbox`
pub(crate) enum Message<P: PublicKey, M: Digestible> {
    /// Broadcast a [crate::Broadcaster::Message] to the network.
    Broadcast {
        recipients: Recipients<P>,
        message: Arc<M>,
    },

    /// Subscribe to receive a message by digest.
    ///
    /// The responder will be sent the message when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    Subscribe {
        digest: M::Digest,
        responder: oneshot::Sender<Arc<M>>,
    },

    /// Get a message by digest.
    Get {
        digest: M::Digest,
        responder: oneshot::Sender<Option<Arc<M>>>,
    },
}

impl<P: PublicKey, M: Digestible> Message<P, M> {
    fn response_closed(&self) -> bool {
        match self {
            Self::Subscribe { responder, .. } => responder.is_closed(),
            Self::Get { responder, .. } => responder.is_closed(),
            Self::Broadcast { .. } => false,
        }
    }
}

pub(crate) struct Pending<P: PublicKey, M: Digestible>(VecDeque<Message<P, M>>);

impl<P: PublicKey, M: Digestible> Default for Pending<P, M> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<P: PublicKey, M: Digestible> Overflow<Message<P, M>> for Pending<P, M> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<P, M>) -> Option<Message<P, M>>,
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

impl<P: PublicKey, M: Digestible> Policy for Message<P, M> {
    type Overflow = Pending<P, M>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }

        overflow.0.push_back(message);
    }
}

/// Ingress mailbox for [super::Engine].
#[derive(Clone)]
pub struct Mailbox<P: PublicKey, M: Digestible + Codec> {
    sender: Sender<Message<P, M>>,
}

impl<P: PublicKey, M: Digestible + Codec> Mailbox<P, M> {
    pub(super) const fn new(sender: Sender<Message<P, M>>) -> Self {
        Self { sender }
    }

    /// Subscribe to a message by digest.
    ///
    /// The responder will be sent the message when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    ///
    /// If the engine has shut down, the returned receiver will resolve to `Canceled`.
    pub fn subscribe(&self, digest: M::Digest) -> oneshot::Receiver<Arc<M>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::Subscribe { digest, responder });
        receiver
    }

    /// Get a message by digest.
    ///
    /// If the engine has shut down, returns `None`.
    pub async fn get(&self, digest: M::Digest) -> Option<Arc<M>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Get { digest, responder });
        receiver.await.unwrap_or_default()
    }

    /// Broadcast a shared message to recipients.
    ///
    /// If the engine has shut down, returns [`Feedback::Closed`].
    pub fn broadcast_shared(&self, recipients: Recipients<P>, message: Arc<M>) -> Feedback {
        self.sender.enqueue(Message::Broadcast {
            recipients,
            message,
        })
    }
}

impl<P: PublicKey, M: Digestible + Codec> Broadcaster for Mailbox<P, M> {
    type Recipients = Recipients<P>;
    type Message = M;

    /// Broadcast a message to recipients.
    ///
    /// If the engine has shut down, returns [`Feedback::Closed`].
    fn broadcast(&self, recipients: Self::Recipients, message: Self::Message) -> Feedback {
        self.broadcast_shared(recipients, Arc::new(message))
    }
}
