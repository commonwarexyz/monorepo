use crate::Broadcaster;
use commonware_codec::{Codec, Config};
use commonware_cryptography::{Digest, Digestible};
use commonware_utils::Array;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::marker::PhantomData;

/// Message types that can be sent to the `Mailbox`
pub enum Message<P: Array, D: Digest, M: Digestible<D>> {
    /// Broadcast a [`Message`](crate::Broadcaster::Message) to the network.
    ///
    /// The responder will be sent a list of peers that received the message.
    Broadcast {
        message: M,
        responder: oneshot::Sender<Vec<P>>,
    },

    /// Subscribe to receive a message by digest.
    ///
    /// The responder will be sent the message when it is available; either instantly (if cached) or
    /// when it is received from the network. The request can be canceled by dropping the responder.
    Subscribe {
        digest: D,
        responder: oneshot::Sender<M>,
    },

    /// Get a message by digest.
    Get {
        digest: D,
        responder: oneshot::Sender<Option<M>>,
    },
}

/// Ingress mailbox for [`Engine`](super::Engine).
#[derive(Clone)]
pub struct Mailbox<Cfg: Config, P: Array, D: Digest, M: Digestible<D>> {
    sender: mpsc::Sender<Message<P, D, M>>,
    _phantom: PhantomData<Cfg>,
}

impl<Cfg: Config, P: Array, D: Digest, M: Digestible<D>> Mailbox<Cfg, P, D, M> {
    pub(super) fn new(sender: mpsc::Sender<Message<P, D, M>>) -> Self {
        Self {
            sender,
            _phantom: PhantomData,
        }
    }

    /// Subscribe to a message by digest.
    ///
    /// The responder will be sent the message when it is available; either instantly (if cached) or
    /// when it is received from the network. The request can be canceled by dropping the responder.
    pub async fn subscribe(&mut self, digest: D) -> oneshot::Receiver<M> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Subscribe {
                digest,
                responder: sender,
            })
            .await
            .expect("mailbox closed");
        receiver
    }

    /// Subscribe to a message by digest with an externally prepared sender.
    ///
    /// The responder will be sent the message when it is available; either instantly (if cached) or
    /// when it is received from the network. The request can be canceled by dropping the responder.
    pub async fn subscribe_prepared(&mut self, digest: D, sender: oneshot::Sender<M>) {
        self.sender
            .send(Message::Subscribe {
                digest,
                responder: sender,
            })
            .await
            .expect("mailbox closed");
    }

    /// Get a message by digest.
    pub async fn get(&mut self, digest: D) -> Option<M> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get {
                digest,
                responder: sender,
            })
            .await
            .expect("mailbox closed");
        receiver.await.unwrap_or(None)
    }
}

impl<Cfg: Config, P: Array, D: Digest, M: Codec<Cfg> + Digestible<D>> Broadcaster<Cfg>
    for Mailbox<Cfg, P, D, M>
{
    type Message = M;
    type Response = Vec<P>;

    async fn broadcast(&mut self, message: Self::Message) -> oneshot::Receiver<Vec<P>> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Broadcast {
                message,
                responder: sender,
            })
            .await
            .expect("mailbox closed");
        receiver
    }
}
