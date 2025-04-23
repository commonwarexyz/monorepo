use crate::Broadcaster;
use commonware_codec::{Codec, Config};
use commonware_cryptography::{Digest, Digestible};
use commonware_utils::Array;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// Message types that can be sent to the `Mailbox`
pub enum Message<P: Array, D: Digest, M: Digestible<D>> {
    /// Broadcast a [`Message`](crate::Broadcaster::Message) to the network.
    ///
    /// The responder will be sent a list of peers that received the message.
    Broadcast {
        message: M,
        responder: oneshot::Sender<Vec<P>>,
    },

    /// Get a message by digest.
    ///
    /// The responder will be sent the message when it is available; either instantly (if cached) or
    /// when it is received from the network. The request can be canceled by dropping the responder.
    Get {
        digest: D,
        responder: oneshot::Sender<M>,
    },
}

/// Ingress mailbox for [`Engine`](super::Engine).
#[derive(Clone)]
pub struct Mailbox<P: Array, D: Digest, M: Digestible<D>> {
    sender: mpsc::Sender<Message<P, D, M>>,
}

impl<P: Array, D: Digest, M: Digestible<D>> Mailbox<P, D, M> {
    pub(super) fn new(sender: mpsc::Sender<Message<P, D, M>>) -> Self {
        Self { sender }
    }
}

impl<P: Array, D: Digest, M: Digestible<D>> Mailbox<P, D, M> {
    /// Get a message by digest.
    pub async fn get(&mut self, digest: D) -> oneshot::Receiver<M> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get {
                digest,
                responder: sender,
            })
            .await
            .expect("mailbox closed");
        receiver
    }
}

impl<Cfg: Config, P: Array, D: Digest, M: Codec<Cfg> + Digestible<D>> Broadcaster<Cfg>
    for Mailbox<P, D, M>
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
