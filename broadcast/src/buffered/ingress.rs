use crate::Broadcaster;
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Digestible};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// Message types that can be sent to the `Mailbox`
pub enum Message<D, M> {
    /// Broadcast a [`Message`](crate::Broadcaster::Message) to the network.
    Broadcast { message: M },

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
pub struct Mailbox<D: Digest, M: Digestible<D>> {
    sender: mpsc::Sender<Message<D, M>>,
}

impl<D: Digest, M: Digestible<D>> Mailbox<D, M> {
    pub(super) fn new(sender: mpsc::Sender<Message<D, M>>) -> Self {
        Self { sender }
    }
}

impl<D: Digest, M: Digestible<D>> Mailbox<D, M> {
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

impl<Cfg, D: Digest, M: Codec<Cfg> + Digestible<D>> Broadcaster<Cfg> for Mailbox<D, M> {
    type Message = M;

    async fn broadcast(&mut self, message: Self::Message) {
        self.sender
            .send(Message::Broadcast { message })
            .await
            .expect("mailbox closed");
    }
}
