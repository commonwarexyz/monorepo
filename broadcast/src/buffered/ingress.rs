use crate::Broadcaster;
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Digestible};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// Message types that can be sent to the `Mailbox`
pub enum Message<D, B> {
    /// Broadcast a blob to the network.
    Broadcast { blob: B },

    /// Request to retrieve a blob by digest.
    ///
    /// The responder will be sent the blob if it is available.
    /// The request can be canceled by dropping the responder.
    Retrieve {
        digest: D,
        responder: oneshot::Sender<B>,
    },
}

/// Ingress mailbox for [`Engine`](super::Engine).
#[derive(Clone)]
pub struct Mailbox<D: Digest, B: Digestible<D>> {
    sender: mpsc::Sender<Message<D, B>>,
}

impl<D: Digest, B: Digestible<D>> Mailbox<D, B> {
    pub(super) fn new(sender: mpsc::Sender<Message<D, B>>) -> Self {
        Self { sender }
    }
}

impl<D: Digest, B: Digestible<D>> Mailbox<D, B> {
    /// Retrieve a blob by digest.
    pub async fn retrieve(&mut self, digest: D) -> oneshot::Receiver<B> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Retrieve {
                digest,
                responder: sender,
            })
            .await
            .expect("mailbox closed");
        receiver
    }
}

impl<D: Digest, B: Codec + Digestible<D>> Broadcaster for Mailbox<D, B> {
    type Blob = B;

    async fn broadcast(&mut self, blob: Self::Blob) {
        self.sender
            .send(Message::Broadcast { blob })
            .await
            .expect("mailbox closed");
    }
}
