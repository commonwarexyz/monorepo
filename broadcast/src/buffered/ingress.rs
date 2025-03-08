use std::time::SystemTime;

use super::{Broadcaster, Digestible};
use commonware_utils::Array;
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
    /// If the blob is not available, the responder may wait until the deadline.
    Retrieve {
        digest: D,
        responder: oneshot::Sender<B>,
        deadline: SystemTime,
    },
}

/// Ingress mailbox for [`Engine`](super::Engine).
#[derive(Clone)]
pub struct Mailbox<D: Array, B: Digestible<D>> {
    sender: mpsc::Sender<Message<D, B>>,
}

impl<D: Array, B: Digestible<D>> Mailbox<D, B> {
    pub(super) fn new(sender: mpsc::Sender<Message<D, B>>) -> Self {
        Self { sender }
    }
}

impl<D: Array, B: Digestible<D>> Mailbox<D, B> {
    /// Retrieve a blob by digest.
    pub async fn retrieve(&mut self, digest: D, deadline: SystemTime) -> oneshot::Receiver<B> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Retrieve {
                digest,
                responder: sender,
                deadline,
            })
            .await
            .expect("mailbox closed");
        receiver
    }
}

impl<D: Array, B: Digestible<D>> Broadcaster for Mailbox<D, B> {
    type Blob = B;

    async fn broadcast(&mut self, blob: Self::Blob) {
        self.sender
            .send(Message::Broadcast { blob })
            .await
            .expect("mailbox closed");
    }
}
