use super::{Broadcaster, Digestible};
use commonware_utils::Array;
use futures::{channel::mpsc, SinkExt};
use std::marker::PhantomData;

/// Message types that can be sent to the `Mailbox`
pub enum Message<B> {
    Broadcast { blob: B },
}

/// Ingress mailbox for [`Engine`](super::Engine).
#[derive(Clone)]
pub struct Mailbox<D: Array, B: Digestible<D>> {
    sender: mpsc::Sender<Message<B>>,
    _digest: PhantomData<D>,
}

impl<D: Array, B: Digestible<D>> Mailbox<D, B> {
    pub(super) fn new(sender: mpsc::Sender<Message<B>>) -> Self {
        Self {
            sender,
            _digest: PhantomData,
        }
    }
}

impl<D: Array, B: Digestible<D>> Broadcaster for Mailbox<D, B> {
    type Blob = B;

    async fn boradcast(&mut self, blob: Self::Blob) {
        self.sender
            .send(Message::Broadcast { blob })
            .await
            .expect("mailbox closed");
    }
}
