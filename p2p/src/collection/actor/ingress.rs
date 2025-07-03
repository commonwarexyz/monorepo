use crate::collection::Collector;
use bytes::Bytes;
use commonware_cryptography::{Committable, PublicKey};
use futures::channel::{mpsc, oneshot};
use std::collections::HashMap;

type Response<PK> = oneshot::Receiver<HashMap<PK, Bytes>>;

pub enum Message<M: Committable, P: PublicKey> {
    Send {
        message: M,
    },
    Peek {
        id: M::Digest,
        sender: oneshot::Sender<Response<P>>,
    },
    Cancel {
        id: M::Digest,
    },
}

#[derive(Clone)]
pub struct Mailbox<M: Committable, P: PublicKey> {
    sender: mpsc::Sender<Message<M, P>>,
}

impl<M: Committable, P: PublicKey> Mailbox<M, P> {
    pub fn new(sender: mpsc::Sender<Message<M, P>>) -> Self {
        Self { sender }
    }
}

impl<M: Committable + std::fmt::Debug, P: PublicKey> Collector for Mailbox<M, P> {
    type Message = M;
    type PublicKey = P;

    async fn send(&mut self, message: M) {
        let command = Message::Send { message };
        let _ = self.sender.try_send(command);
    }

    async fn peek(&mut self, id: M::Digest) -> Response<P> {
        let (sender, receiver) = oneshot::channel();
        let command = Message::Peek { id, sender };
        let _ = self.sender.try_send(command);
        receiver.await.unwrap()
    }

    async fn cancel(&mut self, id: M::Digest) {
        let command = Message::Cancel { id };
        let _ = self.sender.try_send(command);
    }
}
