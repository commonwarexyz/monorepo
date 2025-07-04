use crate::collection::Collector;
use commonware_cryptography::{Committable, Digest, Digestible, PublicKey};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::{collections::HashMap, fmt::Debug};

pub enum Message<
    D: Digest,
    P: PublicKey,
    Req: Committable + Digestible<Digest = D>,
    Res: Digestible<Digest = D>,
> {
    Send {
        request: Req,
    },
    Peek {
        id: D,
        sender: oneshot::Sender<HashMap<P, Res>>,
    },
    Cancel {
        id: D,
    },
}

#[derive(Clone)]
pub struct Mailbox<
    D: Digest,
    P: PublicKey,
    Req: Committable + Digestible<Digest = D>,
    Res: Digestible<Digest = D>,
> {
    sender: mpsc::Sender<Message<D, P, Req, Res>>,
}

impl<
        D: Digest,
        P: PublicKey,
        Req: Committable + Digestible<Digest = D>,
        Res: Digestible<Digest = D>,
    > Mailbox<D, P, Req, Res>
{
    pub fn new(sender: mpsc::Sender<Message<D, P, Req, Res>>) -> Self {
        Self { sender }
    }
}

impl<
        D: Digest,
        P: PublicKey,
        Req: Committable + Digestible<Digest = D> + Debug,
        Res: Digestible<Digest = D> + Debug,
    > Collector<D> for Mailbox<D, P, Req, Res>
{
    type Request = Req;
    type Response = Res;
    type PublicKey = P;

    async fn send(&mut self, request: Req) {
        let command = Message::Send { request };
        let _ = self.sender.try_send(command);
    }

    async fn peek(&mut self, id: D) -> oneshot::Receiver<HashMap<P, Res>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(Message::Peek { id, sender: tx }).await;
        rx
    }

    async fn cancel(&mut self, id: D) {
        let command = Message::Cancel { id };
        let _ = self.sender.try_send(command);
    }
}
