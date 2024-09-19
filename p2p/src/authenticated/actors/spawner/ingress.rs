use crate::authenticated::{actors::tracker, connection::Stream};
use commonware_cryptography::{PublicKey, Scheme};
use tokio::sync::mpsc;

pub enum Message<C: Scheme> {
    Spawn {
        peer: PublicKey,
        connection: Stream<C>,
        reservation: tracker::Reservation,
    },
}

#[derive(Clone)]
pub struct Mailbox<C: Scheme> {
    sender: mpsc::Sender<Message<C>>,
}

impl<C: Scheme> Mailbox<C> {
    pub fn new(sender: mpsc::Sender<Message<C>>) -> Self {
        Self { sender }
    }

    pub async fn spawn(
        &self,
        peer: PublicKey,
        connection: Stream<C>,
        reservation: tracker::Reservation,
    ) {
        self.sender
            .send(Message::Spawn {
                peer,
                connection,
                reservation,
            })
            .await
            .unwrap();
    }
}
