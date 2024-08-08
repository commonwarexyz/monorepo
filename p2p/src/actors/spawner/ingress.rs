use crate::{
    actors::tracker,
    connection::Stream,
    crypto::{Crypto, PublicKey},
};
use tokio::sync::mpsc;

pub enum Message<C: Crypto> {
    Spawn {
        peer: PublicKey,
        connection: Stream<C>,
        reservation: tracker::Reservation,
    },
}

#[derive(Clone)]
pub struct Mailbox<C: Crypto> {
    sender: mpsc::Sender<Message<C>>,
}

impl<C: Crypto> Mailbox<C> {
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
