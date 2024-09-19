use crate::authenticated::{actors::tracker, connection::Stream};
use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::{Clock, Spawner};
use tokio::sync::mpsc;

pub enum Message<E: Spawner + Clock, C: Scheme> {
    Spawn {
        peer: PublicKey,
        connection: Stream<E, C>,
        reservation: tracker::Reservation<E>,
    },
}

#[derive(Clone)]
pub struct Mailbox<E: Spawner + Clock, C: Scheme> {
    sender: mpsc::Sender<Message<E, C>>,
}

impl<E: Spawner + Clock, C: Scheme> Mailbox<E, C> {
    pub fn new(sender: mpsc::Sender<Message<E, C>>) -> Self {
        Self { sender }
    }

    pub async fn spawn(
        &self,
        peer: PublicKey,
        connection: Stream<E, C>,
        reservation: tracker::Reservation<E>,
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
