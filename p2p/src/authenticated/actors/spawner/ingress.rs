use crate::authenticated::{actors::tracker, connection::Stream};
use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::{Clock, Spawner, Stream as RStream};
use futures::{channel::mpsc, SinkExt};

pub enum Message<E: Spawner + Clock, C: Scheme, S: RStream> {
    Spawn {
        peer: PublicKey,
        connection: Stream<E, C, S>,
        reservation: tracker::Reservation<E>,
    },
}

#[derive(Clone)]
pub struct Mailbox<E: Spawner + Clock, C: Scheme, S: RStream> {
    sender: mpsc::Sender<Message<E, C, S>>,
}

impl<E: Spawner + Clock, C: Scheme, S: RStream> Mailbox<E, C, S> {
    pub fn new(sender: mpsc::Sender<Message<E, C, S>>) -> Self {
        Self { sender }
    }

    pub async fn spawn(
        &mut self,
        peer: PublicKey,
        connection: Stream<E, C, S>,
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
