use crate::authenticated::{actors::tracker, connection::Instance};
use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use futures::{channel::mpsc, SinkExt};

pub enum Message<E: Spawner + Clock, C: Scheme, Si: Sink, St: Stream> {
    Spawn {
        peer: PublicKey,
        connection: Instance<E, C, Si, St>,
        reservation: tracker::Reservation<E>,
    },
}

#[derive(Clone)]
pub struct Mailbox<E: Spawner + Clock, C: Scheme, Si: Sink, St: Stream> {
    sender: mpsc::Sender<Message<E, C, Si, St>>,
}

impl<E: Spawner + Clock, C: Scheme, Si: Sink, St: Stream> Mailbox<E, C, Si, St> {
    pub fn new(sender: mpsc::Sender<Message<E, C, Si, St>>) -> Self {
        Self { sender }
    }

    pub async fn spawn(
        &mut self,
        peer: PublicKey,
        connection: Instance<E, C, Si, St>,
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
