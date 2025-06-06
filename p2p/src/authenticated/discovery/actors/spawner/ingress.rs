use crate::authenticated::{discovery::actors::tracker::Reservation, Mailbox};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Metrics, Sink, Spawner, Stream};
use commonware_stream::public_key::Connection;
use futures::SinkExt;

pub enum Message<E: Spawner + Clock + Metrics, Si: Sink, St: Stream, P: PublicKey> {
    Spawn {
        peer: P,
        connection: Connection<Si, St>,
        reservation: Reservation<E, P>,
    },
}

impl<E: Spawner + Clock + Metrics, Si: Sink, St: Stream, P: PublicKey>
    Mailbox<Message<E, Si, St, P>>
{
    pub async fn spawn(&mut self, connection: Connection<Si, St>, reservation: Reservation<E, P>) {
        self.0
            .send(Message::Spawn {
                peer: reservation.metadata().public_key().clone(),
                connection,
                reservation,
            })
            .await
            .unwrap();
    }
}
