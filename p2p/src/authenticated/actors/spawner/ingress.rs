use crate::authenticated::{actors::tracker::Reservation, Mailbox};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Metrics, Network, SinkOf, Spawner, StreamOf};
use commonware_stream::public_key::Connection;

/// Messages that can be processed by the spawner [Actor](super::Actor).
pub enum Message<E: Spawner + Clock + Metrics + Network, P: PublicKey> {
    /// Notify the spawner to create a new task for the given peer.
    Spawn {
        /// The peer's public key.
        peer: P,
        /// The connection to the peer.
        connection: Connection<SinkOf<E>, StreamOf<E>>,
        /// The reservation for the peer.
        reservation: Reservation<E, P>,
    },
}

impl<E: Spawner + Clock + Metrics + Network, P: PublicKey> Mailbox<Message<E, P>> {
    /// Send a message to the actor to spawn a new task for the given peer.
    pub async fn spawn(
        &mut self,
        connection: Connection<SinkOf<E>, StreamOf<E>>,
        reservation: Reservation<E, P>,
    ) {
        self.send(Message::Spawn {
            peer: reservation.metadata().public_key().clone(),
            connection,
            reservation,
        })
        .await
        .unwrap();
    }
}
