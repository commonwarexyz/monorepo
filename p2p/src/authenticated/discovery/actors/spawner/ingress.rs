use crate::authenticated::{discovery::actors::tracker::Reservation, Mailbox};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Metrics, Network, Sink, Spawner, Stream};
use commonware_stream::{Receiver, Sender};

/// Messages that can be processed by the spawner actor.
pub enum Message<E: Spawner + Clock + Metrics, O: Sink, I: Stream, P: PublicKey> {
    /// Notify the spawner to create a new task for the given peer.
    Spawn {
        /// The peer's public key.
        peer: P,
        /// The connection to the peer.
        connection: (Sender<O>, Receiver<I>),
        /// The reservation for the peer.
        reservation: Reservation<E, P>,
    },
}

impl<E: Spawner + Clock + Metrics + Network, P: PublicKey, O: Sink, I: Stream>
    Mailbox<Message<E, O, I, P>>
{
    /// Send a message to the actor to spawn a new task for the given peer.
    pub async fn spawn(
        &mut self,
        connection: (Sender<O>, Receiver<I>),
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
