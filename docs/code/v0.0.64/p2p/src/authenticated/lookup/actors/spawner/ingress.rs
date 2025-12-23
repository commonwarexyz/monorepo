use crate::authenticated::{lookup::actors::tracker::Reservation, Mailbox};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Sink, Stream};
use commonware_stream::{Receiver, Sender};

/// Messages that can be processed by the spawner actor.
pub enum Message<Si: Sink, St: Stream, P: PublicKey> {
    /// Notify the spawner to create a new task for the given peer.
    Spawn {
        /// The peer's public key.
        peer: P,
        /// The connection to the peer.
        connection: (Sender<Si>, Receiver<St>),
        /// The reservation for the peer.
        reservation: Reservation<P>,
    },
}

impl<Si: Sink, St: Stream, P: PublicKey> Mailbox<Message<Si, St, P>> {
    /// Send a message to the actor to spawn a new task for the given peer.
    pub async fn spawn(
        &mut self,
        connection: (Sender<Si>, Receiver<St>),
        reservation: Reservation<P>,
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
