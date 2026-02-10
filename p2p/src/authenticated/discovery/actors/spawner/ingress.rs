use crate::authenticated::{discovery::actors::tracker::Reservation, Mailbox};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Closer, Sink, Stream};
use commonware_stream::encrypted::{Receiver, Sender};
use commonware_utils::channel::fallible::AsyncFallibleExt;

/// Messages that can be processed by the spawner actor.
pub enum Message<O: Sink, I: Stream, Cl: Closer, P: PublicKey> {
    /// Notify the spawner to create a new task for the given peer.
    Spawn {
        /// The peer's public key.
        peer: P,
        /// The connection to the peer.
        connection: (Sender<O>, Receiver<I>, Cl),
        /// The reservation for the peer.
        reservation: Reservation<P>,
    },
}

impl<P: PublicKey, O: Sink, I: Stream, Cl: Closer> Mailbox<Message<O, I, Cl, P>> {
    /// Send a message to the actor to spawn a new task for the given peer.
    ///
    /// This may fail during shutdown if the spawner has already exited,
    /// which is harmless since no new connections need to be spawned.
    pub async fn spawn(
        &mut self,
        connection: (Sender<O>, Receiver<I>, Cl),
        reservation: Reservation<P>,
    ) {
        self.0
            .send_lossy(Message::Spawn {
                peer: reservation.metadata().public_key().clone(),
                connection,
                reservation,
            })
            .await;
    }
}
