use crate::authenticated::{discovery::actors::tracker::Reservation, Mailbox};
use commonware_actor::{mailbox::Policy, Feedback};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Sink, Stream};
use commonware_stream::encrypted::{Receiver, Sender};
use std::collections::VecDeque;

/// Messages that can be processed by the spawner actor.
pub enum Message<O: Sink, I: Stream, P: PublicKey> {
    /// Notify the spawner to create a new task for the given peer.
    Spawn {
        /// The peer's public key.
        peer: P,
        /// The connection to the peer.
        connection: (Sender<O>, Receiver<I>),
        /// The reservation for the peer.
        reservation: Reservation<P>,
    },
}

impl<P: PublicKey, O: Sink, I: Stream> Policy for Message<O, I, P> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

impl<P: PublicKey, O: Sink, I: Stream> Mailbox<Message<O, I, P>> {
    /// Send a message to the actor to spawn a new task for the given peer.
    ///
    /// This may fail during shutdown if the spawner has already exited,
    /// which is harmless since no new connections need to be spawned.
    pub fn spawn(
        &mut self,
        connection: (Sender<O>, Receiver<I>),
        reservation: Reservation<P>,
    ) -> Feedback {
        self.0.enqueue(Message::Spawn {
            peer: reservation.metadata().public_key().clone(),
            connection,
            reservation,
        })
    }
}
