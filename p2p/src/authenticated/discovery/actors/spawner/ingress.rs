use crate::authenticated::{
    discovery::{actors::tracker::Reservation, types},
    Mailbox,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Sink, Stream};
use commonware_stream::encrypted::{Receiver, Sender};
use commonware_utils::channel::actor::{Backpressure, Enqueue, MessagePolicy};
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

impl<P: PublicKey, O: Sink, I: Stream> MessagePolicy for Message<O, I, P> {
    fn backpressure(queue: &mut VecDeque<Self>, message: Self) -> Backpressure<Self> {
        Backpressure::retain(queue, message)
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
    ) -> Enqueue<Message<O, I, P>> {
        self.enqueue(Message::Spawn {
            peer: reservation.metadata().public_key().clone(),
            connection,
            reservation,
        })
    }
}

/// Messages sent to a peer setup task.
#[derive(Debug)]
pub(crate) enum Connect<P: PublicKey> {
    /// Response to a tracker connection request.
    Connected(Option<types::Info<P>>),
}

impl<P: PublicKey> MessagePolicy for Connect<P> {
    fn backpressure(queue: &mut VecDeque<Self>, message: Self) -> Backpressure<Self> {
        Backpressure::retain(queue, message)
    }
}

impl<P: PublicKey> Mailbox<Connect<P>> {
    pub(crate) fn connected(&self, info: Option<types::Info<P>>) -> Enqueue<Connect<P>> {
        self.enqueue(Connect::Connected(info))
    }
}
