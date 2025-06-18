use crate::authenticated::lookup::actors::tracker::Reservation;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Metrics, Sink, Spawner, Stream};
use commonware_stream::public_key::Connection;
use futures::{channel::mpsc, SinkExt};

/// Messages that can be processed by the spawner [super::Actor].
pub enum Message<E: Spawner + Clock + Metrics, Si: Sink, St: Stream, P: PublicKey> {
    /// Notify the spawner to create a new task for the given peer.
    Spawn {
        /// The peer's public key.
        peer: P,
        /// The connection to the peer.
        connection: Connection<Si, St>,
        /// The reservation for the peer.
        reservation: Reservation<E, P>,
    },
}

/// Sends messages to the spawner [super::Actor].
pub struct Mailbox<E: Spawner + Clock + Metrics, Si: Sink, St: Stream, P: PublicKey> {
    sender: mpsc::Sender<Message<E, Si, St, P>>,
}

impl<E: Spawner + Clock + Metrics, Si: Sink, St: Stream, P: PublicKey> Mailbox<E, Si, St, P> {
    /// Returns a new [Mailbox] with the given `sender`.
    /// (The [super::Actor] has the corresponding receiver.)
    pub fn new(sender: mpsc::Sender<Message<E, Si, St, P>>) -> Self {
        Self { sender }
    }

    /// Send a message to the [super::Actor] to spawn a new task for the given peer.
    pub async fn spawn(&mut self, connection: Connection<Si, St>, reservation: Reservation<E, P>) {
        self.sender
            .send(Message::Spawn {
                peer: reservation.metadata().public_key().clone(),
                connection,
                reservation,
            })
            .await
            .unwrap();
    }
}

impl<E: Spawner + Clock + Metrics, Si: Sink, St: Stream, P: PublicKey> Clone
    for Mailbox<E, Si, St, P>
{
    /// Clone the mailbox.
    ///
    /// We manually implement `clone` because the auto-generated `derive` would
    /// require the `E`, `C`, `Si`, and `St` types to be `Clone`.
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}
