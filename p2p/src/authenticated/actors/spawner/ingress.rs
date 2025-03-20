use crate::authenticated::actors::tracker;
use commonware_cryptography::Scheme;
use commonware_runtime::{Clock, Metrics, Sink, Spawner, Stream};
use commonware_stream::public_key::Connection;
use futures::{channel::mpsc, SinkExt};

pub enum Message<E: Spawner + Clock + Metrics, Si: Sink, St: Stream, C: Scheme> {
    Spawn {
        peer: C::PublicKey,
        connection: Connection<Si, St>,
        reservation: tracker::Reservation<E, C>,
    },
}

pub struct Mailbox<E: Spawner + Clock + Metrics, Si: Sink, St: Stream, C: Scheme> {
    sender: mpsc::Sender<Message<E, Si, St, C>>,
}

impl<E: Spawner + Clock + Metrics, Si: Sink, St: Stream, C: Scheme> Mailbox<E, Si, St, C> {
    pub fn new(sender: mpsc::Sender<Message<E, Si, St, C>>) -> Self {
        Self { sender }
    }

    pub async fn spawn(
        &mut self,
        peer: C::PublicKey,
        connection: Connection<Si, St>,
        reservation: tracker::Reservation<E, C>,
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

impl<E: Spawner + Clock + Metrics, Si: Sink, St: Stream, C: Scheme> Clone
    for Mailbox<E, Si, St, C>
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
