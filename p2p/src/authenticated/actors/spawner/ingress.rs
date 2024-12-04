use crate::authenticated::actors::tracker;
use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use commonware_stream::public_key::Instance;
use futures::{channel::mpsc, SinkExt};

pub enum Message<E: Spawner + Clock, C: Scheme, Si: Sink, St: Stream> {
    Spawn {
        peer: PublicKey,
        connection: Instance<C, Si, St>,
        reservation: tracker::Reservation<E>,
    },
}

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
        connection: Instance<C, Si, St>,
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

impl<E: Spawner + Clock, C: Scheme, Si: Sink, St: Stream> Clone for Mailbox<E, C, Si, St> {
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
