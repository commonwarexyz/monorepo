use crate::authenticated::actors::tracker;
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use commonware_stream::public_key::Connection;
use commonware_utils::Array;
use futures::{channel::mpsc, SinkExt};

pub enum Message<E: Spawner + Clock, Si: Sink, St: Stream, P: Array> {
    Spawn {
        peer: P,
        connection: Connection<Si, St>,
        reservation: tracker::Reservation<E, P>,
    },
}

pub struct Mailbox<E: Spawner + Clock, Si: Sink, St: Stream, P: Array> {
    sender: mpsc::Sender<Message<E, Si, St, P>>,
}

impl<E: Spawner + Clock, Si: Sink, St: Stream, P: Array> Mailbox<E, Si, St, P> {
    pub fn new(sender: mpsc::Sender<Message<E, Si, St, P>>) -> Self {
        Self { sender }
    }

    pub async fn spawn(
        &mut self,
        peer: P,
        connection: Connection<Si, St>,
        reservation: tracker::Reservation<E, P>,
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

impl<E: Spawner + Clock, Si: Sink, St: Stream, P: Array> Clone for Mailbox<E, Si, St, P> {
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
