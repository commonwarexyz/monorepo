use crate::authenticated::lookup::actors::tracker::{Message, Metadata};
use commonware_cryptography::PublicKey;
use futures::channel::mpsc;

/// A way to send release requests to the releaser actor.
#[derive(Clone)]
pub struct Mailbox<C: PublicKey> {
    tracker: mpsc::Sender<Message<C>>,
    backlog: mpsc::UnboundedSender<Metadata<C>>,
}

impl<C: PublicKey> Mailbox<C> {
    pub(super) fn new(
        tracker: mpsc::Sender<Message<C>>,
        backlog: mpsc::UnboundedSender<Metadata<C>>,
    ) -> Self {
        Self { tracker, backlog }
    }

    /// Releases a reservation, queueing it in the releaser actor backlog if the
    /// tracker mailbox is currently full.
    ///
    /// Returns `true` when the release request was sent to the tracker immediately (or
    /// the tracker mailbox was already closed), and `false` when it was queued in the
    /// releaser actor backlog.
    pub fn release(&mut self, metadata: Metadata<C>) -> bool {
        match self.tracker.try_send(Message::Release {
            metadata: metadata.clone(),
        }) {
            Ok(()) => true,
            Err(e) if e.is_disconnected() => true,
            Err(_) => {
                let _ = self.backlog.unbounded_send(metadata);
                false
            }
        }
    }
}
