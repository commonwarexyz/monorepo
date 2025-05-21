use super::types::{Index, Item};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};

/// Mailbox for the [`Engine`](super::Engine).
pub struct Mailbox<D: Digest> {
    /// The sender for the mailbox.
    pub sender: mpsc::Sender<Item<D>>,
}

impl<D: Digest> Mailbox<D> {
    /// Create a new mailbox.
    pub fn new(sender: mpsc::Sender<Item<D>>) -> Self {
        Self { sender }
    }

    /// Provide the digest at the given index.
    pub async fn send(&mut self, index: Index, digest: D) {
        self.sender.send(Item { index, digest }).await;
    }
}
