use crate::Resolver;
use commonware_utils::Span;
use futures::{channel::mpsc, SinkExt};

/// Messages that can be sent to the broadcast actor.
pub enum Message<K> {
    /// Initiate a fetch request by key.
    Fetch { key: K },
}

/// A way to send messages to the broadcast actor.
#[derive(Clone)]
pub struct Mailbox<K> {
    /// The channel that delivers messages to the broadcast actor.
    sender: mpsc::Sender<Message<K>>,
}

impl<K> Mailbox<K> {
    /// Create a new mailbox.
    pub(super) fn new(sender: mpsc::Sender<Message<K>>) -> Self {
        Self { sender }
    }
}

impl<K: Span> Resolver for Mailbox<K> {
    type Key = K;

    async fn fetch(&mut self, key: Self::Key) {
        self.sender
            .send(Message::Fetch { key })
            .await
            .expect("Failed to send fetch");
    }

    async fn cancel(&mut self, _key: Self::Key) {
        unimplemented!()
    }

    async fn retain(&mut self, _predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {
        unimplemented!()
    }

    async fn clear(&mut self) {
        unimplemented!()
    }
}
