use commonware_actor::mailbox;
use commonware_runtime::Metrics;
use std::num::NonZeroUsize;

/// A mailbox wraps a sender for messages of type `T`.
#[derive(Debug)]
pub struct Mailbox<T: mailbox::UnreliablePolicy>(pub(crate) mailbox::UnreliableSender<T>);

impl<T: mailbox::UnreliablePolicy> Mailbox<T> {
    /// Returns a new mailbox with the given sender.
    pub fn new(
        metrics: impl Metrics,
        size: NonZeroUsize,
    ) -> (Self, mailbox::UnreliableReceiver<T>) {
        let (sender, receiver) = mailbox::new_unreliable(metrics, size);
        (Self(sender), receiver)
    }
}

impl<T: mailbox::UnreliablePolicy> Clone for Mailbox<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
