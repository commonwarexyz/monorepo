use commonware_actor::mailbox;
use std::num::NonZeroUsize;

/// A mailbox wraps a sender for messages of type `T`.
#[derive(Debug)]
pub struct Mailbox<T: mailbox::Policy>(pub(crate) mailbox::Sender<T>);

impl<T: mailbox::Policy> Mailbox<T> {
    /// Returns a new mailbox with the given sender.
    pub fn new(size: NonZeroUsize) -> (Self, mailbox::Receiver<T>) {
        let (sender, receiver) = mailbox::new(size);
        (Self(sender), receiver)
    }
}

impl<T: mailbox::Policy> Clone for Mailbox<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
