use commonware_macros::ready;
use futures::channel::mpsc;

/// A mailbox wraps a sender for messages of type `T`.
#[ready(2)]
#[derive(Debug)]
pub struct Mailbox<T>(pub(crate) mpsc::Sender<T>);

impl<T> Mailbox<T> {
    /// Returns a new mailbox with the given sender.
    pub fn new(size: usize) -> (Self, mpsc::Receiver<T>) {
        let (sender, receiver) = mpsc::channel(size);
        (Self(sender), receiver)
    }
}

impl<T> Clone for Mailbox<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// A mailbox wraps an unbounded sender for messages of type `T`.
#[ready(2)]
#[derive(Debug)]
pub struct UnboundedMailbox<T>(pub(crate) mpsc::UnboundedSender<T>);

impl<T> UnboundedMailbox<T> {
    /// Returns a new mailbox with the given sender.
    pub fn new() -> (Self, mpsc::UnboundedReceiver<T>) {
        let (sender, receiver) = mpsc::unbounded();
        (Self(sender), receiver)
    }
}

impl<T> Clone for UnboundedMailbox<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
