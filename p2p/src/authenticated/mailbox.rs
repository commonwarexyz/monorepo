use commonware_utils::channel::mpsc;

/// A mailbox wraps a sender for messages of type `T`.
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
