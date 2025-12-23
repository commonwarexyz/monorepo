use futures::{channel::mpsc, SinkExt as _};

/// A mailbox wraps a sender for messages of type `T`.
#[derive(Debug)]
pub struct Mailbox<T>(mpsc::Sender<T>);

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

impl<T> Mailbox<T> {
    /// Sends a message to the corresponding receiver.
    pub async fn send(&mut self, message: T) -> Result<(), mpsc::SendError> {
        self.0.send(message).await
    }

    /// Returns true if the mailbox is closed.
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

/// A mailbox wraps an unbounded sender for messages of type `T`.
#[derive(Debug)]
pub struct UnboundedMailbox<T>(mpsc::UnboundedSender<T>);

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

impl<T> UnboundedMailbox<T> {
    /// Sends a message to the corresponding receiver.
    pub fn send(&mut self, message: T) -> Result<(), mpsc::TrySendError<T>> {
        self.0.unbounded_send(message)
    }
}
