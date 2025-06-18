use futures::{channel::mpsc, SinkExt as _};

/// A mailbox wraps a sender for messages of type `T`.
#[derive(Debug)]
pub struct Mailbox<T>(mpsc::Sender<T>);

impl<T> Mailbox<T> {
    /// Returns a new mailbox with the given sender.
    pub fn new(sender: mpsc::Sender<T>) -> Self {
        Self(sender)
    }

    /// Returns a new mailbox and the corresponding receiver.
    /// The capacity of the channel is 1.
    #[cfg(test)]
    pub fn test() -> (Self, mpsc::Receiver<T>) {
        let (sender, receiver) = mpsc::channel(1);
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
