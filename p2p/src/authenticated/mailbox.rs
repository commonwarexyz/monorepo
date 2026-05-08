use commonware_utils::channel::{
    actor::{self, ActorInbox, ActorMailbox, Backpressure}, Feedback,
};

/// A mailbox wraps a sender for messages of type `T`.
#[derive(Debug)]
pub struct Mailbox<T: Backpressure>(pub(crate) ActorMailbox<T>);

impl<T: Backpressure> Mailbox<T> {
    /// Returns a new mailbox with the given sender.
    pub fn new(size: usize) -> (Self, ActorInbox<T>) {
        let (sender, receiver) = actor::channel(size);
        (Self(sender), receiver)
    }

    /// Submit a message without waiting for inbox capacity.
    pub fn enqueue(&self, msg: T) -> Feedback {
        self.0.enqueue(msg)
    }
}

impl<T: Backpressure> Clone for Mailbox<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
