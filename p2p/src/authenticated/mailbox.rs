use commonware_utils::channels::fallible::{AsyncFallibleExt, FallibleExt};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt as _,
};

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

impl<T: Send> AsyncFallibleExt<T> for Mailbox<T> {
    async fn send_lossy(&mut self, msg: T) -> bool {
        self.0.send_lossy(msg).await
    }

    async fn request<R, F>(&mut self, make_msg: F) -> Option<R>
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request(make_msg).await
    }

    async fn request_or<R, F>(&mut self, make_msg: F, default: R) -> R
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request_or(make_msg, default).await
    }

    async fn request_or_default<R, F>(&mut self, make_msg: F) -> R
    where
        R: Default + Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request_or_default(make_msg).await
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

impl<T: Send> FallibleExt<T> for UnboundedMailbox<T> {
    fn send_lossy(&self, msg: T) -> bool {
        self.0.send_lossy(msg)
    }

    async fn request<R, F>(&self, make_msg: F) -> Option<R>
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request(make_msg).await
    }

    async fn request_or<R, F>(&self, make_msg: F, default: R) -> R
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request_or(make_msg, default).await
    }

    async fn request_or_default<R, F>(&self, make_msg: F) -> R
    where
        R: Default + Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request_or_default(make_msg).await
    }
}
