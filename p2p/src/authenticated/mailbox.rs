use commonware_utils::channels::fallible::{AsyncFallibleExt, FallibleExt};
use futures::channel::{mpsc, oneshot};
use std::future::Future;

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

impl<T: Send> AsyncFallibleExt<T> for Mailbox<T> {
    async fn send_lossy(&mut self, msg: T) -> bool {
        self.0.send_lossy(msg).await
    }

    fn request<R, F>(&mut self, make_msg: F) -> impl Future<Output = Option<R>> + Send
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request(make_msg)
    }

    fn request_or<R, F>(&mut self, make_msg: F, default: R) -> impl Future<Output = R> + Send
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request_or(make_msg, default)
    }

    fn request_or_default<R, F>(&mut self, make_msg: F) -> impl Future<Output = R> + Send
    where
        R: Default + Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request_or_default(make_msg)
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

    fn request<R, F>(&self, make_msg: F) -> impl Future<Output = Option<R>> + Send
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request(make_msg)
    }

    fn request_or<R, F>(&self, make_msg: F, default: R) -> impl Future<Output = R> + Send
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request_or(make_msg, default)
    }

    fn request_or_default<R, F>(&self, make_msg: F) -> impl Future<Output = R> + Send
    where
        R: Default + Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.0.request_or_default(make_msg)
    }
}
