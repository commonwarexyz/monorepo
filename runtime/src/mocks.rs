use crate::{Error, Sink, Stream};
use bytes::Bytes;
use futures::{channel::mpsc, SinkExt, StreamExt};

/// A mock sink that stores sent messages in a channel.
pub struct MockSink {
    pub sender: mpsc::UnboundedSender<Bytes>,
}

impl MockSink {
    /// Create a new `MockSink` and a corresponding receiver.
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Bytes>) {
        let (sender, receiver) = mpsc::unbounded();
        (Self { sender }, receiver)
    }
}

impl Sink for MockSink {
    async fn send(&mut self, msg: Bytes) -> Result<(), Error> {
        self.sender.send(msg).await.map_err(|_| Error::WriteFailed)
    }
}

/// A mock stream that reads messages from a channel.
pub struct MockStream {
    pub receiver: mpsc::UnboundedReceiver<Bytes>,
}

impl MockStream {
    /// Create a new `MockStream` and a corresponding sender.
    pub fn new() -> (Self, mpsc::UnboundedSender<Bytes>) {
        let (sender, receiver) = mpsc::unbounded();
        (Self { receiver }, sender)
    }
}

impl Stream for MockStream {
    async fn recv(&mut self) -> Result<Bytes, Error> {
        self.receiver.next().await.ok_or(Error::ReadFailed)
    }
}
