//! Mock implementations of `commonware-runtime` traits for focused, upstream testing.

use crate::{Error, Sink, Stream};
use bytes::{Bytes, BytesMut};
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
    async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        let bytes = Bytes::copy_from_slice(msg);
        self.sender.send(bytes)
            .await
            .map_err(|_| Error::WriteFailed)
    }
}

/// A mock stream that reads messages from a channel.
pub struct MockStream {
    pub receiver: mpsc::UnboundedReceiver<Bytes>,
    buffer: BytesMut,
}

impl MockStream {
    /// Create a new `MockStream` and a corresponding sender.
    pub fn new() -> (Self, mpsc::UnboundedSender<Bytes>) {
        let (sender, receiver) = mpsc::unbounded();
        (Self {
            receiver,
            buffer: BytesMut::with_capacity(1024 * 1024)
        }, sender)
    }

    /// Parse exactly `n` bytes from the stream.
    async fn parse_exact(&mut self, n: usize) -> Result<Bytes, Error> {
        // Keep reading messages into the buffer until we have enough
        while self.buffer.len() < n {
            let msg = self.receiver.next()
                .await
                .ok_or(Error::ReadFailed)?;
            self.buffer.extend_from_slice(&msg);
        }

        // Extract the required number of bytes from the buffer
        Ok(self.buffer.split_to(n).freeze())
    }
}

impl Stream for MockStream {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let msg = self.parse_exact(buf.len()).await?;
        buf.copy_from_slice(&msg);
        Ok(())
    }
}
