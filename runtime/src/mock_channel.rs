//! A mock implementation of a channel that implements the Sink and Stream traits.

use crate::{Error, Sink, Stream};
use bytes::Bytes;
use futures::channel::oneshot;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

// A mock channel struct that is used internally by the ByteSink and ByteStream.
struct ByteChannel {
    buffer: VecDeque<u8>,
    waiter: Option<(usize, oneshot::Sender<Bytes>)>,
}

// Returns an async-safe sink/stream pair that share an underlying ByteChannel.
// The buffer is wrapped in a mutex and an Arc to allow for shared ownership across async tasks.
pub fn new() -> (ByteSink, ByteStream) {
    let channel = Arc::new(Mutex::new(ByteChannel {
        buffer: VecDeque::new(),
        waiter: None,
    }));
    (
        ByteSink { channel: channel.clone() },
        ByteStream { channel },
    )
}

// A mock sink that implements the Sink trait.
pub struct ByteSink {
    channel: Arc<Mutex<ByteChannel>>,
}

impl Sink for ByteSink {
    // Writes the message to the buffer.
    // Resolves the oneshot receiver if-and-only-if the buffer is large enough.
    async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        let (os_send, data) = {
            let mut channel = self.channel.lock().unwrap();
            channel.buffer.extend(msg);

            // If there is a waiter and the buffer is large enough,
            // return the waiter (while clearing the waiter field).
            // Otherwise, return early.
            if channel.waiter.as_ref().map_or(false, |(requested, _)| *requested <= channel.buffer.len()) {
                let (requested, os_send) = channel.waiter.take().unwrap();
                let data: Vec<u8> = channel.buffer.drain(0..requested).collect();
                (os_send, Bytes::from(data))
            } else {
                return Ok(());
            }
        };

        // Resolve the waiter.
        os_send.send(data).map_err(|_| Error::SendFailed)?;
        Ok(())
    }
}

// A mock stream that implements the Stream trait.
pub struct ByteStream {
    channel: Arc<Mutex<ByteChannel>>,
}

impl Stream for ByteStream {
    // Blocks until the buffer has enough bytes to fill `buf`.
    // Does not hold the lock unless it needs to.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let os_recv = {
            let mut channel = self.channel.lock().unwrap();

            // If the message is fully available in the buffer,
            // drain the value into buf and return.
            if channel.buffer.len() >= buf.len() {
                let b: Vec<u8> = channel.buffer.drain(0..buf.len()).collect();
                buf.copy_from_slice(&b);
                return Ok(());
            }

            // Otherwise, create a oneshot receiver and store it in the channel.
            assert!(channel.waiter.is_none());
            let (os_send, os_recv) = oneshot::channel();
            channel.waiter = Some((buf.len(), os_send));
            os_recv
        };

        // Wait for the oneshot receiver to be resolved.
        let data = os_recv.await.map_err(|_| Error::RecvFailed)?;
        buf.copy_from_slice(&data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    #[test]
    fn test_send_recv() {
        let (mut sink, mut stream) = new();

        let data = b"hello world";
        let mut buf = vec![0; data.len()];

        block_on(async {
            sink.send(data).await.unwrap();
            stream.recv(&mut buf).await.unwrap();
        });

        assert_eq!(buf, data);
    }

    #[test]
    fn test_send_recv_partial_multiple() {
        let (mut sink, mut stream) = new();

        let data1 = b"hello";
        let data2 = b"world";
        let mut buf1 = vec![0; data1.len()];
        let mut buf2 = vec![0; data2.len()];

        block_on(async {
            sink.send(data1).await.unwrap();
            sink.send(data2).await.unwrap();
            stream.recv(&mut buf1[0..3]).await.unwrap();
            stream.recv(&mut buf1[3..]).await.unwrap();
            stream.recv(&mut buf2).await.unwrap();
        });

        assert_eq!(buf1, data1);
        assert_eq!(buf2, data2);
    }

    #[test]
    fn test_send_recv_async() {
        let (mut sink, mut stream) = new();

        let data = b"hello world";
        let mut buf = vec![0; data.len()];

        block_on(async {
            futures::try_join!(
                stream.recv(&mut buf),
                async {
                    std::thread::sleep(std::time::Duration::from_millis(10_000));
                    sink.send(data).await
                },
            )
            .unwrap();
        });

        assert_eq!(buf, data);
    }

    /*
    #[test]
    fn test_recv_error() {
        // TODO: If the oneshot sender is dropped before the oneshot receiver is resolved,
        // the recv function should return an error.
        let (sink, mut stream) = new();

        let mut buf = vec![0; 5];

        block_on(async {
            drop(sink.channel.lock().unwrap().waiter.take());
            let result = stream.recv(&mut buf).await;
            assert_eq!(result, Err(Error::RecvFailed));
        });
    }

    #[test]
    fn test_send_error() {
        // TODO: If the waiter value has a min, but the oneshot sender is dropped,
        // the send function should return an error.
    }

    #[test]
    fn test_recv_timeout() {
        // TODO: If there is no data to read, test that the recv function just blocks. A timeout should return first.
    }
    */
}
