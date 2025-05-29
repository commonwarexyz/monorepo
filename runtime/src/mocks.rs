//! A mock implementation of a channel that implements the Sink and Stream traits.

use crate::{Error, Sink as SinkTrait, Stream as StreamTrait};
use bytes::Bytes;
use commonware_utils::StableBuf;
use futures::channel::oneshot;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

/// A mock channel struct that is used internally by Sink and Stream.
pub struct Channel {
    /// Stores the bytes sent by the sink that are not yet read by the stream.
    buffer: VecDeque<u8>,

    /// If the stream is waiting to read bytes, the waiter stores the number of
    /// bytes that the stream is waiting for, as well as the oneshot sender that
    /// the sink uses to send the bytes to the stream directly.
    waiter: Option<(usize, oneshot::Sender<Bytes>)>,
}

impl Channel {
    /// Returns an async-safe Sink/Stream pair that share an underlying buffer of bytes.
    pub fn init() -> (Sink, Stream) {
        let channel = Arc::new(Mutex::new(Channel {
            buffer: VecDeque::new(),
            waiter: None,
        }));
        (
            Sink {
                channel: channel.clone(),
            },
            Stream { channel },
        )
    }
}

/// A mock sink that implements the Sink trait.
pub struct Sink {
    channel: Arc<Mutex<Channel>>,
}

impl SinkTrait for Sink {
    async fn send(&mut self, msg: impl Into<StableBuf> + Send) -> Result<(), Error> {
        let msg = msg.into();
        let (os_send, data) = {
            let mut channel = self.channel.lock().unwrap();
            channel.buffer.extend(msg.as_ref());

            // If there is a waiter and the buffer is large enough,
            // return the waiter (while clearing the waiter field).
            // Otherwise, return early.
            if channel
                .waiter
                .as_ref()
                .is_some_and(|(requested, _)| *requested <= channel.buffer.len())
            {
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

/// A mock stream that implements the Stream trait.
pub struct Stream {
    channel: Arc<Mutex<Channel>>,
}

impl StreamTrait for Stream {
    async fn recv(&mut self, buf: impl Into<StableBuf> + Send) -> Result<StableBuf, Error> {
        let mut buf = buf.into();
        let os_recv = {
            let mut channel = self.channel.lock().unwrap();

            // If the message is fully available in the buffer,
            // drain the value into buf and return.
            if channel.buffer.len() >= buf.len() {
                let b: Vec<u8> = channel.buffer.drain(0..buf.len()).collect();
                buf.put_slice(&b);
                return Ok(buf);
            }

            // Otherwise, populate the waiter.
            assert!(channel.waiter.is_none());
            let (os_send, os_recv) = oneshot::channel();
            channel.waiter = Some((buf.len(), os_send));
            os_recv
        };

        // Wait for the waiter to be resolved.
        let data = os_recv.await.map_err(|_| Error::RecvFailed)?;
        assert_eq!(data.len(), buf.len());
        buf.put_slice(&data);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, Clock, Runner};
    use commonware_macros::select;
    use futures::{executor::block_on, join};
    use std::{thread::sleep, time::Duration};

    #[test]
    fn test_send_recv() {
        let (mut sink, mut stream) = Channel::init();
        let data = b"hello world".to_vec();

        block_on(async {
            sink.send(data.clone()).await.unwrap();
            let buf = stream.recv(vec![0; data.len()]).await.unwrap();
            assert_eq!(buf.as_ref(), data);
        });
    }

    #[test]
    fn test_send_recv_partial_multiple() {
        let (mut sink, mut stream) = Channel::init();
        let data = b"hello".to_vec();
        let data2 = b" world".to_vec();

        block_on(async {
            sink.send(data).await.unwrap();
            sink.send(data2).await.unwrap();
            let buf = stream.recv(vec![0; 5]).await.unwrap();
            assert_eq!(buf.as_ref(), b"hello");
            let buf = stream.recv(buf).await.unwrap();
            assert_eq!(buf.as_ref(), b" worl");
            let buf = stream.recv(vec![0; 1]).await.unwrap();
            assert_eq!(buf.as_ref(), b"d");
        });
    }

    #[test]
    fn test_send_recv_async() {
        let (mut sink, mut stream) = Channel::init();

        let data = b"hello world";
        let buf = block_on(async {
            futures::try_join!(stream.recv(vec![0; data.len()]), async {
                sleep(Duration::from_millis(10_000));
                sink.send(data.to_vec()).await
            },)
            .unwrap()
            .0
        });

        assert_eq!(buf.as_ref(), data);
    }

    #[test]
    fn test_recv_error() {
        let (sink, mut stream) = Channel::init();
        let executor = deterministic::Runner::default();

        // If the oneshot sender is dropped before the oneshot receiver is resolved,
        // the recv function should return an error.
        executor.start(|_| async move {
            let (v, _) = join!(stream.recv(vec![0; 5]), async {
                // Take the waiter and drop it.
                sink.channel.lock().unwrap().waiter.take();
            },);
            assert!(matches!(v, Err(Error::RecvFailed)));
        });
    }

    #[test]
    fn test_send_error() {
        let (mut sink, mut stream) = Channel::init();
        let executor = deterministic::Runner::default();

        // If the waiter value has a min, but the oneshot receiver is dropped,
        // the send function should return an error when attempting to send the data.
        executor.start(|context| async move {
            // Create a waiter using a recv call.
            // But then drop the receiver.
            select! {
                v = stream.recv( vec![0;5]) => {
                    panic!("unexpected value: {:?}", v);
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    "timeout"
                },
            };
            drop(stream);

            // Try to send a message (longer than the requested amount), but the receiver is dropped.
            let result = sink.send(b"hello world".to_vec()).await;
            assert!(matches!(result, Err(Error::SendFailed)));
        });
    }

    #[test]
    fn test_recv_timeout() {
        let (_sink, mut stream) = Channel::init();
        let executor = deterministic::Runner::default();

        // If there is no data to read, test that the recv function just blocks. A timeout should return first.
        executor.start(|context| async move {
            select! {
                v = stream.recv(vec![0;5]) => {
                    panic!("unexpected value: {:?}", v);
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    "timeout"
                },
            };
        });
    }
}
