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

    /// Tracks whether the sink is still alive and able to send messages.
    sink_alive: bool,

    /// Tracks whether the stream is still alive and able to receive messages.
    stream_alive: bool,
}

impl Channel {
    /// Returns an async-safe Sink/Stream pair that share an underlying buffer of bytes.
    pub fn init() -> (Sink, Stream) {
        let channel = Arc::new(Mutex::new(Channel {
            buffer: VecDeque::new(),
            waiter: None,
            sink_alive: true,
            stream_alive: true,
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

            // If the receiver is dead, we cannot send any more messages.
            if !channel.stream_alive {
                return Err(Error::Closed);
            }

            // Add the data to the buffer.
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

impl Drop for Sink {
    fn drop(&mut self) {
        let mut channel = self.channel.lock().unwrap();
        channel.sink_alive = false;

        // If there is a waiter, resolve it by dropping the oneshot sender.
        channel.waiter.take();
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

            // At this point, there is not enough data in the buffer.
            // If the stream is dead, we cannot receive any more messages.
            if !channel.sink_alive {
                return Err(Error::Closed);
            }

            // Otherwise, populate the waiter.
            assert!(channel.waiter.is_none());
            let (os_send, os_recv) = oneshot::channel();
            channel.waiter = Some((buf.len(), os_send));
            os_recv
        };

        // Wait for the waiter to be resolved.
        // If the oneshot sender was dropped, it means the sink is closed.
        let data = os_recv.await.map_err(|_| Error::Closed)?;
        assert_eq!(data.len(), buf.len());
        buf.put_slice(&data);
        Ok(buf)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let mut channel = self.channel.lock().unwrap();
        channel.stream_alive = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, Clock, Runner, Spawner};
    use commonware_macros::select;
    use std::{thread::sleep, time::Duration};

    #[test]
    fn test_send_recv() {
        let (mut sink, mut stream) = Channel::init();
        let data = b"hello world".to_vec();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
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

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
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

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (buf, _) = futures::try_join!(stream.recv(vec![0; data.len()]), async {
                sleep(Duration::from_millis(50));
                sink.send(data.to_vec()).await
            })
            .unwrap();
            assert_eq!(buf.as_ref(), data);
        });
    }

    #[test]
    fn test_recv_error_sink_dropped_while_waiting() {
        let (sink, mut stream) = Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            futures::join!(
                async {
                    let result = stream.recv(vec![0; 5]).await;
                    assert!(matches!(result, Err(Error::Closed)));
                },
                async {
                    // Wait for the stream to start waiting
                    context.sleep(Duration::from_millis(50)).await;
                    drop(sink);
                }
            );
        });
    }

    #[test]
    fn test_recv_error_sink_dropped_before_recv() {
        let (sink, mut stream) = Channel::init();
        drop(sink); // Drop sink immediately

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let result = stream.recv(vec![0; 5]).await;
            assert!(matches!(result, Err(Error::Closed)));
        });
    }

    #[test]
    fn test_send_error_stream_dropped() {
        let (mut sink, mut stream) = Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Send some bytes
            assert!(sink.send(b"7 bytes".to_vec()).await.is_ok());

            // Spawn a task to initiate recv's where the first one will succeed and then will drop.
            let handle = context.clone().spawn(|_| async move {
                let _ = stream.recv(vec![0; 5]).await;
                let _ = stream.recv(vec![0; 5]).await;
            });

            // Give the async task a moment to start
            context.sleep(Duration::from_millis(50)).await;

            // Drop the stream by aborting the handle
            handle.abort();
            assert!(matches!(handle.await, Err(Error::Closed)));

            // Try to send a message. The stream is dropped, so this should fail.
            let result = sink.send(b"hello world".to_vec()).await;
            assert!(matches!(result, Err(Error::Closed)));
        });
    }

    #[test]
    fn test_send_error_stream_dropped_before_send() {
        let (mut sink, stream) = Channel::init();
        drop(stream); // Drop stream immediately

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let result = sink.send(b"hello world".to_vec()).await;
            assert!(matches!(result, Err(Error::Closed)));
        });
    }

    #[test]
    fn test_recv_timeout() {
        let (_sink, mut stream) = Channel::init();

        // If there is no data to read, test that the recv function just blocks.
        // The timeout should return first.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            select! {
                v = stream.recv(vec![0;5]) => {
                    panic!("unexpected value: {v:?}");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    "timeout"
                },
            };
        });
    }
}
