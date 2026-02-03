//! A mock implementation of a channel that implements the Sink and Stream traits.

use crate::{BufMut, Error, IoBufs, Sink as SinkTrait, Stream as StreamTrait};
use bytes::{Bytes, BytesMut};
use commonware_utils::channel::oneshot;
use std::sync::{Arc, Mutex};

/// Default read buffer size for the stream's local buffer (64 KB).
const DEFAULT_READ_BUFFER_SIZE: usize = 64 * 1024;

/// A mock channel struct that is used internally by Sink and Stream.
pub struct Channel {
    /// Stores the bytes sent by the sink that are not yet read by the stream.
    buffer: BytesMut,

    /// If the stream is waiting to read bytes, the waiter stores the number of
    /// bytes that the stream is waiting for, as well as the oneshot sender that
    /// the sink uses to send the bytes to the stream directly.
    waiter: Option<(usize, oneshot::Sender<Bytes>)>,

    /// Target size for the stream's local buffer, used to bound buffering.
    read_buffer_size: usize,

    /// Tracks whether the sink is still alive and able to send messages.
    sink_alive: bool,

    /// Tracks whether the stream is still alive and able to receive messages.
    stream_alive: bool,
}

impl Channel {
    /// Returns an async-safe Sink/Stream pair with default read buffer size.
    pub fn init() -> (Sink, Stream) {
        Self::init_with_read_buffer_size(DEFAULT_READ_BUFFER_SIZE)
    }

    /// Returns an async-safe Sink/Stream pair with the specified buffer capacity.
    pub fn init_with_read_buffer_size(read_buffer_size: usize) -> (Sink, Stream) {
        let channel = Arc::new(Mutex::new(Self {
            buffer: BytesMut::new(),
            waiter: None,
            read_buffer_size,
            sink_alive: true,
            stream_alive: true,
        }));
        (
            Sink {
                channel: channel.clone(),
            },
            Stream {
                channel,
                buffer: BytesMut::new(),
            },
        )
    }
}

/// A mock sink that implements the Sink trait.
pub struct Sink {
    channel: Arc<Mutex<Channel>>,
}

impl SinkTrait for Sink {
    async fn send(&mut self, buf: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let (os_send, data) = {
            let mut channel = self.channel.lock().unwrap();

            // If the receiver is dead, we cannot send any more messages.
            if !channel.stream_alive {
                return Err(Error::Closed);
            }

            channel.buffer.put(buf.into());

            // If there is a waiter and the buffer is large enough,
            // return the waiter (while clearing the waiter field).
            // Otherwise, return early.
            if channel
                .waiter
                .as_ref()
                .is_some_and(|(requested, _)| *requested <= channel.buffer.len())
            {
                // Send up to read_buffer_size bytes (but at least requested amount)
                let (requested, os_send) = channel.waiter.take().unwrap();
                let send_amount = channel
                    .buffer
                    .len()
                    .min(requested.max(channel.read_buffer_size));
                let data = channel.buffer.split_to(send_amount).freeze();
                (os_send, data)
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
    /// Local buffer for data that has been received but not yet consumed.
    buffer: BytesMut,
}

impl StreamTrait for Stream {
    async fn recv(&mut self, len: u64) -> Result<IoBufs, Error> {
        let len = len as usize;

        let os_recv = {
            let mut channel = self.channel.lock().unwrap();

            // Pull data from channel buffer into local buffer.
            if !channel.buffer.is_empty() {
                let target = len.max(channel.read_buffer_size);
                let pull_amount = channel
                    .buffer
                    .len()
                    .min(target.saturating_sub(self.buffer.len()));
                if pull_amount > 0 {
                    let data = channel.buffer.split_to(pull_amount);
                    self.buffer.extend_from_slice(&data);
                }
            }

            // If we have enough, return immediately.
            if self.buffer.len() >= len {
                return Ok(IoBufs::from(self.buffer.split_to(len).freeze()));
            }

            // If the sink is dead, we cannot receive any more messages.
            if !channel.sink_alive {
                return Err(Error::Closed);
            }

            // Set up waiter for remaining amount.
            let remaining = len - self.buffer.len();
            assert!(channel.waiter.is_none());
            let (os_send, os_recv) = oneshot::channel();
            channel.waiter = Some((remaining, os_send));
            os_recv
        };

        // Wait for the waiter to be resolved.
        let data = os_recv.await.map_err(|_| Error::Closed)?;
        self.buffer.extend_from_slice(&data);

        assert!(self.buffer.len() >= len);
        Ok(IoBufs::from(self.buffer.split_to(len).freeze()))
    }

    fn peek(&self, max_len: u64) -> &[u8] {
        let len = (max_len as usize).min(self.buffer.len());
        &self.buffer[..len]
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
        let data = b"hello world";

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            sink.send(data.as_slice()).await.unwrap();
            let received = stream.recv(data.len() as u64).await.unwrap();
            assert_eq!(received.coalesce(), data);
        });
    }

    #[test]
    fn test_send_recv_partial_multiple() {
        let (mut sink, mut stream) = Channel::init();
        let data = b"hello";
        let data2 = b" world";

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            sink.send(data.as_slice()).await.unwrap();
            sink.send(data2.as_slice()).await.unwrap();
            let received = stream.recv(5).await.unwrap();
            assert_eq!(received.coalesce(), b"hello");
            let received = stream.recv(5).await.unwrap();
            assert_eq!(received.coalesce(), b" worl");
            let received = stream.recv(1).await.unwrap();
            assert_eq!(received.coalesce(), b"d");
        });
    }

    #[test]
    fn test_send_recv_async() {
        let (mut sink, mut stream) = Channel::init();
        let data = b"hello world";

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (received, _) = futures::try_join!(stream.recv(data.len() as u64), async {
                sleep(Duration::from_millis(50));
                sink.send(data.as_slice()).await
            })
            .unwrap();
            assert_eq!(received.coalesce(), data);
        });
    }

    #[test]
    fn test_recv_error_sink_dropped_while_waiting() {
        let (sink, mut stream) = Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            futures::join!(
                async {
                    let result = stream.recv(5).await;
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
            let result = stream.recv(5).await;
            assert!(matches!(result, Err(Error::Closed)));
        });
    }

    #[test]
    fn test_send_error_stream_dropped() {
        let (mut sink, mut stream) = Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Send some bytes
            assert!(sink.send(b"7 bytes".as_slice()).await.is_ok());

            // Spawn a task to initiate recv's where the first one will succeed and then will drop.
            let handle = context.clone().spawn(|_| async move {
                let _ = stream.recv(5).await;
                let _ = stream.recv(5).await;
            });

            // Give the async task a moment to start
            context.sleep(Duration::from_millis(50)).await;

            // Drop the stream by aborting the handle
            handle.abort();
            assert!(matches!(handle.await, Err(Error::Closed)));

            // Try to send a message. The stream is dropped, so this should fail.
            let result = sink.send(b"hello world".as_slice()).await;
            assert!(matches!(result, Err(Error::Closed)));
        });
    }

    #[test]
    fn test_send_error_stream_dropped_before_send() {
        let (mut sink, stream) = Channel::init();
        drop(stream); // Drop stream immediately

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let result = sink.send(b"hello world".as_slice()).await;
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
                v = stream.recv(5) => {
                    panic!("unexpected value: {v:?}");
                },
                _ = context.sleep(Duration::from_millis(100)) => "timeout",
            };
        });
    }

    #[test]
    fn test_peek_empty() {
        let (_sink, stream) = Channel::init();

        // Peek on a fresh stream should return empty slice
        assert!(stream.peek(10).is_empty());
    }

    #[test]
    fn test_peek_after_partial_recv() {
        let (mut sink, mut stream) = Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Send more data than we'll consume
            sink.send(b"hello world".as_slice()).await.unwrap();

            // Recv only part of it
            let received = stream.recv(5).await.unwrap();
            assert_eq!(received.coalesce(), b"hello");

            // Peek should show the remaining data
            assert_eq!(stream.peek(100), b" world");

            // Peek with smaller max_len
            assert_eq!(stream.peek(3), b" wo");

            // Peek doesn't consume - can peek again
            assert_eq!(stream.peek(100), b" world");

            // Recv consumes the peeked data
            let received = stream.recv(6).await.unwrap();
            assert_eq!(received.coalesce(), b" world");

            // Peek is now empty
            assert!(stream.peek(100).is_empty());
        });
    }

    #[test]
    fn test_peek_after_recv_wakeup() {
        let (mut sink, mut stream) = Channel::init_with_read_buffer_size(64);

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Spawn recv that will block waiting
            let (tx, rx) = oneshot::channel();
            let recv_handle = context.clone().spawn(|_| async move {
                let data = stream.recv(3).await.unwrap();
                tx.send(stream).ok();
                data
            });

            // Let recv set up waiter
            context.sleep(Duration::from_millis(10)).await;

            // Send more than requested
            sink.send(b"ABCDEFGHIJ".as_slice()).await.unwrap();

            // Recv gets its 3 bytes
            let received = recv_handle.await.unwrap();
            assert_eq!(received.coalesce(), b"ABC");

            // Get stream back and verify peek sees remaining data
            let stream = rx.await.unwrap();
            assert_eq!(stream.peek(100), b"DEFGHIJ");
        });
    }

    #[test]
    fn test_peek_multiple_sends() {
        let (mut sink, mut stream) = Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Send multiple chunks
            sink.send(b"aaa".as_slice()).await.unwrap();
            sink.send(b"bbb".as_slice()).await.unwrap();
            sink.send(b"ccc".as_slice()).await.unwrap();

            // Recv less than total
            let received = stream.recv(4).await.unwrap();
            assert_eq!(received.coalesce(), b"aaab");

            // Peek should show remaining
            assert_eq!(stream.peek(100), b"bbccc");
        });
    }

    #[test]
    fn test_read_buffer_size_limit() {
        // Use a small buffer capacity for testing
        let (mut sink, mut stream) = Channel::init_with_read_buffer_size(10);

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Send more than buffer capacity
            sink.send(b"0123456789ABCDEF".as_slice()).await.unwrap();

            // Recv a small amount - should only pull up to capacity (10 bytes)
            let received = stream.recv(2).await.unwrap();
            assert_eq!(received.coalesce(), b"01");

            // Peek should show remaining buffered data (8 bytes, not 14)
            assert_eq!(stream.peek(100), b"23456789");

            // The rest should still be in the channel buffer
            // Recv more to pull the remaining data
            let received = stream.recv(8).await.unwrap();
            assert_eq!(received.coalesce(), b"23456789");

            // Now peek should show next chunk from channel (up to capacity)
            let received = stream.recv(2).await.unwrap();
            assert_eq!(received.coalesce(), b"AB");

            assert_eq!(stream.peek(100), b"CDEF");
        });
    }

    #[test]
    fn test_recv_before_send() {
        // Use a small buffer capacity for testing
        let (mut sink, mut stream) = Channel::init_with_read_buffer_size(10);

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Start recv before send (will wait)
            let recv_handle = context
                .clone()
                .spawn(|_| async move { stream.recv(3).await.unwrap() });

            // Give recv time to set up waiter
            context.sleep(Duration::from_millis(10)).await;

            // Send more than capacity
            sink.send(b"ABCDEFGHIJKLMNOP".as_slice()).await.unwrap();

            // Recv should get its 3 bytes
            let received = recv_handle.await.unwrap();
            assert_eq!(received.coalesce(), b"ABC");
        });
    }
}
