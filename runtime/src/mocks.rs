//! A mock implementation of a channel that implements the Sink and Stream traits.

use crate::{BufMut, Error, IoBufs};
use bytes::{Bytes, BytesMut};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use std::sync::Arc;

/// Default buffer size (64 KB). Controls both how much data the stream
/// pulls per recv and the backpressure threshold for send.
const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// A mock channel struct that is used internally by Sink and Stream.
pub struct Channel {
    /// Stores the bytes sent by the sink that are not yet read by the stream.
    buffer: BytesMut,

    /// If the stream is waiting to read bytes, the waiter stores the number of
    /// bytes that the stream is waiting for, as well as the oneshot sender that
    /// the sink uses to send the bytes to the stream directly.
    waiter: Option<(usize, oneshot::Sender<Bytes>)>,

    /// Target buffer size, used to bound both the stream's local buffer
    /// and the shared buffer (backpressure threshold).
    buffer_size: usize,

    /// If the sink is blocked waiting for the buffer to drain, this holds
    /// the oneshot sender that the stream uses to wake the sink.
    drain_waiter: Option<oneshot::Sender<()>>,

    /// Tracks whether the sink is still alive and able to send messages.
    sink_alive: bool,

    /// Tracks whether the stream is still alive and able to receive messages.
    stream_alive: bool,
}

impl Channel {
    /// Returns an async-safe Sink/Stream pair with default buffer size.
    pub fn init() -> (Sink, Stream) {
        Self::init_with_buffer_size(DEFAULT_BUFFER_SIZE)
    }

    /// Returns an async-safe Sink/Stream pair with the specified buffer size.
    pub fn init_with_buffer_size(buffer_size: usize) -> (Sink, Stream) {
        let channel = Arc::new(Mutex::new(Self {
            buffer: BytesMut::new(),
            waiter: None,
            buffer_size,
            drain_waiter: None,
            sink_alive: true,
            stream_alive: true,
        }));
        (
            Sink {
                channel: channel.clone(),
                state: SinkState::Open,
            },
            Stream {
                channel,
                buffer: BytesMut::new(),
                poisoned: false,
            },
        )
    }

    /// Restores bytes that were detached from the front of the shared buffer.
    fn restore_front(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }

        let mut restored = BytesMut::with_capacity(data.len() + self.buffer.len());
        restored.extend_from_slice(&data);
        restored.extend_from_slice(&self.buffer);
        self.buffer = restored;
    }

    /// Marks the sink as closed and wakes any waiter.
    fn close_sink(&mut self) {
        self.sink_alive = false;

        // If there is a waiter, resolve it by dropping the oneshot sender.
        self.waiter.take();
    }
}

struct RecvWaiterGuard {
    channel: Arc<Mutex<Channel>>,
    active: bool,
}

impl RecvWaiterGuard {
    const fn new(channel: Arc<Mutex<Channel>>) -> Self {
        Self {
            channel,
            active: true,
        }
    }

    const fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for RecvWaiterGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        self.channel.lock().waiter.take();
    }
}

/// A mock sink that implements the Sink trait.
pub struct Sink {
    channel: Arc<Mutex<Channel>>,
    state: SinkState,
}

/// Lifecycle state for the mock sink half.
enum SinkState {
    /// Sends may be attempted.
    Open,
    /// A send is currently in progress.
    Sending,
    /// The sink has been closed.
    Closed,
}

impl Sink {
    fn close(&mut self) {
        if matches!(self.state, SinkState::Closed) {
            return;
        }
        self.channel.lock().close_sink();
        self.state = SinkState::Closed;
    }
}

impl crate::Sink for Sink {
    async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        match self.state {
            SinkState::Open => {}
            SinkState::Sending => {
                self.close();
                return Err(Error::Closed);
            }
            SinkState::Closed => return Err(Error::Closed),
        }

        let drain_recv = {
            let mut channel = self.channel.lock();

            // If the receiver is dead, we cannot send any more messages.
            if !channel.stream_alive {
                self.state = SinkState::Sending;
                return Err(Error::SendFailed);
            }

            channel.buffer.put(bufs.into());

            // If there is a waiter and the buffer is large enough,
            // resolve the waiter (while clearing the waiter field).
            if channel
                .waiter
                .as_ref()
                .is_some_and(|(requested, _)| *requested <= channel.buffer.len())
            {
                // Send up to buffer_size bytes (but at least requested amount)
                let (requested, os_send) = channel.waiter.take().unwrap();
                let send_amount = channel.buffer.len().min(requested.max(channel.buffer_size));
                let data = channel.buffer.split_to(send_amount).freeze();

                // A canceled recv should behave like a buffered transport:
                // preserve the bytes and allow a subsequent recv to consume them.
                if let Err(data) = os_send.send(data) {
                    channel.restore_front(data);
                    if !channel.stream_alive {
                        self.state = SinkState::Sending;
                        return Err(Error::SendFailed);
                    }
                }
            }

            // If the buffer exceeds the write limit, block until the
            // receiver drains enough data.
            if channel.buffer.len() > channel.buffer_size {
                assert!(channel.drain_waiter.is_none());
                let (os_send, os_recv) = oneshot::channel();
                channel.drain_waiter = Some(os_send);
                os_recv
            } else {
                return Ok(());
            }
        };

        // Mark the sink as sending before awaiting so cancellation can be
        // detected by the next send.
        self.state = SinkState::Sending;

        // Wait for the receiver to drain the buffer.
        match drain_recv.await {
            Ok(()) => {
                self.state = SinkState::Open;
                Ok(())
            }
            Err(_) => Err(Error::SendFailed),
        }
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.close();
    }
}

/// A mock stream that implements the Stream trait.
pub struct Stream {
    channel: Arc<Mutex<Channel>>,
    /// Local buffer for data that has been received but not yet consumed.
    buffer: BytesMut,
    poisoned: bool,
}

impl crate::Stream for Stream {
    async fn recv(&mut self, len: usize) -> Result<IoBufs, Error> {
        if self.poisoned {
            return Err(Error::Closed);
        }

        let os_recv = {
            let mut channel = self.channel.lock();

            // Pull data from channel buffer into local buffer.
            let target = len.max(channel.buffer_size);
            let pull_amount = channel
                .buffer
                .len()
                .min(target.saturating_sub(self.buffer.len()));
            if pull_amount > 0 {
                let data = channel.buffer.split_to(pull_amount);
                self.buffer.extend_from_slice(&data);

                // Wake a blocked sender if the buffer drained below the limit.
                if channel.buffer.len() <= channel.buffer_size {
                    if let Some(sender) = channel.drain_waiter.take() {
                        sender.send_lossy(());
                    }
                }
            }

            // If we have enough, return immediately.
            if self.buffer.len() >= len {
                return Ok(IoBufs::from(self.buffer.split_to(len).freeze()));
            }

            // If the sink is dead, we cannot receive any more messages.
            if !channel.sink_alive {
                self.poisoned = true;
                return Err(Error::RecvFailed);
            }

            // Set up waiter for remaining amount.
            let remaining = len - self.buffer.len();
            assert!(channel.waiter.is_none());
            let (os_send, os_recv) = oneshot::channel();
            channel.waiter = Some((remaining, os_send));
            os_recv
        };

        let mut waiter_guard = RecvWaiterGuard::new(self.channel.clone());

        // Pre-poison so that cancellation  leaves the stream permanently closed.
        self.poisoned = true;

        // Wait for the waiter to be resolved.
        let data = match os_recv.await {
            Ok(data) => {
                waiter_guard.disarm();
                self.poisoned = false;
                data
            }
            Err(_) => {
                waiter_guard.disarm();
                return Err(Error::RecvFailed);
            }
        };
        self.buffer.extend_from_slice(&data);

        assert!(self.buffer.len() >= len);
        Ok(IoBufs::from(self.buffer.split_to(len).freeze()))
    }

    fn peek(&self, max_len: usize) -> &[u8] {
        let len = max_len.min(self.buffer.len());
        &self.buffer[..len]
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let mut channel = self.channel.lock();
        channel.stream_alive = false;

        // Wake a blocked sender so it can observe the closed stream.
        channel.drain_waiter.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, Clock, Runner, Sink, Spawner, Stream};
    use commonware_macros::select;
    use std::{thread::sleep, time::Duration};

    #[test]
    fn test_send_recv() {
        let (mut sink, mut stream) = Channel::init();
        let data = b"hello world";

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            sink.send(data.as_slice()).await.unwrap();
            let received = stream.recv(data.len()).await.unwrap();
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
            let (received, _) = futures::try_join!(stream.recv(data.len()), async {
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
                    assert!(matches!(result, Err(Error::RecvFailed)));
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
            assert!(matches!(result, Err(Error::RecvFailed)));
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
            assert!(matches!(result, Err(Error::SendFailed)));
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
            assert!(matches!(result, Err(Error::SendFailed)));
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
        let (mut sink, mut stream) = Channel::init_with_buffer_size(64);

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
    fn test_buffer_size_limit() {
        // Use a small buffer capacity for testing
        let (mut sink, mut stream) = Channel::init_with_buffer_size(10);

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Send more than buffer capacity concurrently with recv
            // so the sender can drain via backpressure.
            let send_handle = context.clone().spawn(|_| async move {
                sink.send(b"0123456789ABCDEF".as_slice()).await.unwrap();
                sink
            });

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

            // Ensure the sender completes
            send_handle.await.unwrap();
        });
    }

    #[test]
    fn test_recv_before_send() {
        // Use a small buffer capacity for testing
        let (mut sink, mut stream) = Channel::init_with_buffer_size(10);

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
