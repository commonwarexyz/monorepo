use commonware_codec::{
    Encode,
    varint::{Decoder, MAX_U32_VARINT_SIZE, UInt},
};
use commonware_runtime::{Buf, Error as RuntimeError, IoBuf, IoBufs, Sink, Stream};
use commonware_utils::Widen;
use thiserror::Error;

/// Errors that can occur when sending or receiving a length-prefixed frame.
#[derive(Error, Debug)]
pub enum Error {
    #[error("recv failed")]
    RecvFailed(RuntimeError),
    #[error("recv too large: {0} bytes")]
    RecvTooLarge(usize),
    #[error("invalid varint length prefix")]
    InvalidVarint,
    #[error("send failed")]
    SendFailed(RuntimeError),
    #[error("send too large: {0} bytes")]
    SendTooLarge(usize),
}

/// Returns `len` as a u32 if it does not exceed `max_message_size`.
pub(crate) fn validate_frame_len(len: usize, max_message_size: u32) -> Result<u32, Error> {
    u32::try_from(len)
        .ok()
        .filter(|len| *len <= max_message_size)
        .ok_or(Error::SendTooLarge(len))
}

/// Sends data to the sink with a varint length prefix.
///
/// The varint length prefix is prepended to the buffer(s), which results in a
/// chunked `IoBufs`.
///
/// Returns an error if the message is too large or the sink is closed.
pub async fn send_frame<S: Sink>(
    sink: &mut S,
    bufs: impl Into<IoBufs> + Send,
    max_message_size: u32,
) -> Result<(), Error> {
    let mut bufs = bufs.into();
    let len = validate_frame_len(bufs.len(), max_message_size)?;
    bufs.prepend(IoBuf::from(UInt(len).encode()));
    sink.send(bufs).await.map_err(Error::SendFailed)
}

/// Receives data from the stream with a varint length prefix.
/// Returns an error if the message is too large, the varint is invalid, or the
/// stream is closed.
pub async fn recv_frame<T: Stream>(stream: &mut T, max_message_size: u32) -> Result<IoBufs, Error> {
    let (len, skip) = recv_length(stream).await?;
    if len > Widen::<usize>::widen(max_message_size) {
        return Err(Error::RecvTooLarge(len));
    }

    // Consume the prefix separately if the combined read length would overflow.
    let skip = if skip.checked_add(len).is_some() {
        skip
    } else {
        stream.recv(skip).await.map_err(Error::RecvFailed)?;
        0
    };
    stream
        .recv(skip + len)
        .await
        .map(|mut bufs| {
            bufs.advance(skip);
            bufs
        })
        .map_err(Error::RecvFailed)
}

/// Receives and decodes the varint length prefix from the stream.
/// Returns the payload length and number of unconsumed prefix bytes.
async fn recv_length<T: Stream>(stream: &mut T) -> Result<(usize, usize), Error> {
    let mut decoder = Decoder::<u32>::new();

    loop {
        // Use buffered prefix bytes before requesting another byte from the stream.
        let peeked = {
            let peeked = stream.peek(MAX_U32_VARINT_SIZE);
            for (i, byte) in peeked.iter().enumerate() {
                match decoder.feed(*byte) {
                    Ok(Some(len)) => return Ok((Widen::<usize>::widen(len), i + 1)),
                    Ok(None) => continue,
                    Err(_) => return Err(Error::InvalidVarint),
                }
            }
            peeked.len()
        };

        // Consume the peeked bytes already fed to the decoder and request one more byte to make
        // progress.
        let mut buf = stream.recv(peeked + 1).await.map_err(Error::RecvFailed)?;
        buf.advance(peeked);
        match decoder.feed(buf.get_u8()) {
            Ok(Some(len)) => return Ok((Widen::<usize>::widen(len), 0)),
            Ok(None) => {}
            Err(_) => return Err(Error::InvalidVarint),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        BufMut, Error as RuntimeError, IoBufMut, Runner, Spawner, Supervisor as _, deterministic,
        mocks,
    };
    use futures::FutureExt as _;
    use rand::RngExt as _;
    use std::time::Duration;

    const MAX_MESSAGE_SIZE: u32 = 1024;

    /// Records receive request sizes while preserving the mock stream's buffering behavior.
    struct RecordingStream {
        inner: mocks::Stream,
        /// Requested byte counts, including reads that remain pending.
        recv_lengths: Vec<usize>,
    }

    impl Stream for RecordingStream {
        async fn recv(&mut self, len: usize) -> Result<IoBufs, RuntimeError> {
            self.recv_lengths.push(len);
            self.inner.recv(len).await
        }

        fn peek(&self, max_len: usize) -> &[u8] {
            self.inner.peek(max_len)
        }
    }

    /// Reuses buffered prefix bytes after a refill and preserves the following frame.
    #[test]
    fn test_recv_frame_reuses_buffered_prefix() {
        for len in [0u32, 127, 128, 300, 16_383, 16_384] {
            deterministic::Runner::default().start(|_| async move {
                // Queue both frames with enough receive capacity to buffer them in the first read.
                let payload = vec![7; len as usize];
                let prefix_len = UInt(len).encode().len();
                let (mut sink, inner) =
                    mocks::Channel::init_with_buffer_size(prefix_len + payload.len() + 5);
                let mut stream = RecordingStream {
                    inner,
                    recv_lengths: Vec::new(),
                };
                send_frame(&mut sink, payload.clone(), u32::MAX)
                    .await
                    .unwrap();
                send_frame(&mut sink, &b"next"[..], u32::MAX).await.unwrap();
                assert!(stream.peek(MAX_U32_VARINT_SIZE).is_empty());

                // Only the first prefix byte needs its own read. The rest accompanies the payload.
                let received = recv_frame(&mut stream, u32::MAX).await.unwrap();
                assert_eq!(received.coalesce(), payload.as_slice());
                assert_eq!(stream.recv_lengths, [1, prefix_len - 1 + payload.len()]);

                // The next frame is already buffered and must arrive intact in a single read.
                stream.recv_lengths.clear();
                let received = recv_frame(&mut stream, u32::MAX).await.unwrap();
                assert_eq!(received.coalesce(), b"next");
                assert_eq!(stream.recv_lengths, [5]);
            });
        }
    }

    /// Decodes one- through five-byte prefixes across varying refill boundaries.
    #[test]
    fn test_recv_length_across_refills() {
        for len in [0u32, 127, 128, 300, 16_384, 1 << 21, 0x1234_5678, u32::MAX] {
            for buffer_size in 0..=MAX_U32_VARINT_SIZE {
                deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
                    // Send concurrently so prefixes larger than the channel capacity can progress.
                    let (mut sink, mut stream) = mocks::Channel::init_with_buffer_size(buffer_size);
                    let prefix = UInt(len).encode();
                    let sender = context.child("sender").spawn(|_| async move {
                        sink.send(prefix).await.unwrap();
                    });

                    // The decoded length must survive refills. Consume any prefix still buffered.
                    let (decoded, skip) = recv_length(&mut stream).await.unwrap();
                    assert_eq!(decoded, len as usize);
                    stream.recv(skip).await.unwrap();
                    sender.await.unwrap();
                });
            }
        }
    }

    /// Accepts the largest u32 frame length without overflowing receive requests.
    #[test]
    fn test_recv_frame_max_length() {
        for buffered in [true, false] {
            deterministic::Runner::default().start(|_| async move {
                let (mut sink, inner) = mocks::Channel::init();
                let mut stream = RecordingStream {
                    inner,
                    recv_lengths: Vec::new(),
                };

                // Queue only the prefix, optionally making it visible to peek before the first read.
                sink.send(UInt(u32::MAX).encode()).await.unwrap();
                if buffered {
                    stream.inner.recv(0).await.unwrap();
                }

                // Keep the sink open so the body stays pending without allocating its declared length.
                assert!(recv_frame(&mut stream, u32::MAX).now_or_never().is_none());
                let requested: u64 = stream.recv_lengths.iter().map(|&len| len as u64).sum();
                assert_eq!(requested, u64::from(u32::MAX) + MAX_U32_VARINT_SIZE as u64);
            });
        }
    }

    #[test]
    fn test_send_recv_at_max_message_size() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE as usize];
            context.fill(&mut buf);

            let result = send_frame(&mut sink, buf.to_vec(), MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());

            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), buf.len());
            assert_eq!(data.coalesce(), buf);
        });
    }

    #[test]
    fn test_send_recv_multiple() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut buf1 = [0u8; MAX_MESSAGE_SIZE as usize];
            let mut buf2 = [0u8; (MAX_MESSAGE_SIZE as usize) / 2];
            context.fill(&mut buf1);
            context.fill(&mut buf2);

            // Send two messages of different sizes
            let result = send_frame(&mut sink, buf1.to_vec(), MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());
            let result = send_frame(&mut sink, buf2.to_vec(), MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());

            // Read both messages in order
            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), buf1.len());
            assert_eq!(data.coalesce(), buf1);
            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), buf2.len());
            assert_eq!(data.coalesce(), buf2);
        });
    }

    #[test]
    fn test_send_frame() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE as usize];
            context.fill(&mut buf);

            let result = send_frame(&mut sink, buf.to_vec(), MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());

            // Do the reading manually without using recv_frame
            // 1024 (MAX_MESSAGE_SIZE) encodes as varint: [0x80, 0x08] (2 bytes)
            let read = stream.recv(2).await.unwrap();
            assert_eq!(read.coalesce(), &[0x80, 0x08]); // 1024 as varint
            let read = stream.recv(MAX_MESSAGE_SIZE as usize).await.unwrap();
            assert_eq!(read.coalesce(), buf);
        });
    }

    #[test]
    fn test_send_frame_too_large() {
        let (mut sink, _) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE as usize];
            context.fill(&mut buf);

            let result = send_frame(&mut sink, buf.to_vec(), MAX_MESSAGE_SIZE - 1).await;
            assert!(
                matches!(&result, Err(Error::SendTooLarge(n)) if *n == MAX_MESSAGE_SIZE as usize)
            );
        });
    }

    #[test]
    fn test_read_frame() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Do the writing manually without using send_frame
            let mut msg = [0u8; MAX_MESSAGE_SIZE as usize];
            context.fill(&mut msg);

            // 1024 (MAX_MESSAGE_SIZE) encodes as varint: [0x80, 0x08]
            let mut buf = IoBufMut::with_capacity(2 + msg.len());
            buf.put_u8(0x80);
            buf.put_u8(0x08);
            buf.put_slice(&msg);
            sink.send(buf.freeze()).await.unwrap();

            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), MAX_MESSAGE_SIZE as usize);
            assert_eq!(data.coalesce(), msg);
        });
    }

    #[test]
    fn test_read_frame_too_large() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Manually insert a frame that gives MAX_MESSAGE_SIZE as the size
            // 1024 (MAX_MESSAGE_SIZE) encodes as varint: [0x80, 0x08]
            let mut buf = IoBufMut::with_capacity(2);
            buf.put_u8(0x80);
            buf.put_u8(0x08);
            sink.send(buf.freeze()).await.unwrap();

            let result = recv_frame(&mut stream, MAX_MESSAGE_SIZE - 1).await;
            assert!(
                matches!(&result, Err(Error::RecvTooLarge(n)) if *n == MAX_MESSAGE_SIZE as usize)
            );
        });
    }

    #[test]
    fn test_recv_frame_incomplete_varint() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Send incomplete varint (continuation bit set but no following byte)
            let mut buf = IoBufMut::with_capacity(1);
            buf.put_u8(0x80); // Continuation bit set, expects more bytes

            sink.send(buf.freeze()).await.unwrap();
            drop(sink); // Close the sink to simulate a closed stream

            // Expect an error because varint is incomplete
            let result = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await;
            assert!(matches!(&result, Err(Error::RecvFailed(_))));
        });
    }

    #[test]
    fn test_recv_frame_invalid_varint_overflow() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Send a varint that overflows u32 (more than 5 bytes with continuation bits)
            let mut buf = IoBufMut::with_capacity(6);
            buf.put_u8(0xFF); // 7 bits + continue
            buf.put_u8(0xFF); // 7 bits + continue
            buf.put_u8(0xFF); // 7 bits + continue
            buf.put_u8(0xFF); // 7 bits + continue
            buf.put_u8(0xFF); // 5th byte with overflow bits set + continue
            buf.put_u8(0x01); // 6th byte

            sink.send(buf.freeze()).await.unwrap();

            // Expect an error because varint overflows u32
            let result = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await;
            assert!(matches!(&result, Err(Error::InvalidVarint)));
        });
    }

    #[test]
    fn test_recv_frame_peek_paths() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // 300 encodes as [0xAC, 0x02] (2-byte varint)
            let mut payload = vec![0u8; 300];
            context.fill(&mut payload[..]);

            // Fast path: peek returns complete varint
            let (mut sink, mut stream) = mocks::Channel::init();
            send_frame(&mut sink, payload.clone(), MAX_MESSAGE_SIZE)
                .await
                .unwrap();
            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.coalesce(), &payload[..]);

            // Slow path: peek returns empty (buffer_size=0 means send always
            // blocks, so send and recv must run concurrently).
            let (mut sink, mut stream) = mocks::Channel::init_with_buffer_size(0);
            let payload2 = payload.clone();
            let send_handle = context.child("sender_empty_peek").spawn(|_| async move {
                send_frame(&mut sink, payload2, MAX_MESSAGE_SIZE)
                    .await
                    .unwrap();
            });
            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.coalesce(), &payload[..]);
            send_handle.await.unwrap();

            // Slow path: peek returns partial varint
            let (mut sink, mut stream) = mocks::Channel::init_with_buffer_size(1);
            let payload2 = payload.clone();
            let send_handle = context.child("sender_partial_peek").spawn(|_| async move {
                send_frame(&mut sink, payload2, MAX_MESSAGE_SIZE)
                    .await
                    .unwrap();
            });
            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.coalesce(), &payload[..]);
            send_handle.await.unwrap();
        });
    }
}
