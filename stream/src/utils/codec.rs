use crate::encrypted::Error;
use commonware_codec::{
    varint::{Decoder, UInt, MAX_U32_VARINT_SIZE},
    Encode, EncodeSize,
};
use commonware_runtime::{Buf, IoBuf, IoBufs, Sink, Stream};

/// Sends a frame with a varint length prefix, delegating frame assembly to the caller.
///
/// The `assemble` closure receives the varint prefix and must combine it with
/// the payload. This allows callers to choose between:
/// - Chunked: prepend the prefix as a separate buffer
/// - Contiguous: write the prefix directly into a pre-allocated buffer
///
/// Returns an error if the message is too large or the sink is closed.
pub(crate) async fn send_frame_with<S: Sink>(
    sink: &mut S,
    payload_len: usize,
    max_message_size: u32,
    assemble: impl FnOnce(UInt<u32>) -> Result<IoBufs, Error>,
) -> Result<(), Error> {
    // Validate frame size
    if payload_len > max_message_size as usize {
        return Err(Error::SendTooLarge(payload_len));
    }
    let prefix = UInt(payload_len as u32);
    let expected_frame_len = prefix.encode_size() + payload_len;

    let frame = assemble(prefix)?;
    assert_eq!(
        frame.remaining(),
        expected_frame_len,
        "assembled frame should be exactly the prefix and the payload"
    );
    sink.send(frame).await.map_err(Error::SendFailed)
}

/// Sends data to the sink with a varint length prefix.
///
/// The varint length prefix is prepended to the buffer(s), which results in a
/// chunked `IoBufs`.
///
/// Returns an error if the message is too large or the sink is closed.
pub async fn send_frame<S: Sink>(
    sink: &mut S,
    buf: impl Into<IoBufs> + Send,
    max_message_size: u32,
) -> Result<(), Error> {
    let mut bufs = buf.into();

    send_frame_with(sink, bufs.remaining(), max_message_size, |prefix| {
        // Prepend varint-encoded length
        bufs.prepend(IoBuf::from(prefix.encode()));
        Ok(bufs)
    })
    .await
}

/// Receives data from the stream with a varint length prefix.
/// Returns an error if the message is too large, the varint is invalid, or the
/// stream is closed.
pub async fn recv_frame<T: Stream>(stream: &mut T, max_message_size: u32) -> Result<IoBufs, Error> {
    let (len, skip) = recv_length(stream).await?;
    if len > max_message_size {
        return Err(Error::RecvTooLarge(len as usize));
    }

    stream
        .recv(skip as u64 + len as u64)
        .await
        .map(|mut bufs| {
            bufs.advance(skip as usize);
            bufs
        })
        .map_err(Error::RecvFailed)
}

/// Receives and decodes the varint length prefix from the stream.
/// Returns (payload_len, bytes_to_skip) where bytes_to_skip is:
/// - varint_len if decoded from peek buffer (bytes not yet consumed)
/// - 0 if decoded via recv (bytes already consumed)
async fn recv_length<T: Stream>(stream: &mut T) -> Result<(u32, u32), Error> {
    let mut decoder = Decoder::<u32>::new();

    // Fast path: decode from peek buffer without blocking
    let peeked = {
        let peeked = stream.peek(MAX_U32_VARINT_SIZE as u64);
        for (i, byte) in peeked.iter().enumerate() {
            match decoder.feed(*byte) {
                Ok(Some(len)) => return Ok((len, i as u32 + 1)),
                Ok(None) => continue,
                Err(_) => return Err(Error::InvalidVarint),
            }
        }
        peeked.len()
    };

    // Slow path: fetch bytes one at a time (skipping already-decoded peek bytes)
    let mut buf = stream
        .recv(peeked as u64 + 1)
        .await
        .map_err(Error::RecvFailed)?;
    buf.advance(peeked);

    loop {
        match decoder.feed(buf.get_u8()) {
            Ok(Some(len)) => return Ok((len, 0)),
            Ok(None) => {}
            Err(_) => return Err(Error::InvalidVarint),
        }
        buf = stream.recv(1).await.map_err(Error::RecvFailed)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, mocks, BufMut, IoBufMut, Runner};
    use rand::Rng;

    const MAX_MESSAGE_SIZE: u32 = 1024;

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
            let read = stream.recv(MAX_MESSAGE_SIZE as u64).await.unwrap();
            assert_eq!(read.coalesce(), buf);
        });
    }

    #[test]
    fn test_send_frame_with_closure_error() {
        let (mut sink, _) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let result = send_frame_with(&mut sink, 10, MAX_MESSAGE_SIZE, |_prefix| {
                Err(Error::HandshakeError(
                    commonware_cryptography::handshake::Error::EncryptionFailed,
                ))
            })
            .await;
            assert!(matches!(&result, Err(Error::HandshakeError(_))));
        });
    }

    #[test]
    fn test_send_frame_with_too_large() {
        let (mut sink, _) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let result = send_frame_with(
                &mut sink,
                MAX_MESSAGE_SIZE as usize + 1,
                MAX_MESSAGE_SIZE,
                |_prefix| unreachable!(),
            )
            .await;
            assert!(
                matches!(&result, Err(Error::SendTooLarge(n)) if *n == MAX_MESSAGE_SIZE as usize + 1)
            );
        });
    }

    #[test]
    #[should_panic(expected = "assembled frame should be exactly the prefix and the payload")]
    fn test_send_frame_with_incorrect_encoder_panics() {
        let (mut sink, _) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let _ = send_frame_with(&mut sink, 10, MAX_MESSAGE_SIZE, |prefix| {
                // Intentionally return one byte less payload than declared.
                let mut frame = IoBufMut::with_capacity(prefix.encode().len() + 9);
                frame.put_slice(&prefix.encode());
                frame.put_slice(&[0u8; 9]);
                Ok(frame.freeze().into())
            })
            .await;
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

            // Slow path: peek returns empty
            let (mut sink, mut stream) = mocks::Channel::init_with_read_buffer_size(0);
            send_frame(&mut sink, payload.clone(), MAX_MESSAGE_SIZE)
                .await
                .unwrap();
            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.coalesce(), &payload[..]);

            // Slow path: peek returns partial varint
            let (mut sink, mut stream) = mocks::Channel::init_with_read_buffer_size(1);
            send_frame(&mut sink, payload.clone(), MAX_MESSAGE_SIZE)
                .await
                .unwrap();
            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.coalesce(), &payload[..]);
        });
    }
}
