use crate::Error;
use bytes::{Bytes, BytesMut};
use commonware_codec::{
    varint::{Decoder, UInt},
    EncodeSize as _, Write as _,
};
use commonware_runtime::{Sink, Stream};
use commonware_utils::StableBuf;

/// Sends data to the sink with a varint length prefix.
/// Returns an error if the message is too large or the stream is closed.
pub async fn send_frame<S: Sink>(
    sink: &mut S,
    buf: &[u8],
    max_message_size: u32,
) -> Result<(), Error> {
    // Validate frame size
    let n = buf.len();
    if n > max_message_size as usize {
        return Err(Error::SendTooLarge(n));
    }

    // Prefix `buf` with its varint-encoded length and send it
    let len = UInt(n as u32);
    let mut prefixed_buf = BytesMut::with_capacity(len.encode_size() + buf.len());
    len.write(&mut prefixed_buf);
    prefixed_buf.extend_from_slice(buf);
    sink.send(prefixed_buf).await.map_err(Error::SendFailed)
}

/// Receives data from the stream with a varint length prefix.
/// Returns an error if the message is too large, the varint is invalid, or the
/// stream is closed.
pub async fn recv_frame<T: Stream>(stream: &mut T, max_message_size: u32) -> Result<Bytes, Error> {
    // Read and decode the varint length prefix byte-by-byte
    let mut decoder = Decoder::<u32>::new();
    let mut buf = StableBuf::from(vec![0u8; 1]);
    let len = loop {
        buf = stream.recv(buf).await.map_err(Error::RecvFailed)?;
        match decoder.feed(buf[0]) {
            Ok(Some(len)) => break len as usize,
            Ok(None) => continue,
            Err(_) => return Err(Error::InvalidVarint),
        }
    };

    // Validate frame size
    if len > max_message_size as usize {
        return Err(Error::RecvTooLarge(len));
    }

    // Read the rest of the message
    let read = stream.recv(vec![0; len]).await.map_err(Error::RecvFailed)?;
    Ok(read.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use commonware_runtime::{deterministic, mocks, Runner};
    use rand::Rng;

    const MAX_MESSAGE_SIZE: u32 = 1024;

    #[test]
    fn test_send_recv_at_max_message_size() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE as usize];
            context.fill(&mut buf);

            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());

            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), buf.len());
            assert_eq!(data, Bytes::from(buf.to_vec()));
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
            let result = send_frame(&mut sink, &buf1, MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());
            let result = send_frame(&mut sink, &buf2, MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());

            // Read both messages in order
            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), buf1.len());
            assert_eq!(data, Bytes::from(buf1.to_vec()));
            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), buf2.len());
            assert_eq!(data, Bytes::from(buf2.to_vec()));
        });
    }

    #[test]
    fn test_send_frame() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE as usize];
            context.fill(&mut buf);

            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());

            // Do the reading manually without using recv_frame
            // 1024 (MAX_MESSAGE_SIZE) encodes as varint: [0x80, 0x08] (2 bytes)
            let read = stream.recv(vec![0; 2]).await.unwrap();
            assert_eq!(read.as_ref(), &[0x80, 0x08]); // 1024 as varint
            let read = stream
                .recv(vec![0; MAX_MESSAGE_SIZE as usize])
                .await
                .unwrap();
            assert_eq!(read.as_ref(), buf);
        });
    }

    #[test]
    fn test_send_frame_too_large() {
        let (mut sink, _) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE as usize];
            context.fill(&mut buf);

            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE - 1).await;
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
            let mut buf = BytesMut::with_capacity(2 + msg.len());
            buf.put_u8(0x80);
            buf.put_u8(0x08);
            buf.extend_from_slice(&msg);
            sink.send(buf).await.unwrap();

            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), MAX_MESSAGE_SIZE as usize);
            assert_eq!(data, msg.as_ref());
        });
    }

    #[test]
    fn test_read_frame_too_large() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Manually insert a frame that gives MAX_MESSAGE_SIZE as the size
            // 1024 (MAX_MESSAGE_SIZE) encodes as varint: [0x80, 0x08]
            let mut buf = BytesMut::with_capacity(2);
            buf.put_u8(0x80);
            buf.put_u8(0x08);
            sink.send(buf).await.unwrap();

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
            let mut buf = BytesMut::with_capacity(1);
            buf.put_u8(0x80); // Continuation bit set, expects more bytes

            sink.send(buf).await.unwrap();
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
            let mut buf = BytesMut::with_capacity(6);
            buf.put_u8(0xFF); // 7 bits + continue
            buf.put_u8(0xFF); // 7 bits + continue
            buf.put_u8(0xFF); // 7 bits + continue
            buf.put_u8(0xFF); // 7 bits + continue
            buf.put_u8(0xFF); // 5th byte with overflow bits set + continue
            buf.put_u8(0x01); // 6th byte

            sink.send(buf).await.unwrap();

            // Expect an error because varint overflows u32
            let result = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await;
            assert!(matches!(&result, Err(Error::InvalidVarint)));
        });
    }
}
