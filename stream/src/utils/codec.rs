use crate::Error;
use bytes::{BufMut as _, Bytes, BytesMut};
use commonware_runtime::{Sink, Stream};

/// Sends data to the sink with a 4-byte length prefix.
/// Returns an error if the message is too large or the stream is closed.
pub async fn send_frame<S: Sink>(
    sink: &mut S,
    buf: &[u8],
    max_message_size: usize,
) -> Result<(), Error> {
    // Validate frame size
    let n = buf.len();
    if n == 0 {
        return Err(Error::SendZeroSize);
    }
    if n > max_message_size {
        return Err(Error::SendTooLarge(n));
    }

    // Prefix `buf` with its length and send it
    let mut prefixed_buf = BytesMut::with_capacity(4 + buf.len());
    let len: u32 = n.try_into().map_err(|_| Error::SendTooLarge(n))?;
    prefixed_buf.put_u32(len);
    prefixed_buf.extend_from_slice(buf);
    sink.send(prefixed_buf).await.map_err(Error::SendFailed)
}

/// Receives data from the stream with a 4-byte length prefix.
/// Returns an error if the message is too large or the stream is closed.
pub async fn recv_frame<T: Stream>(
    stream: &mut T,
    max_message_size: usize,
) -> Result<Bytes, Error> {
    // Read the first 4 bytes to get the length of the message
    let len_buf = stream.recv(vec![0; 4]).await.map_err(Error::RecvFailed)?;

    // Validate frame size
    let len = u32::from_be_bytes(len_buf.as_ref()[..4].try_into().unwrap()) as usize;
    if len > max_message_size {
        return Err(Error::RecvTooLarge(len));
    }
    if len == 0 {
        return Err(Error::StreamClosed);
    }

    // Read the rest of the message
    let read = stream.recv(vec![0; len]).await.map_err(Error::RecvFailed)?;
    Ok(read.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, mocks, Runner};
    use rand::Rng;

    const MAX_MESSAGE_SIZE: usize = 1024;

    #[test]
    fn test_send_recv_at_max_message_size() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE];
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
            let mut buf1 = [0u8; MAX_MESSAGE_SIZE];
            let mut buf2 = [0u8; MAX_MESSAGE_SIZE / 2];
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
            let mut buf = [0u8; MAX_MESSAGE_SIZE];
            context.fill(&mut buf);

            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());

            // Do the reading manually without using recv_frame
            let read = stream.recv(vec![0; 4]).await.unwrap();
            assert_eq!(read.as_ref(), (buf.len() as u32).to_be_bytes());
            let read = stream.recv(vec![0; MAX_MESSAGE_SIZE]).await.unwrap();
            assert_eq!(read.as_ref(), buf);
        });
    }

    #[test]
    fn test_send_frame_too_large() {
        const MAX_MESSAGE_SIZE: usize = 1024;
        let (mut sink, _) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE];
            context.fill(&mut buf);

            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE - 1).await;
            assert!(matches!(&result, Err(Error::SendTooLarge(n)) if *n == MAX_MESSAGE_SIZE));
        });
    }

    #[test]
    fn test_send_zero_size() {
        let (mut sink, _) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let buf = [];
            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE).await;
            assert!(matches!(&result, Err(Error::SendZeroSize)));
        });
    }

    #[test]
    fn test_read_frame() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Do the writing manually without using send_frame
            let mut msg = [0u8; MAX_MESSAGE_SIZE];
            context.fill(&mut msg);

            let mut buf = BytesMut::with_capacity(4 + msg.len());
            buf.put_u32(MAX_MESSAGE_SIZE as u32);
            buf.extend_from_slice(&msg);
            sink.send(buf).await.unwrap();

            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), MAX_MESSAGE_SIZE);
            assert_eq!(data, msg.as_ref());
        });
    }

    #[test]
    fn test_read_frame_too_large() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Manually insert a frame that gives MAX_MESSAGE_SIZE as the size
            let mut buf = BytesMut::with_capacity(4);
            buf.put_u32(MAX_MESSAGE_SIZE as u32);
            sink.send(buf).await.unwrap();

            let result = recv_frame(&mut stream, MAX_MESSAGE_SIZE - 1).await;
            assert!(matches!(&result, Err(Error::RecvTooLarge(n)) if *n == MAX_MESSAGE_SIZE));
        });
    }

    #[test]
    fn test_read_zero_size() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Manually insert a frame that gives zero as the size
            let mut buf = BytesMut::with_capacity(4);
            buf.put_u32(0);
            sink.send(buf).await.unwrap();

            let result = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await;
            assert!(matches!(&result, Err(Error::StreamClosed)));
        });
    }

    #[test]
    fn test_recv_frame_short_length_prefix() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Manually insert a frame with a short length prefix
            let mut buf = BytesMut::with_capacity(3);
            buf.put_u8(0x00);
            buf.put_u8(0x00);
            buf.put_u8(0x00);

            sink.send(buf).await.unwrap();
            drop(sink); // Close the sink to simulate a closed stream

            // Expect an error rather than a panic
            let result = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await;
            assert!(matches!(&result, Err(Error::RecvFailed(_))));
        });
    }
}
