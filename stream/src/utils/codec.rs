use crate::Error;
use commonware_codec::{
    varint::{Decoder, UInt},
    Encode,
};
use commonware_runtime::{Buf, IoBuf, IoBufs, Sink, Stream};

/// Sends data to the sink with a varint length prefix.
/// Returns an error if the message is too large or the stream is closed.
pub async fn send_frame<S: Sink>(
    sink: &mut S,
    buf: impl Into<IoBufs> + Send,
    max_message_size: u32,
) -> Result<(), Error> {
    let mut bufs = buf.into();

    // Validate frame size
    let n = bufs.remaining();
    if n > max_message_size as usize {
        return Err(Error::SendTooLarge(n));
    }

    // Prepend varint-encoded length
    let len = UInt(n as u32);
    bufs.prepend(IoBuf::from(len.encode()));
    sink.send(bufs).await.map_err(Error::SendFailed)
}

/// Receives data from the stream with a varint length prefix.
/// Returns an error if the message is too large, the varint is invalid, or the
/// stream is closed.
pub async fn recv_frame<T: Stream>(stream: &mut T, max_message_size: u32) -> Result<IoBufs, Error> {
    // Read and decode the varint length prefix byte-by-byte
    let mut decoder = Decoder::<u32>::new();
    let len = loop {
        let buf = stream.recv(1).await.map_err(Error::RecvFailed)?;
        match decoder.feed(buf.chunk()[0]) {
            Ok(Some(len)) => break len as usize,
            Ok(None) => continue,
            Err(_) => return Err(Error::InvalidVarint),
        }
    };
    if len > max_message_size as usize {
        return Err(Error::RecvTooLarge(len));
    }

    // Read the rest of the message
    stream.recv(len as u64).await.map_err(Error::RecvFailed)
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
            assert_eq!(data.coalesce().as_ref(), buf.as_ref());
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
            assert_eq!(data.coalesce().as_ref(), buf1.as_ref());
            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), buf2.len());
            assert_eq!(data.coalesce().as_ref(), buf2.as_ref());
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
            assert_eq!(read.coalesce().as_ref(), &[0x80, 0x08]); // 1024 as varint
            let read = stream.recv(MAX_MESSAGE_SIZE as u64).await.unwrap();
            assert_eq!(read.coalesce().as_ref(), buf.as_ref());
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
            assert_eq!(data.coalesce().as_ref(), msg.as_ref());
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
}
