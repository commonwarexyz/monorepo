use super::super::Error;
use bytes::Bytes;
use commonware_runtime::{Sink, Stream};

// TODO: Test this and write a suitable comment.
const ENCRYPTION_TAG_PADDING: usize = 16;

// Sends data with a 4-byte length prefix.
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
    let len: u32 = n.try_into()
        .map_err(|_| Error::SendTooLarge(n))?;

    // Send the length of the message
    let f: [u8; 4] = len.to_be_bytes();
    sink.send(&f)
        .await
        .map_err(|_| Error::SendFailed)?;

    // Send the rest of the message
    sink.send(buf)
        .await
        .map_err(|_| Error::SendFailed)?;

    Ok(())
}

// Receives data with a 4-byte length prefix.
pub async fn recv_frame<T: Stream>(
    stream: &mut T,
    max_message_size: usize,
) -> Result<Bytes, Error> {
    // Read the first 4 bytes to get the length of the message
    let mut buf = [0u8; 4];
    stream.recv(&mut buf)
        .await
        .map_err(|_| Error::StreamClosed)?;

    // Validate frame size
    let len = u32::from_be_bytes(buf) as usize;
    if len > max_message_size + ENCRYPTION_TAG_PADDING {
        return Err(Error::ReadTooLarge(len));
    }
    if len == 0 {
        return Err(Error::StreamClosed);
    }

    // Read the rest of the message
    let mut buf = vec![0u8; len];
    stream.recv(&mut buf)
        .await
        .map_err(|_| Error::ReadFailed)?;

    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        Runner,
        deterministic::Executor,
        mocks::MockSink,
    };

    #[test]
    fn test_send_frame() {
        const MAX_MESSAGE_SIZE: usize = 1024;
        let (mut sink, _) = MockSink::new();
        // buffer is a random byte array
        let buf = [0u8; 1024];
        buf.iter().for_each(|&byte| {
            assert_eq!(byte, 0);
        });

        let (executor, _runtime, _) = Executor::default();
        executor.start(async move {
            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());
        });
    }
}
