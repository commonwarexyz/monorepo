use super::super::Error;
use bytes::Bytes;
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
    let len: u32 = n.try_into()
        .map_err(|_| Error::SendTooLarge(n))?;

    // Send the length of the message
    let f: [u8; 4] = len.to_be_bytes();
    sink.send(&f).await
        .map_err(|_| Error::SendFailed)?;

    // Send the rest of the message
    sink.send(buf).await
        .map_err(|_| Error::SendFailed)?;

    Ok(())
}

/// Receives data from the stream with a 4-byte length prefix.
/// Returns an error if the message is too large or the stream is closed.
pub async fn recv_frame<T: Stream>(
    stream: &mut T,
    max_message_size: usize,
) -> Result<Bytes, Error> {
    // Read the first 4 bytes to get the length of the message
    let mut buf = [0u8; 4];
    stream.recv(&mut buf).await
        .map_err(|_| Error::StreamClosed)?;

    // Validate frame size
    let len = u32::from_be_bytes(buf) as usize;
    if len > max_message_size {
        return Err(Error::ReadTooLarge(len));
    }
    if len == 0 {
        return Err(Error::StreamClosed);
    }

    // Read the rest of the message
    let mut buf = vec![0u8; len];
    stream.recv(&mut buf).await
        .map_err(|_| Error::ReadFailed)?;

    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        Runner,
        deterministic::Executor,
        mocks,
    };
    use rand::Rng;

    #[test]
    fn test_send_recv_at_max_message_size() {
        const MAX_MESSAGE_SIZE: usize = 512;
        let (mut sink, mut stream) = mocks::new();

        let (executor, mut runtime, _) = Executor::default();
        executor.start(async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE];
            runtime.fill(&mut buf);

            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());

            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), buf.len());
            assert_eq!(data, Bytes::from(buf.to_vec()));
        });
    }

    #[test]
    fn test_send_frame() {
        const MAX_MESSAGE_SIZE: usize = 1024;
        let (mut sink, mut stream) = mocks::new();

        let (executor, mut runtime, _) = Executor::default();
        executor.start(async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE];
            runtime.fill(&mut buf);

            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());

            let mut b = [0u8; 4];
            stream.recv(&mut b).await.unwrap();
            assert_eq!(b, (buf.len() as u32).to_be_bytes());

            let mut b = [0u8; MAX_MESSAGE_SIZE];
            stream.recv(&mut b).await.unwrap();
            assert_eq!(b, buf);
        });
    }

    #[test]
    fn test_read_frame() {
        const MAX_MESSAGE_SIZE: usize = 1024;
        let (mut sink, mut stream) = mocks::new();

        let (executor, mut runtime, _) = Executor::default();
        executor.start(async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE];
            runtime.fill(&mut buf);

            let mut b = [0u8; 4];
            (buf.len() as u32).to_be_bytes().iter().enumerate().for_each(|(i, &byte)| {
                b[i] = byte;
            });
            sink.send(&b).await.unwrap();

            sink.send(&buf).await.unwrap();

            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), buf.len());
            assert_eq!(data, Bytes::from(buf.to_vec()));
        });
    }
}
