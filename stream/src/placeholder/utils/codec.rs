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
        .map_err(|_| Error::RecvFailed)?;

    // Validate frame size
    let len = u32::from_be_bytes(buf) as usize;
    if len > max_message_size {
        return Err(Error::RecvTooLarge(len));
    }
    if len == 0 {
        return Err(Error::StreamClosed);
    }

    // Read the rest of the message
    let mut buf = vec![0u8; len];
    stream.recv(&mut buf).await
        .map_err(|_| Error::RecvFailed)?;

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

    const MAX_MESSAGE_SIZE: usize = 1024;

    #[test]
    fn test_send_recv_at_max_message_size() {
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
    fn test_send_recv_multiple() {
        let (mut sink, mut stream) = mocks::new();

        let (executor, mut runtime, _) = Executor::default();
        executor.start(async move {
            let mut buf1 = [0u8; MAX_MESSAGE_SIZE];
            let mut buf2 = [0u8; MAX_MESSAGE_SIZE / 2];
            runtime.fill(&mut buf1);
            runtime.fill(&mut buf2);

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
        let (mut sink, mut stream) = mocks::new();

        let (executor, mut runtime, _) = Executor::default();
        executor.start(async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE];
            runtime.fill(&mut buf);

            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE).await;
            assert!(result.is_ok());

            // Do the reading manually without using recv_frame
            let mut b = [0u8; 4];
            stream.recv(&mut b).await.unwrap();
            assert_eq!(b, (buf.len() as u32).to_be_bytes());
            let mut b = [0u8; MAX_MESSAGE_SIZE];
            stream.recv(&mut b).await.unwrap();
            assert_eq!(b, buf);
        });
    }

    #[test]
    fn test_send_frame_too_large() {
        const MAX_MESSAGE_SIZE: usize = 1024;
        let (mut sink, _) = mocks::new();

        let (executor, mut runtime, _) = Executor::default();
        executor.start(async move {
            let mut buf = [0u8; MAX_MESSAGE_SIZE];
            runtime.fill(&mut buf);

            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE - 1).await;
            assert!(matches!(&result, Err(Error::SendTooLarge(n)) if *n == MAX_MESSAGE_SIZE));
        });
    }

    #[test]
    fn test_send_zero_size() {
        let (mut sink, _) = mocks::new();

        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let buf = [];
            let result = send_frame(&mut sink, &buf, MAX_MESSAGE_SIZE).await;
            assert!(matches!(&result, Err(Error::SendZeroSize)));
        });
    }

    #[test]
    fn test_read_frame() {
        let (mut sink, mut stream) = mocks::new();

        let (executor, mut runtime, _) = Executor::default();
        executor.start(async move {

            // Do the writing manually without using send_frame
            let mut buf = [0u8; MAX_MESSAGE_SIZE];
            runtime.fill(&mut buf);
            sink.send(&(MAX_MESSAGE_SIZE as u32).to_be_bytes()).await.unwrap();
            sink.send(&buf).await.unwrap();

            let data = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await.unwrap();
            assert_eq!(data.len(), buf.len());
            assert_eq!(data, Bytes::from(buf.to_vec()));
        });
    }

    #[test]
    fn test_read_frame_too_large() {
        let (mut sink, mut stream) = mocks::new();

        let (executor, _, _) = Executor::default();
        executor.start(async move {
            // Manually insert a frame that gives MAX_MESSAGE_SIZE as the size
            sink.send(&(MAX_MESSAGE_SIZE as u32).to_be_bytes()).await.unwrap();

            let result = recv_frame(&mut stream, MAX_MESSAGE_SIZE - 1).await;
            assert!(matches!(&result, Err(Error::RecvTooLarge(n)) if *n == MAX_MESSAGE_SIZE));
        });
    }

    #[test]
    fn test_read_zero_size() {
        let (mut sink, mut stream) = mocks::new();

        let (executor, _, _) = Executor::default();
        executor.start(async move {
            // Manually insert a frame that gives zero as the size
            sink.send(&(0u32).to_be_bytes()).await.unwrap();

            let result = recv_frame(&mut stream, MAX_MESSAGE_SIZE).await;
            assert!(matches!(&result, Err(Error::StreamClosed)));
        });
    }
}
