use chacha20poly1305::Nonce;
use tokio_util::codec::LengthDelimitedCodec;

pub fn codec(max_frame_len: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_type::<u32>()
        .max_frame_length(max_frame_len)
        .new_codec()
}

pub fn nonce_bytes(dialer: bool, iter: u16, seq: u64) -> Nonce {
    let mut nonce_bytes = Nonce::default();
    if dialer {
        nonce_bytes[0] = 0b10000000; // Set the first bit of the byte
    }
    nonce_bytes[2..4].copy_from_slice(&iter.to_be_bytes());
    nonce_bytes[4..].copy_from_slice(&seq.to_be_bytes());
    nonce_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_runtime::{deterministic::Executor, Runner};
    use futures::SinkExt;
    use std::{io::Cursor, time::Duration};
    use tokio_util::codec::Framed;

    #[test]
    fn test_codec_invalid_frame_len() {
        // Initalize runtime
        let (runner, _) = Executor::init(0, Duration::from_millis(1));
        runner.start(async move {
            // Create a stream
            let max_frame_len = 10;
            let codec = codec(max_frame_len);
            let mut framed = Framed::new(Cursor::new(Vec::new()), codec);

            // Create a message larger than the max_frame_len
            let message = vec![0; max_frame_len + 1];
            let message = Bytes::from(message);

            // Encode the message
            let result = framed.send(message).await;

            // Ensure that encoding fails due to exceeding max_frame_len
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_codec_valid_frame_len() {
        // Initialize runtime
        let (runner, _) = Executor::init(0, Duration::from_millis(1));
        runner.start(async move {
            // Create a stream
            let max_frame_len = 10;
            let codec = codec(max_frame_len);
            let mut framed = Framed::new(Cursor::new(Vec::new()), codec);

            // Create a message larger than the max_frame_len
            let message = vec![0; max_frame_len];
            let message = Bytes::from(message);

            // Encode the message
            let result = framed.send(message).await;

            // Ensure that encoding fails due to exceeding max_frame_len
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_nonce_bytes() {
        // Test case 1: dialer is true
        let nonce = nonce_bytes(true, 1, 1);
        assert_eq!(nonce[0], 0b10000000);
        assert_eq!(&nonce[2..4], &1u16.to_be_bytes());
        assert_eq!(&nonce[4..], &1u64.to_be_bytes());

        // Test case 2: dialer is false
        let nonce = nonce_bytes(false, 1, 1);
        assert_eq!(nonce[0], 0b00000000);
        assert_eq!(&nonce[2..4], &1u16.to_be_bytes());
        assert_eq!(&nonce[4..], &1u64.to_be_bytes());

        // Test case 3: different iter and seq values
        let nonce = nonce_bytes(true, 65535, 123456789);
        assert_eq!(nonce[0], 0b10000000);
        assert_eq!(&nonce[2..4], &65535u16.to_be_bytes());
        assert_eq!(&nonce[4..], &123456789u64.to_be_bytes());
    }
}
