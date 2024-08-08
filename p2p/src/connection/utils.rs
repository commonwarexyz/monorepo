use chacha20poly1305::Nonce;
use tokio_util::codec::LengthDelimitedCodec;

pub fn codec(max_frame_len: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_type::<u32>()
        .max_frame_length(max_frame_len)
        .new_codec()
}

pub fn nonce_bytes(nonce: u64, dialer: bool) -> Nonce {
    let mut nonce_bytes = Nonce::default();
    nonce_bytes[..8].copy_from_slice(&nonce.to_be_bytes());
    if dialer {
        nonce_bytes[0] = 1;
    }
    nonce_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::SinkExt;
    use std::io::Cursor;
    use tokio_util::codec::Framed;

    #[tokio::test]
    async fn test_codec_invalid_frame_len() {
        let max_frame_len = 10;
        let codec = codec(max_frame_len);

        // Create a stream
        let mut framed = Framed::new(Cursor::new(Vec::new()), codec);

        // Create a message larger than the max_frame_len
        let message = vec![0; max_frame_len + 1];
        let message = Bytes::from(message);

        // Encode the message
        let result = framed.send(message).await;

        // Ensure that encoding fails due to exceeding max_frame_len
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_codec_valid_frame_len() {
        let max_frame_len = 10;
        let codec = codec(max_frame_len);

        // Create a stream
        let mut framed = Framed::new(Cursor::new(Vec::new()), codec);

        // Create a message larger than the max_frame_len
        let message = vec![0; max_frame_len];
        let message = Bytes::from(message);

        // Encode the message
        let result = framed.send(message).await;

        // Ensure that encoding fails due to exceeding max_frame_len
        assert!(result.is_ok());
    }
}
