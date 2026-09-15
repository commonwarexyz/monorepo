use bytes::Bytes;
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_utils::Span;

/// Represents a message sent between peers.
#[derive(Clone, Debug, PartialEq, Eq, Write, EncodeSize, Read)]
pub struct Message<Key: Span> {
    /// Unique identifier for the message.
    /// Responses should have the same ID as the request they are responding to.
    pub id: u64,

    /// Payload is the data being sent.
    pub payload: Payload<Key>,
}

#[cfg(feature = "arbitrary")]
impl<Key: Span> arbitrary::Arbitrary<'_> for Message<Key>
where
    Key: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let id = u.arbitrary::<u64>()?;
        let payload = u.arbitrary::<Payload<Key>>()?;
        Ok(Self { id, payload })
    }
}

/// Represents the contents of a message sent between peers.
#[derive(Clone, Debug, PartialEq, Eq, Write, EncodeSize, Read)]
#[codec(invalid_tag = { Error::Invalid("Payload", "Invalid payload type") })]
pub enum Payload<Key: Span> {
    // Request is a request for a response.
    Request(Key),

    // Response is a response to a request.
    // The P2P connection bounds the input buffer, so an unbounded codec
    // configuration cannot cause Bytes to allocate beyond the message.
    Response(#[codec(cfg = &(..).into())] Bytes),

    // A response that indicates an unspecified error.
    //
    // This allows the requester to handle the error more quickly than timing out.
    Error,
}

#[cfg(feature = "arbitrary")]
impl<Key: Span> arbitrary::Arbitrary<'_> for Payload<Key>
where
    Key: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => {
                let key = u.arbitrary::<Key>()?;
                Ok(Self::Request(key))
            }
            1 => {
                let size = u.int_in_range(0..=1024)?;
                let bytes = u.bytes(size)?;
                Ok(Self::Response(Bytes::from(bytes.to_vec())))
            }
            2 => Ok(Self::Error),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::mocks::Key as MockKey;
    use bytes::Buf as _;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_runtime::{BufferPooler, Runner, deterministic, iobuf::EncodeExt};

    #[test]
    fn test_codec_request() {
        let key = MockKey(123u8);
        let payload = Payload::Request(key);
        let original = Message { id: 1234, payload };
        let encoded = original.encode();
        let decoded = Message::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_response() {
        let payload = Payload::<MockKey>::Response(Bytes::from("Hello, world!"));
        let original = Message { id: 4321, payload };
        let encoded = original.encode();
        let decoded = Message::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_error() {
        let payload = Payload::<MockKey>::Error;
        let original = Message { id: 255, payload };
        let encoded = original.encode();
        let decoded = Message::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_message_encode_with_pool_matches_encode() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pool = context.network_buffer_pool();

            let msg = Message {
                id: 42,
                payload: Payload::<MockKey>::Response(Bytes::from("hello world")),
            };

            let encoded = msg.encode();
            let mut encoded_pool = msg.encode_with_pool(pool);
            let mut encoded_pool_bytes = vec![0u8; encoded_pool.remaining()];
            encoded_pool.copy_to_slice(&mut encoded_pool_bytes);
            assert_eq!(encoded_pool_bytes, encoded.as_ref());
        });
    }

    #[test]
    fn test_payload_response_encode_with_pool_matches_encode() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pool = context.network_buffer_pool();

            let payload = Payload::<MockKey>::Response(Bytes::from("response data"));

            let encoded = payload.encode();
            let mut encoded_pool = payload.encode_with_pool(pool);
            let mut encoded_pool_bytes = vec![0u8; encoded_pool.remaining()];
            encoded_pool.copy_to_slice(&mut encoded_pool_bytes);
            assert_eq!(encoded_pool_bytes, encoded.as_ref());
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Message<u8>>,
            CodecConformance<Payload<u8>>,
        }
    }
}
