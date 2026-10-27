use bytes::{BufMut, Bytes};
use commonware_codec::{
    Buf, BufsMut, EncodeSize, Error, FixedSize, MaxEncodeSize, Read, ReadExt, Write,
    varint::MAX_U32_VARINT_SIZE,
};
use commonware_utils::Span;

/// Number of bytes a request adds to the key it carries: an 8-byte request ID and a 1-byte tag.
///
/// An error carries no key and is exactly this size.
pub const REQUEST_OVERHEAD: usize = u64::SIZE + u8::SIZE;

/// Largest number of bytes a response adds to the value it carries: the request ID, the tag, and
/// a value-length varint of at most 5 bytes.
pub const MAX_RESPONSE_OVERHEAD: usize = REQUEST_OVERHEAD + MAX_U32_VARINT_SIZE;

/// Returns the largest encoded size of any message for keys of type `Key` and values of at most
/// `value` bytes, or `None` if `value` exceeds `u32::MAX` or the size overflows `usize`.
pub fn max_message_size<Key: MaxEncodeSize>(value: usize) -> Option<usize> {
    // A response's value-length varint encodes at most `u32::MAX`.
    u32::try_from(value).ok()?;

    // An error is a request without a key, so a request is always at least as wide.
    let request = Key::MAX_ENCODE_SIZE.checked_add(REQUEST_OVERHEAD)?;
    let response = value.checked_add(MAX_RESPONSE_OVERHEAD)?;
    Some(request.max(response))
}

/// Represents a message sent between peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message<Key: Span> {
    /// Unique identifier for the message.
    /// Responses should have the same ID as the request they are responding to.
    pub id: u64,

    /// Payload is the data being sent.
    pub payload: Payload<Key>,
}

impl<Key: Span> Write for Message<Key> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.id);
        self.payload.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.id.write(buf);
        self.payload.write_bufs(buf);
    }
}

impl<Key: Span> EncodeSize for Message<Key> {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.payload.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.id.encode_size() + self.payload.encode_inline_size()
    }
}

impl<Key: Span> Read for Message<Key> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let id = u64::read(buf)?;
        let payload = Payload::read(buf)?;
        Ok(Self { id, payload })
    }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload<Key: Span> {
    // Request is a request for a response.
    Request(Key),

    // Response is a response to a request.
    Response(Bytes),

    // A response that indicates an unspecified error.
    //
    // This allows the requester to handle the error more quickly than timing out.
    Error,
}

impl<Key: Span> Write for Payload<Key> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Request(key) => {
                buf.put_u8(0);
                key.write(buf);
            }
            Self::Response(data) => {
                buf.put_u8(1);
                data.write(buf);
            }
            Self::Error => {
                buf.put_u8(2);
            }
        }
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        match self {
            Self::Request(key) => {
                buf.put_u8(0);
                key.write(buf);
            }
            Self::Response(data) => {
                buf.put_u8(1);
                data.write_bufs(buf);
            }
            Self::Error => {
                buf.put_u8(2);
            }
        }
    }
}

impl<Key: Span> EncodeSize for Payload<Key> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Request(key) => key.encode_size(),
            Self::Response(data) => data.encode_size(),
            Self::Error => 0,
        }
    }

    fn encode_inline_size(&self) -> usize {
        1 + match self {
            Self::Request(key) => key.encode_size(),
            Self::Response(data) => data.encode_inline_size(),
            Self::Error => 0,
        }
    }
}

impl<Key: Span> Read for Payload<Key> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let payload_type = u8::read(buf)?;
        match payload_type {
            0 => {
                let key = Key::read(buf)?;
                Ok(Self::Request(key))
            }
            1 => {
                // The maximum length of a message is already bounded by the P2P connection.
                // Since the Bytes type will not allocate more memory than the buffer size,
                // we can safely read the bytes with no limit. If an attacker encodes the length of
                // the bytes with a value greater than the buffer size, the read will fail without
                // allocating more memory.
                let data = Bytes::read_cfg(buf, &(..).into())?;
                Ok(Self::Response(data))
            }
            2 => Ok(Self::Error),
            _ => Err(Error::Invalid("Payload", "Invalid payload type")),
        }
    }
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
    use commonware_runtime::iobuf::EncodeExt;
    use commonware_utils::Widen;

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
    fn test_message_overhead() {
        let size = |payload: Payload<u8>| {
            Message {
                id: u64::MAX,
                payload,
            }
            .encode()
            .len()
        };

        // A request adds exactly its overhead to the key, and an error is exactly that overhead.
        assert_eq!(size(Payload::Request(u8::MAX)), u8::SIZE + REQUEST_OVERHEAD);
        assert_eq!(size(Payload::Error), REQUEST_OVERHEAD);

        // Responses on both sides of each varint length boundary stay within the overhead.
        for len in [0, 127, 128, 16_383, 16_384] {
            assert!(
                size(Payload::Response(Bytes::from(vec![0; len]))) - len <= MAX_RESPONSE_OVERHEAD
            );
        }

        // A response carrying a `u32::MAX`-byte value adds exactly the overhead. Measure the
        // envelope of an empty response and add the largest length prefix, so the test never
        // allocates that value.
        let envelope = size(Payload::Response(Bytes::new())) - Bytes::new().encode_size();
        assert_eq!(
            envelope + Widen::<usize>::widen(u32::MAX).encode_size(),
            MAX_RESPONSE_OVERHEAD
        );
    }

    #[test]
    fn test_max_message_size() {
        // The response is the widest message unless the key is wider than the value plus the
        // largest length prefix. A value too long for its length prefix has no size.
        assert_eq!(max_message_size::<u8>(0), Some(MAX_RESPONSE_OVERHEAD));
        assert_eq!(
            max_message_size::<u8>(100),
            Some(100 + MAX_RESPONSE_OVERHEAD)
        );
        assert_eq!(max_message_size::<[u8; 64]>(0), Some(64 + REQUEST_OVERHEAD));
        let largest: usize = Widen::widen(u32::MAX);
        assert_eq!(
            max_message_size::<u8>(largest),
            Some(largest + MAX_RESPONSE_OVERHEAD)
        );
        assert_eq!(max_message_size::<u8>(largest + 1), None);
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
    fn test_message_encode_iobufs_matches_encode() {
        let msg = Message {
            id: 42,
            payload: Payload::<MockKey>::Response(Bytes::from("hello world")),
        };

        let encoded = msg.encode();
        let mut encoded_bufs = msg.encode_iobufs();
        let mut encoded_bufs_bytes = vec![0u8; encoded_bufs.remaining()];
        encoded_bufs.copy_to_slice(&mut encoded_bufs_bytes);
        assert_eq!(encoded_bufs_bytes, encoded.as_ref());
    }

    #[test]
    fn test_payload_response_encode_iobufs_matches_encode() {
        let payload = Payload::<MockKey>::Response(Bytes::from("response data"));

        let encoded = payload.encode();
        let mut encoded_bufs = payload.encode_iobufs();
        let mut encoded_bufs_bytes = vec![0u8; encoded_bufs.remaining()];
        encoded_bufs.copy_to_slice(&mut encoded_bufs_bytes);
        assert_eq!(encoded_bufs_bytes, encoded.as_ref());
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
