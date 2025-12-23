use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_utils::Span;

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
}

impl<Key: Span> EncodeSize for Message<Key> {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.payload.encode_size()
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
}

impl<Key: Span> EncodeSize for Payload<Key> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Request(key) => key.encode_size(),
            Self::Response(data) => data.encode_size(),
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
    use commonware_codec::{DecodeExt, Encode};

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
