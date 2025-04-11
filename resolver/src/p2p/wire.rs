use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};

/// Represents a message sent between peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerMsg {
    /// Unique identifier for the message.
    /// Responses should have the same ID as the request they are responding to.
    pub id: u64,

    /// Payload is the data being sent.
    pub payload: Payload,
}

impl Write for PeerMsg {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.id);
        self.payload.write(buf);
    }
}

impl EncodeSize for PeerMsg {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.payload.encode_size()
    }
}

impl Read for PeerMsg {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let id = buf.get_u64();
        let payload = Payload::read(buf)?;
        Ok(PeerMsg { id, payload })
    }
}

/// Represents the contents of a message sent between peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    // Request is a request for a response.
    Request(Bytes),

    // Response is a response to a request.
    Response(Bytes),

    // A response that indicates an unspecified error.
    //
    // This allows the requester to handle the error more quickly than timing out.
    ErrorResponse,
}

impl Write for Payload {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Payload::Request(data) => {
                buf.put_u8(0);
                data.write(buf);
            }
            Payload::Response(data) => {
                buf.put_u8(1);
                data.write(buf);
            }
            Payload::ErrorResponse => {
                buf.put_u8(2);
            }
        }
    }
}

impl EncodeSize for Payload {
    fn encode_size(&self) -> usize {
        1 + match self {
            Payload::Request(data) => data.encode_size(),
            Payload::Response(data) => data.encode_size(),
            Payload::ErrorResponse => 0,
        }
    }
}

impl Read for Payload {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let payload_type = buf.get_u8();
        match payload_type {
            0 => {
                let data = Bytes::read_cfg(buf, &..)?;
                Ok(Payload::Request(data))
            }
            1 => {
                let data = Bytes::read_cfg(buf, &..)?;
                Ok(Payload::Response(data))
            }
            2 => Ok(Payload::ErrorResponse),
            _ => Err(Error::Invalid("Payload", "Invalid payload type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn test_codec_request() {
        let payload = Payload::Request(Bytes::from("Hello, world!"));
        let original = PeerMsg { id: 1234, payload };
        let encoded = original.encode();
        let decoded = PeerMsg::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_response() {
        let payload = Payload::Response(Bytes::from("Hello, world!"));
        let original = PeerMsg { id: 4321, payload };
        let encoded = original.encode();
        let decoded = PeerMsg::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_error() {
        let payload = Payload::ErrorResponse;
        let original = PeerMsg { id: 255, payload };
        let encoded = original.encode();
        let decoded = PeerMsg::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
