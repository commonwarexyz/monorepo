use commonware_codec::{Buf, BufsMut, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_runtime::BufMut;

/// Tag of a request.
const REQUEST: u8 = 0;

/// Tag of a response.
const RESPONSE: u8 = 1;

/// Returns an upper bound on the encoded size of any message for requests of at most `request`
/// bytes and responses of at most `response` bytes.
pub fn max_message_size(request: usize, response: usize) -> usize {
    u8::SIZE + request.max(response)
}

/// A request or a response, sent as a one-byte tag followed by its encoding.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Message<Rq, Rs> {
    Request(Rq),
    Response(Rs),
}

impl<Rq: Write, Rs: Write> Write for Message<Rq, Rs> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Request(request) => {
                REQUEST.write(buf);
                request.write(buf);
            }
            Self::Response(response) => {
                RESPONSE.write(buf);
                response.write(buf);
            }
        }
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        match self {
            Self::Request(request) => {
                REQUEST.write(buf);
                request.write_bufs(buf);
            }
            Self::Response(response) => {
                RESPONSE.write(buf);
                response.write_bufs(buf);
            }
        }
    }
}

impl<Rq: EncodeSize, Rs: EncodeSize> EncodeSize for Message<Rq, Rs> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Request(request) => request.encode_size(),
                Self::Response(response) => response.encode_size(),
            }
    }

    fn encode_inline_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Request(request) => request.encode_inline_size(),
                Self::Response(response) => response.encode_inline_size(),
            }
    }
}

impl<Rq: Read, Rs: Read> Read for Message<Rq, Rs> {
    type Cfg = (Rq::Cfg, Rs::Cfg);

    fn read_cfg(buf: &mut impl Buf, (request, response): &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            REQUEST => Ok(Self::Request(Rq::read_cfg(buf, request)?)),
            RESPONSE => Ok(Self::Response(Rs::read_cfg(buf, response)?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<Rq, Rs> arbitrary::Arbitrary<'_> for Message<Rq, Rs>
where
    Rq: for<'a> arbitrary::Arbitrary<'a>,
    Rs: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        match u.int_in_range(REQUEST..=RESPONSE)? {
            REQUEST => Ok(Self::Request(u.arbitrary()?)),
            RESPONSE => Ok(Self::Response(u.arbitrary()?)),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_runtime::{IoBuf, iobuf::EncodeExt as _};

    /// A message with simple request and response types.
    type Simple = Message<u8, u16>;

    #[test]
    fn test_round_trip() {
        // Each variant decodes to the message it was encoded from.
        for message in [Simple::Request(7), Simple::Response(0x0102)] {
            let decoded = Simple::decode_cfg(message.encode(), &((), ())).unwrap();
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn test_tags() {
        // A request starts with the byte 0 and a response with the byte 1.
        assert_eq!(Simple::Request(7).encode().as_ref(), [0, 7]);
        assert_eq!(Simple::Response(0x0102).encode().as_ref(), [1, 1, 2]);
    }

    #[test]
    fn test_max_message_size() {
        // The larger encoding meets the bound, and the smaller one stays below it.
        let bound = max_message_size(u8::SIZE, u16::SIZE);
        assert_eq!(Simple::Response(0x0102).encode().len(), bound);
        assert!(Simple::Request(7).encode().len() < bound);
    }

    #[test]
    fn test_rejects_malformed() {
        // An empty payload does not decode.
        let result = Simple::decode_cfg(Vec::new(), &((), ()));
        assert!(matches!(result, Err(Error::EndOfBuffer)));

        // A tag that marks neither a request nor a response does not decode.
        let result = Simple::decode_cfg(vec![2, 7], &((), ()));
        assert!(matches!(result, Err(Error::InvalidEnum(2))));

        // A request followed by one extra byte does not decode.
        let result = Simple::decode_cfg(vec![0, 7, 0], &((), ()));
        assert!(matches!(result, Err(Error::ExtraData(1))));
    }

    #[test]
    fn test_encode_iobufs_matches_encode() {
        // Each variant writes its tag and the length of its `IoBuf` body inline and appends the
        // body without copying it, and the buffers hold the same bytes as one contiguous encoding.
        let body = IoBuf::from(vec![7; 64]);
        for message in [
            Message::<IoBuf, IoBuf>::Request(body.clone()),
            Message::Response(body),
        ] {
            assert_eq!(message.encode_inline_size(), 2);
            assert_eq!(
                message.encode_iobufs().coalesce().as_ref(),
                message.encode().as_ref()
            );
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Message<u8, u16>>,
        }
    }
}
