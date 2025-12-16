use crate::authenticated::data::Data;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};

/// The maximum overhead (in bytes) when encoding a [Data].
///
/// The byte overhead is calculated as the sum of the following:
/// - 1: Message enum discriminant
/// - 10: Channel varint
/// - 5: Message length varint (lengths longer than 32 bits are forbidden by the codec)
pub const MAX_PAYLOAD_DATA_OVERHEAD: usize = 1 + 10 + 5;

/// Prefix that identifies the message as a Ping message.
pub const PING_MESSAGE_PREFIX: u8 = 0;

/// Prefix that identifies the message as a Data message.
pub const DATA_MESSAGE_PREFIX: u8 = 1;

/// The messages that can be sent between peers.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Message {
    Ping,
    Data(Data),
}

impl From<Data> for Message {
    fn from(data: Data) -> Self {
        Self::Data(data)
    }
}

impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        (match self {
            Self::Ping => 0, // Ping has no payload
            Self::Data(data) => data.encode_size(),
        }) + 1 // 1 bytes for Message discriminant
    }
}

impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Ping => {
                PING_MESSAGE_PREFIX.write(buf); // Discriminant for Ping
            }
            Self::Data(data) => {
                DATA_MESSAGE_PREFIX.write(buf); // Discriminant for Data
                data.write(buf);
            }
        }
    }
}

impl Read for Message {
    type Cfg = usize; // Maximum amount of data to read

    fn read_cfg(buf: &mut impl Buf, max_data_length: &Self::Cfg) -> Result<Self, Error> {
        let message_type = <u8>::read(buf)?;
        match message_type {
            PING_MESSAGE_PREFIX => Ok(Self::Ping),
            DATA_MESSAGE_PREFIX => {
                let data = Data::read_cfg(buf, &(..=*max_data_length).into())?;
                Ok(Self::Data(data))
            }
            _ => Err(Error::Invalid(
                "p2p::authenticated::lookup::Message",
                "Invalid type",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_codec::{Decode as _, Encode as _, Error};

    #[test]
    fn test_max_payload_overhead() {
        let message = Bytes::from(vec![0; 1 << 29]);
        let message_len = message.len();
        let payload = Message::Data(Data {
            channel: u64::MAX,
            message,
        });
        assert_eq!(
            payload.encode_size(),
            message_len + MAX_PAYLOAD_DATA_OVERHEAD
        );
    }

    #[test]
    fn test_decode_data_within_limit() {
        let payload = Message::Data(Data {
            channel: 7,
            message: Bytes::from_static(b"ping"),
        });
        let encoded = payload.encode().freeze();

        let decoded = Message::decode_cfg(encoded, &4).expect("within limit");
        match decoded {
            Message::Data(data) => {
                assert_eq!(data.channel, 7);
                assert_eq!(data.message, Bytes::from_static(b"ping"));
            }
            other => panic!("unexpected message variant: {other:?}"),
        }
    }

    #[test]
    fn test_decode_data_exceeding_limit() {
        let payload = Message::Data(Data {
            channel: 9,
            message: Bytes::from_static(b"hello"),
        });
        let encoded = payload.encode().freeze();

        let result = Message::decode_cfg(encoded, &4);
        assert!(matches!(result, Err(Error::InvalidLength(5))));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Message>,
        }
    }
}
