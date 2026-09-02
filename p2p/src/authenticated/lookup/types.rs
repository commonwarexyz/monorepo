use crate::authenticated::data::Data;
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_runtime::Buf;

/// Prefix that identifies the message as a Data message.
pub const DATA_PREFIX: u8 = crate::authenticated::data::DATA_PREFIX; // 0
/// Prefix that identifies the message as a Ping message.
pub const PING_PREFIX: u8 = 1;

/// The messages that can be sent between peers.
#[derive(Clone, Debug, EncodeSize, Write)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Message {
    #[codec(tag = 0)]
    Data(Data),
    #[codec(tag = 1)]
    Ping,
}

impl From<Data> for Message {
    fn from(data: Data) -> Self {
        Self::Data(data)
    }
}

impl Read for Message {
    type Cfg = usize; // Maximum amount of data to read

    fn read_cfg(buf: &mut impl Buf, max_data_length: &Self::Cfg) -> Result<Self, Error> {
        let message_type = <u8>::read(buf)?;
        match message_type {
            DATA_PREFIX => {
                let data = Data::read_cfg(buf, &(..=*max_data_length).into())?;
                Ok(Self::Data(data))
            }
            PING_PREFIX => Ok(Self::Ping),
            other => Err(Error::InvalidEnum(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::MAX_PAYLOAD_OVERHEAD;
    use commonware_codec::{Decode as _, Encode as _, Error};
    use commonware_runtime::IoBuf;

    #[test]
    fn test_data_prefix_value() {
        assert_eq!(DATA_PREFIX, 0);
    }

    #[test]
    fn test_max_payload_overhead() {
        let message = IoBuf::from(vec![0; 1 << 29]);
        let message_len = message.len();
        let payload = Message::Data(Data {
            channel: u64::MAX,
            message,
        });
        assert_eq!(
            payload.encode_size(),
            message_len + MAX_PAYLOAD_OVERHEAD as usize
        );
    }

    #[test]
    fn test_decode_data_within_limit() {
        let payload = Message::Data(Data {
            channel: 7,
            message: IoBuf::from(b"ping"),
        });
        let encoded = payload.encode();

        let decoded = Message::decode_cfg(encoded, &4).expect("within limit");
        match decoded {
            Message::Data(data) => {
                assert_eq!(data.channel, 7);
                assert_eq!(data.message, IoBuf::from(b"ping"));
            }
            other => panic!("unexpected message variant: {other:?}"),
        }
    }

    #[test]
    fn test_decode_ping() {
        let encoded = Message::Ping.encode();
        assert_eq!(encoded[..], [PING_PREFIX]);
        assert!(matches!(
            Message::decode_cfg(encoded, &4).unwrap(),
            Message::Ping
        ));
    }

    #[test]
    fn test_decode_data_exceeding_limit() {
        let payload = Message::Data(Data {
            channel: 9,
            message: IoBuf::from(b"hello"),
        });
        let encoded = payload.encode();

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
