use crate::authenticated::data::Data;
use commonware_codec::{EncodeSize, Read, Write};

/// The messages that can be sent between peers.
#[derive(Clone, Debug, EncodeSize, Write, Read)]
#[read_cfg(usize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Message {
    #[codec(tag = 0)]
    Data(#[codec(cfg = &((..=*cfg).into()))] Data),
    #[codec(tag = 1)]
    Ping,
}

impl From<Data> for Message {
    fn from(data: Data) -> Self {
        Self::Data(data)
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
        assert_eq!(crate::authenticated::data::DATA_PREFIX, 0);
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
