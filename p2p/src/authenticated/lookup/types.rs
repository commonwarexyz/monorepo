use crate::{
    authenticated::data::{Data, EncodedData},
    Channel,
};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_runtime::{Buf, BufMut, BufferPool, IoBufs};

/// The maximum overhead (in bytes) when encoding a [Data].
///
/// The byte overhead is calculated as the sum of the following:
/// - 1: Message enum discriminant
/// - 10: Channel varint
/// - 5: Message length varint (lengths longer than 32 bits are forbidden by the codec)
pub const MAX_PAYLOAD_DATA_OVERHEAD: u32 = 1 + 10 + 5;

/// Prefix that identifies the message as a Data message.
pub const DATA_PREFIX: u8 = 0;

/// Prefix that identifies the message as a Ping message.
pub const PING_PREFIX: u8 = 1;

/// The messages that can be sent between peers.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Message {
    Data(Data),
    Ping,
}

impl Message {
    /// Encode `Message::Data` bytes for transmission using pooled header allocation.
    pub(crate) fn encode_data(pool: &BufferPool, channel: Channel, message: IoBufs) -> EncodedData {
        EncodedData::encode_with_prefix(pool, DATA_PREFIX, channel, message)
    }
}

impl From<Data> for Message {
    fn from(data: Data) -> Self {
        Self::Data(data)
    }
}

impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        (match self {
            Self::Data(data) => data.encode_size(),
            Self::Ping => 0, // Ping has no payload
        }) + 1 // 1 bytes for Message discriminant
    }
}

impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Data(data) => {
                DATA_PREFIX.write(buf); // Discriminant for Data
                data.write(buf);
            }
            Self::Ping => {
                PING_PREFIX.write(buf); // Discriminant for Ping
            }
        }
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
    use commonware_codec::{Decode as _, Encode as _, Error};
    use commonware_runtime::{deterministic, BufferPooler as _, IoBuf, IoBufs, Runner as _};

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
            message_len + MAX_PAYLOAD_DATA_OVERHEAD as usize
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

    #[test]
    fn test_encode_data_matches_message_data_encode() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let channel = 12345;
            let mut message = IoBufs::from(IoBuf::from(b"Hello, "));
            message.append(IoBuf::from(b"world"));
            message.append(IoBuf::from(b"!"));

            let expected = Message::Data(Data {
                channel,
                message: message.clone().coalesce(),
            })
            .encode();
            let encoded = Message::encode_data(context.network_buffer_pool(), channel, message);

            assert_eq!(encoded.channel, channel);
            assert_eq!(encoded.payload.coalesce().as_ref(), expected.as_ref());
        });
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
