use crate::Channel;
use commonware_codec::{EncodeSize, Error, RangeCfg, Read, ReadExt as _, Write, varint::UInt};
use commonware_runtime::{Buf, BufMut, BufferPool, IoBuf, IoBufs};
use std::collections::HashMap;

/// Data is an arbitrary message sent between peers.
#[derive(Clone, Debug, PartialEq)]
pub struct Data {
    /// A unique identifier for the channel the message is sent on.
    ///
    /// This is used to route the message to the correct handler.
    pub channel: u64,

    /// The payload of the message.
    pub message: IoBuf,
}

impl EncodeSize for Data {
    fn encode_size(&self) -> usize {
        UInt(self.channel).encode_size() + self.message.encode_size()
    }
}

impl Write for Data {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.channel).write(buf);
        self.message.write(buf);
    }
}

impl Read for Data {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, Error> {
        let channel = UInt::read(buf)?.into();
        let message = IoBuf::read_cfg(buf, range)?;
        Ok(Self { channel, message })
    }
}

/// Prefix byte identifying a data frame on the wire.
pub(crate) const DATA_PREFIX: u8 = 0;

/// The maximum overhead (in bytes) when encoding a `message` into a data frame.
///
/// The byte overhead is calculated as the sum of the following:
/// - 1: Frame discriminant
/// - 10: Channel varint
/// - 5: Message length varint (lengths longer than 32 bits are forbidden by the codec)
pub(crate) const MAX_PAYLOAD_DATA_OVERHEAD: u32 = 1 + 10 + 5;

/// Pre-encoded data ready for transmission.
///
/// Contains the channel ID (for metrics) and the pre-encoded payload bytes.
/// The `payload` field contains the fully encoded data frame bytes,
/// stored as one or more buffers ready to be sent directly to the stream layer.
#[derive(Clone, Debug)]
pub struct EncodedData {
    /// The channel this data belongs to (used for metrics/logging).
    pub channel: Channel,

    /// Pre-encoded data frame bytes ready for transmission.
    pub payload: IoBufs,
}

impl EncodedData {
    /// Assert the outbound message's `channel` is registered.
    pub fn validate_channel<V>(self, rate_limits: &HashMap<u64, V>) -> Self {
        assert!(
            rate_limits.contains_key(&self.channel),
            "outbound message on invalid channel"
        );
        self
    }

    /// Encode data frame bytes in-place as:
    /// `DATA_PREFIX || channel || message_len || message`.
    pub fn new(pool: &BufferPool, channel: Channel, mut message: IoBufs) -> Self {
        let payload_len = message.len();
        let header_len =
            DATA_PREFIX.encode_size() + UInt(channel).encode_size() + payload_len.encode_size();
        let mut header = pool.alloc(header_len);
        DATA_PREFIX.write(&mut header);
        UInt(channel).write(&mut header);
        payload_len.write(&mut header);
        assert_eq!(header.len(), header_len, "data header size mismatch");
        message.prepend(header.freeze());

        Self {
            channel,
            payload: message,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Data {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let channel = u.arbitrary::<u64>()?;
        let message = {
            let size = u.int_in_range(0..=1024)?;
            let bytes = u.bytes(size)?;
            IoBuf::copy_from_slice(bytes)
        };
        Ok(Self { channel, message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode as _, Encode as _, Error};
    use commonware_runtime::{BufferPooler as _, Runner as _, deterministic};

    #[test]
    fn test_data_codec() {
        let original = Data {
            channel: 12345,
            message: IoBuf::from(b"Hello, world!"),
        };
        let encoded = original.encode();
        let decoded = Data::decode_cfg(encoded, &(13..=13).into()).unwrap();
        assert_eq!(original, decoded);

        let too_short = Data::decode_cfg(original.encode(), &(0..13).into());
        assert!(matches!(too_short, Err(Error::InvalidLength(13))));

        let too_long = Data::decode_cfg(original.encode(), &(14..).into());
        assert!(matches!(too_long, Err(Error::InvalidLength(13))));
    }

    #[test]
    fn test_decode_invalid() {
        let invalid_payload = [3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let result = Data::decode_cfg(&invalid_payload[..], &(..).into());
        assert!(result.is_err());
    }

    #[test]
    fn test_encoded_data_new_matches_data_encode() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut message = IoBufs::from(IoBuf::from(b"hello "));
            message.append(IoBuf::from(b"world"));
            message.append(IoBuf::from(b"!"));

            let data = Data {
                channel: 12345,
                message: message.clone().coalesce(),
            };

            let mut expected = IoBufs::from(data.encode());
            expected.prepend(IoBuf::from(vec![DATA_PREFIX]));

            let encoded = EncodedData::new(context.network_buffer_pool(), 12345, message);
            assert_eq!(encoded.channel, 12345);
            assert_eq!(encoded.payload.coalesce(), expected.coalesce());
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Data>,
        }
    }
}
