use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{varint::UInt, EncodeSize, Error, RangeCfg, Read, ReadExt as _, Write};

/// Data is an arbitrary message sent between peers.
#[derive(Clone, Debug, PartialEq)]
pub struct Data {
    /// A unique identifier for the channel the message is sent on.
    ///
    /// This is used to route the message to the correct handler.
    pub channel: u64,

    /// The payload of the message.
    pub message: Bytes,
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
        let message = Bytes::read_cfg(buf, range)?;
        Ok(Self { channel, message })
    }
}

#[cfg(test)]
mod tests {
    use crate::authenticated::data::Data;
    use bytes::Bytes;
    use commonware_codec::{Decode as _, Encode as _, Error};

    #[test]
    fn test_data_codec() {
        let original = Data {
            channel: 12345,
            message: Bytes::from("Hello, world!"),
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
}
