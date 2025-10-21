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
pub enum Message {
    Ping,
    Data(Data),
}

impl From<Data> for Message {
    fn from(data: Data) -> Self {
        Message::Data(data)
    }
}

impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        (match self {
            Message::Ping => 0, // Ping has no payload
            Message::Data(data) => data.encode_size(),
        }) + 1 // 1 bytes for Message discriminant
    }
}

impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Message::Ping => {
                PING_MESSAGE_PREFIX.write(buf); // Discriminant for Ping
            }
            Message::Data(data) => {
                DATA_MESSAGE_PREFIX.write(buf); // Discriminant for Data
                data.write(buf);
            }
        }
    }
}

impl Read for Message {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max: &Self::Cfg) -> Result<Self, Error> {
        let message_type = <u8>::read(buf)?;
        match message_type {
            PING_MESSAGE_PREFIX => Ok(Message::Ping),
            DATA_MESSAGE_PREFIX => {
                let data = Data::read_cfg(buf, &(..=*max).into())?;
                Ok(Message::Data(data))
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
}
