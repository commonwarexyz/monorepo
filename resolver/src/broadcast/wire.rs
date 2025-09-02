use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_utils::Span;

/// Represents the contents of a message used by broadcast resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload<Key: Span> {
    /// Broadcast request for a key
    Request(Key),

    /// Response with key and data (supports push-style updates)
    Response { key: Key, data: Bytes },
}

impl<Key: Span> Write for Payload<Key> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Payload::Request(key) => {
                0u8.write(buf);
                key.write(buf);
            }
            Payload::Response { key, data } => {
                1u8.write(buf);
                key.write(buf);
                data.write(buf);
            }
        }
    }
}

impl<Key: Span> EncodeSize for Payload<Key> {
    fn encode_size(&self) -> usize {
        match self {
            Payload::Request(key) => 1 + key.encode_size(),
            Payload::Response { key, data } => 1 + key.encode_size() + data.encode_size(),
        }
    }
}

impl<Key: Span> Read for Payload<Key> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let t = u8::read(buf)?;
        Ok(match t {
            0 => Self::Request(Key::read(buf)?),
            1 => {
                let key = Key::read(buf)?;
                // The maximum length is bounded by P2P channel; allow any here
                let data = Bytes::read_cfg(buf, &(..).into())?;
                Self::Response { key, data }
            }
            _ => return Err(Error::InvalidEnum(t)),
        })
    }
}
