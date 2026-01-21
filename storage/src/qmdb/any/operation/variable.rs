use crate::{
    mmr::Location,
    qmdb::any::{
        operation::{Operation, Update, COMMIT_CONTEXT, DELETE_CONTEXT, UPDATE_CONTEXT},
        value::VariableEncoding,
        VariableValue,
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_utils::Array;

impl<K, V, S> EncodeSize for Operation<K, VariableEncoding<V>, S>
where
    K: Array,
    V: VariableValue,
    S: Update<K, VariableEncoding<V>> + EncodeSize,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(_, loc) => K::SIZE + loc.encode_size(),
            Self::Update(p, loc) => p.encode_size() + loc.encode_size(),
            Self::CommitFloor(v, floor, loc) => {
                v.encode_size() + floor.encode_size() + loc.encode_size()
            }
        }
    }
}

impl<K, V, S> Write for Operation<K, VariableEncoding<V>, S>
where
    K: Array + Codec,
    V: VariableValue,
    S: Update<K, VariableEncoding<V>> + Write,
{
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Delete(k, loc) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
                loc.write(buf);
            }
            Self::Update(p, loc) => {
                UPDATE_CONTEXT.write(buf);
                p.write(buf);
                loc.write(buf);
            }
            Self::CommitFloor(metadata, floor_loc, loc) => {
                COMMIT_CONTEXT.write(buf);
                metadata.write(buf);
                floor_loc.write(buf);
                loc.write(buf);
            }
        }
    }
}

impl<K, V, S> Read for Operation<K, VariableEncoding<V>, S>
where
    K: Array + Codec,
    V: VariableValue,
    S: Update<K, VariableEncoding<V>> + Read<Cfg = <V as Read>::Cfg>,
{
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            DELETE_CONTEXT => {
                let key = K::read(buf)?;
                let loc = Location::read(buf)?;
                Ok(Self::Delete(key, loc))
            }
            UPDATE_CONTEXT => {
                let payload = S::read_cfg(buf, cfg)?;
                let loc = Location::read(buf)?;
                Ok(Self::Update(payload, loc))
            }
            COMMIT_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, cfg)?;
                let floor_loc = Location::read(buf)?;
                let loc = Location::read(buf)?;
                Ok(Self::CommitFloor(metadata, floor_loc, loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}
