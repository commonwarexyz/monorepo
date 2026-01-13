use crate::{
    mmr::Location,
    qmdb::any::{
        operation::{Operation, Update, COMMIT_CONTEXT, DELETE_CONTEXT, UPDATE_CONTEXT},
        value::VariableEncoding,
        VariableValue,
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Codec, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_utils::Array;

impl<K, V, S> EncodeSize for Operation<K, VariableEncoding<V>, S>
where
    K: Array,
    V: VariableValue,
    S: Update<K, VariableEncoding<V>> + EncodeSize,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(_) => K::SIZE,
            Self::Update(p) => p.encode_size(),
            Self::CommitFloor(v, floor) => v.encode_size() + UInt(**floor).encode_size(),
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
            Self::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
            }
            Self::Update(p) => {
                UPDATE_CONTEXT.write(buf);
                p.write(buf);
            }
            Self::CommitFloor(metadata, floor_loc) => {
                COMMIT_CONTEXT.write(buf);
                metadata.write(buf);
                UInt(**floor_loc).write(buf);
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
                Ok(Self::Delete(key))
            }
            UPDATE_CONTEXT => {
                let payload = S::read_cfg(buf, cfg)?;
                Ok(Self::Update(payload))
            }
            COMMIT_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, cfg)?;
                let floor_loc = UInt::read(buf)?;
                let floor_loc = Location::new(floor_loc.into()).ok_or_else(|| {
                    CodecError::Invalid(
                        "storage::qmdb::any::operation::variable::Operation",
                        "commit floor location overflow",
                    )
                })?;
                Ok(Self::CommitFloor(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}
