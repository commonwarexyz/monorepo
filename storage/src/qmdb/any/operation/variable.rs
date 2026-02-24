use crate::{
    mmr::Location,
    qmdb::{
        any::{
            operation::{Operation, Update, COMMIT_CONTEXT, DELETE_CONTEXT, UPDATE_CONTEXT},
            value::VariableEncoding,
            VariableValue,
        },
        operation::Key,
    },
};
use commonware_codec::{varint::UInt, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_runtime::{Buf, BufMut};

impl<K, V, S> EncodeSize for Operation<K, VariableEncoding<V>, S>
where
    K: Key + EncodeSize,
    V: VariableValue,
    S: Update<K, VariableEncoding<V>> + EncodeSize,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(k) => k.encode_size(),
            Self::Update(p) => p.encode_size(),
            Self::CommitFloor(v, floor) => v.encode_size() + UInt(**floor).encode_size(),
        }
    }
}

impl<K, V, S> Write for Operation<K, VariableEncoding<V>, S>
where
    K: Key + Write,
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
    K: Key + Read,
    V: VariableValue,
    S: Update<K, VariableEncoding<V>> + Read<Cfg = (<K as Read>::Cfg, <V as Read>::Cfg)>,
{
    type Cfg = (<K as Read>::Cfg, <V as Read>::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            DELETE_CONTEXT => {
                let key = K::read_cfg(buf, &cfg.0)?;
                Ok(Self::Delete(key))
            }
            UPDATE_CONTEXT => {
                let payload = S::read_cfg(buf, cfg)?;
                Ok(Self::Update(payload))
            }
            COMMIT_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, &cfg.1)?;
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
