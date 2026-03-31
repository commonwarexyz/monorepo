use crate::{
    merkle::{Family, Location},
    qmdb::{
        any::{
            operation::{
                update, Operation, OperationCodec, Update, COMMIT_CONTEXT, DELETE_CONTEXT,
                UPDATE_CONTEXT,
            },
            value::VariableEncoding,
            VariableValue,
        },
        operation::Key,
    },
};
use commonware_codec::{varint::UInt, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_runtime::{Buf, BufMut};

impl<F, V, S> OperationCodec<F, S> for VariableEncoding<V>
where
    F: Family,
    S::Key: Write + Read,
    V: VariableValue,
    S: Update<Value = V, ValueEncoding = Self>
        + Write
        + Read<Cfg = (<S::Key as Read>::Cfg, <V as Read>::Cfg)>,
{
    type ReadCfg = (<S::Key as Read>::Cfg, <V as Read>::Cfg);

    fn write_operation(op: &Operation<F, S>, buf: &mut impl BufMut) {
        match op {
            Operation::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
            }
            Operation::Update(p) => {
                UPDATE_CONTEXT.write(buf);
                p.write(buf);
            }
            Operation::CommitFloor(metadata, floor_loc) => {
                COMMIT_CONTEXT.write(buf);
                metadata.write(buf);
                UInt(**floor_loc).write(buf);
            }
        }
    }

    fn read_operation(
        buf: &mut impl Buf,
        cfg: &Self::ReadCfg,
    ) -> Result<Operation<F, S>, CodecError> {
        match u8::read(buf)? {
            DELETE_CONTEXT => {
                let key = S::Key::read_cfg(buf, &cfg.0)?;
                Ok(Operation::Delete(key))
            }
            UPDATE_CONTEXT => {
                let payload = S::read_cfg(buf, cfg)?;
                Ok(Operation::Update(payload))
            }
            COMMIT_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, &cfg.1)?;
                let floor_loc = Location::read(buf)?;
                Ok(Operation::CommitFloor(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

// EncodeSize for ordered variable operations.
impl<F, K, V> EncodeSize for Operation<F, update::Ordered<K, VariableEncoding<V>>>
where
    F: Family,
    K: Key + EncodeSize,
    V: VariableValue,
    update::Ordered<K, VariableEncoding<V>>: EncodeSize,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(k) => k.encode_size(),
            Self::Update(p) => p.encode_size(),
            Self::CommitFloor(v, floor) => v.encode_size() + UInt(**floor).encode_size(),
        }
    }
}

// EncodeSize for unordered variable operations.
impl<F, K, V> EncodeSize for Operation<F, update::Unordered<K, VariableEncoding<V>>>
where
    F: Family,
    K: Key + EncodeSize,
    V: VariableValue,
    update::Unordered<K, VariableEncoding<V>>: EncodeSize,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(k) => k.encode_size(),
            Self::Update(p) => p.encode_size(),
            Self::CommitFloor(v, floor) => v.encode_size() + UInt(**floor).encode_size(),
        }
    }
}
