//! Shared `EncodeSize` and `Write` implementations for all variable-size operation encodings:
//! - [VariableValue](super::super::encoding::VariableValue)
//! - [VariableBoth](super::super::encoding::VariableBoth)
//! - [VariableKey](super::super::encoding::VariableKey)
//!
//! These encodings all produce variable-size operations with the same wire format: a context byte
//! followed by the payload. The `Read` implementations remain separate in [super::variable] and
//! [super::varkey] because their `Cfg` types differ.

use crate::qmdb::any::{
    encoding::VariableEncoding,
    operation::{Operation, Update, COMMIT_CONTEXT, DELETE_CONTEXT, UPDATE_CONTEXT},
};
use commonware_codec::{varint::UInt, EncodeSize, Write};
use commonware_runtime::BufMut;

impl<E, S> EncodeSize for Operation<E, S>
where
    E: VariableEncoding,
    E::Key: EncodeSize,
    S: Update<E> + EncodeSize,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(k) => k.encode_size(),
            Self::Update(p) => p.encode_size(),
            Self::CommitFloor(v, floor) => v.encode_size() + UInt(**floor).encode_size(),
        }
    }
}

impl<E, S> Write for Operation<E, S>
where
    E: VariableEncoding,
    E::Key: Write,
    S: Update<E> + Write,
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
