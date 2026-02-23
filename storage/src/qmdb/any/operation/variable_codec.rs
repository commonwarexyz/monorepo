//! Shared `EncodeSize` and `Write` implementations for all variable-size operation encodings:
//! - [VariableEncoding](super::super::value::VariableEncoding)
//! - [VarKeyEncoding](super::super::value::VarKeyEncoding)
//! - [VarKeyFixedEncoding](super::super::value::VarKeyFixedEncoding)
//!
//! These encodings all produce variable-size operations with the same wire format: a context byte
//! followed by the payload. The `Read` implementations remain separate in [super::variable] and
//! [super::varkey] because their `Cfg` types differ.

use crate::qmdb::{
    any::{
        operation::{Operation, Update, COMMIT_CONTEXT, DELETE_CONTEXT, UPDATE_CONTEXT},
        value::VarOperationEncoding,
    },
    operation::Key,
};
use commonware_codec::{varint::UInt, EncodeSize, Write};
use commonware_runtime::BufMut;

impl<K, V, S> EncodeSize for Operation<K, V, S>
where
    K: Key + EncodeSize,
    V: VarOperationEncoding,
    S: Update<K, V> + EncodeSize,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(k) => k.encode_size(),
            Self::Update(p) => p.encode_size(),
            Self::CommitFloor(v, floor) => v.encode_size() + UInt(**floor).encode_size(),
        }
    }
}

impl<K, V, S> Write for Operation<K, V, S>
where
    K: Key + Write,
    V: VarOperationEncoding,
    S: Update<K, V> + Write,
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
