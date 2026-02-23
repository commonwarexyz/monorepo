use crate::{
    mmr::Location,
    qmdb::any::{
        encoding::{VariableVal, VariableValue},
        operation::{Operation, Update, COMMIT_CONTEXT, DELETE_CONTEXT, UPDATE_CONTEXT},
    },
};
use commonware_codec::{varint::UInt, Error as CodecError, Read, ReadExt as _};
use commonware_runtime::Buf;
use commonware_utils::Array;

// Note: `EncodeSize` and `Write` impls are in `var_common.rs`, shared with the varkey encodings.

impl<K, V, S> Read for Operation<VariableValue<K, V>, S>
where
    K: Array + commonware_codec::Codec,
    V: VariableVal,
    S: Update<VariableValue<K, V>> + Read<Cfg = <V as Read>::Cfg>,
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
