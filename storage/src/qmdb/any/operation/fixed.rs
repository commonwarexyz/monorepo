use crate::{
    mmr::Location,
    qmdb::any::{
        operation::{COMMIT_CONTEXT, DELETE_CONTEXT, UPDATE_CONTEXT},
        update::Update,
        value::FixedEncoding,
        FixedValue, Operation,
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    util::{at_least, ensure_zeros},
    Codec, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_utils::Array;

impl<K, V, S> Operation<K, FixedEncoding<V>, S>
where
    K: Array,
    V: FixedValue,
    S: Update<K, FixedEncoding<V>> + FixedSize,
{
    const UPDATE_OP_SIZE: usize = 1 + S::SIZE;
    const COMMIT_OP_SIZE: usize = 1 + 1 + V::SIZE + u64::SIZE;
    const DELETE_OP_SIZE: usize = 1 + K::SIZE;
}

impl<K, V, S> FixedSize for Operation<K, FixedEncoding<V>, S>
where
    K: Array,
    V: FixedValue,
    S: Update<K, FixedEncoding<V>> + FixedSize,
{
    const SIZE: usize = {
        let max = if Self::UPDATE_OP_SIZE > Self::COMMIT_OP_SIZE {
            Self::UPDATE_OP_SIZE
        } else {
            Self::COMMIT_OP_SIZE
        };
        if max > Self::DELETE_OP_SIZE {
            max
        } else {
            Self::DELETE_OP_SIZE
        }
    };
}

impl<K, V, S> Write for Operation<K, FixedEncoding<V>, S>
where
    K: Array + Codec,
    V: FixedValue,
    S: Update<K, FixedEncoding<V>> + FixedSize + Write,
{
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
                buf.put_bytes(0, Self::SIZE - Self::DELETE_OP_SIZE);
            }
            Self::Update(p) => {
                UPDATE_CONTEXT.write(buf);
                p.write(buf);
                buf.put_bytes(0, Self::SIZE - Self::UPDATE_OP_SIZE);
            }
            Self::CommitFloor(metadata, floor_loc) => {
                COMMIT_CONTEXT.write(buf);
                if let Some(metadata) = metadata {
                    true.write(buf);
                    metadata.write(buf);
                } else {
                    buf.put_bytes(0, V::SIZE + 1);
                }
                buf.put_slice(&floor_loc.to_be_bytes());
                buf.put_bytes(0, Self::SIZE - Self::COMMIT_OP_SIZE);
            }
        }
    }
}

impl<K, V, S> Read for Operation<K, FixedEncoding<V>, S>
where
    K: Array + Codec,
    V: FixedValue,
    S: Update<K, FixedEncoding<V>> + FixedSize + Read<Cfg = ()>,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;

        match u8::read(buf)? {
            UPDATE_CONTEXT => {
                let payload = S::read_cfg(buf, cfg)?;
                ensure_zeros(buf, Self::SIZE - Self::UPDATE_OP_SIZE)?;
                Ok(Self::Update(payload))
            }
            DELETE_CONTEXT => {
                let key = K::read(buf)?;
                ensure_zeros(buf, Self::SIZE - Self::DELETE_OP_SIZE)?;
                Ok(Self::Delete(key))
            }
            COMMIT_CONTEXT => {
                let is_some = bool::read(buf)?;
                let metadata = if is_some {
                    Some(V::read_cfg(buf, cfg)?)
                } else {
                    ensure_zeros(buf, V::SIZE)?;
                    None
                };
                let floor_loc = u64::read(buf)?;
                let floor_loc = Location::new(floor_loc).ok_or_else(|| {
                    CodecError::Invalid(
                        "storage::qmdb::any::todo::Operation2",
                        "commit floor location overflow",
                    )
                })?;
                ensure_zeros(buf, Self::SIZE - Self::COMMIT_OP_SIZE)?;
                Ok(Self::CommitFloor(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}
