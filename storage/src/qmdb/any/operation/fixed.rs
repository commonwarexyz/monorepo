use crate::{
    merkle::{Family, Location},
    qmdb::any::{
        operation::{
            update, Operation, OperationCodec, Update, COMMIT_CONTEXT, DELETE_CONTEXT,
            UPDATE_CONTEXT,
        },
        value::FixedEncoding,
        FixedValue,
    },
};
use commonware_codec::{
    util::{at_least, ensure_zeros},
    Codec, CodecFixed, Error as CodecError, FixedSize, ReadExt as _, Write,
};
use commonware_runtime::{Buf, BufMut};
use commonware_utils::Array;

/// `max(a, b)` in a const context.
const fn const_max(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

const fn update_op_size<S: FixedSize>() -> usize {
    1 + S::SIZE
}

const fn commit_op_size<V: FixedSize>() -> usize {
    1 + 1 + V::SIZE + u64::SIZE
}

const fn delete_op_size<K: Array>() -> usize {
    1 + K::SIZE
}

const fn total_op_size<K: Array, V: FixedSize, S: FixedSize>() -> usize {
    const_max(
        update_op_size::<S>(),
        const_max(commit_op_size::<V>(), delete_op_size::<K>()),
    )
}

impl<F, V, S> OperationCodec<F, S> for FixedEncoding<V>
where
    F: Family,
    S::Key: Array + Codec,
    V: FixedValue,
    S: Update<Value = V, ValueEncoding = Self> + CodecFixed<Cfg = ()>,
{
    type ReadCfg = ();

    fn write_operation(op: &Operation<F, S>, buf: &mut impl BufMut) {
        let total = total_op_size::<S::Key, V, S>();
        match op {
            Operation::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
                buf.put_bytes(0, total - delete_op_size::<S::Key>());
            }
            Operation::Update(p) => {
                UPDATE_CONTEXT.write(buf);
                p.write(buf);
                buf.put_bytes(0, total - update_op_size::<S>());
            }
            Operation::CommitFloor(metadata, floor_loc) => {
                COMMIT_CONTEXT.write(buf);
                if let Some(metadata) = metadata {
                    true.write(buf);
                    metadata.write(buf);
                } else {
                    buf.put_bytes(0, V::SIZE + 1);
                }
                buf.put_slice(&floor_loc.to_be_bytes());
                buf.put_bytes(0, total - commit_op_size::<V>());
            }
        }
    }

    fn read_operation(
        buf: &mut impl Buf,
        cfg: &Self::ReadCfg,
    ) -> Result<Operation<F, S>, CodecError> {
        let total = total_op_size::<S::Key, V, S>();
        at_least(buf, total)?;

        match u8::read(buf)? {
            DELETE_CONTEXT => {
                let key = S::Key::read(buf)?;
                ensure_zeros(buf, total - delete_op_size::<S::Key>())?;
                Ok(Operation::Delete(key))
            }
            UPDATE_CONTEXT => {
                let payload = S::read_cfg(buf, cfg)?;
                ensure_zeros(buf, total - update_op_size::<S>())?;
                Ok(Operation::Update(payload))
            }
            COMMIT_CONTEXT => {
                let is_some = bool::read(buf)?;
                let metadata = if is_some {
                    Some(V::read_cfg(buf, cfg)?)
                } else {
                    ensure_zeros(buf, V::SIZE)?;
                    None
                };
                let floor_loc = Location::new(u64::read(buf)?);
                if !floor_loc.is_valid() {
                    return Err(CodecError::Invalid(
                        "storage::qmdb::any::operation::fixed::Operation",
                        "commit floor location overflow",
                    ));
                }
                ensure_zeros(buf, total - commit_op_size::<V>())?;
                Ok(Operation::CommitFloor(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

// FixedSize for ordered fixed operations.
impl<F, K, V> FixedSize for Operation<F, update::Ordered<K, FixedEncoding<V>>>
where
    F: Family,
    K: Array,
    V: FixedValue,
    update::Ordered<K, FixedEncoding<V>>: FixedSize,
{
    const SIZE: usize = total_op_size::<K, V, update::Ordered<K, FixedEncoding<V>>>();
}

// FixedSize for unordered fixed operations.
impl<F, K, V> FixedSize for Operation<F, update::Unordered<K, FixedEncoding<V>>>
where
    F: Family,
    K: Array,
    V: FixedValue,
    update::Unordered<K, FixedEncoding<V>>: FixedSize,
{
    const SIZE: usize = total_op_size::<K, V, update::Unordered<K, FixedEncoding<V>>>();
}
