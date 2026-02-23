//! Codec implementations for operations with variable-length keys.
//!
//! This parallels [super::variable] (fixed key + variable value) but supports variable-length
//! keys by using `EncodeSize` for the key instead of `FixedSize`. Both variable-value
//! ([VarKeyEncoding]) and fixed-value ([VarKeyFixedEncoding]) variants are supported.

use crate::{
    mmr::Location,
    qmdb::{
        any::{
            operation::{Operation, Update, COMMIT_CONTEXT, DELETE_CONTEXT, UPDATE_CONTEXT},
            value::{VarKeyEncoding, VarKeyFixedEncoding},
            FixedValue, VariableValue,
        },
        operation::Key,
    },
};
use commonware_codec::{varint::UInt, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_runtime::{Buf, BufMut};

impl<K, V, S> EncodeSize for Operation<K, VarKeyEncoding<V>, S>
where
    K: Key + EncodeSize,
    V: VariableValue,
    S: Update<K, VarKeyEncoding<V>> + EncodeSize,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(k) => k.encode_size(),
            Self::Update(p) => p.encode_size(),
            Self::CommitFloor(v, floor) => v.encode_size() + UInt(**floor).encode_size(),
        }
    }
}

impl<K, V, S> Write for Operation<K, VarKeyEncoding<V>, S>
where
    K: Key + Write,
    V: VariableValue,
    S: Update<K, VarKeyEncoding<V>> + Write,
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

impl<K, V, S> Read for Operation<K, VarKeyEncoding<V>, S>
where
    K: Key + Read,
    V: VariableValue,
    S: Update<K, VarKeyEncoding<V>> + Read<Cfg = (<K as Read>::Cfg, <V as Read>::Cfg)>,
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
                        "storage::qmdb::any::operation::varkey::Operation",
                        "commit floor location overflow",
                    )
                })?;
                Ok(Self::CommitFloor(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

// --- Variable key + Fixed value ---

impl<K, V, S> EncodeSize for Operation<K, VarKeyFixedEncoding<V>, S>
where
    K: Key + EncodeSize,
    V: FixedValue,
    S: Update<K, VarKeyFixedEncoding<V>> + EncodeSize,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(k) => k.encode_size(),
            Self::Update(p) => p.encode_size(),
            Self::CommitFloor(v, floor) => v.encode_size() + UInt(**floor).encode_size(),
        }
    }
}

impl<K, V, S> Write for Operation<K, VarKeyFixedEncoding<V>, S>
where
    K: Key + Write,
    V: FixedValue,
    S: Update<K, VarKeyFixedEncoding<V>> + Write,
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

impl<K, V, S> Read for Operation<K, VarKeyFixedEncoding<V>, S>
where
    K: Key + Read,
    V: FixedValue,
    S: Update<K, VarKeyFixedEncoding<V>> + Read<Cfg = <K as Read>::Cfg>,
{
    type Cfg = <K as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            DELETE_CONTEXT => {
                let key = K::read_cfg(buf, cfg)?;
                Ok(Self::Delete(key))
            }
            UPDATE_CONTEXT => {
                let payload = S::read_cfg(buf, cfg)?;
                Ok(Self::Update(payload))
            }
            COMMIT_CONTEXT => {
                let metadata = Option::<V>::read(buf)?;
                let floor_loc = UInt::read(buf)?;
                let floor_loc = Location::new(floor_loc.into()).ok_or_else(|| {
                    CodecError::Invalid(
                        "storage::qmdb::any::operation::varkey::Operation",
                        "commit floor location overflow",
                    )
                })?;
                Ok(Self::CommitFloor(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmdb::any::{
        operation::update::Unordered as UnorderedUpdate, value::VarKeyEncoding,
    };
    use commonware_codec::{Codec, RangeCfg, Read};

    type Op = Operation<
        Vec<u8>,
        VarKeyEncoding<Vec<u8>>,
        UnorderedUpdate<Vec<u8>, VarKeyEncoding<Vec<u8>>>,
    >;

    fn roundtrip<T>(value: &T, cfg: &<T as Read>::Cfg)
    where
        T: Codec + PartialEq + std::fmt::Debug,
    {
        let encoded = value.encode();
        let decoded = T::decode_cfg(encoded.clone(), cfg).expect("decode");
        assert_eq!(decoded, *value);
        let encoded2 = decoded.encode();
        assert_eq!(encoded, encoded2);
    }

    fn cfg() -> <Op as Read>::Cfg {
        ((RangeCfg::from(..), ()), (RangeCfg::from(..), ()))
    }

    #[test]
    fn varkey_delete_roundtrip() {
        roundtrip(&Op::Delete(vec![1, 2, 3, 4, 5]), &cfg());
    }

    #[test]
    fn varkey_update_roundtrip() {
        let update = Op::Update(UnorderedUpdate(vec![10, 20, 30], vec![40, 50, 60, 70]));
        roundtrip(&update, &cfg());
    }

    #[test]
    fn varkey_commit_roundtrip() {
        roundtrip(
            &Op::CommitFloor(Some(vec![1, 2, 3]), Location::new_unchecked(5)),
            &cfg(),
        );
        roundtrip(&Op::CommitFloor(None, Location::new_unchecked(7)), &cfg());
    }

    #[test]
    fn varkey_empty_key_roundtrip() {
        roundtrip(&Op::Delete(vec![]), &cfg());
        let update = Op::Update(UnorderedUpdate(vec![], vec![1, 2, 3]));
        roundtrip(&update, &cfg());
    }

    #[test]
    fn varkey_large_key_roundtrip() {
        let key = vec![0xAB; 1024];
        let value = vec![0xCD; 2048];
        let update = Op::Update(UnorderedUpdate(key, value));
        roundtrip(&update, &cfg());
    }

    // --- Variable key + Fixed value ---

    type FixedOp = Operation<
        Vec<u8>,
        VarKeyFixedEncoding<u64>,
        UnorderedUpdate<Vec<u8>, VarKeyFixedEncoding<u64>>,
    >;

    fn fixed_cfg() -> <FixedOp as Read>::Cfg {
        (RangeCfg::from(..), ())
    }

    #[test]
    fn varkey_fixed_delete_roundtrip() {
        roundtrip(&FixedOp::Delete(vec![1, 2, 3]), &fixed_cfg());
    }

    #[test]
    fn varkey_fixed_update_roundtrip() {
        let update = FixedOp::Update(UnorderedUpdate(vec![10, 20], 0xdead_beef_u64));
        roundtrip(&update, &fixed_cfg());
    }

    #[test]
    fn varkey_fixed_commit_roundtrip() {
        roundtrip(
            &FixedOp::CommitFloor(Some(42u64), Location::new_unchecked(5)),
            &fixed_cfg(),
        );
        roundtrip(
            &FixedOp::CommitFloor(None, Location::new_unchecked(7)),
            &fixed_cfg(),
        );
    }
}
