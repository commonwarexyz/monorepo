use crate::qmdb::any::{
    operation::{update::sealed::Sealed, Update as UpdateTrait},
    value::{FixedEncoding, ValueEncoding, VariableEncoding, VarKeyEncoding},
    FixedValue, VariableValue,
};
use crate::qmdb::operation::Key;
use commonware_codec::{
    Encode as _, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_runtime::{Buf, BufMut};
use commonware_utils::{hex, Array};
use std::fmt;

#[derive(Clone, PartialEq, Debug, Eq)]
pub struct Update<K: Key, V: ValueEncoding>(pub K, pub V::Value);

#[cfg(feature = "arbitrary")]
impl<K: Key, V: ValueEncoding> arbitrary::Arbitrary<'_> for Update<K, V>
where
    K: for<'a> arbitrary::Arbitrary<'a>,
    V::Value: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?, u.arbitrary()?))
    }
}

impl<K: Key, V: ValueEncoding> Sealed for Update<K, V> {}

impl<K: Key, V: ValueEncoding> UpdateTrait<K, V> for Update<K, V> {
    fn key(&self) -> &K {
        &self.0
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[key:{} value:{}]", hex(&self.0), hex(&self.1.encode()))
    }
}

// --- Fixed key + Fixed value ---

impl<K: Array, V: FixedValue> FixedSize for Update<K, FixedEncoding<V>> {
    const SIZE: usize = K::SIZE + V::SIZE;
}

impl<K: Array, V: FixedValue> Write for Update<K, FixedEncoding<V>> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
        self.1.write(buf);
    }
}

impl<K: Array, V: FixedValue> Read for Update<K, FixedEncoding<V>> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self(key, value))
    }
}

// --- Fixed key + Variable value ---

impl<K: Array, V: VariableValue> EncodeSize for Update<K, VariableEncoding<V>> {
    fn encode_size(&self) -> usize {
        K::SIZE + self.1.encode_size()
    }
}

impl<K: Array, V: VariableValue> Write for Update<K, VariableEncoding<V>> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
        self.1.write(buf);
    }
}

impl<K: Array, V: VariableValue> Read for Update<K, VariableEncoding<V>> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self(key, value))
    }
}

// --- Variable key + Variable value ---

impl<K, V> EncodeSize for Update<K, VarKeyEncoding<V>>
where
    K: Key + EncodeSize,
    V: VariableValue,
{
    fn encode_size(&self) -> usize {
        self.0.encode_size() + self.1.encode_size()
    }
}

impl<K, V> Write for Update<K, VarKeyEncoding<V>>
where
    K: Key + Write,
    V: VariableValue,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
        self.1.write(buf);
    }
}

impl<K, V> Read for Update<K, VarKeyEncoding<V>>
where
    K: Key + Read,
    V: VariableValue,
{
    type Cfg = (<K as Read>::Cfg, <V as Read>::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read_cfg(buf, &cfg.0)?;
        let value = V::read_cfg(buf, &cfg.1)?;
        Ok(Self(key, value))
    }
}
