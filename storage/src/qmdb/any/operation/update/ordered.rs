use crate::qmdb::{
    any::{
        operation::{update::sealed::Sealed, Update as UpdateTrait},
        value::{FixedEncoding, ValueEncoding, VariableEncoding},
        FixedValue, VariableValue,
    },
    operation::Key,
};
use commonware_codec::{
    Encode as _, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_runtime::{Buf, BufMut};
use commonware_utils::{hex, Array};
use std::fmt;

#[derive(Clone, PartialEq, Debug, Eq)]
pub struct Update<K: Key, V: ValueEncoding> {
    pub key: K,
    pub value: V::Value,
    pub next_key: K,
}

#[cfg(feature = "arbitrary")]
impl<K: Key, V: ValueEncoding> arbitrary::Arbitrary<'_> for Update<K, V>
where
    K: for<'a> arbitrary::Arbitrary<'a>,
    V::Value: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: u.arbitrary()?,
            value: u.arbitrary()?,
            next_key: u.arbitrary()?,
        })
    }
}

impl<K: Key, V: ValueEncoding> Sealed for Update<K, V> {}

impl<K: Key, V: ValueEncoding> UpdateTrait<K, V> for Update<K, V> {
    fn key(&self) -> &K {
        &self.key
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[key:{} next_key:{} value:{}]",
            hex(&self.key),
            hex(&self.next_key),
            hex(&self.value.encode())
        )
    }
}

impl<K: Array, V: FixedValue> FixedSize for Update<K, FixedEncoding<V>> {
    const SIZE: usize = K::SIZE + V::SIZE + K::SIZE;
}

impl<K: Array, V: FixedValue> Write for Update<K, FixedEncoding<V>> {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
        self.value.write(buf);
        self.next_key.write(buf);
    }
}

impl<K: Array, V: FixedValue> Read for Update<K, FixedEncoding<V>> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        let next_key = K::read(buf)?;
        Ok(Self {
            key,
            value,
            next_key,
        })
    }
}

impl<K, V> EncodeSize for Update<K, VariableEncoding<V>>
where
    K: Key + EncodeSize,
    V: VariableValue,
{
    fn encode_size(&self) -> usize {
        self.key.encode_size() + self.value.encode_size() + self.next_key.encode_size()
    }
}

impl<K, V> Write for Update<K, VariableEncoding<V>>
where
    K: Key + Write,
    V: VariableValue,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
        self.value.write(buf);
        self.next_key.write(buf);
    }
}

impl<K, V> Read for Update<K, VariableEncoding<V>>
where
    K: Key + Read,
    V: VariableValue,
{
    type Cfg = (<K as Read>::Cfg, <V as Read>::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read_cfg(buf, &cfg.0)?;
        let value = V::read_cfg(buf, &cfg.1)?;
        let next_key = K::read_cfg(buf, &cfg.0)?;
        Ok(Self {
            key,
            value,
            next_key,
        })
    }
}
